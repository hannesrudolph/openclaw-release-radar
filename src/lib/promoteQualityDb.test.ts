import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawn, spawnSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import {
  chmodSync,
  constants as fsConstants,
  copyFileSync,
  existsSync,
  linkSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readdirSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import {
  INSTALLER_PENDING_STATE_FIELDS,
  INSTALLER_PENDING_STATE_SCHEMA_VERSION,
  INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD,
  INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION,
  PROMOTION_AUTHORIZATION_HASH_DOMAIN,
  PROMOTION_AUTHORIZATION_SCHEMA_VERSION,
  PROMOTION_IMMUTABLE_LEDGER_TABLES,
  PROMOTION_REQUIRED_APPEND_ONLY_TRIGGERS,
  PROMOTION_VALIDATION_REPORT_HASH_DOMAIN,
  acquireDeploymentLock,
  canonicalPromotionEnvironment,
  installerPendingStateHash,
  listDestinationHolders,
  parsePromotionArgs,
  promotionImmutableLedgerDoctorSummary,
  promoteQualityDb,
  readPromotionAdvisoryAuditProjection,
  verifyInheritedDeploymentLock,
  verifyPromotionGithubReleaseCatalog,
  validatePromotionValidationReport,
} from '../../scripts/promote-quality-db.mjs';
import { ReleaseAuditReader } from '../../scripts/lib/release-audit-reader.mjs';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger.ts';
import { scoreSourceIdentityForDb } from './scoreSourceIdentity.ts';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
} from './stateEventSnapshot.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from './analysisVersions.ts';
import {
  PROMPT_VERSION,
  SCORE_MODEL_VERSION,
} from './releaseScoring.ts';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisorySnapshotContentHash,
  buildCompoundAdvisorySnapshot,
  canonicalCompoundAdvisorySnapshotJson,
  compoundAdvisoryScoreRows,
  compoundAdvisorySnapshotLedgerContentHash,
  compoundAdvisorySnapshotMetadataDigest,
  compoundAdvisorySnapshotPublicationAuthorizations,
  type CompoundAdvisorySnapshotMetadata,
} from './advisorySnapshot.ts';
import {
  canonicalJson as canonicalOperationJson,
  operationAttemptConfigHash,
  operationAttemptContentHash,
  operationCaptureReceiptContentHash,
  operationCaptureReceiptId,
  operationStageEventContentHash,
  operationStageEventId,
  verifyOperationReceiptLedger,
} from './operationReceipts.ts';
import {
  projectReleaseCatalogActiveRows,
  releaseCatalogCaptureReceiptContentHash,
  releaseCatalogCaptureReceiptId,
  verifyReleaseCatalogCaptureReceiptLedger,
} from './releaseCatalogReceipt.ts';
import {
  buildReleaseArtifactPublication,
} from './releaseArtifactPublication.ts';
import {
  assessReleaseValidationObservation,
  buildCompoundAdvisorySnapshotValidationEvidence,
  releaseValidationObservationTargets,
  type AdvisorySnapshotValidationEvidence,
  type ObservationAssessmentInput,
  type ReleaseScoreAuditHistoryEvidenceRow,
  type ReleaseValidationForecastLedgerRow,
} from './releaseValidation.ts';
import {
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
  stageIssueCatalogSnapshot,
} from './issueCatalogSnapshot.ts';
import { codeRevisionFromEnv } from './codeRevision.ts';
import {
  planReleaseValidationOpportunityEnrollments,
  releaseValidationOpportunityEnrollmentContentHash,
  releaseValidationOpportunityId,
} from './releaseValidationOpportunityDenominator.ts';
import {
  locallyHeldRepositoryDatabaseWriterLockOwner,
} from './exclusiveProcessLock.ts';
import {
  releaseValidationCohortCellKey,
  sealReleaseValidationCohort,
  sealReleaseValidationEvaluationReceipt,
  sealReleaseValidationPolicy,
  sealReleaseValidationProofEpoch,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const lsofAvailable = !spawnSync('lsof', ['-v'], { encoding: 'utf8' }).error;
const fixtureRepository = 'openclaw/openclaw';
const releaseCatalogReceiptColumns = [
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
] as const;
const historyColumns = [
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
const fixtureGenericImmutableLedgerTables = [
  'closure_claim_source_snapshots',
  'closure_claim_candidates',
  'closure_claim_extraction_receipts',
  'closure_claim_extraction_receipt_members',
  'classifier_attempt_runs',
  'classifier_attempts',
  'classifier_attempt_terminal_receipts',
  'classifier_classification_publications',
  'issue_label_events',
  'repository_collaborator_permission_snapshots',
  'repository_collaborator_permission_rows',
  'approved_maintainer_roster_snapshots',
  'approved_maintainer_roster_entries',
  'issue_label_evidence_snapshots',
  'issue_label_evidence_rows',
  'repository_collaborator_permission_snapshots_v2',
  'repository_collaborator_permission_rows_v2',
  'signed_maintainer_roster_snapshots',
  'signed_maintainer_roster_entries',
  'score_authority_resolution_runs',
  'score_authority_resolution_rows',
  'release_score_audit_history_v2_seals',
] as const;
const fixtureCanonicalValidationProofTables = [
  ['release_validation_proof_epochs', 'proof_epoch_id'],
  ['release_validation_proof_epoch_retirements', 'retirement_id'],
  ['release_validation_policies', 'policy_id'],
  ['release_validation_cohorts', 'cohort_id'],
  ['release_validation_catalog_observations', 'observation_id'],
  ['release_validation_catalog_members', 'member_id'],
  ['release_validation_catalog_reconciliations', 'reconciliation_id'],
  [
    'release_validation_catalog_reconciliation_rows',
    'reconciliation_row_id',
  ],
  ['release_validation_obligations', 'obligation_id'],
  ['release_validation_split_assignments', 'assignment_id'],
  ['release_validation_forecasts_v2', 'forecast_id'],
  ['release_validation_outcomes_v2', 'outcome_id'],
  ['release_validation_proof_observation_batches', 'batch_id'],
  ['release_validation_evaluation_receipts', 'evaluation_id'],
  ['release_validation_promotion_receipts', 'promotion_id'],
] as const;

describe('quality database promotion', () => {
  it('defaults to dry-run and requires explicit source and destination identities', () => {
    const installerArgs = [
      '--source', 'quality.db',
      '--destination', 'primary.db',
      '--rollback-backup', 'rollback.db',
      '--deployment-transaction-id', '11111111-1111-4111-8111-111111111111',
      '--release-name', 'release-candidate',
      '--release-sha', 'a'.repeat(40),
      '--artifact-digest', `sha256:${'b'.repeat(64)}`,
      '--pending-state-hash', 'c'.repeat(64),
      '--required-score-receipt-id', 'd'.repeat(64),
      '--apply',
      '--deployment-lock-fd', '9',
    ];
    assert.deepEqual(
      parsePromotionArgs(['--source', 'quality.db', '--destination', 'primary.db']),
      {
        help: false,
        sourcePath: 'quality.db',
        destinationPath: 'primary.db',
        rollbackBackupPath: null,
        deploymentTransaction: null,
        apply: false,
        explicitDryRun: false,
      },
    );
    assert.throws(
      () => parsePromotionArgs(['--source', 'quality.db']),
      /Both --source and --destination/,
    );
    assert.throws(
      () => parsePromotionArgs([
        '--source', 'quality.db',
        '--destination', 'primary.db',
        '--apply',
        '--dry-run',
      ]),
      /mutually exclusive/,
    );
    assert.throws(
      () => parsePromotionArgs([
        '--source', 'quality.db',
        '--destination', 'primary.db',
        '--apply',
        '--force-stop-holders',
      ]),
      /Unknown option: --force-stop-holders/,
    );
    assert.equal(
      parsePromotionArgs(installerArgs).deploymentTransaction?.inheritedLockFd,
      9,
    );
    assert.throws(
      () => parsePromotionArgs(
        installerArgs,
        { RADAR_DEPLOY_LOCK_HELD: '1' },
      ),
      /RADAR_DEPLOY_LOCK_HELD no longer authorizes promotion/,
    );
    assert.throws(
      () => parsePromotionArgs(installerArgs.slice(0, -2)),
      /requires --deployment-lock-fd/,
    );
    assert.throws(
      () => parsePromotionArgs([
        '--source', 'quality.db',
        '--destination', 'primary.db',
        '--deployment-lock-fd', '9',
      ]),
      /may be used only with an installer-owned deployment transaction/,
    );
  });

  it('records canonical promotion receipts against an existing writable database', () => {
    const environment = canonicalPromotionEnvironment('/private/quality.db', {
      npm_lifecycle_event: 'promote:quality-db',
      RADAR_DB_BOOTSTRAP_MODE: 'fresh',
      RADAR_DB_READ_ONLY: '1',
      SENTINEL: 'preserved',
    });

    assert.equal(environment.DB_PATH, '/private/quality.db');
    assert.equal(environment.RADAR_DB_BOOTSTRAP_MODE, 'existing');
    assert.equal(environment.RADAR_DB_READ_ONLY, undefined);
    assert.equal(environment.REFRESH_ON_STARTUP, 'false');
    assert.equal(environment.REFRESH_MINUTES, '0');
    assert.equal(environment.npm_lifecycle_event, 'promote:quality-db');
    assert.equal(environment.SENTINEL, 'preserved');
  });

  it('requires the inherited descriptor itself to carry the canonical exclusive flock', () => {
    const lockPath = '/opt/radar/shared/deploy-promotion.lock';
    const directoryInfo = {
      isDirectory: () => true,
      isFile: () => false,
      isSymbolicLink: () => false,
    };
    const fileInfo = {
      dev: 41n,
      ino: 73n,
      isDirectory: () => false,
      isFile: () => true,
      isSymbolicLink: () => false,
    };
    let fdInfo =
      'pos:\t0\nflags:\t0100001\nmnt_id:\t29\nino:\t73\n' +
      'lock:\t1: FLOCK  ADVISORY  WRITE 123 00:2a:73 0 EOF\n';
    const dependencies = {
      platform: 'linux',
      fstat: () => fileInfo,
      stat: () => fileInfo,
      lstat: (path: string) =>
        path === lockPath ? fileInfo : directoryInfo,
      readFdInfo: () => fdInfo,
    };
    const lock = verifyInheritedDeploymentLock({
      path: lockPath,
      fd: 9,
    }, dependencies);

    assert.deepEqual(lock.proof, {
      schemaVersion: INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION,
      method: INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD,
      fd: 9,
      path: lockPath,
      device: '41',
      inode: '73',
      lockType: 'exclusive',
      verified: true,
    });
    lock.assertHeld('test boundary');

    fdInfo = 'pos:\t0\nflags:\t0100001\nmnt_id:\t29\nino:\t73\n';
    assert.throws(
      () => lock.assertHeld('lost-lock boundary'),
      /does not carry the exclusive FLOCK lock before lost-lock boundary/,
    );
    assert.throws(
      () => verifyInheritedDeploymentLock({
        path: lockPath,
        fd: 9,
      }, {
        ...dependencies,
        fstat: () => ({ ...fileInfo, ino: 74n }),
      }),
      /does not match .*deploy-promotion\.lock/,
    );
  });

  it('runs doctor, score, release-audit, and validation gates on the source/staged database', async () => {
    const fixture = createFixture('staged-quality-gates');
    const doctorCalls: Array<{ dbPath: string; failOnWarnings: boolean }> = [];
    const scoreCalls: string[] = [];
    const releaseAuditCalls: string[] = [];
    const validationCalls: Array<{
      dbPath: string;
      expectedReceipt: ReturnType<typeof testEvaluationReceipt>;
    }> = [];
    const promotionCalls: Array<Record<string, any>> = [];
    try {
      closeFixtureDatabases(fixture);
      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
      }, testDependencies({
        doctor: (options: { dbPath: string; failOnWarnings: boolean }) => {
          doctorCalls.push(options);
          return healthyDoctor()();
        },
        verifyScore: ({ dbPath }: { dbPath: string }) => {
          scoreCalls.push(dbPath);
          return { name: 'full score recomputation', passed: true };
        },
        verifyReleaseAudit: ({ dbPath }: { dbPath: string }) => {
          releaseAuditCalls.push(dbPath);
          return { name: 'full release-audit invariants', passed: true };
        },
        verifyValidation: ({
          dbPath,
          expectedReceipt,
        }: {
          dbPath: string;
          expectedReceipt: ReturnType<typeof testEvaluationReceipt>;
        }) => {
          validationCalls.push({ dbPath, expectedReceipt });
          return validationGateResult(validationReport('validated'), 0);
        },
        recordPromotion: (input: Record<string, any>) => {
          promotionCalls.push(input);
          return recordTestPromotion(input);
        },
      }));

      assert.equal(result.applied, false);
      assert.equal(scoreCalls.length, 1);
      assert.equal(releaseAuditCalls.length, 1);
      assert.equal(scoreCalls[0], releaseAuditCalls[0]);
      assert.match(scoreCalls[0], /\.source\.sqlite$/);
      assert.equal(validationCalls.length, 2);
      assert.match(validationCalls[0].dbPath, /\.source\.sqlite$/);
      assert.equal(validationCalls[1].dbPath, scoreCalls[0]);
      assert.deepEqual(validationCalls[0].expectedReceipt, testEvaluationReceipt());
      assert.deepEqual(validationCalls[1].expectedReceipt, testEvaluationReceipt());
      assert.ok(
        doctorCalls.some((call) =>
          call.dbPath === scoreCalls[0] && call.failOnWarnings === true),
      );
      assert.equal(result.staged.qualityVerification.score.passed, true);
      assert.equal(result.staged.qualityVerification.releaseAudit.passed, true);
      assert.equal(result.source.validation.status, 'validated');
      assert.equal(result.source.validation.validated, true);
      assert.equal(result.staged.qualityVerification.validation.status, 'validated');
      assert.equal(result.staged.qualityVerification.validation.validated, true);
      assert.equal(promotionCalls.length, 1);
      assert.equal(
        promotionCalls[0].evaluation.evaluationId,
        result.staged.qualityVerification.validation
          .canonicalEvaluationReceipt.evaluationId,
      );
      assert.equal(
        promotionCalls[0].evaluation.contentHash,
        result.staged.qualityVerification.validation
          .canonicalEvaluationReceipt.contentHash,
      );
      assert.equal(
        promotionCalls[0].sourceProofHash,
        result.source.database.logicalContentDigest,
      );
      assert.equal(
        promotionCalls[0].destinationProofHash,
        result.destination.database.logicalContentDigest,
      );
      assert.deepEqual(
        result.staged.canonicalPromotionReceipt,
        promotionReceiptResult(promotionCalls[0]),
      );
      assert.equal(result.promotionAuthorization, null);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects validation report identity drift between source and staged verification', async () => {
    const fixture = createFixture('validation-report-identity-drift');
    let validationCalls = 0;
    let promotionCalls = 0;
    try {
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          verifyValidation: () => {
            validationCalls += 1;
            const report = validationReport('validated');
            if (validationCalls === 2) {
              report.forecastLedgerRowCount += 1;
            }
            return validationGateResult(report, 0);
          },
          recordPromotion: () => {
            promotionCalls += 1;
            throw new Error('promotion recorder must not run after report drift');
          },
        })),
        /validation report identity drifted from the verified source report/,
      );
      assert.equal(validationCalls, 2);
      assert.equal(promotionCalls, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects promotion receipt identity or content-hash drift from immutable storage', async () => {
    const fixture = createFixture('promotion-receipt-identity-drift');
    try {
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          recordPromotion: (input: Record<string, any>) => {
            const receipt = promotionReceiptResult(input);
            const storedContentHash = 'e'.repeat(64);
            const db = new DatabaseSync(input.dbPath);
            try {
              db.prepare(`
                INSERT INTO release_validation_promotion_receipts (
                  promotion_id, content_hash, record_json
                )
                VALUES (?, ?, ?)
              `).run(
                receipt.promotionId,
                storedContentHash,
                JSON.stringify({
                  ...receipt,
                  contentHash: storedContentHash,
                }),
              );
            } finally {
              db.close();
            }
            return receipt;
          },
        })),
        /canonical promotion receipt identity\/content hash drifted from the recorded immutable receipt/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects insufficient validation instead of treating calibration as promotable', async () => {
    const fixture = createFixture('validation-insufficient');
    const report = validationReport('insufficient');
    try {
      assert.throws(
        () => validatePromotionValidationReport(report, 2, 'test candidate'),
        /prospective validation report is not explicitly validated/,
      );
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          verifyValidation: () => ({
            name: 'prospective validation evaluation',
            script: 'scripts/validation/evaluate-score-quality.mjs',
            args: [],
            passed: true,
            status: 'insufficient',
            validated: false,
            exitCode: 2,
            report,
          }),
        })),
        /prospective validation result is not explicitly validated/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('accepts genuinely validated prospective evaluation', async () => {
    const fixture = createFixture('validation-validated');
    const report = validationReport('validated');
    try {
      closeFixtureDatabases(fixture);
      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
      }, testDependencies({
        verifyValidation: () => validationGateResult(report, 0),
      }));

      assert.equal(result.source.validation.status, 'validated');
      assert.equal(result.source.validation.validated, true);
      assert.equal(result.staged.qualityVerification.validation.status, 'validated');
      assert.equal(result.staged.qualityVerification.validation.validated, true);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects failed, integrity-invalid, hidden-failure, and malformed validation reports', async () => {
    const cases = [
      {
        name: 'measurable-failure',
        report: validationReport('measurable_but_failed'),
        exitCode: 1,
        pattern: /failed measurably|hides a failed measurable model/,
      },
      {
        name: 'ledger-integrity',
        report: {
          ...validationReport('measurable_but_failed'),
          failureClass: 'ledger_integrity',
          errors: ['score history seal is invalid'],
        },
        exitCode: 1,
        pattern: /integrity or semantic errors/,
      },
      {
        name: 'hidden-measurable-failure',
        report: {
          ...validationReport('insufficient'),
          currentStratum: {
            status: 'measurable_but_failed',
            sampleSufficient: true,
            qualityPassed: false,
          },
        },
        exitCode: 2,
        pattern: /hides a failed measurable model/,
      },
      {
        name: 'malformed',
        report: {
          schemaVersion: 4,
          status: 'insufficient',
          failureClass: 'sample_or_power',
        },
        exitCode: 2,
        pattern: /errors must be an array/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(`validation-${testCase.name}`);
      try {
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies({
            verifyValidation: () => validationGateResult(
              testCase.report,
              testCase.exitCode,
            ),
          })),
          testCase.pattern,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects forged, missing, and stale validation results at the promotion boundary', async () => {
    const cases = [
      {
        name: 'forged-validated-flag',
        result: {
          ...validationGateResult(validationReport('validated'), 0),
          validated: false,
        },
        pattern: /result is not explicitly validated/,
      },
      {
        name: 'missing-result',
        result: null,
        pattern: /result must be an object/,
      },
      {
        name: 'stale-report',
        result: validationGateResult({
          ...validationReport('validated'),
          generatedAt: '2026-07-03T12:34:55.999Z',
        }, 0),
        pattern: /report is stale/,
      },
      {
        name: 'invalid-generated-at',
        result: {
          ...validationGateResult(validationReport('validated'), 0),
          report: {
            ...validationReport('validated'),
            generatedAt: 'not-a-timestamp',
          },
        },
        pattern: /generatedAt must be a valid timestamp/,
      },
      {
        name: 'same-time-conflicting-receipt',
        result: {
          ...validationGateResult(validationReport('validated'), 0),
          canonicalEvaluationReceipt: {
            ...testEvaluationReceipt(),
            contentHash: 'c'.repeat(64),
          },
        },
        pattern: /contentHash does not match the recorded immutable receipt/,
      },
      {
        name: 'unrecorded-newer-receipt',
        result: validationGateResult({
          ...validationReport('validated'),
          generatedAt: '2026-07-03T12:34:56.001Z',
        }, 0),
        pattern: /evaluatedAt does not match the recorded immutable receipt/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(`validation-${testCase.name}`);
      try {
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies({
            verifyValidation: () => testCase.result,
          })),
          testCase.pattern,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('preserves a destination history extension with coherent run seals', async () => {
    const fixture = createFixture('history-extension');
    let promotionCalls = 0;
    try {
      const shared = historyRow('shared', 'v1', 8);
      seedHistory(fixture.source, [shared]);
      seedHistory(fixture.destination, [
        shared,
        historyRow('destination-only', 'v2', 6),
      ]);
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          recordPromotion: () => {
            promotionCalls++;
            throw new Error('promotion recorder must not run');
          },
        })),
        /Destination score history is ahead of the source by 1 sealed run/,
      );
      assert.equal(promotionCalls, 0);
      assert.deepEqual(
        readHistory(fixture.destinationPath).map((row) => row.run_id),
        ['destination-only', 'shared'],
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects an internally consistent obsolete model with the real score verifier', async () => {
    const fixture = createProductionDoctorFixture('production-doctor-history-extension');
    try {
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, {
          doctor: healthyDoctor(),
          verifyGithubReleaseCatalog: ({
            dbPath,
            observedAt,
          }: {
            dbPath: string;
            observedAt: string;
          }) => testGithubReleaseCatalogProof(dbPath, observedAt),
          verifyValidation: () => validationGateResult(validationReport('validated'), 0),
          latestEvaluationReceipt: () => testEvaluationReceipt(),
          verifyReleaseAudit: () => ({
            name: 'full release-audit invariants',
            passed: true,
          }),
          readAdvisoryAuditProjection: () => testAdvisoryAuditProjection(),
          listHolders: () => [],
          now: () => new Date('2026-07-03T12:34:56.000Z'),
          acquireDeploymentLock: noopDeploymentLock,
          snapshotDatabase: copyDatabaseSnapshotForTest,
        }),
        /staged promotion failed full score recomputation:.*score_model_version/s,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects internally consistent but mathematically wrong scores with the real score verifier', async () => {
    const fixture = createProductionDoctorFixture('production-wrong-math');
    try {
      rewriteProductionCandidate(fixture.sourcePath, { score: 9 });
      rewriteProductionCandidate(fixture.destinationPath, { score: 9 });

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, {
          doctor: healthyDoctor(),
          verifyGithubReleaseCatalog: ({
            dbPath,
            observedAt,
          }: {
            dbPath: string;
            observedAt: string;
          }) => testGithubReleaseCatalogProof(dbPath, observedAt),
          verifyValidation: () => validationGateResult(validationReport('validated'), 0),
          latestEvaluationReceipt: () => testEvaluationReceipt(),
          verifyReleaseAudit: () => ({
            name: 'full release-audit invariants',
            passed: true,
          }),
          readAdvisoryAuditProjection: () => testAdvisoryAuditProjection(),
          listHolders: () => [],
          now: () => new Date('2026-07-03T12:34:56.000Z'),
          snapshotDatabase: copyDatabaseSnapshotForTest,
        }),
        /staged promotion failed full score recomputation:.*final_score drifted/s,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects a real-default promotion before validation when no canonical evaluation receipt exists', async () => {
    const fixture = createRealVerifierPromotionFixture('production-default-stack-pass');
    try {
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, {
          verifyGithubReleaseCatalog: ({
            dbPath,
            observedAt,
          }: {
            dbPath: string;
            observedAt: string;
          }) => testGithubReleaseCatalogProof(dbPath, observedAt),
          listHolders: () => [],
          now: () => new Date('2026-07-04T12:34:56.000Z'),
          snapshotDatabase: copyDatabaseSnapshotForTest,
        }),
        /has no recorded canonical validation evaluation receipt/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('includes promotion-critical ledgers in the promotion doctor identity', () => {
    const fixture = createFixture('promotion-ledger-doctor-identity');
    try {
      closeFixtureDatabases(fixture);
      const summary = promotionImmutableLedgerDoctorSummary(fixture.sourcePath);
      assert.equal(summary.ok, true);
      assert.equal(summary.tableCount, 56);
      assert.equal(summary.appendOnlyTriggerCount, 112);
      assert.equal(PROMOTION_IMMUTABLE_LEDGER_TABLES.length, 56);
      assert.equal(PROMOTION_REQUIRED_APPEND_ONLY_TRIGGERS.length, 112);
      assert.deepEqual(
        Object.keys(summary.tables),
        PROMOTION_IMMUTABLE_LEDGER_TABLES,
      );
      assert.match(summary.tableDigest, /^[0-9a-f]{64}$/);
      assert.match(summary.appendOnlyTriggerDigest, /^[0-9a-f]{64}$/);
      for (const table of [
        'issue_catalog_snapshot_consumptions',
        'classifier_classification_publications',
        'score_authority_resolution_runs',
        'release_score_audit_history_v2_seals',
        'release_validation_opportunity_enrollments',
        'release_validation_observation_batches',
      ]) {
        assert.equal(summary.tables[table].present, true);
      }
    } finally {
      fixture.cleanup();
    }
  });

  it('matches the canonical immutable-ledger manifest to the production schema', () => {
    const dir = mkdtempSync(join(tmpdir(), 'radar-promote-manifest-parity-'));
    const path = join(dir, 'production.db');
    try {
      initializeProductionSchema(path);
      const summary = promotionImmutableLedgerDoctorSummary(path);
      assert.equal(summary.ok, true, summary.error);
      assert.equal(summary.tableCount, 56);
      assert.equal(summary.appendOnlyTriggerCount, 112);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('deduplicates identical sealed history runs', async () => {
    const fixture = createFixture('exact-run');
    try {
      const rows = [
        historyRow('shared', 'v1', 8),
        historyRow('shared', 'v2', 7),
      ];
      seedHistory(fixture.source, rows);
      seedHistory(fixture.destination, rows);
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());
      assert.equal(result.historyMerge.insertedRows, 0);
      assert.equal(result.historyMerge.insertedRuns, 0);
      assert.equal(result.historyMerge.deduplicatedRows, 2);
      assert.equal(readHistory(fixture.destinationPath).length, 2);
      assert.equal(readHistoryRunSeals(fixture.destinationPath).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects divergent sealed history chains instead of remapping or dropping runs', async () => {
    const fixture = createFixture('divergent-history');
    try {
      seedHistory(fixture.source, [historyRow('source-run', 'v1', 8)]);
      seedHistory(fixture.destination, [historyRow('destination-run', 'v2', 6)]);
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /run seals diverge from the source run chain/,
      );
      assert.deepEqual(
        readHistory(fixture.destinationPath).map((row) => row.run_id),
        ['destination-run'],
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects a sealed history run whose authority_run_id differs', async () => {
    const fixture = createFixture('history-authority-conflict');
    try {
      seedHistory(fixture.source, [{
        ...historyRow('shared', 'v1', 8),
        authority_run_id: 'authority-source',
      }]);
      seedHistory(fixture.destination, [{
        ...historyRow('shared', 'v1', 8),
        authority_run_id: 'authority-destination',
      }]);
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /Destination score history run "shared" conflicts with a sealed source run/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('fails closed when destination-only history cannot be reconciled to score persistence metadata', async () => {
    const fixture = createFixture('publication-metadata-divergence');
    try {
      const shared = historyRow('shared', 'v1', 8);
      seedHistory(fixture.source, [shared]);
      seedHistory(fixture.destination, [shared]);
      fixture.destination.prepare(`
        UPDATE meta
        SET value=?
        WHERE key='score_persistence_last_run'
      `).run(JSON.stringify({
        schemaVersion: 2,
        historyRunId: 'shared',
        historyRunContentHash:
          readHistoryRunSeals(fixture.destinationPath).at(-1)?.content_hash,
        authorityRunId: 'destination-only-authority',
        authorityRunContentHash: '1'.repeat(64),
        historyV2SealContentHash: '2'.repeat(64),
      }));
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /Destination current score publication metadata differs at an equal sealed history tip/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('requires operator-managed destination shutdown and never kills holders', async () => {
    const fixture = createFixture('holders');
    try {
      closeFixtureDatabases(fixture);
      const holder = { pid: 123, command: 'node', paths: [fixture.destinationPath] };
      const doctor = healthyDoctor();

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, {
          doctor,
          listHolders: () => [holder],
          snapshotDatabase: copyDatabaseSnapshotForTest,
        }),
        /explicit --dry-run/,
      );

      const explicitDryRun = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        explicitDryRun: true,
      }, testDependencies({ doctor, listHolders: () => [holder] }));
      assert.equal(explicitDryRun.applied, false);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, {
          doctor,
          listHolders: () => [holder],
          acquireDeploymentLock: noopDeploymentLock,
          snapshotDatabase: copyDatabaseSnapshotForTest,
        }),
        /operator-managed service workflow/,
      );

      const invalid = createFixture('holders-invalid');
      try {
        invalid.source.exec('DROP TRIGGER release_score_audit_history_runs_no_delete');
        closeFixtureDatabases(invalid);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: invalid.sourcePath,
            destinationPath: invalid.destinationPath,
            apply: true,
          }, testDependencies({ doctor })),
          /missing required append-only trigger release_score_audit_history_runs_no_delete/,
        );
      } finally {
        invalid.cleanup();
      }
    } finally {
      fixture.cleanup();
    }
  });

  it('allows a stale destination doctor report while requiring a healthy source and stage', async () => {
    const fixture = createFixture('stale-destination-doctor');
    try {
      closeFixtureDatabases(fixture);
      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
      }, testDependencies({
        doctor: ({ dbPath }: { dbPath: string }) => {
          if (dbPath.includes('.destination.sqlite')) {
            return { ok: false, failures: ['stale score model'] };
          }
          return healthyDoctor()();
        },
      }));
      assert.equal(result.applied, false);
      assert.equal(result.source.doctor.ok, true);
      assert.equal(result.destination.doctor.ok, false);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects destination-only immutable ledgers that cannot be merged without loss', async () => {
    const cases: Array<{
      name: string;
      table: string;
      seed(db: DatabaseSync): void;
      seedSource?(db: DatabaseSync): void;
    }> = [
      {
        name: 'advisory',
        table: 'advisory_snapshot_history',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO advisory_snapshot_history (id, captured_at, row_count, content_hash)
            VALUES (1, '2026-07-03T00:00:00.000Z', 0, 'advisory-only')
          `).run();
        },
      },
      {
        name: 'advisory-v2',
        table: 'advisory_snapshot_v2_history',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO advisory_snapshot_v2_history (
              id, schema_version, captured_at,
              repository_owner, repository_name, repository_url,
              target_ecosystem, target_package_name,
              source_hash, catalog_hash, score_hash, score_ready,
              row_count, score_row_count, score_content_digest,
              snapshot_json, previous_content_hash, content_hash
            )
            VALUES (
              1, 2, '2026-07-03T00:00:00.000Z',
              'openclaw', 'openclaw', 'https://github.com/openclaw/openclaw',
              'npm', 'openclaw',
              'source-only', 'catalog-only', 'score-only', 1,
              0, 0, 'score-content-only',
              '{}', NULL, 'advisory-v2-only'
            )
          `).run();
        },
      },
      {
        name: 'advisory-row',
        table: 'advisory_snapshot_rows',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO advisory_snapshot_rows (
              snapshot_id, advisory_key, payload
            )
            VALUES (1, 'destination-only-advisory', '{}')
          `).run();
        },
      },
      {
        name: 'advisory-v2-row',
        table: 'advisory_snapshot_v2_rows',
        seedSource(db: DatabaseSync) {
          seedEmptyAdvisoryV2Snapshot(db, 1, 'shared-advisory-v2');
        },
        seed(db: DatabaseSync) {
          seedEmptyAdvisoryV2Snapshot(db, 1, 'shared-advisory-v2');
          db.prepare(`
            INSERT INTO advisory_snapshot_v2_rows (
              snapshot_id, range_identity, ghsa_id,
              package_ecosystem, package_name, vulnerable_version_range,
              state, target_package, score_eligible, audit_only,
              row_json, row_hash
            )
            VALUES (
              1, 'destination-only-range', 'GHSA-destination-only',
              'npm', 'openclaw', '<1.0.0',
              'published', 1, 1, 0, '{}', 'destination-only-row'
            )
          `).run();
        },
      },
      {
        name: 'forecast',
        table: 'release_validation_forecasts',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO release_validation_forecasts (
              id, decision_id, opportunity_code, latest_release_tag,
              score_model_version, prompt_version, payload
            )
            VALUES (
              1, 'decision-only', 'first_verified_after_24h', 'v-only',
              'test-model', 1, '{}'
            )
          `).run();
        },
      },
      {
        name: 'issue_catalog_snapshots',
        table: 'issue_catalog_snapshots',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO issue_catalog_snapshots (
              snapshot_id, schema_version, row_schema_version, repository, source,
              source_order, captured_at, boundary_total_count, observed_total_count,
              post_boundary_growth_count, terminal_node_id, terminal_issue_number,
              terminal_created_at, fetched_count, unique_count, page_count,
              pages_fetched, sweep_count, membership_digest, content_digest,
              last_request_cursor, row_count, row_schema_digest, rows_content_hash,
              previous_content_hash, content_hash
            )
            VALUES (
              'destination-only-snapshot', 1, 1, 'openclaw/openclaw',
              'github.repository.issues', 'CREATED_AT_ASC',
              '2026-07-03T00:00:00.000Z', 0, 0, 0, NULL, NULL, NULL,
              0, 0, 0, 2, 2, 'membership-only', 'content-only', NULL, 0,
              'row-schema-only', 'rows-only', NULL, 'snapshot-only'
            )
          `).run();
        },
      },
      {
        name: 'issue_catalog_snapshot_rows',
        table: 'issue_catalog_snapshot_rows',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO issue_catalog_snapshot_rows (
              snapshot_id, source_ordinal, issue_number,
              node_id, issue_json, content_hash
            )
            VALUES (
              'destination-only-snapshot', 0, 1,
              'ISSUE-destination-only', '{}', 'destination-only-row'
            )
          `).run();
        },
      },
      {
        name: 'outcome',
        table: 'release_validation_outcome_observations',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO release_validation_outcome_observations (
              id, observation_id, decision_id, horizon_code, status, payload
            )
            VALUES (1, 'observation-only', 'decision-only', '24h', 'pending', '{}')
          `).run();
        },
      },
      {
        name: 'issue-catalog-consumption',
        table: 'issue_catalog_snapshot_consumptions',
        seedSource(db: DatabaseSync) {
          seedIssueCatalogSnapshot(db);
        },
        seed(db: DatabaseSync) {
          seedIssueCatalogSnapshotConsumption(db);
        },
      },
      {
        name: 'validation-enrollment',
        table: 'release_validation_opportunity_enrollments',
        seedSource(db: DatabaseSync) {
          seedOperationReceiptRunWithCatalogAuthority(db, {
            runId: 'destination-enrollment-run',
          });
        },
        seed(db: DatabaseSync) {
          const run = seedOperationReceiptRunWithCatalogAuthority(db, {
            runId: 'destination-enrollment-run',
          });
          db.prepare(`
            INSERT INTO release_validation_opportunity_enrollments (
              opportunity_id, enrolled_at, release_node_id, release_tag,
              release_published_at, opportunity_code, opens_at,
              closes_at_exclusive, score_model_version, prompt_version,
              code_revision, enrollment_run_id, operation_attempt_content_hash,
              catalog_digest, catalog_release_count, previous_content_hash,
              content_hash
            )
            VALUES (
              'destination-enrollment', '2026-07-03T03:00:00.000Z',
              'release-node-only', 'v-only', '2026-07-03T00:00:00.000Z',
              'first_verified_after_3h', '2026-07-03T03:00:00.000Z',
              '2026-07-03T06:00:00.000Z', 'test-model', 1,
              'revision-destination-enrollment-run', 'destination-enrollment-run',
              ?, 'catalog-only', 1, NULL, 'enrollment-only'
            )
          `).run(run.attempt.content_hash);
        },
      },
      {
        name: 'validation-observation-batch',
        table: 'release_validation_observation_batches',
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO release_validation_observation_batches (
              batch_id, observed_at, code_revision, source_identity_digest,
              forecast_count, intended_count, inserted_count,
              already_existing_count, pending_count, excluded_count,
              indeterminate_count, results_json, outcome_chain_previous_hash,
              outcome_chain_content_hash, previous_content_hash, content_hash
            )
            VALUES (
              'destination-batch', '2026-07-03T12:00:00.000Z',
              'revision-destination-batch', 'source-digest-only',
              1, 1, 1, 0, 0, 0, 0, '[]', NULL,
              'outcome-chain-only', NULL, 'batch-only'
            )
          `).run();
        },
      },
      {
        name: 'release_artifact_verification_receipts',
        table: 'release_artifact_verification_receipts',
        seed(db: DatabaseSync) {
          seedArtifactReceiptLedgerRow(db, {
            identitySeed: '1',
            tag: 'v-destination-only-receipt',
          });
        },
      },
      {
        name: 'release_artifact_verification_observations',
        table: 'release_artifact_verification_observations',
        seedSource(db: DatabaseSync) {
          seedArtifactReceiptLedgerRow(db, {
            identitySeed: '2',
            tag: 'v-destination-only-observation',
          });
        },
        seed(db: DatabaseSync) {
          const receipt = seedArtifactReceiptLedgerRow(db, {
            identitySeed: '2',
            tag: 'v-destination-only-observation',
          });
          seedArtifactObservationLedgerRow(db, {
            identitySeed: '3',
            runId: 'destination-only-artifact-run',
            receipt,
          });
        },
      },
      ...fixtureGenericImmutableLedgerTables.map((table) => ({
        name: table,
        table,
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO ${table} (ledger_id, content_hash)
            VALUES (?, ?)
          `).run(`${table}-destination-only`, `${table}-content`);
        },
      })),
      ...fixtureCanonicalValidationProofTables.map(([table, idColumn]) => ({
        name: table,
        table,
        seed(db: DatabaseSync) {
          db.prepare(`
            INSERT INTO ${table} (${idColumn}, content_hash, record_json)
            VALUES (?, ?, '{}')
          `).run(`${table}-destination-only`, `${table}-content`);
        },
      })),
    ];

    for (const testCase of cases) {
      const fixture = createFixture(`destination-only-${testCase.name}`);
      try {
        testCase.seedSource?.(fixture.source);
        testCase.seed(fixture.destination);
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies()),
          new RegExp(`immutable ledger ${testCase.table} contains 1 row`),
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('requires append-only triggers for every promotion-critical ledger', () => {
    const fixture = createFixture('all-append-only-guards');
    try {
      for (const [trigger] of PROMOTION_REQUIRED_APPEND_ONLY_TRIGGERS) {
        const row = fixture.source.prepare(`
          SELECT sql
          FROM sqlite_schema
          WHERE type='trigger' AND name=?
        `).get(trigger) as { sql?: string } | undefined;
        assert.ok(row?.sql, `missing fixture trigger ${trigger}`);
        fixture.source.exec(`DROP TRIGGER ${trigger}`);
        const summary = promotionImmutableLedgerDoctorSummary(fixture.sourcePath);
        assert.equal(summary.ok, false, trigger);
        assert.match(
          String(summary.error),
          new RegExp(`missing required append-only trigger ${trigger}`),
          trigger,
        );
        fixture.source.exec(row.sql);
      }
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects an append-only ledger omitted from the canonical manifest', async () => {
    const fixture = createFixture('undeclared-append-only-ledger');
    try {
      for (const db of [fixture.source, fixture.destination]) {
        db.exec(`
          CREATE TABLE undeclared_immutable_ledger (
            ledger_id TEXT PRIMARY KEY
          );
          CREATE TRIGGER undeclared_immutable_ledger_no_update
          BEFORE UPDATE ON undeclared_immutable_ledger
          BEGIN
            SELECT RAISE(ABORT, 'undeclared_immutable_ledger is append-only');
          END;
          CREATE TRIGGER undeclared_immutable_ledger_no_delete
          BEFORE DELETE ON undeclared_immutable_ledger
          BEGIN
            SELECT RAISE(ABORT, 'undeclared_immutable_ledger is append-only');
          END;
        `);
      }
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /undeclared append-only trigger undeclared_immutable_ledger_no_update on undeclared_immutable_ledger/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('promotes source issue catalog staging as resumable operational data', async () => {
    const fixture = createFixture('source-issue-catalog-staging');
    const seed = (db: DatabaseSync, snapshotId: string, issueNumber: number) => {
      db.prepare(`
        INSERT INTO issue_catalog_snapshots (
          snapshot_id, schema_version, row_schema_version, repository, source,
          source_order, captured_at, boundary_total_count, observed_total_count,
          post_boundary_growth_count, terminal_node_id, terminal_issue_number,
          terminal_created_at, fetched_count, unique_count, page_count,
          pages_fetched, sweep_count, membership_digest, content_digest,
          last_request_cursor, row_count, row_schema_digest, rows_content_hash,
          previous_content_hash, content_hash
        )
        VALUES (
          ?, 1, 1, 'openclaw/openclaw', 'github.repository.issues',
          'CREATED_AT_ASC', '2026-07-04T00:00:00.000Z', 1, 1, 0,
          ?, ?, '2026-07-03T00:00:00.000Z', 1, 1, 1, 2, 2,
          ?, ?, NULL, 1, ?, ?, NULL, ?
        )
      `).run(
        snapshotId,
        `ISSUE-${issueNumber}`,
        issueNumber,
        `${snapshotId}-membership`,
        `${snapshotId}-content`,
        `${snapshotId}-schema`,
        `${snapshotId}-rows`,
        snapshotId,
      );
      db.prepare(`
        INSERT INTO issue_catalog_snapshot_rows (
          snapshot_id, source_ordinal, issue_number, node_id, issue_json, content_hash
        )
        VALUES (?, 0, ?, ?, '{}', ?)
      `).run(snapshotId, issueNumber, `ISSUE-${issueNumber}`, `${snapshotId}-row`);
    };
    try {
      seed(fixture.source, 'source-snapshot', 1);
      closeFixtureDatabases(fixture);

      await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      assert.deepEqual(
        readRows(
          fixture.destinationPath,
          `SELECT snapshot_id FROM issue_catalog_snapshots ORDER BY id`,
        ),
        [{ snapshot_id: 'source-snapshot' }],
      );
      assert.deepEqual(
        readRows(
          fixture.destinationPath,
          `SELECT snapshot_id, issue_number FROM issue_catalog_snapshot_rows`,
        ),
        [{ snapshot_id: 'source-snapshot', issue_number: 1 }],
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('preserves destination-only ingestion failures and comparison snapshots exactly', async () => {
    const fixture = createFixture('preserved-destination-evidence');
    try {
      fixture.source.prepare(`
        INSERT INTO ingestion_evidence_failures (
          id, run_id, occurred_at, source, scope, message, context_json, scoring_blocking
        )
        VALUES (1, 'source-run', '2026-07-03T01:00:00Z', 'source', 'source-scope',
                'source failure', '{"source":true}', 1)
      `).run();
      fixture.destination.prepare(`
        INSERT INTO ingestion_evidence_failures (
          id, run_id, occurred_at, source, scope, release_tag, issue_number,
          message, context_json, scoring_blocking
        )
        VALUES (7, 'destination-run', '2026-07-03T02:00:00Z', 'issues', 'page 7',
                'v7', 707, 'destination failure', '{"page":7}', 1)
      `).run();
      fixture.destination.prepare(`
        INSERT INTO comparison_snapshots (
          id, source_url, captured_at, page_title, page_text, raw_html
        )
        VALUES (9, 'https://comparison.test', '2026-07-03T03:00:00Z',
                'Comparison', 'page text', '<html>comparison</html>')
      `).run();
      fixture.destination.prepare(`
        INSERT INTO comparison_releases (
          snapshot_id, tag, name, published_at, html_url, displayed_date,
          score, band, status, recommended, reason, negative_issues,
          positive_issues, total_attributed_issues, visible_issues_json, raw_card_text
        )
        VALUES (
          9, 'v9', 'Release 9', '2026-07-03T00:00:00Z',
          'https://comparison.test/v9', 'Jul 3', 8.5, 'good', 'eligible', 1,
          'upstream recommendation', 1, 4, 5, '[{"number":9}]', 'raw card'
        )
      `).run();
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      assert.equal(result.preservationMerge.ingestion_evidence_failures.insertedRows, 1);
      assert.equal(result.preservationMerge.comparison_snapshots.insertedRows, 1);
      assert.equal(result.preservationMerge.comparison_releases.insertedRows, 1);
      assert.deepEqual(
        readRows(
          fixture.destinationPath,
          `SELECT id, run_id, message FROM ingestion_evidence_failures ORDER BY id`,
        ),
        [
          { id: 1, run_id: 'source-run', message: 'source failure' },
          { id: 7, run_id: 'destination-run', message: 'destination failure' },
        ],
      );
      assert.deepEqual(
        readRows(
          fixture.destinationPath,
          `SELECT snapshot_id, tag, visible_issues_json, raw_card_text
           FROM comparison_releases`,
        ),
        [{
          snapshot_id: 9,
          tag: 'v9',
          visible_issues_json: '[{"number":9}]',
          raw_card_text: 'raw card',
        }],
      );
      assert.equal(
        readRows(
          result.backupPath,
          `SELECT COUNT(*) AS count FROM comparison_snapshots`,
        )[0].count,
        1,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('loads complete artifact ledgers and rejects missing or substituted membership', async () => {
    const valid = createFixture('artifact-membership-valid');
    try {
      seedArtifactPublicationOperationRun(valid.source, {
        runId: 'artifact-membership-valid',
      });
      closeFixtureDatabases(valid);
      const result = await promoteQualityDb({
        sourcePath: valid.sourcePath,
        destinationPath: valid.destinationPath,
      }, testDependencies());
      assert.equal(result.applied, false);
    } finally {
      valid.cleanup();
    }

    const cases = [
      {
        name: 'missing-observation',
        options: { omitObservation: true },
        pattern:
          /extra immutable observation membership|has no supplied immutable observation/,
      },
      {
        name: 'substituted-receipt-hash',
        options: { substituteReceiptContentHash: true },
        pattern: /is substituted: receipt content hash/,
      },
    ] as const;
    for (const testCase of cases) {
      const fixture = createFixture(`artifact-membership-${testCase.name}`);
      try {
        seedArtifactPublicationOperationRun(fixture.source, {
          runId: `artifact-membership-${testCase.name}`,
          ...testCase.options,
        });
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies()),
          testCase.pattern,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects missing, fixture, foreign, wrong-attempt, failed, and mismatched catalog authority', async () => {
    const cases = [
      {
        name: 'missing-destination-receipt',
        target: 'destination' as const,
        mutate: (db: DatabaseSync) => deleteReleaseCatalogReceiptChain(db),
        pattern: /active release catalog has no valid immutable capture receipt/,
      },
      {
        name: 'fixture-authority',
        target: 'source' as const,
        mutate: (db: DatabaseSync) =>
          appendTestFixtureReleaseCatalogReceipt(db),
        pattern: /forbidden test_fixture authority|cannot authorize product reads or promotion/,
      },
      {
        name: 'foreign-repository',
        target: 'source' as const,
        mutate: (db: DatabaseSync) =>
          appendReleaseCatalogAuthority(db, {
            runId: 'foreign-catalog-refresh',
            repository: 'foreign/repository',
          }),
        pattern: /repository does not match configuration/,
      },
      {
        name: 'wrong-attempt-hash',
        target: 'source' as const,
        mutate: (db: DatabaseSync) =>
          rewriteLatestReleaseCatalogReceipt(db, (payload) => ({
            ...payload,
            operationAttemptContentHash: 'f'.repeat(64),
          })),
        pattern: /does not bind the exact refresh operation attempt/,
      },
      {
        name: 'failed-terminal',
        target: 'source' as const,
        mutate: (db: DatabaseSync) =>
          appendReleaseCatalogAuthority(db, {
            runId: 'failed-catalog-refresh',
            status: 'failure',
          }),
        pattern: /latest GitHub catalog capture run terminated with failure/,
      },
      {
        name: 'active-catalog-mismatch',
        target: 'source' as const,
        mutate: (db: DatabaseSync) => mutateActiveReleaseCatalog(db),
        pattern: /does not match the exact active catalog projection/,
      },
      {
        name: 'active-catalog-rank-mismatch',
        target: 'source' as const,
        mutate: (db: DatabaseSync) => mutateActiveReleaseCatalogRank(db),
        pattern: /exact stored digest and rank/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(`catalog-authority-${testCase.name}`);
      try {
        testCase.mutate(fixture[testCase.target]);
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies()),
          testCase.pattern,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('requires exact independent GitHub identity while excluding drafts', async () => {
    const fixture = createFixture('catalog-independent-exact');
    try {
      const rows = destinationPromotionCatalogForTest();
      replaceActiveReleaseCatalogForTest(fixture.source, rows);
      const runtimeEnvPath = githubRuntimeEnvForTest(fixture.dir);
      closeFixtureDatabases(fixture);
      const proof = await verifyPromotionGithubReleaseCatalog({
        dbPath: fixture.sourcePath,
        label: 'independent catalog fixture',
        runtimeEnvPath,
        observedAt: '2026-07-05T12:00:00.000Z',
        fetchCatalog: async () => githubReleaseCatalogForTest(rows, {
          drafts: [{
            node_id: 'RE_draft',
            tag_name: 'v2026.8.0-draft',
            tag_commit_oid: 'd'.repeat(40),
            name: 'Draft release',
            published_at: null,
            created_at: '2026-07-05T10:00:00.000Z',
            updated_at: '2026-07-05T11:00:00.000Z',
            html_url:
              'https://github.com/openclaw/openclaw/releases/tag/v2026.8.0-draft',
            prerelease: false,
            draft: true,
            body: '',
          }],
        }),
      });
      assert.deepEqual(
        proof.activeCatalog.tags,
        rows.map((row) => row.tag),
      );
      assert.equal(proof.remoteCatalog.draftCount, 1);
      assert.equal(proof.exactIdentityMatch, true);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects phantom inactive rows outside the exact active GitHub catalog', async () => {
    const fixture = createFixture('catalog-independent-phantom-inactive');
    try {
      const rows = destinationPromotionCatalogForTest();
      replaceActiveReleaseCatalogForTest(fixture.source, rows);
      insertInactiveReleaseCatalogForTest(
        fixture.source,
        promotionCatalogReleaseForTest({
          tag: 'v-phantom-inactive',
          nodeId: 'RE_phantom_inactive',
          tagCommitOid: 'f'.repeat(40),
          publishedAt: '2026-07-01T00:00:00.000Z',
          prerelease: 0,
        }),
      );
      const runtimeEnvPath = githubRuntimeEnvForTest(fixture.dir);
      closeFixtureDatabases(fixture);
      await assert.rejects(
        verifyPromotionGithubReleaseCatalog({
          dbPath: fixture.sourcePath,
          label: 'independent catalog phantom fixture',
          runtimeEnvPath,
          observedAt: '2026-07-05T12:00:00.000Z',
          fetchCatalog: async () => githubReleaseCatalogForTest(rows),
        }),
        /release catalog contains 1 row\(s\) outside the exact active GitHub catalog: "v-phantom-inactive" \(catalog_active=0\)/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('allows promotion when the next authoritative capture omits a previously active phantom', async () => {
    const fixture = createFixture('catalog-independent-omitted-phantom');
    try {
      const {
        previousCatalog,
        currentCatalog,
        phantom,
      } = omittedPhantomPromotionCatalogsForTest();
      const previousProjection =
        projectReleaseCatalogActiveRows(previousCatalog);
      seedSharedPromotionCatalogForTest(fixture, previousCatalog);
      replaceActiveReleaseCatalogForTest(
        fixture.source,
        currentCatalog,
        { preserveInactive: true },
      );
      appendReleaseCatalogAuthority(fixture.source, {
        runId: 'catalog-independent-omitted-phantom',
        startedAt: '2026-07-05T01:00:00.000Z',
      });
      assert.deepEqual(
        {
          ...fixture.source.prepare(`
          SELECT tag, catalog_active, catalog_rank, catalog_digest
          FROM releases
          WHERE tag=?
          `).get(phantom.tag),
        },
        {
          tag: phantom.tag,
          catalog_active: 0,
          catalog_rank: previousCatalog.length - 1,
          catalog_digest: previousProjection.digest,
        },
      );
      assertPromotionCatalogAuthoritiesAreSelfConsistent(
        fixture,
        'omitted phantom',
      );
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
      }, testDependencies({
        verifyGithubReleaseCatalog:
          independentGithubVerifierForTest(fixture, currentCatalog),
      }));
      assert.equal(result.applied, false);
      assert.deepEqual(
        result.githubReleaseCatalog.source.activeCatalog.tags,
        currentCatalog.map((release) => release.tag),
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects an inactive tombstone with forged historical coordinates', async () => {
    const fixture = createFixture('catalog-independent-forged-tombstone');
    try {
      const {
        previousCatalog,
        currentCatalog,
        phantom,
      } = omittedPhantomPromotionCatalogsForTest();
      seedSharedPromotionCatalogForTest(fixture, previousCatalog);
      replaceActiveReleaseCatalogForTest(
        fixture.source,
        currentCatalog,
        { preserveInactive: true },
      );
      appendReleaseCatalogAuthority(fixture.source, {
        runId: 'catalog-independent-forged-tombstone',
        startedAt: '2026-07-05T01:00:00.000Z',
      });
      fixture.source.prepare(`
        UPDATE releases
        SET catalog_rank=0
        WHERE tag=?
      `).run(phantom.tag);
      closeFixtureDatabases(fixture);

      await assert.rejects(
        verifyPromotionGithubReleaseCatalog({
          dbPath: fixture.sourcePath,
          label: 'independent forged tombstone fixture',
          runtimeEnvPath: githubRuntimeEnvForTest(fixture.dir),
          observedAt: '2026-07-05T12:00:00.000Z',
          fetchCatalog: async () =>
            githubReleaseCatalogForTest(currentCatalog),
        }),
        /release catalog contains 1 row\(s\) outside the exact active GitHub catalog: "v-phantom-omitted" \(catalog_active=0\)/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('requires the source catalog receipt repository to exactly match independent GitHub', async () => {
    const fixture = createFixture('catalog-independent-repository-mismatch');
    try {
      const rows = activeReleaseCatalogRowsForTest(fixture.source);
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          verifyGithubReleaseCatalog: independentGithubVerifierForTest(
            fixture,
            rows,
            { repository: 'foreign/openclaw' },
          ),
        })),
        /Source snapshot release-catalog receipt repository "openclaw\/openclaw" does not exactly match independently fetched GitHub repository "foreign\/openclaw"/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  const allowedCatalogEvolutionCases = [
    {
      name: 'new releases',
      preserveInactive: false,
      mutate: (
        destinationCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => [
        promotionCatalogReleaseForTest({
          tag: 'v2026.7.5',
          nodeId: 'RE_v2026_7_5',
          tagCommitOid: '5'.repeat(40),
          publishedAt: '2026-07-05T00:00:00.000Z',
          prerelease: 0,
        }),
        ...destinationCatalog,
      ],
    },
    {
      name: 'deleted release',
      preserveInactive: true,
      mutate: (
        destinationCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => destinationCatalog.filter(
        (release) => release.tag !== 'v2026.7.2-beta.1',
      ),
    },
    {
      name: 'renamed release',
      preserveInactive: true,
      mutate: (
        destinationCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => destinationCatalog.map((release) =>
        release.tag === 'v2026.7.2'
          ? {
              ...release,
              tag: 'v2026.7.2-renamed',
              name: 'OpenClaw v2026.7.2-renamed',
              html_url:
                'https://github.com/openclaw/openclaw/releases/tag/v2026.7.2-renamed',
            }
          : release),
    },
  ];

  for (const testCase of allowedCatalogEvolutionCases) {
    it(`allows GitHub-proven catalog evolution: ${testCase.name}`, async () => {
      const fixture = createFixture(
        `catalog-live-allowed-${testCase.name.replaceAll(' ', '-')}`,
      );
      try {
        const destinationCatalog = destinationPromotionCatalogForTest();
        const sourceCatalog = testCase.mutate(destinationCatalog);
        seedSharedPromotionCatalogForTest(fixture, destinationCatalog);
        replaceActiveReleaseCatalogForTest(
          fixture.source,
          sourceCatalog,
          { preserveInactive: testCase.preserveInactive },
        );
        appendReleaseCatalogAuthority(fixture.source, {
          runId:
            `catalog-live-allowed-${testCase.name.replaceAll(' ', '-')}`,
          startedAt: '2026-07-05T01:00:00.000Z',
        });
        assertPromotionCatalogAuthoritiesAreSelfConsistent(
          fixture,
          testCase.name,
        );
        closeFixtureDatabases(fixture);
        const result = await promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          verifyGithubReleaseCatalog:
            independentGithubVerifierForTest(fixture, sourceCatalog),
        }));
        assert.equal(result.applied, false);
        assert.equal(
          result.githubReleaseCatalog.source.exactIdentityMatch,
          true,
        );
      } finally {
        fixture.cleanup();
      }
    });
  }

  const rejectedCatalogEvolutionCases = [
    {
      name: 'fabricated-newer-release',
      mutate: (
        liveCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => [
        promotionCatalogReleaseForTest({
          tag: 'v2026.7.5',
          nodeId: 'RE_fabricated_v2026_7_5',
          tagCommitOid: '5'.repeat(40),
          publishedAt: '2026-07-05T00:00:00.000Z',
          prerelease: 0,
        }),
        ...liveCatalog,
      ],
    },
    {
      name: 'omitted-live-release',
      mutate: (
        liveCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => liveCatalog.filter(
        (release) => release.tag !== 'v2026.7.2-beta.1',
      ),
    },
    ...[
      ['tag', (release: any) => ({
        ...release,
        tag: 'v2026.7.2-rewritten',
      })],
      ['node-id', (release: any) => ({
        ...release,
        node_id: 'RE_substituted_v2026_7_2',
      })],
      ['tag-commit-oid', (release: any) => ({
        ...release,
        catalog_tag_commit_oid: 'f'.repeat(40),
      })],
      ['prerelease', (release: any) => ({
        ...release,
        prerelease: 1,
      })],
      ['published-at', (release: any) => ({
        ...release,
        published_at: '2026-07-01T00:00:00.000Z',
      })],
      ['created-at', (release: any) => ({
        ...release,
        created_at: '2026-06-01T00:00:00.000Z',
      })],
      ['updated-at', (release: any) => ({
        ...release,
        updated_at: '2026-07-02T01:00:00.000Z',
      })],
      ['url', (release: any) => ({
        ...release,
        html_url: `${release.html_url}-forged`,
      })],
      ['name', (release: any) => ({
        ...release,
        name: 'Forged release name',
      })],
      ['body', (release: any) => ({
        ...release,
        body: 'Forged release body',
      })],
    ].map(([name, mutateRelease]) => ({
      name: `altered-${name}`,
      mutate: (
        liveCatalog: ReturnType<typeof destinationPromotionCatalogForTest>,
      ) => liveCatalog.map((release) =>
        release.tag === 'v2026.7.2'
          ? (mutateRelease as (release: any) => any)(release)
          : release),
    })),
  ];

  for (const testCase of rejectedCatalogEvolutionCases) {
    it(`rejects candidate catalog absent from GitHub: ${testCase.name}`, async () => {
      const fixture = createFixture(`catalog-live-rejected-${testCase.name}`);
      try {
        const liveCatalog = destinationPromotionCatalogForTest();
        const sourceCatalog = testCase.mutate(liveCatalog);
        seedSharedPromotionCatalogForTest(fixture, liveCatalog);
        replaceActiveReleaseCatalogForTest(fixture.source, sourceCatalog);
        appendReleaseCatalogAuthority(fixture.source, {
          runId: `catalog-live-rejected-${testCase.name}`,
          startedAt: '2026-07-05T01:00:00.000Z',
        });
        assertPromotionCatalogAuthoritiesAreSelfConsistent(
          fixture,
          testCase.name,
        );
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies({
            verifyGithubReleaseCatalog:
              independentGithubVerifierForTest(fixture, liveCatalog),
          })),
          /does not exactly match independent GitHub GraphQL authority/,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    });
  }

  it('rejects tampered, deleted, and reordered catalog receipt chains', async () => {
    const cases = [
      {
        name: 'tampered',
        mutate(db: DatabaseSync) {
          tamperLatestReleaseCatalogReceiptPayload(db);
        },
        pattern: /payload_json is not canonical|content hash mismatch/,
      },
      {
        name: 'deleted',
        mutate(db: DatabaseSync) {
          appendReleaseCatalogAuthority(db, {
            runId: 'catalog-refresh-after-deleted-link',
          });
          deleteFirstReleaseCatalogReceipt(db);
        },
        pattern: /previous content hash mismatch/,
      },
      {
        name: 'reordered',
        mutate(db: DatabaseSync) {
          appendReleaseCatalogAuthority(db, {
            runId: 'catalog-refresh-after-reordered-link',
          });
          reorderFirstTwoReleaseCatalogReceipts(db);
        },
        pattern: /previous content hash mismatch/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(`catalog-chain-${testCase.name}`);
      try {
        testCase.mutate(fixture.source);
        closeFixtureDatabases(fixture);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies()),
          testCase.pattern,
          testCase.name,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rechecks catalog receipt authority after staged writes', async () => {
    const fixture = createFixture('catalog-authority-staged-recheck');
    try {
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          recordPromotion: (input: Record<string, any>) => {
            const receipt = recordTestPromotion(input);
            const db = new DatabaseSync(input.dbPath);
            try {
              tamperLatestReleaseCatalogReceiptPayload(db);
            } finally {
              db.close();
            }
            return receipt;
          },
        })),
        /staged promotion with promotion receipt failed release catalog capture receipt integrity/,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('preserves the destination catalog receipt chain as the exact ordered prefix', async () => {
    const fixture = createFixture('catalog-receipt-prefix');
    try {
      appendReleaseCatalogAuthority(fixture.source, {
        runId: 'quality-catalog-refresh',
      });
      const sourceBefore = readReleaseCatalogReceiptRows(fixture.sourcePath);
      const destinationBefore =
        readReleaseCatalogReceiptRows(fixture.destinationPath);
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      const installed = readReleaseCatalogReceiptRows(fixture.destinationPath);
      assert.deepEqual(installed, sourceBefore);
      assert.deepEqual(
        installed.slice(0, destinationBefore.length),
        destinationBefore,
      );
      assert.deepEqual(
        verifyReleaseCatalogReceiptDb(fixture.destinationPath).problems,
        [],
      );
      assert.equal(
        result.destination.database.releaseCatalogReceipt.latestReceiptId,
        sourceBefore.at(-1)?.receipt_id,
      );
    } finally {
      fixture.cleanup();
    }

    const divergent = createFixture('catalog-receipt-divergence');
    try {
      appendReleaseCatalogAuthority(divergent.source, {
        runId: 'quality-catalog-refresh',
      });
      appendReleaseCatalogAuthority(divergent.destination, {
        runId: 'production-catalog-refresh',
      });
      closeFixtureDatabases(divergent);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: divergent.sourcePath,
          destinationPath: divergent.destinationPath,
        }, testDependencies()),
        /release catalog capture receipt chain is not the exact ordered prefix/,
      );
    } finally {
      divergent.cleanup();
    }
  });

  it('preserves the destination receipt chain and appends source-only operation history', async () => {
    const fixture = createFixture('operation-receipt-merge');
    try {
      for (const db of [fixture.source, fixture.destination]) {
        seedOperationReceiptRunWithCatalogAuthority(db, {
          runId: 'production-refresh',
          trigger: 'scheduled',
          startedAt: '2026-07-03T10:00:00.000Z',
        });
      }
      const sourceRun = seedOperationReceiptRunWithCatalogAuthority(
        fixture.source,
        {
          runId: 'quality-refresh',
          trigger: 'quality-build',
          startedAt: '2026-07-03T11:00:00.000Z',
        },
      );
      const destinationBefore = readOperationReceiptLedger(fixture.destinationPath);
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      const installed = readOperationReceiptLedger(fixture.destinationPath);
      const verification = verifyOperationReceiptLedger(installed);
      assert.deepEqual(verification.problems, []);
      assert.deepEqual(
        installed.attempts.map((row) => row.run_id),
        [
          'catalog-refresh-default',
          'production-refresh',
          'quality-refresh',
        ],
      );
      assert.equal(installed.stageEvents.length, 12);
      assert.deepEqual(
        installed.receipts.map((row) => row.run_id),
        [
          'catalog-refresh-default',
          'production-refresh',
          'quality-refresh',
        ],
      );
      assert.deepEqual(
        installed.receipts.slice(0, destinationBefore.receipts.length),
        destinationBefore.receipts,
      );
      assert.equal(
        installed.receipts[2].previous_content_hash,
        destinationBefore.receipts.at(-1)?.content_hash,
      );
      assert.equal(
        installed.receipts[2].previous_content_hash,
        sourceRun.receipt.previous_content_hash,
      );
      assert.equal(
        installed.receipts[2].content_hash,
        sourceRun.receipt.content_hash,
      );
      assert.equal(
        installed.receipts[2].payload_json,
        sourceRun.receipt.payload_json,
      );
      assert.equal(result.operationReceiptMerge.receipts.destinationChainPreservedAsPrefix, true);
      assert.equal(result.operationReceiptMerge.receipts.appendedSourceRows, 1);
      assert.equal(result.operationReceiptMerge.receipts.rehashedSourceRows, 0);
      assert.equal(result.operationReceiptMerge.receipts.identityMappings.length, 3);
      const identityMapping =
        result.operationReceiptMerge.receipts.identityMappings.find(
          (mapping: Record<string, any>) =>
            mapping.runId === 'quality-refresh',
        );
      assert.ok(identityMapping);
      assert.deepEqual(identityMapping, {
        runId: 'quality-refresh',
        receiptId: sourceRun.receipt.receipt_id,
        mergedRunId: 'quality-refresh',
        mergedReceiptId: sourceRun.receipt.receipt_id,
        originalHashes: {
          previousContentHash: sourceRun.receipt.previous_content_hash,
          contentHash: sourceRun.receipt.content_hash,
        },
        mergedHashes: {
          previousContentHash: installed.receipts[2].previous_content_hash,
          contentHash: installed.receipts[2].content_hash,
        },
        semanticIdentity: {
          originalDigest: identityMapping.semanticIdentity.originalDigest,
          mergedDigest: identityMapping.semanticIdentity.originalDigest,
          unchanged: true,
        },
      });
      assert.match(
        identityMapping.semanticIdentity.originalDigest,
        /^[0-9a-f]{64}$/,
      );
      assert.deepEqual(
        readOperationReceiptLedger(result.backupPath).receipts,
        destinationBefore.receipts,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('keeps persisted security outcomes valid when promotion re-chains their authorizing receipt', async () => {
    const fixture = createFixture('security-outcome-receipt-rechain');
    try {
      for (const db of [fixture.source, fixture.destination]) {
        seedOperationReceiptRunWithCatalogAuthority(db, {
          runId: 'production-refresh',
          trigger: 'scheduled',
          startedAt: '2026-01-02T09:00:00.000Z',
        });
      }
      const metadata = seedEmptyCompoundAdvisorySnapshot(fixture.source, {
        capturedAt: '2026-01-02T10:00:02.000Z',
      });
      fixture.source.prepare(`
        INSERT INTO meta (key, value)
        VALUES (?, ?)
        ON CONFLICT(key) DO UPDATE SET value=excluded.value
      `).run(
        ADVISORY_SNAPSHOT_V2_META_KEY,
        canonicalOperationJson(metadata),
      );
      const sourceRun = seedOperationReceiptRunWithCatalogAuthority(
        fixture.source,
        {
          runId: 'quality-refresh-security',
          trigger: 'quality-build',
          startedAt: '2026-01-02T10:00:00.000Z',
          advisoryCatalog: compoundAdvisoryReceiptBinding(metadata),
        },
      );
      const sourceLedger = readOperationReceiptLedger(fixture.sourcePath);
      const sourceAuthorization = compoundAdvisoryAuthorization(
        metadata,
        sourceLedger,
      );
      assert.deepEqual(sourceAuthorization.problems, []);
      assert.equal(sourceAuthorization.authorizations.length, 1);
      const sourceSnapshots =
        buildCompoundAdvisorySnapshotValidationEvidence(
          [{ metadata, scoreRows: [] }],
          sourceAuthorization.authorizations,
        );
      assert.equal(sourceSnapshots.length, 1);

      const forecast = securityPromotionForecast();
      const sourceAssessment = assessReleaseValidationObservation(
        securityPromotionObservationInput(forecast, sourceSnapshots),
      );
      assert.equal(sourceAssessment.status, 'matured');
      if (sourceAssessment.status !== 'matured') return;
      fixture.source.prepare(`
        INSERT INTO release_validation_outcome_observations (
          id, observation_id, decision_id, horizon_code, status, payload
        )
        VALUES (1, ?, ?, 'security_30d', 'matured', ?)
      `).run(
        'security-outcome-receipt-rechain',
        forecast.decision_id,
        JSON.stringify(sourceAssessment.outcome),
      );
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies({
        readAdvisoryAuditProjection: readPromotionAdvisoryAuditProjection,
      }));

      const installedLedger = readOperationReceiptLedger(
        fixture.destinationPath,
      );
      assert.deepEqual(
        verifyOperationReceiptLedger(installedLedger).problems,
        [],
      );
      const installedReceipt = installedLedger.receipts.find(
        (row) => row.run_id === sourceRun.receipt.run_id,
      );
      assert.ok(installedReceipt);
      assert.equal(
        installedReceipt.content_hash,
        sourceRun.receipt.content_hash,
      );
      assert.equal(
        installedReceipt.previous_content_hash,
        sourceRun.receipt.previous_content_hash,
      );
      const installedAuthorization = compoundAdvisoryAuthorization(
        metadata,
        installedLedger,
      );
      assert.deepEqual(installedAuthorization.problems, []);
      assert.equal(installedAuthorization.authorizations.length, 1);
      assert.equal(
        installedAuthorization.authorizations[0].receiptSemanticIdentity,
        sourceAuthorization.authorizations[0].receiptSemanticIdentity,
      );

      const installedSnapshots =
        buildCompoundAdvisorySnapshotValidationEvidence(
          [{ metadata, scoreRows: [] }],
          installedAuthorization.authorizations,
        );
      const persistedOutcome = JSON.parse(String(readRows(
        fixture.destinationPath,
        `SELECT payload
         FROM release_validation_outcome_observations
         WHERE observation_id='security-outcome-receipt-rechain'`,
      )[0]?.payload));
      const installedAssessment = assessReleaseValidationObservation(
        securityPromotionObservationInput(forecast, installedSnapshots),
      );
      assert.equal(installedAssessment.status, 'matured');
      if (installedAssessment.status !== 'matured') return;
      assert.deepEqual(installedAssessment.outcome, persistedOutcome);
      assert.equal(
        persistedOutcome.security.snapshotProvenance.publication
          .receiptSemanticIdentity,
        installedAuthorization.authorizations[0].receiptSemanticIdentity,
      );
      assert.equal(
        result.operationReceiptMerge.receipts.rehashedSourceRows,
        0,
      );
      const projectionEvidence = result.advisoryPublicAuditProjection;
      assert.equal(projectionEvidence.exactAcrossCompletedStages, true);
      assert.match(projectionEvidence.source.digest, /^[0-9a-f]{64}$/);
      assert.equal(
        projectionEvidence.staged.digest,
        projectionEvidence.source.digest,
      );
      assert.equal(
        projectionEvidence.install.digest,
        projectionEvidence.source.digest,
      );
      assert.equal(
        projectionEvidence.installed.digest,
        projectionEvidence.source.digest,
      );
      assert.equal(
        projectionEvidence.installed.projection.authorizingReceipt
          .receiptSemanticIdentity,
        sourceAuthorization.authorizations[0].receiptSemanticIdentity,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects an unverified advisory public-audit projection before staging', async () => {
    const fixture = createFixture('advisory-projection-unverified');
    try {
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          readAdvisoryAuditProjection: () => ({
            ...testAdvisoryAuditProjection(),
            verified: false,
            failedCount: 1,
            problems: ['injected advisory authorization failure'],
          }),
        })),
        /source snapshot does not have a verified receipt-authorized advisory public-audit projection/,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects advisory public-audit projection drift at every promotion boundary', async () => {
    for (const boundary of [
      {
        label: 'staged promotion with promotion receipt',
        error: /Staged promotion changed the receipt-authorized advisory public-audit projection/,
        swapped: false,
      },
      {
        label: 'metadata-preserving staged promotion',
        error: /Metadata-preserving staged promotion changed the receipt-authorized advisory public-audit projection/,
        swapped: false,
      },
      {
        label: 'installed destination',
        error: /original destination was restored automatically.*Installed destination changed the receipt-authorized advisory public-audit projection/s,
        swapped: true,
      },
    ]) {
      const fixture = createFixture(
        `advisory-projection-drift-${boundary.label.replaceAll(' ', '-')}`,
      );
      try {
        closeFixtureDatabases(fixture);
        const projection = testAdvisoryAuditProjection();
        const driftedProjection = structuredClone(projection);
        driftedProjection.authorizingReceipt.receiptSemanticIdentity =
          '6'.repeat(64);

        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
            apply: true,
          }, testDependencies({
            readAdvisoryAuditProjection: ({ label }: { label: string }) =>
              label === boundary.label ? driftedProjection : projection,
          })),
          boundary.error,
        );
        assert.equal(readPromotionState(fixture.destinationPath), 'initial');
        assert.equal(
          backupFiles(fixture).length,
          boundary.label === 'staged promotion with promotion receipt' ? 0 : 1,
        );
        if (boundary.swapped) {
          assert.equal(backupFiles(fixture).length, 1);
        }
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects conflicting terminal receipts before rewriting operation provenance', async () => {
    const fixture = createFixture('operation-receipt-conflict');
    try {
      seedOperationReceiptRun(fixture.source, {
        runId: 'shared-refresh',
        trigger: 'quality-build',
        status: 'abandoned',
      });
      seedOperationReceiptRun(fixture.destination, {
        runId: 'shared-refresh',
        trigger: 'scheduled',
        status: 'abandoned',
      });
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /Refresh capture receipt "shared-refresh" conflicts.*cannot preserve both terminal results/s,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('installs source score-evidence snapshots and retains destination snapshots in the backup', async () => {
    const fixture = createFixture('score-evidence-install-backup');
    try {
      seedScoreEvidenceSnapshots(fixture.source, {
        issueNumber: 101,
        issueState: 'open',
        releaseTag: 'source-release',
      });
      seedScoreEvidenceSnapshots(fixture.destination, {
        issueNumber: 202,
        issueState: 'closed',
        releaseTag: 'destination-release',
      });
      const sourceEvidence = readScoreEvidenceRows(fixture.sourcePath);
      const destinationEvidence = readScoreEvidenceRows(fixture.destinationPath);
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      assert.deepEqual(readScoreEvidenceRows(fixture.destinationPath), sourceEvidence);
      assert.deepEqual(readScoreEvidenceRows(result.backupPath), destinationEvidence);
    } finally {
      fixture.cleanup();
    }
  });

  it('restores destination score-evidence snapshots during automatic rollback', async () => {
    const fixture = createFixture('score-evidence-rollback');
    try {
      seedScoreEvidenceSnapshots(fixture.source, {
        issueNumber: 101,
        issueState: 'open',
        releaseTag: 'source-release',
      });
      seedScoreEvidenceSnapshots(fixture.destination, {
        issueNumber: 202,
        issueState: 'closed',
        releaseTag: 'destination-release',
      });
      const destinationEvidence = readScoreEvidenceRows(fixture.destinationPath);
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            const db = new DatabaseSync(to);
            try {
              db.prepare(`
                UPDATE promotion_state
                SET value='force-post-install-mismatch'
                WHERE key='state'
              `).run();
            } finally {
              db.close();
            }
          },
        })),
        /original destination was restored automatically.*logical contents differ/s,
      );
      assert.deepEqual(readScoreEvidenceRows(fixture.destinationPath), destinationEvidence);
      const [backupPath] = backupFiles(fixture);
      assert.ok(backupPath);
      assert.deepEqual(readScoreEvidenceRows(backupPath), destinationEvidence);
    } finally {
      fixture.cleanup();
    }
  });

  it('aborts instead of rewriting conflicting destination-preserved identities', async () => {
    const fixture = createFixture('preserved-identity-conflict');
    try {
      for (const [db, message] of [
        [fixture.source, 'source message'],
        [fixture.destination, 'destination message'],
      ] as const) {
        db.prepare(`
          INSERT INTO ingestion_evidence_failures (
            id, run_id, occurred_at, source, message, scoring_blocking
          )
          VALUES (1, 'run', '2026-07-03T01:00:00Z', 'issues', ?, 1)
        `).run(message);
      }
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies()),
        /primary-key conflict.*cannot preserve both rows without changing evidence identity/s,
      );
      assert.equal(
        readRows(
          fixture.destinationPath,
          `SELECT message FROM ingestion_evidence_failures WHERE id=1`,
        )[0].message,
        'destination message',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('reports active source activity in dry-run and refuses it during every apply', async () => {
    const activeLease = createFixture('active-source-refresh-lease');
    try {
      seedRefreshLease(
        activeLease.source,
        'github-refresh',
        'active-holder',
        '2026-07-03T12:00:00Z',
        '2026-07-03T13:00:00Z',
      );
      closeFixtureDatabases(activeLease);
      const sourceHolder = {
        pid: 444,
        command: 'quality-refresh',
        paths: [activeLease.sourcePath],
        accesses: ['u'],
      };

      const dryRun = await promoteQualityDb({
        sourcePath: activeLease.sourcePath,
        destinationPath: activeLease.destinationPath,
      }, testDependencies({
        listHolders: (
          path: string,
          options: { phase?: string },
        ) => path === activeLease.sourcePath && options.phase?.startsWith('source-')
          ? [sourceHolder]
          : [],
      }));
      assert.equal(dryRun.applied, false);
      assert.equal(dryRun.reportValidity.durableEvidence, false);
      assert.equal(dryRun.reportValidity.authorizesLaterApply, false);
      assert.equal(dryRun.reportValidity.applyRequiresFreshActivityRevalidation, true);
      assert.equal(dryRun.activity.source.active, true);
      assert.equal(dryRun.activity.source.beforeSnapshot.holderCount, 1);
      assert.equal(dryRun.activity.source.beforeSnapshot.refreshLeases.activeCount, 1);
      assert.equal(dryRun.activity.destination.active, false);
      assert.equal(dryRun.activity.applyRevalidation, null);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: activeLease.sourcePath,
          destinationPath: activeLease.destinationPath,
          apply: true,
        }, testDependencies()),
        /source database has 1 active or malformed refresh lease/i,
      );
      assert.equal(backupFiles(activeLease).length, 0);
    } finally {
      activeLease.cleanup();
    }

    const activeHolder = createFixture('active-source-holder');
    try {
      closeFixtureDatabases(activeHolder);
      const holder = {
        pid: 445,
        command: 'candidate-server',
        paths: [activeHolder.sourcePath],
        accesses: ['r'],
      };
      await assert.rejects(
        promoteQualityDb({
          sourcePath: activeHolder.sourcePath,
          destinationPath: activeHolder.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            path: string,
            options: { phase?: string },
          ) => path === activeHolder.sourcePath && options.phase === 'source-before-snapshot'
            ? [holder]
            : [],
        })),
        /Source database has active holders.*cannot use an earlier dry-run report/s,
      );
      assert.equal(backupFiles(activeHolder).length, 0);
    } finally {
      activeHolder.cleanup();
    }

    const revalidation = createFixture('source-activity-revalidation');
    try {
      closeFixtureDatabases(revalidation);
      const holder = {
        pid: 446,
        command: 'late-refresh',
        paths: [revalidation.sourcePath],
        accesses: ['u'],
      };
      await assert.rejects(
        promoteQualityDb({
          sourcePath: revalidation.sourcePath,
          destinationPath: revalidation.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            path: string,
            options: { phase?: string },
          ) => path === revalidation.sourcePath &&
            options.phase === 'source-before-final-snapshot'
            ? [holder]
            : [],
        })),
        /Source database has active holders/,
      );
      assert.equal(backupFiles(revalidation).length, 0);
    } finally {
      revalidation.cleanup();
    }
  });

  it('aborts when source contents drift after staging even without a persistent holder', async () => {
    const fixture = createFixture('source-content-drift-after-staging');
    try {
      closeFixtureDatabases(fixture);
      let mutated = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            path: string,
            options: { phase?: string },
          ) => {
            if (
              path === fixture.sourcePath &&
              options.phase === 'source-after-staging' &&
              !mutated
            ) {
              mutated = true;
              const db = new DatabaseSync(fixture.sourcePath);
              try {
                db.prepare(`
                  UPDATE promotion_state
                  SET value='drifted-after-staging'
                  WHERE key='state'
                `).run();
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /source database after promotion staging logical contents or database identity drifted/i,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('clears empty source read sidecars but rejects a data-bearing source WAL', async () => {
    const emptySidecars = createFixture('empty-source-read-sidecars');
    try {
      closeFixtureDatabases(emptySidecars);
      let injected = false;
      const result = await promoteQualityDb({
        sourcePath: emptySidecars.sourcePath,
        destinationPath: emptySidecars.destinationPath,
      }, testDependencies({
        snapshotDatabase(sourcePath: string, snapshotPath: string) {
          copyDatabaseSnapshotForTest(sourcePath, snapshotPath);
          if (sourcePath !== emptySidecars.sourcePath || injected) return;
          injected = true;
          writeFileSync(`${sourcePath}-wal`, '');
          writeFileSync(`${sourcePath}-shm`, Buffer.alloc(32 * 1024));
        },
      }));
      assert.equal(result.applied, false);
      assert.equal(injected, true);
      assert.equal(existsSync(`${emptySidecars.sourcePath}-wal`), false);
      assert.equal(existsSync(`${emptySidecars.sourcePath}-shm`), false);
    } finally {
      emptySidecars.cleanup();
    }

    const dataBearingWal = createFixture('data-bearing-source-wal');
    try {
      closeFixtureDatabases(dataBearingWal);
      let injected = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: dataBearingWal.sourcePath,
          destinationPath: dataBearingWal.destinationPath,
        }, testDependencies({
          snapshotDatabase(sourcePath: string, snapshotPath: string) {
            copyDatabaseSnapshotForTest(sourcePath, snapshotPath);
            if (sourcePath !== dataBearingWal.sourcePath || injected) return;
            injected = true;
            writeFileSync(`${sourcePath}-wal`, 'unverified-write');
          },
        })),
        /non-empty SQLite wal sidecar/,
      );
      assert.equal(injected, true);
      assert.equal(backupFiles(dataBearingWal).length, 0);
    } finally {
      dataBearingWal.cleanup();
    }
  });

  it('aborts when the source inode is replaced at the final swap boundary', async () => {
    const fixture = createFixture('source-inode-drift-final-boundary');
    try {
      closeFixtureDatabases(fixture);
      let replaced = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            path: string,
            options: { phase?: string },
          ) => {
            if (
              path === fixture.sourcePath &&
              options.phase === 'source-immediately-before-swap' &&
              !replaced
            ) {
              replaced = true;
              const previousPath = join(fixture.dir, 'quality-before-replacement.db');
              renameSync(fixture.sourcePath, previousPath);
              copyFileSync(previousPath, fixture.sourcePath);
            }
            return [];
          },
        })),
        /finalization failed before the swap.*changed inode or path identity/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('rechecks source quiescence after awaited GitHub verification before the final swap', async () => {
    const fixture = createFixture('source-holder-after-github-verification');
    try {
      closeFixtureDatabases(fixture);
      let finalGithubVerificationCompleted = false;
      let renameCalls = 0;
      const postGithubSourcePhases: string[] = [];
      const holder = {
        pid: 447,
        command: 'late-candidate-writer',
        paths: [`${fixture.sourcePath}-journal`],
        accesses: ['u'],
      };

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          verifyGithubReleaseCatalog: async ({
            dbPath,
            label,
            observedAt,
          }: {
            dbPath: string;
            label: string;
            observedAt: string;
          }) => {
            const proof = testGithubReleaseCatalogProof(dbPath, observedAt);
            if (label === 'source database immediately before swap') {
              await Promise.resolve();
              finalGithubVerificationCompleted = true;
            }
            return proof;
          },
          listHolders: (
            path: string,
            options: { phase?: string },
          ) => {
            if (path !== fixture.sourcePath || !finalGithubVerificationCompleted) {
              return [];
            }
            postGithubSourcePhases.push(options.phase ?? '');
            return [holder];
          },
          rename(from: string, to: string) {
            renameCalls += 1;
            renameSync(from, to);
          },
        })),
        /Source database has active holders/,
      );
      assert.equal(finalGithubVerificationCompleted, true);
      assert.ok(postGithubSourcePhases.length > 0);
      assert.equal(renameCalls, 0);
      assert.equal(readPromotionState(fixture.destinationPath), 'initial');
    } finally {
      fixture.cleanup();
    }
  });

  it('rechecks destination contents after the final source snapshot before swap', async () => {
    const fixture = createFixture('destination-drift-during-final-source-snapshot');
    try {
      closeFixtureDatabases(fixture);
      let destinationMutated = false;
      let renameCalls = 0;

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          snapshotDatabase(sourcePath: string, snapshotPath: string) {
            copyDatabaseSnapshotForTest(sourcePath, snapshotPath);
            if (
              sourcePath !== fixture.sourcePath ||
              !snapshotPath.includes('.source-final-boundary.sqlite') ||
              destinationMutated
            ) {
              return;
            }
            destinationMutated = true;
            const destination = new DatabaseSync(fixture.destinationPath);
            try {
              setPromotionState(
                destination,
                'destination-mutated-during-final-source-snapshot',
              );
            } finally {
              destination.close();
            }
          },
          rename(from: string, to: string) {
            renameCalls += 1;
            renameSync(from, to);
          },
        })),
        /Destination logical contents changed immediately before promotion swap/,
      );
      assert.equal(destinationMutated, true);
      assert.equal(renameCalls, 0);
      assert.equal(
        readPromotionState(fixture.destinationPath),
        'destination-mutated-during-final-source-snapshot',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('does not yield after the final source boundary hold before swap', async () => {
    const fixture = createFixture('no-yield-after-source-boundary');
    try {
      closeFixtureDatabases(fixture);
      let sourceBoundaryObserved = false;
      let boundaryMicrotaskRan = false;
      let renameCalls = 0;

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies({
        listHolders: (
          path: string,
          options: { phase?: string },
        ) => {
          if (
            path === fixture.sourcePath &&
            options.phase === 'source-at-swap-boundary'
          ) {
            assert.equal(sourceBoundaryObserved, false);
            sourceBoundaryObserved = true;
            queueMicrotask(() => {
              boundaryMicrotaskRan = true;
            });
          }
          return [];
        },
        rename(from: string, to: string) {
          renameCalls += 1;
          assert.equal(sourceBoundaryObserved, true);
          assert.equal(boundaryMicrotaskRan, false);
          renameSync(from, to);
        },
      }));

      assert.equal(result.applied, true);
      assert.equal(renameCalls, 1);
      assert.equal(boundaryMicrotaskRan, true);
    } finally {
      fixture.cleanup();
    }
  });

  it('allows expired source leases, reports them as stale, and strips them from the install', async () => {
    const fixture = createFixture('stale-source-refresh-lease');
    try {
      seedRefreshLease(
        fixture.source,
        'stale-refresh',
        'stale-holder',
        '2026-07-03T10:00:00Z',
        '2026-07-03T11:00:00Z',
      );
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      assert.equal(result.applied, true);
      assert.equal(result.activity.source.active, false);
      assert.equal(result.source.snapshotProof.refreshLeases.rowCount, 1);
      assert.equal(result.source.snapshotProof.refreshLeases.activeCount, 0);
      assert.equal(result.source.snapshotProof.refreshLeases.staleCount, 1);
      assert.equal(result.leaseSanitization.strippedCount, 1);
      assert.equal(result.leaseSanitization.remainingCount, 0);
      assert.equal(
        readRows(fixture.destinationPath, `SELECT COUNT(*) AS count FROM refresh_leases`)[0].count,
        0,
      );
      assert.equal(
        readRows(fixture.sourcePath, `SELECT COUNT(*) AS count FROM refresh_leases`)[0].count,
        1,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('keeps a clean apply unchanged while recording fresh source and destination checks', async () => {
    const fixture = createFixture('clean-activity-apply');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      assert.equal(result.applied, true);
      assert.equal(readPromotionState(fixture.destinationPath), 'source');
      assert.equal(result.activity.source.active, false);
      assert.equal(result.activity.destination.active, false);
      assert.equal(
        result.activity.applyRevalidation.beforeFinalSnapshot.source.active,
        false,
      );
      assert.equal(
        result.activity.applyRevalidation.beforeFinalSnapshot.destination.active,
        false,
      );
      assert.equal(
        result.activity.applyRevalidation.immediatelyBeforeSwap.source.active,
        false,
      );
      assert.equal(
        result.activity.applyRevalidation.immediatelyBeforeSwap.destination.active,
        false,
      );
      assert.equal(result.reportValidity.authorizesLaterApply, false);
      assert.ok(result.backupPath);
    } finally {
      fixture.cleanup();
    }
  });

  it('refuses an active destination refresh lease during apply', async () => {
    const fixture = createFixture('active-destination-refresh-lease');
    try {
      seedRefreshLease(
        fixture.destination,
        'github-refresh',
        'production-holder',
        '2026-07-03T12:00:00Z',
        '2026-07-03T13:00:00Z',
      );
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies()),
        /destination database at invocation has 1 active or malformed refresh lease/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('aborts if destination-preserved evidence changes during staging', async () => {
    const fixture = createFixture('concurrent-preserved-evidence');
    try {
      closeFixtureDatabases(fixture);
      let mutated = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (options.phase === 'before-final-snapshot' && !mutated) {
              mutated = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                db.prepare(`
                  INSERT INTO ingestion_evidence_failures (
                    id, run_id, occurred_at, source, message, scoring_blocking
                  )
                  VALUES (5, 'late-run', '2026-07-03T12:35:00Z',
                          'late-writer', 'late failure', 1)
                `).run();
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /Destination evidence changed while the promotion was staged: ingestion_evidence_failures/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('aborts if either destination score-evidence snapshot table changes during staging', async () => {
    const fixture = createFixture('concurrent-score-evidence');
    try {
      closeFixtureDatabases(fixture);
      let mutated = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (options.phase === 'before-final-snapshot' && !mutated) {
              mutated = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                seedScoreEvidenceSnapshots(db, {
                  issueNumber: 303,
                  issueState: 'open',
                  releaseTag: 'late-release',
                });
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /Destination evidence changed while the promotion was staged: issue_state_event_snapshots, release_closure_dependency_snapshots/,
      );
      assert.equal(backupFiles(fixture).length, 0);
      assert.deepEqual(readScoreEvidenceKeys(fixture.destinationPath), {
        issueNumbers: [303],
        releaseTags: ['late-release'],
      });
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects concurrent immutable destination ledger drift before checkpoint or swap', async () => {
    const fixture = createFixture('concurrent-ledger-drift');
    try {
      closeFixtureDatabases(fixture);
      let mutated = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (options.phase === 'before-final-snapshot' && !mutated) {
              mutated = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                db.prepare(`
                  INSERT INTO release_validation_forecasts (
                    id, decision_id, opportunity_code, latest_release_tag,
                    score_model_version, prompt_version, payload
                  )
                  VALUES (
                    1, 'concurrent-decision', 'first_verified_after_24h',
                    'v-concurrent', 'test-model', 1, '{}'
                  )
                `).run();
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /Destination immutable ledgers changed while the promotion was staged: release_validation_forecasts/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects destination operation receipt history appended during staging', async () => {
    const fixture = createFixture('concurrent-operation-receipt-drift');
    try {
      closeFixtureDatabases(fixture);
      let mutated = false;
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (options.phase === 'before-final-snapshot' && !mutated) {
              mutated = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                seedOperationReceiptRunWithCatalogAuthority(db, {
                  runId: 'late-production-refresh',
                  trigger: 'scheduled',
                  startedAt: '2026-07-03T12:30:00.000Z',
                });
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /Destination immutable ledgers changed while the promotion was staged:.*refresh_operation_attempts.*refresh_operation_stage_events.*refresh_capture_receipts/s,
      );
      assert.equal(backupFiles(fixture).length, 0);
      assert.deepEqual(
        readOperationReceiptLedger(fixture.destinationPath).receipts
          .map((row) => row.run_id),
        ['catalog-refresh-default', 'late-production-refresh'],
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects bypassable triggers and partial non-enforcing unique indexes', async () => {
    const whenTrigger = createFixture('when-trigger');
    try {
      whenTrigger.source.exec(`
        DROP TRIGGER release_score_audit_history_no_delete;
        CREATE TRIGGER release_score_audit_history_no_delete
        BEFORE DELETE ON release_score_audit_history
        WHEN 0
        BEGIN
          SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
        END;
      `);
      closeFixtureDatabases(whenTrigger);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: whenTrigger.sourcePath,
          destinationPath: whenTrigger.destinationPath,
        }, testDependencies()),
        /missing required append-only trigger release_score_audit_history_no_delete/,
      );
    } finally {
      whenTrigger.cleanup();
    }

    const partialHistory = createFixture('partial-history-index');
    try {
      replaceHistoryUniqueWithPartial(partialHistory.source);
      closeFixtureDatabases(partialHistory);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: partialHistory.sourcePath,
          destinationPath: partialHistory.destinationPath,
        }, testDependencies()),
        /missing a full, enforcing UNIQUE\(run_id, release_tag\)/,
      );
    } finally {
      partialHistory.cleanup();
    }

    const partialMatured = createFixture('partial-matured-index');
    try {
      partialMatured.source.exec(`
        DROP INDEX idx_release_validation_outcomes_one_matured;
        CREATE UNIQUE INDEX idx_release_validation_outcomes_one_matured
        ON release_validation_outcome_observations(decision_id, horizon_code)
        WHERE 0;
      `);
      closeFixtureDatabases(partialMatured);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: partialMatured.sourcePath,
          destinationPath: partialMatured.destinationPath,
        }, testDependencies()),
        /missing the enforcing partial unique index idx_release_validation_outcomes_one_matured/,
      );
    } finally {
      partialMatured.cleanup();
    }

    const legacyForecastIdentity = createFixture('legacy-forecast-identity');
    try {
      legacyForecastIdentity.source.exec(`
        CREATE UNIQUE INDEX legacy_release_validation_forecast_identity
        ON release_validation_forecasts(opportunity_code, latest_release_tag)
      `);
      closeFixtureDatabases(legacyForecastIdentity);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: legacyForecastIdentity.sourcePath,
          destinationPath: legacyForecastIdentity.destinationPath,
        }, testDependencies()),
        /legacy identity that omits code_revision/,
      );
    } finally {
      legacyForecastIdentity.cleanup();
    }
  });

  it('rejects older or incompatible source schemas before creating a backup', async () => {
    const fixture = createFixture('older-schema');
    try {
      fixture.source.exec('DROP TABLE promotion_state');
      fixture.destination.exec('PRAGMA user_version = 1');
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies()),
        /Source schema is older or incompatible with the destination/,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects equal-userVersion schema drift while allowing a forward-compatible source', async () => {
    const equalVersion = createFixture('equal-version-schema-drift');
    try {
      equalVersion.source.exec(`
        CREATE TABLE source_only_equal_version_schema (
          id INTEGER PRIMARY KEY,
          value TEXT NOT NULL
        )
      `);
      closeFixtureDatabases(equalVersion);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: equalVersion.sourcePath,
          destinationPath: equalVersion.destinationPath,
        }, testDependencies()),
        /schema digest differs from the destination at equal user_version 0/,
      );
    } finally {
      equalVersion.cleanup();
    }

    const forwardVersion = createFixture('forward-version-schema');
    try {
      forwardVersion.destination.exec('PRAGMA user_version = 1');
      forwardVersion.source.exec(`
        PRAGMA user_version = 2;
        CREATE TABLE source_only_forward_schema (
          id INTEGER PRIMARY KEY,
          value TEXT NOT NULL
        );
      `);
      closeFixtureDatabases(forwardVersion);
      const result = await promoteQualityDb({
        sourcePath: forwardVersion.sourcePath,
        destinationPath: forwardVersion.destinationPath,
      }, testDependencies());
      assert.equal(result.source.database.userVersion, 2);
      assert.equal(result.destination.database.userVersion, 1);
      assert.notEqual(
        result.source.database.schemaDigest,
        result.destination.database.schemaDigest,
      );
    } finally {
      forwardVersion.cleanup();
    }

    const forwardTrigger = createFixture('forward-version-extra-trigger');
    try {
      forwardTrigger.destination.exec('PRAGMA user_version = 1');
      forwardTrigger.source.exec(`
        PRAGMA user_version = 2;
        CREATE TABLE source_only_forward_trigger_target (
          id INTEGER PRIMARY KEY,
          value TEXT NOT NULL
        );
        CREATE TRIGGER malicious_source_only_forward_trigger
        AFTER INSERT ON source_only_forward_trigger_target
        BEGIN
          DELETE FROM releases;
        END;
      `);
      closeFixtureDatabases(forwardTrigger);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: forwardTrigger.sourcePath,
          destinationPath: forwardTrigger.destinationPath,
        }, testDependencies()),
        /Source schema has triggers absent from the destination: trigger:malicious_source_only_forward_trigger/,
      );
    } finally {
      forwardTrigger.cleanup();
    }
  });

  it('requires canonical score-evidence schemas even when the destination predates them', async () => {
    const missingIndex = createFixture('missing-state-snapshot-index');
    try {
      missingIndex.source.exec('DROP INDEX idx_issue_state_event_snapshots_verified');
      dropScoreEvidenceSnapshotTables(missingIndex.destination);
      closeFixtureDatabases(missingIndex);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: missingIndex.sourcePath,
          destinationPath: missingIndex.destinationPath,
        }, testDependencies()),
        /missing canonical index idx_issue_state_event_snapshots_verified on issue_state_event_snapshots/,
      );
    } finally {
      missingIndex.cleanup();
    }

    const invalidDependencyPrimaryKey = createFixture('invalid-dependency-snapshot-pk');
    try {
      invalidDependencyPrimaryKey.source.exec(`
        ALTER TABLE release_closure_dependency_snapshots
          RENAME TO release_closure_dependency_snapshots_old;
        CREATE TABLE release_closure_dependency_snapshots (
          release_tag TEXT NOT NULL,
          schema_version INTEGER NOT NULL,
          analyzer_version INTEGER NOT NULL,
          issue_numbers_json TEXT NOT NULL,
          dependency_digest TEXT NOT NULL,
          dependency_row_count INTEGER NOT NULL,
          captured_at TEXT NOT NULL
        );
        DROP TABLE release_closure_dependency_snapshots_old;
      `);
      dropScoreEvidenceSnapshotTables(invalidDependencyPrimaryKey.destination);
      closeFixtureDatabases(invalidDependencyPrimaryKey);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: invalidDependencyPrimaryKey.sourcePath,
          destinationPath: invalidDependencyPrimaryKey.destinationPath,
        }, testDependencies()),
        /non-canonical columns or constraints for release_closure_dependency_snapshots/,
      );
    } finally {
      invalidDependencyPrimaryKey.cleanup();
    }
  });

  it('allows a canonical source to promote over a destination that predates score-evidence tables', async () => {
    const fixture = createFixture('destination-without-score-evidence');
    try {
      fixture.source.exec('PRAGMA user_version = 1');
      dropScoreEvidenceSnapshotTables(fixture.destination);
      closeFixtureDatabases(fixture);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
      }, testDependencies());
      assert.equal(result.applied, false);
      assert.equal(
        result.destination.database.destinationDriftTables.issue_state_event_snapshots.present,
        false,
      );
      assert.equal(
        result.staged.database.destinationDriftTables.issue_state_event_snapshots.present,
        true,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('detects a holder reopened immediately before swap and retains the backup', async () => {
    const fixture = createFixture('holder-before-swap');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      const holder = {
        pid: 811,
        command: 'reopened-server',
        paths: [fixture.destinationPath],
        accesses: ['u'],
      };

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => options.phase === 'immediately-before-swap' ? [holder] : [],
        })),
        /finalization failed before the swap.*holder race detected immediately before swap/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('detects old-inode writers immediately after swap and rolls back', async () => {
    const fixture = createFixture('old-inode-writer');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      const oldInodeWriter = {
        pid: 812,
        command: 'stale-writer',
        paths: [`${fixture.destinationPath} (deleted)`],
        accesses: ['w'],
      };

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => options.phase === 'old-inode-immediately-after-swap'
            ? [oldInodeWriter]
            : [],
        })),
        /original destination was restored automatically.*holder race detected immediately after swap/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('finds a real writable holder after its database inode is replaced', {
    skip: !lsofAvailable,
  }, async () => {
    const fixture = createFixture('real-old-inode-holder');
    let child: ReturnType<typeof spawn> | null = null;
    try {
      closeFixtureDatabases(fixture);
      const familyPaths = [
        fixture.destinationPath,
        `${fixture.destinationPath}-wal`,
        `${fixture.destinationPath}-shm`,
        `${fixture.destinationPath}-journal`,
      ];
      for (const sidecarPath of familyPaths.slice(1)) {
        writeFileSync(sidecarPath, 'holder-sidecar');
      }
      const oldFamilyIdentity = familyPaths.map((path) => {
        const info = statSync(path, { bigint: true });
        return {
          path,
          device: String(info.dev),
          inode: String(info.ino),
        };
      });
      child = spawn(process.execPath, [
        '-e',
        `
          const fs = require('node:fs');
          for (const path of process.argv.slice(1)) fs.openSync(path, 'r+');
          process.stdout.write('ready\\n');
          setInterval(() => {}, 1000);
        `,
        ...familyPaths,
      ], { stdio: ['ignore', 'pipe', 'pipe'] });
      await waitForChildReady(child);

      const currentHolder = listDestinationHolders(fixture.destinationPath)
        .find((holder) => holder.pid === child?.pid);
      assert.ok(currentHolder);
      const heldRealPaths = currentHolder.paths.map((path) => realpathSync(path));
      for (const familyPath of familyPaths) {
        assert.ok(heldRealPaths.includes(realpathSync(familyPath)));
      }

      const oldPath = join(fixture.dir, 'old-primary.db');
      renameSync(fixture.destinationPath, oldPath);
      for (const sidecarPath of familyPaths.slice(1)) {
        rmSync(sidecarPath, { force: true });
      }
      copyFileSync(fixture.sourcePath, fixture.destinationPath);
      rmSync(oldPath, { force: true });
      for (const member of oldFamilyIdentity) {
        const oldInodeWriters = listDestinationHolders(
          fixture.destinationPath,
          {
            identity: { family: [member] },
            writersOnly: true,
          },
        );
        assert.ok(
          oldInodeWriters.some((holder) => holder.pid === child?.pid),
          `expected deleted-inode holder for ${member.path}`,
        );
      }
    } finally {
      if (child && child.exitCode == null) {
        child.kill('SIGTERM');
        await new Promise((resolvePromise) => child?.once('exit', resolvePromise));
      }
      fixture.cleanup();
    }
  });

  it('detects recreated WAL sidecars and restores from the retained backup', async () => {
    const fixture = createFixture('stale-wal');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            writeFileSync(`${to}-wal`, 'stale-wal');
          },
        })),
        /original destination was restored automatically.*stale or recreated SQLite sidecar/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(existsSync(`${fixture.destinationPath}-wal`), false);
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('detects a recreated rollback journal and restores from the retained backup', async () => {
    const fixture = createFixture('stale-rollback-journal');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            writeFileSync(`${to}-journal`, 'stale-rollback-journal');
          },
        })),
        /original destination was restored automatically.*(?:sidecar|journal)/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(existsSync(`${fixture.destinationPath}-journal`), false);
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('cleans the complete SQLite family for failed temporary promotion artifacts', async () => {
    const fixture = createFixture('temporary-family-cleanup');
    const temporaryFamily: string[] = [];
    try {
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
        }, testDependencies({
          snapshotDatabase(sourcePath: string, snapshotPath: string) {
            copyFileSync(sourcePath, snapshotPath);
            temporaryFamily.push(
              snapshotPath,
              `${snapshotPath}-wal`,
              `${snapshotPath}-shm`,
              `${snapshotPath}-journal`,
            );
            for (const sidecarPath of temporaryFamily.slice(1)) {
              writeFileSync(sidecarPath, 'temporary-sidecar');
            }
            throw new Error('injected temporary snapshot failure');
          },
        })),
        /injected temporary snapshot failure/,
      );
      assert.ok(temporaryFamily.length > 0);
      for (const familyPath of temporaryFamily) {
        assert.equal(existsSync(familyPath), false);
      }
    } finally {
      fixture.cleanup();
    }
  });

  it('does not restore a rollback clone after the retained backup changes', async () => {
    const fixture = createFixture('rollback-backup-clone-race');
    let restoreRenameCalls = 0;
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            writeFileSync(`${to}-wal`, 'force automatic rollback');
          },
          cloneWithMetadata(sourcePath: string, destinationPath: string) {
            copyFileSync(sourcePath, destinationPath);
            if (!destinationPath.includes('.rollback-')) return;
            const backup = new DatabaseSync(sourcePath);
            try {
              setPromotionState(backup, 'mutated-during-rollback-clone');
            } finally {
              backup.close();
            }
          },
          restoreRename(from: string, to: string) {
            restoreRenameCalls += 1;
            renameSync(from, to);
          },
        })),
        /automatic rollback did not complete.*retained promotion backup logical contents changed while the rollback candidate was built/is,
      );
      assert.equal(restoreRenameCalls, 0);
      assert.equal(readPromotionState(fixture.destinationPath), 'source');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('detects post-install logical mismatch and never reports applied', async () => {
    const fixture = createFixture('post-install-mismatch');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            const db = new DatabaseSync(to);
            try {
              db.prepare(`UPDATE promotion_state SET value='tampered-after-rename' WHERE key='state'`).run();
            } finally {
              db.close();
            }
          },
        })),
        /original destination was restored automatically.*logical contents differ/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('automatically restores after a post-rename fsync failure and retains the backup', async () => {
    const fixture = createFixture('post-rename-fsync');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      let renamed = false;
      let injected = false;

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename(from: string, to: string) {
            renameSync(from, to);
            renamed = true;
          },
          fsyncDirectory() {
            if (renamed && !injected) {
              injected = true;
              throw new Error('injected post-rename fsync failure');
            }
          },
        })),
        /original destination was restored automatically.*injected post-rename fsync failure/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('checks active leases before reporting success and rolls back when the boundary is raced', async () => {
    const fixture = createFixture('lease-before-success');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      let leaseInserted = false;

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (options.phase === 'before-success' && !leaseInserted) {
              leaseInserted = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                seedRefreshLease(
                  db,
                  'late-refresh',
                  'late-holder',
                  '2026-07-03T12:34:56.000Z',
                  '2026-07-03T13:34:56.000Z',
                );
              } finally {
                db.close();
              }
            } else if (options.phase === 'before-rollback' && leaseInserted) {
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                db.prepare(`DELETE FROM refresh_leases WHERE name='late-refresh'`).run();
              } finally {
                db.close();
              }
            }
            return [];
          },
        })),
        /original destination was restored automatically.*active or malformed refresh lease/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('reports the exact retained backup when a holder blocks automatic rollback', async () => {
    const fixture = createFixture('rollback-blocked');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      const holder = { pid: 999, command: 'node', paths: [fixture.destinationPath] };
      let renamed = false;

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => renamed && (
            options.phase === 'immediately-after-swap' ||
            options.phase === 'before-rollback'
          ) ? [holder] : [],
          rename(from: string, to: string) {
            renameSync(from, to);
            renamed = true;
            const db = new DatabaseSync(to);
            try {
              db.prepare(`UPDATE promotion_state SET value='tampered-after-rename' WHERE key='state'`).run();
            } finally {
              db.close();
            }
          },
        })),
        (error: unknown) => {
          assert.match(String(error), /automatic rollback did not complete/);
          const [backupPath] = backupFiles(fixture);
          assert.ok(backupPath);
          assert.match(String(error), new RegExp(`Rollback backup: ${escapeRegExp(backupPath)}`));
          return true;
        },
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'tampered-after-rename');
    } finally {
      fixture.cleanup();
    }
  });

  it('blocks automatic rollback when a refresh lease appears at the rollback boundary', async () => {
    const fixture = createFixture('rollback-blocked-by-lease');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      let renamed = false;
      let leaseInserted = false;

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          listHolders: (
            _path: string,
            options: { phase?: string },
          ) => {
            if (renamed && options.phase === 'before-rollback' && !leaseInserted) {
              leaseInserted = true;
              const db = new DatabaseSync(fixture.destinationPath);
              try {
                seedRefreshLease(
                  db,
                  'rollback-race',
                  'replacement-writer',
                  '2026-07-03T12:34:56.000Z',
                  '2026-07-03T13:34:56.000Z',
                );
              } finally {
                db.close();
              }
            }
            return [];
          },
          rename(from: string, to: string) {
            renameSync(from, to);
            renamed = true;
            const db = new DatabaseSync(to);
            try {
              db.prepare(`
                UPDATE promotion_state
                SET value='tampered-before-lease-blocked-rollback'
                WHERE key='state'
              `).run();
            } finally {
              db.close();
            }
          },
        })),
        /automatic rollback did not complete.*blocked by active refresh leases/s,
      );
      assert.equal(
        readPromotionState(fixture.destinationPath),
        'tampered-before-lease-blocked-rollback',
      );
      assert.equal(backupFiles(fixture).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('retains an independent backup when the atomic staged rename fails', async () => {
    const fixture = createFixture('rename-failure');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          rename() {
            throw new Error('injected rename failure');
          },
        })),
        /original destination remains unchanged.*Backup retained/s,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      const [backupPath] = backupFiles(fixture);
      assert.ok(backupPath);
      assert.notEqual(statSync(backupPath).ino, statSync(fixture.destinationPath).ino);
    } finally {
      fixture.cleanup();
    }
  });

  it('preserves destination owner, group, mode, ACLs, and xattrs', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const fixture = createFixture('metadata-preservation');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      chmodSync(fixture.destinationPath, 0o640);
      runTestCommand('/bin/chmod', ['+a', 'everyone allow read', fixture.destinationPath]);
      runTestCommand('/usr/bin/xattr', [
        '-w',
        'com.openclaw.promotion-test',
        'preserved-value',
        fixture.destinationPath,
      ]);
      const before = statSync(fixture.destinationPath);
      const beforeAcl = readTestAcl(fixture.destinationPath);

      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
      }, testDependencies());

      for (const path of [fixture.destinationPath, result.backupPath]) {
        const after = statSync(path);
        assert.equal(after.uid, before.uid);
        assert.equal(after.gid, before.gid);
        assert.equal(after.mode & 0o7777, before.mode & 0o7777);
        assert.deepEqual(readTestAcl(path), beforeAcl);
        assert.equal(
          runTestCommand('/usr/bin/xattr', [
            '-p',
            'com.openclaw.promotion-test',
            path,
          ]),
          'preserved-value',
        );
      }
      assert.equal(result.metadataPreservation.verified, true);
      assert.ok(result.metadataPreservation.destination.aclEntryCount >= 1);
      assert.ok(result.metadataPreservation.destination.xattrCount >= 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('fails before swap when ACL or xattr metadata cannot be preserved', {
    skip: process.platform !== 'darwin',
  }, async () => {
    const fixture = createFixture('metadata-preservation-failure');
    try {
      setPromotionState(fixture.source, 'source');
      setPromotionState(fixture.destination, 'destination');
      closeFixtureDatabases(fixture);
      runTestCommand('/bin/chmod', ['+a', 'everyone allow read', fixture.destinationPath]);
      runTestCommand('/usr/bin/xattr', [
        '-w',
        'com.openclaw.promotion-test',
        'must-survive',
        fixture.destinationPath,
      ]);

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          apply: true,
        }, testDependencies({
          cloneWithMetadata(sourcePath: string, destinationPath: string) {
            copyFileSync(sourcePath, destinationPath);
            runTestCommand('/bin/chmod', ['-N', destinationPath]);
            runTestCommand('/usr/bin/xattr', ['-c', destinationPath]);
          },
        })),
        /could not preserve owner, group, mode, ACLs, and xattrs/,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'destination');
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects foreign-key violations and same-file identities', async () => {
    const foreignKeyFixture = createFixture('foreign-key');
    try {
      foreignKeyFixture.source.exec(`
        PRAGMA foreign_keys=OFF;
        CREATE TABLE promotion_parent (id INTEGER PRIMARY KEY);
        CREATE TABLE promotion_child (
          id INTEGER PRIMARY KEY,
          parent_id INTEGER REFERENCES promotion_parent(id)
        );
        INSERT INTO promotion_child (id, parent_id) VALUES (1, 999);
      `);
      closeFixtureDatabases(foreignKeyFixture);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: foreignKeyFixture.sourcePath,
          destinationPath: foreignKeyFixture.destinationPath,
        }, testDependencies()),
        /failed foreign_key_check/,
      );
    } finally {
      foreignKeyFixture.cleanup();
    }

    const sameFile = createFixture('same-file');
    try {
      closeFixtureDatabases(sameFile);
      const hardLinkPath = join(sameFile.dir, 'same-primary.db');
      linkSync(sameFile.destinationPath, hardLinkPath);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: hardLinkPath,
          destinationPath: sameFile.destinationPath,
        }, testDependencies()),
        /distinct database files/,
      );
    } finally {
      sameFile.cleanup();
    }

    const hardlinkedDestination = createFixture('hardlinked-destination');
    try {
      const aliasPath = join(hardlinkedDestination.dir, 'primary-alias.db');
      linkSync(hardlinkedDestination.destinationPath, aliasPath);
      closeFixtureDatabases(hardlinkedDestination);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: hardlinkedDestination.sourcePath,
          destinationPath: hardlinkedDestination.destinationPath,
          apply: true,
        }, testDependencies()),
        /Destination database must have exactly one hard link before apply/,
      );
      assert.equal(backupFiles(hardlinkedDestination).length, 0);
    } finally {
      hardlinkedDestination.cleanup();
    }
  });

  it('rejects resolved-path and inode aliases across complete source, destination, and rollback SQLite families', async () => {
    const familyAliasError =
      /(?:SQLite database family contains path or inode aliases|distinct database files across their SQLite families: .* aliases)/i;
    const internalFamilyAlias = createFixture('internal-family-inode-alias');
    try {
      closeFixtureDatabases(internalFamilyAlias);
      rmSync(`${internalFamilyAlias.sourcePath}-wal`, { force: true });
      linkSync(
        internalFamilyAlias.sourcePath,
        `${internalFamilyAlias.sourcePath}-wal`,
      );

      await assert.rejects(
        promoteQualityDb({
          sourcePath: internalFamilyAlias.sourcePath,
          destinationPath: internalFamilyAlias.destinationPath,
        }, testDependencies()),
        familyAliasError,
      );
    } finally {
      internalFamilyAlias.cleanup();
    }

    const resolvedAlias = createFixture('resolved-family-alias');
    try {
      closeFixtureDatabases(resolvedAlias);
      const realDirectory = join(resolvedAlias.dir, 'real');
      const aliasDirectory = join(resolvedAlias.dir, 'alias');
      mkdirSync(realDirectory);
      symlinkSync(realDirectory, aliasDirectory);
      const sourcePath = join(realDirectory, 'quality.db');
      const destinationTargetPath = `${sourcePath}-wal`;
      const destinationPath = join(aliasDirectory, 'quality.db-wal');
      renameSync(resolvedAlias.sourcePath, sourcePath);
      rmSync(destinationTargetPath, { force: true });
      renameSync(resolvedAlias.destinationPath, destinationTargetPath);

      await assert.rejects(
        promoteQualityDb({
          sourcePath,
          destinationPath,
        }, testDependencies()),
        familyAliasError,
      );
    } finally {
      resolvedAlias.cleanup();
    }

    const inodeAliasPairs = [
      { sourceSuffix: '', destinationSuffix: '-wal' },
      { sourceSuffix: '-wal', destinationSuffix: '-shm' },
      { sourceSuffix: '-shm', destinationSuffix: '-journal' },
      { sourceSuffix: '-journal', destinationSuffix: '' },
    ] as const;
    for (const { sourceSuffix, destinationSuffix } of inodeAliasPairs) {
      const fixture = createFixture(
        `inode-family-alias-${sourceSuffix || 'main'}-${destinationSuffix || 'main'}`,
      );
      try {
        closeFixtureDatabases(fixture);
        const sourceMember = `${fixture.sourcePath}${sourceSuffix}`;
        const destinationMember =
          `${fixture.destinationPath}${destinationSuffix}`;
        if (sourceSuffix && destinationSuffix) {
          rmSync(sourceMember, { force: true });
          rmSync(destinationMember, { force: true });
          writeFileSync(sourceMember, '');
          linkSync(sourceMember, destinationMember);
        } else if (sourceSuffix) {
          rmSync(sourceMember, { force: true });
          linkSync(destinationMember, sourceMember);
        } else {
          rmSync(destinationMember, { force: true });
          linkSync(sourceMember, destinationMember);
        }

        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
          }, testDependencies()),
          familyAliasError,
        );
      } finally {
        fixture.cleanup();
      }
    }

    const rollbackAlias = createFixture('rollback-family-inode-alias');
    try {
      closeFixtureDatabases(rollbackAlias);
      const rollbackPath = join(rollbackAlias.dir, 'rollback.db');
      copyFileSync(rollbackAlias.destinationPath, rollbackPath);
      rmSync(`${rollbackAlias.destinationPath}-journal`, { force: true });
      rmSync(`${rollbackPath}-shm`, { force: true });
      writeFileSync(`${rollbackAlias.destinationPath}-journal`, '');
      linkSync(
        `${rollbackAlias.destinationPath}-journal`,
        `${rollbackPath}-shm`,
      );

      await assert.rejects(
        promoteQualityDb({
          sourcePath: rollbackAlias.sourcePath,
          destinationPath: rollbackAlias.destinationPath,
          rollbackBackupPath: rollbackPath,
        }, testDependencies()),
        familyAliasError,
      );
    } finally {
      rollbackAlias.cleanup();
    }

    const sourceRollbackAlias = createFixture('source-rollback-family-inode-alias');
    try {
      closeFixtureDatabases(sourceRollbackAlias);
      const rollbackPath = join(sourceRollbackAlias.dir, 'rollback.db');
      copyFileSync(sourceRollbackAlias.destinationPath, rollbackPath);
      rmSync(`${sourceRollbackAlias.sourcePath}-journal`, { force: true });
      rmSync(`${rollbackPath}-shm`, { force: true });
      writeFileSync(`${sourceRollbackAlias.sourcePath}-journal`, '');
      linkSync(
        `${sourceRollbackAlias.sourcePath}-journal`,
        `${rollbackPath}-shm`,
      );

      await assert.rejects(
        promoteQualityDb({
          sourcePath: sourceRollbackAlias.sourcePath,
          destinationPath: sourceRollbackAlias.destinationPath,
          rollbackBackupPath: rollbackPath,
        }, testDependencies()),
        familyAliasError,
      );
    } finally {
      sourceRollbackAlias.cleanup();
    }
  });

  it('registers the package command without replacing concurrent script edits', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    assert.equal(pkg.scripts['promote:quality-db'], 'tsx scripts/promote-quality-db.mjs');
    assert.equal(pkg.scripts['validation:evaluate'], 'tsx scripts/validation/evaluate-score-quality.mjs');
  });

  it('rejects promotion while the installer pending-deploy rollback window is active', async () => {
    const fixture = createFixture('pending-deploy', { installerLayout: true });
    const pendingPath = join(fixture.dir, '.pending-deploy');
    let validationCalls = 0;
    try {
      const destinationStateBefore = readPromotionState(fixture.destinationPath);
      mkdirSync(pendingPath);
      writeFileSync(
        join(pendingPath, 'database_path'),
        `${fixture.destinationPath}\n`,
      );
      writeFileSync(
        join(pendingPath, 'db_snapshot_path'),
        `${join(fixture.dir, 'deploy-backups', 'pre-migration.sqlite')}\n`,
      );
      closeFixtureDatabases(fixture);

      for (const apply of [false, true]) {
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
            apply,
          }, testDependencies({
            verifyValidation: () => {
              validationCalls += 1;
              return validationGateResult(validationReport('validated'), 0);
            },
          })),
          new RegExp(
            `pending-deploy directory exists: ${escapeRegExp(pendingPath)}`,
          ),
        );
      }
      assert.equal(validationCalls, 0);
      assert.equal(
        readPromotionState(fixture.destinationPath),
        destinationStateBefore,
      );
      assert.equal(backupFiles(fixture).length, 0);
    } finally {
      fixture.cleanup();
    }
  });

  it('accepts only the exact installer-owned transaction under the inherited deployment lock', async () => {
    const fixture = createFixture('installer-owned-promotion', {
      installerLayout: true,
    });
    const lockEvents: string[] = [];
    try {
      const installer = prepareInstallerOwnedPromotion(fixture);
      const lockPath = join(
        fixture.dir,
        'shared',
        'deploy-promotion.lock',
      );
      const lockProof = testInheritedDeploymentLock({
        path: lockPath,
        fd: 9,
      }).proof;
      const result = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        rollbackBackupPath: installer.rollbackBackupPath,
        deploymentTransaction: installer.transaction,
        apply: true,
        lockTimeoutSeconds: 9,
      }, testDependencies({
        acquireDeploymentLock: async () => {
          lockEvents.push('acquired');
          return async () => {
            lockEvents.push('released');
          };
        },
        verifyInheritedDeploymentLock: (input: {
          path: string;
          fd: number;
        }) => {
          lockEvents.push(`verify:${input.path}:${input.fd}`);
          return {
            proof: lockProof,
            assertHeld: (label: string) => {
              lockEvents.push(`assert:${label}`);
            },
          };
        },
      }));

      assert.equal(result.applied, true);
      assert.equal(readPromotionState(fixture.destinationPath), 'quality-ready');
      assert.equal(result.backupPath, installer.rollbackBackupPath);
      assert.deepEqual(lockEvents, [
        `verify:${lockPath}:9`,
        'assert:before installer-owned promotion',
        'assert:immediately before promotion swap',
        'assert:before promotion success',
      ]);
      assert.deepEqual(result.deploymentLock, {
        path: lockPath,
        timeoutSeconds: 9,
        sharedWithInstaller: true,
        inheritedFromInstaller: true,
        transactionId: installer.transaction.transactionId,
        proof: lockProof,
      });
      assert.equal(result.deploymentTransaction.lockHeldByInstaller, true);
      assert.equal(
        Object.hasOwn(result.deploymentTransaction, 'inheritedLockFd'),
        false,
      );
      assert.equal(
        result.deploymentTransaction.pendingDeploymentAuthorization.verified,
        true,
      );
      assert.equal(
        result.deploymentTransaction.sourceAuthorization.receiptId,
        installer.receiptId,
      );
      assert.equal(
        result.deploymentTransaction.sourceAuthorization.codeRevision,
        installer.transaction.releaseSha,
      );
      assert.equal(result.rollbackBackup.externallyPrepared, true);
      assert.equal(
        result.rollbackBackup.verifiedAgainstPrePromotionDestination,
        true,
      );
      const promotionAuthorization = result.promotionAuthorization;
      assert.ok(promotionAuthorization);
      assert.deepEqual(
        Object.keys(promotionAuthorization).sort(),
        [
          'contentHash',
          'evaluationReceipt',
          'githubReleaseCatalog',
          'installedDatabase',
          'phase',
          'promotionReceipt',
          'schemaVersion',
          'sourceDatabase',
          'validationReport',
        ],
      );
      assert.deepEqual(
        Object.keys(promotionAuthorization.sourceDatabase).sort(),
        [
          'applicationId',
          'logicalContentDigest',
          'schemaDigest',
          'userVersion',
        ],
      );
      assert.deepEqual(
        Object.keys(promotionAuthorization.installedDatabase).sort(),
        [
          'logicalContentDigest',
          'physicalSha256',
          'schemaDigest',
        ],
      );
      assert.deepEqual(
        Object.keys(promotionAuthorization.validationReport).sort(),
        ['contentHash', 'generatedAt', 'schemaVersion', 'status'],
      );
      assert.deepEqual(
        Object.keys(promotionAuthorization.evaluationReceipt).sort(),
        ['contentHash', 'evaluatedAt', 'evaluationId', 'status'],
      );
      assert.deepEqual(
        Object.keys(promotionAuthorization.promotionReceipt).sort(),
        ['contentHash', 'promotionId'],
      );
      assert.equal(
        promotionAuthorization.schemaVersion,
        PROMOTION_AUTHORIZATION_SCHEMA_VERSION,
      );
      assert.equal(promotionAuthorization.phase, 'applied');
      const currentSourceDatabase =
        result.activity.applyRevalidation.immediatelyBeforeSwap.source.database;
      assert.deepEqual(promotionAuthorization.sourceDatabase, {
        applicationId: currentSourceDatabase.applicationId,
        userVersion: currentSourceDatabase.userVersion,
        logicalContentDigest: currentSourceDatabase.logicalContentDigest,
        schemaDigest: currentSourceDatabase.schemaDigest,
      });
      const currentInstalledDatabase = result.destination.database;
      assert.deepEqual(promotionAuthorization.installedDatabase, {
        logicalContentDigest: currentInstalledDatabase.logicalContentDigest,
        schemaDigest: currentInstalledDatabase.schemaDigest,
        physicalSha256: sha256File(fixture.destinationPath),
      });
      const validationReportIdentity =
        result.staged.qualityVerification.validation.report;
      assert.deepEqual(promotionAuthorization.validationReport, {
        schemaVersion: validationReportIdentity.schemaVersion,
        generatedAt: validationReportIdentity.generatedAt,
        status: validationReportIdentity.status,
        contentHash: createHash('sha256')
          .update(
            `${PROMOTION_VALIDATION_REPORT_HASH_DOMAIN}\0` +
            canonicalOperationJson(validationReportIdentity),
          )
          .digest('hex'),
      });
      assert.deepEqual(promotionAuthorization.evaluationReceipt, {
        evaluationId:
          result.staged.qualityVerification.validation
            .canonicalEvaluationReceipt.evaluationId,
        contentHash:
          result.staged.qualityVerification.validation
            .canonicalEvaluationReceipt.contentHash,
        evaluatedAt:
          result.staged.qualityVerification.validation
            .canonicalEvaluationReceipt.evaluatedAt,
        status: 'validated',
      });
      assert.deepEqual(promotionAuthorization.promotionReceipt, {
        promotionId: result.staged.canonicalPromotionReceipt.promotionId,
        contentHash: result.staged.canonicalPromotionReceipt.contentHash,
      });
      assert.deepEqual(promotionAuthorization.githubReleaseCatalog, {
        schemaVersion: 1,
        source: 'independent_github_graphql',
        repository: result.githubReleaseCatalog.beforeSwap.repository,
        observedAt: result.githubReleaseCatalog.beforeSwap.observedAt,
        remoteCatalogDigest:
          result.githubReleaseCatalog.beforeSwap.remoteCatalog.digest,
        activeCatalogDigest:
          result.githubReleaseCatalog.beforeSwap.activeCatalog.digest,
        activeReleaseCount:
          result.githubReleaseCatalog.beforeSwap.activeCatalog.releaseCount,
        activeReleaseTags:
          result.githubReleaseCatalog.beforeSwap.activeCatalog.tags,
        exactIdentityMatch: true,
      });
      const {
        contentHash: promotionAuthorizationContentHash,
        ...promotionAuthorizationPayload
      } = promotionAuthorization;
      assert.equal(
        promotionAuthorizationContentHash,
        createHash('sha256')
          .update(
            `${PROMOTION_AUTHORIZATION_HASH_DOMAIN}\0` +
            canonicalOperationJson(promotionAuthorizationPayload),
          )
          .digest('hex'),
      );
      assert.equal(
        readPromotionState(installer.rollbackBackupPath),
        'initial',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects missing inherited-lock proof and every mismatched installer transaction identity', async () => {
    const cases = [
      {
        name: 'missing-inherited-lock',
        mutate(installer: ReturnType<typeof prepareInstallerOwnedPromotion>) {
          (installer.transaction as any).inheritedLockFd = undefined;
          (installer.transaction as any).lockHeldByInstaller = true;
        },
        pattern: /requires a concrete inherited deployment lock descriptor/,
      },
      {
        name: 'wrong-pending-state-hash',
        mutate(installer: ReturnType<typeof prepareInstallerOwnedPromotion>) {
          installer.transaction.pendingStateHash = 'f'.repeat(64);
        },
        pattern: /pending-state hash does not match installer state/,
      },
      {
        name: 'wrong-transaction-id',
        mutate(installer: ReturnType<typeof prepareInstallerOwnedPromotion>) {
          installer.transaction.transactionId =
            '22222222-2222-4222-8222-222222222222';
        },
        pattern: /transaction_id does not match deployment transaction/,
      },
      {
        name: 'tampered-pending-marker',
        mutate(installer: ReturnType<typeof prepareInstallerOwnedPromotion>) {
          writeFileSync(
            join(installer.pendingPath, 'release_name'),
            'release-tampered\n',
          );
        },
        pattern: /pending-deploy identity hash mismatch/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(
        `installer-identity-${testCase.name}`,
        { installerLayout: true },
      );
      try {
        const installer = prepareInstallerOwnedPromotion(fixture);
        testCase.mutate(installer);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
            rollbackBackupPath: installer.rollbackBackupPath,
            deploymentTransaction: installer.transaction,
            apply: true,
            lockPath: join(fixture.dir, 'deploy-promotion.lock'),
          }, testDependencies()),
          testCase.pattern,
          testCase.name,
        );
        assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects installer transactions not authorized by the exact source receipt and code revision', async () => {
    const cases = [
      {
        name: 'wrong-source-receipt',
        update: { required_score_receipt_id: 'e'.repeat(64) },
        pattern: /source receipt .* does not match required/,
      },
      {
        name: 'wrong-source-revision',
        update: { github_sha: 'd'.repeat(40) },
        pattern: /source code revision .* does not match release SHA/,
      },
    ];

    for (const testCase of cases) {
      const fixture = createFixture(
        `installer-source-${testCase.name}`,
        { installerLayout: true },
      );
      try {
        const installer = prepareInstallerOwnedPromotion(fixture);
        updateInstallerPendingIdentity(installer, testCase.update);
        await assert.rejects(
          promoteQualityDb({
            sourcePath: fixture.sourcePath,
            destinationPath: fixture.destinationPath,
            rollbackBackupPath: installer.rollbackBackupPath,
            deploymentTransaction: installer.transaction,
            apply: true,
            lockPath: join(fixture.dir, 'deploy-promotion.lock'),
          }, testDependencies()),
          testCase.pattern,
          testCase.name,
        );
        assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects drift in the installer-owned rollback backup before swapping the destination', async () => {
    const fixture = createFixture('installer-rollback-backup-drift', {
      installerLayout: true,
    });
    try {
      const installer = prepareInstallerOwnedPromotion(fixture);
      const backup = new DatabaseSync(installer.rollbackBackupPath);
      try {
        setPromotionState(backup, 'tampered-backup');
      } finally {
        backup.close();
      }

      await assert.rejects(
        promoteQualityDb({
          sourcePath: fixture.sourcePath,
          destinationPath: fixture.destinationPath,
          rollbackBackupPath: installer.rollbackBackupPath,
          deploymentTransaction: installer.transaction,
          apply: true,
          lockPath: join(fixture.dir, 'deploy-promotion.lock'),
        }, testDependencies()),
        /Promotion backup differs from the verified final destination snapshot/,
      );
      assert.equal(readPromotionState(fixture.destinationPath), 'initial');
      assert.equal(
        readPromotionState(installer.rollbackBackupPath),
        'tampered-backup',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('serializes apply with the installer deployment lock and always releases it', async () => {
    const fixture = createFixture('shared-deployment-lock');
    const events: string[] = [];
    const lockPath = join(fixture.dir, 'deploy-promotion.lock');
    const acquireDeploymentLock = async (options: {
      path: string;
      timeoutSeconds: number;
    }) => {
      events.push(`acquire:${options.path}:${options.timeoutSeconds}`);
      return async () => {
        events.push('release');
      };
    };
    try {
      closeFixtureDatabases(fixture);
      const dryRun = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        lockPath,
      }, testDependencies({ acquireDeploymentLock }));
      assert.equal(dryRun.applied, false);
      assert.deepEqual(events, []);

      const applied = await promoteQualityDb({
        sourcePath: fixture.sourcePath,
        destinationPath: fixture.destinationPath,
        apply: true,
        lockPath,
        lockTimeoutSeconds: 9,
      }, testDependencies({ acquireDeploymentLock }));
      assert.equal(applied.applied, true);
      assert.deepEqual(applied.deploymentLock, {
        path: lockPath,
        timeoutSeconds: 9,
        sharedWithInstaller: true,
      });
      assert.deepEqual(events, [
        `acquire:${lockPath}:9`,
        'release',
      ]);
    } finally {
      fixture.cleanup();
    }

    const invalid = createFixture('shared-deployment-lock-error');
    try {
      invalid.source.exec('DROP TRIGGER release_score_audit_history_runs_no_delete');
      closeFixtureDatabases(invalid);
      await assert.rejects(
        promoteQualityDb({
          sourcePath: invalid.sourcePath,
          destinationPath: invalid.destinationPath,
          apply: true,
          lockPath,
        }, testDependencies({ acquireDeploymentLock })),
        /missing required append-only trigger release_score_audit_history_runs_no_delete/,
      );
      assert.deepEqual(events.slice(-2), [
        `acquire:${lockPath}:120`,
        'release',
      ]);
    } finally {
      invalid.cleanup();
    }
  });

  it('detects standalone deployment-lock holder death after LOCKED', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'radar-promote-lock-loss-'));
    const flockBin = join(dir, 'flock');
    const deathMarker = `${flockBin}.die`;
    writeFileSync(flockBin, `#!/usr/bin/env bash
set -euo pipefail
if [ "\${1:-}" = "-n" ]; then
  exit 1
fi
printf 'LOCKED\\n'
while [ ! -e "\${0}.die" ]; do
  sleep 0.01
done
exit 23
`);
    chmodSync(flockBin, 0o755);

    let lock: Awaited<ReturnType<typeof acquireDeploymentLock>> | null = null;
    try {
      lock = await acquireDeploymentLock({
        path: join(dir, 'deploy.lock'),
        timeoutSeconds: 2,
        flockBin,
      });
      lock.assertHeld('initial post-acquisition boundary');
      writeFileSync(deathMarker, 'die\n');

      let loss: unknown = null;
      for (let attempt = 0; attempt < 100 && loss == null; attempt++) {
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 10));
        try {
          lock.assertHeld('post-acquisition child-death boundary');
        } catch (error) {
          loss = error;
        }
      }
      assert.match(
        String(loss),
        /deployment lock holder exited after acquisition before post-acquisition child-death boundary.*exit 23/,
      );
      await lock.release();
      lock = null;
    } finally {
      if (lock) {
        try {
          await lock.release();
        } catch {
          // The assertion above owns the expected abnormal-exit diagnosis.
        }
      }
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

function createProductionDoctorFixture(name: string) {
  const dir = mkdtempSync(join(tmpdir(), `radar-promote-${name}-`));
  const sourcePath = join(dir, 'quality.db');
  const destinationPath = join(dir, 'primary.db');
  try {
    initializeProductionSchema(sourcePath);
    const source = new DatabaseSync(sourcePath);
    try {
      seedProductionDoctorDb(source, sourcePath);
      source.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } finally {
      source.close();
    }
    rmSync(`${sourcePath}-wal`, { force: true });
    rmSync(`${sourcePath}-shm`, { force: true });
    rmSync(`${sourcePath}-journal`, { force: true });
    copyFileSync(sourcePath, destinationPath);
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  return {
    dir,
    sourcePath,
    destinationPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function createRealVerifierPromotionFixture(name: string) {
  const dir = mkdtempSync(join(tmpdir(), `radar-promote-${name}-`));
  const sourcePath = join(dir, 'quality.db');
  const destinationPath = join(dir, 'primary.db');
  try {
    initializeProductionSchema(sourcePath);
    const source = new DatabaseSync(sourcePath);
    try {
      seedProductionDoctorDb(source, sourcePath);
      seedProductionValidationDenominator(source);
      source.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    } finally {
      source.close();
    }
    rmSync(`${sourcePath}-wal`, { force: true });
    rmSync(`${sourcePath}-shm`, { force: true });
    rmSync(`${sourcePath}-journal`, { force: true });
    rescoreProductionCandidate(sourcePath);
    copyFileSync(sourcePath, destinationPath);
  } catch (error) {
    rmSync(dir, { recursive: true, force: true });
    throw error;
  }
  return {
    dir,
    sourcePath,
    destinationPath,
    cleanup: () => rmSync(dir, { recursive: true, force: true }),
  };
}

function rescoreProductionCandidate(path: string) {
  const scoredAtMs = Date.parse('2026-07-04T12:00:00.000Z');
  const childAuthority = productionDatabaseChildAuthority(path);
  try {
    const result = spawnSync(
      join(root, 'node_modules', '.bin', 'tsx'),
      ['-e', `
        import { db, listReleasesDb } from './src/lib/db.ts';
        import {
          buildReleaseScoreRun,
          persistReleaseScoreRun,
        } from './src/lib/releaseScoring.ts';
        const releases = listReleasesDb(2);
        const run = buildReleaseScoreRun({
          releases,
          nowForRelease: () => ${scoredAtMs},
        });
        persistReleaseScoreRun(run, {
          source: 'promotion-fixture',
          scope: 'real-default-verifier-stack',
          clock: {
            wallTimeMs: () => ${scoredAtMs},
            monotonicTimeMs: () => 1,
          },
        });
        db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
        db.close();
      `],
      {
        cwd: root,
        env: {
          ...childAuthority.environment,
          DB_PATH: path,
          RADAR_DB_BOOTSTRAP_MODE: 'existing',
          RADAR_DB_READ_ONLY: '0',
        },
        encoding: 'utf8',
        maxBuffer: 64 * 1024 * 1024,
      },
    );
    assert.equal(
      result.status,
      0,
      `Production candidate rescore failed: ${String(result.stderr ?? '').trim()}`,
    );
  } finally {
    childAuthority.cleanup();
  }
  rmSync(`${path}-wal`, { force: true });
  rmSync(`${path}-shm`, { force: true });
  rmSync(`${path}-journal`, { force: true });
}

function initializeProductionSchema(path: string) {
  const childAuthority = productionDatabaseChildAuthority(path);
  try {
    const result = spawnSync(
      join(root, 'node_modules', '.bin', 'tsx'),
      [
        '-e',
        `import { db } from './src/lib/db.ts'; ` +
        `db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close();`,
      ],
      {
        cwd: root,
        env: {
          ...childAuthority.environment,
          DB_PATH: path,
          RADAR_DB_BOOTSTRAP_MODE: 'fresh',
          RADAR_DB_READ_ONLY: '0',
        },
        encoding: 'utf8',
      },
    );
    assert.equal(
      result.status,
      0,
      `Production schema initialization failed: ${String(result.stderr ?? '').trim()}`,
    );
  } finally {
    childAuthority.cleanup();
  }
}

function productionDatabaseChildAuthority(path: string) {
  const inheritedWriterToken =
    process.env.RADAR_TEST_WRITER_LOCK_TOKEN?.trim();
  const inheritedWriterPid =
    process.env.RADAR_TEST_WRITER_LOCK_PID?.trim();
  const inheritedWriterLeasePath =
    process.env.RADAR_TEST_WRITER_LEASE_PATH?.trim();
  const inheritedFields = [
    inheritedWriterToken,
    inheritedWriterPid,
    inheritedWriterLeasePath,
  ];
  assert.ok(
    inheritedFields.every(Boolean) ||
      inheritedFields.every((value) => !value),
    'Test writer lease path, token, and pid must be inherited together',
  );
  if (
    inheritedWriterToken &&
    inheritedWriterPid &&
    inheritedWriterLeasePath
  ) {
    return {
      environment: { ...process.env },
      cleanup: () => {},
    };
  }

  const owner = locallyHeldRepositoryDatabaseWriterLockOwner({
    repositoryRoot: root,
  });
  assert.ok(
    owner,
    'Production database child requires a locally held repository writer lock',
  );
  assert.equal(
    owner.pid,
    process.pid,
    'Production database child writer authority must belong to its parent process',
  );
  const inheritedTempRoot = process.env.RADAR_TEST_TEMP_ROOT?.trim();
  const tempRoot = resolve(inheritedTempRoot || dirname(path));
  const relativeDatabasePath = relative(tempRoot, resolve(path));
  assert.ok(
    relativeDatabasePath.length > 0 &&
      relativeDatabasePath !== '..' &&
      !relativeDatabasePath.startsWith(`..${sep}`) &&
      !isAbsolute(relativeDatabasePath),
    `Production database child path must stay inside ${tempRoot}`,
  );
  const leasePath = join(
    tempRoot,
    `.writer-lease-${process.pid}-${randomUUID()}.json`,
  );
  writeFileSync(
    leasePath,
    `${JSON.stringify({
      token: owner.token,
      pid: owner.pid,
      repositoryRoot: root,
    })}\n`,
    { flag: 'wx', mode: 0o600 },
  );
  return {
    environment: {
      ...process.env,
      NODE_TEST_CONTEXT:
        process.env.NODE_TEST_CONTEXT ?? 'promotion-database-child',
      RADAR_TEST_RUN_ID:
        process.env.RADAR_TEST_RUN_ID ??
        `promotion-database-child-${process.pid}`,
      RADAR_TEST_TEMP_ROOT: tempRoot,
      RADAR_TEST_WRITER_LOCK_PID: String(owner.pid),
      RADAR_TEST_WRITER_LEASE_PATH: leasePath,
      RADAR_TEST_WRITER_LOCK_TOKEN: owner.token,
    },
    cleanup: () => rmSync(leasePath, { force: true }),
  };
}

function seedProductionValidationDenominator(db: DatabaseSync) {
  const codeRevision = codeRevisionFromEnv();
  assert.ok(codeRevision, 'Production validation fixture requires a code revision');
  const enrolledAtMs = Date.now() - 10_000;
  const enrolledAt = new Date(enrolledAtMs).toISOString();
  const publishedAt = new Date(enrolledAtMs - 60 * 60_000).toISOString();
  const run = seedOperationReceiptRun(db, {
    runId: 'production-validation-enrollment',
    startedAt: enrolledAt,
    status: 'abandoned',
    codeRevision,
  });
  const enrollments = planReleaseValidationOpportunityEnrollments({
    enrolledAt,
    release: {
      nodeId: 'production-validation-release-node',
      tag: 'v-production-validation',
      tagCommitOid: 'f'.repeat(40),
      publishedAt,
    },
    cohort: {
      modelVersion: SCORE_MODEL_VERSION,
      promptVersion: PROMPT_VERSION,
      codeRevision,
    },
    evidence: {
      enrollmentRunId: run.attempt.run_id,
      operationAttemptContentHash: run.attempt.content_hash,
      catalogDigest: 'e'.repeat(64),
      catalogReleaseCount: 1,
    },
  });
  assert.equal(enrollments.length, 2);

  const insert = db.prepare(`
    INSERT INTO release_validation_opportunity_enrollments (
      opportunity_id, enrolled_at, cohort_inception_at, enrollment_kind,
      release_node_id, release_tag, release_tag_commit_oid,
      release_published_at, opportunity_code, opens_at,
      closes_at_exclusive, score_model_version, prompt_version,
      code_revision, enrollment_run_id, operation_attempt_content_hash,
      catalog_digest, catalog_release_count, previous_content_hash,
      content_hash
    )
    VALUES (
      :opportunity_id, :enrolled_at, :cohort_inception_at, :enrollment_kind,
      :release_node_id, :release_tag, :release_tag_commit_oid,
      :release_published_at, :opportunity_code, :opens_at,
      :closes_at_exclusive, :score_model_version, :prompt_version,
      :code_revision, :enrollment_run_id, :operation_attempt_content_hash,
      :catalog_digest, :catalog_release_count, :previous_content_hash,
      :content_hash
    )
  `);
  let previousContentHash: string | null = null;
  for (const enrollment of enrollments) {
    const row = {
      ...enrollment,
      opportunity_id: releaseValidationOpportunityId(enrollment),
      previous_content_hash: previousContentHash,
      content_hash: '',
    };
    row.content_hash = releaseValidationOpportunityEnrollmentContentHash(row);
    insert.run(row);
    previousContentHash = row.content_hash;
  }
}

function seedProductionDoctorDb(db: DatabaseSync, dbPath: string) {
  const evidenceAt = '2026-07-03T11:00:00.000Z';
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = 'ISSUE-node-production-doctor-1';
  const releases = [
    ['v0', '2026-07-03T08:00:00.000Z', null, null, 0, null],
    ['v1', '2026-07-03T09:00:00.000Z', 7.5, 'eligible', 0, '2026-07-03T11:30:00.000Z'],
    ['v2', '2026-07-03T10:00:00.000Z', 7.8, 'eligible', 1, '2026-07-03T12:00:00.000Z'],
  ] as const;
  const insertRelease = db.prepare(`
    INSERT INTO releases (
      tag, name, published_at, html_url, prerelease, final_score, state,
      recommended, score_reason, scored_at, release_metadata_fetched_at,
      release_derived_fetched_at, release_artifact_checked_at
    )
    VALUES (?, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  for (const [tag, publishedAt, score, status, recommended, scoredAt] of releases) {
    insertRelease.run(
      tag,
      `Release ${tag}`,
      publishedAt,
      `https://example.test/${tag}`,
      score,
      status,
      recommended,
      score == null ? null : 'production doctor fixture',
      scoredAt,
      evidenceAt,
      evidenceAt,
      evidenceAt,
    );
    db.prepare(`
      INSERT INTO release_commits (
        tag, tag_commit_oid, committed_at, fetched_at
      )
      VALUES (?, ?, ?, ?)
    `).run(tag, tag.slice(1).repeat(40), publishedAt, evidenceAt);
  }
  const activeReleaseRows = [...releases].reverse().map(
    ([tag, publishedAt], catalogRank) => ({
      catalog_rank: catalogRank,
      node_id: `RE_${tag}`,
      catalog_tag_commit_oid: tag.slice(1).repeat(40),
      tag,
      name: `Release ${tag}`,
      published_at: publishedAt,
      created_at: publishedAt,
      updated_at: publishedAt,
      html_url: `https://example.test/${tag}`,
      prerelease: 0,
      body: null,
    }),
  );
  const activeReleaseCatalog =
    projectReleaseCatalogActiveRows(activeReleaseRows);
  const activateRelease = db.prepare(`
    UPDATE releases
    SET
      node_id=:node_id,
      catalog_tag_commit_oid=:catalog_tag_commit_oid,
      created_at=:created_at,
      updated_at=:updated_at,
      catalog_rank=:catalog_rank,
      catalog_digest=:catalog_digest,
      catalog_active=1,
      body=:body
    WHERE tag=:tag
  `);
  for (const release of activeReleaseRows) {
    activateRelease.run({
      node_id: release.node_id,
      catalog_tag_commit_oid: release.catalog_tag_commit_oid,
      created_at: release.created_at,
      updated_at: release.updated_at,
      catalog_rank: release.catalog_rank,
      catalog_digest: activeReleaseCatalog.digest,
      body: release.body,
      tag: release.tag,
    });
  }

  db.prepare(`
    INSERT INTO issues (
      number, node_id, state, title, author_node_id, author_type,
      created_at, updated_at, closed_at, comments, labels,
      fetched_at, checked_at, commenter_scan_truncated
    )
    VALUES (
      1, ?, 'closed', 'production doctor issue', 'ACTOR-reporter', 'User',
      '2026-07-01T22:00:00.000Z',
      '2026-07-02T00:00:00.000Z', '2026-07-02T00:00:00.000Z',
      0, '[]', ?, ?, 0
    )
  `).run(issueNodeId, evidenceAt, evidenceAt);
  db.prepare(`
    INSERT INTO classifications (
      issue_number, sentiment, severity, scope, functionality, affected_users,
      has_workaround, workaround_status, confidence, rationale, classified_at,
      classified_updated_at, prompt_version
    )
    VALUES (
      1, 'neutral', 'low', 'single', 'other', 'few', 0, 'unknown', 1,
      'production doctor fixture', ?, '2026-07-02T00:00:00.000Z', 6
    )
  `).run(evidenceAt);
  const closedStateEvent = {
    eventId: 'closed-production-doctor-1',
    eventNodeType: 'ClosedEvent' as const,
    type: 'closed' as const,
    occurredAt: '2026-07-02T00:00:00.000Z',
    connectionOrdinal: 0,
    actorNodeId: 'ACTOR-maintainer',
    actorLogin: 'maintainer',
    actorType: 'User',
    stateReason: 'COMPLETED',
    closerNodeId: 'COMMIT-node-production-doctor-1',
    closerType: 'Commit',
    closerNumber: null,
    closerOid: 'a'.repeat(40),
  };
  const normalizedStateEvents = normalizeIssueStateEvents([closedStateEvent]);
  const stateSweep = {
    repositoryNodeId,
    issueNumber: 1,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueState: 'closed' as const,
    issueUpdatedAt: closedStateEvent.occurredAt,
    totalCount: normalizedStateEvents.length,
    events: normalizedStateEvents,
  };
  const firstStateSweep = issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 1,
  });
  const secondStateSweep = issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 2,
  });
  const stateStabilization = issueStateEventStabilizationIdentity(
    firstStateSweep,
    secondStateSweep,
    2,
  );
  db.prepare(`
    INSERT INTO issue_closure_events (
      issue_number, issue_node_id, event_id, closed_at, connection_ordinal,
      actor_node_id, actor_login, actor_type, state_reason,
      closer_node_id, closer_type, closer_number, closer_oid, raw_json, fetched_at
    )
    VALUES (1, ?, ?, ?, 0, ?, ?, ?, ?, ?, ?, NULL, ?, '{}', ?)
  `).run(
    issueNodeId,
    closedStateEvent.eventId,
    closedStateEvent.occurredAt,
    closedStateEvent.actorNodeId,
    closedStateEvent.actorLogin,
    closedStateEvent.actorType,
    closedStateEvent.stateReason,
    closedStateEvent.closerNodeId,
    closedStateEvent.closerType,
    closedStateEvent.closerOid,
    evidenceAt,
  );
  db.prepare(`
    INSERT INTO issue_state_event_snapshots (
      issue_number, repository_node_id, issue_node_id, issue_node_type,
      schema_version, issue_state, issue_updated_at, total_count, fetched_count,
      events_digest, authority_digest, events_json, sweep_count, stabilized,
      stabilization_json, stabilization_identity_digest,
      revision, fetched_at, verified_at
    )
    VALUES (
      1, ?, ?, 'Issue', ?, 'closed', '2026-07-02T00:00:00.000Z',
      1, 1, ?, ?, ?, 2, 1, ?, ?, 1, ?, ?
    )
  `).run(
    repositoryNodeId,
    issueNodeId,
    ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
    issueStateEventsDigest(normalizedStateEvents, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
    }),
    secondStateSweep.sweepDigest,
    JSON.stringify(normalizedStateEvents),
    JSON.stringify(stateStabilization),
    stateStabilization.identityDigest,
    evidenceAt,
    evidenceAt,
  );
  const insertDependencySnapshot = db.prepare(`
    INSERT INTO release_closure_dependency_snapshots (
      release_tag, schema_version, analyzer_version, issue_numbers_json,
      dependency_digest, dependency_row_count, captured_at
    )
    VALUES (?, 3, ?, '[]', ?, 0, ?)
  `);
  for (const tag of ['v1', 'v2']) {
    insertDependencySnapshot.run(
      tag,
      CLOSURE_PROOF_ANALYZER_VERSION,
      '0'.repeat(64),
      evidenceAt,
    );
  }
  const emptyAdvisoryDigest = advisorySnapshotContentHash([]);
  db.prepare(`
    INSERT INTO advisory_snapshot_history(captured_at, row_count, content_hash)
    VALUES (?, 0, ?)
  `).run(evidenceAt, emptyAdvisoryDigest);
  db.prepare(`INSERT INTO meta(key, value) VALUES(?, ?)`).run(
    ADVISORY_SNAPSHOT_META_KEY,
    JSON.stringify({
      schemaVersion: 1,
      source: 'github-security-vulnerabilities',
      sourceOrder: 'UPDATED_AT_DESC',
      ecosystem: 'npm',
      packageName: 'openclaw',
      capturedAt: evidenceAt,
      exhausted: true,
      stabilized: true,
      totalCount: 0,
      nodeCount: 0,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      sourceDigest: 'a'.repeat(64),
      advisoryCount: 0,
      activeAdvisoryCount: 0,
      withdrawnAdvisoryCount: 0,
      rowCount: 0,
      contentDigest: emptyAdvisoryDigest,
    }),
  );
  seedProductionIssueCrawl(db);

  const temporaryIdentity = scoreSourceIdentityForDb(db);
  insertProductionDoctorAudits(db, temporaryIdentity);
  const reader = new ReleaseAuditReader(db);
  const updateDependencySnapshot = db.prepare(`
    UPDATE release_closure_dependency_snapshots
    SET dependency_digest=?, dependency_row_count=?
    WHERE release_tag=?
  `);
  for (const tag of ['v1', 'v2']) {
    const dependency = reader.closureDependencySnapshotIntegrityForRelease(tag).currentIdentity;
    assert.ok(dependency?.digest);
    assert.ok(Number.isInteger(dependency?.rowCount));
    updateDependencySnapshot.run(dependency.digest, dependency.rowCount, tag);
  }

  const sourceIdentity = scoreSourceIdentityForDb(db);
  db.prepare(`
    UPDATE release_score_audits
    SET source_identity_json=?
  `).run(JSON.stringify(sourceIdentity));
  const tip = appendCurrentAuditHistoryRun(
    db,
    'source-run',
    '2026-07-03T12:05:00.000Z',
  );
  db.prepare(`
    INSERT INTO meta (key, value)
    VALUES ('score_persistence_last_run', ?)
  `).run(JSON.stringify({
    schemaVersion: 2,
    source: 'test',
    scope: null,
    persistedAt: '2026-07-03T12:05:00.000Z',
    scoreModelVersion: 'test-model',
    promptVersion: 6,
    scoredReleaseCount: 2,
    recommendedTag: 'v2',
    releaseTags: ['v2', 'v1'],
    minScoredAt: '2026-07-03T11:30:00.000Z',
    maxScoredAt: '2026-07-03T12:00:00.000Z',
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    sourceIdentityRowCount: sourceIdentity.rowCount,
    sourceIdentitySourceCount: sourceIdentity.sourceCount,
    historyRunId: tip.runId,
    historyRunContentHash: tip.contentHash,
  }));
  appendReleaseCatalogAuthority(db, {
    runId: 'production-doctor-catalog-refresh',
    startedAt: '2026-07-03T10:30:00.000Z',
  });
}

function seedProductionIssueCrawl(db: DatabaseSync) {
  const repository = 'openclaw/openclaw';
  const issue = {
    node_id: 'ISSUE-production-doctor-1',
    node_type: 'Issue' as const,
    number: 1,
    title: 'production doctor issue',
    body: null,
    state: 'closed' as const,
    user: {
      id: 'USER-production-reporter',
      type: 'User',
      login: 'production-reporter',
    },
    author_association: 'CONTRIBUTOR',
    created_at: '2026-07-01T22:00:00.000Z',
    updated_at: '2026-07-02T00:00:00.000Z',
    closed_at: '2026-07-02T00:00:00.000Z',
    html_url: 'https://example.test/issues/1',
    comments: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: [],
  };
  const records = [{ nodeId: issue.node_id, issue }];
  const membershipDigest = canonicalIssueMembershipDigest(1, records);
  const contentDigest = canonicalIssueContentDigest(1, records);
  const capturedAt = '2026-07-03T10:49:00.000Z';
  const staged = stageIssueCatalogSnapshot({
    repository,
    capturedAt,
    previousContentHash: null,
    catalog: {
      issues: [issue],
      metadata: {
        exhausted: true,
        stabilized: true,
        totalCount: 1,
        observedTotalCount: 1,
        postBoundaryGrowthCount: 0,
        nodeCount: 1,
        uniqueCount: 1,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        digest: membershipDigest,
        membershipDigest,
        contentDigest,
        snapshotBoundary: {
          totalCount: 1,
          terminalIssue: {
            nodeId: issue.node_id,
            issueNumber: issue.number,
            createdAt: issue.created_at,
          },
          membershipDigest,
        },
        lastRequestCursor: null,
        nextCursor: null,
        hasNextPage: false,
        sourceOrder: 'CREATED_AT_ASC',
      },
    },
  });
  const header = staged.header;
  db.prepare(`
    INSERT INTO issue_catalog_snapshots (
      snapshot_id, schema_version, row_schema_version, repository, source,
      source_order, captured_at, boundary_total_count, observed_total_count,
      post_boundary_growth_count, terminal_node_id, terminal_issue_number,
      terminal_created_at, fetched_count, unique_count, page_count,
      pages_fetched, sweep_count, membership_digest, content_digest,
      last_request_cursor, row_count, row_schema_digest, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (
      :snapshot_id, :schema_version, :row_schema_version, :repository, :source,
      :source_order, :captured_at, :boundary_total_count, :observed_total_count,
      :post_boundary_growth_count, :terminal_node_id, :terminal_issue_number,
      :terminal_created_at, :fetched_count, :unique_count, :page_count,
      :pages_fetched, :sweep_count, :membership_digest, :content_digest,
      :last_request_cursor, :row_count, :row_schema_digest, :rows_content_hash,
      :previous_content_hash, :content_hash
    )
  `).run({
    snapshot_id: header.snapshotId,
    schema_version: header.schemaVersion,
    row_schema_version: header.rowSchemaVersion,
    repository: header.repository,
    source: header.source,
    source_order: header.sourceOrder,
    captured_at: header.capturedAt,
    boundary_total_count: header.boundaryTotalCount,
    observed_total_count: header.observedTotalCount,
    post_boundary_growth_count: header.postBoundaryGrowthCount,
    terminal_node_id: header.terminalNodeId,
    terminal_issue_number: header.terminalIssueNumber,
    terminal_created_at: header.terminalCreatedAt,
    fetched_count: header.fetchedCount,
    unique_count: header.uniqueCount,
    page_count: header.pageCount,
    pages_fetched: header.pagesFetched,
    sweep_count: header.sweepCount,
    membership_digest: header.membershipDigest,
    content_digest: header.contentDigest,
    last_request_cursor: header.lastRequestCursor,
    row_count: header.rowCount,
    row_schema_digest: header.rowSchemaDigest,
    rows_content_hash: header.rowsContentHash,
    previous_content_hash: header.previousContentHash,
    content_hash: header.contentHash,
  });
  const insertRow = db.prepare(`
    INSERT INTO issue_catalog_snapshot_rows (
      snapshot_id, source_ordinal, issue_number, node_id, issue_json, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  for (const row of staged.rows) {
    insertRow.run(
      row.snapshotId,
      row.sourceOrdinal,
      row.issueNumber,
      row.nodeId,
      row.issueJson,
      row.contentHash,
    );
  }

  const consumptionRunId = 'production-doctor-refresh-run';
  const consumedAt = '2026-07-03T10:55:00.000Z';
  const previousConsumptionContentHash = (
    db.prepare(`
      SELECT content_hash AS contentHash
      FROM issue_catalog_snapshot_consumptions
      ORDER BY id DESC
      LIMIT 1
    `).get() as { contentHash?: string } | undefined
  )?.contentHash ?? null;
  const consumptionContentHash = createHash('sha256')
    .update(canonicalOperationJson([
      'issue-catalog-snapshot-consumption-v1',
      1,
      header.snapshotId,
      repository,
      consumptionRunId,
      consumedAt,
      header.rowCount,
      header.pageCount,
      header.contentHash,
      previousConsumptionContentHash,
    ]))
    .digest('hex');
  db.prepare(`
    INSERT INTO issue_catalog_snapshot_consumptions (
      schema_version, snapshot_id, repository, run_id, consumed_at,
      processed_row_count, processed_page_count, snapshot_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    header.snapshotId,
    repository,
    consumptionRunId,
    consumedAt,
    header.rowCount,
    header.pageCount,
    header.contentHash,
    previousConsumptionContentHash,
    consumptionContentHash,
  );

  const boundary = {
    totalCount: header.boundaryTotalCount,
    terminalIssue: {
      nodeId: header.terminalNodeId,
      issueNumber: header.terminalIssueNumber,
      createdAt: header.terminalCreatedAt,
    },
    membershipDigest: header.membershipDigest,
  };
  const baseline = {
    schemaVersion: 2,
    source: 'github.repository.issues',
    repository,
    sourceOrder: 'CREATED_AT_ASC',
    establishedAt: '2026-07-03T11:00:00.000Z',
    crawlStartedAt: '2026-07-03T10:50:00.000Z',
    boundaryTotalCount: 1,
    observedTotalCount: 1,
    postBoundaryGrowthCount: 0,
    asOfBoundary: boundary,
    fetchedCount: 1,
    uniqueCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: membershipDigest,
    membershipDigest,
    contentDigest: header.contentDigest,
    identity: createHash('sha256')
      .update(JSON.stringify([
        'openclaw/openclaw',
        'CREATED_AT_ASC',
        1,
        boundary.terminalIssue.nodeId,
        boundary.terminalIssue.issueNumber,
        boundary.terminalIssue.createdAt,
        membershipDigest,
      ]))
      .digest('hex'),
  };
  const issueCrawl = {
    schemaVersion: 4,
    repository: baseline.repository,
    startedAt: baseline.crawlStartedAt,
    finishedAt: baseline.establishedAt,
    fullIssueBackfill: true,
    crawlMode: 'exhaustive',
    backfillCompleteAtStart: false,
    backfillCompleteAfterRun: true,
    baseline,
    pagination: {
      schemaVersion: 2,
      source: 'github.repository.issues',
      repository: baseline.repository,
      sourceOrder: baseline.sourceOrder,
      completeness: 'exhaustive_stable',
      boundaryTotalCount: 1,
      observedTotalCount: 1,
      postBoundaryGrowthCount: 0,
      asOfBoundary: boundary,
      fetchedCount: 1,
      uniqueCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      exhausted: true,
      stabilized: true,
      digest: baseline.digest,
      membershipDigest: baseline.membershipDigest,
      contentDigest: baseline.contentDigest,
      lastRequestCursor: null,
      nextCursor: null,
      hasNextPage: false,
    },
    catalogSnapshot: {
      schemaVersion: 1,
      snapshotId: header.snapshotId,
      contentHash: header.contentHash,
      capturedAt,
      resumed: false,
      priorStatus: 'missing',
      maxAgeHours: 24,
      consumedAt,
      consumedByRunId: consumptionRunId,
      consumptionContentHash,
    },
    catalogAttestation: {
      schemaVersion: 1,
      snapshotId: header.snapshotId,
      snapshotContentHash: header.contentHash,
      observedAt: '2026-07-03T10:56:00.000Z',
      totalCount: header.boundaryTotalCount,
      membershipDigest: header.membershipDigest,
      contentDigest: header.contentDigest,
      finalSweepCount: header.sweepCount,
      finalPagesFetched: header.pagesFetched,
    },
    stopReason: 'exhausted',
    evidenceRefreshFailures: [],
    classificationFailures: [],
    scorePersisted: true,
    scorePersistedAt: '2026-07-03T12:05:00.000Z',
  };
  db.prepare(`
    INSERT INTO meta(key, value) VALUES('issue_crawl_exhaustive_baseline', ?)
  `).run(JSON.stringify(baseline));
  db.prepare(`
    INSERT INTO meta(key, value) VALUES('issue_crawl_last_run', ?)
  `).run(JSON.stringify(issueCrawl));
}

function insertProductionDoctorAudits(
  db: DatabaseSync,
  sourceIdentity: ReturnType<typeof scoreSourceIdentityForDb>,
) {
  const rows = [
    ['v2', 'v1', 7.8, 1, '2026-07-03T12:00:00.000Z'],
    ['v1', 'v0', 7.5, 0, '2026-07-03T11:30:00.000Z'],
  ] as const;
  const insert = db.prepare(`
    INSERT INTO release_score_audits (
      release_tag, scored_at, score_model_version, prompt_version,
      final_score, status, band, recommended, input_json, components_json,
      issue_evidence_json, gate_evidence_json, source_identity_json
    )
    VALUES (?, ?, 'test-model', 6, ?, 'eligible', 'good', ?, ?, '{}', ?, ?, ?)
  `);
  for (const [tag, predecessorTag, score, recommended, scoredAt] of rows) {
    const closureProof = {
      schemaVersion: 1,
      creditedCount: 0,
      notCreditedCount: 0,
      analyzedClosedCount: 0,
      containedFixedCount: 0,
      containedNotCreditedCount: 0,
      targetTag: tag,
      predecessorTag,
      fixCreditDecisionCounts: { credited: 0, withheld: 0, invalid: 0 },
      fixCreditDecisions: [],
      byStatus: {},
      byRiskDisposition: {},
      riskSummary: {},
    };
    const releaseFixCredit = {
      schemaVersion: 1,
      targetTag: tag,
      predecessorTag,
      countedClosedCount: 0,
      notCountedClosedCount: 0,
      analyzedClosedCount: 0,
      containedFixedCount: 0,
      containedNotCreditedCount: 0,
      decisionCounts: { credited: 0, withheld: 0, invalid: 0 },
      decisions: [],
    };
    insert.run(
      tag,
      scoredAt,
      score,
      recommended,
      JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 1 }),
      JSON.stringify({
        debtSummary: {},
        verifiedDebt: [],
        carryoverDebt: [],
        staleDebt: [],
        openedFeltSerious: [],
        verifiedFixed: [],
        unverifiedClosed: [],
        unclassifiedIssues: [],
      }),
      JSON.stringify({ fixProvenance: { closureProof, releaseFixCredit } }),
      JSON.stringify(sourceIdentity),
    );
  }
}

function appendCurrentAuditHistoryRun(
  db: DatabaseSync,
  runId: string,
  recordedAt: string,
) {
  db.prepare(`
    INSERT INTO release_score_audit_history (
      run_id, recorded_at, release_tag, scored_at, score_model_version,
      prompt_version, final_score, status, band, recommended, input_json,
      components_json, issue_evidence_json, gate_evidence_json,
      source_identity_json
    )
    SELECT
      ?, ?, release_tag, scored_at, score_model_version, prompt_version,
      final_score, status, band, recommended, input_json, components_json,
      issue_evidence_json, gate_evidence_json, source_identity_json
    FROM release_score_audits
    ORDER BY release_tag
  `).run(runId, recordedAt);
  const rows = db.prepare(`
    SELECT *
    FROM release_score_audit_history
    WHERE run_id=?
    ORDER BY release_tag
  `).all(runId) as Array<Record<string, unknown>>;
  const previousContentHash = (db.prepare(`
    SELECT content_hash
    FROM release_score_audit_history_runs
    ORDER BY id DESC
    LIMIT 1
  `).get() as { content_hash?: string } | undefined)?.content_hash ?? null;
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
  const contentHash = releaseScoreAuditHistoryRunContentHash({
    runId,
    recordedAt,
    rowCount: rows.length,
    rowsContentHash,
    previousContentHash,
  });
  db.prepare(`
    INSERT INTO release_score_audit_history_runs (
      run_id, recorded_at, row_count, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(
    runId,
    recordedAt,
    rows.length,
    rowsContentHash,
    previousContentHash,
    contentHash,
  );
  return { runId, contentHash };
}

function updateScorePersistenceHistoryTip(
  db: DatabaseSync,
  tip: { runId: string; contentHash: string },
) {
  const value = db.prepare(`
    SELECT value
    FROM meta
    WHERE key='score_persistence_last_run'
  `).get()?.value;
  const meta = JSON.parse(String(value));
  db.prepare(`
    UPDATE meta
    SET value=?
    WHERE key='score_persistence_last_run'
  `).run(JSON.stringify({
    ...meta,
    historyRunId: tip.runId,
    historyRunContentHash: tip.contentHash,
  }));
}

function rewriteProductionCandidate(path: string, { score }: { score: number }) {
  const db = new DatabaseSync(path);
  try {
    db.exec(`
      DROP TRIGGER release_score_audit_history_no_update;
      DROP TRIGGER release_score_audit_history_runs_no_update;
    `);
    db.prepare(`
      UPDATE releases
      SET final_score=?
      WHERE final_score IS NOT NULL
    `).run(score);
    db.prepare(`
      UPDATE release_score_audits
      SET final_score=?, score_model_version=?, prompt_version=?
    `).run(score, SCORE_MODEL_VERSION, PROMPT_VERSION);
    db.prepare(`
      UPDATE release_score_audit_history
      SET final_score=?, score_model_version=?, prompt_version=?
    `).run(score, SCORE_MODEL_VERSION, PROMPT_VERSION);

    let previousContentHash: string | null = null;
    const seals = db.prepare(`
      SELECT *
      FROM release_score_audit_history_runs
      ORDER BY id
    `).all() as any[];
    for (const seal of seals) {
      const rows = db.prepare(`
        SELECT *
        FROM release_score_audit_history
        WHERE run_id=?
        ORDER BY release_tag
      `).all(seal.run_id) as Array<Record<string, unknown>>;
      const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(rows);
      const contentHash = releaseScoreAuditHistoryRunContentHash({
        runId: seal.run_id,
        recordedAt: seal.recorded_at,
        rowCount: rows.length,
        rowsContentHash,
        previousContentHash,
      });
      db.prepare(`
        UPDATE release_score_audit_history_runs
        SET row_count=?, rows_content_hash=?, previous_content_hash=?, content_hash=?
        WHERE run_id=?
      `).run(
        rows.length,
        rowsContentHash,
        previousContentHash,
        contentHash,
        seal.run_id,
      );
      previousContentHash = contentHash;
    }
    const meta = readScorePersistenceMetaFromDb(db);
    db.prepare(`
      UPDATE meta
      SET value=?
      WHERE key='score_persistence_last_run'
    `).run(JSON.stringify({
      ...meta,
      scoreModelVersion: SCORE_MODEL_VERSION,
      promptVersion: PROMPT_VERSION,
      historyRunContentHash: previousContentHash,
    }));
    installProductionHistoryUpdateTriggers(db);
    db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
  } finally {
    db.close();
  }
  rmSync(`${path}-wal`, { force: true });
  rmSync(`${path}-shm`, { force: true });
  rmSync(`${path}-journal`, { force: true });
}

function readScorePersistenceMetaFromDb(db: DatabaseSync) {
  return JSON.parse(String(db.prepare(`
    SELECT value
    FROM meta
    WHERE key='score_persistence_last_run'
  `).get()?.value));
}

function installProductionHistoryUpdateTriggers(db: DatabaseSync) {
  db.exec(`
    CREATE TRIGGER release_score_audit_history_no_update
    BEFORE UPDATE ON release_score_audit_history
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_runs_no_update
    BEFORE UPDATE ON release_score_audit_history_runs
    BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_runs is append-only');
    END;
  `);
}

function createFixture(
  name: string,
  { installerLayout = false }: { installerLayout?: boolean } = {},
) {
  const dir = mkdtempSync(join(tmpdir(), `radar-promote-${name}-`));
  const sourcePath = join(dir, 'quality.db');
  const destinationDirectory = installerLayout ? join(dir, 'shared') : dir;
  if (installerLayout) mkdirSync(destinationDirectory);
  const destinationPath = join(destinationDirectory, 'primary.db');
  const source = createPromotionDb(sourcePath);
  const destination = createPromotionDb(destinationPath);
  return {
    dir,
    source,
    destination,
    sourcePath,
    destinationPath,
    cleanup: () => {
      try { source.close(); } catch { /* already closed */ }
      try { destination.close(); } catch { /* already closed */ }
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

const installerPendingIdentityFields = INSTALLER_PENDING_STATE_FIELDS;

function prepareInstallerOwnedPromotion(
  fixture: ReturnType<typeof createFixture>,
) {
  const releaseSha = 'a'.repeat(40);
  const releaseName = 'release-candidate';
  const artifactDigest = `sha256:${'c'.repeat(64)}`;
  const transactionId = '11111111-1111-4111-8111-111111111111';
  setPromotionState(fixture.source, 'quality-ready');
  seedHistory(fixture.source, [historyRow('installer-history', 'v1', 8)]);
  const operation = seedOperationReceiptRunWithCatalogAuthority(fixture.source, {
    runId: 'installer-refresh',
    codeRevision: releaseSha,
  });
  const scorePersistence = readScorePersistenceMetaFromDb(fixture.source);
  fixture.source.prepare(`
    UPDATE meta
    SET value=?
    WHERE key='score_persistence_last_run'
  `).run(JSON.stringify({
    ...scorePersistence,
    operationReceiptRequired: true,
    operationRunId: operation.attempt.run_id,
    codeRevision: releaseSha,
  }));
  closeFixtureDatabases(fixture);

  const rollbackBackupPath = join(
    fixture.dir,
    'deploy-backups',
    releaseName,
    'pre-migration.sqlite',
  );
  mkdirSync(dirname(rollbackBackupPath), { recursive: true });
  copyFileSync(fixture.destinationPath, rollbackBackupPath);
  const pendingPath = join(fixture.dir, '.pending-deploy');
  mkdirSync(pendingPath);
  const runtimeEnvPath = join(
    fixture.dir,
    'runtime-env',
    `${releaseName}.env`,
  );
  mkdirSync(dirname(runtimeEnvPath), { recursive: true });
  writeFileSync(
    runtimeEnvPath,
    [
      'GITHUB_OWNER=openclaw',
      'GITHUB_REPO=openclaw',
      'GITHUB_TOKEN=github-test-token',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  const fields: Record<(typeof installerPendingIdentityFields)[number], string> = {
    pending_schema_version: String(INSTALLER_PENDING_STATE_SCHEMA_VERSION),
    promotion_required: '1',
    transaction_id: transactionId,
    deadline_epoch: String(Math.floor(Date.now() / 1000) + 2_400),
    release_name: releaseName,
    github_sha: releaseSha,
    artifact_digest: artifactDigest,
    release_dir: join(fixture.dir, 'releases', releaseName),
    release_created: '1',
    previous_current_present: '1',
    previous_current_target: join(fixture.dir, 'releases', 'release-previous'),
    tarball: join(fixture.dir, `${releaseName}.tar.gz`),
    tarball_sha256: 'd'.repeat(64),
    tarball_size_bytes: '1',
    runtime_env_path: runtimeEnvPath,
    runtime_env_created: '1',
    database_path: fixture.destinationPath,
    db_snapshot_path: rollbackBackupPath,
    db_snapshot_sha256: sha256File(rollbackBackupPath),
    quality_database_path: fixture.sourcePath,
    required_score_receipt_id: operation.receipt.receipt_id,
  };
  writeInstallerPendingIdentity(pendingPath, fields);
  const pendingStateHash = installerPendingStateHash(fields);
  writeFileSync(
    join(pendingPath, 'pending_state_hash'),
    `${pendingStateHash}\n`,
  );
  return {
    pendingPath,
    rollbackBackupPath,
    receiptId: operation.receipt.receipt_id,
    fields,
    transaction: {
      transactionId,
      releaseName,
      releaseSha,
      artifactDigest,
      pendingStateHash,
      requiredScoreReceiptId: operation.receipt.receipt_id,
      inheritedLockFd: 9,
    },
  };
}

function updateInstallerPendingIdentity(
  installer: ReturnType<typeof prepareInstallerOwnedPromotion>,
  updates: Partial<Record<(typeof installerPendingIdentityFields)[number], string>>,
) {
  Object.assign(installer.fields, updates);
  writeInstallerPendingIdentity(installer.pendingPath, installer.fields);
  installer.transaction.transactionId = installer.fields.transaction_id;
  installer.transaction.releaseName = installer.fields.release_name;
  installer.transaction.releaseSha = installer.fields.github_sha;
  installer.transaction.artifactDigest = installer.fields.artifact_digest;
  installer.transaction.requiredScoreReceiptId =
    installer.fields.required_score_receipt_id;
  installer.transaction.pendingStateHash =
    installerPendingStateHash(installer.fields);
  writeFileSync(
    join(installer.pendingPath, 'pending_state_hash'),
    `${installer.transaction.pendingStateHash}\n`,
  );
}

function writeInstallerPendingIdentity(
  pendingPath: string,
  fields: Record<(typeof installerPendingIdentityFields)[number], string>,
) {
  for (const field of installerPendingIdentityFields) {
    writeFileSync(join(pendingPath, field), `${fields[field]}\n`);
  }
}

function sha256File(path: string) {
  return createHash('sha256').update(readFileSync(path)).digest('hex');
}

function createPromotionDb(path: string) {
  const db = new DatabaseSync(path);
  db.exec('BEGIN IMMEDIATE');
  try {
    db.exec(`
    CREATE TABLE advisory_snapshot_history (
      id INTEGER PRIMARY KEY,
      captured_at TEXT NOT NULL,
      row_count INTEGER NOT NULL,
      content_hash TEXT NOT NULL
    );
    CREATE TABLE advisory_snapshot_rows (
      snapshot_id INTEGER NOT NULL,
      advisory_key TEXT NOT NULL,
      payload TEXT,
      PRIMARY KEY(snapshot_id, advisory_key)
    );
    CREATE TABLE advisories (
      advisory_key TEXT PRIMARY KEY,
      ghsa_id TEXT NOT NULL,
      cve_id TEXT,
      summary TEXT NOT NULL,
      severity TEXT NOT NULL,
      html_url TEXT NOT NULL,
      published_at TEXT,
      package_ecosystem TEXT,
      package_name TEXT,
      vulnerable_version_range TEXT,
      patched_versions TEXT,
      fetched_at TEXT NOT NULL
    );
    CREATE TABLE releases (
      tag TEXT PRIMARY KEY,
      node_id TEXT,
      catalog_tag_commit_oid TEXT,
      name TEXT,
      published_at TEXT,
      created_at TEXT,
      updated_at TEXT,
      html_url TEXT,
      prerelease INTEGER NOT NULL DEFAULT 0,
      catalog_rank INTEGER,
      catalog_digest TEXT,
      catalog_active INTEGER NOT NULL DEFAULT 0,
      final_score REAL,
      negative_issues INTEGER,
      positive_issues INTEGER,
      scored_at TEXT,
      state TEXT,
      closed_serious_fixed INTEGER NOT NULL DEFAULT 0,
      opened_serious_during_reign INTEGER NOT NULL DEFAULT 0,
      body TEXT,
      recommended INTEGER NOT NULL DEFAULT 0,
      score_reason TEXT,
      broken_surfaces TEXT
    );
    CREATE TABLE advisory_snapshot_v2_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      schema_version INTEGER NOT NULL CHECK(schema_version = 2),
      captured_at TEXT NOT NULL,
      repository_owner TEXT NOT NULL,
      repository_name TEXT NOT NULL,
      repository_url TEXT NOT NULL,
      target_ecosystem TEXT NOT NULL,
      target_package_name TEXT NOT NULL,
      source_hash TEXT NOT NULL,
      catalog_hash TEXT NOT NULL,
      score_hash TEXT NOT NULL,
      score_ready INTEGER NOT NULL CHECK(score_ready = 1),
      row_count INTEGER NOT NULL,
      score_row_count INTEGER NOT NULL,
      score_content_digest TEXT NOT NULL,
      snapshot_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX idx_advisory_snapshot_v2_history_captured
      ON advisory_snapshot_v2_history(captured_at, id);
    CREATE TABLE advisory_snapshot_v2_rows (
      snapshot_id INTEGER NOT NULL,
      range_identity TEXT NOT NULL,
      ghsa_id TEXT NOT NULL,
      package_ecosystem TEXT NOT NULL,
      package_name TEXT NOT NULL,
      vulnerable_version_range TEXT NOT NULL,
      state TEXT NOT NULL,
      target_package INTEGER NOT NULL CHECK(target_package IN (0, 1)),
      score_eligible INTEGER NOT NULL CHECK(score_eligible IN (0, 1)),
      audit_only INTEGER NOT NULL CHECK(audit_only IN (0, 1)),
      row_json TEXT NOT NULL,
      row_hash TEXT NOT NULL,
      PRIMARY KEY(snapshot_id, range_identity),
      FOREIGN KEY(snapshot_id)
        REFERENCES advisory_snapshot_v2_history(id) ON DELETE RESTRICT
    );
    CREATE INDEX idx_advisory_snapshot_v2_rows_ghsa
      ON advisory_snapshot_v2_rows(snapshot_id, ghsa_id, range_identity);
    CREATE TABLE issue_catalog_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      snapshot_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL,
      row_schema_version INTEGER NOT NULL,
      repository TEXT NOT NULL,
      source TEXT NOT NULL,
      source_order TEXT NOT NULL,
      captured_at TEXT NOT NULL,
      boundary_total_count INTEGER NOT NULL,
      observed_total_count INTEGER NOT NULL,
      post_boundary_growth_count INTEGER NOT NULL,
      terminal_node_id TEXT,
      terminal_issue_number INTEGER,
      terminal_created_at TEXT,
      fetched_count INTEGER NOT NULL,
      unique_count INTEGER NOT NULL,
      page_count INTEGER NOT NULL,
      pages_fetched INTEGER NOT NULL,
      sweep_count INTEGER NOT NULL,
      membership_digest TEXT NOT NULL,
      content_digest TEXT NOT NULL,
      last_request_cursor TEXT,
      row_count INTEGER NOT NULL,
      row_schema_digest TEXT NOT NULL,
      rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE issue_catalog_snapshot_rows (
      snapshot_id TEXT NOT NULL,
      source_ordinal INTEGER NOT NULL,
      issue_number INTEGER NOT NULL,
      node_id TEXT NOT NULL,
      issue_json TEXT NOT NULL,
      content_hash TEXT NOT NULL,
      PRIMARY KEY(snapshot_id, source_ordinal),
      UNIQUE(snapshot_id, issue_number),
      UNIQUE(snapshot_id, node_id)
    );
    CREATE TABLE issue_catalog_snapshot_consumptions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      schema_version INTEGER NOT NULL,
      snapshot_id TEXT NOT NULL UNIQUE,
      repository TEXT NOT NULL,
      run_id TEXT NOT NULL UNIQUE,
      consumed_at TEXT NOT NULL,
      processed_row_count INTEGER NOT NULL,
      processed_page_count INTEGER NOT NULL,
      snapshot_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      FOREIGN KEY(snapshot_id)
        REFERENCES issue_catalog_snapshots(snapshot_id) ON DELETE RESTRICT
    );
    CREATE INDEX idx_issue_catalog_snapshot_consumptions_run
      ON issue_catalog_snapshot_consumptions(run_id, consumed_at);
    CREATE TABLE release_score_audit_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      scored_at TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      final_score REAL,
      status TEXT NOT NULL,
      band TEXT NOT NULL,
      recommended INTEGER NOT NULL DEFAULT 0,
      input_json TEXT NOT NULL,
      components_json TEXT,
      issue_evidence_json TEXT NOT NULL,
      gate_evidence_json TEXT NOT NULL,
      source_identity_json TEXT NOT NULL,
      authority_run_id TEXT,
      UNIQUE(run_id, release_tag)
    );
    CREATE TABLE release_score_audit_history_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL UNIQUE,
      recorded_at TEXT NOT NULL,
      row_count INTEGER NOT NULL,
      rows_content_hash TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE TABLE release_validation_forecasts (
      id INTEGER PRIMARY KEY,
      decision_id TEXT NOT NULL UNIQUE,
      opportunity_code TEXT NOT NULL,
      latest_release_tag TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      code_revision TEXT,
      payload TEXT NOT NULL
    );
    CREATE UNIQUE INDEX idx_release_validation_forecasts_series_without_revision
      ON release_validation_forecasts(
        opportunity_code, latest_release_tag, score_model_version, prompt_version
      )
      WHERE code_revision IS NULL;
    CREATE UNIQUE INDEX idx_release_validation_forecasts_series_with_revision
      ON release_validation_forecasts(
        opportunity_code, latest_release_tag, score_model_version, prompt_version, code_revision
      )
      WHERE code_revision IS NOT NULL;
    CREATE TABLE release_validation_opportunity_enrollments (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      opportunity_id TEXT NOT NULL UNIQUE,
      enrolled_at TEXT NOT NULL,
      release_node_id TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      release_published_at TEXT NOT NULL,
      opportunity_code TEXT NOT NULL,
      opens_at TEXT NOT NULL,
      closes_at_exclusive TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      code_revision TEXT NOT NULL,
      enrollment_run_id TEXT NOT NULL,
      operation_attempt_content_hash TEXT NOT NULL,
      catalog_digest TEXT NOT NULL,
      catalog_release_count INTEGER NOT NULL CHECK(catalog_release_count > 0),
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      UNIQUE(
        release_tag,
        opportunity_code,
        score_model_version,
        prompt_version,
        code_revision
      ),
      FOREIGN KEY(enrollment_run_id)
        REFERENCES refresh_operation_attempts(run_id) ON DELETE RESTRICT
    );
    CREATE INDEX idx_release_validation_opportunity_enrollments_cohort
      ON release_validation_opportunity_enrollments(
        score_model_version, prompt_version, code_revision, enrolled_at, id
      );
    CREATE INDEX idx_release_validation_opportunity_enrollments_release
      ON release_validation_opportunity_enrollments(
        release_tag, release_published_at, opportunity_code
      );
    CREATE TABLE release_validation_outcome_observations (
      id INTEGER PRIMARY KEY,
      observation_id TEXT NOT NULL,
      decision_id TEXT NOT NULL,
      horizon_code TEXT NOT NULL,
      status TEXT NOT NULL,
      payload TEXT NOT NULL
    );
    CREATE UNIQUE INDEX idx_release_validation_outcomes_one_matured
      ON release_validation_outcome_observations(decision_id, horizon_code)
      WHERE status='matured';
    CREATE TABLE release_validation_observation_batches (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      batch_id TEXT NOT NULL UNIQUE,
      observed_at TEXT NOT NULL,
      code_revision TEXT NOT NULL,
      source_identity_digest TEXT NOT NULL,
      forecast_count INTEGER NOT NULL CHECK(forecast_count >= 0),
      intended_count INTEGER NOT NULL CHECK(intended_count >= 0),
      inserted_count INTEGER NOT NULL CHECK(inserted_count >= 0),
      already_existing_count INTEGER NOT NULL CHECK(already_existing_count >= 0),
      pending_count INTEGER NOT NULL CHECK(pending_count >= 0),
      excluded_count INTEGER NOT NULL CHECK(excluded_count >= 0),
      indeterminate_count INTEGER NOT NULL CHECK(indeterminate_count >= 0),
      results_json TEXT NOT NULL,
      outcome_chain_previous_hash TEXT,
      outcome_chain_content_hash TEXT,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX idx_release_validation_observation_batches_observed
      ON release_validation_observation_batches(observed_at, id);
    CREATE TABLE promotion_state (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    INSERT INTO promotion_state (key, value) VALUES ('state', 'initial');
    CREATE TABLE meta (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE refresh_leases (
      name TEXT PRIMARY KEY,
      holder_id TEXT NOT NULL,
      acquired_at TEXT NOT NULL,
      expires_at TEXT NOT NULL
    );
    CREATE TABLE refresh_operation_attempts (
      run_id TEXT PRIMARY KEY,
      operation TEXT NOT NULL,
      trigger TEXT NOT NULL,
      started_at TEXT NOT NULL,
      lease_name TEXT NOT NULL,
      lease_holder_id TEXT NOT NULL,
      lease_expires_at TEXT NOT NULL,
      code_revision TEXT NOT NULL,
      effective_config_json TEXT NOT NULL,
      effective_config_hash TEXT NOT NULL,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX idx_refresh_operation_attempts_started
      ON refresh_operation_attempts(started_at, run_id);
    CREATE TABLE refresh_operation_stage_events (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event_id TEXT NOT NULL UNIQUE,
      run_id TEXT NOT NULL,
      sequence INTEGER NOT NULL,
      stage TEXT NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('started', 'completed', 'failed')),
      occurred_at TEXT NOT NULL,
      duration_ms INTEGER,
      counts_json TEXT,
      details_json TEXT,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      UNIQUE(run_id, sequence),
      FOREIGN KEY(run_id) REFERENCES refresh_operation_attempts(run_id) ON DELETE RESTRICT
    );
    CREATE INDEX idx_refresh_operation_stage_events_run
      ON refresh_operation_stage_events(run_id, sequence);
    CREATE TABLE refresh_capture_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      run_id TEXT NOT NULL UNIQUE,
      status TEXT NOT NULL CHECK(status IN ('success', 'failure', 'abandoned')),
      finished_at TEXT NOT NULL,
      duration_ms INTEGER NOT NULL,
      stage_event_count INTEGER NOT NULL,
      stage_chain_hash TEXT,
      payload_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      FOREIGN KEY(run_id) REFERENCES refresh_operation_attempts(run_id) ON DELETE RESTRICT
    );
    CREATE INDEX idx_refresh_capture_receipts_finished
      ON refresh_capture_receipts(finished_at, id);
    CREATE TABLE release_catalog_capture_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      operation_run_id TEXT,
      source_kind TEXT NOT NULL
        CHECK(source_kind IN ('github_graphql', 'test_fixture')),
      repository TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      active_catalog_digest TEXT NOT NULL,
      active_release_count INTEGER NOT NULL CHECK(active_release_count >= 0),
      payload_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      CHECK(
        (source_kind = 'github_graphql' AND operation_run_id IS NOT NULL) OR
        (source_kind = 'test_fixture' AND operation_run_id IS NULL)
      ),
      FOREIGN KEY(operation_run_id)
        REFERENCES refresh_operation_attempts(run_id) ON DELETE RESTRICT
    );
    CREATE UNIQUE INDEX idx_release_catalog_capture_operation
      ON release_catalog_capture_receipts(operation_run_id)
      WHERE operation_run_id IS NOT NULL;
    CREATE INDEX idx_release_catalog_capture_observed
      ON release_catalog_capture_receipts(observed_at, id);
    CREATE TABLE issue_state_event_snapshots (
      issue_number INTEGER PRIMARY KEY,
      repository_node_id TEXT,
      issue_node_id TEXT,
      issue_node_type TEXT,
      schema_version INTEGER NOT NULL,
      issue_state TEXT NOT NULL,
      issue_updated_at TEXT NOT NULL,
      total_count INTEGER NOT NULL,
      fetched_count INTEGER NOT NULL,
      events_digest TEXT NOT NULL,
      authority_digest TEXT,
      events_json TEXT NOT NULL,
      sweep_count INTEGER NOT NULL DEFAULT 0,
      stabilized INTEGER NOT NULL DEFAULT 0,
      stabilization_json TEXT,
      stabilization_identity_digest TEXT,
      revision INTEGER NOT NULL DEFAULT 1,
      fetched_at TEXT NOT NULL,
      verified_at TEXT NOT NULL
    );
    CREATE INDEX idx_issue_state_event_snapshots_verified
      ON issue_state_event_snapshots(verified_at);
    CREATE TABLE release_closure_dependency_snapshots (
      release_tag TEXT PRIMARY KEY,
      schema_version INTEGER NOT NULL,
      analyzer_version INTEGER NOT NULL,
      issue_numbers_json TEXT NOT NULL,
      dependency_digest TEXT NOT NULL,
      dependency_row_count INTEGER NOT NULL,
      captured_at TEXT NOT NULL
    );
    CREATE TABLE ingestion_evidence_failures (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      occurred_at TEXT NOT NULL,
      source TEXT NOT NULL,
      scope TEXT,
      release_tag TEXT,
      issue_number INTEGER,
      pr_repository_name_with_owner TEXT,
      pr_number INTEGER,
      message TEXT NOT NULL,
      context_json TEXT,
      scoring_blocking INTEGER NOT NULL DEFAULT 1
    );
    CREATE TABLE comparison_snapshots (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_url TEXT NOT NULL,
      captured_at TEXT NOT NULL,
      page_title TEXT NOT NULL,
      page_text TEXT NOT NULL,
      raw_html TEXT NOT NULL
    );
    CREATE TABLE comparison_releases (
      snapshot_id INTEGER NOT NULL,
      tag TEXT NOT NULL,
      name TEXT,
      published_at TEXT,
      html_url TEXT NOT NULL,
      displayed_date TEXT,
      score REAL,
      band TEXT,
      status TEXT,
      recommended INTEGER NOT NULL DEFAULT 0,
      reason TEXT,
      negative_issues INTEGER,
      positive_issues INTEGER,
      total_attributed_issues INTEGER,
      visible_issues_json TEXT NOT NULL DEFAULT '[]',
      raw_card_text TEXT NOT NULL,
      PRIMARY KEY (snapshot_id, tag),
      FOREIGN KEY (snapshot_id) REFERENCES comparison_snapshots(id) ON DELETE CASCADE
    );

    CREATE TRIGGER advisory_snapshot_history_no_update
    BEFORE UPDATE ON advisory_snapshot_history BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_history_no_delete
    BEFORE DELETE ON advisory_snapshot_history BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_rows_no_update
    BEFORE UPDATE ON advisory_snapshot_rows BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_rows_no_delete
    BEFORE DELETE ON advisory_snapshot_rows BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_history_no_update
    BEFORE UPDATE ON advisory_snapshot_v2_history BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_history_no_delete
    BEFORE DELETE ON advisory_snapshot_v2_history BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_history is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_rows_no_update
    BEFORE UPDATE ON advisory_snapshot_v2_rows BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_rows is append-only');
    END;
    CREATE TRIGGER advisory_snapshot_v2_rows_no_delete
    BEFORE DELETE ON advisory_snapshot_v2_rows BEGIN
      SELECT RAISE(ABORT, 'advisory_snapshot_v2_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshots_no_update
    BEFORE UPDATE ON issue_catalog_snapshots BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshots is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshots_no_delete
    BEFORE DELETE ON issue_catalog_snapshots BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshots is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_rows_no_update
    BEFORE UPDATE ON issue_catalog_snapshot_rows BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_rows_no_delete
    BEFORE DELETE ON issue_catalog_snapshot_rows BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_rows is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_consumptions_no_update
    BEFORE UPDATE ON issue_catalog_snapshot_consumptions BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_consumptions is append-only');
    END;
    CREATE TRIGGER issue_catalog_snapshot_consumptions_no_delete
    BEFORE DELETE ON issue_catalog_snapshot_consumptions BEGIN
      SELECT RAISE(ABORT, 'issue_catalog_snapshot_consumptions is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_no_update
    BEFORE UPDATE ON release_score_audit_history BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_no_delete
    BEFORE DELETE ON release_score_audit_history BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_runs_no_update
    BEFORE UPDATE ON release_score_audit_history_runs BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_runs is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_runs_no_delete
    BEFORE DELETE ON release_score_audit_history_runs BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history_runs is append-only');
    END;
    CREATE TRIGGER release_validation_forecasts_no_update
    BEFORE UPDATE ON release_validation_forecasts BEGIN
      SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
    END;
    CREATE TRIGGER release_validation_forecasts_no_delete
    BEFORE DELETE ON release_validation_forecasts BEGIN
      SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
    END;
    CREATE TRIGGER release_validation_opportunity_enrollments_no_update
    BEFORE UPDATE ON release_validation_opportunity_enrollments BEGIN
      SELECT RAISE(ABORT, 'release_validation_opportunity_enrollments is append-only');
    END;
    CREATE TRIGGER release_validation_opportunity_enrollments_no_delete
    BEFORE DELETE ON release_validation_opportunity_enrollments BEGIN
      SELECT RAISE(ABORT, 'release_validation_opportunity_enrollments is append-only');
    END;
    CREATE TRIGGER release_validation_outcomes_no_update
    BEFORE UPDATE ON release_validation_outcome_observations BEGIN
      SELECT RAISE(ABORT, 'release_validation_outcome_observations is append-only');
    END;
    CREATE TRIGGER release_validation_outcomes_no_delete
    BEFORE DELETE ON release_validation_outcome_observations BEGIN
      SELECT RAISE(ABORT, 'release_validation_outcome_observations is append-only');
    END;
    CREATE TRIGGER release_validation_observation_batches_no_update
    BEFORE UPDATE ON release_validation_observation_batches BEGIN
      SELECT RAISE(ABORT, 'release_validation_observation_batches is append-only');
    END;
    CREATE TRIGGER release_validation_observation_batches_no_delete
    BEFORE DELETE ON release_validation_observation_batches BEGIN
      SELECT RAISE(ABORT, 'release_validation_observation_batches is append-only');
    END;
    CREATE TRIGGER refresh_operation_attempts_no_update
    BEFORE UPDATE ON refresh_operation_attempts BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_attempts is append-only');
    END;
    CREATE TRIGGER refresh_operation_attempts_no_delete
    BEFORE DELETE ON refresh_operation_attempts BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_attempts is append-only');
    END;
    CREATE TRIGGER refresh_operation_stage_events_no_update
    BEFORE UPDATE ON refresh_operation_stage_events BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_stage_events is append-only');
    END;
    CREATE TRIGGER refresh_operation_stage_events_no_delete
    BEFORE DELETE ON refresh_operation_stage_events BEGIN
      SELECT RAISE(ABORT, 'refresh_operation_stage_events is append-only');
    END;
    CREATE TRIGGER refresh_capture_receipts_no_update
    BEFORE UPDATE ON refresh_capture_receipts BEGIN
      SELECT RAISE(ABORT, 'refresh_capture_receipts is append-only');
    END;
    CREATE TRIGGER refresh_capture_receipts_no_delete
    BEFORE DELETE ON refresh_capture_receipts BEGIN
      SELECT RAISE(ABORT, 'refresh_capture_receipts is append-only');
    END;
    CREATE TRIGGER release_catalog_capture_receipts_no_update
    BEFORE UPDATE ON release_catalog_capture_receipts BEGIN
      SELECT RAISE(ABORT, 'release_catalog_capture_receipts is append-only');
    END;
    CREATE TRIGGER release_catalog_capture_receipts_no_delete
    BEFORE DELETE ON release_catalog_capture_receipts BEGIN
      SELECT RAISE(ABORT, 'release_catalog_capture_receipts is append-only');
    END;
  `);
    createReleaseArtifactVerificationTables(db);
    createGenericImmutableLedgerTables(db);
    createCanonicalValidationProofTables(db);
    seedDefaultReleaseCatalogAuthority(db);
    db.exec('COMMIT');
    return db;
  } catch (error) {
    try {
      db.exec('ROLLBACK');
    } catch {
      // Preserve the original fixture-construction failure.
    }
    db.close();
    throw error;
  }
}

function createReleaseArtifactVerificationTables(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE release_artifact_verification_receipts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      receipt_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL CHECK(schema_version = 2),
      release_repository TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      release_node_id TEXT NOT NULL,
      release_tag_commit_oid TEXT NOT NULL,
      release_published_at TEXT NOT NULL,
      evidence_identity TEXT NOT NULL UNIQUE,
      canonical_receipt_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE
    );
    CREATE INDEX idx_release_artifact_receipts_release
      ON release_artifact_verification_receipts(
        release_repository,
        release_tag,
        release_node_id,
        release_tag_commit_oid,
        id
      );
    CREATE TRIGGER release_artifact_verification_receipts_no_update
    BEFORE UPDATE ON release_artifact_verification_receipts
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_receipts is append-only'
      );
    END;
    CREATE TRIGGER release_artifact_verification_receipts_no_delete
    BEFORE DELETE ON release_artifact_verification_receipts
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_receipts is append-only'
      );
    END;

    CREATE TABLE release_artifact_verification_observations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      observation_id TEXT NOT NULL UNIQUE,
      schema_version INTEGER NOT NULL CHECK(schema_version = 1),
      run_id TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      release_repository TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      release_node_id TEXT NOT NULL,
      release_tag_commit_oid TEXT NOT NULL,
      release_published_at TEXT NOT NULL,
      receipt_id TEXT NOT NULL,
      receipt_content_hash TEXT NOT NULL,
      canonical_observation_json TEXT NOT NULL,
      previous_content_hash TEXT,
      content_hash TEXT NOT NULL UNIQUE,
      UNIQUE(
        run_id,
        release_repository,
        release_node_id,
        release_tag_commit_oid
      )
    );
    CREATE INDEX idx_release_artifact_observations_run
      ON release_artifact_verification_observations(run_id, id);
    CREATE INDEX idx_release_artifact_observations_release
      ON release_artifact_verification_observations(
        release_repository,
        release_tag,
        release_node_id,
        release_tag_commit_oid,
        id
      );
    CREATE TRIGGER release_artifact_verification_observations_no_update
    BEFORE UPDATE ON release_artifact_verification_observations
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_observations is append-only'
      );
    END;
    CREATE TRIGGER release_artifact_verification_observations_no_delete
    BEFORE DELETE ON release_artifact_verification_observations
    BEGIN
      SELECT RAISE(
        ABORT,
        'release_artifact_verification_observations is append-only'
      );
    END;
  `);
}

function createGenericImmutableLedgerTables(db: DatabaseSync) {
  for (const table of fixtureGenericImmutableLedgerTables) {
    db.exec(`
      CREATE TABLE ${table} (
        ledger_id TEXT PRIMARY KEY,
        content_hash TEXT NOT NULL UNIQUE
      );
      CREATE TRIGGER ${table}_no_update
      BEFORE UPDATE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
      CREATE TRIGGER ${table}_no_delete
      BEFORE DELETE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
    `);
  }
}

function createCanonicalValidationProofTables(db: DatabaseSync) {
  for (const [table, idColumn] of fixtureCanonicalValidationProofTables) {
    const evaluationColumns =
      table === 'release_validation_evaluation_receipts'
        ? `
          epoch_sequence INTEGER NOT NULL DEFAULT 1,
          evaluated_at TEXT NOT NULL DEFAULT '1970-01-01T00:00:00.000Z',
          status TEXT NOT NULL DEFAULT 'insufficient',
        `
        : '';
    db.exec(`
      CREATE TABLE ${table} (
        ${idColumn} TEXT PRIMARY KEY,
        ${evaluationColumns}
        content_hash TEXT NOT NULL UNIQUE,
        record_json TEXT NOT NULL
      );
      CREATE TRIGGER ${table}_no_update
      BEFORE UPDATE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
      CREATE TRIGGER ${table}_no_delete
      BEFORE DELETE ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${table} is append-only');
      END;
    `);
  }
}

function historyRow(runId: string, tag: string, score: number) {
  return {
    run_id: runId,
    recorded_at: '2026-07-03T00:00:00.000Z',
    release_tag: tag,
    scored_at: '2026-07-03T00:00:00.000Z',
    score_model_version: 'test-model',
    prompt_version: 1,
    final_score: score,
    status: 'eligible',
    band: 'good',
    recommended: tag === 'v1' ? 1 : 0,
    input_json: JSON.stringify({ tag, score }),
    components_json: '{}',
    issue_evidence_json: '{}',
    gate_evidence_json: '{}',
    source_identity_json: JSON.stringify({ schemaVersion: 2, digest: 'a'.repeat(64) }),
    authority_run_id: null,
  };
}

function seedHistory(db: DatabaseSync, rows: Array<Record<string, unknown>>) {
  const insert = db.prepare(`
    INSERT INTO release_score_audit_history (${historyColumns.join(', ')})
    VALUES (${historyColumns.map((column) => `:${column}`).join(', ')})
  `);
  const runOrder: string[] = [];
  for (const row of rows) {
    insert.run(row);
    const runId = String(row.run_id);
    if (!runOrder.includes(runId)) runOrder.push(runId);
  }

  let previousContentHash = (db.prepare(`
    SELECT content_hash
    FROM release_score_audit_history_runs
    ORDER BY id DESC
    LIMIT 1
  `).get() as { content_hash?: string } | undefined)?.content_hash ?? null;
  const insertSeal = db.prepare(`
    INSERT INTO release_score_audit_history_runs (
      run_id, recorded_at, row_count, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?)
  `);
  for (const runId of runOrder) {
    const runRows = db.prepare(`
      SELECT *
      FROM release_score_audit_history
      WHERE run_id=?
      ORDER BY release_tag
    `).all(runId) as Array<Record<string, unknown>>;
    const recordedAt = String(runRows[0].recorded_at);
    const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(runRows);
    const contentHash = releaseScoreAuditHistoryRunContentHash({
      runId,
      recordedAt,
      rowCount: runRows.length,
      rowsContentHash,
      previousContentHash,
    });
    insertSeal.run(
      runId,
      recordedAt,
      runRows.length,
      rowsContentHash,
      previousContentHash,
      contentHash,
    );
    previousContentHash = contentHash;
  }
  const tip = db.prepare(`
    SELECT run_id, content_hash
    FROM release_score_audit_history_runs
    ORDER BY id DESC
    LIMIT 1
  `).get() as { run_id?: string; content_hash?: string } | undefined;
  if (tip?.run_id && tip.content_hash) {
    db.prepare(`
      INSERT INTO meta (key, value)
      VALUES ('score_persistence_last_run', ?)
      ON CONFLICT(key) DO UPDATE SET value=excluded.value
    `).run(JSON.stringify({
      schemaVersion: 2,
      historyRunId: tip.run_id,
      historyRunContentHash: tip.content_hash,
    }));
  }
}

function replaceHistoryUniqueWithPartial(db: DatabaseSync) {
  db.exec(`
    DROP TRIGGER release_score_audit_history_no_update;
    DROP TRIGGER release_score_audit_history_no_delete;
    ALTER TABLE release_score_audit_history RENAME TO release_score_audit_history_old;
    CREATE TABLE release_score_audit_history (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_id TEXT NOT NULL,
      recorded_at TEXT NOT NULL,
      release_tag TEXT NOT NULL,
      scored_at TEXT NOT NULL,
      score_model_version TEXT NOT NULL,
      prompt_version INTEGER NOT NULL,
      final_score REAL,
      status TEXT NOT NULL,
      band TEXT NOT NULL,
      recommended INTEGER NOT NULL DEFAULT 0,
      input_json TEXT NOT NULL,
      components_json TEXT,
      issue_evidence_json TEXT NOT NULL,
      gate_evidence_json TEXT NOT NULL,
      source_identity_json TEXT NOT NULL,
      authority_run_id TEXT
    );
    INSERT INTO release_score_audit_history
    SELECT * FROM release_score_audit_history_old;
    DROP TABLE release_score_audit_history_old;
    CREATE UNIQUE INDEX release_score_audit_history_run_release_partial
      ON release_score_audit_history(run_id, release_tag)
      WHERE 0;
    CREATE TRIGGER release_score_audit_history_no_update
    BEFORE UPDATE ON release_score_audit_history BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
    CREATE TRIGGER release_score_audit_history_no_delete
    BEFORE DELETE ON release_score_audit_history BEGIN
      SELECT RAISE(ABORT, 'release_score_audit_history is append-only');
    END;
  `);
}

function readHistory(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare(`
      SELECT ${historyColumns.join(', ')}
      FROM release_score_audit_history
      ORDER BY run_id, release_tag
    `).all() as Array<Record<string, any>>;
  } finally {
    db.close();
  }
}

function readHistoryRunSeals(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare(`
      SELECT *
      FROM release_score_audit_history_runs
      ORDER BY id
    `).all() as Array<Record<string, any>>;
  } finally {
    db.close();
  }
}

function readScorePersistenceMeta(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    const value = db.prepare(`
      SELECT value
      FROM meta
      WHERE key='score_persistence_last_run'
    `).get()?.value;
    return JSON.parse(String(value ?? 'null')) as Record<string, any>;
  } finally {
    db.close();
  }
}

function readRows(path: string, sql: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return db.prepare(sql).all().map((row) => ({ ...row })) as Array<Record<string, any>>;
  } finally {
    db.close();
  }
}

function seedScoreEvidenceSnapshots(
  db: DatabaseSync,
  {
    issueNumber,
    issueState,
    releaseTag,
  }: {
    issueNumber: number;
    issueState: string;
    releaseTag: string;
  },
) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `ISSUE-node-${issueNumber}`;
  const normalizedState = issueState === 'closed' ? 'closed' : 'open';
  const events = normalizeIssueStateEvents(
    normalizedState === 'closed'
      ? [{
          eventId: `EVENT-close-${issueNumber}`,
          eventNodeType: 'ClosedEvent',
          type: 'closed',
          occurredAt: '2026-07-03T01:00:00Z',
          connectionOrdinal: 0,
          actorNodeId: 'ACTOR-maintainer',
          actorLogin: 'maintainer',
          actorType: 'User',
          stateReason: 'COMPLETED',
          closerNodeId: `COMMIT-node-${issueNumber}`,
          closerType: 'Commit',
          closerNumber: null,
          closerOid: 'a'.repeat(40),
        }]
      : [],
  );
  const sweep = {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueState: normalizedState,
    issueUpdatedAt: '2026-07-03T01:00:00Z',
    totalCount: events.length,
    events,
  };
  const firstSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  const stabilization = issueStateEventStabilizationIdentity(
    firstSweep,
    secondSweep,
    2,
  );
  db.prepare(`
    INSERT INTO issue_state_event_snapshots (
      issue_number, repository_node_id, issue_node_id, issue_node_type,
      schema_version,
      issue_state, issue_updated_at, total_count, fetched_count,
      events_digest, authority_digest, events_json,
      sweep_count, stabilized, stabilization_json,
      stabilization_identity_digest, revision, fetched_at, verified_at
    )
    VALUES (
      ?, ?, ?, 'Issue', ?, ?, '2026-07-03T01:00:00Z',
      ?, ?, ?, ?, ?, 2, 1, ?, ?, 1,
      '2026-07-03T01:01:00Z', '2026-07-03T01:01:00Z'
    )
  `).run(
    issueNumber,
    repositoryNodeId,
    issueNodeId,
    ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
    normalizedState,
    events.length,
    events.length,
    issueStateEventsDigest(events, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
    }),
    secondSweep.sweepDigest,
    JSON.stringify(events),
    JSON.stringify(stabilization),
    stabilization.identityDigest,
  );
  db.prepare(`
    INSERT INTO release_closure_dependency_snapshots (
      release_tag, schema_version, analyzer_version, issue_numbers_json,
      dependency_digest, dependency_row_count, captured_at
    )
    VALUES (?, 3, ?, ?, ?, 1, '2026-07-03T01:02:00Z')
  `).run(
    releaseTag,
    CLOSURE_PROOF_ANALYZER_VERSION,
    JSON.stringify([issueNumber]),
    String(issueNumber + 1).padStart(64, '0'),
  );
}

function readScoreEvidenceKeys(path: string) {
  return {
    issueNumbers: readRows(
      path,
      `SELECT issue_number FROM issue_state_event_snapshots ORDER BY issue_number`,
    ).map((row) => row.issue_number),
    releaseTags: readRows(
      path,
      `SELECT release_tag FROM release_closure_dependency_snapshots ORDER BY release_tag`,
    ).map((row) => row.release_tag),
  };
}

function readScoreEvidenceRows(path: string) {
  return {
    issueStateEventSnapshots: readRows(
      path,
      `SELECT * FROM issue_state_event_snapshots ORDER BY issue_number`,
    ),
    releaseClosureDependencySnapshots: readRows(
      path,
      `SELECT * FROM release_closure_dependency_snapshots ORDER BY release_tag`,
    ),
  };
}

function dropScoreEvidenceSnapshotTables(db: DatabaseSync) {
  db.exec(`
    DROP INDEX IF EXISTS idx_issue_state_event_snapshots_verified;
    DROP TABLE IF EXISTS issue_state_event_snapshots;
    DROP TABLE IF EXISTS release_closure_dependency_snapshots;
  `);
}

function seedRefreshLease(
  db: DatabaseSync,
  name: string,
  holderId: string,
  acquiredAt: string,
  expiresAt: string,
) {
  db.prepare(`
    INSERT INTO refresh_leases (name, holder_id, acquired_at, expires_at)
    VALUES (?, ?, ?, ?)
  `).run(name, holderId, acquiredAt, expiresAt);
}

function seedOperationReceiptRun(
  db: DatabaseSync,
  {
    runId,
    trigger = 'test',
    startedAt = '2026-07-03T10:00:00.000Z',
    status = 'success',
    codeRevision = `revision-${runId}`,
    repository = fixtureRepository,
    advisoryCatalog,
    releaseCatalog,
    releaseArtifacts,
  }: {
    runId: string;
    trigger?: string;
    startedAt?: string;
    status?: 'success' | 'failure' | 'abandoned';
    codeRevision?: string;
    repository?: string;
    advisoryCatalog?: Record<string, unknown>;
    releaseCatalog?: Record<string, unknown>;
    releaseArtifacts?: ReturnType<typeof buildReleaseArtifactPublication>;
  },
) {
  const startedAtMs = Date.parse(startedAt);
  const [owner, repo] = repository.split('/');
  const effectiveConfigJson = canonicalOperationJson({
    github: { owner, repo },
    runId,
    schemaVersion: 1,
  });
  const attempt = {
    run_id: runId,
    operation: 'refresh',
    trigger,
    started_at: startedAt,
    lease_name: 'github-refresh',
    lease_holder_id: `holder-${runId}`,
    lease_expires_at: new Date(startedAtMs + 5 * 60_000).toISOString(),
    code_revision: codeRevision,
    effective_config_json: effectiveConfigJson,
    effective_config_hash: operationAttemptConfigHash(effectiveConfigJson),
    content_hash: '',
  };
  attempt.content_hash = operationAttemptContentHash({
    runId: attempt.run_id,
    operation: attempt.operation,
    trigger: attempt.trigger,
    startedAt: attempt.started_at,
    leaseName: attempt.lease_name,
    leaseHolderId: attempt.lease_holder_id,
    leaseExpiresAt: attempt.lease_expires_at,
    codeRevision: attempt.code_revision,
    effectiveConfigJson: attempt.effective_config_json,
  });
  db.prepare(`
    INSERT INTO refresh_operation_attempts (
      run_id, operation, trigger, started_at, lease_name, lease_holder_id,
      lease_expires_at, code_revision, effective_config_json,
      effective_config_hash, content_hash
    )
    VALUES (
      :run_id, :operation, :trigger, :started_at, :lease_name, :lease_holder_id,
      :lease_expires_at, :code_revision, :effective_config_json,
      :effective_config_hash, :content_hash
    )
  `).run(attempt);

  const historyRunId = `history-${runId}`;
  const historyRunContentHash = createHash('sha256')
    .update(`history-content:${runId}`)
    .digest('hex');
  const authorityRunId = `score-authority:${runId}`;
  const authorityRunContentHash = createHash('sha256')
    .update(`authority-content:${runId}`)
    .digest('hex');
  const historyV2SealContentHash = createHash('sha256')
    .update(`history-v2-content:${runId}`)
    .digest('hex');
  const commitNotBefore = new Date(startedAtMs + 1_500).toISOString();
  const commitNotAfter = new Date(startedAtMs + 2_000).toISOString();
  const publicationStages = [
    {
      stage: 'score.persist',
      status: 'started',
      counts: null,
      details: null,
    },
    {
      stage: 'score.persist',
      status: 'completed',
      counts: { scoredReleases: 1 },
      details: {
        historyRunId,
        historyRunContentHash,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        commitNotBefore,
        commitNotAfter,
      },
    },
    {
      stage: 'forecast.capture',
      status: 'started',
      counts: null,
      details: null,
    },
    {
      stage: 'forecast.capture',
      status: 'completed',
      counts: { validationForecasts: 0 },
      details: { eligibilityOutcome: 'not_eligible' },
    },
  ];
  let previousStageHash: string | null = null;
  for (const [index, publicationStage] of publicationStages.entries()) {
    const sequence = index + 1;
    const occurredAt = new Date(startedAtMs + sequence * 1_000).toISOString();
    const eventId = operationStageEventId({
      runId,
      sequence,
      stage: publicationStage.stage,
      status: publicationStage.status as 'started' | 'completed',
    });
    const event = {
      event_id: eventId,
      run_id: runId,
      sequence,
      stage: publicationStage.stage,
      status: publicationStage.status,
      occurred_at: occurredAt,
      duration_ms: publicationStage.status === 'completed' ? 1_000 : null,
      counts_json:
        publicationStage.counts == null
          ? null
          : JSON.stringify(publicationStage.counts),
      details_json:
        publicationStage.details == null
          ? null
          : JSON.stringify(publicationStage.details),
      previous_content_hash: previousStageHash,
      content_hash: '',
    };
    event.content_hash = operationStageEventContentHash({
      eventId: event.event_id,
      runId: event.run_id,
      sequence: event.sequence,
      stage: event.stage,
      status: event.status as 'started' | 'completed',
      occurredAt: event.occurred_at,
      durationMs: event.duration_ms,
      countsJson: event.counts_json,
      detailsJson: event.details_json,
      previousContentHash: event.previous_content_hash,
    });
    db.prepare(`
      INSERT INTO refresh_operation_stage_events (
        event_id, run_id, sequence, stage, status, occurred_at, duration_ms,
        counts_json, details_json, previous_content_hash, content_hash
      )
      VALUES (
        :event_id, :run_id, :sequence, :stage, :status, :occurred_at, :duration_ms,
        :counts_json, :details_json, :previous_content_hash, :content_hash
      )
    `).run(event);
    previousStageHash = event.content_hash;
  }

  const previousReceiptHash = String(db.prepare(`
    SELECT content_hash
    FROM refresh_capture_receipts
    ORDER BY id DESC
    LIMIT 1
  `).get()?.content_hash ?? '') || null;
  const receipt = {
    receipt_id: operationCaptureReceiptId(runId),
    run_id: runId,
    status,
    finished_at: new Date(startedAtMs + 4_000).toISOString(),
    duration_ms: 4_000,
    stage_event_count: publicationStages.length,
    stage_chain_hash: previousStageHash,
    payload_json: canonicalOperationJson({
      schemaVersion: releaseArtifacts ? 2 : 1,
      runId,
      status,
      operation: attempt.operation,
      trigger: attempt.trigger,
      codeRevision,
      scoreHistory: {
        runId: historyRunId,
        contentHash: historyRunContentHash,
      },
      scoreAuthority: {
        runId: authorityRunId,
        contentHash: authorityRunContentHash,
        historyV2SealContentHash,
      },
      scoreCommit: {
        historyRunId,
        historyRunContentHash,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        commitNotBefore,
        commitNotAfter,
      },
      releaseTags: ['v-test'],
      forecast: {
        eligibilityOutcome: 'not_eligible',
        decisionIds: [],
        captures: [],
      },
      ...(advisoryCatalog ? { advisoryCatalog } : {}),
      ...(releaseCatalog ? { releaseCatalog } : {}),
      ...(releaseArtifacts ? { releaseArtifacts } : {}),
    }),
    previous_content_hash: previousReceiptHash,
    content_hash: '',
  };
  receipt.content_hash = operationCaptureReceiptContentHash({
    receiptId: receipt.receipt_id,
    runId: receipt.run_id,
    status: receipt.status,
    finishedAt: receipt.finished_at,
    durationMs: receipt.duration_ms,
    stageEventCount: receipt.stage_event_count,
    stageChainHash: receipt.stage_chain_hash,
    payloadJson: receipt.payload_json,
    previousContentHash: receipt.previous_content_hash,
  });
  db.prepare(`
    INSERT INTO refresh_capture_receipts (
      receipt_id, run_id, status, finished_at, duration_ms, stage_event_count,
      stage_chain_hash, payload_json, previous_content_hash, content_hash
    )
    VALUES (
      :receipt_id, :run_id, :status, :finished_at, :duration_ms, :stage_event_count,
      :stage_chain_hash, :payload_json, :previous_content_hash, :content_hash
    )
  `).run(receipt);
  return { attempt, receipt };
}

function seedDefaultReleaseCatalogAuthority(db: DatabaseSync) {
  const release = {
    catalog_rank: 0,
    node_id: 'RE_default-catalog-release',
    catalog_tag_commit_oid: '1'.repeat(40),
    tag: 'v-test',
    name: 'Release v-test',
    published_at: '2026-07-03T08:00:00.000Z',
    created_at: '2026-07-03T08:00:00.000Z',
    updated_at: '2026-07-03T08:00:00.000Z',
    html_url: 'https://example.test/releases/v-test',
    prerelease: 0,
    body: '',
  };
  const activeCatalog = projectReleaseCatalogActiveRows([release]);
  db.prepare(`
    INSERT INTO releases (
      tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
      updated_at, html_url, prerelease, catalog_rank, catalog_digest,
      catalog_active, body
    )
    VALUES (
      :tag, :node_id, :catalog_tag_commit_oid, :name, :published_at, :created_at,
      :updated_at, :html_url, :prerelease, :catalog_rank, :catalog_digest, 1, :body
    )
  `).run({
    ...release,
    catalog_digest: activeCatalog.digest,
  });
  appendReleaseCatalogAuthority(db, {
    runId: 'catalog-refresh-default',
    startedAt: '2026-07-03T09:00:00.000Z',
  });
}

function appendReleaseCatalogAuthority(
  db: DatabaseSync,
  {
    runId,
    startedAt = '2026-07-03T09:30:00.000Z',
    repository = fixtureRepository,
    status = 'success',
  }: {
    runId: string;
    startedAt?: string;
    repository?: string;
    status?: 'success' | 'failure' | 'abandoned';
  },
) {
  return seedOperationReceiptRunWithCatalogAuthority(db, {
    runId,
    startedAt,
    repository,
    status,
  }).catalogReceipt;
}

function seedOperationReceiptRunWithCatalogAuthority(
  db: DatabaseSync,
  options: Omit<
    Parameters<typeof seedOperationReceiptRun>[1],
    'releaseCatalog'
  >,
) {
  const runId = options.runId;
  const startedAt =
    options.startedAt ?? '2026-07-03T10:00:00.000Z';
  const repository = options.repository ?? fixtureRepository;
  const activeCatalog = activeReleaseCatalogProjectionForTest(db);
  const remoteCatalog = {
    repositoryNodeId: `REPO_${runId}`,
    repositoryNameWithOwner: repository,
    digest: createHash('sha256')
      .update(`release-catalog:${repository}:${runId}`)
      .digest('hex'),
    totalCount: activeCatalog.releaseCount,
    nodeCount: activeCatalog.releaseCount,
    publishedCount: activeCatalog.releaseCount,
    draftCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    sweepPageCounts: [1, 1],
    exhausted: true as const,
    stabilized: true as const,
    sourceOrder: 'CREATED_AT_DESC' as const,
  };
  const operation = seedOperationReceiptRun(db, {
    ...options,
    startedAt,
    repository,
    releaseCatalog: {
      digest: remoteCatalog.digest,
      nodeCount: remoteCatalog.nodeCount,
      totalCount: remoteCatalog.totalCount,
      attestation: {
        localActiveCatalog: {
          digest: activeCatalog.digest,
          releaseCount: activeCatalog.releaseCount,
        },
        latestStable: activeCatalog.latestStable,
      },
    },
  });
  const observedAt = new Date(Date.parse(startedAt) + 2_000).toISOString();
  const payload = {
    schemaVersion: 1 as const,
    source: 'github_graphql' as const,
    repository,
    observedAt,
    operationRunId: operation.attempt.run_id,
    operation: operation.attempt.operation,
    operationAttemptContentHash: operation.attempt.content_hash,
    remoteCatalog,
    activeCatalog,
  };
  return {
    ...operation,
    catalogReceipt: insertReleaseCatalogReceipt(db, payload),
  };
}

function appendTestFixtureReleaseCatalogReceipt(db: DatabaseSync) {
  const payload = {
    schemaVersion: 1 as const,
    source: 'test_fixture' as const,
    repository: fixtureRepository,
    observedAt: '2026-07-03T09:45:00.000Z',
    operationRunId: null,
    operation: null,
    operationAttemptContentHash: null,
    remoteCatalog: null,
    activeCatalog: activeReleaseCatalogProjectionForTest(db),
  };
  return insertReleaseCatalogReceipt(db, payload);
}

function insertReleaseCatalogReceipt(
  db: DatabaseSync,
  payload: Parameters<typeof releaseCatalogCaptureReceiptContentHash>[0]['payload'],
) {
  const previousContentHash = String(db.prepare(`
    SELECT content_hash
    FROM release_catalog_capture_receipts
    ORDER BY id DESC
    LIMIT 1
  `).get()?.content_hash ?? '') || null;
  const contentHash = releaseCatalogCaptureReceiptContentHash({
    payload,
    previousContentHash,
  });
  const receiptId = releaseCatalogCaptureReceiptId(contentHash);
  db.prepare(`
    INSERT INTO release_catalog_capture_receipts (
      receipt_id, operation_run_id, source_kind, repository, observed_at,
      active_catalog_digest, active_release_count, payload_json,
      previous_content_hash, content_hash
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    receiptId,
    payload.operationRunId,
    payload.source,
    payload.repository,
    payload.observedAt,
    payload.activeCatalog.digest,
    payload.activeCatalog.releaseCount,
    canonicalOperationJson(payload),
    previousContentHash,
    contentHash,
  );
  return db.prepare(`
    SELECT ${releaseCatalogReceiptColumns.join(', ')}
    FROM release_catalog_capture_receipts
    WHERE receipt_id=?
  `).get(receiptId) as Record<string, any>;
}

function activeReleaseCatalogProjectionForTest(db: DatabaseSync) {
  const projected = projectReleaseCatalogActiveRows(
    activeReleaseCatalogRowsForTest(db),
  );
  return {
    digest: projected.digest,
    releaseCount: projected.releaseCount,
    stableCount: projected.stableCount,
    prereleaseCount: projected.prereleaseCount,
    tags: projected.tags,
    latestStable: projected.latestStable,
  };
}

function testGithubReleaseCatalogProof(
  dbPath: string,
  observedAt: string,
) {
  const db = new DatabaseSync(dbPath, { readOnly: true });
  try {
    const rows = activeReleaseCatalogRowsForTest(db);
    const projected = projectReleaseCatalogActiveRows(rows);
    return {
      schemaVersion: 1,
      source: 'independent_github_graphql',
      repository: fixtureRepository,
      observedAt,
      configurationSource: {
        kind: 'test',
        path: null,
      },
      remoteCatalog: {
        digest: createHash('sha256')
          .update(canonicalOperationJson(rows))
          .digest('hex'),
        totalCount: rows.length,
        nodeCount: rows.length,
        publishedCount: rows.length,
        draftCount: 0,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        sweepPageCounts: [1, 1],
        exhausted: true,
        stabilized: true,
        sourceOrder: 'CREATED_AT_DESC',
      },
      activeCatalog: {
        digest: projected.digest,
        releaseCount: projected.releaseCount,
        stableCount: projected.stableCount,
        prereleaseCount: projected.prereleaseCount,
        tags: projected.tags,
        latestStable: projected.latestStable,
      },
      exactIdentityMatch: true,
    };
  } finally {
    db.close();
  }
}

function activeReleaseCatalogRowsForTest(db: DatabaseSync) {
  return db.prepare(`
    SELECT
      catalog_rank, node_id, catalog_tag_commit_oid, tag, name, published_at,
      created_at, updated_at, html_url, prerelease, body
    FROM releases
    WHERE catalog_active=1
    ORDER BY catalog_rank IS NULL, catalog_rank, published_at DESC, tag
  `).all() as Array<{
    catalog_rank: number | null;
    node_id: string | null;
    catalog_tag_commit_oid: string | null;
    tag: string;
    name: string | null;
    published_at: string | null;
    created_at: string | null;
    updated_at: string | null;
    html_url: string;
    prerelease: number;
    body: string | null;
  }>;
}

function rewriteLatestReleaseCatalogReceipt(
  db: DatabaseSync,
  mutate: (payload: Record<string, any>) => Record<string, any>,
) {
  const row = db.prepare(`
    SELECT ${releaseCatalogReceiptColumns.join(', ')}
    FROM release_catalog_capture_receipts
    ORDER BY id DESC
    LIMIT 1
  `).get() as Record<string, any>;
  const payload = mutate(JSON.parse(String(row.payload_json)));
  const payloadJson = canonicalOperationJson(payload);
  const contentHash = releaseCatalogCaptureReceiptContentHash({
    payload: payload as Parameters<
      typeof releaseCatalogCaptureReceiptContentHash
    >[0]['payload'],
    previousContentHash: row.previous_content_hash ?? null,
  });
  const receiptId = releaseCatalogCaptureReceiptId(contentHash);
  withReleaseCatalogReceiptGuardDisabled(db, 'UPDATE', () => {
    db.prepare(`
      UPDATE release_catalog_capture_receipts
      SET
        receipt_id=?,
        operation_run_id=?,
        source_kind=?,
        repository=?,
        observed_at=?,
        active_catalog_digest=?,
        active_release_count=?,
        payload_json=?,
        content_hash=?
      WHERE id=?
    `).run(
      receiptId,
      payload.operationRunId,
      payload.source,
      payload.repository,
      payload.observedAt,
      payload.activeCatalog.digest,
      payload.activeCatalog.releaseCount,
      payloadJson,
      contentHash,
      row.id,
    );
  });
}

function tamperLatestReleaseCatalogReceiptPayload(db: DatabaseSync) {
  withReleaseCatalogReceiptGuardDisabled(db, 'UPDATE', () => {
    db.prepare(`
      UPDATE release_catalog_capture_receipts
      SET payload_json=payload_json || ' '
      WHERE id=(
        SELECT id
        FROM release_catalog_capture_receipts
        ORDER BY id DESC
        LIMIT 1
      )
    `).run();
  });
}

function deleteReleaseCatalogReceiptChain(db: DatabaseSync) {
  withReleaseCatalogReceiptGuardDisabled(db, 'DELETE', () => {
    db.prepare(`DELETE FROM release_catalog_capture_receipts`).run();
  });
}

function deleteFirstReleaseCatalogReceipt(db: DatabaseSync) {
  withReleaseCatalogReceiptGuardDisabled(db, 'DELETE', () => {
    db.prepare(`
      DELETE FROM release_catalog_capture_receipts
      WHERE id=(
        SELECT id
        FROM release_catalog_capture_receipts
        ORDER BY id
        LIMIT 1
      )
    `).run();
  });
}

function reorderFirstTwoReleaseCatalogReceipts(db: DatabaseSync) {
  const rows = db.prepare(`
    SELECT id
    FROM release_catalog_capture_receipts
    ORDER BY id
    LIMIT 2
  `).all() as Array<{ id: number }>;
  assert.equal(rows.length, 2);
  const temporaryId = -Math.max(rows[0].id, rows[1].id);
  withReleaseCatalogReceiptGuardDisabled(db, 'UPDATE', () => {
    db.prepare(`
      UPDATE release_catalog_capture_receipts SET id=? WHERE id=?
    `).run(temporaryId, rows[0].id);
    db.prepare(`
      UPDATE release_catalog_capture_receipts SET id=? WHERE id=?
    `).run(rows[0].id, rows[1].id);
    db.prepare(`
      UPDATE release_catalog_capture_receipts SET id=? WHERE id=?
    `).run(rows[1].id, temporaryId);
  });
}

function withReleaseCatalogReceiptGuardDisabled(
  db: DatabaseSync,
  event: 'UPDATE' | 'DELETE',
  mutate: () => void,
) {
  const triggerName =
    `release_catalog_capture_receipts_no_${event.toLowerCase()}`;
  const triggerSql = String(db.prepare(`
    SELECT sql
    FROM sqlite_schema
    WHERE type='trigger' AND name=?
  `).get(triggerName)?.sql ?? '');
  assert.ok(triggerSql, `missing ${triggerName}`);
  db.exec(`DROP TRIGGER ${triggerName}`);
  try {
    mutate();
  } finally {
    db.exec(triggerSql);
  }
}

function mutateActiveReleaseCatalog(db: DatabaseSync) {
  const rows = activeReleaseCatalogRowsForTest(db);
  const mutated = rows.map((row, index) =>
    index === 0 ? { ...row, name: `${row.name ?? row.tag} changed` } : row);
  const projection = projectReleaseCatalogActiveRows(mutated);
  db.prepare(`
    UPDATE releases
    SET name=?, catalog_digest=?
    WHERE tag=?
  `).run(mutated[0].name, projection.digest, mutated[0].tag);
  db.prepare(`
    UPDATE releases
    SET catalog_digest=?
    WHERE catalog_active=1
  `).run(projection.digest);
}

function mutateActiveReleaseCatalogRank(db: DatabaseSync) {
  db.prepare(`
    UPDATE releases
    SET catalog_rank=NULL
    WHERE catalog_active=1 AND catalog_rank=0
  `).run();
}

function promotionCatalogReleaseForTest({
  tag,
  nodeId,
  tagCommitOid,
  publishedAt,
  createdAt = publishedAt,
  prerelease,
}: {
  tag: string;
  nodeId: string;
  tagCommitOid: string;
  publishedAt: string;
  createdAt?: string;
  prerelease: 0 | 1;
}) {
  return {
    catalog_rank: 0,
    node_id: nodeId,
    catalog_tag_commit_oid: tagCommitOid,
    tag,
    name: `OpenClaw ${tag}`,
    published_at: publishedAt,
    created_at: createdAt,
    updated_at: publishedAt,
    html_url: `https://github.com/openclaw/openclaw/releases/tag/${tag}`,
    prerelease,
    body: '',
  };
}

function destinationPromotionCatalogForTest() {
  return [
    promotionCatalogReleaseForTest({
      tag: 'v2026.7.3',
      nodeId: 'RE_v2026_7_3',
      tagCommitOid: '3'.repeat(40),
      publishedAt: '2026-07-03T12:00:00.000Z',
      prerelease: 0,
    }),
    promotionCatalogReleaseForTest({
      tag: 'v2026.7.2-beta.1',
      nodeId: 'RE_v2026_7_2_beta_1',
      tagCommitOid: 'b'.repeat(40),
      publishedAt: '2026-07-02T12:00:00.000Z',
      prerelease: 1,
    }),
    promotionCatalogReleaseForTest({
      tag: 'v2026.7.2',
      nodeId: 'RE_v2026_7_2',
      tagCommitOid: '2'.repeat(40),
      publishedAt: '2026-07-02T00:00:00.000Z',
      prerelease: 0,
    }),
  ].map((release, catalogRank) => ({
    ...release,
    catalog_rank: catalogRank,
  }));
}

function omittedPhantomPromotionCatalogsForTest() {
  const phantom = promotionCatalogReleaseForTest({
    tag: 'v-phantom-omitted',
    nodeId: 'RE_phantom_omitted',
    tagCommitOid: 'f'.repeat(40),
    publishedAt: '2026-07-01T00:00:00.000Z',
    prerelease: 0,
  });
  const previousCatalog = [
    ...destinationPromotionCatalogForTest(),
    phantom,
  ].map((release, catalogRank) => ({
    ...release,
    catalog_rank: catalogRank,
  }));
  return {
    phantom,
    previousCatalog,
    currentCatalog: previousCatalog.filter(
      (release) => release.tag !== phantom.tag,
    ),
  };
}

function githubReleaseCatalogForTest(
  rows: ReturnType<typeof activeReleaseCatalogRowsForTest>,
  {
    drafts = [],
  }: {
    drafts?: Array<Record<string, unknown>>;
  } = {},
) {
  const releases = [
    ...rows.map((row) => ({
      node_id: row.node_id,
      tag_name: row.tag,
      tag_commit_oid: row.catalog_tag_commit_oid,
      name: row.name,
      published_at: row.published_at,
      created_at: row.created_at,
      updated_at: row.updated_at,
      html_url: row.html_url,
      prerelease: row.prerelease === 1,
      draft: false,
      body: row.body,
    })),
    ...drafts,
  ];
  return {
    releases,
    metadata: {
      exhausted: true,
      stabilized: true,
      totalCount: releases.length,
      nodeCount: releases.length,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      sweepPageCounts: [1, 1],
      digest: createHash('sha256')
        .update(canonicalOperationJson(releases))
        .digest('hex'),
      sourceOrder: 'CREATED_AT_DESC' as const,
    },
  };
}

function githubRuntimeEnvForTest(
  dir: string,
  repository = fixtureRepository,
): string {
  const parts = repository.split('/');
  assert.equal(parts.length, 2);
  const [owner, repo] = parts;
  const path = join(dir, 'github-runtime.env');
  writeFileSync(
    path,
    [
      `GITHUB_OWNER=${owner}`,
      `GITHUB_REPO=${repo}`,
      'GITHUB_TOKEN=github-test-token',
      '',
    ].join('\n'),
    { mode: 0o600 },
  );
  return path;
}

function independentGithubVerifierForTest(
  fixture: ReturnType<typeof createFixture>,
  rows: ReturnType<typeof activeReleaseCatalogRowsForTest>,
  {
    repository = fixtureRepository,
  }: {
    repository?: string;
  } = {},
) {
  const runtimeEnvPath = githubRuntimeEnvForTest(fixture.dir, repository);
  const catalog = githubReleaseCatalogForTest(rows);
  return (input: {
    dbPath: string;
    label: string;
    observedAt: string;
  }) => verifyPromotionGithubReleaseCatalog({
    ...input,
    runtimeEnvPath,
    fetchCatalog: async () => catalog,
  });
}

function releaseCatalogIdentityTuplesForTest(
  rows: ReturnType<typeof activeReleaseCatalogRowsForTest>,
) {
  return rows.map((row) => [
    row.tag,
    row.node_id,
    row.catalog_tag_commit_oid,
    row.prerelease,
  ]);
}

function seedSharedPromotionCatalogForTest(
  fixture: ReturnType<typeof createFixture>,
  rows: ReturnType<typeof activeReleaseCatalogRowsForTest>,
) {
  for (const db of [fixture.source, fixture.destination]) {
    replaceActiveReleaseCatalogForTest(db, rows);
    appendReleaseCatalogAuthority(db, {
      runId: 'catalog-refresh-trusted-history',
      startedAt: '2026-07-03T13:00:00.000Z',
    });
  }
}

function assertPromotionCatalogAuthoritiesAreSelfConsistent(
  fixture: ReturnType<typeof createFixture>,
  label = 'catalog evolution',
) {
  const sourceAuthority = verifyReleaseCatalogReceiptDb(fixture.sourcePath);
  const destinationAuthority =
    verifyReleaseCatalogReceiptDb(fixture.destinationPath);
  assert.deepEqual(sourceAuthority.problems, [], label);
  assert.deepEqual(destinationAuthority.problems, [], label);
  assert.notEqual(
    sourceAuthority.latestPayload?.activeCatalog.digest,
    destinationAuthority.latestPayload?.activeCatalog.digest,
    label,
  );
  const sourceReceipts = readReleaseCatalogReceiptRows(fixture.sourcePath);
  const destinationReceipts =
    readReleaseCatalogReceiptRows(fixture.destinationPath);
  assert.equal(
    sourceReceipts.length,
    destinationReceipts.length + 1,
    label,
  );
  assert.deepEqual(
    sourceReceipts.slice(0, destinationReceipts.length),
    destinationReceipts,
    label,
  );
}

function replaceActiveReleaseCatalogForTest(
  db: DatabaseSync,
  rows: ReturnType<typeof activeReleaseCatalogRowsForTest>,
  {
    preserveInactive = false,
  }: {
    preserveInactive?: boolean;
  } = {},
) {
  const normalizedRows = rows.map((row, catalogRank) => ({
    ...row,
    catalog_rank: catalogRank,
  }));
  const projection = projectReleaseCatalogActiveRows(normalizedRows);
  const upsert = db.prepare(`
    INSERT INTO releases (
      tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
      updated_at, html_url, prerelease, catalog_rank, catalog_digest,
      catalog_active, body
    )
    VALUES (
      :tag, :node_id, :catalog_tag_commit_oid, :name, :published_at, :created_at,
      :updated_at, :html_url, :prerelease, :catalog_rank, :catalog_digest,
      1, :body
    )
    ON CONFLICT(tag) DO UPDATE SET
      node_id=excluded.node_id,
      catalog_tag_commit_oid=excluded.catalog_tag_commit_oid,
      name=excluded.name,
      published_at=excluded.published_at,
      created_at=excluded.created_at,
      updated_at=excluded.updated_at,
      html_url=excluded.html_url,
      prerelease=excluded.prerelease,
      catalog_rank=excluded.catalog_rank,
      catalog_digest=excluded.catalog_digest,
      catalog_active=1,
      body=excluded.body
  `);
  db.exec('BEGIN IMMEDIATE');
  try {
    db.prepare(`
      UPDATE releases
      SET catalog_active=0
      WHERE catalog_active=1
    `).run();
    for (const row of normalizedRows) {
      upsert.run({
        ...row,
        catalog_digest: projection.digest,
      });
    }
    if (!preserveInactive) {
      db.prepare(`
        DELETE FROM releases
        WHERE catalog_active IS NOT 1
      `).run();
    }
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

function insertInactiveReleaseCatalogForTest(
  db: DatabaseSync,
  row: ReturnType<typeof promotionCatalogReleaseForTest>,
) {
  db.prepare(`
    INSERT INTO releases (
      tag, node_id, catalog_tag_commit_oid, name, published_at, created_at,
      updated_at, html_url, prerelease, catalog_rank, catalog_digest,
      catalog_active, body
    )
    VALUES (
      :tag, :node_id, :catalog_tag_commit_oid, :name, :published_at, :created_at,
      :updated_at, :html_url, :prerelease, NULL, NULL, 0, :body
    )
  `).run({
    tag: row.tag,
    node_id: row.node_id,
    catalog_tag_commit_oid: row.catalog_tag_commit_oid,
    name: row.name,
    published_at: row.published_at,
    created_at: row.created_at,
    updated_at: row.updated_at,
    html_url: row.html_url,
    prerelease: row.prerelease,
    body: row.body,
  });
}

function readReleaseCatalogReceiptRows(path: string) {
  return readRows(
    path,
    `SELECT ${releaseCatalogReceiptColumns.join(', ')}
     FROM release_catalog_capture_receipts
     ORDER BY id`,
  );
}

function verifyReleaseCatalogReceiptDb(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return verifyReleaseCatalogCaptureReceiptLedger({
      receipts: db.prepare(`
        SELECT ${releaseCatalogReceiptColumns.join(', ')}
        FROM release_catalog_capture_receipts
        ORDER BY id
      `).all() as any[],
      attempts: db.prepare(`
        SELECT run_id, operation, started_at, effective_config_json, content_hash
        FROM refresh_operation_attempts
        ORDER BY started_at, run_id
      `).all() as any[],
      terminalReceipts: db.prepare(`
        SELECT run_id, status, finished_at, payload_json
        FROM refresh_capture_receipts
        ORDER BY id
      `).all() as any[],
      expectedRepository: fixtureRepository,
      activeCatalog: activeReleaseCatalogProjectionForTest(db),
      allowTestFixture: false,
    });
  } finally {
    db.close();
  }
}

function artifactReceiptLedgerFixture({
  identitySeed,
  tag,
}: {
  identitySeed: string;
  tag: string;
}) {
  const evidenceIdentity = createHash('sha256')
    .update(`artifact-evidence:${identitySeed}`)
    .digest('hex');
  const evidenceReportIdentity =
    `release-evidence-v1:sha256:${
      createHash('sha256')
        .update(`artifact-report:${identitySeed}`)
        .digest('hex')
    }`;
  const release = {
    repository: 'openclaw/openclaw',
    tag,
    releaseNodeId: `RE_${identitySeed}`,
    catalogTagCommitOid: createHash('sha1')
      .update(`artifact-commit:${identitySeed}`)
      .digest('hex'),
    publishedAt: '2026-07-03T00:00:00.000Z',
  };
  const receiptId = `artifact-receipt-v2:${evidenceIdentity}`;
  const contentHash = createHash('sha256')
    .update(`artifact-receipt-content:${identitySeed}`)
    .digest('hex');
  return {
    receiptId,
    release,
    evidenceIdentity,
    evidenceReportIdentity,
    contentHash,
    storage: {
      receipt_id: receiptId,
      schema_version: 2,
      release_repository: release.repository,
      release_tag: release.tag,
      release_node_id: release.releaseNodeId,
      release_tag_commit_oid: release.catalogTagCommitOid,
      release_published_at: release.publishedAt,
      evidence_identity: evidenceIdentity,
      canonical_receipt_json: canonicalOperationJson({
        schemaVersion: 2,
        release,
        evidenceReportIdentity,
      }),
      previous_content_hash: null,
      content_hash: contentHash,
    },
  };
}

function insertArtifactReceiptLedgerRow(
  db: DatabaseSync,
  receipt: ReturnType<typeof artifactReceiptLedgerFixture>,
) {
  db.prepare(`
    INSERT INTO release_artifact_verification_receipts (
      receipt_id, schema_version, release_repository, release_tag,
      release_node_id, release_tag_commit_oid, release_published_at,
      evidence_identity, canonical_receipt_json, previous_content_hash,
      content_hash
    )
    VALUES (
      :receipt_id, :schema_version, :release_repository, :release_tag,
      :release_node_id, :release_tag_commit_oid, :release_published_at,
      :evidence_identity, :canonical_receipt_json, :previous_content_hash,
      :content_hash
    )
  `).run(receipt.storage);
}

function seedArtifactReceiptLedgerRow(
  db: DatabaseSync,
  input: {
    identitySeed: string;
    tag: string;
  },
) {
  const receipt = artifactReceiptLedgerFixture(input);
  insertArtifactReceiptLedgerRow(db, receipt);
  return receipt;
}

function artifactObservationLedgerFixture({
  identitySeed,
  runId,
  receipt,
}: {
  identitySeed: string;
  runId: string;
  receipt: ReturnType<typeof artifactReceiptLedgerFixture>;
}) {
  const observationId =
    `artifact-observation-v1:${
      createHash('sha256')
        .update(`artifact-observation:${identitySeed}`)
        .digest('hex')
    }`;
  const observedAt = '2026-07-03T10:00:03.500Z';
  const contentHash = createHash('sha256')
    .update(`artifact-observation-content:${identitySeed}`)
    .digest('hex');
  return {
    observationId,
    runId,
    release: receipt.release,
    receiptId: receipt.receiptId,
    receiptContentHash: receipt.contentHash,
    contentHash,
    storage: {
      observation_id: observationId,
      schema_version: 1,
      run_id: runId,
      observed_at: observedAt,
      release_repository: receipt.release.repository,
      release_tag: receipt.release.tag,
      release_node_id: receipt.release.releaseNodeId,
      release_tag_commit_oid: receipt.release.catalogTagCommitOid,
      release_published_at: receipt.release.publishedAt,
      receipt_id: receipt.receiptId,
      receipt_content_hash: receipt.contentHash,
      canonical_observation_json: canonicalOperationJson({
        schemaVersion: 1,
        observationId,
        runId,
        observedAt,
        release: receipt.release,
        receiptId: receipt.receiptId,
        receiptContentHash: receipt.contentHash,
      }),
      previous_content_hash: null,
      content_hash: contentHash,
    },
  };
}

function insertArtifactObservationLedgerRow(
  db: DatabaseSync,
  observation: ReturnType<typeof artifactObservationLedgerFixture>,
) {
  db.prepare(`
    INSERT INTO release_artifact_verification_observations (
      observation_id, schema_version, run_id, observed_at,
      release_repository, release_tag, release_node_id,
      release_tag_commit_oid, release_published_at, receipt_id,
      receipt_content_hash, canonical_observation_json,
      previous_content_hash, content_hash
    )
    VALUES (
      :observation_id, :schema_version, :run_id, :observed_at,
      :release_repository, :release_tag, :release_node_id,
      :release_tag_commit_oid, :release_published_at, :receipt_id,
      :receipt_content_hash, :canonical_observation_json,
      :previous_content_hash, :content_hash
    )
  `).run(observation.storage);
}

function seedArtifactObservationLedgerRow(
  db: DatabaseSync,
  input: {
    identitySeed: string;
    runId: string;
    receipt: ReturnType<typeof artifactReceiptLedgerFixture>;
  },
) {
  const observation = artifactObservationLedgerFixture(input);
  insertArtifactObservationLedgerRow(db, observation);
  return observation;
}

function seedArtifactPublicationOperationRun(
  db: DatabaseSync,
  {
    runId,
    omitObservation = false,
    substituteReceiptContentHash = false,
  }: {
    runId: string;
    omitObservation?: boolean;
    substituteReceiptContentHash?: boolean;
  },
) {
  const artifactReceipt = artifactReceiptLedgerFixture({
    identitySeed: runId,
    tag: 'v-test',
  });
  const artifactObservation = artifactObservationLedgerFixture({
    identitySeed: runId,
    runId,
    receipt: artifactReceipt,
  });
  const publication = buildReleaseArtifactPublication([{
    release: artifactObservation.release,
    observationId: artifactObservation.observationId,
    observationContentHash: artifactObservation.contentHash,
    receiptId: artifactReceipt.receiptId,
    receiptContentHash: substituteReceiptContentHash
      ? createHash('sha256').update(`substituted:${runId}`).digest('hex')
      : artifactReceipt.contentHash,
    evidenceIdentity: artifactReceipt.evidenceIdentity,
    evidenceReportIdentity: artifactReceipt.evidenceReportIdentity,
  }]);
  const operation = seedOperationReceiptRunWithCatalogAuthority(db, {
    runId,
    releaseArtifacts: publication,
  });
  insertArtifactReceiptLedgerRow(db, artifactReceipt);
  if (!omitObservation) {
    insertArtifactObservationLedgerRow(db, artifactObservation);
  }
  return {
    operation,
    artifactReceipt,
    artifactObservation,
    publication,
  };
}

function seedEmptyCompoundAdvisorySnapshot(
  db: DatabaseSync,
  {
    snapshotId = 1,
    capturedAt,
  }: {
    snapshotId?: number;
    capturedAt: string;
  },
): CompoundAdvisorySnapshotMetadata {
  const repository = {
    owner: 'openclaw',
    name: 'openclaw',
    url: 'https://github.com/openclaw/openclaw',
  };
  const target = {
    ecosystem: 'npm',
    packageName: 'openclaw',
  };
  const emptyIdentityDigest = createHash('sha256')
    .update(JSON.stringify([]))
    .digest('hex');
  const emptyRepositoryIdentityDigest = createHash('sha256')
    .update(JSON.stringify([0, []]))
    .digest('hex');
  const graphqlObservation = {
    source: 'graphql-security-vulnerabilities' as const,
    retrieval: {
      startedAt: capturedAt,
      completedAt: capturedAt,
    },
    ecosystem: target.ecosystem,
    packageName: target.packageName,
    exhausted: true,
    stabilized: true,
    totalCount: 0,
    nodeCount: 0,
    uniqueRangeCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: createHash('sha256')
      .update(JSON.stringify([0, []]))
      .digest('hex'),
    identityDigest: emptyIdentityDigest,
    ranges: [],
    rangeIdentities: [],
  };
  const repositoryObservation = {
    source: 'repository-security-advisories-rest' as const,
    retrieval: {
      startedAt: capturedAt,
      completedAt: capturedAt,
    },
    stabilized: true,
    exhausted: false,
    totalCount: null,
    observedAdvisoryCount: 0,
    observedRangeCount: 0,
    targetRangeCount: 0,
    pageCount: 1,
    pagesFetched: 4,
    sweepCount: 4,
    digest: createHash('sha256')
      .update(JSON.stringify([0, []]))
      .digest('hex'),
    identityDigest: emptyRepositoryIdentityDigest,
    targetIdentityDigest: emptyIdentityDigest,
    allRangeIdentities: [],
    targetRangeIdentities: [],
    advisories: [],
    completeness: {
      terminalPageProven: false,
      terminalPageEvidence: 'unproven-no-link' as const,
      terminalPageLinkHeaderPresent: false,
      remoteTotalCount: null,
      enumeratedCount: 0,
      crossOrderVerified: true,
      boundaryEvidence: {
        updatedAtDesc: {
          mode: 'single-page-no-link' as const,
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
        updatedAtAsc: {
          mode: 'single-page-no-link' as const,
          linkHeaderPresent: false,
          pageCount: 1,
          sweepCount: 2,
        },
      },
    },
  };
  const snapshot = buildCompoundAdvisorySnapshot({
    capturedAt,
    repository,
    observations: {
      securityVulnerabilities: graphqlObservation,
      repositoryAdvisories: repositoryObservation,
    },
    reconciliation: {
      target,
      graphqlSecurityVulnerabilities: {
        totalCount: 0,
        rangeCount: 0,
        identityDigest: emptyIdentityDigest,
        rangeIdentities: [],
      },
      repositoryAdvisories: {
        totalCount: null,
        observedAdvisoryCount: 0,
        targetRangeCount: 0,
        identityDigest: emptyIdentityDigest,
        rangeIdentities: [],
        completenessProven: false,
      },
    },
  });
  const scoreRows = compoundAdvisoryScoreRows(snapshot);
  const scoreContentDigest = advisorySnapshotContentHash(scoreRows);
  const snapshotJson = canonicalCompoundAdvisorySnapshotJson(snapshot);
  const contentHash = compoundAdvisorySnapshotLedgerContentHash({
    capturedAt,
    repository,
    target,
    sourceHash: snapshot.sourceHash,
    catalogHash: snapshot.catalogHash,
    scoreHash: snapshot.score.hash,
    rowCount: snapshot.rows.length,
    scoreRowCount: scoreRows.length,
    scoreContentDigest,
    snapshotJson,
    previousContentHash: null,
  });
  const metadata: CompoundAdvisorySnapshotMetadata = {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    snapshotId,
    capturedAt,
    repository,
    target,
    sourceHash: snapshot.sourceHash,
    catalogHash: snapshot.catalogHash,
    scoreHash: snapshot.score.hash,
    contentHash,
    previousContentHash: null,
    rowCount: snapshot.rows.length,
    scoreRowCount: scoreRows.length,
    scoreReady: true,
    scoreContentDigest,
  };
  db.prepare(`
    INSERT INTO advisory_snapshot_v2_history (
      id, schema_version, captured_at,
      repository_owner, repository_name, repository_url,
      target_ecosystem, target_package_name,
      source_hash, catalog_hash, score_hash, score_ready,
      row_count, score_row_count, score_content_digest,
      snapshot_json, previous_content_hash, content_hash
    )
    VALUES (
      :snapshotId, :schemaVersion, :capturedAt,
      :repositoryOwner, :repositoryName, :repositoryUrl,
      :targetEcosystem, :targetPackageName,
      :sourceHash, :catalogHash, :scoreHash, 1,
      0, 0, :scoreContentDigest,
      :snapshotJson, NULL, :contentHash
    )
  `).run({
    snapshotId,
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    capturedAt,
    repositoryOwner: repository.owner,
    repositoryName: repository.name,
    repositoryUrl: repository.url,
    targetEcosystem: target.ecosystem,
    targetPackageName: target.packageName,
    sourceHash: snapshot.sourceHash,
    catalogHash: snapshot.catalogHash,
    scoreHash: snapshot.score.hash,
    scoreContentDigest,
    snapshotJson,
    contentHash,
  });
  return metadata;
}

function compoundAdvisoryReceiptBinding(
  metadata: CompoundAdvisorySnapshotMetadata,
) {
  return {
    metaKey: ADVISORY_SNAPSHOT_V2_META_KEY,
    metadataDigest: compoundAdvisorySnapshotMetadataDigest(metadata),
    metadata,
    snapshotId: metadata.snapshotId,
    sourceHash: metadata.sourceHash,
    catalogHash: metadata.catalogHash,
    scoreHash: metadata.scoreHash,
    contentHash: metadata.contentHash,
    contentDigest: metadata.scoreContentDigest,
    advisoryCount: metadata.scoreRowCount,
    rowCount: metadata.scoreRowCount,
    catalogRowCount: metadata.rowCount,
    scoreRowCount: metadata.scoreRowCount,
  };
}

function compoundAdvisoryAuthorization(
  metadata: CompoundAdvisorySnapshotMetadata,
  ledger: ReturnType<typeof readOperationReceiptLedger>,
) {
  const verification = verifyOperationReceiptLedger(ledger);
  return compoundAdvisorySnapshotPublicationAuthorizations({
    snapshots: [{ metadata }],
    attempts: ledger.attempts.map((attempt) => ({
      runId: String(attempt.run_id),
      startedAt: String(attempt.started_at),
    })),
    receipts: ledger.receipts.map((receipt) => ({
      receiptId: String(receipt.receipt_id),
      runId: String(receipt.run_id),
      status: String(receipt.status),
      finishedAt: String(receipt.finished_at),
      durationMs: Number(receipt.duration_ms),
      stageEventCount: Number(receipt.stage_event_count),
      stageChainHash:
        receipt.stage_chain_hash == null
          ? null
          : String(receipt.stage_chain_hash),
      payloadJson: String(receipt.payload_json),
    })),
    operationLedgerProblems: verification.problems,
  });
}

function securityPromotionForecast(): ReleaseValidationForecastLedgerRow {
  return {
    id: 1,
    decision_id: 'decision-security-receipt-rechain',
    opportunity_code: 'first_verified_after_24h',
    recorded_at: '2025-12-01T00:00:00.000Z',
    latest_release_tag: 'v2025.12.1',
    latest_release_published_at: '2025-11-29T00:00:00.000Z',
    selected_tag: 'v2025.12.1',
    audit_history_run_id: 'history-security-receipt-rechain',
    score_model_version: 'model-v1',
    prompt_version: 6,
    policy_code: 'highest_confidence_with_recency_tolerance',
    candidate_scores_json: '[{"tag":"v2025.12.1","score":8.5}]',
    decision_json: '{"schemaVersion":4,"selectedTag":"v2025.12.1"}',
    source_identity_json: JSON.stringify({
      schemaVersion: 2,
      digest: 'source-at-forecast',
    }),
    content_hash: 'forecast-security-receipt-rechain',
  };
}

function securityPromotionObservationInput(
  forecast: ReleaseValidationForecastLedgerRow,
  advisorySnapshots: AdvisorySnapshotValidationEvidence[],
): ObservationAssessmentInput {
  const observedAt = '2026-01-02T11:00:00.000Z';
  const currentSourceIdentity = {
    schemaVersion: 2,
    digest: 'source-at-observation',
  };
  const targets = releaseValidationObservationTargets(forecast);
  const auditHistory: ReleaseScoreAuditHistoryEvidenceRow[] = targets.map(
    (target, index) => ({
      id: index + 1,
      run_id: `observe-security-receipt-rechain-${index}`,
      recorded_at: observedAt,
      release_tag: target.targetReleaseTag,
      scored_at: observedAt,
      score_model_version: 'model-v1',
      prompt_version: 6,
      final_score: 8.5,
      status: 'eligible',
      band: 'good',
      recommended: 1,
      input_json: JSON.stringify({
        rawIssueCount: 0,
        classifiedIssueCount: 0,
        hoursToNextStable: null,
      }),
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: JSON.stringify({
        schemaVersion: 2,
        evidenceCounts: {
          verifiedDebt: 0,
          carryoverDebt: 0,
          staleDebt: 0,
          openedFeltSerious: 0,
          verifiedFixed: 0,
          unverifiedClosed: 0,
          unclassifiedIssues: 0,
        },
        debtSummary: { verified: { count: 0 } },
        verifiedDebt: [],
        openedFeltSerious: [],
        unclassifiedIssues: [],
      }),
      gate_evidence_json: '{"schemaVersion":1}',
      source_identity_json: JSON.stringify(currentSourceIdentity),
    }),
  );
  return {
    forecast,
    horizonCode: 'security_30d',
    now: observedAt,
    auditHistory,
    currentSourceIdentity,
    issueCrawl: {
      finishedAt: observedAt,
      scorePersistedAt: observedAt,
      scorePersisted: true,
      stopReason: 'early_stop',
      backfillCompleteAfterRun: true,
      commenterScanTruncatedCount: 0,
      classificationFailures: [],
      evidenceRefreshFailures: [],
    },
    scorePersistence: {
      persistedAt: observedAt,
      scoreModelVersion: 'model-v1',
      promptVersion: 6,
      sourceIdentityDigest: currentSourceIdentity.digest,
      releaseTags: targets.map((target) => target.targetReleaseTag),
      issueCrawlFinishedAt: observedAt,
      issueCrawlScorePersistedAt: observedAt,
    },
    advisorySnapshots,
    independentFieldEvidence: null,
  };
}

function seedEmptyAdvisoryV2Snapshot(
  db: DatabaseSync,
  id: number,
  contentHash: string,
) {
  db.prepare(`
    INSERT INTO advisory_snapshot_v2_history (
      id, schema_version, captured_at,
      repository_owner, repository_name, repository_url,
      target_ecosystem, target_package_name,
      source_hash, catalog_hash, score_hash, score_ready,
      row_count, score_row_count, score_content_digest,
      snapshot_json, previous_content_hash, content_hash
    )
    VALUES (
      ?, 2, '2026-07-03T00:00:00.000Z',
      'openclaw', 'openclaw', 'https://github.com/openclaw/openclaw',
      'npm', 'openclaw',
      'shared-source', 'shared-catalog', 'shared-score', 1,
      0, 0, 'shared-score-content',
      '{}', NULL, ?
    )
  `).run(id, contentHash);
}

function seedIssueCatalogSnapshot(db: DatabaseSync) {
  db.prepare(`
    INSERT INTO issue_catalog_snapshots (
      snapshot_id, schema_version, row_schema_version, repository, source,
      source_order, captured_at, boundary_total_count, observed_total_count,
      post_boundary_growth_count, terminal_node_id, terminal_issue_number,
      terminal_created_at, fetched_count, unique_count, page_count,
      pages_fetched, sweep_count, membership_digest, content_digest,
      last_request_cursor, row_count, row_schema_digest, rows_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (
      'destination-snapshot', 1, 1, 'openclaw/openclaw',
      'github.repository.issues', 'CREATED_AT_ASC',
      '2026-07-03T00:00:00.000Z', 0, 0, 0, NULL, NULL, NULL,
      0, 0, 0, 2, 2, 'membership-only', 'content-only', NULL, 0,
      'row-schema-only', 'rows-only', NULL, 'snapshot-only'
    )
  `).run();
}

function seedIssueCatalogSnapshotConsumption(db: DatabaseSync) {
  seedIssueCatalogSnapshot(db);
  db.prepare(`
    INSERT INTO issue_catalog_snapshot_consumptions (
      schema_version, snapshot_id, repository, run_id, consumed_at,
      processed_row_count, processed_page_count, snapshot_content_hash,
      previous_content_hash, content_hash
    )
    VALUES (
      1, 'destination-snapshot', 'openclaw/openclaw',
      'destination-consumption-run', '2026-07-03T01:00:00.000Z',
      0, 0, 'snapshot-only', NULL, 'consumption-only'
    )
  `).run();
}

function readOperationReceiptLedger(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return {
      attempts: db.prepare(`
        SELECT *
        FROM refresh_operation_attempts
        ORDER BY started_at, run_id
      `).all() as Array<Record<string, any>>,
      stageEvents: db.prepare(`
        SELECT *
        FROM refresh_operation_stage_events
        ORDER BY run_id, sequence
      `).all() as Array<Record<string, any>>,
      receipts: db.prepare(`
        SELECT *
        FROM refresh_capture_receipts
        ORDER BY id
      `).all() as Array<Record<string, any>>,
    };
  } finally {
    db.close();
  }
}

function runTestCommand(command: string, args: string[]) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  assert.equal(
    result.status,
    0,
    `${command} ${args.join(' ')} failed: ${String(result.stderr ?? '').trim()}`,
  );
  return String(result.stdout ?? '').trim();
}

function waitForChildReady(child: ReturnType<typeof spawn>) {
  return new Promise<void>((resolvePromise, rejectPromise) => {
    const timeout = setTimeout(() => {
      rejectPromise(new Error('Timed out waiting for holder process'));
    }, 5_000);
    const cleanup = () => {
      clearTimeout(timeout);
      child.off('error', onError);
      child.off('exit', onExit);
      child.stdout?.off('data', onData);
    };
    const onError = (error: Error) => {
      cleanup();
      rejectPromise(error);
    };
    const onExit = (code: number | null) => {
      cleanup();
      rejectPromise(new Error(`Holder process exited before ready with code ${code}`));
    };
    const onData = (chunk: Buffer | string) => {
      if (!String(chunk).includes('ready')) return;
      cleanup();
      resolvePromise();
    };
    child.on('error', onError);
    child.on('exit', onExit);
    child.stdout?.on('data', onData);
  });
}

function readTestAcl(path: string) {
  return runTestCommand('/bin/ls', ['-lde', path])
    .split('\n')
    .slice(1)
    .map((line) => line.trim())
    .filter(Boolean);
}

function setPromotionState(db: DatabaseSync, value: string) {
  db.prepare(`UPDATE promotion_state SET value=? WHERE key='state'`).run(value);
}

function readPromotionState(path: string) {
  const db = new DatabaseSync(path, { readOnly: true });
  try {
    return String(db.prepare(`SELECT value FROM promotion_state WHERE key='state'`).get()?.value);
  } finally {
    db.close();
  }
}

function backupFiles(fixture: ReturnType<typeof createFixture>) {
  const prefix = `${fixture.destinationPath}.pre-promotion-`;
  const destinationDirectory = dirname(fixture.destinationPath);
  return readdirSync(destinationDirectory)
    .map((name) => join(destinationDirectory, name))
    .filter((path) => path.startsWith(prefix) && path.includes('.bak'))
    .sort();
}

function closeFixtureDatabases(fixture: ReturnType<typeof createFixture>) {
  fixture.source.close();
  fixture.destination.close();
}

function healthyDoctor() {
  return (_options?: unknown) => ({
    ok: true,
    failures: [],
    latestScoredStable: {
      tag: 'v1',
      scoredAt: '2026-07-03T00:00:00.000Z',
    },
    scorePersistence: {
      sourceIdentity: {
        current: { digest: 'current-source-digest' },
        persisted: { digest: 'persisted-source-digest' },
      },
    },
  });
}

function validationReport(
  status: 'insufficient' | 'validated' | 'measurable_but_failed',
) {
  const validated = status === 'validated';
  const insufficient = status === 'insufficient';
  return {
    schemaVersion: 4,
    generatedAt: '2026-07-03T12:34:56.000Z',
    status,
    failureClass: validated
      ? null
      : insufficient
        ? 'sample_or_power'
        : 'minimum_quality_criteria',
    errors: [],
    forecastLedgerRowCount: insufficient ? 4 : 20,
    eligibleForecastCount: insufficient ? 4 : 20,
    outcomeLedgerRowCount: insufficient ? 0 : 40,
    currentStratum: {
      status,
      sampleSufficient: !insufficient,
      qualityPassed: validated,
    },
  };
}

function validationGateResult(report: Record<string, unknown>, exitCode: number) {
  const status = String(report.status);
  return {
    name: 'prospective validation evaluation',
    script: 'scripts/validation/evaluate-score-quality.mjs',
    args: [],
    passed: true,
    ...validatePromotionValidationReport(report, exitCode, 'test candidate'),
    canonicalEvaluationReceipt: {
      evaluationId: 'a'.repeat(64),
      contentHash: 'b'.repeat(64),
      evaluatedAt: report.generatedAt,
      status,
      persistence: 'already_captured',
      insertedCount: 0,
      equivalentCount: 0,
    },
    report,
  };
}

function testEvaluationReceipt() {
  return validationGateResult(
    validationReport('validated'),
    0,
  ).canonicalEvaluationReceipt;
}

function promotionReceiptResult({
  environment,
  promotedAt,
  evaluation,
  sourceProofHash,
  destinationProofHash,
}: Record<string, any>) {
  return {
    schemaVersion: 1,
    promotionId: 'c'.repeat(64),
    contentHash: 'd'.repeat(64),
    environment,
    promotedAt,
    evaluationId: evaluation.evaluationId,
    evaluationContentHash: evaluation.contentHash,
    sourceProofHash,
    destinationProofHash,
    persistence: 'inserted',
    insertedCount: 1,
    equivalentCount: 0,
  };
}

function recordTestPromotion(input: Record<string, any>) {
  const receipt = promotionReceiptResult(input);
  const db = new DatabaseSync(input.dbPath);
  try {
    db.prepare(`
      INSERT INTO release_validation_promotion_receipts (
        promotion_id, content_hash, record_json
      )
      VALUES (?, ?, ?)
    `).run(
      receipt.promotionId,
      receipt.contentHash,
      JSON.stringify(receipt),
    );
  } finally {
    db.close();
  }
  return receipt;
}

function testInheritedDeploymentLock({
  path,
  fd,
}: {
  path: string;
  fd: number;
}) {
  return {
    assertHeld: () => {},
    proof: {
      schemaVersion: INHERITED_DEPLOYMENT_LOCK_PROOF_SCHEMA_VERSION,
      method: INHERITED_DEPLOYMENT_LOCK_PROOF_METHOD,
      fd,
      path,
      device: '41',
      inode: '73',
      lockType: 'exclusive',
      verified: true,
    },
  };
}

function testDependencies(overrides: Record<string, unknown> = {}) {
  return {
    doctor: healthyDoctor(),
    verifyScore: () => ({ name: 'full score recomputation', passed: true }),
    verifyReleaseAudit: () => ({ name: 'full release-audit invariants', passed: true }),
    verifyValidation: () => validationGateResult(validationReport('validated'), 0),
    verifyGithubReleaseCatalog: ({
      dbPath,
      observedAt,
    }: {
      dbPath: string;
      observedAt: string;
    }) => testGithubReleaseCatalogProof(dbPath, observedAt),
    latestEvaluationReceipt: () => testEvaluationReceipt(),
    recordPromotion: recordTestPromotion,
    readAdvisoryAuditProjection: () => testAdvisoryAuditProjection(),
    listHolders: () => [],
    now: () => new Date('2026-07-03T12:34:56.000Z'),
    acquireDeploymentLock: noopDeploymentLock,
    verifyInheritedDeploymentLock: testInheritedDeploymentLock,
    snapshotDatabase: copyDatabaseSnapshotForTest,
    ...overrides,
  };
}

function testAdvisoryAuditProjection() {
  const metadata = {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    snapshotId: 1,
    capturedAt: '2026-07-03T12:00:00.000Z',
    repository: {
      owner: 'openclaw',
      name: 'openclaw',
      url: 'https://github.com/openclaw/openclaw',
    },
    target: {
      ecosystem: 'npm',
      packageName: 'openclaw',
    },
    sourceHash: '1'.repeat(64),
    catalogHash: '2'.repeat(64),
    scoreHash: '3'.repeat(64),
    contentHash: '4'.repeat(64),
    previousContentHash: null,
    rowCount: 0,
    scoreRowCount: 0,
    scoreReady: true,
    scoreContentDigest: advisorySnapshotContentHash([]),
  };
  return {
    schemaVersion: 1,
    sourceMode: 'receipt_authorized_compound_advisory_v2',
    verified: true,
    snapshotCount: 1,
    latestSnapshotId: 1,
    activeSnapshotId: 1,
    activeMetadata: metadata,
    activeMetadataDigest: compoundAdvisorySnapshotMetadataDigest(metadata),
    activeContentHash: metadata.contentHash,
    activeScoreContentDigest: metadata.scoreContentDigest,
    activeRowCount: 0,
    activeScoreRowCount: 0,
    activeProjectionVerified: true,
    authorizingReceipt: {
      schemaVersion: 1,
      snapshotId: 1,
      metadataDigest: compoundAdvisorySnapshotMetadataDigest(metadata),
      receiptId: 'receipt:test-advisory',
      runId: 'test-advisory',
      receiptSemanticIdentity: '5'.repeat(64),
      operationStartedAt: '2026-07-03T11:59:00.000Z',
      finishedAt: '2026-07-03T12:01:00.000Z',
    },
    authorizedSnapshotIds: [1],
    authorizedSnapshotCount: 1,
    stagedSnapshotIds: [],
    stagedSnapshotCount: 0,
    integrityProblems: [],
    activeProjectionProblems: [],
    operationLedgerProblems: [],
    authorizationProblems: [],
    problems: [],
    failedCount: 0,
  };
}

function copyDatabaseSnapshotForTest(sourcePath: string, snapshotPath: string) {
  rmSync(snapshotPath, { force: true });
  copyFileSync(sourcePath, snapshotPath, fsConstants.COPYFILE_FICLONE);
}

async function noopDeploymentLock() {
  return async () => {};
}

function escapeRegExp(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
