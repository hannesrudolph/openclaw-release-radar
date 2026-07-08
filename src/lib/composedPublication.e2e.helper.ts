import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { Express } from 'express';
import type {
  GhIssueCatalog,
  GhIssueCatalogIssue,
  GhRelease,
  GhReleaseCatalog,
} from './github';

type DatabaseGuardInstallation = {
  assertActive(options: {
    requirePrivateArtifacts: true;
  }): {
    runId: string;
    policyKind: string;
    databasePath: string;
    databaseIdentity: {
      dev: string;
      ino: string;
    } | null;
    dotenvPath: string;
    tempRoot: string;
  };
};

const databaseGuard = require(
  '../../test/database-guard-runtime.cjs',
) as DatabaseGuardInstallation;
const guardAttestation = databaseGuard.assertActive({
  requirePrivateArtifacts: true,
});

const scenario = process.argv[2] ?? 'clean';
const helperCodeRevision =
  process.env.RADAR_CODE_REVISION ?? 'composed-publication-e2e-v1';
const simpleTag = 'v2099.7.5';
const simpleVersion = simpleTag.slice(1);
const predecessorTag = 'v2099.7.4';
const predecessorVersion = predecessorTag.slice(1);
const simpleReleaseNodeId = 'RE_composed_publication';
const predecessorReleaseNodeId = 'RE_composed_publication_predecessor';
const simpleReleaseSha = 'c'.repeat(40);
const predecessorReleaseSha = 'b'.repeat(40);
const simpleIssueNumber = 97501;
const crashWorkerLeaseTtlMs = 60_000;
const incidentPhantomTags = ['v2026.7.1', 'v2026.6.30'] as const;
const fixtureNowMs = Date.now();
const simplePublishedAt = new Date(
  fixtureNowMs - 28 * 60 * 60 * 1_000,
).toISOString();
const predecessorPublishedAt = new Date(
  fixtureNowMs - 72 * 60 * 60 * 1_000,
).toISOString();

assert.equal(
  process.env.NODE_TEST_CONTEXT,
  undefined,
  'composed publication helper must not inherit NODE_TEST_CONTEXT',
);
assert.equal(
  process.env.RADAR_CODE_REVISION,
  helperCodeRevision,
  'composed publication helper must use its fixture code revision',
);
assert.equal(
  guardAttestation.runId,
  process.env.RADAR_TEST_RUN_ID,
  'composed publication helper must use the installed guard run identity',
);
assert.equal(
  guardAttestation.policyKind,
  'authoritative-test-database-guard-policy',
  'composed publication helper must use the authoritative kernel write boundary',
);
assert.equal(
  guardAttestation.databasePath,
  process.env.DB_PATH,
  'composed publication helper must use the guarded private database',
);
assert.equal(
  guardAttestation.dotenvPath,
  process.env.DOTENV_CONFIG_PATH,
  'composed publication helper must use the guarded empty dotenv artifact',
);
assert.equal(
  process.env.RADAR_DB_BOOTSTRAP_MODE,
  composedScenarioBootstrapMode(scenario),
  `composed publication scenario ${scenario} has the wrong bootstrap mode`,
);

const { createE2eDatabaseImportGuard } = require(
  './e2eDatabaseImportGuard',
) as typeof import('./e2eDatabaseImportGuard');
const databaseImportGuard = createE2eDatabaseImportGuard({
  helperName: 'composed publication helper',
  guardAttestation,
  expectedBootstrapMode: composedScenarioBootstrapMode(scenario),
});

const express = require('express') as typeof import('express');
const { config } = require('../config') as typeof import('../config');
const { repositoryAdvisoryCatalogContentDigest } = require(
  './advisoryCatalogDigest',
) as typeof import('./advisoryCatalogDigest');
const { buildArtifactVerificationEvidence } = require(
  './artifactVerification',
) as typeof import('./artifactVerification');
const { canonicalJson } = require(
  './operationReceipts',
) as typeof import('./operationReceipts');
const { buildScoreAuthorityResolutionRun } = require(
  './scoreAuthorityResolution',
) as typeof import('./scoreAuthorityResolution');
const {
  canonicalIssueContentDigest,
  canonicalIssueMembershipDigest,
} = require('./issueCatalogSnapshot') as typeof import('./issueCatalogSnapshot');
const { buildReleaseArtifactPublicationScope } = require(
  './releaseArtifactPublicationScope',
) as typeof import('./releaseArtifactPublicationScope');

process.env.REFRESH_ON_STARTUP = 'false';
process.env.REFRESH_MINUTES = '0';
process.env.COMPARISON_API_ENABLED = 'false';

type DbModule = typeof import('./db');
type RefreshModule = typeof import('./refresh');
type ReleaseScoringModule = typeof import('./releaseScoring');
type SimpleScoreRun = ReturnType<ReleaseScoringModule['buildReleaseScoreRun']>;
type SimpleScorePersistence =
  ReturnType<ReleaseScoringModule['persistReleaseScoreRun']>;
type SimpleForecast =
  ReturnType<ReleaseScoringModule['captureReleaseValidationForecasts']>;

type FixtureReleaseArtifactIdentity =
  Parameters<DbModule['persistReleaseArtifactVerification']>[0]['release'];

type PublishedAuditLinks = {
  review: string;
  issues: string;
  closureProofs: string;
  reachability: string;
};

type ReleaseCatalogTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
  prerelease: boolean,
];

type ReleaseArtifactIdentityTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
];

function composedScenarioBootstrapMode(
  value: string,
): 'fresh' | 'existing' {
  const failurePhases = new Set([
    'score.persist',
    'forecast.capture',
    'success.receipt',
    'commit.fence',
    'lease-loss-before-commit',
  ]);
  const recoveryStatuses = new Set([
    'receiptless',
    'failure',
    'abandoned',
    'multiple',
  ]);
  const crashPhases = new Set([
    'after-attempt',
    'score.persist',
    'forecast.capture',
    'success.receipt',
    'after-commit',
  ]);
  if (value === 'classifier-verify') return 'existing';
  if (
    value === 'clean' ||
    value === 'api-epoch' ||
    value === 'classifier-seed'
  ) {
    return 'fresh';
  }
  if (value.startsWith('failure:')) {
    const phase = value.slice('failure:'.length);
    if (failurePhases.has(phase)) return 'fresh';
  }
  if (value.startsWith('recovery:')) {
    const status = value.slice('recovery:'.length);
    if (recoveryStatuses.has(status)) return 'fresh';
  }
  if (value.startsWith('crash-worker:')) {
    const phase = value.slice('crash-worker:'.length);
    if (crashPhases.has(phase)) return 'fresh';
  }
  if (value.startsWith('crash-recover:')) {
    const phase = value.slice('crash-recover:'.length);
    if (crashPhases.has(phase)) return 'existing';
  }
  throw new Error(`Unknown composed publication scenario: ${value}`);
}

async function main(): Promise<void> {
  if (scenario === 'api-epoch') {
    await runApiEpochScenario();
    return;
  }

  databaseImportGuard.assertReady();
  const dbModule = await import('./db');
  const refreshModule = await import('./refresh');
  try {
    let result: Record<string, unknown>;
    if (scenario === 'clean') {
      result = await runCleanPublication(dbModule, refreshModule);
    } else if (scenario.startsWith('failure:')) {
      result = await runAtomicFailure(
        dbModule,
        refreshModule,
        scenario.slice('failure:'.length),
      );
    } else if (scenario.startsWith('recovery:')) {
      result = await runRecoveryScenario(
        dbModule,
        scenario.slice('recovery:'.length),
      );
    } else if (scenario === 'classifier-seed') {
      result = await seedClassifierAttempts(dbModule);
    } else if (scenario === 'classifier-verify') {
      result = verifyClassifierAttempts(dbModule);
    } else if (scenario.startsWith('crash-worker:')) {
      await runCrashWorker(
        dbModule,
        refreshModule,
        scenario.slice('crash-worker:'.length),
      );
      return;
    } else if (scenario.startsWith('crash-recover:')) {
      result = runCrashRecovery(
        dbModule,
        scenario.slice('crash-recover:'.length),
      );
    } else {
      throw new Error(`Unknown composed publication scenario: ${scenario}`);
    }
    assertNoIncidentPhantomReleaseRows(dbModule);
    emitResult({ scenario, ...result });
  } finally {
    dbModule.db.close();
  }
}

async function runCleanPublication(
  dbModule: DbModule,
  refreshModule: RefreshModule,
): Promise<Record<string, unknown>> {
  const publication = await executeSimplePublication(dbModule, refreshModule, {
    holderId: 'clean-holder',
    trigger: 'clean-publication',
  });
  const { verifyOperationReceiptLedger, verifyOperationReceiptSemanticLinks } =
    await import('./operationReceipts');
  const attempts = dbModule.listRefreshOperationAttempts();
  const stageEvents = dbModule.listRefreshOperationStageEvents();
  const receipts = dbModule.listRefreshCaptureReceipts();
  const historyRows = dbModule.listReleaseScoreAuditHistoryForRun(
    publication.scorePersistence.historyRunId,
  );
  const historyRun = dbModule.getReleaseScoreAuditHistoryRunSeal(
    publication.scorePersistence.historyRunId,
  );
  assert.ok(historyRun);
  const scoringModule = await import('./releaseScoring');
  const { verifyScoreAuditPayloadContracts } =
    await import('./scoreAuditContracts');
  const currentAudit = dbModule.getReleaseScoreAudit(simpleTag);
  assert.ok(currentAudit);
  const scoreContractFailures = verifyScoreAuditPayloadContracts({
    tag: simpleTag,
    scoredAt: currentAudit.scored_at,
    input: JSON.parse(requiredPersistedJson(
      currentAudit.input_json,
      'input_json',
    )),
    components: JSON.parse(requiredPersistedJson(
      currentAudit.components_json,
      'components_json',
    )),
    issueEvidence: JSON.parse(requiredPersistedJson(
      currentAudit.issue_evidence_json,
      'issue_evidence_json',
    )),
    gateEvidence: JSON.parse(requiredPersistedJson(
      currentAudit.gate_evidence_json,
      'gate_evidence_json',
    )),
    versions: {
      scoreInput: scoringModule.SCORE_INPUT_SCHEMA_VERSION,
      scoreComponents: scoringModule.SCORE_COMPONENTS_SCHEMA_VERSION,
      issueEvidence: scoringModule.ISSUE_EVIDENCE_SCHEMA_VERSION,
      gateEvidence: scoringModule.GATE_EVIDENCE_SCHEMA_VERSION,
    },
  });
  assert.deepEqual(scoreContractFailures, []);
  const ledger = verifyOperationReceiptLedger({
    attempts,
    stageEvents,
    receipts,
    leases: dbModule.listRefreshLeases(),
  });
  const links = verifyOperationReceiptSemanticLinks({
    attempts,
    receipts,
    historyRows: historyRows.map((row) => ({
      ...row,
      source_identity_json: row.source_identity_json ?? '',
    })),
    historyRuns: [historyRun],
    forecasts: dbModule.listReleaseValidationForecasts(),
    authorityRuns: dbModule.listScoreAuthorityResolutionRuns(),
    historyV2Seals: dbModule.listReleaseScoreAuditHistoryV2Seals(),
    validationProof: dbModule.readReleaseValidationProofBundle(),
  });
  const probeRows = simpleProbeRows(dbModule);
  assert.deepEqual(probeRows, ['forecast', 'ingestion', 'score']);
  assert.deepEqual(ledger.problems, []);
  assert.deepEqual(links.problems, []);
  assert.equal(
    dbModule.getRelease(simpleTag)?.final_score,
    publication.finalScore,
  );
  assert.notEqual(publication.forecast.eligibilityOutcome, 'not_eligible');
  assert.ok(publication.forecast.forecasts.length > 0);
  assert.ok(publication.forecast.canonicalForecasts.length > 0);
  assert.equal(
    dbModule.getRefreshCaptureReceipt(publication.runId)?.receipt_id,
    publication.receiptId,
  );
  const receipt = dbModule.getRefreshCaptureReceipt(publication.runId);
  assert.ok(receipt);
  const receiptPayload = JSON.parse(receipt.payload_json);
  const catalogEvidence = exactReleaseCatalogEvidence(
    dbModule,
    receiptPayload.releaseArtifacts,
  );
  const runArtifactPublication = dbModule.releaseArtifactPublicationForRun(
    publication.runId,
  );
  const currentArtifact =
    dbModule.getCurrentReleaseArtifactVerificationObservation(
      simpleReleaseIdentity(),
    );
  const stagedSourceIdentity = publication.stagedSourceIdentity;
  const publishedSourceIdentity = dbModule.scoreSourceIdentity();
  const historySourceIdentity = JSON.parse(
    historyRows[0]?.source_identity_json ?? 'null',
  );
  assert.equal(receiptPayload.schemaVersion, 3);
  assert.deepEqual(receiptPayload.releaseArtifacts, runArtifactPublication);
  assert.deepEqual(receiptPayload.releaseArtifactScope.scoredReleaseTags, [
    simpleTag,
  ]);
  assert.deepEqual(receiptPayload.releaseArtifactScope.dependencyReleaseTags, [
    predecessorTag,
  ]);
  assert.deepEqual(
    receiptPayload.releaseArtifactScope.predecessorByReleaseTag,
    { [simpleTag]: predecessorTag },
  );
  assert.equal(runArtifactPublication.linkCount, 2);
  const scoredArtifactLink = runArtifactPublication.links.find(
    (link) => link.release.tag === simpleTag,
  );
  assert.ok(scoredArtifactLink);
  assert.equal(
    scoredArtifactLink.receiptId,
    publication.artifactReceiptId,
  );
  assert.equal(
    scoredArtifactLink.observationId,
    publication.artifactObservationId,
  );
  assert.equal(currentArtifact?.receiptId, publication.artifactReceiptId);
  assert.equal(
    currentArtifact?.observationId,
    publication.artifactObservationId,
  );
  assert.deepEqual(publishedSourceIdentity, stagedSourceIdentity);
  assert.deepEqual(historySourceIdentity, stagedSourceIdentity);
  assert.equal(dbModule.releaseRefreshLease(
    publication.leaseName,
    publication.holderId,
  ), true);
  const apiVerification = await verifyPublicationApis({
    runId: publication.runId,
    finalScore: publication.finalScore,
    sourceIdentityDigest: stagedSourceIdentity.digest,
  });
  const sourceIdentityBeforeMutableArtifactFields = dbModule.scoreSourceIdentity();
  let sourceIdentityAfterMutableArtifactFields =
    sourceIdentityBeforeMutableArtifactFields;
  const rollbackMutableArtifactProbe = new Error(
    'rollback mutable release artifact probe',
  );
  try {
    dbModule.runInWriteTransaction(() => {
      mutateSimpleReleaseArtifactFields(dbModule);
      sourceIdentityAfterMutableArtifactFields = dbModule.scoreSourceIdentity();
      assert.deepEqual(
        sourceIdentityAfterMutableArtifactFields,
        sourceIdentityBeforeMutableArtifactFields,
      );
      throw rollbackMutableArtifactProbe;
    });
  } catch (error) {
    assert.equal(error, rollbackMutableArtifactProbe);
  }
  assert.deepEqual(
    dbModule.scoreSourceIdentity(),
    sourceIdentityBeforeMutableArtifactFields,
  );
  const artifactLedger = dbModule.releaseArtifactVerificationLedgerIntegrity();
  assert.deepEqual(artifactLedger.problems, []);
  assert.equal(artifactLedger.receiptCount, 2);
  assert.equal(artifactLedger.observationCount, 2);
  const validationAdvisorySnapshots =
    dbModule.listAuthorizedReleaseValidationAdvisorySnapshots();
  const compoundValidationAdvisorySnapshots =
    validationAdvisorySnapshots.filter((snapshot) => snapshot.schemaVersion === 2);
  assert.equal(compoundValidationAdvisorySnapshots.length, 1);
  assert.equal(
    compoundValidationAdvisorySnapshots[0].snapshotId,
    receiptPayload.advisoryCatalog.snapshotId,
  );
  assert.equal(
    compoundValidationAdvisorySnapshots[0].provenance?.publication.runId,
    publication.runId,
  );
  assert.equal(
    compoundValidationAdvisorySnapshots[0].provenance?.publication.receiptId,
    publication.receiptId,
  );
  return {
    runId: publication.runId,
    receiptId: publication.receiptId,
    historyRunId: publication.scorePersistence.historyRunId,
    historyRunContentHash: publication.scorePersistence.historyRunContentHash,
    finalScore: publication.finalScore,
    forecastEligibilityOutcome: publication.forecast.eligibilityOutcome,
    forecastCount: publication.forecast.forecasts.length,
    canonicalForecastCount: publication.forecast.canonicalForecasts.length,
    probeRows,
    ledgerProblems: ledger.problems,
    linkProblems: links.problems,
    scoreContractFailures,
    apiVerificationProblems: apiVerification.receiptProblems,
    apiOutcome: apiVerification.receiptOutcome,
    apiReceiptVerified: apiVerification.receiptVerified,
    apiSemanticLinksVerified: apiVerification.semanticLinksVerified,
    publicStatus: apiVerification.publicStatus,
    publicSnapshotId: apiVerification.publicSnapshotId,
    publicAuditDigest: apiVerification.publicAuditDigest,
    publicScore: apiVerification.publicScore,
    publicReleaseTags: apiVerification.publicReleaseTags,
    releaseIndexTags: apiVerification.releaseIndexTags,
    phantomReviewStatuses: apiVerification.phantomReviewStatuses,
    reviewStatus: apiVerification.reviewStatus,
    issuesReviewStatus: apiVerification.issuesReviewStatus,
    closureProofsReviewStatus:
      apiVerification.closureProofsReviewStatus,
    reachabilityReviewStatus:
      apiVerification.reachabilityReviewStatus,
    releaseAuditFailures: apiVerification.releaseAuditFailures,
    artifactLedgerProblems: artifactLedger.problems,
    artifactReceiptCount: artifactLedger.receiptCount,
    artifactObservationCount: artifactLedger.observationCount,
    authorizedAdvisoryV2SnapshotCount:
      compoundValidationAdvisorySnapshots.length,
    authorizedAdvisoryV2SnapshotId:
      compoundValidationAdvisorySnapshots[0].snapshotId,
    authorizedAdvisoryV2RunId:
      compoundValidationAdvisorySnapshots[0].provenance?.publication.runId,
    authorizedAdvisoryV2ReceiptId:
      compoundValidationAdvisorySnapshots[0].provenance?.publication.receiptId,
    artifactPublicationLinkCount: runArtifactPublication.linkCount,
    artifactPublicationDigest: runArtifactPublication.contentDigest,
    artifactScopeReleaseCount:
      receiptPayload.releaseArtifactScope.releaseCount,
    artifactScopeDigest:
      receiptPayload.releaseArtifactScope.contentDigest,
    artifactScopeScoredReleaseTags:
      receiptPayload.releaseArtifactScope.scoredReleaseTags,
    artifactScopeDependencyReleaseTags:
      receiptPayload.releaseArtifactScope.dependencyReleaseTags,
    artifactReceiptId: publication.artifactReceiptId,
    artifactObservationId: publication.artifactObservationId,
    stagedSourceIdentityDigest: stagedSourceIdentity.digest,
    publishedSourceIdentityDigest: publishedSourceIdentity.digest,
    historySourceIdentityDigest: historySourceIdentity.digest,
    mutableArtifactSourceIdentityDigest:
      sourceIdentityAfterMutableArtifactFields.digest,
    ...catalogEvidence,
  };
}

async function runAtomicFailure(
  dbModule: DbModule,
  refreshModule: RefreshModule,
  failurePhase: string,
): Promise<Record<string, unknown>> {
  assert.ok(
    [
      'score.persist',
      'forecast.capture',
      'success.receipt',
      'commit.fence',
      'lease-loss-before-commit',
    ].includes(failurePhase),
    `unsupported failure phase ${failurePhase}`,
  );
  let thrown: unknown;
  let runId = '';
  let leaseName = '';
  let holderId = '';
  try {
    const publication = await executeSimplePublication(dbModule, refreshModule, {
      holderId: `failure-${failurePhase}`,
      trigger: `failure-${failurePhase}`,
      failurePhase,
    });
    runId = publication.runId;
    leaseName = publication.leaseName;
    holderId = publication.holderId;
  } catch (error) {
    thrown = error;
    const marker = JSON.parse(
      dbModule.getMeta('composed_publication_attempt') ?? 'null',
    ) as {
      runId: string;
      leaseName: string;
      holderId: string;
    } | null;
    assert.ok(marker);
    ({ runId, leaseName, holderId } = marker);
  }
  assert.ok(thrown instanceof Error, `${failurePhase} must throw`);
  const receipt = dbModule.getRefreshCaptureReceipt(runId);
  const stages = dbModule.listRefreshOperationStageEvents(runId);
  const failureEvent = stages.find((event) => event.status === 'failed');
  assert.ok(failureEvent);
  const details = JSON.parse(failureEvent.details_json ?? '{}');
  const expectedPublicationPhase = failurePhase === 'lease-loss-before-commit'
    ? 'commit.fence'
    : failurePhase;
  assert.equal(details.publicationPhase, expectedPublicationPhase);
  assert.equal(receipt?.status, 'failure');
  assert.equal(dbModule.getRelease(simpleTag)?.final_score, null);
  assert.equal(dbModule.getReleaseScoreAudit(simpleTag), undefined);
  assert.equal(
    dbModule.listReleaseScoreAuditHistoryForRun(`refresh:${runId}`).length,
    0,
  );
  assert.deepEqual(simpleProbeRows(dbModule), ['ingestion']);
  assert.equal(dbModule.getMeta('score_persistence_last_run'), null);
  const { verifyOperationReceiptLedger } = await import('./operationReceipts');
  const verification = verifyOperationReceiptLedger({
    attempts: dbModule.listRefreshOperationAttempts(),
    stageEvents: dbModule.listRefreshOperationStageEvents(),
    receipts: dbModule.listRefreshCaptureReceipts(),
    leases: dbModule.listRefreshLeases(),
  });
  assert.deepEqual(verification.problems, []);
  assert.equal(dbModule.releaseRefreshLease(leaseName, holderId), true);
  return {
    failurePhase,
    expectedPublicationPhase,
    error: thrown.message,
    receiptStatus: receipt?.status ?? null,
    stageStatuses: stages.map((event) =>
      `${event.stage}:${event.status}:${event.sequence}`),
    probeRows: simpleProbeRows(dbModule),
    ledgerProblems: verification.problems,
  };
}

async function executeSimplePublication(
  dbModule: DbModule,
  refreshModule: RefreshModule,
  options: {
    holderId: string;
    trigger: string;
    failurePhase?: string;
    leaseTtlMs?: number;
    crashPhase?: string;
  },
): Promise<{
  runId: string;
  leaseName: string;
  holderId: string;
  receiptId: string;
  scoreRun: SimpleScoreRun;
  scorePersistence: SimpleScorePersistence;
  forecast: SimpleForecast;
  finalScore: number;
  artifactReceiptId: string;
  artifactObservationId: string;
  stagedSourceIdentity: ReturnType<DbModule['scoreSourceIdentity']>;
}> {
  const releaseCatalog = seedSimpleReleaseCatalog(dbModule);
  ensureSimpleProbeTable(dbModule);
  dbModule.db.prepare(`
    INSERT OR REPLACE INTO composed_publication_probe(kind, value)
    VALUES('ingestion', ?)
  `).run(options.trigger);
  const startedAt = new Date(Date.now() - 100).toISOString();
  const leaseName = `composed-publication-${options.holderId}`;
  const leaseTtlMs = options.leaseTtlMs ?? 300_000;
  assert.equal(
    dbModule.acquireRefreshLease(
      leaseName,
      options.holderId,
      startedAt,
      leaseTtlMs,
    ),
    true,
  );
  const appendReceipt = (
    input: Parameters<typeof dbModule.appendRefreshCaptureReceipt>[0],
  ) => {
    if (
      options.failurePhase === 'success.receipt' &&
      input.status === 'success'
    ) {
      throw new Error('injected success.receipt failure');
    }
    return dbModule.appendRefreshCaptureReceipt(input);
  };
  const orchestration = refreshModule.__refreshTest.createRefreshOrchestration({
    operation: 'refresh',
    trigger: options.trigger,
    codeRevision: helperCodeRevision,
    effectiveConfig: { schemaVersion: 1, fixture: 'composed-publication' },
    leaseName,
    leaseHolderId: options.holderId,
    leaseTtlMs,
    startedAt,
    dependencies: { appendReceipt },
  });
  dbModule.setMeta('composed_publication_attempt', JSON.stringify({
    runId: orchestration.runId,
    leaseName,
    holderId: options.holderId,
  }));
  if (options.crashPhase === 'after-attempt') {
    crashReady(options.crashPhase);
  }
  const artifactVerification = persistSimpleArtifactVerification(
    dbModule,
    orchestration.runId,
    new Date(Date.parse(startedAt) + 10).toISOString(),
  );
  persistFixtureArtifactVerification(dbModule, {
    runId: orchestration.runId,
    observedAt: new Date(Date.parse(startedAt) + 11).toISOString(),
    release: predecessorReleaseIdentity(),
    version: predecessorVersion,
    bytes: Buffer.from('composed publication predecessor artifact bytes'),
  });
  const scoringModule = await import('./releaseScoring');
  const issue = await seedSimpleNeutralIssue(dbModule);
  dbModule.replaceReleaseClosureDependencySnapshot(
    dbModule.releaseClosureDependencyIdentity(
      simpleTag,
      [simpleIssueNumber],
    ),
  );
  const advisoryProvenance = await persistSimpleAdvisorySnapshot(
    dbModule,
    new Date(Date.parse(startedAt) + 20).toISOString(),
  );
  const issueCrawl = seedSimpleIssueCatalogPublication({
    dbModule,
    refreshModule,
    runId: orchestration.runId,
    startedAt,
    issue,
    advisoryProvenance,
    releaseCatalog,
  });
  await seedSimpleValidationPrerequisites({
    dbModule,
    runId: orchestration.runId,
    leaseName,
    holderId: options.holderId,
    observedAt: new Date(Date.parse(startedAt) + 50).toISOString(),
    scoringModule,
  });
  const scoreNowMs = Date.now();
  const scoreBuiltAt = new Date(scoreNowMs).toISOString();
  const scoreRun = scoringModule.buildReleaseScoreRun({
    releases: [dbModule.getRelease(simpleTag)!],
    oldestScoredStablePredecessorTag: predecessorTag,
    nowForRelease: () => scoreNowMs,
    artifactObservationRunId: orchestration.runId,
  });
  const catalogAttestation =
    refreshModule.__refreshTest.finalReleaseCatalogAttestation({
      initialCatalog: releaseCatalog,
      finalCatalog: releaseCatalog,
      monitoredReleaseCount: 1,
      scoreRun,
      scoreBuiltAt,
      finalObservedAt: scoreBuiltAt,
    });
  const stagedSourceIdentity = scoreRun.sourceIdentity;

  const publish = () => orchestration.publishScore({
    scoreRun,
    scoredReleaseCount: scoreRun.scored.length,
    persistScore: () => {
      if (options.failurePhase === 'score.persist') {
        throw new Error('injected score.persist failure');
      }
      const scorePersistence = scoringModule.persistReleaseScoreRun(
        scoreRun,
        {
          source: 'refresh',
          scope: simpleTag,
          runId: orchestration.runId,
          codeRevision: helperCodeRevision,
          issueCrawl,
          catalogAttestation,
        },
      );
      dbModule.db.prepare(`
        INSERT OR REPLACE INTO composed_publication_probe(kind, value)
        VALUES('score', ?)
      `).run(scorePersistence.historyRunId);
      return scorePersistence;
    },
    afterPersist: () => {
      if (options.crashPhase === 'score.persist') {
        crashReady(options.crashPhase);
      }
    },
    scorePersistDetails: (scorePersistence) => ({
      historyRunId: scorePersistence.historyRunId,
      historyRunContentHash: scorePersistence.historyRunContentHash,
      authorityRunId: scorePersistence.authorityRunId,
      authorityRunContentHash: scorePersistence.authorityRunContentHash,
      historyV2SealContentHash: scorePersistence.historyV2SealContentHash,
      commitNotBefore: scorePersistence.commitTiming.commitNotBefore,
      commitNotAfter: scorePersistence.commitTiming.commitNotAfter,
    }),
    finalizeScore:
      scoringModule.finalizeReleaseScorePublicationMetadata,
    captureForecast: (scorePersistence) => {
      if (options.failurePhase === 'forecast.capture') {
        throw new Error('injected forecast.capture failure');
      }
      const forecast = scoringModule.captureReleaseValidationForecasts({
        run: scoreRun,
        scorePersistence,
      });
      dbModule.db.prepare(`
        INSERT OR REPLACE INTO composed_publication_probe(kind, value)
        VALUES('forecast', ?)
      `).run(forecast.eligibilityOutcome);
      if (options.crashPhase === 'forecast.capture') {
        crashReady(options.crashPhase);
      }
      return forecast;
    },
    forecastCount: (forecast) => forecast.forecasts.length,
    forecastDetails: (forecast) => ({
      eligibilityOutcome: forecast.eligibilityOutcome,
    }),
    successPayload: (scorePersistence, forecastCapture) =>
      refreshModule.__refreshTest.successReceiptPayload({
        operation: 'refresh',
        trigger: options.trigger,
        codeRevision: helperCodeRevision,
        scoreRun,
        scorePersistence,
        forecastCapture,
        advisoryProvenance,
        releaseArtifacts: dbModule.releaseArtifactPublicationForRun(
          orchestration.runId,
        ),
      }),
    assertCommitAllowed: () => {
      if (options.failurePhase === 'lease-loss-before-commit') {
        dbModule.db.prepare(`
          UPDATE refresh_leases
          SET expires_at=?
          WHERE name=? AND holder_id=?
        `).run(
          new Date(Date.now() - 1_000).toISOString(),
          leaseName,
          options.holderId,
        );
        assert.equal(
          dbModule.isRefreshLeaseHeld(
            leaseName,
            options.holderId,
            new Date().toISOString(),
          ),
          false,
        );
        throw new Error('refresh lease was lost before score publication commit');
      }
      if (options.failurePhase === 'commit.fence') {
        throw new Error('injected commit.fence failure');
      }
      if (options.crashPhase === 'success.receipt') {
        crashReady(options.crashPhase);
      }
      const publishedSourceIdentity = dbModule.scoreSourceIdentity();
      if (
        canonicalJson(publishedSourceIdentity) !==
        canonicalJson(stagedSourceIdentity)
      ) {
        throw new Error(
          `Published fixture source identity ${publishedSourceIdentity.digest} ` +
          `does not match staged identity ${stagedSourceIdentity.digest}`,
        );
      }
    },
  });
  const finalized = await orchestration.run(async () => publish());
  if (options.crashPhase === 'after-commit') {
    crashReady(options.crashPhase);
  }
  const finalScore = scoreRun.scored[0]?.conf.score;
  assert.ok(finalScore != null);
  return {
    runId: orchestration.runId,
    leaseName,
    holderId: options.holderId,
    receiptId: finalized.receiptId,
    scoreRun,
    scorePersistence: finalized.scorePersistence,
    forecast: finalized.forecast,
    finalScore,
    artifactReceiptId: artifactVerification.receipt.row.receiptId,
    artifactObservationId:
      artifactVerification.observation.row.observationId,
    stagedSourceIdentity,
  };
}

function repositoryIdentity(): string {
  return `${config.github.owner}/${config.github.repo}`;
}

function remoteRelease(input: {
  tag: string;
  nodeId: string;
  tagCommitOid: string;
  publishedAt: string;
}): GhRelease {
  return {
    node_id: input.nodeId,
    tag_name: input.tag,
    tag_commit_oid: input.tagCommitOid,
    name: input.tag,
    published_at: input.publishedAt,
    created_at: input.publishedAt,
    updated_at: input.publishedAt,
    html_url:
      `https://github.com/${repositoryIdentity()}/releases/tag/${input.tag}`,
    prerelease: false,
    draft: false,
    body: '',
  };
}

function releaseCatalogDigest(releases: GhRelease[]): string {
  const canonical = releases
    .slice()
    .sort((left, right) =>
      left.node_id.localeCompare(right.node_id) ||
      left.tag_name.localeCompare(right.tag_name))
    .map((release) => [
      release.node_id,
      release.tag_name,
      release.tag_commit_oid,
      release.name,
      release.published_at,
      release.created_at,
      release.updated_at,
      release.html_url,
      release.prerelease,
      release.draft,
      release.body,
    ]);
  return createHash('sha256')
    .update(JSON.stringify([releases.length, canonical]))
    .digest('hex');
}

function seedSimpleReleaseCatalog(dbModule: DbModule): GhReleaseCatalog {
  const releases = [
    remoteRelease({
      tag: simpleTag,
      nodeId: simpleReleaseNodeId,
      tagCommitOid: simpleReleaseSha,
      publishedAt: simplePublishedAt,
    }),
    remoteRelease({
      tag: predecessorTag,
      nodeId: predecessorReleaseNodeId,
      tagCommitOid: predecessorReleaseSha,
      publishedAt: predecessorPublishedAt,
    }),
  ];
  dbModule.replaceActiveReleaseCatalog(releases.map((release) => ({
    node_id: release.node_id,
    catalog_tag_commit_oid: release.tag_commit_oid,
    tag: release.tag_name,
    name: release.name,
    published_at: release.published_at!,
    created_at: release.created_at,
    updated_at: release.updated_at,
    html_url: release.html_url,
    prerelease: release.prerelease,
    body: release.body,
  })));
  seedSimpleReleaseEvidence(
    dbModule,
    simpleTag,
    simplePublishedAt,
    simpleReleaseSha,
    null,
  );
  seedSimpleReleaseEvidence(
    dbModule,
    predecessorTag,
    predecessorPublishedAt,
    predecessorReleaseSha,
    48,
  );
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
      digest: releaseCatalogDigest(releases),
      sourceOrder: 'CREATED_AT_DESC',
    },
  };
}

function exactReleaseCatalogEvidence(
  dbModule: DbModule,
  releaseArtifacts: unknown,
): {
  persistedCatalogTuples: ReleaseCatalogTuple[];
  catalogCaptureReceiptTags: string[];
  catalogCaptureReceiptStableCount: number;
  catalogCaptureReceiptPrereleaseCount: number;
  catalogCaptureReceiptLatestStableTuple: ReleaseCatalogTuple | null;
  refreshReceiptArtifactIdentityTuples: ReleaseArtifactIdentityTuple[];
  catalogCaptureReceiptCount: number;
  catalogCaptureReceiptSource: string | null;
  allPersistedReleaseTags: string[];
  inactivePersistedReleaseTags: string[];
} {
  const activeCatalog = dbModule.currentActiveReleaseCatalog();
  const receiptLedger =
    dbModule.releaseCatalogCaptureReceiptLedgerIntegrity(activeCatalog);
  assert.deepEqual(receiptLedger.problems, []);
  assert.ok(
    receiptLedger.latestPayload,
    'active release catalog must have a capture receipt payload',
  );
  const persistedCatalogTuples = dbModule.listActiveReleaseCatalogDb()
    .map((release): ReleaseCatalogTuple => {
      assert.ok(
        release.node_id,
        `persisted catalog release ${release.tag} must have a node ID`,
      );
      assert.ok(
        release.catalog_tag_commit_oid,
        `persisted catalog release ${release.tag} must have a tag commit OID`,
      );
      assert.ok(
        release.prerelease === 0 || release.prerelease === 1,
        `persisted catalog release ${release.tag} must have a prerelease flag`,
      );
      return [
        release.tag,
        release.node_id,
        release.catalog_tag_commit_oid,
        release.prerelease === 1,
      ];
    });
  const receiptActiveCatalog = receiptLedger.latestPayload.activeCatalog;
  const refreshReceiptArtifactIdentityTuples =
    releaseArtifactIdentityTuplesFromReceipt(releaseArtifacts);
  assert.deepEqual(
    refreshReceiptArtifactIdentityTuples
      .map(([tag]) => tag)
      .slice()
      .sort(),
    receiptActiveCatalog.tags.slice().sort(),
    'refresh receipt artifact identities must cover the capture receipt tags',
  );
  const latestStable = receiptActiveCatalog.latestStable;
  const allPersistedReleaseRows = dbModule.db.prepare(`
    SELECT tag, catalog_active
    FROM releases
    ORDER BY catalog_active DESC, catalog_rank IS NULL, catalog_rank, tag
  `).all() as Array<{ tag: string; catalog_active: number }>;
  return {
    persistedCatalogTuples,
    catalogCaptureReceiptTags: [...receiptActiveCatalog.tags],
    catalogCaptureReceiptStableCount: receiptActiveCatalog.stableCount,
    catalogCaptureReceiptPrereleaseCount: receiptActiveCatalog.prereleaseCount,
    catalogCaptureReceiptLatestStableTuple: latestStable
      ? [
          latestStable.tag,
          latestStable.nodeId,
          latestStable.tagCommitOid,
          false,
        ]
      : null,
    refreshReceiptArtifactIdentityTuples,
    catalogCaptureReceiptCount: receiptLedger.receiptCount,
    catalogCaptureReceiptSource: receiptLedger.latestSource,
    allPersistedReleaseTags: allPersistedReleaseRows.map((release) => release.tag),
    inactivePersistedReleaseTags: allPersistedReleaseRows
      .filter((release) => release.catalog_active !== 1)
      .map((release) => release.tag),
  };
}

function releaseArtifactIdentityTuplesFromReceipt(
  releaseArtifacts: unknown,
): ReleaseArtifactIdentityTuple[] {
  assert.ok(
    isRecord(releaseArtifacts) && Array.isArray(releaseArtifacts.links),
    'refresh receipt must carry release artifact links',
  );
  return releaseArtifacts.links.map(
    (link, index): ReleaseArtifactIdentityTuple => {
      assert.ok(
        isRecord(link) && isRecord(link.release),
        `refresh receipt artifact link ${index} must carry a release identity`,
      );
      const release = link.release;
      const tag = release.tag;
      const releaseNodeId = release.releaseNodeId;
      const tagCommitOid = release.catalogTagCommitOid;
      assert.ok(typeof tag === 'string');
      assert.ok(typeof releaseNodeId === 'string');
      assert.ok(typeof tagCommitOid === 'string');
      return [tag, releaseNodeId, tagCommitOid];
    },
  );
}

function seedSimpleReleaseEvidence(
  dbModule: DbModule,
  tag: string,
  publishedAt: string,
  tagCommitOid: string,
  hoursToNextStable: number | null,
): void {
  dbModule.upsertReleaseCommit({
    tag,
    tag_commit_oid: tagCommitOid,
    committed_at: publishedAt,
    check_state: 'SUCCESS',
    check_total: 1,
    check_success: 1,
    check_failure: 0,
    check_pending: 0,
    check_skipped: 0,
    check_contexts_json: JSON.stringify([{
      type: 'CheckRun',
      name: 'release-contract',
      workflowName: 'Release Contract',
      appSlug: 'github-actions',
      status: 'COMPLETED',
      conclusion: 'SUCCESS',
      url: 'https://example.test/checks/release-contract',
    }]),
  });
  dbModule.updateReleaseDerivedStats({
    tag,
    breaking_count: 0,
    fixes_count: 1,
    changes_count: 0,
    highlights_count: 0,
    pr_refs_count: 0,
    beta_count: 0,
    hours_to_next_release: hoursToNextStable,
    hours_to_next_stable: hoursToNextStable,
    npm_package_url:
      `https://www.npmjs.com/package/${config.github.repo}/v/` +
      `${tag.replace(/^v/, '')}`,
    release_tarball_url:
      `https://registry.npmjs.org/${config.github.repo}/-/` +
      `${config.github.repo}-${tag.replace(/^v/, '')}.tgz`,
    release_integrity: `sha512-${tagCommitOid}`,
    release_sha: tagCommitOid,
    full_release_ci_report_url:
      `https://github.com/${repositoryIdentity()}/blob/` +
      `${tagCommitOid}/release-evidence.json`,
    full_release_validation_url:
      `https://github.com/${repositoryIdentity()}/actions/runs/1`,
  });
}

function stableJson(value: unknown): string {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean' ||
    typeof value === 'number'
  ) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(stableJson).join(',')}]`;
  }
  const row = value as Record<string, unknown>;
  return `{${Object.keys(row).sort().map((key) =>
    `${JSON.stringify(key)}:${stableJson(row[key])}`).join(',')}}`;
}

async function seedSimpleNeutralIssue(
  dbModule: DbModule,
): Promise<GhIssueCatalogIssue> {
  const {
    CLASSIFICATION_PROMPT_TEMPLATE_HASH,
    PROMPT_VERSION,
    __llmTest,
  } = await import('./llm');
  const {
    AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    commentEvidenceDigest,
    commentEvidenceStabilizationIdentity,
    commentEvidenceSweepIdentity,
    serializeCommentEvidence,
  } = await import('./commentEvidence');
  const {
    appendClassifierAttempt,
    captureClassifierRawModelOutput,
    captureClassifierRawResponse,
    createClassifierAttemptLedger,
    createClassifierAttemptRun,
    createClassifierAttemptTerminalReceipt,
  } = await import('./classifierAttemptLedger');
  const {
    issueStateEventStabilizationIdentity,
    issueStateEventSweepIdentity,
    issueStateEventsDigest,
    normalizeIssueStateEvents,
  } = await import('./stateEventSnapshot');
  const { CLOSURE_PROOF_ANALYZER_VERSION } =
    await import('./analysisVersions');
  const createdAt = new Date(
    fixtureNowMs - 3 * 60 * 60 * 1_000,
  ).toISOString();
  const closedAt = new Date(
    fixtureNowMs - 60 * 60 * 1_000,
  ).toISOString();
  const commentAt = new Date(
    fixtureNowMs - 90 * 60 * 1_000,
  ).toISOString();
  const repositoryNodeId = 'REPO-node-composed-publication';
  const issueNodeId = `ISSUE-node-${simpleIssueNumber}`;
  const reporterNodeId = `ACTOR-reporter-${simpleIssueNumber}`;
  const maintainerNodeId = `ACTOR-maintainer-${simpleIssueNumber}`;
  const issueTitle =
    `${simpleTag} low-severity niche documentation question about expected behavior`;
  const issueUrl =
    `https://github.com/${repositoryIdentity()}/issues/${simpleIssueNumber}`;
  const comment = {
    id: 975010,
    node_id: 'COMMENT-node-975010',
    node_type: 'IssueComment' as const,
    url: `${issueUrl}#issuecomment-975010`,
    user: {
      id: maintainerNodeId,
      type: 'User',
      login: 'maintainer',
    },
    author_association: 'MEMBER',
    body: 'This is expected behavior, so no code change is required.',
    created_at: commentAt,
    updated_at: commentAt,
  };
  const commentsDigest = commentEvidenceDigest(1, [comment]);
  const snapshotIdentity = {
    repositoryNodeId,
    issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: reporterNodeId,
      login: 'reporter',
      actorType: 'User',
    },
  };
  const firstCommentSweep = commentEvidenceSweepIdentity({
    sweepOrdinal: 1,
    issueUpdatedAt: closedAt,
    totalCount: 1,
    comments: [comment],
    snapshotIdentity,
  });
  const secondCommentSweep = commentEvidenceSweepIdentity({
    sweepOrdinal: 2,
    issueUpdatedAt: closedAt,
    totalCount: 1,
    comments: [comment],
    snapshotIdentity,
  });
  const commentStabilization = commentEvidenceStabilizationIdentity(
    firstCommentSweep,
    secondCommentSweep,
    2,
  );

  dbModule.upsertIssue({
    number: simpleIssueNumber,
    node_id: issueNodeId,
    state: 'closed',
    title: issueTitle,
    body: '',
    author: 'reporter',
    author_node_id: reporterNodeId,
    author_type: 'User',
    author_association: 'CONTRIBUTOR',
    html_url: issueUrl,
    created_at: createdAt,
    updated_at: closedAt,
    closed_at: closedAt,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 1,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(['question']),
    is_bot: 0,
  });
  dbModule.upsertIssueCommentSnapshot({
    issue_number: simpleIssueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_author_node_id: reporterNodeId,
    issue_author_login: 'reporter',
    issue_author_type: 'User',
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: 1,
    fetched_comment_count: 1,
    latest_comment_updated_at: comment.updated_at,
    comments_digest: commentsDigest,
    authority_digest: secondCommentSweep.authorityDigest,
    issue_updated_at: closedAt,
    comments_json: serializeCommentEvidence([comment]),
    stabilization_json: JSON.stringify(commentStabilization),
    stabilization_identity_digest: commentStabilization.identityDigest,
  });
  dbModule.upsertIssueLabelSnapshot({
    issue_number: simpleIssueNumber,
    issue_node_id: issueNodeId,
    snapshot_at: closedAt,
    labels_json: JSON.stringify(['question']),
  });

  const sourceIdentity = dbModule.classifierSourceIdentity(
    [simpleTag],
    PROMPT_VERSION,
  );
  const issue: GhIssueCatalogIssue = {
    node_id: issueNodeId,
    node_type: 'Issue',
    number: simpleIssueNumber,
    state: 'closed',
    title: issueTitle,
    body: '',
    user: {
      id: reporterNodeId,
      type: 'User',
      login: 'reporter',
    },
    author_association: 'CONTRIBUTOR',
    html_url: issueUrl,
    created_at: createdAt,
    updated_at: closedAt,
    closed_at: closedAt,
    comments: 1,
    reaction_total: 0,
    positive_reactions: 0,
    labels: [{ name: 'question' }],
  };
  const prompt = __llmTest.buildClassifierPromptInput(
    issue,
    [comment],
    [simpleTag],
  );
  const rawModelOutput = JSON.stringify({
    sentiment: 'neutral',
    severity: 'low',
    scope: 'niche',
    functionality: 'docs',
    affected_users: 'unknown',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: simpleTag,
    evidence: {
      sentiment: [{
        source_id: 'issue:title',
        excerpt: 'question about expected behavior',
      }],
      severity: [{
        source_id: 'issue:title',
        excerpt: 'low-severity',
      }],
      scope: [{
        source_id: 'issue:title',
        excerpt: 'niche',
      }],
      functionality: [{
        source_id: 'issue:title',
        excerpt: 'documentation',
      }],
      affected_users: [],
      workaroundStatus: [],
      duplicateCluster: [],
      affectsVersion: [{
        source_id: 'issue:title',
        excerpt: simpleTag,
      }],
    },
    rationale: 'Maintainer confirmed that the observed behavior is expected.',
  });
  const classification = __llmTest.parseRawClassification(
    rawModelOutput,
    [simpleTag],
    prompt.groundingSources,
    prompt.inputTruncation,
  );
  const responseId = `chatcmpl-composed-${simpleIssueNumber}`;
  const requestHash = createHash('sha256')
    .update(`composed-request:${simpleIssueNumber}:${responseId}`)
    .digest('hex');
  const classifierRun = createClassifierAttemptRun({
    runId: `composed-classifier-run:${simpleIssueNumber}:${responseId}`,
    issueNumber: simpleIssueNumber,
    startedAt: new Date(Date.parse(commentAt) + 1_000).toISOString(),
    maxAttempts: 1,
    classifierIdentityHash: sourceIdentity.promptTemplateHash,
    requestHash,
  });
  const rawResponse = JSON.stringify({
    id: responseId,
    model: sourceIdentity.model,
    service_tier: sourceIdentity.serviceTier,
    choices: [{ message: { content: rawModelOutput } }],
  });
  const classifierAttempt = appendClassifierAttempt(classifierRun, [], {
    attemptId:
      `composed-classifier-attempt:${simpleIssueNumber}:${responseId}`,
    status: 'accepted_success',
    startedAt: new Date(Date.parse(commentAt) + 2_000).toISOString(),
    finishedAt: new Date(Date.parse(commentAt) + 3_000).toISOString(),
    rawResponse: captureClassifierRawResponse(rawResponse),
    rawModelOutput: captureClassifierRawModelOutput(rawModelOutput),
    error: null,
    retry: {
      decision: 'stop',
      retryable: false,
      delayMs: null,
      reason: 'accepted_success',
    },
    semanticDiagnostics: [],
    provenance: {
      requestHash,
      responseId,
      responseModel: sourceIdentity.model,
      responseServiceTier: sourceIdentity.serviceTier,
    },
  });
  const classifierReceipt = createClassifierAttemptTerminalReceipt(
    classifierRun,
    [classifierAttempt],
    {
      receiptId:
        `composed-classifier-receipt:${simpleIssueNumber}:${responseId}`,
      status: 'accepted_success',
      finishedAt: new Date(Date.parse(commentAt) + 4_000).toISOString(),
      error: null,
    },
  );
  const classifierLedger = createClassifierAttemptLedger(
    classifierRun,
    [classifierAttempt],
    classifierReceipt,
  );
  dbModule.recordClassifierAttemptRun(classifierRun);
  dbModule.recordClassifierAttempt(classifierAttempt);
  dbModule.recordClassifierAttemptTerminalReceipt(classifierReceipt);
  assert.ok(classifierReceipt.selectedAttempt);
  const provenance = {
    schemaVersion: 2 as const,
    responseId,
    requestedModel: sourceIdentity.model,
    responseModel: sourceIdentity.model,
    requestedServiceTier: sourceIdentity.serviceTier,
    responseServiceTier: sourceIdentity.serviceTier,
    reasoningEffort: sourceIdentity.reasoningEffort,
    promptVersion: PROMPT_VERSION,
    promptTemplateHash: CLASSIFICATION_PROMPT_TEMPLATE_HASH,
    promptHash: 'a'.repeat(64),
    rawModelOutputHash: createHash('sha256')
      .update(rawModelOutput)
      .digest('hex'),
    rawModelOutput,
    groundingSources: prompt.groundingSources,
    groundingSourcesHash: createHash('sha256')
      .update(stableJson(prompt.groundingSources))
      .digest('hex'),
    inputTruncation: prompt.inputTruncation,
  };

  const closureEvent = {
    issue_number: simpleIssueNumber,
    issue_node_id: issueNodeId,
    event_id: `closed-${simpleIssueNumber}`,
    closed_at: closedAt,
    connection_ordinal: 0,
    actor_node_id: maintainerNodeId,
    actor_login: 'maintainer',
    actor_type: 'User',
    state_reason: 'COMPLETED',
    closer_type: 'Commit',
    closer_number: null,
    closer_node_id: `COMMIT-node-${simpleIssueNumber}`,
    closer_oid: 'd'.repeat(40),
    raw_json: JSON.stringify({
      id: `closed-${simpleIssueNumber}`,
      __typename: 'ClosedEvent',
      actor: {
        id: maintainerNodeId,
        __typename: 'User',
        login: 'maintainer',
      },
      closer: {
        id: `COMMIT-node-${simpleIssueNumber}`,
        __typename: 'Commit',
        oid: 'd'.repeat(40),
      },
    }),
  };
  const normalizedStateEvents = normalizeIssueStateEvents([{
    eventId: closureEvent.event_id,
    eventNodeType: 'ClosedEvent',
    type: 'closed',
    occurredAt: closedAt,
    connectionOrdinal: 0,
    actorNodeId: closureEvent.actor_node_id,
    actorLogin: closureEvent.actor_login,
    actorType: closureEvent.actor_type,
    stateReason: closureEvent.state_reason,
    closerNodeId: closureEvent.closer_node_id,
    closerType: closureEvent.closer_type,
    closerNumber: null,
    closerOid: closureEvent.closer_oid,
  }]);
  const stateSweep = {
    repositoryNodeId,
    issueNumber: simpleIssueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    issueState: 'closed' as const,
    issueUpdatedAt: closedAt,
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
  dbModule.replaceIssueStateEventSnapshot({
    issue_number: simpleIssueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_node_type: 'Issue',
    issue_state: 'closed',
    issue_updated_at: closedAt,
    total_count: 1,
    fetched_count: 1,
    sweep_count: 2,
    stabilized: true,
    events_digest: issueStateEventsDigest(normalizedStateEvents, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
    }),
    authority_digest: secondStateSweep.sweepDigest,
    stabilization: issueStateEventStabilizationIdentity(
      firstStateSweep,
      secondStateSweep,
      2,
    ),
    closure_events: [closureEvent],
    reopen_events: [],
  });
  const revisions = dbModule.issueEvidenceRevisions(
    [simpleIssueNumber],
  ).get(simpleIssueNumber);
  assert.ok(revisions);
  dbModule.upsertClassification(
    simpleIssueNumber,
    { ...classification, provenance },
    closedAt,
    PROMPT_VERSION,
    commentsDigest,
    sourceIdentity,
    {
      ledger: classifierLedger,
      selectedAttemptBinding: classifierReceipt.selectedAttempt,
      evidenceRevisions: {
        issueRevision: revisions.issueRevision,
        snapshotRevision: revisions.snapshotRevision,
        stateSnapshotRevision: revisions.stateSnapshotRevision,
      },
    },
  );

  const rationaleComment = {
    databaseId: comment.id,
    issueNumber: simpleIssueNumber,
    url: comment.url,
    author: comment.user.login,
    createdAt: comment.created_at,
    updatedAt: comment.updated_at,
    snippet: comment.body,
  };
  dbModule.upsertIssueClosureProof({
    release_tag: simpleTag,
    issue_number: simpleIssueNumber,
    status: 'non_bug_not_actionable',
    summary: 'Maintainer confirmed expected behavior.',
    evidence_json: JSON.stringify({
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
      closedAt,
      closureEventClosedAt: [closedAt],
      stateReasons: ['COMPLETED'],
      hasClosingLink: false,
      hasMergedClosingPr: false,
      hasReachableClosingPr: false,
      hasNotReachableClosingPr: false,
      hasReachableFixCommit: false,
      hasNotReachableFixCommit: false,
      hasUnknownFixCommit: false,
      reachableFixCommits: [],
      notReachableFixCommits: [],
      unknownFixCommits: [],
      targetReachableFixCommits: [],
      targetNotReachableFixCommits: [],
      targetUnknownFixCommits: [],
      predecessorContainedFixCommits: [],
      firstContainingUnknownFixCommits: [],
      directCommitFirstContainingProofs: [],
      fixCommitProof: [],
      linkedPrs: [],
      matchingComments: [rationaleComment],
      nonActionableRationaleComments: [rationaleComment],
      closureContextCommentCount: 1,
    }),
  });
  return issue;
}

async function persistSimpleAdvisorySnapshot(
  dbModule: DbModule,
  capturedAt: string,
) {
  const { buildCompoundAdvisorySnapshot } =
    await import('./advisorySnapshot');
  const hashJson = (value: unknown) =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const packageName = 'openclaw' as const;
  const emptyIdentityDigest = hashJson([]);
  const snapshot = buildCompoundAdvisorySnapshot({
    capturedAt,
    repository: {
      owner: config.github.owner,
      name: config.github.repo,
      url: `https://github.com/${repositoryIdentity()}`,
    },
    target: {
      ecosystem: 'npm',
      packageName,
    },
    sources: {
      graphql: {
        source: 'graphql-security-vulnerabilities',
        retrieval: {
          startedAt: capturedAt,
          completedAt: capturedAt,
        },
        ecosystem: 'npm',
        packageName,
        exhausted: true,
        stabilized: true,
        totalCount: 0,
        nodeCount: 0,
        uniqueRangeCount: 0,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        digest: hashJson([0, []]),
        identityDigest: emptyIdentityDigest,
        ranges: [],
        rangeIdentities: [],
      },
      repositoryRest: {
        source: 'repository-security-advisories-rest',
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
        digest: repositoryAdvisoryCatalogContentDigest([]),
        identityDigest: hashJson([0, []]),
        targetIdentityDigest: emptyIdentityDigest,
        allRangeIdentities: [],
        targetRangeIdentities: [],
        advisories: [],
        completeness: {
          terminalPageProven: false,
          terminalPageEvidence: 'unproven-no-link',
          terminalPageLinkHeaderPresent: false,
          remoteTotalCount: null,
          enumeratedCount: 0,
          crossOrderVerified: true,
          boundaryEvidence: {
            updatedAtDesc: {
              mode: 'single-page-no-link',
              linkHeaderPresent: false,
              pageCount: 1,
              sweepCount: 2,
            },
            updatedAtAsc: {
              mode: 'single-page-no-link',
              linkHeaderPresent: false,
              pageCount: 1,
              sweepCount: 2,
            },
          },
        },
      },
    },
    reconciliation: {
      target: {
        ecosystem: 'npm',
        packageName,
      },
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
  return dbModule.persistCompoundAdvisorySnapshot(snapshot).metadata;
}

function simpleIssueCatalog(issue: GhIssueCatalogIssue): GhIssueCatalog {
  const records = [{ nodeId: issue.node_id, issue }];
  const membershipDigest = canonicalIssueMembershipDigest(1, records);
  const contentDigest = canonicalIssueContentDigest(1, records);
  return {
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
  };
}

function seedSimpleIssueCatalogPublication(input: {
  dbModule: DbModule;
  refreshModule: RefreshModule;
  runId: string;
  startedAt: string;
  issue: GhIssueCatalogIssue;
  advisoryProvenance: Awaited<
    ReturnType<typeof persistSimpleAdvisorySnapshot>
  >;
  releaseCatalog: GhReleaseCatalog;
}): Record<string, unknown> {
  const repository = repositoryIdentity();
  const catalog = simpleIssueCatalog(input.issue);
  const capturedAt = new Date(
    Date.parse(input.startedAt) + 30,
  ).toISOString();
  const header = input.dbModule.insertIssueCatalogSnapshot({
    repository,
    capturedAt,
    catalog,
  });
  const snapshot = input.dbModule.getIssueCatalogSnapshot(header.snapshotId);
  assert.ok(snapshot);
  const consumedAt = new Date(
    Date.parse(input.startedAt) + 40,
  ).toISOString();
  const consumption = input.dbModule.consumeIssueCatalogSnapshot({
    snapshotId: header.snapshotId,
    repository,
    runId: input.runId,
    consumedAt,
    processedRowCount: catalog.metadata.nodeCount,
    processedPageCount: catalog.metadata.pageCount,
  });
  const observedAt = new Date(
    Date.parse(input.startedAt) + 50,
  ).toISOString();
  const catalogAttestation =
    input.refreshModule.__refreshTest.finalIssueCatalogAttestation({
      snapshot,
      finalCatalog: catalog,
      observedAt,
    });
  const baseline =
    input.refreshModule.__refreshTest.issueCrawlBaselineFromCatalog(
      catalog.metadata,
      observedAt,
      input.startedAt,
    );
  input.dbModule.setMeta(
    'issue_crawl_exhaustive_baseline',
    JSON.stringify(baseline),
  );
  const pagination =
    input.refreshModule.__refreshTest.issuePaginationFromCatalog(
      catalog.metadata,
    );
  const issueCrawl = {
    schemaVersion: 4,
    repository,
    startedAt: input.startedAt,
    finishedAt: observedAt,
    fullIssueBackfill: true,
    crawlMode: 'exhaustive',
    backfillCompleteAtStart: false,
    backfillCompleteAfterRun: true,
    baseline,
    pagination,
    catalogSnapshot: {
      schemaVersion: 1,
      snapshotId: header.snapshotId,
      contentHash: header.contentHash,
      capturedAt: header.capturedAt,
      resumed: false,
      priorStatus: 'missing',
      maxAgeHours: 24,
      consumedAt: consumption.consumedAt,
      consumedByRunId: consumption.runId,
      consumptionContentHash: consumption.contentHash,
    },
    catalogAttestation,
    promptSweep: false,
    staleClassificationsAtStart: 0,
    monitoredReleaseCount: 1,
    oldestMonitoredAt: simplePublishedAt,
    pagesFetched: 1,
    issuesFetched: 1,
    monitoredIssuesFetched: 1,
    commentSnapshotIssuesRequested: 1,
    metadataOnlyIssuesObserved: 0,
    maxIssuePages: 100,
    stopReason: 'exhausted',
    crossedOldestEver: true,
    commenterScanTruncatedCount: 0,
    classificationFailures: [],
    evidenceRefreshFailures: [],
    advisoryProvenance: input.advisoryProvenance,
    releaseCatalog: input.releaseCatalog.metadata,
    scorePersisted: false,
    scorePersistedAt: null,
    timings: {},
  };
  const problems =
    input.refreshModule.__refreshTest.issueCrawlMetadataProblems(
      issueCrawl,
      baseline,
      {
        repository,
        forScorePersistence: true,
      },
    );
  assert.deepEqual(problems, []);
  input.dbModule.setMeta(
    'issue_crawl_last_run',
    JSON.stringify(issueCrawl),
  );
  return issueCrawl;
}

async function seedSimpleValidationPrerequisites(input: {
  dbModule: DbModule;
  runId: string;
  leaseName: string;
  holderId: string;
  observedAt: string;
  scoringModule: ReleaseScoringModule;
}): Promise<void> {
  const { planReleaseValidationProofLifecycle } =
    await import('./releaseValidationProofLifecycle');
  const {
    RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
  } = await import('./releaseValidationProof');
  const { planReleaseValidationOpportunityEnrollments } =
    await import('./releaseValidationOpportunityDenominator');
  const releases = [
    {
      nodeId: simpleReleaseNodeId,
      tag: simpleTag,
      tagCommitOid: simpleReleaseSha,
      publishedAt: simplePublishedAt,
    },
    {
      nodeId: predecessorReleaseNodeId,
      tag: predecessorTag,
      tagCommitOid: predecessorReleaseSha,
      publishedAt: predecessorPublishedAt,
    },
  ];
  const cohortInceptionAt = new Date(
    Date.parse(simplePublishedAt) - 60 * 60 * 1_000,
  ).toISOString();
  const cohortLifecycle = planReleaseValidationProofLifecycle({
    existing: input.dbModule.readReleaseValidationProofBundle(),
    repository: repositoryIdentity(),
    observedAt: cohortInceptionAt,
    source: 'github_graphql_stable_releases',
    releases: [],
    modelVersion: input.scoringModule.SCORE_MODEL_VERSION,
    promptVersion: input.scoringModule.PROMPT_VERSION,
    codeRevision: helperCodeRevision,
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
    developmentReleaseCount:
      RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
  });
  input.dbModule.appendReleaseValidationProof(cohortLifecycle.append);
  const lifecycle = planReleaseValidationProofLifecycle({
    existing: input.dbModule.readReleaseValidationProofBundle(),
    repository: repositoryIdentity(),
    observedAt: input.observedAt,
    source: 'github_graphql_stable_releases',
    releases: releases.map((release) => ({
      repository: repositoryIdentity(),
      nodeId: release.nodeId,
      tagCommitOid: release.tagCommitOid,
      publishedAt: release.publishedAt,
      aliases: [release.tag],
    })),
    modelVersion: input.scoringModule.SCORE_MODEL_VERSION,
    promptVersion: input.scoringModule.PROMPT_VERSION,
    codeRevision: helperCodeRevision,
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
    developmentReleaseCount:
      RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
  });
  input.dbModule.appendReleaseValidationProof(lifecycle.append);
  assert.ok(
    lifecycle.append.obligations.length > 0 &&
      lifecycle.append.splitAssignments.length > 0,
    'latest release must create prospective proof obligations and assignments',
  );
  const attempt = input.dbModule.getRefreshOperationAttempt(input.runId);
  assert.ok(attempt);
  const catalog = input.dbModule.currentActiveReleaseCatalog();
  const enrollments = releases.flatMap((release) =>
    planReleaseValidationOpportunityEnrollments({
      enrolledAt: input.observedAt,
      cohortInceptionAt: lifecycle.cohort.startsAt,
      release,
      cohort: {
        modelVersion: input.scoringModule.SCORE_MODEL_VERSION,
        promptVersion: input.scoringModule.PROMPT_VERSION,
        codeRevision: helperCodeRevision,
      },
      evidence: {
        enrollmentRunId: input.runId,
        operationAttemptContentHash: attempt.content_hash,
        catalogDigest: catalog.digest,
        catalogReleaseCount: catalog.releaseCount,
      },
    }));
  const persisted =
    input.dbModule.insertReleaseValidationOpportunityEnrollments({
      enrollments,
      lease_name: input.leaseName,
      lease_holder_id: input.holderId,
    });
  assert.ok(
    persisted.rows.some((row) => row.release_tag === simpleTag),
    'latest release must have validation opportunity enrollments',
  );
}

function persistSimpleArtifactVerification(
  dbModule: DbModule,
  runId: string,
  observedAt: string,
) {
  return persistFixtureArtifactVerification(dbModule, {
    runId,
    observedAt,
    release: simpleReleaseIdentity(),
    version: simpleVersion,
    bytes: Buffer.from('composed publication artifact bytes'),
  });
}

function persistFixtureArtifactVerification(
  dbModule: DbModule,
  input: {
    runId: string;
    observedAt: string;
    release: FixtureReleaseArtifactIdentity;
    version: string;
    bytes: Buffer;
  },
) {
  const digest = createHash('sha512').update(input.bytes).digest('base64');
  const integrity = `sha512-${digest}`;
  const tarballUrl =
    `https://registry.npmjs.org/${config.github.repo}/-/` +
    `${config.github.repo}-${input.version}.tgz`;
  const reportUrl =
    `https://github.com/${repositoryIdentity()}/blob/` +
    `${input.release.catalogTagCommitOid}/release-evidence.json`;
  const rawReportUrl =
    `https://raw.githubusercontent.com/${repositoryIdentity()}/` +
    `${input.release.catalogTagCommitOid}/release-evidence.json`;
  const artifact = buildArtifactVerificationEvidence({
    packageName: config.github.repo,
    requestedVersion: input.version,
    metadataUrl:
      `https://registry.npmjs.org/${config.github.repo}/${input.version}`,
    metadataContentDigest: '5'.repeat(64),
    registryAvailability: 'available',
    registryPackageName: config.github.repo,
    registryVersion: input.version,
    registryIntegrity: integrity,
    registryTarballUrl: tarballUrl,
    registryGitHead: input.release.catalogTagCommitOid,
    actualDigests: { sha512: digest },
    tarballByteCount: input.bytes.length,
    expectedIntegrity: integrity,
    expectedTarballUrl: tarballUrl,
    expectedReleaseSha: input.release.catalogTagCommitOid,
  });
  const evidenceReport = {
    url: reportUrl,
    rawUrl: rawReportUrl,
    fallbackUrl: null,
    fallbackKind: null,
    fallbackArtifactCount: 0,
    contentDigest: '6'.repeat(64),
    fallbackArtifactDigest: null,
    expectedReleaseTag: input.release.tag,
    expectedReleaseSha: input.release.catalogTagCommitOid,
    verified: true,
    mismatch: null,
  };
  const persisted = dbModule.persistReleaseArtifactVerification({
    runId: input.runId,
    observedAt: input.observedAt,
    release: input.release,
    releaseMetadata: {
      npmPackageUrl:
        `https://www.npmjs.com/package/${config.github.repo}/v/${input.version}`,
      releaseTarballUrl: tarballUrl,
      releaseIntegrity: integrity,
      releaseSha: input.release.catalogTagCommitOid,
      ciReportUrl: reportUrl,
      fullReleaseValidationUrl: null,
    },
    artifact,
    evidenceReport,
  });
  dbModule.updateReleaseArtifactVerification({
    tag: input.release.tag,
    registry_version: artifact.version,
    registry_integrity: artifact.integrity,
    registry_tarball_url: artifact.tarballUrl,
    ci_report_verified: evidenceReport.verified ? 1 : 0,
    ci_report_mismatch: evidenceReport.mismatch,
    release_validation_verified: 0,
    release_validation_mismatch: null,
    artifact_verified: artifact.verified ? 1 : 0,
    artifact_mismatch: artifact.mismatch,
  });
  return persisted;
}

function simpleReleaseIdentity() {
  return {
    repository: repositoryIdentity(),
    tag: simpleTag,
    releaseNodeId: simpleReleaseNodeId,
    catalogTagCommitOid: simpleReleaseSha,
    publishedAt: simplePublishedAt,
  };
}

function predecessorReleaseIdentity() {
  return {
    repository: repositoryIdentity(),
    tag: predecessorTag,
    releaseNodeId: predecessorReleaseNodeId,
    catalogTagCommitOid: predecessorReleaseSha,
    publishedAt: predecessorPublishedAt,
  };
}

function mutateSimpleReleaseArtifactFields(dbModule: DbModule): void {
  dbModule.updateReleaseDerivedStats({
    tag: simpleTag,
    breaking_count: 0,
    fixes_count: 1,
    changes_count: 0,
    highlights_count: 0,
    pr_refs_count: 0,
    beta_count: 0,
    hours_to_next_release: null,
    hours_to_next_stable: null,
    npm_package_url: 'https://mutable.invalid/package',
    release_tarball_url: 'https://mutable.invalid/tarball.tgz',
    release_integrity: 'sha512-mutable',
    release_sha: 'f'.repeat(40),
    full_release_ci_report_url: 'https://mutable.invalid/report',
    full_release_validation_url: 'https://mutable.invalid/validation',
  });
  dbModule.updateReleaseArtifactVerification({
    tag: simpleTag,
    registry_version: 'mutable',
    registry_integrity: 'sha512-mutable',
    registry_tarball_url: 'https://mutable.invalid/registry.tgz',
    ci_report_verified: 0,
    ci_report_mismatch: 'mutable',
    release_validation_verified: 0,
    release_validation_mismatch: 'mutable',
    artifact_verified: 0,
    artifact_mismatch: 'mutable',
  });
}

function ensureSimpleProbeTable(dbModule: DbModule): void {
  dbModule.db.exec(`
    CREATE TABLE IF NOT EXISTS composed_publication_probe (
      kind TEXT PRIMARY KEY,
      value TEXT NOT NULL
    )
  `);
}

function simpleProbeRows(dbModule: DbModule): string[] {
  return dbModule.db.prepare(`
    SELECT kind
    FROM composed_publication_probe
    ORDER BY kind
  `).all().map((row) => String(row.kind));
}

function requiredPersistedJson(
  value: string | null,
  field: string,
): string {
  if (typeof value !== 'string') {
    throw new Error(
      `${simpleTag} score audit must persist ${field}`,
    );
  }
  return value;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function publishedAuditLinks(
  release: Record<string, unknown>,
): PublishedAuditLinks {
  const links = release.auditLinks;
  assert.ok(isRecord(links), `${String(release.tag)} must expose auditLinks`);
  for (const key of [
    'review',
    'issues',
    'closureProofs',
    'reachability',
  ] as const) {
    assert.equal(
      typeof links[key],
      'string',
      `${String(release.tag)} auditLinks.${key} must be a string`,
    );
  }
  return links as PublishedAuditLinks;
}

function publicationBoundUrl(
  value: string,
  apiBase: string,
  snapshotId: string,
  auditDigest: string,
): URL {
  const url = new URL(value, apiBase);
  assert.equal(
    url.searchParams.get('publicationSnapshot'),
    snapshotId,
    `${url.pathname} must bind the public publication snapshot`,
  );
  assert.equal(
    url.searchParams.get('auditDigest'),
    auditDigest,
    `${url.pathname} must bind the public audit digest`,
  );
  return url;
}

function bindPublishedAuditUrl(
  requestedUrl: string,
  apiBase: string,
  links: PublishedAuditLinks,
): string {
  const requested = new URL(requestedUrl);
  const match = requested.pathname.match(
    /^\/api\/releases\/([^/]+)\/review(?:\/(issues|closure-proofs|reachability))?$/,
  );
  if (!match || decodeURIComponent(match[1]) !== simpleTag) {
    return requestedUrl;
  }
  const key = ({
    undefined: 'review',
    issues: 'issues',
    'closure-proofs': 'closureProofs',
    reachability: 'reachability',
  } as const)[
    String(match[2]) as
      'undefined' | 'issues' | 'closure-proofs' | 'reachability'
  ];
  const published = new URL(links[key], apiBase);
  for (const [name, value] of requested.searchParams) {
    if (name !== 'publicationSnapshot' && name !== 'auditDigest') {
      published.searchParams.append(name, value);
    }
  }
  return published.toString();
}

async function fetchJsonResponse(url: string | URL): Promise<{
  status: number;
  body: any;
  headers: Headers;
}> {
  const response = await fetch(url);
  const text = await response.text();
  return {
    status: response.status,
    body: text ? JSON.parse(text) : null,
    headers: response.headers,
  };
}

async function verifyPublicationApis(input: {
  runId: string;
  finalScore: number;
  sourceIdentityDigest: string;
}): Promise<{
  receiptOutcome: string;
  receiptProblems: string[];
  receiptVerified: boolean;
  semanticLinksVerified: boolean;
  publicStatus: number;
  publicSnapshotId: string;
  publicAuditDigest: string;
  publicScore: number;
  publicReleaseTags: string[];
  releaseIndexTags: string[];
  phantomReviewStatuses: Record<string, number>;
  reviewStatus: number;
  issuesReviewStatus: number;
  closureProofsReviewStatus: number;
  reachabilityReviewStatus: number;
  releaseAuditFailures: string[];
}> {
  const { api } = await import('../routes/api');
  const app = express();
  app.use('/api', api);
  const server = await listen(app);
  let reader: { close(): void } | null = null;
  try {
    const address = server.address() as AddressInfo;
    const apiBase = `http://127.0.0.1:${address.port}`;
    const publicResponse = await fetchJsonResponse(`${apiBase}/api/public`);
    let publicHealth = publicResponse.status === 200
      ? null
      : await fetchJsonResponse(`${apiBase}/api/health`);
    assert.equal(
      publicResponse.status,
      200,
      JSON.stringify({
        public: publicResponse.body,
        health: publicHealth?.body ?? null,
      }),
    );
    assert.equal(publicResponse.body.schemaVersion, 4);
    assert.equal(publicResponse.body.snapshot?.actionable, true);
    assert.equal(publicResponse.body.snapshot?.retained, false);
    assert.equal(
      publicResponse.headers.get('x-radar-snapshot-id'),
      publicResponse.body.snapshotId,
    );
    const expectedStableApiTags = [simpleTag];
    const publicReleaseTags = publicResponse.body.releases.map(
      (release: unknown) => {
        assert.ok(isRecord(release) && typeof release.tag === 'string');
        return release.tag;
      },
    );
    assert.deepEqual(
      publicReleaseTags,
      expectedStableApiTags,
      '/api/public must expose the exact stable fixture catalog',
    );
    const releaseIndexResponse = await fetchJsonResponse(
      `${apiBase}/api/releases`,
    );
    assert.equal(
      releaseIndexResponse.status,
      200,
      JSON.stringify(releaseIndexResponse.body),
    );
    const releaseIndexTags = releaseIndexResponse.body.map(
      (release: unknown) => {
        assert.ok(isRecord(release) && typeof release.tag === 'string');
        return release.tag;
      },
    );
    assert.deepEqual(
      releaseIndexTags,
      expectedStableApiTags,
      '/api/releases must expose the exact stable fixture catalog',
    );
    const phantomReviewStatuses: Record<string, number> = {};
    for (const phantomTag of incidentPhantomTags) {
      const response = await fetchJsonResponse(
        `${apiBase}/api/releases/${encodeURIComponent(phantomTag)}/review`,
      );
      phantomReviewStatuses[phantomTag] = response.status;
      assert.equal(
        response.status,
        404,
        `${phantomTag} must not resolve through the review API`,
      );
    }
    const publicRelease = publicResponse.body.releases.find(
      (release: unknown) =>
        isRecord(release) && release.tag === simpleTag,
    );
    assert.ok(publicRelease, `/api/public must include ${simpleTag}`);
    if (publicRelease.score !== input.finalScore && publicHealth == null) {
      publicHealth = await fetchJsonResponse(`${apiBase}/api/health`);
    }
    assert.equal(
      publicRelease.score,
      input.finalScore,
      JSON.stringify({
        release: publicRelease,
        health: publicHealth?.body ?? null,
      }),
    );
    assert.equal(publicRelease.staleAudit, null);
    assert.equal(publicRelease.profileEvidence?.sourceMode, 'sealed_score_replay');
    assert.equal(
      publicRelease.profileEvidence?.publicationBinding?.sourceIdentityDigest,
      input.sourceIdentityDigest,
    );
    const snapshotId = publicResponse.body.snapshotId;
    const auditDigest = publicRelease.scoreAudit?.auditDigest;
    assert.match(snapshotId, /^[0-9a-f]{64}$/);
    assert.match(auditDigest, /^[0-9a-f]{64}$/);
    const auditLinks = publishedAuditLinks(publicRelease);
    const boundLinks = {
      review: publicationBoundUrl(
        auditLinks.review,
        apiBase,
        snapshotId,
        auditDigest,
      ),
      issues: publicationBoundUrl(
        auditLinks.issues,
        apiBase,
        snapshotId,
        auditDigest,
      ),
      closureProofs: publicationBoundUrl(
        auditLinks.closureProofs,
        apiBase,
        snapshotId,
        auditDigest,
      ),
      reachability: publicationBoundUrl(
        auditLinks.reachability,
        apiBase,
        snapshotId,
        auditDigest,
      ),
    };
    const reviewResponse = await fetchJsonResponse(boundLinks.review);
    const issuesResponse = await fetchJsonResponse(boundLinks.issues);
    const closureProofsResponse = await fetchJsonResponse(
      boundLinks.closureProofs,
    );
    const reachabilityResponse = await fetchJsonResponse(
      boundLinks.reachability,
    );
    for (const [label, response] of [
      ['review', reviewResponse],
      ['issues', issuesResponse],
      ['closure-proofs', closureProofsResponse],
      ['reachability', reachabilityResponse],
    ] as const) {
      assert.equal(response.status, 200, `${label}: ${JSON.stringify(response.body)}`);
      assert.equal(response.body.snapshotId, snapshotId, `${label} snapshot`);
      assert.equal(response.headers.get('x-radar-snapshot-id'), snapshotId);
    }
    assert.equal(reviewResponse.body.local?.auditDigest, auditDigest);
    assert.equal(
      reviewResponse.body.local?.sourceProvenance?.auditDigest,
      auditDigest,
    );
    assert.deepEqual(reviewResponse.body.auditLinks, auditLinks);
    for (const response of [
      issuesResponse,
      closureProofsResponse,
      reachabilityResponse,
    ]) {
      assert.equal(response.body.auditDigest, auditDigest);
      assert.equal(response.body.auditIdentity, auditDigest);
      assert.equal(response.body.tag, simpleTag);
      assert.equal(response.body.sourceMode, 'current_db');
    }

    const receiptResponse = await fetchJsonResponse(
      `${apiBase}/api/receipts/${encodeURIComponent(input.runId)}`,
    );
    assert.equal(
      receiptResponse.status,
      200,
      JSON.stringify(receiptResponse.body),
    );
    assert.equal(receiptResponse.body.receipt.outcome, 'success');
    assert.equal(receiptResponse.body.verification.verified, true);
    assert.equal(receiptResponse.body.receipt.verification.verified, true);
    assert.equal(
      receiptResponse.body.verification.semanticLinks.verified,
      true,
    );
    assert.deepEqual(receiptResponse.body.verification.problems, []);
    assert.deepEqual(
      receiptResponse.body.receipt.verification.problems,
      [],
    );

    const readerModulePath = '../../scripts/lib/release-audit-reader.mjs';
    const invariantsModulePath =
      '../../scripts/lib/release-audit-invariants.mjs';
    const { openReleaseAuditReader } = await import(readerModulePath);
    const { verifyReleaseAudit } = await import(invariantsModulePath);
    reader = openReleaseAuditReader(databaseImportGuard.databasePath, {
      allowTestFixtureCatalog: true,
    });
    const verification = await verifyReleaseAudit({
      reader,
      apiBase,
      limit: 1,
      scoredOnly: true,
      fetchJson: async (url: string) => {
        const response = await fetchJsonResponse(
          bindPublishedAuditUrl(url, apiBase, auditLinks),
        );
        if (response.status < 200 || response.status >= 300) {
          throw Object.assign(
            new Error(
              `${url} returned ${response.status}: ` +
              JSON.stringify(response.body),
            ),
            {
              status: response.status,
              payload: response.body,
            },
          );
        }
        return response.body;
      },
    });
    assert.deepEqual(verification.failures, []);
    return {
      receiptOutcome: receiptResponse.body.receipt.outcome,
      receiptProblems: receiptResponse.body.verification.problems,
      receiptVerified: receiptResponse.body.verification.verified,
      semanticLinksVerified:
        receiptResponse.body.verification.semanticLinks.verified,
      publicStatus: publicResponse.status,
      publicSnapshotId: snapshotId,
      publicAuditDigest: auditDigest,
      publicScore: publicRelease.score,
      publicReleaseTags,
      releaseIndexTags,
      phantomReviewStatuses,
      reviewStatus: reviewResponse.status,
      issuesReviewStatus: issuesResponse.status,
      closureProofsReviewStatus: closureProofsResponse.status,
      reachabilityReviewStatus: reachabilityResponse.status,
      releaseAuditFailures: verification.failures,
    };
  } finally {
    reader?.close();
    await closeServer(server);
  }
}

async function runRecoveryScenario(
  dbModule: DbModule,
  terminalStatus: string,
): Promise<Record<string, unknown>> {
  assert.ok(
    ['receiptless', 'failure', 'abandoned', 'multiple'].includes(terminalStatus),
    `unsupported recovery status ${terminalStatus}`,
  );
  const nowMs = Date.now();
  const tag = `v-composed-recovery-${terminalStatus}`;
  const leaseName = `composed-recovery-${terminalStatus}`;
  const priorOperationRunId = `prior-${terminalStatus}`;
  const priorHistoryRunId = `refresh:${priorOperationRunId}`;
  const failedOperationRunId = `failed-${terminalStatus}`;
  const failedHistoryRunId = `refresh:${failedOperationRunId}`;
  const successorRunId = `successor-${terminalStatus}`;
  const successorHolderId = `successor-holder-${terminalStatus}`;
  const prior = await seedActionableRefreshPublication(dbModule, {
    tag,
    operationRunId: priorOperationRunId,
    historyRunId: priorHistoryRunId,
    leaseName,
    holderId: `prior-holder-${terminalStatus}`,
    nowMs: nowMs - (terminalStatus === 'multiple' ? 50_000 : 20_000),
  });
  const priorReceipt = dbModule.getRefreshCaptureReceipt(priorOperationRunId);
  assert.ok(priorReceipt);
  const priorReceiptPayload = JSON.parse(priorReceipt.payload_json);
  assert.equal(priorReceiptPayload.schemaVersion, 3);
  assert.deepEqual(priorReceiptPayload.releaseArtifactScope.scoredReleaseTags, [
    tag,
  ]);
  assert.deepEqual(
    priorReceiptPayload.releaseArtifactScope.predecessorByReleaseTag,
    { [tag]: null },
  );
  const failedTips = terminalStatus === 'multiple'
    ? [
        {
          operationRunId: `${failedOperationRunId}-a`,
          historyRunId: `${failedHistoryRunId}-a`,
          holderId: `failed-holder-${terminalStatus}-a`,
          nowMs: nowMs - 15_000,
          terminalStatus: 'failure' as const,
        },
        {
          operationRunId: `${failedOperationRunId}-b`,
          historyRunId: `${failedHistoryRunId}-b`,
          holderId: `failed-holder-${terminalStatus}-b`,
          nowMs,
          terminalStatus: 'failure' as const,
        },
      ]
    : [{
        operationRunId: failedOperationRunId,
        historyRunId: failedHistoryRunId,
        holderId: `failed-holder-${terminalStatus}`,
        nowMs,
        terminalStatus:
          terminalStatus as 'receiptless' | 'failure' | 'abandoned',
      }];
  let successorLeaseHeld = false;
  for (const failedTip of failedTips) {
    const failed = overlayUnsuccessfulRefreshScoreTip(dbModule, {
      tag,
      operationRunId: failedTip.operationRunId,
      historyRunId: failedTip.historyRunId,
      leaseName,
      failedHolderId: failedTip.holderId,
      successorHolderId,
      nowMs: failedTip.nowMs,
      terminalStatus: failedTip.terminalStatus,
    });
    successorLeaseHeld ||= failed.successorLeaseHeld;
  }
  if (!successorLeaseHeld) {
    assert.equal(dbModule.acquireRefreshLease(
      leaseName,
      successorHolderId,
      new Date(nowMs).toISOString(),
      300_000,
    ), true);
  }
  const successorStartedAt = new Date(nowMs).toISOString();
  const successor = dbModule.beginRefreshOperationAttempt({
    run_id: successorRunId,
    operation: 'refresh',
    trigger: 'test-successor',
    started_at: successorStartedAt,
    lease_name: leaseName,
    lease_holder_id: successorHolderId,
    lease_expires_at: new Date(nowMs + 300_000).toISOString(),
    code_revision: 'restorable-revision',
    effective_config: { schemaVersion: 1 },
  });
  const activeFailedTip = failedTips.at(-1)!;
  assert.deepEqual(successor.scoreRecovery, {
    cleaned: true,
    restored: true,
    releaseRows: 1,
    auditRows: 1,
    historyRunId: activeFailedTip.historyRunId,
    restoredHistoryRunId: priorHistoryRunId,
    restoredOperationRunId: priorOperationRunId,
  });
  assert.equal(
    successor.abandonedReceipts.length,
    terminalStatus === 'receiptless' ? 1 : 0,
  );
  assert.equal(dbModule.getRelease(tag)?.final_score, 8.5);
  assert.equal(dbModule.getRelease(tag)?.score_reason, 'prior actionable publication');
  assert.deepEqual({ ...dbModule.getReleaseScoreAudit(tag) }, prior.audit);
  const restoredMeta = JSON.parse(
    dbModule.getMeta('score_persistence_last_run') ?? 'null',
  );
  assert.equal(restoredMeta.historyRunId, priorHistoryRunId);
  assert.equal(restoredMeta.operationRunId, priorOperationRunId);
  assert.equal(
    restoredMeta.publicationRecovery.displacedPublicationCount,
    failedTips.length,
  );
  assert.deepEqual(
    restoredMeta.publicationRecovery.displacedPublications.map(
      (binding: Record<string, unknown>) => binding.operationRunId,
    ),
    failedTips.map((tip) => tip.operationRunId),
  );
  assert.equal(
    dbModule.getSealedReleaseScoreAuditPublication(tag).valid,
    true,
  );
  const restoredRelease = dbModule.currentActiveReleaseCatalog().latestStable;
  assert.ok(restoredRelease);
  assert.equal(restoredRelease.tag, tag);
  const restoredArtifact =
    dbModule.getCurrentReleaseArtifactVerificationObservation({
      repository: 'openclaw/openclaw',
      tag,
      releaseNodeId: restoredRelease.nodeId,
      catalogTagCommitOid: restoredRelease.tagCommitOid,
      publishedAt: restoredRelease.publishedAt,
    });
  assert.ok(restoredArtifact);
  assert.equal(restoredArtifact.runId, priorOperationRunId);
  const artifactLedger = dbModule.releaseArtifactVerificationLedgerIntegrity();
  assert.deepEqual(artifactLedger.problems, []);
  const successorFinishedAtMs = Math.max(
    Date.now(),
    Date.parse(successorStartedAt),
  );
  dbModule.appendRefreshCaptureReceipt({
    run_id: successorRunId,
    lease_name: leaseName,
    lease_holder_id: successorHolderId,
    status: 'failure',
    finished_at: new Date(successorFinishedAtMs).toISOString(),
    duration_ms: successorFinishedAtMs - Date.parse(successorStartedAt),
    payload: {
      schemaVersion: 1,
      operation: 'refresh',
      trigger: 'test-successor',
      codeRevision: 'restorable-revision',
      error: {
        message: 'test successor completed recovery verification only',
      },
    },
  });
  assert.equal(dbModule.releaseRefreshLease(leaseName, successorHolderId), true);
  return {
    terminalStatus,
    scoreRecovery: successor.scoreRecovery,
    abandonedReceiptCount: successor.abandonedReceipts.length,
    restoredScore: dbModule.getRelease(tag)?.final_score ?? null,
    restoredHistoryRunId: restoredMeta.historyRunId,
    restoredOperationRunId: restoredMeta.operationRunId,
    restoredReceiptSchemaVersion: priorReceiptPayload.schemaVersion,
    restoredArtifactRunId: restoredArtifact.runId,
    artifactLedgerProblems: artifactLedger.problems,
    displacedPublicationCount:
      restoredMeta.publicationRecovery.displacedPublicationCount,
    displacedOperationRunIds:
      restoredMeta.publicationRecovery.displacedPublications.map(
        (binding: Record<string, unknown>) => binding.operationRunId,
      ),
  };
}

async function seedActionableRefreshPublication(
  dbModule: DbModule,
  input: {
    tag: string;
    operationRunId: string;
    historyRunId: string;
    leaseName: string;
    holderId: string;
    nowMs: number;
  },
): Promise<{
  audit: Record<string, unknown>;
}> {
  const { canonicalJson } = await import('./operationReceipts');
  const {
    ADVISORY_SNAPSHOT_V2_META_KEY,
    buildCompoundAdvisorySnapshot,
  } = await import('./advisorySnapshot');
  const { config } = await import('../config');
  const { planReleaseValidationOpportunityEnrollments } =
    await import('./releaseValidationOpportunityDenominator');
  const startedAt = new Date(input.nowMs - 60_000).toISOString();
  const enrolledAt = new Date(input.nowMs - 45_000).toISOString();
  const scoredAt = new Date(input.nowMs - 20_000).toISOString();
  const publishedAt = new Date(
    Date.parse(scoredAt) - 4 * 60 * 60 * 1000,
  ).toISOString();
  const finishedAt = new Date(input.nowMs - 10_000).toISOString();
  const codeRevision = 'restorable-revision';
  const operationAttempt = dbModule.insertRefreshOperationAttempt({
    run_id: input.operationRunId,
    operation: 'refresh',
    trigger: 'test-actionable',
    started_at: startedAt,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    lease_expires_at: new Date(input.nowMs + 300_000).toISOString(),
    code_revision: codeRevision,
    effective_config: { schemaVersion: 1 },
  }).row;
  assert.equal(dbModule.acquireRefreshLease(
    input.leaseName,
    input.holderId,
    new Date(input.nowMs - 50_000).toISOString(),
    300_000,
  ), true);
  seedRecoveryRelease(dbModule, input.tag, publishedAt);
  const catalogAttestation = forecastCatalogAttestation(
    dbModule,
    input.tag,
    publishedAt,
    new Date(input.nowMs - 30_000).toISOString(),
  );
  const advisoryCapturedAt = new Date(input.nowMs - 30_000).toISOString();
  const nativeJsonHash = (value: unknown) =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const advisoryTargetPackage = 'openclaw' as const;
  const emptyIdentityDigest = nativeJsonHash([]);
  const graphqlObservation: import('./github').GhSecurityVulnerabilityCatalogObservation = {
    source: 'graphql-security-vulnerabilities' as const,
    retrieval: {
      startedAt: advisoryCapturedAt,
      completedAt: advisoryCapturedAt,
    },
    ecosystem: 'npm',
    packageName: advisoryTargetPackage,
    exhausted: true,
    stabilized: true,
    totalCount: 0,
    nodeCount: 0,
    uniqueRangeCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: nativeJsonHash([0, []]),
    identityDigest: emptyIdentityDigest,
    ranges: [],
    rangeIdentities: [],
  };
  const repositoryObservation: import('./github').GhRepositoryAdvisoryCatalogObservation = {
    source: 'repository-security-advisories-rest' as const,
    retrieval: {
      startedAt: advisoryCapturedAt,
      completedAt: advisoryCapturedAt,
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
    digest: repositoryAdvisoryCatalogContentDigest([]),
    identityDigest: nativeJsonHash([0, []]),
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
  const advisoryMetadata = dbModule.persistCompoundAdvisorySnapshot(
    buildCompoundAdvisorySnapshot({
      capturedAt: advisoryCapturedAt,
      repository: {
        owner: config.github.owner,
        name: config.github.repo,
        url: `https://github.com/${config.github.owner}/${config.github.repo}`,
      },
      target: {
        ecosystem: 'npm',
        packageName: advisoryTargetPackage,
      },
      sources: {
        graphql: graphqlObservation,
        repositoryRest: repositoryObservation,
      },
      reconciliation: {
        target: {
          ecosystem: 'npm',
          packageName: advisoryTargetPackage,
        },
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
    }),
  ).metadata;
  const issueCrawlMetadata = {
    schemaVersion: 2,
    startedAt,
    finishedAt: new Date(input.nowMs - 25_000).toISOString(),
    stopReason: 'exhausted',
    scorePersisted: true,
    scorePersistedAt: scoredAt,
  };
  dbModule.setMeta(
    'issue_crawl_last_run',
    JSON.stringify(issueCrawlMetadata),
  );
  const releaseIdentity = {
    repository: 'openclaw/openclaw',
    tag: input.tag,
    releaseNodeId: catalogAttestation.latestStable.nodeId,
    catalogTagCommitOid: catalogAttestation.latestStable.tagCommitOid,
    publishedAt,
  };
  persistFixtureArtifactVerification(dbModule, {
    runId: input.operationRunId,
    observedAt: new Date(input.nowMs - 24_000).toISOString(),
    release: releaseIdentity,
    version: input.tag.replace(/^v/, ''),
    bytes: Buffer.from(
      `composed recovery artifact bytes:${input.operationRunId}`,
    ),
  });
  const sourceIdentity = dbModule.scoreSourceIdentity({
    artifactObservationRunId: input.operationRunId,
  });
  const authorityRun = insertEmptyScoreAuthorityRun(
    dbModule,
    `score-authority:${input.historyRunId}`,
    sourceIdentity,
    scoredAt,
    input.operationRunId,
  );
  const recommendationDecision = {
    schemaVersion: 1,
    policyCode: 'highest_confidence_with_recency_tolerance',
    threshold: 7,
    recencyTolerance: 0.5,
    selectedTag: input.tag,
    selectedScore: 8.5,
    highestScoringTag: input.tag,
    highestScore: 8.5,
    releaseTag: input.tag,
    releaseScore: 8.5,
    qualifies: true,
    selected: true,
    recencyRank: 1,
    scoreRank: 1,
    scoreDeltaToHighest: 0,
    decisionCode: 'highest_confidence',
    summary: `${input.tag} is the highest-confidence qualifying release.`,
  };
  const audit = {
    release_tag: input.tag,
    scored_at: scoredAt,
    score_model_version: 'model-restorable',
    prompt_version: 1,
    final_score: 8.5,
    status: 'eligible',
    band: 'solid',
    recommended: 1,
    input_json: '{"schemaVersion":1}',
    components_json: JSON.stringify({
      schemaVersion: 1,
      reason: 'prior actionable publication',
      recommendationDecision,
    }),
    issue_evidence_json: '{"schemaVersion":1}',
    gate_evidence_json: '{"schemaVersion":1}',
    source_identity_json: JSON.stringify(sourceIdentity),
    authority_run_id: authorityRun.authorityRunId,
  };
  dbModule.updateReleaseScore({
    tag: input.tag,
    final_score: 8.5,
    negative_issues: 2,
    positive_issues: 5,
    state: 'eligible',
    recommended: 1,
    score_reason: 'prior actionable publication',
    broken_surfaces: '[{"label":"CLI","count":2}]',
    closed_serious_fixed: 3,
    opened_serious_during_reign: 1,
    scored_at: scoredAt,
  });
  dbModule.upsertReleaseScoreAudit(audit);
  dbModule.insertReleaseScoreAuditHistory(input.historyRunId, scoredAt, audit);
  const seal = dbModule.sealReleaseScoreAuditHistoryRun(
    input.historyRunId,
    scoredAt,
  );
  const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
    historyRunId: input.historyRunId,
    authorityRunId: authorityRun.authorityRunId,
    sealedAt: scoredAt,
  });
  const scoreCommit = {
    schemaVersion: 4,
    historyRunId: input.historyRunId,
    historyRunContentHash: seal.row.content_hash,
    authorityRunId: authorityRun.authorityRunId,
    authorityRunContentHash: authorityRun.contentHash,
    historyV2SealContentHash: historyV2Seal.row.contentHash,
    historyRecordedAt: scoredAt,
    commitNotBefore: scoredAt,
    commitNotAfter: scoredAt,
    commitNotBeforeMs: Date.parse(scoredAt),
    commitNotAfterMs: Date.parse(scoredAt),
  };
  const activeCatalog = dbModule.currentActiveReleaseCatalog();
  const enrollment = dbModule.insertReleaseValidationOpportunityEnrollments({
    enrollments: planReleaseValidationOpportunityEnrollments({
      enrolledAt,
      release: {
        nodeId: catalogAttestation.latestStable.nodeId,
        tag: input.tag,
        tagCommitOid: catalogAttestation.latestStable.tagCommitOid,
        publishedAt,
      },
      cohort: {
        modelVersion: audit.score_model_version,
        promptVersion: audit.prompt_version,
        codeRevision,
      },
      evidence: {
        enrollmentRunId: input.operationRunId,
        operationAttemptContentHash: operationAttempt.content_hash,
        catalogDigest: activeCatalog.digest,
        catalogReleaseCount: activeCatalog.releaseCount,
      },
    }),
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
  });
  const forecastEnrollment = enrollment.rows.find(
    (row) => row.opportunity_code === 'first_verified_after_3h',
  );
  assert.ok(forecastEnrollment);
  const scoreMeta = {
    schemaVersion: 2,
    source: 'refresh',
    scope: input.tag,
    persistedAt: scoredAt,
    operationRunId: input.operationRunId,
    operationReceiptRequired: true,
    codeRevision,
    catalogAttestation,
    scoreModelVersion: audit.score_model_version,
    promptVersion: audit.prompt_version,
    scoredReleaseCount: 1,
    recommendedTag: input.tag,
    recommendationPolicyCode: 'highest_confidence_with_recency_tolerance',
    releaseTags: [input.tag],
    predecessorByReleaseTag: {
      [input.tag]: null,
    },
    minScoredAt: scoredAt,
    maxScoredAt: scoredAt,
    issueCrawlStartedAt: issueCrawlMetadata.startedAt,
    issueCrawlFinishedAt: issueCrawlMetadata.finishedAt,
    issueCrawlStopReason: issueCrawlMetadata.stopReason,
    issueCrawlScorePersistedAt: issueCrawlMetadata.scorePersistedAt,
    issueCrawlMetadataDigest: createHash('sha256')
      .update(canonicalJson(issueCrawlMetadata))
      .digest('hex'),
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    sourceIdentityRowCount: sourceIdentity.rowCount,
    sourceIdentitySourceCount: sourceIdentity.sourceCount,
    historyRunId: input.historyRunId,
    historyRunContentHash: seal.row.content_hash,
    authorityRunId: authorityRun.authorityRunId,
    authorityRunContentHash: authorityRun.contentHash,
    historyV2SealContentHash: historyV2Seal.row.contentHash,
    commitTiming: scoreCommit,
    forecastPlan: {
      schemaVersion: 1,
      preflightAt: scoredAt,
      latestReleaseTag: input.tag,
      latestReleasePublishedAt: publishedAt,
      selectedTag: input.tag,
      scoreModelVersion: audit.score_model_version,
      promptVersion: audit.prompt_version,
      policyCode: 'highest_confidence_with_recency_tolerance',
      codeRevision,
      slots: enrollment.rows.map((row) => ({
        opportunityCode: row.opportunity_code,
        existingDecisionId: null,
        existingContentHash: null,
      })),
    },
  };
  dbModule.setMeta('score_persistence_last_run', JSON.stringify(scoreMeta));
  dbModule.setMeta('last_scored_at', scoredAt);
  const forecast = dbModule.insertReleaseValidationForecast({
    opportunity_code: 'first_verified_after_3h',
    recorded_at: scoredAt,
    latest_release_tag: input.tag,
    latest_release_published_at: publishedAt,
    selected_tag: input.tag,
    audit_history_run_id: input.historyRunId,
    score_model_version: audit.score_model_version,
    prompt_version: audit.prompt_version,
    policy_code: recommendationDecision.policyCode,
    candidate_scores_json: JSON.stringify([{
      releaseTag: input.tag,
      releasePublishedAt: publishedAt,
      scoreSnapshot: {
        scoredAt: audit.scored_at,
        finalScore: audit.final_score,
        status: audit.status,
        band: audit.band,
        recommended: true,
      },
      recommendationDecision,
      auditSnapshot: {
        run_id: input.historyRunId,
        recorded_at: scoredAt,
        ...audit,
      },
    }]),
    decision_json: JSON.stringify(forecastDecisionV4({
      opportunityCode: 'first_verified_after_3h',
      recordedAt: scoredAt,
      latestReleaseTag: input.tag,
      latestReleasePublishedAt: publishedAt,
      selectedTag: input.tag,
      recommendationDecision,
      historyRunId: input.historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      historyRecordedAt: scoredAt,
      catalogAttestation,
    })),
    source_identity_json: JSON.stringify(sourceIdentity),
    code_revision: codeRevision,
  }).row;
  appendPublicationStage(dbModule, input, 'score.persist', 'started',
    new Date(input.nowMs - 40_000).toISOString(), null);
  appendPublicationStage(dbModule, input, 'score.persist', 'completed', scoredAt,
    20_000, { scoredReleases: 1 }, {
      historyRunId: input.historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      commitNotBefore: scoredAt,
      commitNotAfter: scoredAt,
    });
  appendPublicationStage(dbModule, input, 'forecast.capture', 'started',
    new Date(input.nowMs - 15_000).toISOString(), null);
  appendPublicationStage(
    dbModule,
    input,
    'forecast.capture',
    'completed',
    finishedAt,
    5_000,
    { validationForecasts: 1 },
    { eligibilityOutcome: 'eligible_and_captured' },
  );
  dbModule.appendRefreshCaptureReceipt({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    status: 'success',
    finished_at: finishedAt,
    duration_ms: 50_000,
    payload: {
      schemaVersion: 3,
      operation: 'refresh',
      trigger: 'test-actionable',
      codeRevision,
      scoreHistory: {
        runId: input.historyRunId,
        contentHash: seal.row.content_hash,
        persistedAt: scoredAt,
      },
      scoreAuthority: {
        runId: authorityRun.authorityRunId,
        contentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
      },
      scoreCommit,
      scoreMetadata: scoreMeta,
      scoreRows: [{
        tag: input.tag,
        finalScore: 8.5,
        negativeIssues: 2,
        positiveIssues: 5,
        state: 'eligible',
        recommended: true,
        scoreReason: 'prior actionable publication',
        brokenSurfaces: '[{"label":"CLI","count":2}]',
        closedSeriousFixed: 3,
        openedSeriousDuringReign: 1,
        scoredAt,
      }],
      releaseTags: [input.tag],
      releaseArtifacts: dbModule.releaseArtifactPublicationForRun(
        input.operationRunId,
      ),
      releaseArtifactScope: buildReleaseArtifactPublicationScope({
        scoredReleaseTags: [input.tag],
        predecessorByReleaseTag: {
          [input.tag]: null,
        },
      }),
      recommendation: {
        selectedTag: input.tag,
        decisions: [{
          releaseTag: input.tag,
          decision: recommendationDecision,
        }],
      },
      issueCrawl: {
        metaKey: 'issue_crawl_last_run',
        metadataDigest: scoreMeta.issueCrawlMetadataDigest,
        metadata: issueCrawlMetadata,
      },
      releaseCatalog: {
        digest: catalogAttestation.finalRemoteCatalog.digest,
        nodeCount: catalogAttestation.finalRemoteCatalog.nodeCount,
        totalCount: catalogAttestation.finalRemoteCatalog.totalCount,
        sweepCount: catalogAttestation.finalRemoteCatalog.sweepCount,
        attestation: catalogAttestation,
      },
      advisoryCatalog: {
        metaKey: ADVISORY_SNAPSHOT_V2_META_KEY,
        metadataDigest: createHash('sha256')
          .update(canonicalJson(advisoryMetadata))
          .digest('hex'),
        metadata: advisoryMetadata,
        snapshotId: advisoryMetadata.snapshotId,
        sourceHash: advisoryMetadata.sourceHash,
        catalogHash: advisoryMetadata.catalogHash,
        scoreHash: advisoryMetadata.scoreHash,
        contentHash: advisoryMetadata.contentHash,
        contentDigest: advisoryMetadata.scoreContentDigest,
        advisoryCount: advisoryMetadata.scoreRowCount,
        rowCount: advisoryMetadata.scoreRowCount,
        catalogRowCount: advisoryMetadata.rowCount,
        scoreRowCount: advisoryMetadata.scoreRowCount,
      },
      forecast: {
        eligibilityOutcome: 'eligible_and_captured',
        decisionIds: [forecast.decision_id],
        newDecisionIds: [forecast.decision_id],
        existingDecisionIds: [],
        captures: [{
          opportunityCode: forecast.opportunity_code,
          status: 'inserted',
          decisionId: forecast.decision_id,
          codeRevision,
          opportunityId: forecastEnrollment.opportunity_id,
          enrollmentContentHash: forecastEnrollment.content_hash,
        }],
      },
    },
  });
  assert.equal(
    dbModule.releaseRefreshLease(input.leaseName, input.holderId),
    true,
  );
  const publication = dbModule.getSealedReleaseScoreAuditPublication(input.tag);
  assert.equal(publication.valid, true, publication.problems.join('; '));
  return { audit };
}

function appendPublicationStage(
  dbModule: DbModule,
  input: {
    operationRunId: string;
    leaseName: string;
    holderId: string;
  },
  stage: string,
  status: 'started' | 'completed',
  occurredAt: string,
  durationMs: number | null,
  counts: Record<string, unknown> | null = null,
  details: Record<string, unknown> | null = null,
): void {
  dbModule.appendRefreshOperationStageEvent({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    stage,
    status,
    occurred_at: occurredAt,
    duration_ms: durationMs,
    counts,
    details,
  });
}

function overlayUnsuccessfulRefreshScoreTip(
  dbModule: DbModule,
  input: {
    tag: string;
    operationRunId: string;
    historyRunId: string;
    leaseName: string;
    failedHolderId: string;
    successorHolderId: string;
    nowMs: number;
    terminalStatus: 'receiptless' | 'failure' | 'abandoned';
  },
): { successorLeaseHeld: boolean } {
  const startedAt = new Date(input.nowMs - 8_000).toISOString();
  const artifactObservedAt = new Date(input.nowMs - 7_000).toISOString();
  const scoredAt = new Date(input.nowMs - 5_000).toISOString();
  dbModule.insertRefreshOperationAttempt({
    run_id: input.operationRunId,
    operation: 'refresh',
    trigger: `test-${input.terminalStatus}`,
    started_at: startedAt,
    lease_name: input.leaseName,
    lease_holder_id: input.failedHolderId,
    lease_expires_at: new Date(input.nowMs - 1_000).toISOString(),
    code_revision: 'restorable-revision',
    effective_config: { schemaVersion: 1 },
  });
  assert.equal(dbModule.acquireRefreshLease(
    input.leaseName,
    input.failedHolderId,
    new Date().toISOString(),
    300_000,
  ), true);
  const activeRelease = dbModule.currentActiveReleaseCatalog().latestStable;
  assert.ok(activeRelease);
  assert.equal(activeRelease.tag, input.tag);
  persistFixtureArtifactVerification(dbModule, {
    runId: input.operationRunId,
    observedAt: artifactObservedAt,
    release: {
      repository: 'openclaw/openclaw',
      tag: activeRelease.tag,
      releaseNodeId: activeRelease.nodeId,
      catalogTagCommitOid: activeRelease.tagCommitOid,
      publishedAt: activeRelease.publishedAt,
    },
    version: input.tag.replace(/^v/, ''),
    bytes: Buffer.from(
      `composed failed publication artifact bytes:${input.operationRunId}`,
    ),
  });
  const sourceIdentity = dbModule.scoreSourceIdentity({
    artifactObservationRunId: input.operationRunId,
  });
  const authorityRun = insertEmptyScoreAuthorityRun(
    dbModule,
    `score-authority:${input.historyRunId}`,
    sourceIdentity,
    scoredAt,
    input.operationRunId,
  );
  const audit = {
    release_tag: input.tag,
    scored_at: scoredAt,
    score_model_version: 'model-failed-tip',
    prompt_version: 1,
    final_score: 2,
    status: 'eligible',
    band: 'weak',
    recommended: 0,
    input_json: '{"schemaVersion":1}',
    components_json: '{"schemaVersion":1,"reason":"failed tip"}',
    issue_evidence_json: '{"schemaVersion":1}',
    gate_evidence_json: '{"schemaVersion":1}',
    source_identity_json: JSON.stringify(sourceIdentity),
    authority_run_id: authorityRun.authorityRunId,
  };
  dbModule.updateReleaseScore({
    tag: input.tag,
    final_score: 2,
    negative_issues: 9,
    positive_issues: 0,
    state: 'eligible',
    recommended: 0,
    score_reason: 'failed tip',
    broken_surfaces: '[]',
    closed_serious_fixed: 0,
    opened_serious_during_reign: 9,
    scored_at: scoredAt,
  });
  dbModule.upsertReleaseScoreAudit(audit);
  dbModule.insertReleaseScoreAuditHistory(input.historyRunId, scoredAt, audit);
  const seal = dbModule.sealReleaseScoreAuditHistoryRun(
    input.historyRunId,
    scoredAt,
  );
  const historyV2Seal = dbModule.sealReleaseScoreAuditHistoryV2({
    historyRunId: input.historyRunId,
    authorityRunId: authorityRun.authorityRunId,
    sealedAt: scoredAt,
  });
  dbModule.setMeta('score_persistence_last_run', JSON.stringify({
    schemaVersion: 2,
    source: 'refresh',
    operationReceiptRequired: true,
    operationRunId: input.operationRunId,
    historyRunId: input.historyRunId,
    historyRunContentHash: seal.row.content_hash,
    authorityRunId: authorityRun.authorityRunId,
    authorityRunContentHash: authorityRun.contentHash,
    historyV2SealContentHash: historyV2Seal.row.contentHash,
    maxScoredAt: scoredAt,
  }));
  dbModule.setMeta('last_scored_at', scoredAt);
  dbModule.setMeta('issue_crawl_last_run', JSON.stringify({
    schemaVersion: 2,
    scorePersisted: true,
    scorePersistedAt: scoredAt,
    failedTip: input.operationRunId,
  }));
  let successorLeaseHeld = false;
  if (input.terminalStatus === 'failure') {
    dbModule.appendRefreshCaptureReceipt({
      run_id: input.operationRunId,
      lease_name: input.leaseName,
      lease_holder_id: input.failedHolderId,
      status: 'failure',
      finished_at: new Date(input.nowMs - 2_000).toISOString(),
      duration_ms: 6_000,
      payload: {
        schemaVersion: 1,
        operation: 'refresh',
        trigger: 'test-failure',
        codeRevision: 'restorable-revision',
        error: { message: 'injected failed publication' },
      },
    });
    assert.equal(
      dbModule.releaseRefreshLease(input.leaseName, input.failedHolderId),
      true,
    );
  }
  if (input.terminalStatus === 'receiptless') {
    assert.equal(
      dbModule.releaseRefreshLease(input.leaseName, input.failedHolderId),
      true,
    );
  }
  if (input.terminalStatus === 'abandoned') {
    assert.equal(
      dbModule.releaseRefreshLease(input.leaseName, input.failedHolderId),
      true,
    );
    assert.equal(dbModule.acquireRefreshLease(
      input.leaseName,
      input.successorHolderId,
      new Date(input.nowMs).toISOString(),
      300_000,
    ), true);
    successorLeaseHeld = true;
    dbModule.appendRefreshCaptureReceipt({
      run_id: input.operationRunId,
      lease_name: input.leaseName,
      lease_holder_id: input.successorHolderId,
      status: 'abandoned',
      finished_at: new Date(input.nowMs).toISOString(),
      duration_ms: 8_000,
      payload: {
        schemaVersion: 1,
        reason: 'lease_expired',
        successorRunId: `successor-${input.terminalStatus}`,
        lease: {
          name: input.leaseName,
          holderId: input.failedHolderId,
          expiredAt: new Date(input.nowMs - 1_000).toISOString(),
        },
      },
    });
  }
  return { successorLeaseHeld };
}

function seedRecoveryRelease(
  dbModule: DbModule,
  tag: string,
  publishedAt: string,
): void {
  dbModule.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease: false,
    body: '',
  });
  dbModule.upsertReleaseCommit({
    tag,
    tag_commit_oid: '1'.repeat(40),
    committed_at: publishedAt,
  });
}

function forecastCatalogAttestation(
  dbModule: DbModule,
  tag: string,
  publishedAt: string,
  observedAt: string,
): any {
  dbModule.replaceActiveReleaseCatalog([{
    node_id: `R_${tag}`,
    catalog_tag_commit_oid: '1'.repeat(40),
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease: false,
    body: '',
  }]);
  const catalog = dbModule.currentActiveReleaseCatalog();
  const remote = {
    digest: 'f'.repeat(64),
    totalCount: catalog.releaseCount,
    nodeCount: catalog.releaseCount,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    exhausted: true,
    stabilized: true,
    sourceOrder: 'CREATED_AT_DESC',
  };
  return {
    schemaVersion: 4,
    initialRemoteCatalog: remote,
    finalRemoteCatalog: { ...remote },
    finalObservedAt: observedAt,
    projectedActiveCatalog: {
      digest: catalog.digest,
      releaseCount: catalog.releaseCount,
    },
    localActiveCatalog: {
      digest: catalog.digest,
      releaseCount: catalog.releaseCount,
    },
    latestStable: catalog.latestStable,
    scoreBuiltAt: observedAt,
  };
}

function forecastDecisionV4(input: {
  opportunityCode: 'first_verified_after_3h';
  recordedAt: string;
  latestReleaseTag: string;
  latestReleasePublishedAt: string;
  selectedTag: string;
  recommendationDecision: Record<string, unknown>;
  historyRunId: string;
  historyRunContentHash: string;
  authorityRunId: string;
  authorityRunContentHash: string;
  historyV2SealContentHash: string;
  historyRecordedAt: string;
  catalogAttestation: Record<string, unknown>;
}): Record<string, unknown> {
  const minAgeHours = 3;
  const maxAgeHours = 6;
  const publishedAtMs = Date.parse(input.latestReleasePublishedAt);
  const recordedAtMs = Date.parse(input.recordedAt);
  return {
    schemaVersion: 4,
    opportunityCode: input.opportunityCode,
    recordedAt: input.recordedAt,
    latestReleaseTag: input.latestReleaseTag,
    latestReleasePublishedAt: input.latestReleasePublishedAt,
    latestReleaseAgeHours: (recordedAtMs - publishedAtMs) / 3_600_000,
    opportunityWindow: {
      minAgeHours,
      maxAgeHours,
      windowStartAt: new Date(
        publishedAtMs + minAgeHours * 3_600_000,
      ).toISOString(),
      windowEndAt: new Date(
        publishedAtMs + maxAgeHours * 3_600_000,
      ).toISOString(),
      windowStartMs: publishedAtMs + minAgeHours * 3_600_000,
      windowEndMs: publishedAtMs + maxAgeHours * 3_600_000,
      observedAtMs: recordedAtMs,
      observedAgeHours: (recordedAtMs - publishedAtMs) / 3_600_000,
      valid: true,
    },
    selectedTag: input.selectedTag,
    recommendationDecision: input.recommendationDecision,
    scoreCommit: {
      schemaVersion: 4,
      historyRunId: input.historyRunId,
      historyRunContentHash: input.historyRunContentHash,
      authorityRunId: input.authorityRunId,
      authorityRunContentHash: input.authorityRunContentHash,
      historyV2SealContentHash: input.historyV2SealContentHash,
      historyRecordedAt: input.historyRecordedAt,
      commitNotBefore: input.recordedAt,
      commitNotAfter: input.recordedAt,
      commitNotBeforeMs: recordedAtMs,
      commitNotAfterMs: recordedAtMs,
    },
    catalogAttestation: input.catalogAttestation,
  };
}

function insertEmptyScoreAuthorityRun(
  dbModule: DbModule,
  authorityRunId: string,
  sourceIdentity: {
    schemaVersion: number;
    digest: string;
  },
  recordedAt: string,
  artifactObservationRunId?: string,
) {
  const previousContentHash =
    dbModule.listScoreAuthorityResolutionRuns().at(-1)?.contentHash ?? null;
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId,
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    recordedAt,
    previousContentHash,
    rows: [],
  });
  dbModule.insertScoreAuthorityResolutionRun(
    authorityRun,
    artifactObservationRunId == null
      ? {}
      : {
          sourceIdentityOptions: {
            artifactObservationRunId,
          },
        },
  );
  return authorityRun;
}

async function seedClassifierAttempts(
  dbModule: DbModule,
): Promise<Record<string, unknown>> {
  const {
    appendClassifierAttempt,
    captureClassifierError,
    createClassifierAttemptRun,
    createClassifierAttemptTerminalReceipt,
  } = await import('./classifierAttemptLedger');
  const baseRequestHash = hash('composed-classifier-request');
  const classifierIdentityHash = hash('composed-classifier-identity');
  const statuses = ['receiptless', 'terminal_failure', 'abandoned'] as const;
  for (const [index, status] of statuses.entries()) {
    const run = createClassifierAttemptRun({
      runId: `composed-classifier-${status}`,
      issueNumber: 88_000 + index,
      startedAt: classifierTime(index * 10),
      maxAttempts: 3,
      classifierIdentityHash,
      requestHash: hash(`${baseRequestHash}:${status}`),
    });
    const error = captureClassifierError(
      new Error(`${status} classifier transport failure`),
    );
    const attempt = appendClassifierAttempt(run, [], {
      attemptId: `${run.runId}:attempt:1`,
      status: 'transport_failure',
      startedAt: classifierTime(index * 10 + 1),
      finishedAt: classifierTime(index * 10 + 2),
      rawResponse: null,
      error,
      retry: status === 'terminal_failure'
        ? {
          decision: 'stop',
          retryable: false,
          delayMs: null,
          reason: 'non_retryable_transport_failure',
        }
        : {
          decision: 'retry',
          retryable: true,
          delayMs: 100,
          reason: 'retryable_transport_failure',
        },
      semanticDiagnostics: [],
      provenance: {
        requestHash: run.requestHash,
        responseId: null,
        responseModel: null,
        responseServiceTier: null,
      },
    });
    dbModule.recordClassifierAttemptRun(run);
    dbModule.recordClassifierAttempt(attempt);
    if (status !== 'receiptless') {
      const receipt = createClassifierAttemptTerminalReceipt(
        run,
        [attempt],
        {
          receiptId: `${run.runId}:receipt`,
          status,
          finishedAt: classifierTime(index * 10 + 3),
          error,
        },
      );
      dbModule.recordClassifierAttemptTerminalReceipt(receipt);
    }
  }
  return verifyClassifierAttempts(dbModule);
}

function verifyClassifierAttempts(
  dbModule: DbModule,
): Record<string, unknown> {
  const runs = dbModule.listClassifierAttemptRuns();
  const attempts = dbModule.listClassifierAttempts();
  const receipts = dbModule.listClassifierAttemptTerminalReceipts();
  const receiptlessRun = dbModule.getClassifierAttemptLedger(
    'composed-classifier-receiptless',
  );
  const failedLedger = dbModule.getClassifierAttemptLedger(
    'composed-classifier-terminal_failure',
  );
  const abandonedLedger = dbModule.getClassifierAttemptLedger(
    'composed-classifier-abandoned',
  );
  const classificationCount = Number(
    (dbModule.db.prepare(`
      SELECT COUNT(*) AS count
      FROM classifications
    `).get() as { count: number }).count,
  );
  const publicationCount =
    dbModule.listClassifierClassificationPublications().length;
  assert.equal(runs.length, 3);
  assert.equal(attempts.length, 3);
  assert.equal(receipts.length, 2);
  assert.equal(receiptlessRun, null);
  assert.equal(failedLedger?.receipt.status, 'terminal_failure');
  assert.equal(abandonedLedger?.receipt.status, 'abandoned');
  assert.equal(classificationCount, 0);
  assert.equal(publicationCount, 0);
  return {
    runCount: runs.length,
    attemptCount: attempts.length,
    receiptCount: receipts.length,
    terminalStatuses: receipts.map((receipt) => receipt.status).sort(),
    classificationCount,
    publicationCount,
  };
}

async function runApiEpochScenario(): Promise<void> {
  assert.equal(config.comparison.apiEnabled, true);
  const scoreReadBarrierPath =
    `${process.env.TMPDIR}/score-read-worker.barrier`;
  writeFileSync(scoreReadBarrierPath, '');
  process.env.RADAR_TEST_SCORE_READ_WORKER_BARRIER =
    scoreReadBarrierPath;
  databaseImportGuard.assertReady();
  const dbModule = await import('./db');
  const refreshModule = await import('./refresh');
  const publication = await executeSimplePublication(dbModule, refreshModule, {
    holderId: 'api-epoch-holder',
    trigger: 'api-epoch-publication',
  });
  assert.equal(
    dbModule.releaseRefreshLease(
      publication.leaseName,
      publication.holderId,
    ),
    true,
  );
  const apiModule = await import('../routes/api');
  const app = express();
  app.use('/api', apiModule.api);
  const server = await listen(app);
  try {
    apiModule.resetScoreReadWorkerLifecycleForTests();
    const address = server.address() as AddressInfo;
    const apiBase = `http://127.0.0.1:${address.port}`;
    const reviewPromise = fetchJson(
      `${apiBase}/api/releases/${encodeURIComponent(simpleTag)}/review`,
    );
    await waitFor(
      () => apiModule.scoreReadWorkerLifecycleSnapshot().active === 1,
      'score-read worker to become active',
    );
    dbModule.db.prepare(`
      UPDATE issues
      SET title=?
      WHERE number=?
    `).run(
      `${simpleTag} score-relevant issue evidence epoch-change`,
      simpleIssueNumber,
    );
    const comparisonPromise = fetchJson(`${apiBase}/api/comparison`);
    await waitFor(
      () => apiModule.scoreReadWorkerLifecycleSnapshot().canceled >= 1,
      'stale score-read worker cancellation',
    );
    rmSync(scoreReadBarrierPath, { force: true });
    const [review, comparison] = await Promise.all([
      reviewPromise,
      comparisonPromise,
    ]);
    assert.equal(
      review.status,
      200,
      JSON.stringify({
        body: review.body,
        lifecycle: apiModule.scoreReadWorkerLifecycleSnapshot(),
      }),
    );
    assert.equal(
      comparison.status,
      200,
      JSON.stringify({
        body: comparison.body,
        lifecycle: apiModule.scoreReadWorkerLifecycleSnapshot(),
      }),
    );
    assert.equal(review.body.local.score, null);
    assert.equal(review.body.local.status, 'stale');
    assert.ok(
      review.body.local.staleAudit.causes.includes('evidence_source_changed'),
    );
    const local = comparison.body.releases.find(
      (release: any) => release.tag === simpleTag,
    )?.local;
    assert.ok(local);
    assert.equal(local.score, null);
    assert.equal(local.status, 'stale');
    await waitFor(
      () => apiModule.scoreReadWorkerLifecycleSnapshot().active === 0,
      'score-read workers to terminate',
    );
    const lifecycle = apiModule.scoreReadWorkerLifecycleSnapshot();
    assert.ok(lifecycle.spawned >= 3);
    assert.ok(lifecycle.canceled >= 1);
    assert.equal(lifecycle.terminated, lifecycle.spawned);
    assertNoIncidentPhantomReleaseRows(dbModule);
    emitResult({
      scenario,
      reviewStatus: review.status,
      comparisonStatus: comparison.status,
      reviewLocalStatus: review.body.local.status,
      comparisonLocalStatus: local.status,
      lifecycle,
    });
  } finally {
    delete process.env.RADAR_TEST_SCORE_READ_WORKER_BARRIER;
    rmSync(scoreReadBarrierPath, { force: true });
    await closeServer(server);
    dbModule.db.close();
  }
}

async function runCrashWorker(
  dbModule: DbModule,
  refreshModule: RefreshModule,
  crashPhase: string,
): Promise<void> {
  assert.ok(
    [
      'after-attempt',
      'score.persist',
      'forecast.capture',
      'success.receipt',
      'after-commit',
    ].includes(crashPhase),
    `unsupported crash phase ${crashPhase}`,
  );
  await executeSimplePublication(dbModule, refreshModule, {
    holderId: `crash-${crashPhase}`,
    trigger: `crash-${crashPhase}`,
    leaseTtlMs: crashWorkerLeaseTtlMs,
    crashPhase,
  });
  throw new Error(`crash worker escaped phase ${crashPhase}`);
}

function runCrashRecovery(
  dbModule: DbModule,
  crashPhase: string,
): Record<string, unknown> {
  const marker = JSON.parse(
    dbModule.getMeta('composed_publication_attempt') ?? 'null',
  ) as {
    runId: string;
    leaseName: string;
    holderId: string;
  } | null;
  assert.ok(marker);
  const successorStartedAtMs = Date.now();
  const successorStartedAt = new Date(successorStartedAtMs).toISOString();
  const expiredLease = dbModule.db.prepare(`
    UPDATE refresh_leases
    SET expires_at=?
    WHERE name=? AND holder_id=?
  `).run(
    new Date(successorStartedAtMs - 1).toISOString(),
    marker.leaseName,
    marker.holderId,
  );
  assert.equal(Number(expiredLease.changes), 1);
  const successorHolderId = `recovery-${crashPhase}`;
  assert.equal(
    dbModule.acquireRefreshLease(
      marker.leaseName,
      successorHolderId,
      successorStartedAt,
      300_000,
    ),
    true,
  );
  const successor = dbModule.beginRefreshOperationAttempt({
    run_id: `successor-${crashPhase}`,
    operation: 'refresh',
    trigger: 'crash-recovery',
    started_at: successorStartedAt,
    lease_name: marker.leaseName,
    lease_holder_id: successorHolderId,
    lease_expires_at: new Date(successorStartedAtMs + 300_000).toISOString(),
    code_revision: helperCodeRevision,
    effective_config: { schemaVersion: 1 },
  });
  const crashReceipt = dbModule.getRefreshCaptureReceipt(marker.runId);
  const release = dbModule.getRelease(simpleTag);
  const expectedCommitted = crashPhase === 'after-commit';
  assert.equal(crashReceipt?.status, expectedCommitted ? 'success' : 'abandoned');
  assert.equal(successor.abandonedReceipts.length, expectedCommitted ? 0 : 1);
  if (expectedCommitted) {
    assert.equal(typeof release?.final_score, 'number');
  } else {
    assert.equal(release?.final_score ?? null, null);
  }
  assert.deepEqual(
    simpleProbeRows(dbModule),
    expectedCommitted
      ? ['forecast', 'ingestion', 'score']
      : ['ingestion'],
  );
  const successorFinishedAtMs = Math.max(Date.now(), successorStartedAtMs);
  dbModule.appendRefreshCaptureReceipt({
    run_id: `successor-${crashPhase}`,
    lease_name: marker.leaseName,
    lease_holder_id: successorHolderId,
    status: 'failure',
    finished_at: new Date(successorFinishedAtMs).toISOString(),
    duration_ms: successorFinishedAtMs - successorStartedAtMs,
    payload: {
      schemaVersion: 1,
      operation: 'refresh',
      trigger: 'crash-recovery',
      codeRevision: helperCodeRevision,
      error: {
        message: 'test successor completed crash recovery verification only',
      },
    },
  });
  assert.equal(
    dbModule.releaseRefreshLease(marker.leaseName, successorHolderId),
    true,
  );
  return {
    crashPhase,
    crashReceiptStatus: crashReceipt?.status ?? null,
    abandonedReceiptCount: successor.abandonedReceipts.length,
    committedScore: release?.final_score ?? null,
    probeRows: simpleProbeRows(dbModule),
  };
}

function assertNoIncidentPhantomReleaseRows(dbModule: DbModule): void {
  const rows = dbModule.db.prepare(`
    SELECT tag, catalog_active
    FROM releases
    WHERE tag IN (?, ?)
    ORDER BY tag
  `).all(...incidentPhantomTags) as Array<{
    tag: string;
    catalog_active: number;
  }>;
  assert.deepEqual(
    rows,
    [],
    'incident phantom releases must not exist even as inactive rows',
  );
}

function crashReady(phase: string): never {
  process.stdout.write(`CRASH_READY=${phase}\n`);
  const cell = new Int32Array(new SharedArrayBuffer(4));
  Atomics.wait(cell, 0, 0);
  throw new Error(`crash wait unexpectedly returned for ${phase}`);
}

async function fetchJson(url: string): Promise<{ status: number; body: any }> {
  const response = await fetch(url, {
    signal: AbortSignal.timeout(15_000),
  });
  return {
    status: response.status,
    body: JSON.parse(await response.text()),
  };
}

async function waitFor(
  predicate: () => boolean,
  description: string,
): Promise<void> {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (predicate()) return;
    await new Promise<void>((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${description}`);
}

function emitResult(result: Record<string, unknown>): void {
  console.log(`COMPOSED_E2E_RESULT=${JSON.stringify(result)}`);
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function classifierTime(seconds: number): string {
  return new Date(Date.UTC(2041, 0, 1, 0, 0, seconds)).toISOString();
}

async function listen(app: Express): Promise<Server> {
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.once('listening', resolve);
  });
  return server;
}

async function closeServer(server: Server): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    server.close((error) => error ? reject(error) : resolve());
  });
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
