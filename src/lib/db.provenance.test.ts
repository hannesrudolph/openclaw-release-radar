import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import {
  chmodSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import {
  spawn,
  spawnSync,
  type SpawnSyncOptionsWithStringEncoding,
} from 'node:child_process';
import { dirname, join } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { backup, DatabaseSync } from 'node:sqlite';
import {
  CLASSIFICATION_PROMPT_TEMPLATE_HASH,
  type IssueClassification,
} from './llm.ts';
import {
  CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MAX_COUNT,
  CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MESSAGE_MAX_BYTES,
  appendClassifierAttempt,
  captureClassifierError,
  captureClassifierRawModelOutput,
  captureClassifierRawResponse,
  captureClassifierSemanticDiagnostics,
  classifierAttemptContentHash,
  classifierAttemptProvenanceHash,
  classifierAttemptRunContentHash,
  createClassifierAttemptLedger,
  createClassifierAttemptRun,
  createClassifierAttemptTerminalReceipt,
} from './classifierAttemptLedger.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from './analysisVersions.ts';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
  COMPOUND_ADVISORY_AUTHORITY_POLICY,
  advisoryRangeIdentityV2,
  advisoryVulnerabilityKey,
  buildCompoundAdvisorySnapshot,
} from './advisorySnapshot.ts';
import { repositoryAdvisoryCatalogContentDigest } from './advisoryCatalogDigest.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  serializeCommentEvidence,
} from './commentEvidence.ts';
import { extractClosureClaimCandidates } from './closureClaimCandidates.ts';
import { ReleaseAuditReader } from '../../scripts/lib/release-audit-reader.mjs';
import {
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  type NormalizedIssueStateEvent,
} from './stateEventSnapshot.ts';
import {
  APPROVED_ROSTER_KEYRING_PURPOSE,
  APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
  APPROVED_ROSTER_PURPOSE,
  APPROVED_ROSTER_SIGNATURE_ALGORITHM,
  APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
  approvedMaintainerRosterChainState,
  buildApprovedMaintainerRosterSnapshot,
  buildApprovedMaintainerRosterKeyring,
  buildRepositoryCollaboratorPermissionSnapshot,
  signApprovedMaintainerRosterManifest,
} from './labelAuthorityEvidenceIngestion.ts';
import { buildIssueLabelEvidenceSnapshot } from './issueLabelEvidenceSnapshot.ts';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  repositoryPermissionObservationRowHash,
  type LabelAuthorityEvidence,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';
import {
  buildScoreCommentAuthorityResolution,
  buildScoreAuthorityResolution,
  buildScoreAuthorityResolutionRun,
} from './scoreAuthorityResolution.ts';
import { scoreCommentBodyDigest } from './score.ts';
import { config } from '../config.ts';
import {
  canonicalJson as canonicalOperationJson,
  verifyOperationReceiptLedger,
  verifyOperationReceiptSemanticLinks,
} from './operationReceipts.ts';
import { planReleaseValidationOpportunityEnrollments } from './releaseValidationOpportunityDenominator.ts';
import {
  releaseValidationObservationBatchForecastInputs,
  stageReleaseValidationObservationBatchReceipt,
  stageReleaseValidationOutcomeRows,
  type ReleaseValidationObservationBatchResult,
} from './releaseValidationBatch.ts';
import { buildArtifactVerificationEvidence } from './artifactVerification.ts';
import {
  sealReleaseValidationForecastV2,
} from './releaseValidationProof.ts';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle.ts';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
} from './scoreSourceIdentity.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const inheritedEmptyDotenvPath = process.env.DOTENV_CONFIG_PATH;
const emptyDotenvPath = inheritedEmptyDotenvPath ?? join(
  mkdtempSync(join(tmpdir(), 'radar-empty-dotenv-')),
  '.env',
);
if (!inheritedEmptyDotenvPath) {
  writeFileSync(emptyDotenvPath, '');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
}

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-${name}-`)), 'radar.db');
}

function databaseSubprocessEnv(
  path: string,
  mode: 'fresh' | 'existing',
  overrides: NodeJS.ProcessEnv = {},
): NodeJS.ProcessEnv {
  return {
    ...process.env,
    DB_PATH: path,
    RADAR_DB_BOOTSTRAP_MODE: mode,
    ...overrides,
  };
}

function tsxEvalArgs(script: string): string[] {
  return ['--import', 'tsx', '--input-type=module', '--eval', script];
}

function spawnTsxEvalSync(
  script: string,
  options: SpawnSyncOptionsWithStringEncoding,
) {
  return spawnSync(process.execPath, tsxEvalArgs(script), options);
}

let sharedDb: Promise<{ db: any; path: string }> | null = null;

async function freshDb(name: string) {
  return (await freshDbWithPath(name)).db;
}

async function freshDbWithPath(name: string) {
  if (!sharedDb) {
    const path = assignedWorkerDatabasePath ?? dbPath(name);
    if (!assignedWorkerDatabasePath) process.env.DB_PATH = path;
    sharedDb = import(`./db.ts?case=${name}-${Date.now()}-${Math.random()}`)
      .then((db) => ({ db, path }));
  }
  const fixture = await sharedDb;
  resetDatabase(fixture.db.db);
  return fixture;
}

function resetDatabase(database: any): void {
  const tables = (database.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND name <> 'score_api_source_epoch'
    ORDER BY name
  `).all() as Array<{ name: string }>).map((row) => row.name);
  const appendOnlyTriggers = database.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND sql LIKE '% is append-only%'
    ORDER BY name
  `).all() as Array<{ name: string; sql: string }>;
  database.exec('PRAGMA foreign_keys=OFF');
  try {
    database.exec('BEGIN');
    for (const trigger of appendOnlyTriggers) {
      database.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    for (const table of tables) {
      database.exec(`DELETE FROM "${table.replaceAll('"', '""')}"`);
    }
    database.exec('DELETE FROM sqlite_sequence');
    for (const trigger of appendOnlyTriggers) database.exec(trigger.sql);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  } finally {
    database.exec('PRAGMA foreign_keys=ON');
  }
}

function classification(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.9,
    rationale: '',
    ...overrides,
  };
}

function acceptedClassifierLedger(
  input: {
    issueNumber: number;
    rawModelOutput: string;
    sourceIdentity: {
      model: string;
      serviceTier: string;
      promptTemplateHash: string;
      digest: string;
    };
    responseId: string;
  },
) {
  const requestHash = createHash('sha256')
    .update(`request:${input.issueNumber}:${input.responseId}`)
    .digest('hex');
  const run = createClassifierAttemptRun({
    runId: `classifier-run-${input.issueNumber}-${input.responseId}`,
    issueNumber: input.issueNumber,
    startedAt: '2040-01-01T00:00:00.000Z',
    maxAttempts: 1,
    classifierIdentityHash: input.sourceIdentity.promptTemplateHash,
    requestHash,
  });
  const rawResponse = JSON.stringify({
    id: input.responseId,
    model: input.sourceIdentity.model,
    service_tier: input.sourceIdentity.serviceTier,
    choices: [{
      finish_reason: 'stop',
      message: {
        content: input.rawModelOutput,
        refusal: null,
      },
    }],
  });
  const attempt = appendClassifierAttempt(run, [], {
    attemptId: `classifier-attempt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    startedAt: '2040-01-01T00:00:00.000Z',
    finishedAt: '2040-01-01T00:00:01.000Z',
    rawResponse: captureClassifierRawResponse(rawResponse),
    rawModelOutput: captureClassifierRawModelOutput(input.rawModelOutput),
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
      responseId: input.responseId,
      responseModel: input.sourceIdentity.model,
      responseServiceTier: input.sourceIdentity.serviceTier,
    },
  });
  const receipt = createClassifierAttemptTerminalReceipt(run, [attempt], {
    receiptId: `classifier-receipt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    finishedAt: '2040-01-01T00:00:02.000Z',
    error: null,
  });
  const ledger = createClassifierAttemptLedger(run, [attempt], receipt);
  return { run, attempt, receipt, ledger };
}

function recordAcceptedClassifierLedger(
  db: any,
  input: Parameters<typeof acceptedClassifierLedger>[0],
) {
  const { run, attempt, receipt, ledger } = acceptedClassifierLedger(input);
  db.recordClassifierAttemptRun(run);
  db.recordClassifierAttempt(attempt);
  db.recordClassifierAttemptTerminalReceipt(receipt);
  const revisions = db.issueEvidenceRevisions([input.issueNumber]).get(input.issueNumber);
  assert.ok(revisions);
  assert.ok(receipt.selectedAttempt);
  return {
    ledger,
    selectedAttemptBinding: receipt.selectedAttempt,
    evidenceRevisions: {
      issueRevision: revisions.issueRevision,
      snapshotRevision: revisions.snapshotRevision,
      stateSnapshotRevision: revisions.stateSnapshotRevision,
    },
  };
}

function groundingRetryRawModelOutput(): string {
  return JSON.stringify({
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affected_users: 'unknown',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    evidence: {
      sentiment: [],
      severity: [],
      scope: [],
      functionality: [],
      affected_users: [],
      workaroundStatus: [],
      duplicateCluster: [],
      affectsVersion: [],
    },
    rationale: 'Grounding fixture requires corrected citations.',
  });
}

function acceptedClassifierSemanticRetryLedger(
  input: Parameters<typeof acceptedClassifierLedger>[0],
) {
  const initialRequestHash = createHash('sha256')
    .update(`initial-request:${input.issueNumber}:${input.responseId}`)
    .digest('hex');
  const finalRequestHash = createHash('sha256')
    .update(`feedback-request:${input.issueNumber}:${input.responseId}`)
    .digest('hex');
  const run = createClassifierAttemptRun({
    runId: `classifier-run-${input.issueNumber}-${input.responseId}`,
    issueNumber: input.issueNumber,
    startedAt: '2040-01-01T00:00:00.000Z',
    maxAttempts: 2,
    classifierIdentityHash: input.sourceIdentity.promptTemplateHash,
    requestHash: initialRequestHash,
  });
  const rejectedRawModelOutput = groundingRetryRawModelOutput();
  const rejectedResponseId = `${input.responseId}-rejected`;
  const rejectedAttempt = appendClassifierAttempt(run, [], {
    attemptId: `classifier-attempt-${input.issueNumber}-${rejectedResponseId}`,
    status: 'semantic_rejection',
    startedAt: '2040-01-01T00:00:00.000Z',
    finishedAt: '2040-01-01T00:00:01.000Z',
    rawResponse: captureClassifierRawResponse(JSON.stringify({
      id: rejectedResponseId,
      model: input.sourceIdentity.model,
      service_tier: input.sourceIdentity.serviceTier,
      choices: [{
        finish_reason: 'stop',
        message: {
          content: rejectedRawModelOutput,
          refusal: null,
        },
      }],
    })),
    rawModelOutput: captureClassifierRawModelOutput(rejectedRawModelOutput),
    error: captureClassifierError({
      name: 'ClassificationGroundingError',
      message: 'severity requires a supporting citation',
    }),
    retry: {
      decision: 'retry',
      retryable: true,
      delayMs: 0,
      reason: 'retryable_semantic_rejection',
    },
    semanticDiagnostics: captureClassifierSemanticDiagnostics([{
      field: 'severity',
      code: 'missing_support',
      message: 'severity requires a supporting citation',
    }]),
    provenance: {
      requestHash: initialRequestHash,
      responseId: rejectedResponseId,
      responseModel: input.sourceIdentity.model,
      responseServiceTier: input.sourceIdentity.serviceTier,
    },
  });
  const acceptedAttempt = appendClassifierAttempt(run, [rejectedAttempt], {
    attemptId: `classifier-attempt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    startedAt: '2040-01-01T00:00:01.000Z',
    finishedAt: '2040-01-01T00:00:02.000Z',
    rawResponse: captureClassifierRawResponse(JSON.stringify({
      id: input.responseId,
      model: input.sourceIdentity.model,
      service_tier: input.sourceIdentity.serviceTier,
      choices: [{
        finish_reason: 'stop',
        message: {
          content: input.rawModelOutput,
          refusal: null,
        },
      }],
    })),
    rawModelOutput: captureClassifierRawModelOutput(input.rawModelOutput),
    error: null,
    retry: {
      decision: 'stop',
      retryable: false,
      delayMs: null,
      reason: 'accepted_success',
    },
    semanticDiagnostics: [],
    provenance: {
      requestHash: finalRequestHash,
      responseId: input.responseId,
      responseModel: input.sourceIdentity.model,
      responseServiceTier: input.sourceIdentity.serviceTier,
    },
  });
  const receipt = createClassifierAttemptTerminalReceipt(
    run,
    [rejectedAttempt, acceptedAttempt],
    {
      receiptId: `classifier-receipt-${input.issueNumber}-${input.responseId}`,
      status: 'accepted_success',
      finishedAt: '2040-01-01T00:00:03.000Z',
      error: null,
    },
  );
  const ledger = createClassifierAttemptLedger(
    run,
    [rejectedAttempt, acceptedAttempt],
    receipt,
  );
  return {
    initialRequestHash,
    finalRequestHash,
    run,
    rejectedAttempt,
    acceptedAttempt,
    receipt,
    ledger,
  };
}

function recordAcceptedClassifierSemanticRetryLedger(
  db: any,
  input: Parameters<typeof acceptedClassifierLedger>[0],
) {
  const fixture = acceptedClassifierSemanticRetryLedger(input);
  db.recordClassifierAttemptRun(fixture.run);
  db.recordClassifierAttempt(fixture.rejectedAttempt);
  db.recordClassifierAttempt(fixture.acceptedAttempt);
  db.recordClassifierAttemptTerminalReceipt(fixture.receipt);
  const revisions = db.issueEvidenceRevisions([input.issueNumber]).get(input.issueNumber);
  assert.ok(revisions);
  assert.ok(fixture.receipt.selectedAttempt);
  return {
    ...fixture,
    selectedAttemptBinding: fixture.receipt.selectedAttempt,
    evidenceRevisions: {
      issueRevision: revisions.issueRevision,
      snapshotRevision: revisions.snapshotRevision,
      stateSnapshotRevision: revisions.stateSnapshotRevision,
    },
  };
}

function resealClassifierAttempt(attempt: any): any {
  attempt.provenanceHash = classifierAttemptProvenanceHash(
    attempt.provenance,
  );
  const { contentHash: _contentHash, ...withoutContentHash } = attempt;
  attempt.contentHash = classifierAttemptContentHash(withoutContentHash);
  return attempt;
}

function testReleaseCommitOid(tag: string): string {
  return createHash('sha1')
    .update(`openclaw-release-radar:test-release:${tag}`)
    .digest('hex');
}

function seedRawRelease(
  db: any,
  tag = 'v1',
  publishedAt: string | null = '2026-06-01T00:00:00Z',
  prerelease = false,
) {
  db.upsertRelease({
    tag,
    name: tag,
    published_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: testReleaseCommitOid(tag),
    committed_at: publishedAt,
  });
}

function catalogRelease(
  tag: string,
  publishedAt: string,
  prerelease = false,
  tagCommitOid = '1'.repeat(40),
) {
  return {
    node_id: `R_${tag}`,
    catalog_tag_commit_oid: tagCommitOid,
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/${tag}`,
    prerelease,
    body: '',
  };
}

function seedAuthorizedReleaseCatalog(
  db: any,
  releases: ReadonlyArray<ReturnType<typeof catalogRelease>>,
): void {
  assert.ok(releases.length > 0, 'authorized release fixtures require a catalog');
  const rows = releases.map((release) => ({ ...release }));
  for (let index = 1; index < rows.length; index++) {
    assert.ok(
      Date.parse(rows[index - 1].created_at) >= Date.parse(rows[index].created_at),
      'authorized release fixtures must be newest-first',
    );
  }
  db.replaceActiveReleaseCatalog(rows, {
    capture: { source: 'test_fixture' },
  });
  for (const release of rows) {
    db.upsertReleaseCommit({
      tag: release.tag,
      tag_commit_oid: release.catalog_tag_commit_oid,
      committed_at: release.published_at,
    });
  }
}

function seedRelease(
  db: any,
  tag = 'v1',
  publishedAt: string | null = '2026-06-01T00:00:00Z',
  prerelease = false,
  tagCommitOid = testReleaseCommitOid(tag),
) {
  assert.ok(
    publishedAt && Number.isFinite(Date.parse(publishedAt)),
    'authorized release fixtures require a finite publication timestamp',
  );
  seedAuthorizedReleaseCatalog(db, [
    catalogRelease(tag, publishedAt, prerelease, tagCommitOid),
  ]);
}

function forecastCatalogAttestation(
  db: any,
  tag: string,
  publishedAt: string,
  observedAt: string,
) {
  const releaseCommit = db.db.prepare(`
    SELECT tag_commit_oid
    FROM release_commits
    WHERE tag=?
  `).get(tag) as { tag_commit_oid?: string } | undefined;
  db.replaceActiveReleaseCatalog([
    catalogRelease(
      tag,
      publishedAt,
      false,
      releaseCommit?.tag_commit_oid ?? '1'.repeat(40),
    ),
  ]);
  const catalog = db.currentActiveReleaseCatalog();
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

function buildEmptyCompoundAdvisorySnapshot(
  capturedAt: string,
  authorityPolicy?: typeof COMPOUND_ADVISORY_AUTHORITY_POLICY | null,
) {
  const hashJson = (value: unknown) =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const packageName = config.github.repo;
  const emptyIdentityDigest = hashJson([]);
  const emptyRepositoryIdentityDigest = hashJson([0, []]);
  return buildCompoundAdvisorySnapshot({
    capturedAt,
    ...(authorityPolicy === undefined ? {} : { authorityPolicy }),
    repository: {
      owner: config.github.owner,
      name: config.github.repo,
      url: `https://github.com/${config.github.owner}/${config.github.repo}`,
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
        identityDigest: emptyRepositoryIdentityDigest,
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
}

function buildGraphqlOnlyCompoundAdvisorySnapshot(capturedAt: string) {
  const empty = buildEmptyCompoundAdvisorySnapshot(capturedAt);
  const hashJson = (value: unknown) =>
    createHash('sha256').update(JSON.stringify(value)).digest('hex');
  const ghsaId = 'GHSA-public-audit';
  const ecosystem = empty.target.ecosystem;
  const packageName = empty.target.packageName;
  const vulnerableVersionRange = '< 2.0.0';
  const identity = advisoryRangeIdentityV2(
    ghsaId,
    ecosystem,
    packageName,
    vulnerableVersionRange,
  );
  const range = {
    ghsaId,
    cveId: 'CVE-2040-0001',
    summary: 'Score-eligible advisory projection fixture',
    severity: 'high' as const,
    htmlUrl: `https://github.com/advisories/${ghsaId}`,
    publishedAt: capturedAt,
    withdrawnAt: null,
    ecosystem,
    packageName,
    vulnerableVersionRange,
    firstPatchedVersion: '2.0.0',
    updatedAt: capturedAt,
    identity,
  };
  const rangeIdentities = [identity];
  const graphql = {
    ...empty.sourceObservations.graphql.observation,
    totalCount: 1,
    nodeCount: 1,
    uniqueRangeCount: 1,
    digest: hashJson([
      1,
      [[
        identity,
        range.cveId,
        range.summary,
        range.severity,
        range.htmlUrl,
        range.publishedAt,
        range.withdrawnAt,
        range.firstPatchedVersion,
        range.updatedAt,
      ]],
    ]),
    identityDigest: hashJson(rangeIdentities),
    ranges: [range],
    rangeIdentities,
  };
  const repositoryRest =
    empty.sourceObservations.repositoryRest.observation;
  return buildCompoundAdvisorySnapshot({
    capturedAt,
    repository: empty.repository,
    target: empty.target,
    sources: { graphql, repositoryRest },
    reconciliation: {
      target: { ecosystem, packageName },
      graphqlSecurityVulnerabilities: {
        totalCount: graphql.totalCount,
        rangeCount: graphql.uniqueRangeCount,
        identityDigest: graphql.identityDigest,
        rangeIdentities,
      },
      repositoryAdvisories: {
        totalCount: repositoryRest.totalCount,
        observedAdvisoryCount: repositoryRest.observedAdvisoryCount,
        targetRangeCount: repositoryRest.targetRangeCount,
        identityDigest: repositoryRest.targetIdentityDigest,
        rangeIdentities: repositoryRest.targetRangeIdentities,
        completenessProven:
          repositoryRest.completeness.terminalPageProven,
      },
    },
  });
}

function persistEmptyCompoundAdvisorySnapshot(db: any, capturedAt: string) {
  return db.persistCompoundAdvisorySnapshot(
    buildEmptyCompoundAdvisorySnapshot(capturedAt),
  ).metadata;
}

function seedActionableRefreshPublication(db: any, input: {
  tag: string;
  operationRunId: string;
  historyRunId: string;
  leaseName: string;
  holderId: string;
  nowMs: number;
  advisorySnapshot?: ReturnType<typeof buildCompoundAdvisorySnapshot>;
}) {
  const startedAt = new Date(input.nowMs - 60_000).toISOString();
  const enrolledAt = new Date(input.nowMs - 45_000).toISOString();
  const scoredAt = new Date(input.nowMs - 20_000).toISOString();
  const publishedAt = new Date(Date.parse(scoredAt) - 4 * 60 * 60 * 1000).toISOString();
  const finishedAt = new Date(input.nowMs - 10_000).toISOString();
  seedRelease(db, input.tag, publishedAt);
  const catalogAttestation = forecastCatalogAttestation(
    db,
    input.tag,
    publishedAt,
    new Date(input.nowMs - 30_000).toISOString(),
  );
  const advisoryMetadata = input.advisorySnapshot
    ? db.persistCompoundAdvisorySnapshot(input.advisorySnapshot).metadata
    : persistEmptyCompoundAdvisorySnapshot(
        db,
        new Date(input.nowMs - 30_000).toISOString(),
      );
  const issueCrawlMetadata = {
    schemaVersion: 2,
    startedAt,
    finishedAt: new Date(input.nowMs - 25_000).toISOString(),
    stopReason: 'exhausted',
    scorePersisted: true,
    scorePersistedAt: scoredAt,
  };
  db.setMeta('issue_crawl_last_run', JSON.stringify(issueCrawlMetadata));
  const codeRevision = 'restorable-revision';
  const operationAttempt = db.insertRefreshOperationAttempt({
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
  assert.equal(db.acquireRefreshLease(
    input.leaseName,
    input.holderId,
    new Date(input.nowMs - 50_000).toISOString(),
    300_000,
  ), true);
  persistRecoveryArtifactVerification(db, {
    runId: input.operationRunId,
    observedAt: new Date(input.nowMs - 24_000).toISOString(),
    release: {
      repository: 'openclaw/openclaw',
      tag: input.tag,
      releaseNodeId: catalogAttestation.latestStable.nodeId,
      catalogTagCommitOid: catalogAttestation.latestStable.tagCommitOid,
      publishedAt,
    },
  });
  const sourceIdentity = db.scoreSourceIdentity({
    artifactObservationRunId: input.operationRunId,
  });
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
  const auditInput = {
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
  };
  db.updateReleaseScore({
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
  const {
    audit,
    authorityRun,
    seal,
    historyV2Seal,
  } = insertAuthorityBackedHistory(db, {
    historyRunId: input.historyRunId,
    recordedAt: scoredAt,
    audit: auditInput,
    upsertCurrent: true,
    artifactObservationRunId: input.operationRunId,
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
  const activeCatalog = db.currentActiveReleaseCatalog();
  const enrollment = db.insertReleaseValidationOpportunityEnrollments({
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
    (row: any) => row.opportunity_code === 'first_verified_after_3h',
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
    minScoredAt: scoredAt,
    maxScoredAt: scoredAt,
    issueCrawlStartedAt: issueCrawlMetadata.startedAt,
    issueCrawlFinishedAt: issueCrawlMetadata.finishedAt,
    issueCrawlStopReason: issueCrawlMetadata.stopReason,
    issueCrawlScorePersistedAt: issueCrawlMetadata.scorePersistedAt,
    issueCrawlMetadataDigest: createHash('sha256')
      .update(canonicalOperationJson(issueCrawlMetadata))
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
      slots: enrollment.rows.map((row: any) => ({
        opportunityCode: row.opportunity_code,
        existingDecisionId: null,
        existingContentHash: null,
      })),
    },
  };
  db.setMeta('score_persistence_last_run', JSON.stringify(scoreMeta));
  db.setMeta('last_scored_at', scoredAt);
  const forecast = db.insertReleaseValidationForecast({
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
  const proofLifecycle = planReleaseValidationProofLifecycle({
    existing: db.readReleaseValidationProofBundle(),
    repository: 'openclaw/openclaw',
    observedAt: publishedAt,
    source: 'actionable-refresh-publication-test',
    releases: [{
      repository: 'openclaw/openclaw',
      nodeId: catalogAttestation.latestStable.nodeId,
      tag: input.tag,
      tagCommitOid: catalogAttestation.latestStable.tagCommitOid,
      publishedAt,
      aliases: [input.tag],
    }],
    modelVersion: audit.score_model_version,
    promptVersion: audit.prompt_version,
    codeRevision,
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  const proofObligation = proofLifecycle.bundle.obligations.find(
    (row: any) =>
      row.opportunityCode === forecast.opportunity_code &&
      row.horizonCode === 'field_regression_72h',
  );
  assert.ok(proofObligation);
  const proofAssignment = proofLifecycle.bundle.splitAssignments.find(
    (row: any) => row.obligationId === proofObligation.obligationId,
  );
  assert.ok(proofAssignment);
  const proofCohortRows = [
    ...proofLifecycle.bundle.obligations,
    ...proofLifecycle.bundle.splitAssignments,
    ...proofLifecycle.bundle.forecasts,
    ...proofLifecycle.bundle.outcomes,
    ...proofLifecycle.bundle.observationBatches,
  ].filter((row: any) => row.cohortId === proofLifecycle.cohort.cohortId);
  const canonicalForecast = sealReleaseValidationForecastV2({
    proofEpochId: proofLifecycle.cohort.proofEpochId,
    cohortId: proofLifecycle.cohort.cohortId,
    cohortSequence: Math.max(
      0,
      ...proofCohortRows.map((row: any) => row.cohortSequence),
    ) + 1,
    previousCohortContentHash:
      proofLifecycle.verification.cohortChainTips[
        proofLifecycle.cohort.cohortId
      ] ?? null,
    obligationId: proofObligation.obligationId,
    splitAssignmentId: proofAssignment.assignmentId,
    policyId: proofLifecycle.cohort.policyId,
    policyContentHash: proofLifecycle.cohort.policyContentHash,
    recordedAt: forecast.recorded_at,
    latestRelease: proofObligation.release,
    candidates: [proofObligation.release],
    selectedReleaseId: proofObligation.release.releaseId,
    forecast: {
      schemaVersion: 1,
      legacyForecast: {
        decisionId: forecast.decision_id,
        contentHash: forecast.content_hash,
      },
      originalScorePublication: {
        historyRunId: input.historyRunId,
      },
      canonicalCapturePublication: {
        historyRunId: input.historyRunId,
        historyRunContentHash: seal.row.content_hash,
        authorityRunId: authorityRun.authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
      },
    },
  });
  db.appendReleaseValidationProof({
    ...proofLifecycle.append,
    forecasts: [canonicalForecast],
  });
  db.appendRefreshOperationStageEvent({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    stage: 'score.persist',
    status: 'started',
    occurred_at: new Date(input.nowMs - 40_000).toISOString(),
  });
  db.appendRefreshOperationStageEvent({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    stage: 'score.persist',
    status: 'completed',
    occurred_at: scoredAt,
    duration_ms: 20_000,
    counts: { scoredReleases: 1 },
    details: {
      historyRunId: input.historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      commitNotBefore: scoredAt,
      commitNotAfter: scoredAt,
    },
  });
  db.appendRefreshOperationStageEvent({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    stage: 'forecast.capture',
    status: 'started',
    occurred_at: new Date(input.nowMs - 15_000).toISOString(),
  });
  db.appendRefreshOperationStageEvent({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    stage: 'forecast.capture',
    status: 'completed',
    occurred_at: finishedAt,
    duration_ms: 5_000,
    counts: { validationForecasts: 1 },
    details: { eligibilityOutcome: 'eligible_and_captured' },
  });
  const receipt = db.appendRefreshCaptureReceipt({
    run_id: input.operationRunId,
    lease_name: input.leaseName,
    lease_holder_id: input.holderId,
    status: 'success',
    finished_at: finishedAt,
    duration_ms: 50_000,
    payload: {
      schemaVersion: 2,
      operation: 'refresh',
      trigger: 'test-actionable',
      codeRevision,
      releaseArtifacts: db.releaseArtifactPublicationForRun(
        input.operationRunId,
      ),
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
      recommendation: {
        selectedTag: input.tag,
        decisions: [{ releaseTag: input.tag, decision: recommendationDecision }],
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
          .update(canonicalOperationJson(advisoryMetadata))
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
        canonicalForecastIds: [canonicalForecast.forecastId],
        canonicalForecastContentHashes: [canonicalForecast.contentHash],
        newCanonicalForecastIds: [canonicalForecast.forecastId],
        existingCanonicalForecastIds: [],
        canonicalCaptures: [{
          opportunityCode: proofObligation.opportunityCode,
          horizonCode: proofObligation.horizonCode,
          status: 'inserted',
          forecastId: canonicalForecast.forecastId,
          contentHash: canonicalForecast.contentHash,
          obligationId: canonicalForecast.obligationId,
          splitAssignmentId: canonicalForecast.splitAssignmentId,
          cohortId: canonicalForecast.cohortId,
          legacyDecisionId: forecast.decision_id,
          legacyContentHash: forecast.content_hash,
        }],
      },
    },
  }).row;
  assert.equal(db.releaseRefreshLease(input.leaseName, input.holderId), true);
  const publication = db.getSealedReleaseScoreAuditPublication(input.tag);
  assert.equal(publication.valid, true, publication.problems.join('; '));
  return {
    audit,
    issueCrawlMetadata,
    scoreMeta,
    seal: seal.row,
    authorityRun,
    historyV2Seal: historyV2Seal.row,
    scoredAt,
    recommendationDecision,
    forecast,
    receipt,
  };
}

function overlayUnsuccessfulRefreshScoreTip(db: any, input: {
  tag: string;
  operationRunId: string;
  historyRunId: string;
  leaseName: string;
  failedHolderId: string;
  successorHolderId: string;
  nowMs: number;
  terminalStatus: 'receiptless' | 'failure' | 'abandoned';
}) {
  const startedAt = new Date(input.nowMs - 8_000).toISOString();
  const artifactObservedAt = new Date(input.nowMs - 7_000).toISOString();
  const scoredAt = new Date(input.nowMs - 5_000).toISOString();
  db.insertRefreshOperationAttempt({
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
  assert.equal(db.acquireRefreshLease(
    input.leaseName,
    input.failedHolderId,
    new Date().toISOString(),
    300_000,
  ), true);
  const activeRelease = db.currentActiveReleaseCatalog().latestStable;
  assert.ok(activeRelease);
  assert.equal(activeRelease.tag, input.tag);
  persistRecoveryArtifactVerification(db, {
    runId: input.operationRunId,
    observedAt: artifactObservedAt,
    release: {
      repository: 'openclaw/openclaw',
      tag: activeRelease.tag,
      releaseNodeId: activeRelease.nodeId,
      catalogTagCommitOid: activeRelease.tagCommitOid,
      publishedAt: activeRelease.publishedAt,
    },
  });
  const sourceIdentity = db.scoreSourceIdentity({
    artifactObservationRunId: input.operationRunId,
  });
  const auditInput = {
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
  };
  db.updateReleaseScore({
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
  const {
    authorityRun,
    seal,
    historyV2Seal,
  } = insertAuthorityBackedHistory(db, {
    historyRunId: input.historyRunId,
    recordedAt: scoredAt,
    audit: auditInput,
    upsertCurrent: true,
    artifactObservationRunId: input.operationRunId,
  });
  db.setMeta('score_persistence_last_run', JSON.stringify({
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
  db.setMeta('last_scored_at', scoredAt);
  db.setMeta('issue_crawl_last_run', JSON.stringify({
    schemaVersion: 2,
    scorePersisted: true,
    scorePersistedAt: scoredAt,
    failedTip: input.operationRunId,
  }));

  let successorLeaseHeld = false;
  if (input.terminalStatus === 'failure') {
    db.appendRefreshCaptureReceipt({
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
    assert.equal(db.releaseRefreshLease(input.leaseName, input.failedHolderId), true);
  }
  if (input.terminalStatus === 'receiptless') {
    assert.equal(
      db.releaseRefreshLease(input.leaseName, input.failedHolderId),
      true,
    );
  }
  if (input.terminalStatus === 'abandoned') {
    assert.equal(
      db.releaseRefreshLease(input.leaseName, input.failedHolderId),
      true,
    );
    assert.equal(db.acquireRefreshLease(
      input.leaseName,
      input.successorHolderId,
      new Date(input.nowMs).toISOString(),
      300_000,
    ), true);
    successorLeaseHeld = true;
    db.appendRefreshCaptureReceipt({
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
  return {
    seal: seal.row,
    authorityRun,
    historyV2Seal: historyV2Seal.row,
    successorLeaseHeld,
  };
}

function persistRecoveryArtifactVerification(db: any, input: {
  runId: string;
  observedAt: string;
  release: {
    repository: string;
    tag: string;
    releaseNodeId: string;
    catalogTagCommitOid: string;
    publishedAt: string;
  };
}) {
  const version = input.release.tag.replace(/^v/, '');
  const bytes = Buffer.from(
    `provenance recovery artifact bytes:${input.runId}`,
  );
  const digest = createHash('sha512').update(bytes).digest('base64');
  const integrity = `sha512-${digest}`;
  const tarballUrl =
    `https://registry.npmjs.org/openclaw/-/openclaw-${version}.tgz`;
  const reportUrl =
    `https://github.com/openclaw/openclaw/blob/` +
    `${input.release.catalogTagCommitOid}/release-evidence.json`;
  return db.persistReleaseArtifactVerification({
    runId: input.runId,
    observedAt: input.observedAt,
    release: input.release,
    releaseMetadata: {
      npmPackageUrl: `https://www.npmjs.com/package/openclaw/v/${version}`,
      releaseTarballUrl: tarballUrl,
      releaseIntegrity: integrity,
      releaseSha: input.release.catalogTagCommitOid,
      ciReportUrl: reportUrl,
      fullReleaseValidationUrl: null,
    },
    artifact: buildArtifactVerificationEvidence({
      packageName: 'openclaw',
      requestedVersion: version,
      metadataUrl: `https://registry.npmjs.org/openclaw/${version}`,
      metadataContentDigest: '5'.repeat(64),
      registryAvailability: 'available',
      registryPackageName: 'openclaw',
      registryVersion: version,
      registryIntegrity: integrity,
      registryTarballUrl: tarballUrl,
      registryGitHead: input.release.catalogTagCommitOid,
      actualDigests: { sha512: digest },
      tarballByteCount: bytes.length,
      expectedIntegrity: integrity,
      expectedTarballUrl: tarballUrl,
      expectedReleaseSha: input.release.catalogTagCommitOid,
    }),
    evidenceReport: {
      url: reportUrl,
      rawUrl:
        `https://raw.githubusercontent.com/openclaw/openclaw/` +
        `${input.release.catalogTagCommitOid}/release-evidence.json`,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      contentDigest: '6'.repeat(64),
      fallbackArtifactDigest: null,
      expectedReleaseTag: input.release.tag,
      expectedReleaseSha: input.release.catalogTagCommitOid,
      verified: true,
      mismatch: null,
    },
  });
}

function forecastDecisionV4(input: {
  opportunityCode: 'first_verified_after_3h' | 'first_verified_after_24h';
  recordedAt: string;
  latestReleaseTag: string;
  latestReleasePublishedAt: string;
  selectedTag: string | null;
  recommendationDecision: Record<string, unknown>;
  historyRunId: string;
  historyRunContentHash: string;
  authorityRunId: string;
  authorityRunContentHash: string;
  historyV2SealContentHash: string;
  historyRecordedAt: string;
  catalogAttestation: Record<string, unknown>;
}) {
  const minAgeHours = input.opportunityCode === 'first_verified_after_3h' ? 3 : 24;
  const maxAgeHours = input.opportunityCode === 'first_verified_after_3h' ? 6 : 30;
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
      windowStartAt: new Date(publishedAtMs + minAgeHours * 3_600_000).toISOString(),
      windowEndAt: new Date(publishedAtMs + maxAgeHours * 3_600_000).toISOString(),
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

function insertAuthorityBackedHistory<
  T extends Record<string, unknown> & { source_identity_json: string },
>(db: any, input: {
  historyRunId: string;
  recordedAt: string;
  audit: T;
  upsertCurrent?: boolean;
  artifactObservationRunId?: string;
}) {
  const sourceIdentity = JSON.parse(input.audit.source_identity_json);
  const authorityRunId = `score-authority:${input.historyRunId}`;
  const previousAuthorityRun =
    db.listScoreAuthorityResolutionRuns().at(-1) ?? null;
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId,
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    recordedAt: input.recordedAt,
    previousContentHash: previousAuthorityRun?.contentHash ?? null,
    rows: [],
  });
  const storedAuthorityRun =
    db.insertScoreAuthorityResolutionRun(
      authorityRun,
      input.artifactObservationRunId == null
        ? {}
        : {
            sourceIdentityOptions: {
              artifactObservationRunId: input.artifactObservationRunId,
            },
          },
    ).row;
  const audit = {
    ...input.audit,
    authority_run_id: storedAuthorityRun.authorityRunId,
  };
  if (input.upsertCurrent) db.upsertReleaseScoreAudit(audit);
  db.insertReleaseScoreAuditHistory(
    input.historyRunId,
    input.recordedAt,
    audit,
  );
  const seal = db.sealReleaseScoreAuditHistoryRun(
    input.historyRunId,
    input.recordedAt,
  );
  const historyV2Seal = db.sealReleaseScoreAuditHistoryV2({
    historyRunId: input.historyRunId,
    authorityRunId: storedAuthorityRun.authorityRunId,
    sealedAt: input.recordedAt,
  });
  return {
    audit,
    authorityRun: storedAuthorityRun,
    seal,
    historyV2Seal,
  };
}

function seedIssue(
  db: any,
  number: number,
  closedAt: string | null = '2026-06-02T00:00:00Z',
  createdAt = '2026-06-01T12:00:00Z',
) {
  db.upsertIssue({
    number,
    state: closedAt ? 'closed' : 'open',
    title: `issue ${number}`,
    author: 'tester',
    html_url: `https://example.test/issues/${number}`,
    created_at: createdAt,
    updated_at: closedAt ?? createdAt,
    closed_at: closedAt,
    comments: 0,
    labels: '[]',
    is_bot: 0,
  });
  db.upsertClassification(number, classification(), closedAt ?? createdAt, 1);
}

function seedPr(db: any, pr: number, merged = true) {
  db.upsertPullRequestFix({
    pr_number: pr,
    title: `PR ${pr}`,
    url: `https://example.test/pull/${pr}`,
    state: 'MERGED',
    merged: merged ? 1 : 0,
    merged_at: merged ? '2026-05-31T00:00:00Z' : null,
    merge_commit_oid: `merge-${pr}`,
    base_ref_name: 'main',
  });
}

function seedClosure(db: any, issue: number, reason = 'COMPLETED', closedAt = '2026-06-02T00:00:00Z') {
  db.upsertIssueClosureEvent({
    issue_number: issue,
    event_id: `closed-${issue}`,
    closed_at: closedAt,
    actor_login: 'maintainer',
    state_reason: reason,
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
}

function authoritativeStateSnapshotFields(input: {
  repositoryNodeId: string;
  issueNumber: number;
  issueNodeId: string;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  events: readonly NormalizedIssueStateEvent[];
}) {
  const issueNodeType = 'Issue' as const;
  const sweep = {
    repositoryNodeId: input.repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId: input.issueNodeId,
    issueNodeType,
    issueState: input.issueState,
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: input.events.length,
    events: input.events,
  };
  const firstSweep = issueStateEventSweepIdentity({ ...sweep, sweepOrdinal: 1 });
  const secondSweep = issueStateEventSweepIdentity({ ...sweep, sweepOrdinal: 2 });
  return {
    repository_node_id: input.repositoryNodeId,
    issue_node_id: input.issueNodeId,
    issue_node_type: issueNodeType,
    events_digest: issueStateEventsDigest(input.events, {
      repositoryNodeId: input.repositoryNodeId,
      issueNodeId: input.issueNodeId,
      issueNodeType,
    }),
    authority_digest: secondSweep.sweepDigest,
    stabilization: issueStateEventStabilizationIdentity(firstSweep, secondSweep, 2),
  };
}

function authorityFixtureHash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function insertAuthorityLabelEvent(db: any, input: {
  issueNumber: number;
  eventId: string;
  actorNodeId: string | null;
  actorLogin: string | null;
  actorType: string | null;
  eventTime: string;
  issueUpdatedAt?: string;
  label?: string;
}) {
  const issueNodeId = `I_authority_event_${input.issueNumber}`;
  const issueUpdatedAt = input.issueUpdatedAt ?? input.eventTime;
  const label = input.label ?? 'P1';
  seedIssue(db, input.issueNumber, null, issueUpdatedAt);
  db.db.prepare(`
    UPDATE issues
    SET node_id=?
    WHERE number=?
  `).run(issueNodeId, input.issueNumber);
  const raw = {
    __typename: 'LabeledEvent',
    id: input.eventId,
    createdAt: input.eventTime,
    label: {
      id: `L_${label}`,
      name: label,
    },
    actor: input.actorNodeId == null
      ? null
      : {
          __typename: input.actorType,
          id: input.actorNodeId,
          login: input.actorLogin,
        },
  };
  const snapshot = buildIssueLabelEvidenceSnapshot({
    schemaVersion: 2,
    repository: 'openclaw/openclaw',
    repositoryNodeId: 'R_openclaw',
    issueNumber: input.issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    capturedAt: new Date(Date.parse(issueUpdatedAt) + 1_000).toISOString(),
    issueUpdatedAt,
    totalCount: 1,
    fetchedCount: 1,
    pageCount: 1,
    sweepCount: 2,
    stabilized: true,
    events: [{
      issueNumber: input.issueNumber,
      issueNodeId,
      issueNodeType: 'Issue',
      eventId: input.eventId,
      action: 'labeled',
      labelNodeId: `L_${label}`,
      labelName: label,
      actorNodeId: input.actorNodeId,
      actorLogin: input.actorLogin,
      actorType: input.actorType,
      createdAt: input.eventTime,
      raw,
    }],
  });
  db.upsertIssueLabelEvent({
    issue_number: input.issueNumber,
    issue_node_id: issueNodeId,
    event_id: input.eventId,
    action: 'labeled',
    label_name: label,
    actor_node_id: input.actorNodeId,
    actor_login: input.actorLogin,
    actor_type: input.actorType,
    created_at: input.eventTime,
    raw_json: JSON.stringify(raw),
  });
  db.insertIssueLabelEvidenceSnapshot(snapshot);
  return snapshot;
}

function authorityCommentFixture(issueNumber: number) {
  const issueNodeId = `I_authority_${issueNumber}`;
  const issueAuthorNodeId = `U_authority_reporter_${issueNumber}`;
  const issueUpdatedAt = '2026-07-04T11:59:00Z';
  const commentId = 900000 + issueNumber;
  const commentNodeId = `IC_${issueNumber}`;
  const commentUrl =
    `https://example.test/issues/${issueNumber}#issuecomment-${commentId}`;
  const commentBody =
    `I can independently reproduce this issue on the affected release. ` +
    `Fixed by PR #${issueNumber}.`;
  const commentCreatedAt = '2026-07-04T11:57:00Z';
  return {
    issueNodeId,
    issueAuthorNodeId,
    issueUpdatedAt,
    comment: {
      id: commentId,
      node_id: commentNodeId,
      node_type: 'IssueComment' as const,
      url: commentUrl,
      user: {
        id: 'U_alice',
        login: 'alice',
        type: 'User' as const,
      },
      author_association: 'MEMBER',
      body: commentBody,
      created_at: commentCreatedAt,
      updated_at: commentCreatedAt,
    },
  };
}

function insertAuthoritativeTestCommentSnapshot(
  db: any,
  input: {
    issueNumber: number;
    issueUpdatedAt: string;
    body: string;
    createdAt?: string;
  },
) {
  const issueNodeId = `I_closure_claim_${input.issueNumber}`;
  const actorNodeId = `U_closure_claim_reporter_${input.issueNumber}`;
  const createdAt = input.createdAt ?? input.issueUpdatedAt;
  db.db.prepare(`
    UPDATE issues
    SET node_id=?, author_node_id=?, author_type='User', comments=1,
        updated_at=?
    WHERE number=?
  `).run(
    issueNodeId,
    actorNodeId,
    input.issueUpdatedAt,
    input.issueNumber,
  );
  const comment = {
    id: 1,
    node_id: `IC_test_${input.issueNumber}_1`,
    node_type: 'IssueComment' as const,
    url: `https://example.test/issues/${input.issueNumber}#issuecomment-1`,
    user: {
      id: actorNodeId,
      login: 'reporter',
      type: 'User' as const,
    },
    author_association: null,
    body: input.body,
    created_at: createdAt,
    updated_at: createdAt,
  };
  insertClosureClaimCommentSnapshot(db, {
    issueNumber: input.issueNumber,
    issueUpdatedAt: input.issueUpdatedAt,
    comments: [{
      nodeId: comment.node_id,
      databaseId: comment.id,
      url: comment.url,
      actor: {
        nodeId: comment.user.id,
        login: comment.user.login,
        type: comment.user.type,
      },
      createdAt: comment.created_at,
      updatedAt: comment.updated_at,
      body: comment.body,
    }],
  });
  return [comment];
}

function seedClosureClaimIssueIdentity(
  db: any,
  issueNumber: number,
  issueNodeId = `I_closure_claim_${issueNumber}`,
  issueAuthorNodeId = `U_closure_claim_reporter_${issueNumber}`,
): void {
  seedIssue(db, issueNumber, null);
  db.db.prepare(`
    UPDATE issues
    SET node_id=?, author_node_id=?, author_type='User', raw_json=?
    WHERE number=?
  `).run(
    issueNodeId,
    issueAuthorNodeId,
    '{"raw":"closure-claim-issue"}',
    issueNumber,
  );
}

function closureClaimFixture(
  issueNumber: number,
  body = `Fixed by PR #${issueNumber} and PR #${issueNumber + 1} in v2026.7.4.`,
  overrides: {
    issueNodeId?: string;
    sourceNodeId?: string | null;
    actorNodeId?: string | null;
    actorLogin?: string | null;
    actorType?: string | null;
    createdAt?: string;
    updatedAt?: string;
  } = {},
) {
  const issueNodeId =
    overrides.issueNodeId ?? `I_closure_claim_${issueNumber}`;
  const source = {
    nodeId:
      overrides.sourceNodeId === undefined
        ? `IC_closure_claim_${issueNumber}`
        : overrides.sourceNodeId,
    databaseId: 800000 + issueNumber,
    url: `https://example.test/issues/${issueNumber}#issuecomment-${800000 + issueNumber}`,
    actor: {
      nodeId:
        overrides.actorNodeId === undefined
          ? 'U_closure_claim_maintainer'
          : overrides.actorNodeId,
      login:
        overrides.actorLogin === undefined
          ? 'maintainer'
          : overrides.actorLogin,
      type:
        overrides.actorType === undefined
          ? 'User'
          : overrides.actorType,
    },
    createdAt: overrides.createdAt ?? '2026-07-04T12:00:00Z',
    updatedAt: overrides.updatedAt ?? '2026-07-04T12:00:00Z',
    body,
  };
  const extraction = extractClosureClaimCandidates({
    repository: {
      nodeId: 'R_openclaw',
      nameWithOwner: 'openclaw/openclaw',
    },
    issue: {
      nodeId: issueNodeId,
      number: issueNumber,
      author: {
        nodeId: `U_closure_claim_reporter_${issueNumber}`,
        login: 'reporter',
        type: 'User',
      },
    },
    comments: [source],
  });
  return { ...extraction, fixtureComments: [source] };
}

function closureEventClaimFixture(
  issueNumber: number,
  overrides: {
    eventId?: string;
    actorNodeId?: string;
    actorLogin?: string;
    actorType?: string;
    occurredAt?: string;
  } = {},
) {
  const closureEvent = {
    nodeId: overrides.eventId ?? `CE_closure_claim_${issueNumber}`,
    actor: {
      nodeId: overrides.actorNodeId ?? 'U_closure_claim_maintainer',
      login: overrides.actorLogin ?? 'maintainer',
      type: overrides.actorType ?? 'User',
    },
    occurredAt: overrides.occurredAt ?? '2026-07-04T12:00:00Z',
    stateReason: 'COMPLETED',
    closer: {
      nodeId: `PR_closure_claim_${issueNumber}`,
      type: 'PullRequest',
      number: issueNumber,
      oid: authorityFixtureHash(`closure-${issueNumber}`).slice(0, 40),
      repositoryNameWithOwner: 'openclaw/openclaw',
    },
  };
  const extraction = extractClosureClaimCandidates({
    repository: {
      nodeId: 'R_openclaw',
      nameWithOwner: 'openclaw/openclaw',
    },
    issue: {
      nodeId: `I_closure_claim_${issueNumber}`,
      number: issueNumber,
      author: {
        nodeId: `U_closure_claim_reporter_${issueNumber}`,
        login: 'reporter',
        type: 'User',
      },
    },
    closureEvents: [closureEvent],
  });
  return { ...extraction, fixtureClosureEvents: [closureEvent] };
}

function insertClosureClaimPermissionSnapshot(
  db: any,
  actorNodeId: string,
  observedAt = '2026-07-04T11:55:00Z',
  permission = 'maintain',
) {
  const snapshot = buildRepositoryCollaboratorPermissionSnapshot({
    repositoryNodeId: 'R_openclaw',
    repository: 'openclaw/openclaw',
    observedAt,
    exhaustive: true,
    complete: true,
    totalCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    rows: [{
      nodeId: actorNodeId,
      login: 'maintainer',
      actorType: 'User',
      association: 'MEMBER',
      permission,
    }],
  });
  db.insertRepositoryCollaboratorPermissionSnapshotV2(snapshot);
  return snapshot;
}

function insertClosureClaimStateSnapshot(
  db: any,
  input: {
    issueNumber: number;
    eventId?: string;
    actorNodeId?: string;
    actorLogin?: string;
    actorType?: string;
    occurredAt?: string;
    issueUpdatedAt?: string;
  },
) {
  const issueNodeId = `I_closure_claim_${input.issueNumber}`;
  const occurredAt = input.occurredAt ?? '2026-07-04T12:00:00Z';
  const issueUpdatedAt = input.issueUpdatedAt ?? occurredAt;
  const closure = {
    issue_number: input.issueNumber,
    issue_node_id: issueNodeId,
    event_id: input.eventId ?? `CE_closure_claim_${input.issueNumber}`,
    closed_at: occurredAt,
    connection_ordinal: 0,
    actor_node_id: input.actorNodeId ?? 'U_closure_claim_maintainer',
    actor_login: input.actorLogin ?? 'maintainer',
    actor_type: input.actorType ?? 'User',
    state_reason: 'COMPLETED',
    closer_type: 'PullRequest',
    closer_number: input.issueNumber,
    closer_node_id: `PR_closure_claim_${input.issueNumber}`,
    closer_oid: authorityFixtureHash(`closure-${input.issueNumber}`).slice(0, 40),
    raw_json: JSON.stringify({
      id: input.eventId ?? `CE_closure_claim_${input.issueNumber}`,
      __typename: 'ClosedEvent',
    }),
  };
  const events = normalizeIssueStateEvents([{
    eventId: closure.event_id,
    eventNodeType: 'ClosedEvent',
    type: 'closed',
    occurredAt: closure.closed_at,
    connectionOrdinal: closure.connection_ordinal,
    actorNodeId: closure.actor_node_id,
    actorLogin: closure.actor_login,
    actorType: closure.actor_type,
    stateReason: closure.state_reason,
    closerNodeId: closure.closer_node_id,
    closerType: closure.closer_type,
    closerNumber: closure.closer_number,
    closerOid: closure.closer_oid,
  }]);
  const snapshot = authoritativeStateSnapshotFields({
    repositoryNodeId: 'R_openclaw',
    issueNumber: input.issueNumber,
    issueNodeId,
    issueState: 'closed',
    issueUpdatedAt,
    events,
  });
  db.db.prepare(`
    UPDATE issues
    SET state='closed', updated_at=?, closed_at=?
    WHERE number=?
  `).run(issueUpdatedAt, occurredAt, input.issueNumber);
  db.replaceIssueStateEventSnapshot({
    issue_number: input.issueNumber,
    issue_state: 'closed',
    issue_updated_at: issueUpdatedAt,
    total_count: events.length,
    fetched_count: events.length,
    sweep_count: 2,
    stabilized: true,
    closure_events: [closure],
    reopen_events: [],
    ...snapshot,
  });
  return closure;
}

function insertClosureClaimCommentSnapshot(
  db: any,
  input: {
    issueNumber: number;
    issueUpdatedAt: string;
    comments: Array<{
      nodeId: string | null;
      databaseId: number | null;
      url: string | null;
      actor: {
        nodeId: string | null;
        login: string | null;
        type: string | null;
      };
      createdAt: string | null;
      updatedAt: string | null;
      body: string;
    }>;
  },
) {
  const issueNodeId = `I_closure_claim_${input.issueNumber}`;
  const issue = db.getIssue(input.issueNumber);
  assert.ok(issue?.author_node_id);
  assert.ok(issue?.author_type);
  const comments = input.comments.map((comment) => {
    assert.ok(comment.nodeId);
    assert.ok(comment.databaseId);
    assert.ok(comment.actor.nodeId);
    assert.ok(comment.actor.login);
    assert.ok(comment.actor.type);
    assert.ok(comment.createdAt);
    assert.ok(comment.updatedAt);
    return {
      id: comment.databaseId,
      node_id: comment.nodeId,
      node_type: 'IssueComment' as const,
      url: comment.url,
      user: {
        id: comment.actor.nodeId,
        login: comment.actor.login,
        type: comment.actor.type,
      },
      body: comment.body,
      created_at: comment.createdAt,
      updated_at: comment.updatedAt,
    };
  });
  const snapshotIdentity = {
    repositoryNodeId: 'R_openclaw',
    issueNodeId,
    issueNodeType: 'Issue' as const,
    issueAuthor: {
      nodeId: issue.author_node_id,
      login: issue.author ?? 'tester',
      actorType: issue.author_type,
    },
  };
  const sweep = {
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: comments.length,
    comments,
    snapshotIdentity,
  };
  const firstSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = commentEvidenceSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  const stabilization = commentEvidenceStabilizationIdentity(
    firstSweep,
    secondSweep,
    2,
  );
  db.upsertIssueCommentSnapshot({
    issue_number: input.issueNumber,
    repository_node_id: 'R_openclaw',
    issue_node_id: issueNodeId,
    issue_author_node_id: issue.author_node_id,
    issue_author_login: issue.author ?? 'tester',
    issue_author_type: issue.author_type,
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    verified_at: input.issueUpdatedAt,
    comment_count: comments.length,
    fetched_comment_count: comments.length,
    latest_comment_updated_at: comments.at(-1)?.updated_at ?? null,
    comments_digest: commentEvidenceDigest(comments.length, comments),
    authority_digest: secondSweep.authorityDigest,
    issue_updated_at: input.issueUpdatedAt,
    comments_json: serializeCommentEvidence(comments),
    stabilization_json: JSON.stringify(stabilization),
    stabilization_identity_digest: stabilization.identityDigest,
  });
}

function insertClosureClaimOpenStateSnapshot(
  db: any,
  issueNumber: number,
  issueUpdatedAt: string,
) {
  const fields = authoritativeStateSnapshotFields({
    repositoryNodeId: 'R_openclaw',
    issueNumber,
    issueNodeId: `I_closure_claim_${issueNumber}`,
    issueState: 'open',
    issueUpdatedAt,
    events: [],
  });
  db.replaceIssueStateEventSnapshot({
    issue_number: issueNumber,
    issue_state: 'open',
    issue_updated_at: issueUpdatedAt,
    total_count: 0,
    fetched_count: 0,
    sweep_count: 2,
    stabilized: true,
    closure_events: [],
    reopen_events: [],
    ...fields,
  });
}

function persistClosureClaimFixture(
  db: any,
  issueNumber: number,
  extracted: ReturnType<typeof closureClaimFixture> |
    ReturnType<typeof closureEventClaimFixture>,
) {
  if ('fixtureComments' in extracted) {
    const issueUpdatedAt =
      extracted.fixtureComments.at(-1)?.updatedAt ??
      '2026-07-04T12:00:00Z';
    assert.ok(issueUpdatedAt);
    db.db.prepare(`
      UPDATE issues
      SET state='open', closed_at=NULL, comments=?, updated_at=?
      WHERE number=?
    `).run(extracted.fixtureComments.length, issueUpdatedAt, issueNumber);
    insertClosureClaimCommentSnapshot(db, {
      issueNumber,
      issueUpdatedAt,
      comments: extracted.fixtureComments,
    });
    insertClosureClaimOpenStateSnapshot(db, issueNumber, issueUpdatedAt);
  } else {
    const closureEvent = extracted.fixtureClosureEvents[0];
    assert.ok(closureEvent);
    insertClosureClaimStateSnapshot(db, {
      issueNumber,
      eventId: closureEvent.nodeId,
      actorNodeId: closureEvent.actor.nodeId,
      actorLogin: closureEvent.actor.login,
      actorType: closureEvent.actor.type,
      occurredAt: closureEvent.occurredAt,
      issueUpdatedAt: closureEvent.occurredAt,
    });
    insertClosureClaimCommentSnapshot(db, {
      issueNumber,
      issueUpdatedAt: closureEvent.occurredAt,
      comments: [],
    });
  }
  return db.persistClosureClaimExtraction({
    issueNumber,
    extraction: extracted,
    capturedAt: '2026-07-04T12:05:00Z',
  });
}

function insertRawAuthorityV2Evidence(db: any, issueNumber: number) {
  const commentFixture = authorityCommentFixture(issueNumber);
  const issueNodeId = `I_authority_${issueNumber}`;
  db.db.prepare(`
    UPDATE issues
    SET node_id=?, author_node_id=?, author_type='User', comments=1,
        updated_at=?, raw_json=?
    WHERE number=?
  `).run(
    issueNodeId,
    commentFixture.issueAuthorNodeId,
    commentFixture.issueUpdatedAt,
    '{"raw":"issue"}',
    issueNumber,
  );
  const comments = [commentFixture.comment];
  const commentSnapshotIdentity = {
    repositoryNodeId: 'R_openclaw',
    issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: commentFixture.issueAuthorNodeId,
      login: 'tester',
      actorType: 'User',
    },
  };
  const commentSweep = {
    issueUpdatedAt: commentFixture.issueUpdatedAt,
    totalCount: comments.length,
    comments,
    snapshotIdentity: commentSnapshotIdentity,
  };
  const firstCommentSweep = commentEvidenceSweepIdentity({
    ...commentSweep,
    sweepOrdinal: 1,
  });
  const secondCommentSweep = commentEvidenceSweepIdentity({
    ...commentSweep,
    sweepOrdinal: 2,
  });
  const commentStabilization = commentEvidenceStabilizationIdentity(
    firstCommentSweep,
    secondCommentSweep,
    2,
  );
  db.upsertIssueCommentSnapshot({
    issue_number: issueNumber,
    repository_node_id: 'R_openclaw',
    issue_node_id: issueNodeId,
    issue_author_node_id: commentFixture.issueAuthorNodeId,
    issue_author_login: 'tester',
    issue_author_type: 'User',
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    verified_at: commentFixture.issueUpdatedAt,
    comment_count: comments.length,
    fetched_comment_count: comments.length,
    latest_comment_updated_at: commentFixture.comment.updated_at,
    comments_digest: commentEvidenceDigest(comments.length, comments),
    authority_digest: secondCommentSweep.authorityDigest,
    issue_updated_at: commentFixture.issueUpdatedAt,
    comments_json: serializeCommentEvidence(comments),
    stabilization_json: JSON.stringify(commentStabilization),
    stabilization_identity_digest: commentStabilization.identityDigest,
  });
  const stateSnapshot = authoritativeStateSnapshotFields({
    repositoryNodeId: 'R_openclaw',
    issueNumber,
    issueNodeId,
    issueState: 'open',
    issueUpdatedAt: commentFixture.issueUpdatedAt,
    events: [],
  });
  db.replaceIssueStateEventSnapshot({
    issue_number: issueNumber,
    issue_state: 'open',
    issue_updated_at: commentFixture.issueUpdatedAt,
    total_count: 0,
    fetched_count: 0,
    sweep_count: 2,
    stabilized: true,
    closure_events: [],
    reopen_events: [],
    ...stateSnapshot,
  });
  const labelRaw = {
    __typename: 'LabeledEvent',
    id: `LE_${issueNumber}`,
    createdAt: '2026-07-04T11:58:00Z',
    label: {
      id: 'L_P1',
      name: 'P1',
    },
    actor: {
      __typename: 'User',
      id: 'U_alice',
      login: 'alice',
    },
  };
  const labelSnapshot = buildIssueLabelEvidenceSnapshot({
    schemaVersion: 2,
    repository: 'openclaw/openclaw',
    repositoryNodeId: 'R_openclaw',
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    capturedAt: '2026-07-04T12:00:00Z',
    issueUpdatedAt: '2026-07-04T11:59:00Z',
    totalCount: 1,
    fetchedCount: 1,
    pageCount: 1,
    sweepCount: 2,
    stabilized: true,
    events: [{
      issueNumber,
      issueNodeId,
      issueNodeType: 'Issue',
      eventId: `LE_${issueNumber}`,
      action: 'labeled',
      labelNodeId: 'L_P1',
      labelName: 'P1',
      actorNodeId: 'U_alice',
      actorLogin: 'alice',
      actorType: 'User',
      createdAt: '2026-07-04T11:58:00Z',
      raw: labelRaw,
    }],
  });
  db.insertIssueLabelEvidenceSnapshot(labelSnapshot);
  const labelSnapshotId = labelSnapshot.snapshotId;
  const collaboratorSnapshot = buildRepositoryCollaboratorPermissionSnapshot({
    repositoryNodeId: 'R_openclaw',
    repository: 'openclaw/openclaw',
    observedAt: '2026-07-04T11:55:00Z',
    exhaustive: true,
    complete: true,
    totalCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    rows: [{
      nodeId: 'U_alice',
      login: 'alice',
      actorType: 'User',
      association: 'MEMBER',
      permission: 'maintain',
    }],
  });
  db.insertRepositoryCollaboratorPermissionSnapshotV2(collaboratorSnapshot);
  const collaboratorSnapshotId = collaboratorSnapshot.snapshotId;
  const rosterKeyring = buildApprovedMaintainerRosterKeyring({
    schemaVersion: APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
    purpose: APPROVED_ROSTER_KEYRING_PURPOSE,
    repositoryNodeId: 'R_openclaw',
    repository: 'openclaw/openclaw',
    keys: [{
      keyId: 'operator-key-1',
      algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
      secret: Buffer.alloc(32, 17).toString('base64'),
      validFrom: '2026-01-01T00:00:00Z',
      validUntil: null,
      revokedAt: null,
    }],
  });
  const rosterSnapshot = buildApprovedMaintainerRosterSnapshot(
    signApprovedMaintainerRosterManifest({
      schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
      purpose: APPROVED_ROSTER_PURPOSE,
      repositoryNodeId: 'R_openclaw',
      repository: 'openclaw/openclaw',
      approvalId: `approval-${issueNumber}`,
      approvedAt: '2026-07-04T11:50:00Z',
      sequence: 1,
      priorDigest: null,
      signerKeyId: 'operator-key-1',
      entries: [{
        actorNodeId: 'U_alice',
        login: 'alice',
        actorType: 'User',
        association: 'MEMBER',
        role: 'maintain',
        effectiveFrom: '2026-01-01T00:00:00Z',
        effectiveUntil: null,
      }],
    }, rosterKeyring),
    {
      keyring: rosterKeyring,
      expectedRepositoryNodeId: 'R_openclaw',
      previousState: null,
      verifiedAt: '2026-07-04T11:51:00Z',
    },
  );
  db.insertSignedApprovedMaintainerRosterSnapshot(rosterSnapshot);
  const extracted = extractClosureClaimCandidates({
    repository: {
      nodeId: 'R_openclaw',
      nameWithOwner: 'openclaw/openclaw',
    },
    issue: {
      nodeId: issueNodeId,
      number: issueNumber,
      author: {
        nodeId: commentFixture.issueAuthorNodeId,
        login: 'tester',
        type: 'User',
      },
    },
    comments: [{
      nodeId: commentFixture.comment.node_id,
      databaseId: commentFixture.comment.id,
      url: commentFixture.comment.url,
      actor: {
        nodeId: commentFixture.comment.user.id,
        login: commentFixture.comment.user.login,
        type: commentFixture.comment.user.type,
      },
      createdAt: commentFixture.comment.created_at,
      updatedAt: commentFixture.comment.updated_at,
      body: commentFixture.comment.body,
    }],
  });
  assert.deepEqual(extracted.rejections, []);
  db.persistClosureClaimExtraction({
    issueNumber,
    extraction: extracted,
    capturedAt: '2026-07-04T12:00:00Z',
  });
  const candidateId = extracted.candidates.find((candidate) =>
    candidate.claimKind === 'fix_proof' &&
    candidate.claim.kind === 'fix_proof' &&
    candidate.claim.proofType === 'pull_request'
  )?.candidateId;
  assert.ok(candidateId);
  return {
    issueNodeId,
    labelSnapshotId,
    collaboratorSnapshotId,
    rosterSnapshotId: rosterSnapshot.snapshotId,
    candidateId,
  };
}

function insertDerivedAuthorityV2Publication(
  db: any,
  issueNumber: number,
  releaseTag: string,
) {
  const authorityRunId = `authority-run-${issueNumber}`;
  const historyRunId = `history-run-${issueNumber}`;
  const recordedAt = '2026-07-04T12:05:00.000Z';
  const sourceIdentity = db.scoreSourceIdentity();
  const labelResolution = buildScoreAuthorityResolution(
    db.labelAuthorityEvidenceForEvent(`LE_${issueNumber}`),
  );
  const commentFixture = authorityCommentFixture(issueNumber);
  const commentResolution = buildScoreCommentAuthorityResolution({
    issueNumber,
    issueNodeId: commentFixture.issueNodeId,
    issueAuthorNodeId: commentFixture.issueAuthorNodeId,
    issueAuthorType: 'User',
    commentNodeId: commentFixture.comment.node_id,
    commentId: commentFixture.comment.id,
    commentUrl: commentFixture.comment.url,
    actorNodeId: commentFixture.comment.user.id,
    actorType: 'User',
    commentCreatedAt: commentFixture.comment.created_at,
    commentUpdatedAt: commentFixture.comment.updated_at,
    commentBodyDigest: scoreCommentBodyDigest(commentFixture.comment.body),
    claimSnippet: commentFixture.comment.body,
  });
  const authorityRun = buildScoreAuthorityResolutionRun({
    authorityRunId,
    sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
    sourceIdentityDigest: sourceIdentity.digest,
    recordedAt,
    previousContentHash:
      db.listScoreAuthorityResolutionRuns().at(-1)?.contentHash ?? null,
    rows: [
      {
        releaseTag: null,
        issueNumber,
        subjectKind: 'label_event',
        subjectIdentity: labelResolution.eventId,
        candidateId: null,
        resolution: labelResolution,
      },
      {
        releaseTag: null,
        issueNumber,
        subjectKind: 'comment',
        subjectIdentity: commentResolution.commentNodeId,
        candidateId: null,
        resolution: commentResolution,
      },
    ],
  });
  db.insertScoreAuthorityResolutionRun(authorityRun);
  const audit = {
    release_tag: releaseTag,
    scored_at: recordedAt,
    score_model_version: 'authority-v2-test',
    prompt_version: 1,
    final_score: 8,
    status: 'eligible',
    band: 'good',
    recommended: 1,
    input_json: '{"schemaVersion":1}',
    components_json: '{"schemaVersion":1}',
    issue_evidence_json: '{"schemaVersion":1}',
    gate_evidence_json: '{"schemaVersion":1}',
    source_identity_json: JSON.stringify(sourceIdentity),
    authority_run_id: authorityRunId,
  };
  db.upsertReleaseScoreAudit(audit);
  db.insertReleaseScoreAuditHistory(historyRunId, recordedAt, audit);
  db.sealReleaseScoreAuditHistoryRun(historyRunId, recordedAt);
  db.sealReleaseScoreAuditHistoryV2({
    historyRunId,
    authorityRunId,
    sealedAt: recordedAt,
  });
  return { authorityRunId, historyRunId, sourceIdentity };
}

function seedClosureProof(
  db: any,
  tag: string,
  issue: number,
  status = 'fixed_in_release',
  evidence: Record<string, unknown> = {},
) {
  db.upsertIssueClosureProof({
    release_tag: tag,
    issue_number: issue,
    status,
    summary: 'Test closure proof.',
    evidence_json: JSON.stringify(evidence),
  });
}

function trustedProofPr(prNumber: number, overrides: Record<string, unknown> = {}) {
  return {
    number: prNumber,
    repositoryNameWithOwner: `${config.github.owner}/${config.github.repo}`,
    source: 'ClosureComment.fixProof',
    trustedFixProof: 1,
    merged: 1,
    ...overrides,
  };
}

function strictPrReachabilityEvidence(
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
  mergeCommitOid: string,
  catalogProof?: Record<string, unknown>,
) {
  return {
    schemaVersion: 1,
    evidence: status === 'reachable'
      ? 'merge_commit_in_release_history'
      : 'not_reachable_from_release_tag',
    method: 'git-merge-base',
    ...(catalogProof ? { catalogProof } : {}),
    tagCommitOid,
    checkedCommitOid: mergeCommitOid,
    baseRefName: 'main',
    commandStatus: status === 'reachable' ? 0 : 1,
    stdout: null,
    stderr: null,
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    aborted: false,
  };
}

function strictUnknownPrReachabilityEvidence(
  tagCommitOid: string,
  reason = 'merge_commit_oid_unavailable',
  catalogProof?: Record<string, unknown>,
) {
  return {
    schemaVersion: 1,
    evidence: reason,
    method: 'git-merge-base',
    ...(catalogProof ? { catalogProof } : {}),
    tagCommitOid,
    checkedCommitOid: null,
    baseRefName: 'main',
    commandStatus: null,
    stdout: null,
    stderr: null,
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    aborted: false,
  };
}

function strictUnknownPrReachabilityErrorEvidence(
  tagCommitOid: string,
  mergeCommitOid: string,
  catalogProof?: Record<string, unknown>,
) {
  return {
    schemaVersion: 1,
    evidence: 'merge_base_error',
    method: 'git-merge-base',
    ...(catalogProof ? { catalogProof } : {}),
    tagCommitOid,
    checkedCommitOid: mergeCommitOid,
    baseRefName: 'main',
    commandStatus: 2,
    stdout: null,
    stderr: 'git merge-base failed',
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    aborted: false,
  };
}

function testReleaseCatalogProof(db: any, tag: string) {
  const authorized = db.readAuthorizedReleaseReachabilityData({
    integrityExampleLimit: 0,
  });
  const release = authorized.releases.find(
    (candidate: any) => candidate.tag === tag,
  );
  assert.ok(release);
  return {
    catalogDigest: authorized.catalog.digest,
    catalogReceiptId: authorized.catalog.receiptId,
    releaseNodeId: release.releaseNodeId,
    checkedReleaseNodeId: null,
  };
}

function strictDirectReachabilityEvidence(
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
  checkedCommitOid: string,
  evidence:
    | 'fix_commit_in_release_history'
    | 'predecessor_release_in_target_history'
    | 'not_reachable_from_release_tag',
  catalogProof: Record<string, unknown>,
) {
  return {
    schemaVersion: 1,
    evidence,
    method: 'git-merge-base',
    repositoryNameWithOwner: `${config.github.owner}/${config.github.repo}`,
    catalogProof,
    tagCommitOid,
    checkedCommitOid,
    baseRefName: null,
    commandStatus: status === 'reachable' ? 0 : 1,
    stdout: null,
    stderr: null,
    signal: null,
    timedOut: false,
    outputLimitExceeded: false,
    aborted: false,
  };
}

function strictDirectFirstContainingProof(db: any, input: {
  commitOid: string;
  targetTag?: string;
  targetTagCommitOid?: string;
  predecessorTag?: string;
  predecessorTagCommitOid?: string;
  predecessorContainsCommit?: boolean;
}) {
  const targetTag = input.targetTag ?? 'v-target';
  const predecessorTag = input.predecessorTag ?? 'v-boundary';
  const authorized = db.readAuthorizedReleaseReachabilityData({
    integrityExampleLimit: 0,
  });
  const stableReleases = authorized.releases.filter(
    (release: any) => !release.prerelease,
  );
  const targetIndex = stableReleases.findIndex(
    (release: any) => release.tag === targetTag,
  );
  const targetRelease = stableReleases[targetIndex];
  const predecessorRelease = stableReleases[targetIndex + 1];
  assert.ok(targetRelease);
  assert.equal(predecessorRelease?.tag, predecessorTag);
  const olderReleases = stableReleases.slice(targetIndex + 1).reverse();
  const targetTagCommitOid =
    input.targetTagCommitOid ?? targetRelease.resolvedTagCommitOid;
  const predecessorTagCommitOid =
    input.predecessorTagCommitOid ?? predecessorRelease.resolvedTagCommitOid;
  assert.match(targetTagCommitOid, /^[0-9a-f]{40}$/);
  assert.match(predecessorTagCommitOid, /^[0-9a-f]{40}$/);
  const predecessorContainsCommit = input.predecessorContainsCommit === true;
  const catalogProof = (
    release: any,
    checkedRelease: any = null,
  ) => ({
    catalogDigest: authorized.catalog.digest,
    catalogReceiptId: authorized.catalog.receiptId,
    releaseNodeId: release.releaseNodeId,
    checkedReleaseNodeId: checkedRelease?.releaseNodeId ?? null,
  });
  const directProof = (
    release: any,
    status: 'reachable' | 'not_reachable',
  ) => {
    const tagCommitOid = release.resolvedTagCommitOid;
    const proofIdentity = catalogProof(release);
    assert.match(tagCommitOid, /^[0-9a-f]{40}$/);
    return {
      releaseNodeId: release.releaseNodeId,
      tag: release.tag,
      catalogRank: release.catalogRank,
      catalogDigest: authorized.catalog.digest,
      catalogReleaseCount: authorized.catalog.releaseCount,
      catalogProof: proofIdentity,
      status,
      tagCommitOid,
      checkedCommitOid: input.commitOid,
      method: 'git-merge-base',
      evidence: strictDirectReachabilityEvidence(
        status,
        tagCommitOid,
        input.commitOid,
        status === 'reachable'
          ? 'fix_commit_in_release_history'
          : 'not_reachable_from_release_tag',
        proofIdentity,
      ),
      strictValid: true,
      validationReasonCode: null,
    };
  };
  const olderProofs = olderReleases.map((release: any) =>
    directProof(
      release,
      predecessorContainsCommit && release.tag === predecessorTag
        ? 'reachable'
        : 'not_reachable',
    ));
  const predecessorProof = olderProofs.at(-1);
  assert.ok(predecessorProof);
  const targetProofIdentity = catalogProof(targetRelease);
  const releaseAncestryProofIdentity =
    catalogProof(targetRelease, predecessorRelease);
  return {
    schemaVersion: 1,
    kind: 'direct_commit',
    repositoryNameWithOwner: `${config.github.owner}/${config.github.repo}`,
    commitOid: input.commitOid,
    targetTag,
    predecessorTag,
    status: predecessorContainsCommit ? 'withheld' : 'credited',
    reasonCode: predecessorContainsCommit
      ? 'predecessor_contains_commit'
      : 'first_containing_direct_commit',
    creditEligible: !predecessorContainsCommit,
    catalogIdentity: {
      catalogDigest: authorized.catalog.digest,
      catalogReceiptId: authorized.catalog.receiptId,
      targetReleaseNodeId: targetRelease.releaseNodeId,
      predecessorReleaseNodeId: predecessorRelease.releaseNodeId,
    },
    target: {
      releaseNodeId: targetRelease.releaseNodeId,
      tag: targetTag,
      catalogRank: targetRelease.catalogRank,
      catalogDigest: authorized.catalog.digest,
      catalogReleaseCount: authorized.catalog.releaseCount,
      catalogProof: targetProofIdentity,
      status: 'reachable',
      tagCommitOid: targetTagCommitOid,
      checkedCommitOid: input.commitOid,
      method: 'git-merge-base',
      evidence: strictDirectReachabilityEvidence(
        'reachable',
        targetTagCommitOid,
        input.commitOid,
        'fix_commit_in_release_history',
        targetProofIdentity,
      ),
      strictValid: true,
      validationReasonCode: null,
    },
    predecessor: predecessorProof,
    olderReleases: olderProofs,
    releaseAncestry: {
      releaseNodeId: targetRelease.releaseNodeId,
      tag: targetTag,
      catalogRank: targetRelease.catalogRank,
      catalogDigest: authorized.catalog.digest,
      catalogReleaseCount: authorized.catalog.releaseCount,
      catalogProof: releaseAncestryProofIdentity,
      status: 'reachable',
      tagCommitOid: targetTagCommitOid,
      checkedCommitOid: predecessorTagCommitOid,
      method: 'git-merge-base',
      evidence: strictDirectReachabilityEvidence(
        'reachable',
        targetTagCommitOid,
        predecessorTagCommitOid,
        'predecessor_release_in_target_history',
        releaseAncestryProofIdentity,
      ),
      strictValid: true,
      validationReasonCode: null,
    },
    failure: null,
  };
}

function directCommitClosureEvidence(
  proof: ReturnType<typeof strictDirectFirstContainingProof>,
) {
  return {
    hasReachableFixCommit: proof.creditEligible,
    reachableFixCommits: proof.creditEligible ? [proof.commitOid] : [],
    fixCommitProof: [{
      commitOid: proof.commitOid,
      creditEligible: true,
    }],
    predecessorContainedFixCommits: proof.reasonCode === 'predecessor_contains_commit'
      ? [proof.commitOid]
      : [],
    firstContainingUnknownFixCommits: [],
    directCommitFirstContainingProofs: [proof],
  };
}

function seedFirstContainingFixMatrix(db: any, input: {
  issueNumber: number;
  prNumber: number;
  releases: Array<readonly [
    tag: string,
    publishedAt: string,
    status: 'reachable' | 'not_reachable' | null,
  ]>;
}): void {
  const mergeCommitOid = 'f'.repeat(40);
  seedIssue(db, input.issueNumber);
  db.upsertIssuePrLink({
    issue_number: input.issueNumber,
    pr_number: input.prNumber,
    source: 'ClosureComment.fixProof',
    will_close_target: 1,
    referenced_at: input.releases.at(-1)?.[1] ?? null,
  });
  db.upsertPullRequestFix({
    pr_number: input.prNumber,
    title: `fix ${input.issueNumber}`,
    url: `https://example.test/pull/${input.prNumber}`,
    state: 'MERGED',
    merged: 1,
    merged_at: input.releases.at(-1)?.[1] ?? null,
    merge_commit_oid: mergeCommitOid,
    base_ref_name: 'main',
  });
  db.replaceActiveReleaseCatalog(
    input.releases
      .map(([tag, publishedAt], index) =>
        catalogRelease(
          tag,
          publishedAt,
          false,
          `${index + 1}`.repeat(40),
        ))
      .reverse(),
  );
  input.releases.forEach(([tag, publishedAt, status], index) => {
    const tagCommitOid = `${index + 1}`.repeat(40);
    db.upsertReleaseCommit({
      tag,
      tag_commit_oid: tagCommitOid,
      committed_at: publishedAt,
    });
    if (!status) return;
    const authorized = db.readAuthorizedReleaseReachabilityData({
      integrityExampleLimit: 0,
    });
    const release = authorized.releases.find(
      (candidate: any) => candidate.tag === tag,
    );
    assert.ok(release);
    const proofIdentity = {
      catalogDigest: authorized.catalog.digest,
      catalogReceiptId: authorized.catalog.receiptId,
      releaseNodeId: release.releaseNodeId,
      checkedReleaseNodeId: null,
    };
    db.upsertReleasePrReachability({
      tag,
      pr_number: input.prNumber,
      tag_commit_oid: tagCommitOid,
      merge_commit_oid: mergeCommitOid,
      base_ref_name: 'main',
      status,
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        status,
        tagCommitOid,
        mergeCommitOid,
        proofIdentity,
      )),
    });
  });
  const targetTag = input.releases.at(-1)?.[0];
  if (targetTag) {
    seedClosureProof(db, targetTag, input.issueNumber, 'fixed_in_release', {
      linkedPrs: [trustedProofPr(input.prNumber)],
    });
  }
}

function seedReopen(db: any, issue: number, reopenedAt = '2026-06-02T12:00:00Z') {
  db.upsertIssueReopenEvent({
    issue_number: issue,
    event_id: `reopened-${issue}-${reopenedAt}`,
    reopened_at: reopenedAt,
    actor_login: 'maintainer',
    raw_json: '{}',
  });
}

describe('release fix provenance', () => {
  it('supports nested write transactions with savepoint rollback', async () => {
    const db = await freshDb('nested-write-transactions');

    db.runInWriteTransaction(() => {
      seedRawRelease(db, 'v-outer');
      assert.throws(() => {
        db.runInWriteTransaction(() => {
          seedRawRelease(db, 'v-inner');
          throw new Error('inner failure');
        });
      }, /inner failure/);
      seedRawRelease(db, 'v-after-inner');
    });

    assert.ok(db.getRelease('v-outer'));
    assert.equal(db.getRelease('v-inner'), undefined);
    assert.ok(db.getRelease('v-after-inner'));

    assert.throws(() => {
      db.runInWriteTransaction(() => {
        seedRawRelease(db, 'v-outer-fail');
        db.runInWriteTransaction(() => {
          seedRawRelease(db, 'v-inner-commit');
        });
        throw new Error('outer failure');
      });
    }, /outer failure/);

    assert.equal(db.getRelease('v-outer-fail'), undefined);
    assert.equal(db.getRelease('v-inner-commit'), undefined);
  });

  it('rejects asynchronous transaction callbacks before they can escape the transaction', async () => {
    const db = await freshDb('synchronous-transaction-callbacks');
    let writeCallbackRan = false;
    let readCallbackRan = false;

    assert.throws(
      () => db.runInWriteTransaction(async () => {
        writeCallbackRan = true;
        seedRawRelease(db, 'v-async-write');
      }),
      /Write transaction callbacks must be synchronous/,
    );
    assert.throws(
      () => db.runInReadTransaction(async () => {
        readCallbackRan = true;
        return db.listReleasesDb(1);
      }),
      /Read transaction callbacks must be synchronous/,
    );
    assert.equal(writeCallbackRan, false);
    assert.equal(readCallbackRan, false);
    assert.equal(db.getRelease('v-async-write'), undefined);

    assert.throws(
      () => db.runInWriteTransaction((() => {
        seedRawRelease(db, 'v-promise-write');
        return Promise.resolve();
      }) as () => void),
      /Write transaction callbacks must not return a promise/,
    );
    assert.equal(db.getRelease('v-promise-write'), undefined);
  });

  it('enforces read transactions at the SQLite boundary and restores write access', async () => {
    const db = await freshDb('read-transaction-enforcement');

    assert.throws(
      () => db.runInReadTransaction(() => {
        seedRawRelease(db, 'v-read-write');
      }),
      /read.?only/i,
    );
    assert.equal(db.getRelease('v-read-write'), undefined);

    assert.throws(
      () => db.runInReadTransaction(() => {
        db.runInWriteTransaction(() => {
          seedRawRelease(db, 'v-nested-read-write');
        });
      }),
      /Cannot start a write transaction inside a read transaction/,
    );
    assert.equal(db.getRelease('v-nested-read-write'), undefined);

    db.db.exec('PRAGMA query_only=ON');
    try {
      assert.deepEqual(
        db.runInReadTransaction(() =>
          db.db.prepare('SELECT tag FROM releases ORDER BY tag').all()),
        [],
      );
      assert.equal(
        Number((db.db.prepare('PRAGMA query_only').get() as any).query_only),
        1,
      );
    } finally {
      db.db.exec('PRAGMA query_only=OFF');
    }

    db.runInWriteTransaction(() => {
      seedRawRelease(db, 'v-after-read');
      assert.deepEqual(
        db.runInReadTransaction(() =>
          db.db.prepare('SELECT tag FROM releases ORDER BY tag')
            .all()
            .map((row: any) => row.tag)),
        ['v-after-read'],
      );
    });
    assert.ok(db.getRelease('v-after-read'));
  });

  it('serializes refresh ownership across processes with an expiring database lease', async () => {
    const db = await freshDb('refresh-lease');
    assert.equal(db.REFRESH_WRITE_LEASE_TTL_MS, 300_000);
    assert.equal(
      db.acquireRefreshLease(
        'github-refresh',
        'run-1',
        '2026-06-01T00:00:00Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      true,
    );
    assert.equal(
      db.acquireRefreshLease(
        'github-refresh',
        'run-2',
        '2026-06-01T00:04:59Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      false,
    );
    assert.deepEqual(db.listRefreshLeases().map((row) => ({ ...row })), [{
      name: 'github-refresh',
      holder_id: 'run-1',
      acquired_at: '2026-06-01T00:00:00Z',
      expires_at: '2026-06-01T00:05:00.000Z',
    }]);
    assert.equal(
      db.renewRefreshLease(
        'github-refresh',
        'run-1',
        '2026-06-01T00:01:00Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      true,
    );
    assert.equal(db.listRefreshLeases()[0].expires_at, '2026-06-01T00:06:00.000Z');
    assert.equal(
      db.renewRefreshLease(
        'github-refresh',
        'run-1',
        '2026-06-01T00:06:00Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      false,
    );
    assert.equal(db.releaseRefreshLease('github-refresh', 'run-2'), false);
    assert.equal(db.releaseRefreshLease('github-refresh', 'run-1'), true);
    assert.deepEqual(db.listRefreshLeases(), []);
    assert.equal(
      db.acquireRefreshLease(
        'github-refresh',
        'run-2',
        '2026-06-01T00:01:01Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      true,
    );
    assert.equal(
      db.acquireRefreshLease(
        'github-refresh',
        'run-3',
        '2026-06-01T00:06:01Z',
        db.REFRESH_WRITE_LEASE_TTL_MS,
      ),
      true,
    );
  });

  it('rejects a regressing refresh stage prefix before inserting it', async () => {
    const db = await freshDb('refresh-stage-prefix-regression');
    const nowMs = Date.now();
    const startedAt = new Date(nowMs - 10_000).toISOString();
    const leaseName = 'refresh-stage-prefix-regression';
    const holderId = 'holder-stage-prefix-regression';
    const runId = 'run-stage-prefix-regression';
    db.insertRefreshOperationAttempt({
      run_id: runId,
      operation: 'refresh',
      trigger: 'test',
      started_at: startedAt,
      lease_name: leaseName,
      lease_holder_id: holderId,
      lease_expires_at: new Date(nowMs + 300_000).toISOString(),
      code_revision: 'stage-prefix-revision',
      effective_config: { schemaVersion: 1 },
    });
    assert.equal(db.acquireRefreshLease(
      leaseName,
      holderId,
      new Date(nowMs - 9_000).toISOString(),
      300_000,
    ), true);
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: holderId,
      stage: 'release.fetch',
      status: 'started',
      occurred_at: new Date(nowMs - 8_000).toISOString(),
    });
    db.appendRefreshOperationStageEvent({
      run_id: runId,
      lease_name: leaseName,
      lease_holder_id: holderId,
      stage: 'release.fetch',
      status: 'completed',
      occurred_at: new Date(nowMs - 6_000).toISOString(),
      duration_ms: 2_000,
    });

    assert.throws(
      () => db.appendRefreshOperationStageEvent({
        run_id: runId,
        lease_name: leaseName,
        lease_holder_id: holderId,
        stage: 'score.persist',
        status: 'started',
        occurred_at: new Date(nowMs - 7_000).toISOString(),
      }),
      /stage prefix semantic validation failed.*timestamps are not nondecreasing/,
    );
    assert.deepEqual(
      db.listRefreshOperationStageEvents(runId).map((event) => [
        event.sequence,
        event.stage,
        event.status,
      ]),
      [
        [1, 'release.fetch', 'started'],
        [2, 'release.fetch', 'completed'],
      ],
    );
    assert.equal(db.releaseRefreshLease(leaseName, holderId), true);
  });

  it('fails before opening an unsafe database in direct test contexts', async () => {
    const databaseModule = await freshDb('package-lifecycle-authorization');
    const probeEnvironmentKeys = [
      'DB_PATH',
      'NODE_ENV',
      'NODE_TEST_CONTEXT',
      'RADAR_TEST_WRITER_LOCK_PID',
      'RADAR_TEST_WRITER_LEASE_PATH',
      'RADAR_TEST_WRITER_LOCK_TOKEN',
      'RADAR_DB_BOOTSTRAP_MODE',
      'RADAR_DB_READ_ONLY',
      'DOTENV_CONFIG_OVERRIDE',
      'DOTENV_CONFIG_PATH',
    ] as const;
    const applyProbeEnvironment = `
      const probeEnvironment = JSON.parse(
        Buffer.from(
          process.env.RADAR_DB_PROBE_ENVIRONMENT_B64 ?? 'e30=',
          'base64',
        ).toString('utf8'),
      );
      delete process.env.RADAR_DB_PROBE_ENVIRONMENT_B64;
      for (const [name, value] of Object.entries(probeEnvironment)) {
        if (value === null) delete process.env[name];
        else process.env[name] = String(value);
      }
    `;
    const importScript = `
      ${applyProbeEnvironment}
      try {
        const database = require('./src/lib/db.ts');
        (database.db ?? database.default?.db).close();
      } catch (error) {
        console.error(error instanceof Error ? error.message : String(error));
        process.exitCode = 1;
      }
    `;
    const baseEnv = { ...process.env };
    for (const key of [
      'DB_PATH',
      'NODE_ENV',
      'NODE_TEST_CONTEXT',
      'RADAR_TEST_RUN_ID',
      'RADAR_TEST_WORKER_DB_PATH',
      'RADAR_TEST_WORKER_DB_ASSIGNED',
      'RADAR_TEST_DB_AUDIT',
      'RADAR_TEST_LIVE_DB',
      'RADAR_TEST_ALLOWED_DB_ROOTS',
      'RADAR_TEST_TEMP_ROOT',
      'RADAR_TEST_PROCESS_LOCK_ROOT',
      'RADAR_TEST_WRITER_LOCK_PID',
      'RADAR_TEST_WRITER_LEASE_PATH',
      'RADAR_TEST_WRITER_LOCK_TOKEN',
      'RADAR_DB_BOOTSTRAP_MODE',
      'RADAR_DB_READ_ONLY',
      'DOTENV_CONFIG_OVERRIDE',
    ]) {
      delete baseEnv[key];
    }
    baseEnv.DOTENV_CONFIG_PATH = '/dev/null';
    const inheritedWriterToken =
      process.env.RADAR_TEST_WRITER_LOCK_TOKEN?.trim();
    const inheritedWriterPid =
      process.env.RADAR_TEST_WRITER_LOCK_PID?.trim();
    const inheritedWriterLeasePath =
      process.env.RADAR_TEST_WRITER_LEASE_PATH?.trim();
    const inheritedWriterRunId = process.env.RADAR_TEST_RUN_ID?.trim();
    const inheritedWriterTempRoot =
      process.env.RADAR_TEST_TEMP_ROOT?.trim();
    const inheritedWriterProcessLockRoot =
      process.env.RADAR_TEST_PROCESS_LOCK_ROOT?.trim();
    assert.ok(
      [inheritedWriterToken, inheritedWriterPid, inheritedWriterLeasePath]
        .every(Boolean) ||
      [inheritedWriterToken, inheritedWriterPid, inheritedWriterLeasePath]
        .every((value) => !value),
      'suite writer lease path, token, and pid must be inherited together',
    );
    assert.ok(
      [
        inheritedWriterToken,
        inheritedWriterPid,
        inheritedWriterLeasePath,
        inheritedWriterRunId,
        inheritedWriterTempRoot,
        inheritedWriterProcessLockRoot,
      ].every(Boolean) ||
      [
        inheritedWriterToken,
        inheritedWriterPid,
        inheritedWriterLeasePath,
        inheritedWriterRunId,
        inheritedWriterTempRoot,
        inheritedWriterProcessLockRoot,
      ].every((value) => !value),
      'suite writer authority and protected runner context must be inherited together',
    );
    const inheritedWriterAuthority =
      inheritedWriterToken &&
      inheritedWriterPid &&
      inheritedWriterLeasePath &&
      inheritedWriterRunId &&
      inheritedWriterTempRoot &&
      inheritedWriterProcessLockRoot
        ? {
            RADAR_TEST_RUN_ID: inheritedWriterRunId,
            RADAR_TEST_TEMP_ROOT: inheritedWriterTempRoot,
            RADAR_TEST_PROCESS_LOCK_ROOT: inheritedWriterProcessLockRoot,
            RADAR_TEST_WRITER_LOCK_PID: inheritedWriterPid,
            RADAR_TEST_WRITER_LEASE_PATH: inheritedWriterLeasePath,
            RADAR_TEST_WRITER_LOCK_TOKEN: inheritedWriterToken,
          }
        : {};
    const inheritedWriterLeaseAuthority =
      inheritedWriterToken &&
      inheritedWriterPid &&
      inheritedWriterLeasePath
        ? {
            RADAR_TEST_WRITER_LOCK_PID: inheritedWriterPid,
            RADAR_TEST_WRITER_LEASE_PATH: inheritedWriterLeasePath,
            RADAR_TEST_WRITER_LOCK_TOKEN: inheritedWriterToken,
          }
        : {};

    const probeLaunchEnvironment = (
      environment: NodeJS.ProcessEnv,
    ): NodeJS.ProcessEnv => {
      const probeEnvironment = Object.fromEntries(
        probeEnvironmentKeys.map((key) => [
          key,
          Object.prototype.hasOwnProperty.call(environment, key)
            ? environment[key] ?? null
            : null,
        ]),
      );
      const requestedDatabase = environment.DB_PATH;
      const repositoryLiveDatabase = join(root, 'data', 'radar.db');
      const launchDatabase =
        requestedDatabase && requestedDatabase !== repositoryLiveDatabase
          ? requestedDatabase
          : process.env.DB_PATH;
      const probeContext =
        environment.NODE_TEST_CONTEXT ||
        environment.RADAR_TEST_RUN_ID ||
        environment.NODE_ENV === 'test'
          ? 'test'
          : 'evaluation';
      assert.ok(
        launchDatabase,
        'guarded database probe requires an inherited private DB_PATH',
      );
      return {
        ...process.env,
        DB_PATH: launchDatabase,
        ESBUILD_WORKER_THREADS: '0',
        RADAR_TEST_DATABASE_POLICY_PROBE: '1',
        RADAR_TEST_DATABASE_POLICY_PROBE_CONTEXT: probeContext,
        RADAR_DB_PROBE_ENVIRONMENT_B64: Buffer.from(
          JSON.stringify(probeEnvironment),
          'utf8',
        ).toString('base64'),
      };
    };

    const runImport = (environment: NodeJS.ProcessEnv) => spawnSync(
      process.execPath,
      ['--require', 'tsx/cjs', '-e', importScript],
      {
        cwd: root,
        env: probeLaunchEnvironment(environment),
        encoding: 'utf8',
      },
    );

    const missingPath = runImport({
      ...baseEnv,
      NODE_TEST_CONTEXT: 'child-v8',
    });
    assert.notEqual(missingPath.status, 0);
    assert.match(
      missingPath.stderr,
      /DB_PATH is required in test contexts; refusing to fall back to data\/radar\.db/,
    );

    const livePath = runImport({
      ...baseEnv,
      DB_PATH: join(root, 'data', 'radar.db'),
      NODE_ENV: 'test',
    });
    assert.notEqual(livePath.status, 0);
    assert.match(
      livePath.stderr,
      /Refusing to open a configured application database in a test context/,
    );

    const missingEvaluationPath = runImport({
      ...baseEnv,
    });
    assert.notEqual(missingEvaluationPath.status, 0);
    assert.match(
      missingEvaluationPath.stderr,
      /DB_PATH is required in ad hoc evaluation contexts; refusing to fall back to data\/radar\.db/,
    );

    const liveEvaluationPath = runImport({
      ...baseEnv,
      DB_PATH: join(root, 'data', 'radar.db'),
    });
    assert.notEqual(liveEvaluationPath.status, 0);
    assert.match(
      liveEvaluationPath.stderr,
      /Refusing to open a configured application database in an ad hoc evaluation context/,
    );

    const probeDatabaseRoot = dirname(process.env.DB_PATH!);
    const probeDbPath = (name: string) => join(
      mkdtempSync(join(probeDatabaseRoot, `policy-${name}-`)),
      'radar.db',
    );
    const testDatabasePath = probeDbPath('structural-test-db-guard');
    const evaluationDatabasePath = probeDbPath('structural-evaluation-db-guard');
    const normalDatabasePath = probeDbPath('structural-normal-db-startup');
    const missingDotenvDatabasePath = probeDbPath('structural-missing-dotenv');
    const nonEmptyDotenvDatabasePath = probeDbPath('structural-nonempty-dotenv');
    const dotenvSafeDatabasePath = probeDbPath('structural-dotenv-safe-path');
    const dotenvAttackDatabasePath = probeDbPath('structural-dotenv-attack-path');
    const existingTestDatabasePath = probeDbPath('structural-existing-test-db');
    const existingEvaluationDatabasePath = probeDbPath(
      'structural-existing-evaluation-db',
    );
    const existingAttestationDatabasePath = probeDbPath(
      'structural-existing-attestation',
    );
    const freshAttestationDatabasePath = probeDbPath(
      'structural-fresh-attestation',
    );
    const journalDatabasePath = probeDbPath('structural-journal-family');
    const nonPrivateTestDatabasePath = probeDbPath('structural-non-private-test');
    const nonPrivateEvaluationDatabasePath = probeDbPath(
      'structural-non-private-evaluation',
    );
    const inheritedWriterDatabasePath = probeDbPath('structural-inherited-writer');
    const missingWriterLeaseDatabasePath = probeDbPath(
      'structural-missing-writer-lease',
    );
    const forgedWriterDatabasePath = probeDbPath('structural-forged-writer');
    const nonEmptyDotenvPath = join(
      dirname(nonEmptyDotenvDatabasePath),
      'non-empty.env',
    );
    const dotenvOverridePath = join(
      dirname(dotenvSafeDatabasePath),
      'override.env',
    );
    const normalProcessScriptPath = join(
      dirname(normalDatabasePath),
      'open-database.mts',
    );
    const packageLifecycleNpmCliPath = join(
      dirname(testDatabasePath),
      'npm-cli.js',
    );
    writeFileSync(nonEmptyDotenvPath, 'UNSAFE=1\n');
    writeFileSync(
      dotenvOverridePath,
      `DB_PATH=${dotenvAttackDatabasePath}\n`,
    );
    writeFileSync(existingTestDatabasePath, '');
    writeFileSync(existingEvaluationDatabasePath, '');
    writeFileSync(`${journalDatabasePath}-journal`, '');
    chmodSync(dirname(nonPrivateTestDatabasePath), 0o755);
    chmodSync(dirname(nonPrivateEvaluationDatabasePath), 0o755);
    writeFileSync(
      normalProcessScriptPath,
      `
        ${applyProbeEnvironment}
        const imported = await import(${JSON.stringify(
          pathToFileURL(join(root, 'src', 'lib', 'db.ts')).href,
        )});
        const database = imported.default ?? imported;
        database.db.close();
      `,
    );
    try {
      const sqliteHeader = Buffer.alloc(4096);
      sqliteHeader.write('SQLite format 3\0', 0, 'binary');
      writeFileSync(existingAttestationDatabasePath, sqliteHeader, {
        flag: 'wx',
        mode: 0o600,
      });
      writeFileSync(packageLifecycleNpmCliPath, '', { mode: 0o600 });
      const packageLifecycleEnvironment = (
        event: string,
        script: string,
      ): NodeJS.ProcessEnv => ({
        npm_execpath: packageLifecycleNpmCliPath,
        npm_lifecycle_event: event,
        npm_lifecycle_script: script,
        npm_node_execpath: process.execPath,
        npm_package_json: join(root, 'package.json'),
      });
      const directAuthorization =
        databaseModule.inspectPackageLifecycleAuthorization({
          entrypoint: join(root, 'scripts', 'doctor.mjs'),
          environment: packageLifecycleEnvironment(
            'doctor',
            'tsx scripts/doctor.mjs',
          ),
          parentPid: 8_101,
          processTable: [
            {
              pid: 8_101,
              parentPid: 1,
              command: `${process.execPath} scripts/doctor.mjs`,
            },
            { pid: 1, parentPid: 0, command: '/sbin/launchd' },
          ],
        });
      assert.deepEqual(directAuthorization, {
        authorized: false,
        claimed: true,
        event: 'doctor',
        problem: 'no npm ancestor is running the declared doctor lifecycle',
      });

      const npmAuthorization =
        databaseModule.inspectPackageLifecycleAuthorization({
          entrypoint: join(root, 'scripts', 'doctor.mjs'),
          environment: packageLifecycleEnvironment(
            'doctor',
            'tsx scripts/doctor.mjs',
          ),
          parentPid: 8_102,
          processTable: [
            {
              pid: 8_102,
              parentPid: 8_103,
              command: '/bin/sh -c tsx scripts/doctor.mjs',
            },
            {
              pid: 8_103,
              parentPid: 1,
              command: 'npm run doctor',
            },
          ],
        });
      assert.deepEqual(npmAuthorization, {
        authorized: true,
        claimed: true,
        event: 'doctor',
        problem: null,
      });

      const npmChildAuthorization =
        databaseModule.inspectPackageLifecycleAuthorization({
          entrypoint: join(
            root,
            'scripts',
            'validation',
            'record-promotion.mjs',
          ),
          environment: packageLifecycleEnvironment(
            'promote:quality-db',
            'tsx scripts/promote-quality-db.mjs',
          ),
          parentPid: 8_104,
          processTable: [
            {
              pid: 8_104,
              parentPid: 8_105,
              command:
                `${process.execPath} ` +
                'scripts/validation/record-promotion.mjs',
            },
            {
              pid: 8_105,
              parentPid: 1,
              command: 'npm run promote:quality-db -- --db-path candidate.db',
            },
          ],
        });
      assert.deepEqual(npmChildAuthorization, {
        authorized: true,
        claimed: true,
        event: 'promote:quality-db',
        problem: null,
      });

      const runE2eImportGuardProbe = (
        databasePath: string,
        source: string,
      ) => spawnSync(
        process.execPath,
        ['--require', 'tsx/cjs', '-e', source],
        {
          cwd: root,
          env: probeLaunchEnvironment({
            ...baseEnv,
            ...inheritedWriterAuthority,
            DB_PATH: databasePath,
            NODE_TEST_CONTEXT: 'child-v8',
          }),
          encoding: 'utf8',
        },
      );
      const existingAttestationProbe = runE2eImportGuardProbe(
        existingAttestationDatabasePath,
        `
          const assert = require('node:assert').strict;
          const {
            renameSync,
            statSync,
            writeFileSync,
          } = require('node:fs');
          delete process.env.NODE_TEST_CONTEXT;
          process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing';
          const databaseGuard = require('./test/database-guard-runtime.cjs');
          const attestation = databaseGuard.assertActive({
            requirePrivateArtifacts: true,
          });
          assert.ok(attestation.databaseIdentity);
          const replacementPath = process.env.DB_PATH + '.replacement';
          const replacement = Buffer.alloc(4096);
          replacement.write('SQLite format 3\\0', 0, 'binary');
          writeFileSync(replacementPath, replacement, {
            flag: 'wx',
            mode: 0o600,
          });
          renameSync(replacementPath, process.env.DB_PATH);
          assert.notEqual(
            String(statSync(process.env.DB_PATH, { bigint: true }).ino),
            attestation.databaseIdentity.ino,
          );
          const {
            createE2eDatabaseImportGuard,
          } = require('./src/lib/e2eDatabaseImportGuard.ts');
          assert.throws(
            () => createE2eDatabaseImportGuard({
              helperName: 'existing attestation probe',
              guardAttestation: attestation,
              expectedBootstrapMode: 'existing',
            }),
            /DB_PATH device\\/inode changed before repository import/,
          );
          console.log(JSON.stringify({
            databaseIdentity: attestation.databaseIdentity,
          }));
        `,
      );
      assert.equal(
        existingAttestationProbe.status,
        0,
        `${existingAttestationProbe.stdout}\n` +
          existingAttestationProbe.stderr,
      );
      const existingAttestationResult = JSON.parse(
        existingAttestationProbe.stdout.trim().split('\n').at(-1)!,
      );
      assert.match(existingAttestationResult.databaseIdentity.dev, /^\d+$/);
      assert.match(existingAttestationResult.databaseIdentity.ino, /^\d+$/);

      const freshAttestationProbe = runE2eImportGuardProbe(
        freshAttestationDatabasePath,
        `
          const assert = require('node:assert').strict;
          const { existsSync } = require('node:fs');
          delete process.env.NODE_TEST_CONTEXT;
          process.env.RADAR_DB_BOOTSTRAP_MODE = 'fresh';
          const databaseGuard = require('./test/database-guard-runtime.cjs');
          const attestation = databaseGuard.assertActive({
            requirePrivateArtifacts: true,
          });
          assert.equal(attestation.databaseIdentity, null);
          const {
            createE2eDatabaseImportGuard,
          } = require('./src/lib/e2eDatabaseImportGuard.ts');
          const importGuard = createE2eDatabaseImportGuard({
            helperName: 'fresh attestation probe',
            guardAttestation: attestation,
            expectedBootstrapMode: 'fresh',
          });
          importGuard.assertReady();
          assert.equal(existsSync(process.env.DB_PATH), false);
          console.log(JSON.stringify({
            databaseIdentity: attestation.databaseIdentity,
          }));
        `,
      );
      assert.equal(
        freshAttestationProbe.status,
        0,
        `${freshAttestationProbe.stdout}\n${freshAttestationProbe.stderr}`,
      );
      const freshAttestationResult = JSON.parse(
        freshAttestationProbe.stdout.trim().split('\n').at(-1)!,
      );
      assert.equal(freshAttestationResult.databaseIdentity, null);

      const dotenvProbe = spawnSync(
        process.execPath,
        [
          '--import',
          'tsx',
          '--input-type=module',
          '--eval',
          `
            ${applyProbeEnvironment}
            await import(${JSON.stringify(
              pathToFileURL(join(root, 'src', 'config.ts')).href,
            )});
            console.log(process.env.DB_PATH);
          `,
        ],
        {
          cwd: root,
          env: probeLaunchEnvironment({
            ...baseEnv,
            DB_PATH: dotenvSafeDatabasePath,
            DOTENV_CONFIG_PATH: dotenvOverridePath,
            DOTENV_CONFIG_OVERRIDE: 'true',
          }),
          encoding: 'utf8',
        },
      );
      assert.equal(
        dotenvProbe.status,
        0,
        `${dotenvProbe.stdout}\n${dotenvProbe.stderr}`,
      );
      assert.equal(
        dotenvProbe.stdout.trim().split('\n').at(-1),
        dotenvSafeDatabasePath,
      );

      const missingDotenvEnvironment = {
        ...baseEnv,
        DB_PATH: missingDotenvDatabasePath,
      };
      delete missingDotenvEnvironment.DOTENV_CONFIG_PATH;
      const missingDotenv = runImport(missingDotenvEnvironment);
      assert.notEqual(missingDotenv.status, 0);
      assert.match(
        missingDotenv.stderr,
        /DOTENV_CONFIG_PATH is required in (?:ad hoc evaluation|test) contexts/,
      );

      const nonEmptyDotenv = runImport({
        ...baseEnv,
        DB_PATH: nonEmptyDotenvDatabasePath,
        DOTENV_CONFIG_PATH: nonEmptyDotenvPath,
      });
      assert.notEqual(nonEmptyDotenv.status, 0);
      assert.match(
        nonEmptyDotenv.stderr,
        /DOTENV_CONFIG_PATH must reference an empty file in (?:an ad hoc evaluation|a test) context/,
      );

      const explicitTestPath = runImport({
        ...baseEnv,
        ...inheritedWriterAuthority,
        DB_PATH: testDatabasePath,
        NODE_TEST_CONTEXT: 'child-v8',
      });
      assert.equal(
        explicitTestPath.status,
        0,
        `${explicitTestPath.stdout}\n${explicitTestPath.stderr}`,
      );

      const explicitEvaluationPath = runImport({
        ...baseEnv,
        ...inheritedWriterLeaseAuthority,
        DB_PATH: evaluationDatabasePath,
      });
      assert.equal(
        explicitEvaluationPath.status,
        0,
        `${explicitEvaluationPath.stdout}\n${explicitEvaluationPath.stderr}`,
      );

      const existingTest = runImport({
        ...baseEnv,
        ...inheritedWriterAuthority,
        DB_PATH: existingTestDatabasePath,
        NODE_TEST_CONTEXT: 'child-v8',
      });
      assert.notEqual(existingTest.status, 0);
      assert.match(
        existingTest.stderr,
        /test requires a fresh SQLite database family; existing path\(s\):/,
      );

      const existingEvaluation = runImport({
        ...baseEnv,
        ...inheritedWriterLeaseAuthority,
        DB_PATH: existingEvaluationDatabasePath,
      });
      assert.notEqual(existingEvaluation.status, 0);
      assert.match(
        existingEvaluation.stderr,
        /evaluation requires a fresh SQLite database family; existing path\(s\):/,
      );

      const journalFamily = runImport({
        ...baseEnv,
        ...inheritedWriterAuthority,
        DB_PATH: journalDatabasePath,
        NODE_TEST_CONTEXT: 'child-v8',
      });
      assert.notEqual(journalFamily.status, 0);
      assert.match(
        journalFamily.stderr,
        /test requires a fresh SQLite database family; existing path\(s\):/,
      );
      assert.ok(journalFamily.stderr.includes(`${journalDatabasePath}-journal`));

      const nonPrivateTest = runImport({
        ...baseEnv,
        ...inheritedWriterAuthority,
        DB_PATH: nonPrivateTestDatabasePath,
        NODE_TEST_CONTEXT: 'child-v8',
      });
      assert.notEqual(nonPrivateTest.status, 0);
      assert.match(
        nonPrivateTest.stderr,
        /DB_PATH parent must be a private directory owned by the current user with no group\/other permissions in a test context/,
      );

      const nonPrivateEvaluation = runImport({
        ...baseEnv,
        ...inheritedWriterLeaseAuthority,
        DB_PATH: nonPrivateEvaluationDatabasePath,
      });
      assert.notEqual(nonPrivateEvaluation.status, 0);
      assert.match(
        nonPrivateEvaluation.stderr,
        /DB_PATH parent must be a private directory owned by the current user with no group\/other permissions in (?:an ad hoc evaluation|a test) context/,
      );

      const existingEvaluationByPolicy = runImport({
        ...baseEnv,
        ...inheritedWriterLeaseAuthority,
        DB_PATH: evaluationDatabasePath,
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
      });
      assert.equal(
        existingEvaluationByPolicy.status,
        0,
        `${existingEvaluationByPolicy.stdout}\n${existingEvaluationByPolicy.stderr}`,
      );

      const runNormalProcess = (
        bootstrapMode?: 'fresh' | 'existing',
      ) => spawnSync(
        process.execPath,
        ['--import', 'tsx', normalProcessScriptPath],
        {
          cwd: root,
          env: probeLaunchEnvironment({
            ...baseEnv,
            ...inheritedWriterLeaseAuthority,
            DB_PATH: normalDatabasePath,
            ...(bootstrapMode
              ? { RADAR_DB_BOOTSTRAP_MODE: bootstrapMode }
              : {}),
          }),
          encoding: 'utf8',
        },
      );
      const initialNormalOpen = runNormalProcess();
      assert.equal(
        initialNormalOpen.status,
        0,
        `${initialNormalOpen.stdout}\n${initialNormalOpen.stderr}`,
      );

      const apiWorkerEnvironment = {
        ...process.env,
        DB_PATH: normalDatabasePath,
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
      };
      const runApiReadWorker = (
        databaseContext: string,
        databaseIdentity?: { dev: number; ino: number },
      ) => {
        const workerSource = [
          "const { parentPort } = require('node:worker_threads');",
          "delete process.env.DOTENV_CONFIG_PATH;",
          "delete process.env.NODE_TEST_CONTEXT;",
          "for (const name of Object.keys(process.env)) {",
          "  if (name.startsWith('RADAR_TEST_')) delete process.env[name];",
          "}",
          "void import('tsx')",
          `.then(() => require(${JSON.stringify(
            join(root, 'src', 'lib', 'db.ts'),
          )}))`,
          ".then((database) => {",
          "  database.db.close();",
          "  parentPort.postMessage('ok');",
          "  parentPort.close();",
          "})",
          ".catch((error) => { setImmediate(() => { throw error; }); });",
        ].join('');
        return spawnSync(
          process.execPath,
          [
            '-e',
            `
            const { Worker } = require('node:worker_threads');
            const worker = new Worker(
              ${JSON.stringify(workerSource)},
              {
                eval: true,
                execArgv: [],
                workerData: {
                  databaseContext: ${JSON.stringify(databaseContext)},
                  databaseIdentity: ${JSON.stringify(databaseIdentity)},
                  task: 'build-release-api-payloads',
                },
              },
            );
            const timeout = setTimeout(() => {
              void worker.terminate();
              console.error('API read worker timed out');
              process.exitCode = 1;
            }, 5000);
            worker.once('message', (message) => {
              clearTimeout(timeout);
              if (message !== 'ok') {
                console.error('unexpected API read worker message');
                process.exitCode = 1;
              }
            });
            worker.once('error', (error) => {
              clearTimeout(timeout);
              console.error(error instanceof Error ? error.message : String(error));
              process.exitCode = 1;
            });
          `,
          ],
          {
            cwd: root,
            env: {
              ...probeLaunchEnvironment(apiWorkerEnvironment),
            },
            encoding: 'utf8',
          },
        );
      };
      const normalDatabaseIdentity = statSync(normalDatabasePath);
      const trustedApiWorker = runApiReadWorker(
        'openclaw-release-radar-api-read-worker-v1',
        {
          dev: normalDatabaseIdentity.dev,
          ino: normalDatabaseIdentity.ino,
        },
      );
      const untrustedApiWorker = runApiReadWorker('untrusted-worker');
      const wrongIdentityApiWorker = runApiReadWorker(
        'openclaw-release-radar-api-read-worker-v1',
        {
          dev: normalDatabaseIdentity.dev,
          ino: normalDatabaseIdentity.ino + 1,
        },
      );
      assert.equal(
        trustedApiWorker.status,
        0,
        `${trustedApiWorker.stdout}\n${trustedApiWorker.stderr}`,
      );
      assert.notEqual(untrustedApiWorker.status, 0);
      assert.match(
        untrustedApiWorker.stderr,
        /DOTENV_CONFIG_PATH is required in (?:ad hoc evaluation|test) contexts|Database guard protected process identity changed/,
      );
      assert.notEqual(wrongIdentityApiWorker.status, 0);
      assert.match(
        wrongIdentityApiWorker.stderr,
        /API read worker database identity does not match the parent process/,
      );

      const incrementalNormalOpen = runNormalProcess();
      assert.notEqual(incrementalNormalOpen.status, 0);
      assert.match(
        incrementalNormalOpen.stderr,
        /evaluation requires a fresh SQLite database family; existing path\(s\):/,
      );
      const explicitIncrementalNormalOpen = runNormalProcess('existing');
      assert.equal(
        explicitIncrementalNormalOpen.status,
        0,
        `${explicitIncrementalNormalOpen.stdout}\n` +
          explicitIncrementalNormalOpen.stderr,
      );

      if (
        inheritedWriterToken &&
        inheritedWriterPid &&
        inheritedWriterLeasePath &&
        inheritedWriterRunId &&
        inheritedWriterTempRoot &&
        inheritedWriterProcessLockRoot
      ) {
        const inheritedWriter = runImport({
          ...baseEnv,
          RADAR_TEST_RUN_ID: inheritedWriterRunId,
          RADAR_TEST_TEMP_ROOT: inheritedWriterTempRoot,
          RADAR_TEST_PROCESS_LOCK_ROOT: inheritedWriterProcessLockRoot,
          DB_PATH: inheritedWriterDatabasePath,
          NODE_TEST_CONTEXT: 'child-v8',
          RADAR_TEST_WRITER_LOCK_PID: inheritedWriterPid,
          RADAR_TEST_WRITER_LEASE_PATH: inheritedWriterLeasePath,
          RADAR_TEST_WRITER_LOCK_TOKEN: inheritedWriterToken,
        });
        assert.equal(
          inheritedWriter.status,
          0,
          `${inheritedWriter.stdout}\n${inheritedWriter.stderr}`,
        );

        const missingWriterLease = runImport({
          ...baseEnv,
          RADAR_TEST_RUN_ID: inheritedWriterRunId,
          RADAR_TEST_TEMP_ROOT: inheritedWriterTempRoot,
          RADAR_TEST_PROCESS_LOCK_ROOT: inheritedWriterProcessLockRoot,
          DB_PATH: missingWriterLeaseDatabasePath,
          NODE_TEST_CONTEXT: 'child-v8',
          RADAR_TEST_WRITER_LOCK_PID: inheritedWriterPid,
          RADAR_TEST_WRITER_LOCK_TOKEN: inheritedWriterToken,
        });
        assert.notEqual(missingWriterLease.status, 0);
        assert.match(
          missingWriterLease.stderr,
          /RADAR_TEST_WRITER_LOCK_TOKEN, RADAR_TEST_WRITER_LOCK_PID, and RADAR_TEST_WRITER_LEASE_PATH must be inherited together/,
        );

        const forgedWriter = runImport({
          ...baseEnv,
          RADAR_TEST_RUN_ID: inheritedWriterRunId,
          RADAR_TEST_TEMP_ROOT: inheritedWriterTempRoot,
          RADAR_TEST_PROCESS_LOCK_ROOT: inheritedWriterProcessLockRoot,
          DB_PATH: forgedWriterDatabasePath,
          NODE_TEST_CONTEXT: 'child-v8',
          RADAR_TEST_WRITER_LOCK_PID: inheritedWriterPid,
          RADAR_TEST_WRITER_LEASE_PATH: inheritedWriterLeasePath,
          RADAR_TEST_WRITER_LOCK_TOKEN: `${inheritedWriterToken}-forged`,
        });
        assert.notEqual(forgedWriter.status, 0);
        assert.match(
          forgedWriter.stderr,
          /Inherited test writer lease does not match protected runner state/,
        );
      }
    } finally {
      rmSync(dirname(testDatabasePath), { recursive: true, force: true });
      rmSync(dirname(evaluationDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(normalDatabasePath), { recursive: true, force: true });
      rmSync(dirname(missingDotenvDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(nonEmptyDotenvDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(dotenvSafeDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(dotenvAttackDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(existingTestDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(existingEvaluationDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(existingAttestationDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(freshAttestationDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(journalDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(nonPrivateTestDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(nonPrivateEvaluationDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(inheritedWriterDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(missingWriterLeaseDatabasePath), {
        recursive: true,
        force: true,
      });
      rmSync(dirname(forgedWriterDatabasePath), {
        recursive: true,
        force: true,
      });
    }
  });

  it('updates metadata-only issue rows without overwriting complete comment-derived stats', async () => {
    const db = await freshDb('issue-metadata-only-upsert');
    db.upsertIssue({
      number: 3901,
      state: 'open',
      title: 'Original',
      body: 'Original body',
      author: 'reporter',
      html_url: 'https://example.test/issues/3901',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-02T00:00:00Z',
      closed_at: null,
      comments: 3,
      unique_human_commenters: 3,
      maintainer_commenters: 2,
      contributor_commenters: 2,
      commenter_scan_truncated: 0,
      reaction_total: 4,
      positive_reactions: 3,
      labels: '["bug"]',
      is_bot: 0,
    });

    db.upsertIssueMetadata({
      number: 3901,
      state: 'closed',
      title: 'Remote metadata changed',
      body: 'Updated body',
      author: 'reporter',
      html_url: 'https://example.test/issues/3901',
      created_at: '2026-01-01T00:00:00Z',
      updated_at: '2026-01-03T00:00:00Z',
      closed_at: '2026-01-03T00:00:00Z',
      comments: 4,
      reaction_total: 5,
      positive_reactions: 4,
      labels: '["bug","closed"]',
      is_bot: 0,
    });

    const row = db.getIssue(3901);
    assert.equal(row?.state, 'closed');
    assert.equal(row?.title, 'Remote metadata changed');
    assert.equal(row?.comments, 4);
    assert.equal(row?.unique_human_commenters, 3);
    assert.equal(row?.maintainer_commenters, 2);
    assert.equal(row?.contributor_commenters, 2);
    assert.equal(row?.commenter_scan_truncated, 0);
  });

  it('indexes created and closed release-window predicates and uses them for range plans', async () => {
    const db = await freshDb('issue-window-indexes');
    const indexes = new Map(
      (db.db.prepare(`PRAGMA index_list(issues)`).all() as Array<{ name: string }>)
        .map((row) => [row.name, row]),
    );
    assert.ok(indexes.has('idx_issues_created_at'));
    assert.ok(indexes.has('idx_issues_closed_at'));

    const createdPlan = db.db.prepare(`
      EXPLAIN QUERY PLAN
      SELECT number
      FROM issues
      WHERE created_at >= ? AND created_at < ?
      ORDER BY created_at DESC
    `).all('2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z') as Array<{ detail: string }>;
    const closedPlan = db.db.prepare(`
      EXPLAIN QUERY PLAN
      SELECT number
      FROM issues
      WHERE closed_at >= ? AND closed_at < ?
      ORDER BY closed_at DESC
    `).all('2026-01-01T00:00:00Z', '2026-02-01T00:00:00Z') as Array<{ detail: string }>;

    assert.ok(createdPlan.some((row) => row.detail.includes('idx_issues_created_at')));
    assert.ok(closedPlan.some((row) => row.detail.includes('idx_issues_closed_at')));
  });

  it('stores append-only ingestion evidence failures for durable fetch provenance', async () => {
    const db = await freshDb('ingestion-evidence-failures');

    const table = db.db.prepare(`
      SELECT name FROM sqlite_master WHERE type='table' AND name='ingestion_evidence_failures'
    `).get();
    assert.equal(table?.name, 'ingestion_evidence_failures');

    db.insertIngestionEvidenceFailure({
      run_id: 'run-1',
      occurred_at: '2026-06-30T01:00:00Z',
      source: 'issue-comments',
      scope: 'page 1',
      message: '[issue-comments] page 1 failed: timeout',
      context_json: '{"page":1}',
    });
    db.insertIngestionEvidenceFailure({
      run_id: 'run-1',
      occurred_at: '2026-06-30T01:01:00Z',
      source: 'issue-comments',
      scope: 'page 1',
      message: '[issue-comments] page 1 failed: retry timeout',
      context_json: '{"page":1,"retry":true}',
    });
    db.insertIngestionEvidenceFailure({
      run_id: 'run-2',
      occurred_at: '2026-06-30T01:02:00Z',
      source: 'advisories',
      scope: 'npm:openclaw',
      message: '[advisories] npm:openclaw failed: unavailable',
      scoring_blocking: false,
    });

    const recent = db.listRecentIngestionEvidenceFailures(5);
    assert.equal(recent.length, 3);
    assert.deepEqual(recent.map((row: any) => row.source), ['advisories', 'issue-comments', 'issue-comments']);
    assert.notEqual(recent[1].id, recent[2].id);

    const blockingAfter = db.ingestionEvidenceFailuresAfter('2026-06-30T00:59:00Z', 10);
    assert.equal(blockingAfter.length, 2);
    assert.deepEqual(blockingAfter.map((row: any) => row.message), [
      '[issue-comments] page 1 failed: retry timeout',
      '[issue-comments] page 1 failed: timeout',
    ]);

    const bySource = db.ingestionEvidenceFailureSourceCountsAfter('2026-06-30T00:59:00Z');
    assert.deepEqual(bySource, [{ source: 'issue-comments', count: 2, maxAt: '2026-06-30T01:01:00Z' }]);

    db.insertIngestionEvidenceFailure({
      run_id: 'run-3',
      occurred_at: '2026-06-30T01:03:00Z',
      source: 'issue-comments',
      scope: 'page 2',
      message: '[issue-comments] page 2 failed in current run',
    });
    assert.equal(db.supersedeIngestionEvidenceFailures({
      successfulRunId: 'run-3',
      supersededAt: '2026-06-30T01:04:00Z',
    }), 2);
    assert.deepEqual(
      db.listActiveIngestionEvidenceFailures(10).map((row: any) => row.run_id),
      ['run-3'],
    );
    const historical = db.listRecentIngestionEvidenceFailures(10);
    assert.equal(historical.length, 4);
    assert.equal(
      historical.filter((row: any) => row.superseded_by_run_id === 'run-3').length,
      2,
    );
    assert.deepEqual(
      db.ingestionEvidenceFailuresAfter('2026-06-30T00:59:00Z', 10).map((row: any) => row.run_id),
      ['run-3'],
    );
  });

  it('supersedes ingestion failures only for the requested source, scope, and release', async () => {
    const db = await freshDb('ingestion-failure-scoped-supersession');
    const failures = [
      ['run-a', 'analyze_closure_proofs', 'v1', 'v1'],
      ['run-b', 'analyze_closure_proofs', 'v2', 'v2'],
      ['run-c', 'ingest_fix_provenance', 'v1', 'v1'],
      ['run-d', 'analyze_closure_proofs', 'v1', 'v2'],
    ];
    failures.forEach(([runId, source, scope, releaseTag], index) => {
      db.insertIngestionEvidenceFailure({
        run_id: runId,
        occurred_at: `2026-06-30T01:0${index}:00Z`,
        source,
        scope,
        release_tag: releaseTag,
        message: `${source} ${scope} failed`,
      });
    });

    assert.equal(db.supersedeIngestionEvidenceFailures({
      successfulRunId: 'repair-v1',
      supersededAt: '2026-06-30T02:00:00Z',
      sources: ['analyze_closure_proofs'],
      scopes: ['v1'],
      releaseTags: ['v1'],
    }), 1);

    assert.deepEqual(
      db.listActiveIngestionEvidenceFailures(10)
        .map((row: any) => [row.run_id, row.source, row.scope, row.release_tag])
        .sort(),
      [
        ['run-b', 'analyze_closure_proofs', 'v2', 'v2'],
        ['run-c', 'ingest_fix_provenance', 'v1', 'v1'],
        ['run-d', 'analyze_closure_proofs', 'v1', 'v2'],
      ],
    );
  });

  it('tracks monotonic issue, snapshot, and classification revisions and rejects stale baselines', async () => {
    const db = await freshDb('issue-evidence-revisions');
    seedIssue(db, 7001, null);
    const initial = db.issueEvidenceRevisions([7001]).get(7001);
    assert.ok(initial);

    db.upsertIssue({ ...db.getIssue(7001) });
    assert.deepEqual(db.issueEvidenceRevisions([7001]).get(7001), initial);

    db.upsertIssue({
      ...db.getIssue(7001),
      title: 'newer issue evidence',
    });
    const changedIssue = db.issueEvidenceRevisions([7001]).get(7001);
    assert.equal(changedIssue.issueRevision, initial.issueRevision + 1);

    const snapshot = {
      issue_number: 7001,
      schema_version: 2,
      comment_count: 0,
      fetched_comment_count: 0,
      latest_comment_updated_at: null,
      comments_digest: commentEvidenceDigest(0, []),
      issue_updated_at: db.getIssue(7001).updated_at,
      comments_json: '[]',
    };
    db.upsertIssueCommentSnapshot(snapshot);
    const withSnapshot = db.issueEvidenceRevisions([7001]).get(7001);
    db.upsertIssueCommentSnapshot(snapshot);
    assert.deepEqual(db.issueEvidenceRevisions([7001]).get(7001), withSnapshot);
    assert.throws(
      () => db.upsertIssueCommentSnapshot({
        ...snapshot,
        comments_digest: 'a'.repeat(64),
      }),
      /comments digest mismatch/,
    );
    const changedComments = [{
      id: 1,
      body: 'changed comment evidence',
      created_at: '2035-01-01T00:00:00Z',
      updated_at: '2035-01-01T00:00:00Z',
    }];
    const changedCommentsDigest = commentEvidenceDigest(1, changedComments);
    db.upsertIssueCommentSnapshot({
      ...snapshot,
      comment_count: 1,
      fetched_comment_count: 1,
      comments_digest: changedCommentsDigest,
      comments_json: serializeCommentEvidence(changedComments),
    });
    const changedSnapshot = db.issueEvidenceRevisions([7001]).get(7001);
    assert.equal(changedSnapshot.snapshotRevision, withSnapshot.snapshotRevision + 1);

    const sourceIdentity = db.classifierSourceIdentity(['v1'], 6);
    db.upsertClassification(
      7001,
      classification(),
      db.getIssue(7001).updated_at,
      6,
      changedSnapshot.snapshotRevision ? changedCommentsDigest : null,
      sourceIdentity,
    );
    const classified = db.issueEvidenceRevisions([7001]).get(7001);
    db.upsertClassification(
      7001,
      classification(),
      db.getIssue(7001).updated_at,
      6,
      changedCommentsDigest,
      sourceIdentity,
    );
    const reclassified = db.issueEvidenceRevisions([7001]).get(7001);
    assert.equal(reclassified.classificationRevision, classified.classificationRevision + 1);

    assert.throws(
      () => db.assertIssueEvidenceRevisions(new Map([[7001, classified]])),
      /evidence revision changed while work was staged/,
    );
  });

  it('persists classifier source identity and changes it for every classifier input dimension', async () => {
    const db = await freshDb('classifier-source-identity');
    seedIssue(db, 7002, null);
    const original = {
      model: config.openai.model,
      reasoningEffort: config.openai.reasoningEffort,
      serviceTier: config.openai.serviceTier,
    };
    try {
      const baseline = db.classifierSourceIdentity(['v2', 'v1'], 6);
      config.openai.model = original.model === 'gpt-5.5' ? 'gpt-4o-mini' : 'gpt-5.5';
      const modelChanged = db.classifierSourceIdentity(['v2', 'v1'], 6);
      config.openai.reasoningEffort = original.reasoningEffort === 'high' ? 'low' : 'high';
      const reasoningChanged = db.classifierSourceIdentity(['v2', 'v1'], 6);
      config.openai.serviceTier = original.serviceTier === 'flex' ? 'priority' : 'flex';
      const tierChanged = db.classifierSourceIdentity(['v2', 'v1'], 6);
      const tagsChanged = db.classifierSourceIdentity(['v3', 'v2', 'v1'], 6);
      const promptChanged = db.classifierSourceIdentity(['v3', 'v2', 'v1'], 8);
      const longTagSet = Array.from({ length: 20 }, (_, index) => `v${20 - index}`);
      const longTagIdentity = db.classifierSourceIdentity(longTagSet, 8);

      assert.equal(new Set([
        baseline.digest,
        modelChanged.digest,
        reasoningChanged.digest,
        tierChanged.digest,
        tagsChanged.digest,
        promptChanged.digest,
      ]).size, 6);
      assert.deepEqual(longTagIdentity.knownTags, longTagSet);
      assert.throws(
        () => db.classifierSourceIdentity(['v2', 'v2'], 8),
        /must not contain duplicates/,
      );

      db.upsertClassification(
        7002,
        classification(),
        db.getIssue(7002).updated_at,
        8,
        commentEvidenceDigest(0, []),
        promptChanged,
      );
      const stored = db.getClassification(7002);
      assert.equal(stored.source_identity_digest, promptChanged.digest);
      assert.deepEqual(JSON.parse(stored.source_identity_json), promptChanged);
      const columns = db.db.prepare(`PRAGMA table_info(classifications)`).all()
        .map((row: any) => row.name);
      assert.ok(columns.includes('source_identity_json'));
      assert.ok(columns.includes('source_identity_digest'));
      assert.ok(columns.includes('classification_origin'));
      assert.ok(columns.includes('raw_model_output'));
      assert.ok(columns.includes('provenance_json'));
      assert.ok(columns.includes('revision'));
      assert.equal(stored.classification_origin, 'legacy_or_manual');
      assert.equal(stored.raw_model_output, null);

      const rawOutput = JSON.stringify({
        sentiment: 'negative',
        severity: 'high',
        scope: 'moderate',
        functionality: 'core',
        affected_users: 'some',
        affected_users_evidence: 'The issue affects the default Windows configuration.',
        hasWorkaround: false,
        workaroundStatus: 'unknown',
        duplicateCluster: null,
        affectsVersion: 'v3',
        confidence: 0.9,
        rationale: 'The issue body and comments describe a reproducible core failure.',
      });
      const accepted = recordAcceptedClassifierLedger(db, {
        issueNumber: 7002,
        rawModelOutput: rawOutput,
        sourceIdentity: promptChanged,
        responseId: 'chatcmpl-db-test',
      });
      db.upsertClassification(
        7002,
        {
          sentiment: 'negative',
          severity: 'high',
          scope: 'moderate',
          functionality: 'core',
          affectedUsers: 'some',
          hasWorkaround: false,
          workaroundStatus: 'unknown',
          duplicateCluster: null,
          affectsVersion: 'v3',
          confidence: 0.9,
          rationale: 'The issue body and comments describe a reproducible core failure.',
          provenance: {
            schemaVersion: 1,
            responseId: 'chatcmpl-db-test',
            requestedModel: promptChanged.model,
            responseModel: promptChanged.model,
            requestedServiceTier: promptChanged.serviceTier,
            responseServiceTier: promptChanged.serviceTier,
            reasoningEffort: promptChanged.reasoningEffort,
            promptVersion: 8,
            promptTemplateHash: CLASSIFICATION_PROMPT_TEMPLATE_HASH,
            promptHash: 'a'.repeat(64),
            rawModelOutputHash: createHash('sha256').update(rawOutput).digest('hex'),
            rawModelOutput: rawOutput,
          },
        },
        db.getIssue(7002).updated_at,
        8,
        commentEvidenceDigest(0, []),
        promptChanged,
        accepted,
      );
      const rawStored = db.getClassification(7002);
      assert.equal(rawStored.classification_origin, 'raw_model');
      assert.equal(rawStored.raw_model_output, rawOutput);
      assert.equal(JSON.parse(rawStored.provenance_json).responseId, 'chatcmpl-db-test');
      assert.throws(
        () => db.upsertClassification(
          7002,
          {
            ...classification({ severity: 'critical' }),
            provenance: JSON.parse(rawStored.provenance_json),
          },
          db.getIssue(7002).updated_at,
          7,
          commentEvidenceDigest(0, []),
          promptChanged,
        ),
        /stored classification columns do not match raw_model_output/,
      );
    } finally {
      config.openai.model = original.model;
      config.openai.reasoningEffort = original.reasoningEffort;
      config.openai.serviceTier = original.serviceTier;
    }
  });

  it('records classifier attempts append-only, rejects malformed order before mutation, and permits exact retries', async () => {
    const db = await freshDb('classifier-attempt-recorder-order');
    const sourceIdentity = db.classifierSourceIdentity(['v-ledger'], 8);
    const requestHash = createHash('sha256').update('ordered-request').digest('hex');
    const run = createClassifierAttemptRun({
      runId: 'classifier-run-ordered',
      issueNumber: 7201,
      startedAt: '2040-02-01T00:00:00.000Z',
      maxAttempts: 2,
      classifierIdentityHash: sourceIdentity.promptTemplateHash,
      requestHash,
    });
    const first = appendClassifierAttempt(run, [], {
      attemptId: 'classifier-attempt-ordered-1',
      status: 'transport_failure',
      startedAt: '2040-02-01T00:00:00.000Z',
      finishedAt: '2040-02-01T00:00:01.000Z',
      rawResponse: captureClassifierRawResponse('temporary failure'),
      rawModelOutput: null,
      error: captureClassifierError(new Error('temporary failure')),
      retry: {
        decision: 'retry',
        retryable: true,
        delayMs: 0,
        reason: 'retryable_transport_failure',
      },
      semanticDiagnostics: [],
      provenance: {
        requestHash,
        responseId: null,
        responseModel: null,
        responseServiceTier: null,
      },
    });
    const rawOutput = JSON.stringify({
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      affected_users_evidence: 'Affects startup.',
      hasWorkaround: false,
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.9,
      rationale: 'Startup fails.',
    });
    const second = appendClassifierAttempt(run, [first], {
      attemptId: 'classifier-attempt-ordered-2',
      status: 'accepted_success',
      startedAt: '2040-02-01T00:00:01.000Z',
      finishedAt: '2040-02-01T00:00:02.000Z',
      rawResponse: captureClassifierRawResponse(JSON.stringify({
        id: 'chatcmpl-ordered',
        model: sourceIdentity.model,
        service_tier: sourceIdentity.serviceTier,
        choices: [{
          finish_reason: 'stop',
          message: {
            content: rawOutput,
            refusal: null,
          },
        }],
      })),
      rawModelOutput: captureClassifierRawModelOutput(rawOutput),
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
        responseId: 'chatcmpl-ordered',
        responseModel: sourceIdentity.model,
        responseServiceTier: sourceIdentity.serviceTier,
      },
    });
    const receipt = createClassifierAttemptTerminalReceipt(run, [first, second], {
      receiptId: 'classifier-receipt-ordered',
      status: 'accepted_success',
      finishedAt: '2040-02-01T00:00:03.000Z',
      error: null,
    });

    assert.equal(db.recordClassifierAttemptRun(run).inserted, true);
    assert.equal(db.recordClassifierAttemptRun(run).equivalent, true);
    assert.throws(
      () => db.recordClassifierAttempt(second),
      /ordinal must equal 1/,
    );
    assert.equal(db.listClassifierAttempts(run.runId).length, 0);
    assert.equal(db.recordClassifierAttempt(first).inserted, true);
    assert.equal(db.recordClassifierAttempt(first).equivalent, true);
    assert.equal(db.recordClassifierAttempt(second).inserted, true);
    assert.equal(db.recordClassifierAttemptTerminalReceipt(receipt).inserted, true);
    assert.equal(
      db.recordClassifierAttemptTerminalReceipt(receipt).equivalent,
      true,
    );
    assert.deepEqual(db.getClassifierAttemptLedger(run.runId), {
      schemaVersion: 1,
      run,
      attempts: [first, second],
      receipt,
    });

    for (const table of [
      'classifier_attempt_runs',
      'classifier_attempts',
      'classifier_attempt_terminal_receipts',
    ]) {
      assert.throws(
        () => db.db.prepare(`UPDATE ${table} SET content_hash=content_hash`).run(),
        new RegExp(`${table} is append-only`),
      );
      assert.throws(
        () => db.db.prepare(`DELETE FROM ${table}`).run(),
        new RegExp(`${table} is append-only`),
      );
    }
  });

  it('mirrors semantic-retry request-hash transitions in durable attempt prefixes', async () => {
    const db = await freshDb('classifier-attempt-request-hash-transition');
    const sourceIdentity = db.classifierSourceIdentity(['v-ledger'], 8);
    const initialRequestHash = createHash('sha256')
      .update('transport-initial-request')
      .digest('hex');
    const changedRequestHash = createHash('sha256')
      .update('transport-changed-request')
      .digest('hex');
    const transportRun = createClassifierAttemptRun({
      runId: 'classifier-run-transport-transition',
      issueNumber: 7202,
      startedAt: '2040-02-02T00:00:00.000Z',
      maxAttempts: 2,
      classifierIdentityHash: sourceIdentity.promptTemplateHash,
      requestHash: initialRequestHash,
    });
    const transportFailure = appendClassifierAttempt(transportRun, [], {
      attemptId: 'classifier-attempt-transport-transition-1',
      status: 'transport_failure',
      startedAt: '2040-02-02T00:00:00.000Z',
      finishedAt: '2040-02-02T00:00:01.000Z',
      rawResponse: captureClassifierRawResponse('temporary failure'),
      rawModelOutput: null,
      error: captureClassifierError(new Error('temporary failure')),
      retry: {
        decision: 'retry',
        retryable: true,
        delayMs: 0,
        reason: 'retryable_transport_failure',
      },
      semanticDiagnostics: [],
      provenance: {
        requestHash: initialRequestHash,
        responseId: null,
        responseModel: null,
        responseServiceTier: null,
      },
    });
    const transportRawOutput = JSON.stringify({
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      affected_users_evidence: 'Affects startup.',
      hasWorkaround: false,
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.9,
      rationale: 'Startup fails.',
    });
    const validTransportRetry = appendClassifierAttempt(
      transportRun,
      [transportFailure],
      {
        attemptId: 'classifier-attempt-transport-transition-2',
        status: 'accepted_success',
        startedAt: '2040-02-02T00:00:01.000Z',
        finishedAt: '2040-02-02T00:00:02.000Z',
        rawResponse: captureClassifierRawResponse(JSON.stringify({
          id: 'chatcmpl-transport-transition',
          model: sourceIdentity.model,
          service_tier: sourceIdentity.serviceTier,
          choices: [{
            finish_reason: 'stop',
            message: {
              content: transportRawOutput,
              refusal: null,
            },
          }],
        })),
        rawModelOutput: captureClassifierRawModelOutput(transportRawOutput),
        error: null,
        retry: {
          decision: 'stop',
          retryable: false,
          delayMs: null,
          reason: 'accepted_success',
        },
        semanticDiagnostics: [],
        provenance: {
          requestHash: initialRequestHash,
          responseId: 'chatcmpl-transport-transition',
          responseModel: sourceIdentity.model,
          responseServiceTier: sourceIdentity.serviceTier,
        },
      },
    );
    const invalidTransportTransition = structuredClone(validTransportRetry) as any;
    invalidTransportTransition.provenance.requestHash = changedRequestHash;
    resealClassifierAttempt(invalidTransportTransition);

    db.recordClassifierAttemptRun(transportRun);
    db.recordClassifierAttempt(transportFailure);
    assert.throws(
      () => db.recordClassifierAttempt(invalidTransportTransition),
      /requestHash changed without an immediately preceding eligible grounding semantic retry/,
    );
    assert.equal(db.listClassifierAttempts(transportRun.runId).length, 1);

    const semanticRetry = acceptedClassifierSemanticRetryLedger({
      issueNumber: 7203,
      rawModelOutput: transportRawOutput,
      sourceIdentity,
      responseId: 'chatcmpl-semantic-transition',
    });
    db.recordClassifierAttemptRun(semanticRetry.run);
    db.recordClassifierAttempt(semanticRetry.rejectedAttempt);
    const unchangedSemanticTransition = resealClassifierAttempt(
      structuredClone(semanticRetry.acceptedAttempt),
    );
    unchangedSemanticTransition.provenance.requestHash =
      semanticRetry.initialRequestHash;
    resealClassifierAttempt(unchangedSemanticTransition);
    assert.throws(
      () => db.recordClassifierAttempt(unchangedSemanticTransition),
      /requestHash must change after an immediately preceding eligible grounding semantic retry/,
    );
    assert.equal(db.listClassifierAttempts(semanticRetry.run.runId).length, 1);
    db.recordClassifierAttempt(semanticRetry.acceptedAttempt);
    db.recordClassifierAttemptTerminalReceipt(semanticRetry.receipt);

    const stored = db.getClassifierAttemptLedger(semanticRetry.run.runId);
    assert.ok(stored);
    assert.equal(stored.run.requestHash, semanticRetry.initialRequestHash);
    assert.deepEqual(
      stored.attempts.map((attempt: any) => attempt.provenance.requestHash),
      [semanticRetry.initialRequestHash, semanticRetry.finalRequestHash],
    );
    assert.equal(
      stored.receipt.selectedAttempt?.provenance.requestHash,
      semanticRetry.finalRequestHash,
    );

    for (const testCase of [
      {
        issueNumber: 7204,
        responseId: 'chatcmpl-duplicate-source-retry',
        mutate(attempt: any) {
          attempt.semanticDiagnostics[0].code = 'duplicate_source_id';
        },
        expected: /duplicate_source_id cannot authorize a semantic retry/,
      },
      {
        issueNumber: 7205,
        responseId: 'chatcmpl-schema-retry',
        mutate(attempt: any) {
          attempt.semanticDiagnostics[0].code = 'schema_shape_rejection';
        },
        expected: /is not a model-correctable grounding failure/,
      },
      {
        issueNumber: 7206,
        responseId: 'chatcmpl-generic-error-retry',
        mutate(attempt: any) {
          attempt.error.name = 'Error';
        },
        expected:
          /semantic retry requires an uncoded ClassificationGroundingError/,
      },
      {
        issueNumber: 7207,
        responseId: 'chatcmpl-oversized-diagnostic-retry',
        mutate(attempt: any) {
          attempt.semanticDiagnostics =
            captureClassifierSemanticDiagnostics([{
              field: 'severity',
              code: 'missing_support',
              message: 'x'.repeat(
                CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MESSAGE_MAX_BYTES + 1,
              ),
            }]);
        },
        expected:
          /message exceeds the semantic retry feedback limit/,
      },
      {
        issueNumber: 7208,
        responseId: 'chatcmpl-delayed-semantic-retry',
        mutate(attempt: any) {
          attempt.retry.delayMs = 1;
        },
        expected: /semantic retry requires delayMs=0/,
      },
      {
        issueNumber: 7210,
        responseId: 'chatcmpl-relabeled-schema-retry',
        mutate(attempt: any) {
          const invalidOutput = '{"severity":"extreme"}';
          const rawResponse = JSON.parse(attempt.rawResponse.text);
          rawResponse.choices[0].message.content = invalidOutput;
          attempt.rawResponse =
            captureClassifierRawResponse(JSON.stringify(rawResponse));
          attempt.rawModelOutput =
            captureClassifierRawModelOutput(invalidOutput);
        },
        expected: /rawModelOutput\.text.*classifier JSON|missing fields/,
      },
      {
        issueNumber: 7211,
        responseId: 'chatcmpl-invalid-usage-retry',
        mutate(attempt: any) {
          const rawResponse = JSON.parse(attempt.rawResponse.text);
          rawResponse.usage = { prompt_tokens: -1 };
          attempt.rawResponse =
            captureClassifierRawResponse(JSON.stringify(rawResponse));
        },
        expected: /semantic retry requires verifiable provider usage/,
      },
      {
        issueNumber: 7212,
        responseId: 'chatcmpl-excessive-diagnostics-retry',
        mutate(attempt: any) {
          attempt.semanticDiagnostics =
            captureClassifierSemanticDiagnostics(Array.from(
              {
                length:
                  CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MAX_COUNT + 1,
              },
              (_, index) => ({
                field: 'severity',
                code: 'missing_support',
                message: `missing support ${index}`,
              }),
            ));
        },
        expected: /semantic retry diagnostics exceed the feedback limit/,
      },
    ]) {
      const fixture = acceptedClassifierSemanticRetryLedger({
        issueNumber: testCase.issueNumber,
        rawModelOutput: transportRawOutput,
        sourceIdentity,
        responseId: testCase.responseId,
      });
      const invalidRejectedAttempt = structuredClone(
        fixture.rejectedAttempt,
      ) as any;
      testCase.mutate(invalidRejectedAttempt);
      resealClassifierAttempt(invalidRejectedAttempt);
      db.recordClassifierAttemptRun(fixture.run);
      assert.throws(
        () => db.recordClassifierAttempt(invalidRejectedAttempt),
        testCase.expected,
      );
      assert.equal(db.listClassifierAttempts(fixture.run.runId).length, 0);
    }

    const exhaustedFixture = acceptedClassifierSemanticRetryLedger({
      issueNumber: 7209,
      rawModelOutput: transportRawOutput,
      sourceIdentity,
      responseId: 'chatcmpl-exhausted-retry-claim',
    });
    const exhaustedRun = structuredClone(exhaustedFixture.run) as any;
    exhaustedRun.maxAttempts = 1;
    const {
      contentHash: _exhaustedRunContentHash,
      ...exhaustedRunWithoutContentHash
    } = exhaustedRun;
    exhaustedRun.contentHash = classifierAttemptRunContentHash(
      exhaustedRunWithoutContentHash,
    );
    const exhaustedAttempt = structuredClone(
      exhaustedFixture.rejectedAttempt,
    ) as any;
    exhaustedAttempt.previousContentHash = exhaustedRun.contentHash;
    resealClassifierAttempt(exhaustedAttempt);
    db.recordClassifierAttemptRun(exhaustedRun);
    assert.throws(
      () => db.recordClassifierAttempt(exhaustedAttempt),
      /retry cannot exceed the run attempt budget/,
    );
    assert.equal(db.listClassifierAttempts(exhaustedRun.runId).length, 0);

    const prematureFixture = acceptedClassifierSemanticRetryLedger({
      issueNumber: 7213,
      rawModelOutput: transportRawOutput,
      sourceIdentity,
      responseId: 'chatcmpl-premature-exhaustion-claim',
    });
    const prematureAttempt = structuredClone(
      prematureFixture.rejectedAttempt,
    ) as any;
    prematureAttempt.retry = {
      decision: 'stop',
      retryable: true,
      delayMs: null,
      reason: 'attempt_budget_exhausted',
    };
    resealClassifierAttempt(prematureAttempt);
    db.recordClassifierAttemptRun(prematureFixture.run);
    assert.throws(
      () => db.recordClassifierAttempt(prematureAttempt),
      /attempt_budget_exhausted is only valid at run\.maxAttempts/,
    );
    assert.equal(
      db.listClassifierAttempts(prematureFixture.run.runId).length,
      0,
    );
  });

  it('keeps receiptless, failed, and abandoned classifier runs durable without publishing classifications', async () => {
    const db = await freshDb('classifier-terminal-nonpublication');
    const requestHash = createHash('sha256').update('terminal-request').digest('hex');
    const sourceIdentity = db.classifierSourceIdentity(['v-terminal'], 8);
    const statuses = ['terminal_failure', 'abandoned'] as const;

    const receiptlessRun = createClassifierAttemptRun({
      runId: 'classifier-run-receiptless',
      issueNumber: 7300,
      startedAt: '2040-03-01T00:00:00.000Z',
      maxAttempts: 1,
      classifierIdentityHash: sourceIdentity.promptTemplateHash,
      requestHash,
    });
    db.recordClassifierAttemptRun(receiptlessRun);
    assert.equal(db.getClassifierAttemptLedger(receiptlessRun.runId), null);

    for (const [index, status] of statuses.entries()) {
      const issueNumber = 7301 + index;
      const run = createClassifierAttemptRun({
        runId: `classifier-run-${status}`,
        issueNumber,
        startedAt: `2040-03-01T00:00:0${index}.000Z`,
        maxAttempts: 1,
        classifierIdentityHash: sourceIdentity.promptTemplateHash,
        requestHash: createHash('sha256').update(`${requestHash}:${status}`).digest('hex'),
      });
      const error = captureClassifierError(new Error(`${status} fixture`));
      const receipt = createClassifierAttemptTerminalReceipt(run, [], {
        receiptId: `classifier-receipt-${status}`,
        status,
        reason: status === 'abandoned' ? 'caller_aborted' : status,
        finishedAt: `2040-03-01T00:00:1${index}.000Z`,
        error,
      });
      db.recordClassifierAttemptRun(run);
      db.recordClassifierAttemptTerminalReceipt(receipt);
      assert.equal(db.getClassifierAttemptLedger(run.runId)?.receipt.status, status);
      assert.equal(db.getClassification(issueNumber), undefined);
    }
    assert.equal(db.listClassifierAttemptRuns().length, 3);
    assert.equal(db.listClassifierAttemptTerminalReceipts().length, 2);
  });

  it('binds accepted classifications to exact durable evidence and detects restart or tampering', async () => {
    const { db, path } = await freshDbWithPath('classifier-accepted-binding');
    db.upsertIssue({
      number: 7401,
      state: 'open',
      title: 'classifier binding fixture',
      body: 'startup fails',
      author: 'tester',
      html_url: 'https://example.test/issues/7401',
      created_at: '2040-04-01T00:00:00.000Z',
      updated_at: '2040-04-01T00:00:00.000Z',
      closed_at: null,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    const commentsDigest = commentEvidenceDigest(0, []);
    db.upsertIssueCommentSnapshot({
      issue_number: 7401,
      schema_version: 2,
      comment_count: 0,
      fetched_comment_count: 0,
      latest_comment_updated_at: null,
      comments_digest: commentsDigest,
      issue_updated_at: '2040-04-01T00:00:00.000Z',
      comments_json: '[]',
    });
    const sourceIdentity = db.classifierSourceIdentity(['v-binding'], 8);
    const rawOutput = JSON.stringify({
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      affected_users_evidence: 'Startup fails for configured users.',
      hasWorkaround: false,
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.9,
      rationale: 'Startup fails.',
    });
    const provenance = {
      schemaVersion: 1 as const,
      responseId: 'chatcmpl-binding',
      requestedModel: sourceIdentity.model,
      responseModel: sourceIdentity.model,
      requestedServiceTier: sourceIdentity.serviceTier,
      responseServiceTier: sourceIdentity.serviceTier,
      reasoningEffort: sourceIdentity.reasoningEffort,
      promptVersion: 8,
      promptTemplateHash: sourceIdentity.promptTemplateHash,
      promptHash: 'd'.repeat(64),
      rawModelOutputHash: createHash('sha256').update(rawOutput).digest('hex'),
      rawModelOutput: rawOutput,
    };
    const accepted = recordAcceptedClassifierSemanticRetryLedger(db, {
      issueNumber: 7401,
      rawModelOutput: rawOutput,
      sourceIdentity,
      responseId: provenance.responseId,
    });
    const rawClassification = classification({
      rationale: 'Startup fails.',
      provenance,
    });
    assert.throws(
      () => db.upsertClassification(
        7401,
        rawClassification,
        '2040-04-01T00:00:00.000Z',
        8,
        commentsDigest,
        sourceIdentity,
      ),
      /accepted classifier ledger binding is required/,
    );
    db.upsertClassification(
      7401,
      rawClassification,
      '2040-04-01T00:00:00.000Z',
      8,
      commentsDigest,
      sourceIdentity,
      accepted,
    );
    const integrity = db.classifierClassificationPublicationIntegrity(7401);
    assert.equal(integrity.valid, true, integrity.problems.join('\n'));
    assert.equal(
      integrity.publication?.raw_model_output_hash,
      provenance.rawModelOutputHash,
    );
    assert.equal(
      integrity.publication?.selected_attempt_content_hash,
      accepted.selectedAttemptBinding.attemptContentHash,
    );
    assert.notEqual(accepted.initialRequestHash, accepted.finalRequestHash);
    assert.equal(accepted.ledger.run.requestHash, accepted.initialRequestHash);
    assert.equal(
      accepted.selectedAttemptBinding.provenance.requestHash,
      accepted.finalRequestHash,
    );
    assert.equal(
      integrity.publication?.request_hash,
      accepted.finalRequestHash,
    );
    assert.equal(
      JSON.parse(integrity.publication?.binding_json ?? '{}').requestHash,
      accepted.finalRequestHash,
    );
    const publishedRevision = db.getClassification(7401)?.revision;
    assert.throws(
      () => db.upsertClassification(
        7401,
        rawClassification,
        '2040-04-01T00:00:00.000Z',
        8,
        commentsDigest,
        sourceIdentity,
        accepted,
      ),
      /already authorized classification/,
    );
    assert.equal(db.getClassification(7401)?.revision, publishedRevision);
    assert.equal(db.listClassifierClassificationPublications().length, 1);
    assert.throws(
      () => db.db.prepare(`
        UPDATE classifier_classification_publications
        SET raw_response_hash=raw_response_hash
      `).run(),
      /classifier_classification_publications is append-only/,
    );

    db.db.exec('PRAGMA wal_checkpoint(TRUNCATE)');
    const restart = spawnSync(process.execPath, [
      '--import',
      'tsx',
      '--input-type=module',
      '--eval',
      `
        const imported = await import('./src/lib/db.ts?classifier-restart=' + Date.now());
        const db = imported.default ?? imported;
        const ledger = db.getClassifierAttemptLedger('classifier-run-7401-chatcmpl-binding');
        const integrity = db.classifierClassificationPublicationIntegrity(7401);
        if (!ledger || ledger.receipt.status !== 'accepted_success') process.exit(11);
        if (!integrity.valid) process.exit(12);
        db.db.close();
      `,
    ], {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing', {
        DOTENV_CONFIG_PATH: emptyDotenvPath,
        RADAR_DB_READ_ONLY: '1',
        NODE_ENV: 'test',
      }),
      encoding: 'utf8',
    });
    assert.equal(restart.status, 0, `${restart.stdout}\n${restart.stderr}`);

    db.db.exec(`DROP TRIGGER classifier_attempts_no_update`);
    try {
      db.db.prepare(`
        UPDATE classifier_attempts
        SET attempt_json=json_set(attempt_json, '$.status', 'semantic_rejection')
        WHERE attempt_id=?
      `).run(accepted.selectedAttemptBinding.attemptId);
      assert.throws(
        () => db.getClassifierAttemptLedger(accepted.ledger.run.runId),
        /Invalid classifier attempt ledger|storage does not match its canonical payload|contentHash/,
      );
      const tampered = db.classifierClassificationPublicationIntegrity(7401);
      assert.equal(tampered.valid, false);
    } finally {
      db.db.exec(`
        CREATE TRIGGER classifier_attempts_no_update
        BEFORE UPDATE ON classifier_attempts
        BEGIN
          SELECT RAISE(ABORT, 'classifier_attempts is append-only');
        END
      `);
    }
  });

  it('projects complete raw classifier provenance through joined release issue views', async () => {
    const db = await freshDb('joined-classification-provenance');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v2', '2026-06-10T00:00:00Z', false, testReleaseCommitOid('v2')),
      catalogRelease('v1', '2026-06-01T00:00:00Z', false, testReleaseCommitOid('v1')),
    ]);
    seedIssue(db, 7101, null, '2026-06-02T00:00:00Z');
    seedIssue(db, 7102, '2026-06-03T00:00:00Z', '2026-06-02T01:00:00Z');
    seedIssue(db, 7103, '2026-06-04T00:00:00Z', '2026-06-02T02:00:00Z');
    seedClosure(db, 7102, 'COMPLETED', '2026-06-03T00:00:00Z');
    seedClosure(db, 7103, 'NOT_PLANNED', '2026-06-04T00:00:00Z');
    seedClosureProof(db, 'v1', 7102, 'fixed_in_release');

    const sourceIdentity = db.classifierSourceIdentity(['v2', 'v1'], 8);
    const rawOutput = JSON.stringify({
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      affected_users_evidence: 'The issue affects the default Windows configuration.',
      hasWorkaround: false,
      workaroundStatus: 'unknown',
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.9,
      rationale: 'Raw classifier provenance fixture.',
    });
    const provenance = {
      schemaVersion: 1 as const,
      responseId: 'chatcmpl-joined-provenance',
      requestedModel: sourceIdentity.model,
      responseModel: sourceIdentity.model,
      requestedServiceTier: sourceIdentity.serviceTier,
      responseServiceTier: sourceIdentity.serviceTier,
      reasoningEffort: sourceIdentity.reasoningEffort,
      promptVersion: 8,
      promptTemplateHash: CLASSIFICATION_PROMPT_TEMPLATE_HASH,
      promptHash: 'b'.repeat(64),
      rawModelOutputHash: createHash('sha256').update(rawOutput).digest('hex'),
      rawModelOutput: rawOutput,
    };
    for (const issueNumber of [7101, 7102, 7103]) {
      const accepted = recordAcceptedClassifierLedger(db, {
        issueNumber,
        rawModelOutput: rawOutput,
        sourceIdentity,
        responseId: provenance.responseId,
      });
      db.upsertClassification(
        issueNumber,
        classification({
          rationale: 'Raw classifier provenance fixture.',
          provenance,
        }),
        db.getIssue(issueNumber).updated_at,
        8,
        commentEvidenceDigest(0, []),
        sourceIdentity,
        accepted,
      );
    }

    const assertProvenance = (row: any) => {
      assert.ok(row);
      assert.equal(row.classification_origin, 'raw_model');
      assert.equal(row.raw_model_output, rawOutput);
      assert.deepEqual(JSON.parse(row.provenance_json), provenance);
      assert.deepEqual(JSON.parse(row.source_identity_json), sourceIdentity);
      assert.equal(row.source_identity_digest, sourceIdentity.digest);
      assert.equal(row.prompt_version, 8);
      assert.equal(row.classified_comments_digest, commentEvidenceDigest(0, []));
    };

    for (const issueNumber of [7101, 7102, 7103]) {
      assertProvenance(db.issuesForVersion('v1').find((row: any) => row.number === issueNumber));
    }
    assertProvenance(db.openedDuringReign('v1').find((row: any) => row.number === 7101));
    assertProvenance(db.closedDuringReign('v1').find((row: any) => row.number === 7102));
    assertProvenance(db.verifiedFixedForRelease('v1').find((row: any) => row.number === 7102));
    assertProvenance(db.unverifiedClosedForRelease('v1').find((row: any) => row.number === 7103));
  });

  it('classifies openclaw-barnacle as an automation author', async () => {
    const db = await freshDb('bot-author-openclaw-barnacle');
    assert.equal(db.detectBot('openclaw-barnacle', '[]'), true);
    assert.equal(db.detectBot('OpenClaw-Barnacle', '[]'), true);
    assert.equal(db.detectBot('openclaw-barnacle-user', '[]'), false);
  });

  it('tracks release-row source freshness for score-affecting metadata', async () => {
    const db = await freshDb('release-row-freshness');
    seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
    db.updateReleaseDerivedStats({
      tag: 'v1',
      breaking_count: 1,
      fixes_count: 2,
      changes_count: 3,
      highlights_count: 4,
      pr_refs_count: 5,
      beta_count: 0,
      hours_to_next_release: null,
      hours_to_next_stable: null,
      npm_package_url: 'https://example.test/pkg',
      release_tarball_url: 'https://example.test/tarball',
      release_integrity: 'sha512-test',
      release_sha: 'sha-test',
      full_release_ci_report_url: 'https://example.test/ci',
      full_release_validation_url: 'https://example.test/validation',
    });
    db.updateReleaseArtifactVerification({
      tag: 'v1',
      registry_version: '1.0.0',
      registry_integrity: 'sha512-registry',
      registry_tarball_url: 'https://example.test/registry.tgz',
      ci_report_verified: 1,
      ci_report_mismatch: null,
      release_validation_verified: 1,
      release_validation_mismatch: null,
      artifact_verified: 1,
      artifact_mismatch: null,
    });

    const release = db.getRelease('v1');
    assert.ok(release);
    assert.ok(Date.parse(String(release.release_metadata_fetched_at)));
    assert.ok(Date.parse(String(release.release_derived_fetched_at)));
    assert.ok(Date.parse(String(release.release_artifact_checked_at)));

    const releaseMetadata = db.releaseDataFreshness('v1').sources.find((source: any) => source.source === 'release_metadata');
    assert.ok(releaseMetadata);
    assert.ok(Date.parse(String(releaseMetadata.maxAt)));
    assert.ok(db.dataFreshnessCacheDigest().count > 0);
  });

  it('tracks local issue fetch freshness separately from GitHub issue updated_at', async () => {
    const db = await freshDb('issue-fetch-freshness');
    seedRelease(db, 'v-fetch', '2036-06-01T00:00:00Z');
    seedIssue(db, 6101, null, '2036-06-01T12:00:00Z');

    const issue = db.getIssue(6101);
    assert.ok(issue);
    assert.ok(Date.parse(String(issue.fetched_at)));

    const freshness = db.releaseDataFreshness('v-fetch');
    const issueRows = freshness.sources.find((source: any) => source.source === 'issue_rows');
    const issueFetches = freshness.sources.find((source: any) => source.source === 'issue_fetches');
    assert.ok(issueRows);
    assert.ok(issueFetches);
    assert.equal(issueRows.maxAt, '2036-06-01T12:00:00Z');
    assert.ok(Date.parse(String(issueFetches.maxAt)));
    assert.notEqual(issueFetches.maxAt, issueRows.maxAt);
    assert.ok(db.dataFreshnessCacheDigest().digest);
  });

  it('separates issue observation time from semantic source freshness', async () => {
    const db = await freshDb('issue-observation-vs-semantic-freshness');
    seedIssue(db, 6151, null, '2036-06-01T12:00:00Z');
    const issue = db.getIssue(6151);
    assert.ok(issue);
    db.db.prepare(`UPDATE issues SET fetched_at=?, checked_at=? WHERE number=?`)
      .run('2000-01-01T00:00:00Z', '2000-01-01T00:00:00Z', 6151);

    db.upsertIssue(issue);
    const unchanged = db.getIssue(6151);
    assert.equal(unchanged?.fetched_at, '2000-01-01T00:00:00Z');
    assert.notEqual(unchanged?.checked_at, '2000-01-01T00:00:00Z');

    db.upsertIssue({ ...issue, title: 'semantic issue change' });
    const changed = db.getIssue(6151);
    assert.notEqual(changed?.fetched_at, '2000-01-01T00:00:00Z');
  });

  it('tracks issue comment snapshot freshness for release issue universes', async () => {
    const db = await freshDb('issue-comment-freshness');
    seedRelease(db, 'v-comment-fresh', '2037-06-01T00:00:00Z');
    seedIssue(db, 6201, null, '2037-06-01T12:00:00Z');
    db.db.prepare(`UPDATE issues SET comments=2 WHERE number=6201`).run();
    const comments = [
      {
        id: 1,
        user: { login: 'one' },
        body: 'one',
        created_at: '2037-06-01T12:20:00Z',
        updated_at: '2037-06-01T12:20:00Z',
      },
      {
        id: 2,
        user: { login: 'two' },
        body: 'two',
        created_at: '2037-06-01T12:30:00Z',
        updated_at: '2037-06-01T12:30:00Z',
      },
    ];
    db.upsertIssueCommentSnapshot({
      issue_number: 6201,
      schema_version: 2,
      comment_count: 2,
      fetched_comment_count: 2,
      latest_comment_updated_at: '2037-06-01T12:30:00Z',
      comments_digest: commentEvidenceDigest(2, comments),
      issue_updated_at: '2037-06-01T12:00:00Z',
      comments_json: serializeCommentEvidence(comments),
    });

    const row = db.db.prepare(`SELECT * FROM issue_comment_snapshots WHERE issue_number=6201`).get() as any;
    assert.equal(row.comment_count, 2);
    assert.equal(row.fetched_comment_count, 2);
    assert.equal(row.latest_comment_updated_at, '2037-06-01T12:30:00Z');
    assert.equal(row.schema_version, 2);
    assert.ok(Date.parse(String(row.verified_at)));
    assert.ok(Date.parse(String(row.fetched_at)));

    const freshness = db.releaseDataFreshness('v-comment-fresh');
    const issueComments = freshness.sources.find((source: any) => source.source === 'issue_comments');
    assert.ok(issueComments);
    assert.equal(issueComments.count, 1);
    assert.equal(issueComments.nullCount, 0);
    assert.equal(issueComments.maxAt, row.verified_at);
    assert.ok(db.dataFreshnessCacheDigest().digest);
  });

  it('reconstructs score freshness from state and closure dependency snapshots', async () => {
    const db = await freshDb('score-freshness-snapshot-sources');
    const tag = 'v-snapshot-freshness';
    const issueNumber = 6251;
    const issueUpdatedAt = '2041-01-01T12:00:00Z';
    const stateFetchedAt = '2041-01-01T13:00:00Z';
    const dependencyCapturedAt = '2041-01-01T14:00:00Z';
    seedRelease(db, tag, '2041-01-01T00:00:00Z');
    seedIssue(db, issueNumber, null, issueUpdatedAt);
    db.replaceIssueStateEventSnapshot({
      issue_number: issueNumber,
      issue_state: 'open',
      issue_updated_at: issueUpdatedAt,
      total_count: 0,
      fetched_count: 0,
      sweep_count: 2,
      stabilized: true,
      closure_events: [],
      reopen_events: [],
      ...authoritativeStateSnapshotFields({
        repositoryNodeId: 'R_snapshot_freshness',
        issueNumber,
        issueNodeId: 'I_snapshot_freshness_6251',
        issueState: 'open',
        issueUpdatedAt,
        events: [],
      }),
    });
    db.db.prepare(`
      UPDATE issue_state_event_snapshots
      SET fetched_at=?
      WHERE issue_number=?
    `).run(stateFetchedAt, issueNumber);
    db.replaceReleaseClosureDependencySnapshot(
      db.releaseClosureDependencyIdentity(tag, [issueNumber]),
    );
    db.db.prepare(`
      UPDATE release_closure_dependency_snapshots
      SET captured_at=?
      WHERE release_tag=?
    `).run(dependencyCapturedAt, tag);

    const freshness = db.releaseDataFreshness(tag);
    const sources = new Map(
      freshness.sources.map((source: any) => [source.source, source]),
    );
    assert.deepEqual(sources.get('issue_state_event_snapshots'), {
      source: 'issue_state_event_snapshots',
      count: 1,
      nullCount: 0,
      maxAt: stateFetchedAt,
      ageHoursAtScore: null,
    });
    assert.deepEqual(sources.get('release_closure_dependency_snapshots'), {
      source: 'release_closure_dependency_snapshots',
      count: 1,
      nullCount: 0,
      maxAt: dependencyCapturedAt,
      ageHoursAtScore: null,
    });
    assert.equal(freshness.sourceFetchedAtMax, dependencyCapturedAt);
  });

  it('rejects verified comment-body tampering during score integrity checks', async () => {
    const db = await freshDb('issue-comment-body-tamper');
    seedRelease(db, 'v-comment-tamper', '2037-06-01T00:00:00Z');
    seedIssue(db, 6202, null, '2037-06-01T12:00:00Z');
    const comments = insertAuthoritativeTestCommentSnapshot(db, {
      issueNumber: 6202,
      issueUpdatedAt: '2037-06-01T12:00:00Z',
      body: 'original verified body',
      createdAt: '2037-06-01T12:30:00Z',
    });
    const commentsDigest = commentEvidenceDigest(1, comments);
    const classifierIdentity = db.classifierSourceIdentity(['v-comment-tamper'], 6);
    db.upsertClassification(
      6202,
      classification(),
      '2037-06-01T12:00:00Z',
      6,
      commentsDigest,
      classifierIdentity,
    );
    assert.equal(
      db.releaseCommentClassificationIntegrity(
        'v-comment-tamper',
        6,
        ['v-comment-tamper'],
      ).failedCount,
      0,
    );

    db.db.prepare(`
      UPDATE issue_comment_snapshots
      SET comments_json=?
      WHERE issue_number=6202
    `).run(serializeCommentEvidence([{ ...comments[0], body: 'tampered body' }]));
    const integrity = db.releaseCommentClassificationIntegrity(
      'v-comment-tamper',
      6,
      ['v-comment-tamper'],
    );
    assert.equal(integrity.commentDigestMismatchCount, 1);
    assert.equal(integrity.invalidSnapshotCount, 1);
    assert.ok(integrity.failedCount > 0);
  });

  it('rejects digest-mismatched snapshots from compact public comment evidence', async () => {
    const db = await freshDb('compact-comment-digest-tamper');
    seedIssue(db, 6203, null, '2037-06-01T12:00:00Z');
    const comments = insertAuthoritativeTestCommentSnapshot(db, {
      issueNumber: 6203,
      issueUpdatedAt: '2037-06-01T12:00:00Z',
      body: 'original verified body',
      createdAt: '2037-06-01T12:30:00Z',
    });
    assert.deepEqual(
      [...db.compactIssueCommentEvidence([6203])],
      [{
        issue_number: 6203,
        complete: 1,
        id: 1,
        url: 'https://example.test/issues/6203#issuecomment-1',
        comment_node_id: 'IC_test_6203_1',
        comment_node_type: 'IssueComment',
        author: 'reporter',
        actor_node_id: 'U_closure_claim_reporter_6203',
        actor_type: 'User',
        author_association: null,
        body: 'original verified body',
        created_at: '2037-06-01T12:30:00Z',
        updated_at: '2037-06-01T12:30:00Z',
      }],
    );

    db.db.prepare(`
      UPDATE issue_comment_snapshots
      SET comments_json=?
      WHERE issue_number=6203
    `).run(serializeCommentEvidence([{ ...comments[0], body: 'tampered body' }]));

    assert.deepEqual(
      [...db.compactIssueCommentEvidence([6203])],
      [{
        issue_number: 6203,
        complete: 0,
        id: null,
        url: null,
        comment_node_id: null,
        comment_node_type: null,
        author: null,
        actor_node_id: null,
        actor_type: null,
        author_association: null,
        body: null,
        created_at: null,
        updated_at: null,
      }],
    );
  });

  it('preserves issue comment snapshot freshness when comment content is unchanged', async () => {
    const db = await freshDb('issue-comment-freshness-noop');
    db.upsertIssueCommentSnapshot({
      issue_number: 6301,
      comment_count: 1,
      fetched_comment_count: 1,
      latest_comment_updated_at: '2038-06-01T12:30:00Z',
      comments_digest: 'same-digest',
      issue_updated_at: '2038-06-01T12:30:00Z',
      comments_json: '[{"id":1,"body":"cached"}]',
    });
    const first = db.db.prepare(`SELECT fetched_at FROM issue_comment_snapshots WHERE issue_number=6301`).get() as any;

    db.upsertIssueCommentSnapshot({
      issue_number: 6301,
      comment_count: 1,
      fetched_comment_count: 1,
      latest_comment_updated_at: '2038-06-01T12:30:00Z',
      comments_digest: 'same-digest',
      issue_updated_at: '2038-06-01T12:30:00Z',
      comments_json: '[{"id":1,"body":"cached"}]',
    });
    const unchanged = db.db.prepare(`
      SELECT fetched_at, issue_updated_at, comments_json
      FROM issue_comment_snapshots
      WHERE issue_number=6301
    `).get() as any;
    assert.equal(unchanged.fetched_at, first.fetched_at);
    assert.equal(unchanged.issue_updated_at, '2038-06-01T12:30:00Z');
    assert.equal(unchanged.comments_json, '[{"id":1,"body":"cached"}]');

    db.upsertIssueCommentSnapshot({
      issue_number: 6301,
      comment_count: 2,
      fetched_comment_count: 2,
      latest_comment_updated_at: '2038-06-01T12:45:00Z',
      comments_digest: 'changed-digest',
    });
    const changed = db.db.prepare(`SELECT fetched_at, comment_count, comments_digest FROM issue_comment_snapshots WHERE issue_number=6301`).get() as any;
    assert.equal(changed.comment_count, 2);
    assert.equal(changed.comments_digest, 'changed-digest');
    assert.ok(changed.fetched_at >= first.fetched_at);
  });

  it('reuses raw closure evidence only when issue and complete comment dependencies match', async () => {
    const db = await freshDb('closure-evidence-refresh-state');
    seedIssue(db, 6351, '2038-06-02T00:00:00Z', '2038-06-01T00:00:00Z');
    insertAuthoritativeTestCommentSnapshot(db, {
      issueNumber: 6351,
      issueUpdatedAt: '2038-06-02T00:00:00Z',
      body: 'cached',
      createdAt: '2038-06-01T12:30:00Z',
    });

    assert.deepEqual(db.closureEvidenceIssuesNeedingRefresh([6351], 1), [6351]);
    db.markIssueClosureEvidenceRefreshed([6351], 1);
    assert.deepEqual(db.closureEvidenceIssuesNeedingRefresh([6351], 1), []);
    assert.deepEqual(db.closureEvidenceIssuesNeedingRefresh([6351], 2), [6351]);

    db.upsertIssue({
      number: 6351,
      state: 'closed',
      title: 'issue 6351 updated',
      author: 'tester',
      html_url: 'https://example.test/issues/6351',
      created_at: '2038-06-01T00:00:00Z',
      updated_at: '2038-06-03T00:00:00Z',
      closed_at: '2038-06-02T00:00:00Z',
      comments: 1,
      labels: '[]',
      is_bot: 0,
    });
    assert.deepEqual(db.closureEvidenceIssuesNeedingRefresh([6351], 1), [6351]);
    assert.throws(
      () => db.markIssueClosureEvidenceRefreshed([6351], 1),
      /only 0 had complete current comment evidence/,
    );
  });

  it('preserves unchanged label evidence timestamps and avoids duplicate snapshots', async () => {
    const db = await freshDb('label-evidence-noop');
    db.upsertIssueLabelEvent({
      issue_number: 6401,
      event_id: 'label-6401',
      action: 'labeled',
      label_name: 'bug',
      actor_login: 'maintainer',
      actor_type: 'User',
      created_at: '2038-06-01T00:00:00Z',
    });
    const firstFetchedAt = (db.db.prepare(`
      SELECT fetched_at
      FROM issue_label_events
      WHERE event_id='label-6401'
    `).get() as any).fetched_at;
    db.upsertIssueLabelEvent({
      issue_number: 6401,
      event_id: 'label-6401',
      action: 'labeled',
      label_name: 'bug',
      actor_login: 'maintainer',
      actor_type: 'User',
      created_at: '2038-06-01T00:00:00Z',
    });
    assert.equal(
      (db.db.prepare(`SELECT fetched_at FROM issue_label_events WHERE event_id='label-6401'`).get() as any).fetched_at,
      firstFetchedAt,
    );
    assert.throws(
      () => db.upsertIssueLabelEvent({
        issue_number: 6402,
        event_id: 'label-6401',
        action: 'unlabeled',
        label_name: 'impact:discord',
        actor_login: 'other-maintainer',
        created_at: '2038-06-02T00:00:00Z',
      }),
      /label-6401 conflicts with immutable persisted provenance/,
    );
    assert.deepEqual(
      { ...(db.db.prepare(`
        SELECT issue_number, action, label_name, actor_login, actor_type, created_at, fetched_at
        FROM issue_label_events
        WHERE event_id='label-6401'
      `).get() as Record<string, unknown>) },
      {
        issue_number: 6401,
        action: 'labeled',
        label_name: 'bug',
        actor_login: 'maintainer',
        actor_type: 'User',
        created_at: '2038-06-01T00:00:00Z',
        fetched_at: firstFetchedAt,
      },
    );

    db.upsertIssueLabelSnapshot({
      issue_number: 6401,
      snapshot_at: '2038-06-01T00:00:00Z',
      labels_json: '["bug"]',
    });
    db.upsertIssueLabelSnapshot({
      issue_number: 6401,
      snapshot_at: '2038-06-02T00:00:00Z',
      labels_json: '["bug"]',
    });
    assert.equal(
      (db.db.prepare(`SELECT COUNT(*) AS count FROM issue_label_snapshots WHERE issue_number=6401`).get() as any).count,
      1,
    );
  });

  it('persists actor types while legacy null label actors remain unknown and immutable', async () => {
    const db = await freshDb('label-authority-legacy-actor');
    db.upsertIssueLabelEvent({
      issue_number: 6402,
      event_id: 'label-typed',
      action: 'labeled',
      label_name: 'P1',
      actor_login: 'alice',
      actor_type: 'User',
      created_at: '2026-07-04T12:00:00Z',
    });
    assert.equal(
      (db.db.prepare(`
        SELECT actor_type
        FROM issue_label_events
        WHERE event_id='label-typed'
      `).get() as any).actor_type,
      'User',
    );

    db.upsertIssueLabelEvent({
      issue_number: 6403,
      event_id: 'label-legacy-null',
      action: 'labeled',
      label_name: 'P1',
      actor_login: 'alice',
      created_at: '2026-07-04T12:00:00Z',
    });
    assert.throws(
      () => db.upsertIssueLabelEvent({
        issue_number: 6403,
        event_id: 'label-legacy-null',
        action: 'labeled',
        label_name: 'P1',
        actor_login: 'alice',
        actor_type: 'User',
        created_at: '2026-07-04T12:00:00Z',
      }),
      /legacy append-only evidence and cannot be silently enriched/,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT actor_type
        FROM issue_label_events
        WHERE event_id='label-legacy-null'
      `).get() as any).actor_type,
      null,
    );
    assert.throws(
      () => db.resolveLabelAuthorityForEvent('label-legacy-null'),
      /authority evidence is invalid: event repositoryNodeId is missing; event actor nodeId is missing/,
    );
    assert.throws(
      () => db.db.prepare(`
        UPDATE issue_label_events
        SET actor_type='User'
        WHERE event_id='label-legacy-null'
      `).run(),
      /issue_label_events is append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM issue_label_events
        WHERE event_id='label-legacy-null'
      `).run(),
      /issue_label_events is append-only/,
    );
  });

  it('resolves collaborator authority exclusively from v2 repository and actor node identities', async () => {
    const db = await freshDb('label-authority-resolution');
    seedRelease(db, 'v-label-authority');
    const before = db.scoreSourceIdentity();
    db.insertRepositoryCollaboratorPermissionSnapshotV2(
      buildRepositoryCollaboratorPermissionSnapshot({
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        observedAt: '2026-07-04T11:30:00Z',
        exhaustive: true,
        complete: true,
        totalCount: 3,
        pageCount: 1,
        pagesFetched: 2,
        sweepCount: 2,
        rows: [
          {
            nodeId: 'U_alice',
            login: 'alice-after-rename',
            actorType: 'User',
            association: 'MEMBER',
            permission: 'maintain',
          },
          {
            nodeId: 'U_bob',
            login: 'bob',
            actorType: 'User',
            association: 'MEMBER',
            permission: 'maintain',
          },
          {
            nodeId: 'U_login_collision',
            login: 'alice-before-rename',
            actorType: 'User',
            association: 'COLLABORATOR',
            permission: 'read',
          },
        ],
      }),
    );
    insertAuthorityLabelEvent(db, {
      issueNumber: 6404,
      eventId: 'label-permission-authorized',
      actorNodeId: 'U_alice',
      actorLogin: 'alice-before-rename',
      actorType: 'User',
      eventTime: '2026-07-04T12:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });
    insertAuthorityLabelEvent(db, {
      issueNumber: 6405,
      eventId: 'label-permission-too-new',
      actorNodeId: 'U_bob',
      actorLogin: 'bob',
      actorType: 'User',
      eventTime: '2026-07-04T10:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });
    insertAuthorityLabelEvent(db, {
      issueNumber: 6406,
      eventId: 'label-login-collision',
      actorNodeId: 'U_intruder',
      actorLogin: 'alice-after-rename',
      actorType: 'User',
      eventTime: '2026-07-04T12:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });
    db.db.prepare(`
      INSERT INTO approved_maintainer_roster_snapshots (
        snapshot_id, schema_version, repository, approval_id, approved_at,
        row_count, content_digest, source_identity
      ) VALUES (
        'legacy-roster', 1, 'openclaw/openclaw', 'legacy-approval',
        '2026-07-04T09:00:00Z', 1, ?, 'legacy-roster-source'
      )
    `).run(authorityFixtureHash('legacy-roster'));
    db.db.prepare(`
      INSERT INTO approved_maintainer_roster_entries (
        snapshot_id, evidence_id, source_identity, actor_login, actor_type,
        role, effective_from, effective_until
      ) VALUES (
        'legacy-roster', 'legacy-entry', 'legacy-entry-source',
        'alice-after-rename', 'User', 'admin', '2026-01-01T00:00:00Z', NULL
      )
    `).run();

    assert.equal(
      db.resolveLabelAuthorityForEvent('label-permission-authorized').reason,
      'authorized_by_repository_permission',
    );
    assert.equal(
      db.resolveLabelAuthorityForEvent('label-permission-too-new').reason,
      'current_permission_cannot_prove_prior_authority',
    );
    assert.equal(
      db.resolveLabelAuthorityForEvent('label-login-collision').reason,
      'authority_proof_absent',
    );
    const after = db.scoreSourceIdentity();
    assert.notEqual(after.digest, before.digest);
    for (const source of [
      'repository_collaborator_permission_snapshots',
      'repository_collaborator_permission_rows',
      'approved_maintainer_roster_snapshots',
      'approved_maintainer_roster_entries',
    ]) {
      assert.equal(
        after.sources.find((entry: any) => entry.source === source),
        undefined,
        `${source} is legacy display evidence and must not participate in current source identity`,
      );
    }
  });

  it('persists and resolves signed roster authority by immutable node identity', async () => {
    const db = await freshDb('label-authority-signed-roster');
    const keyring = buildApprovedMaintainerRosterKeyring({
      schemaVersion: APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
      purpose: APPROVED_ROSTER_KEYRING_PURPOSE,
      repositoryNodeId: 'R_openclaw',
      repository: 'openclaw/openclaw',
      keys: [{
        keyId: 'operator-key-1',
        algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
        secret: Buffer.alloc(32, 23).toString('base64'),
        validFrom: '2026-01-01T00:00:00Z',
        validUntil: null,
        revokedAt: null,
      }],
    });
    const first = buildApprovedMaintainerRosterSnapshot(
      signApprovedMaintainerRosterManifest({
        schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
        purpose: APPROVED_ROSTER_PURPOSE,
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        approvalId: 'signed-roster-approval-1',
        approvedAt: '2026-07-04T09:00:00Z',
        sequence: 1,
        priorDigest: null,
        signerKeyId: 'operator-key-1',
        entries: [{
          actorNodeId: 'U_alice',
          login: 'alice-before-rename',
          actorType: 'User',
          association: 'MEMBER',
          role: 'maintain',
          effectiveFrom: '2026-01-01T00:00:00Z',
          effectiveUntil: '2026-07-04T11:00:00Z',
        }],
      }, keyring),
      {
        keyring,
        expectedRepositoryNodeId: 'R_openclaw',
        previousState: null,
        verifiedAt: '2026-07-04T09:00:01Z',
      },
    );
    assert.deepEqual(
      db.insertSignedApprovedMaintainerRosterSnapshot(first),
      first,
    );
    assert.deepEqual(
      db.getSignedApprovedMaintainerRosterSnapshot(first.snapshotId),
      first,
    );

    insertAuthorityLabelEvent(db, {
      issueNumber: 6411,
      eventId: 'label-roster-before-rename',
      actorNodeId: 'U_alice',
      actorLogin: 'alice-renamed',
      actorType: 'User',
      eventTime: '2026-07-04T10:00:00Z',
      issueUpdatedAt: '2026-07-04T10:01:00Z',
    });
    insertAuthorityLabelEvent(db, {
      issueNumber: 6412,
      eventId: 'label-roster-login-collision',
      actorNodeId: 'U_intruder',
      actorLogin: 'alice-before-rename',
      actorType: 'User',
      eventTime: '2026-07-04T10:00:00Z',
      issueUpdatedAt: '2026-07-04T10:01:00Z',
    });
    assert.equal(
      db.resolveLabelAuthorityForEvent('label-roster-before-rename').reason,
      'authorized_by_approved_roster',
    );
    assert.equal(
      db.resolveLabelAuthorityForEvent('label-roster-login-collision').reason,
      'authority_proof_absent',
    );

    const firstState = approvedMaintainerRosterChainState(first);
    const second = buildApprovedMaintainerRosterSnapshot(
      signApprovedMaintainerRosterManifest({
        schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
        purpose: APPROVED_ROSTER_PURPOSE,
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        approvalId: 'signed-roster-approval-2',
        approvedAt: '2026-07-04T11:30:00Z',
        sequence: 2,
        priorDigest: first.runHash ?? null,
        signerKeyId: 'operator-key-1',
        entries: [{
          actorNodeId: 'U_alice',
          login: 'alice-renamed',
          actorType: 'User',
          association: 'OWNER',
          role: 'admin',
          effectiveFrom: '2026-07-04T11:00:00Z',
          effectiveUntil: null,
        }],
      }, keyring),
      {
        keyring,
        expectedRepositoryNodeId: 'R_openclaw',
        previousState: firstState,
        verifiedAt: '2026-07-04T11:30:01Z',
      },
    );
    db.insertSignedApprovedMaintainerRosterSnapshot(second);
    assert.deepEqual(
      db.verifySignedApprovedMaintainerRosterChain({
        repositoryNodeId: 'R_openclaw',
      }),
      [first, second],
    );
    insertAuthorityLabelEvent(db, {
      issueNumber: 6413,
      eventId: 'label-roster-after-rotation',
      actorNodeId: 'U_alice',
      actorLogin: 'alice-renamed-again',
      actorType: 'User',
      eventTime: '2026-07-04T12:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });
    const resolution = db.resolveLabelAuthorityForEvent(
      'label-roster-after-rotation',
    );
    assert.equal(resolution.reason, 'authorized_by_approved_roster');
    assert.equal(resolution.authorizedForScoring, true);
  });

  it('ingests configured signed rosters idempotently with a monotonic checkpoint', async () => {
    const db = await freshDb('label-authority-configured-roster');
    const directory = mkdtempSync(join(tmpdir(), 'radar-signed-roster-'));
    try {
      const rosterPath = join(directory, 'roster.json');
      const keyringPath = join(directory, 'keyring.json');
      const statePath = join(directory, 'state.json');
      const keyringManifest = {
        schemaVersion: APPROVED_ROSTER_KEYRING_SCHEMA_VERSION,
        purpose: APPROVED_ROSTER_KEYRING_PURPOSE,
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        keys: [{
          keyId: 'operator-key-1',
          algorithm: APPROVED_ROSTER_SIGNATURE_ALGORITHM,
          secret: Buffer.alloc(32, 29).toString('base64'),
          validFrom: '2026-01-01T00:00:00Z',
          validUntil: null,
          revokedAt: null,
        }],
      } as const;
      const keyring = buildApprovedMaintainerRosterKeyring(keyringManifest);
      const manifest = signApprovedMaintainerRosterManifest({
        schemaVersion: APPROVED_ROSTER_SNAPSHOT_SCHEMA_VERSION,
        purpose: APPROVED_ROSTER_PURPOSE,
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        approvalId: 'configured-roster-approval-1',
        approvedAt: '2026-07-04T09:00:00Z',
        sequence: 1,
        priorDigest: null,
        signerKeyId: 'operator-key-1',
        entries: [{
          actorNodeId: 'U_alice',
          login: 'alice',
          actorType: 'User',
          association: 'MEMBER',
          role: 'maintain',
          effectiveFrom: '2026-01-01T00:00:00Z',
          effectiveUntil: null,
        }],
      }, keyring);
      writeFileSync(keyringPath, JSON.stringify(keyringManifest));
      writeFileSync(rosterPath, JSON.stringify(manifest));

      const first = db.ingestConfiguredApprovedMaintainerRosterSnapshot(
        rosterPath,
        {
          keyringPath,
          statePath,
          verifiedAt: '2026-07-04T09:00:01Z',
        },
      );
      assert.deepEqual(
        JSON.parse(readFileSync(statePath, 'utf8')),
        approvedMaintainerRosterChainState(first),
      );
      assert.deepEqual(
        db.ingestConfiguredApprovedMaintainerRosterSnapshot(
          rosterPath,
          {
            keyringPath,
            statePath,
            verifiedAt: '2026-07-05T09:00:01Z',
          },
        ),
        first,
      );

      writeFileSync(statePath, JSON.stringify({
        ...approvedMaintainerRosterChainState(first),
        runDigest: '0'.repeat(64),
      }));
      assert.throws(
        () => db.ingestConfiguredApprovedMaintainerRosterSnapshot(
          rosterPath,
          { keyringPath, statePath },
        ),
        /does not match immutable persisted history/,
      );
    } finally {
      rmSync(directory, { recursive: true, force: true });
    }
  });

  it('fails closed for conflicting collaborator permissions', async () => {
    const db = await freshDb('label-authority-conflicting-permissions');
    insertAuthorityLabelEvent(db, {
      issueNumber: 6407,
      eventId: 'label-conflicting-permissions',
      actorNodeId: 'U_alice',
      actorLogin: 'alice',
      actorType: 'User',
      eventTime: '2026-07-04T12:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });
    for (const permission of ['maintain', 'read'] as const) {
      db.insertRepositoryCollaboratorPermissionSnapshotV2(
        buildRepositoryCollaboratorPermissionSnapshot({
          repositoryNodeId: 'R_openclaw',
          repository: 'openclaw/openclaw',
          observedAt: '2026-07-04T11:30:00Z',
          exhaustive: true,
          complete: true,
          totalCount: 1,
          pageCount: 1,
          pagesFetched: 2,
          sweepCount: 2,
          rows: [{
            nodeId: 'U_alice',
            login: 'alice',
            actorType: 'User',
            association: 'MEMBER',
            permission,
          }],
        }),
      );
    }

    const resolution = db.resolveLabelAuthorityForEvent(
      'label-conflicting-permissions',
    );
    assert.equal(resolution.authority, 'unknown');
    assert.equal(resolution.reason, 'conflicting_authority_evidence');
    assert.equal(resolution.authorizedForScoring, false);
  });

  it('enforces append-only authority tables and detects stored manifest tampering', async () => {
    const db = await freshDb('label-authority-append-only');
    const collaborator = buildRepositoryCollaboratorPermissionSnapshot({
      repositoryNodeId: 'R_openclaw',
      repository: 'openclaw/openclaw',
      observedAt: '2026-07-04T11:30:00Z',
      exhaustive: true,
      complete: true,
      totalCount: 1,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      rows: [{
        nodeId: 'U_alice',
        login: 'alice',
        actorType: 'User',
        association: 'MEMBER',
        permission: 'maintain',
      }],
    });
    db.insertRepositoryCollaboratorPermissionSnapshotV2(collaborator);
    insertAuthorityLabelEvent(db, {
      issueNumber: 6408,
      eventId: 'label-authority-tamper',
      actorNodeId: 'U_alice',
      actorLogin: 'alice',
      actorType: 'User',
      eventTime: '2026-07-04T12:00:00Z',
      issueUpdatedAt: '2026-07-04T12:01:00Z',
    });

    for (const [table, updateColumn] of [
      ['issue_label_evidence_snapshots', 'captured_at'],
      ['issue_label_evidence_rows', 'raw_json'],
      ['repository_collaborator_permission_snapshots_v2', 'row_count'],
      ['repository_collaborator_permission_rows_v2', 'permission'],
    ] as const) {
      assert.throws(
        () => db.db.prepare(`UPDATE ${table} SET ${updateColumn}=${updateColumn}`).run(),
        new RegExp(`${table} is append-only`),
      );
      assert.throws(
        () => db.db.prepare(`DELETE FROM ${table}`).run(),
        new RegExp(`${table} is append-only`),
      );
    }
    assert.throws(
      () => db.insertRepositoryCollaboratorPermissionSnapshotV2({
        ...collaborator,
        complete: false,
      } as any),
      /must be exhaustive and complete/,
    );

    const triggerName =
      'repository_collaborator_permission_snapshots_v2_no_update';
    const triggerSql = (db.db.prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type='trigger' AND name=?
    `).get(triggerName) as { sql: string }).sql;
    db.db.exec(`DROP TRIGGER ${triggerName}`);
    try {
      db.db.prepare(`
        UPDATE repository_collaborator_permission_snapshots_v2
        SET content_hash=?
        WHERE snapshot_id=?
      `).run('0'.repeat(64), collaborator.snapshotId);
    } finally {
      db.db.exec(triggerSql);
    }
    assert.throws(
      () => db.labelAuthorityEvidenceForEvent('label-authority-tamper'),
      /failed immutable verification/,
    );
  });

  it('stores raw v2 authority evidence in score identity while excluding derived runs and seals', async () => {
    const db = await freshDb('authority-v2-source-identity');
    const issueNumber = 6410;
    const releaseTag = 'v-authority-2';
    seedRelease(db, releaseTag);
    seedIssue(db, issueNumber, null);
    const baseline = db.scoreSourceIdentity();
    const raw = insertRawAuthorityV2Evidence(db, issueNumber);
    const withRawEvidence = db.scoreSourceIdentity();
    assert.notEqual(withRawEvidence.digest, baseline.digest);
    for (const source of [
      'issue_label_evidence_snapshots',
      'issue_label_evidence_rows',
      'repository_collaborator_permission_snapshots_v2',
      'repository_collaborator_permission_rows_v2',
      'signed_maintainer_roster_snapshots',
      'signed_maintainer_roster_entries',
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
      'closure_claim_extraction_receipts',
      'closure_claim_extraction_receipt_members',
    ]) {
      assert.ok(
        withRawEvidence.sources.find((entry: any) => entry.source === source)?.count > 0,
        `${source} must participate in current source identity`,
      );
    }

    const derived = insertDerivedAuthorityV2Publication(
      db,
      issueNumber,
      releaseTag,
    );
    assert.deepEqual(
      db.getScoreAuthorityResolutionRun(derived.authorityRunId)?.rows
        .map((row: any) => row.subjectKind)
        .sort(),
      ['comment', 'label_event'],
    );
    assert.deepEqual(db.scoreSourceIdentity(), withRawEvidence);
    assert.equal(
      db.getReleaseScoreAudit(releaseTag)?.authority_run_id,
      derived.authorityRunId,
    );
    assert.equal(
      db.listReleaseScoreAuditHistoryForRun(derived.historyRunId)[0]?.authority_run_id,
      derived.authorityRunId,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM release_score_audit_history_v2_seals
        WHERE history_run_id=? AND authority_run_id=?
      `).get(derived.historyRunId, derived.authorityRunId) as any).count,
      1,
    );

    for (const [table, updateColumn] of [
      ['issue_label_evidence_snapshots', 'captured_at'],
      ['issue_label_evidence_rows', 'raw_json'],
      ['repository_collaborator_permission_snapshots_v2', 'raw_json'],
      ['repository_collaborator_permission_rows_v2', 'permission'],
      ['signed_maintainer_roster_snapshots', 'signature'],
      ['signed_maintainer_roster_entries', 'role'],
      ['closure_claim_source_snapshots', 'canonical_source_json'],
      ['closure_claim_candidates', 'canonical_candidate_json'],
      ['closure_claim_extraction_receipts', 'canonical_receipt_json'],
      ['closure_claim_extraction_receipt_members', 'candidate_content_hash'],
      ['score_authority_resolution_runs', 'recorded_at'],
      ['score_authority_resolution_rows', 'reason'],
      ['release_score_audit_history_v2_seals', 'sealed_at'],
    ] as const) {
      assert.throws(
        () => db.db.prepare(
          `UPDATE ${table} SET ${updateColumn}=${updateColumn}`,
        ).run(),
        new RegExp(`${table} is append-only`),
      );
      assert.throws(
        () => db.db.prepare(`DELETE FROM ${table}`).run(),
        new RegExp(`${table} is append-only`),
      );
    }

    for (const [table, parent] of [
      ['issue_label_evidence_snapshots', 'issues'],
      ['issue_label_evidence_rows', 'issue_label_evidence_snapshots'],
      ['repository_collaborator_permission_rows_v2', 'repository_collaborator_permission_snapshots_v2'],
      ['signed_maintainer_roster_entries', 'signed_maintainer_roster_snapshots'],
      ['closure_claim_source_snapshots', 'issues'],
      ['closure_claim_candidates', 'issues'],
      ['closure_claim_candidates', 'closure_claim_source_snapshots'],
      ['closure_claim_extraction_receipts', 'issues'],
      ['closure_claim_extraction_receipt_members', 'closure_claim_extraction_receipts'],
      ['closure_claim_extraction_receipt_members', 'closure_claim_candidates'],
      ['closure_claim_extraction_receipt_members', 'closure_claim_source_snapshots'],
      ['score_authority_resolution_rows', 'score_authority_resolution_runs'],
      ['release_score_audit_history_v2_seals', 'score_authority_resolution_runs'],
      ['release_score_audit_history_v2_seals', 'release_score_audit_history_runs'],
    ] as const) {
      const foreignKeys = db.db.prepare(`PRAGMA foreign_key_list(${table})`).all() as any[];
      assert.ok(
        foreignKeys.some((foreignKey) =>
          foreignKey.table === parent &&
          String(foreignKey.on_delete).toUpperCase() === 'RESTRICT'),
        `${table} must restrict deletion of ${parent}`,
      );
    }
    assert.throws(
      () => db.db.prepare(`
        INSERT INTO issue_label_evidence_rows (
          snapshot_id, connection_ordinal, event_node_id, action, label_name,
          created_at, raw_json, source_identity, content_hash
        ) VALUES (
          'missing-label-snapshot', 0, 'missing-event', 'labeled', 'P1',
          '2026-07-04T12:00:00Z', '{}', 'source:missing-label-row', ?
        )
      `).run(authorityFixtureHash('missing-label-row')),
      /FOREIGN KEY constraint failed/,
    );
  });

  it('persists one immutable source revision with every same-kind closure claim and replays exactly', async () => {
    const db = await freshDb('closure-claim-ledger-replay');
    const issueNumber = 64101;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    assert.deepEqual(extracted.rejections, []);
    const fixClaims = extracted.candidates.filter(
      (candidate) => candidate.claimKind === 'fix_proof',
    );
    assert.ok(fixClaims.length >= 3);
    assert.equal(
      new Set(fixClaims.map((candidate) => candidate.sourceIdentity)).size,
      1,
    );
    assert.equal(
      new Set(fixClaims.map((candidate) => candidate.candidateId)).size,
      fixClaims.length,
    );

    const first = db.insertClosureClaimCandidates(
      extracted.candidates,
      '2026-07-04T12:05:00Z',
    );
    assert.equal(first.insertedSourceCount, 1);
    assert.equal(first.replayedSourceCount, 0);
    assert.equal(first.insertedCandidateCount, extracted.candidates.length);
    assert.equal(first.replayedCandidateCount, 0);
    assert.deepEqual(
      db.listClosureClaimCandidatesForIssue(issueNumber)
        .map((candidate: any) => candidate.candidateId),
      first.candidateIds,
    );
    for (const candidateId of first.candidateIds) {
      assert.equal(db.getClosureClaimCandidate(candidateId)?.candidateId, candidateId);
    }

    const replay = db.insertClosureClaimCandidates(
      extracted.candidates,
      '2026-07-04T13:05:00Z',
    );
    assert.deepEqual(replay, {
      insertedSourceCount: 0,
      replayedSourceCount: 1,
      insertedCandidateCount: 0,
      replayedCandidateCount: extracted.candidates.length,
      candidateIds: first.candidateIds,
    });
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count FROM closure_claim_source_snapshots
      `).get() as any).count,
      1,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count FROM closure_claim_candidates
      `).get() as any).count,
      extracted.candidates.length,
    );
  });

  it('fails closed when one source revision replays with changed actor or content', async () => {
    const db = await freshDb('closure-claim-ledger-conflict');
    const issueNumber = 64102;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const original = closureClaimFixture(issueNumber);
    db.insertClosureClaimCandidates(original.candidates);

    const changedActor = closureClaimFixture(issueNumber, undefined, {
      actorNodeId: 'U_different_actor',
    });
    assert.throws(
      () => db.insertClosureClaimCandidates(changedActor.candidates),
      /source revision .* conflicts with stored source/,
    );
    const changedContent = closureClaimFixture(
      issueNumber,
      `Fixed by PR #${issueNumber + 10}.`,
    );
    assert.throws(
      () => db.insertClosureClaimCandidates(changedContent.candidates),
      /source revision .* conflicts with stored source/,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count FROM closure_claim_source_snapshots
      `).get() as any).count,
      1,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count FROM closure_claim_candidates
      `).get() as any).count,
      original.candidates.length,
    );
  });

  it('rejects display-only evidence and rolls back a mixed invalid candidate batch', async () => {
    const db = await freshDb('closure-claim-ledger-rollback');
    const issueNumber = 64103;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const displayOnly = closureClaimFixture(issueNumber, undefined, {
      sourceNodeId: null,
      actorNodeId: null,
      actorType: null,
    });
    assert.ok(displayOnly.candidates.length > 0);
    assert.ok(displayOnly.candidates.every(
      (candidate) => candidate.eligibility === 'display_only',
    ));
    assert.throws(
      () => db.insertClosureClaimCandidates(displayOnly.candidates),
      /display-only/,
    );

    const valid = closureClaimFixture(issueNumber);
    const missingIssue = closureClaimFixture(issueNumber + 1);
    assert.throws(
      () => db.insertClosureClaimCandidates([
        ...valid.candidates,
        ...missingIssue.candidates,
      ]),
      /does not match persisted issue/,
    );
    const mismatchedIdentity = closureClaimFixture(issueNumber, undefined, {
      issueNodeId: 'I_wrong_issue_identity',
    });
    assert.throws(
      () => db.insertClosureClaimCandidates(mismatchedIdentity.candidates),
      /does not match persisted issue/,
    );
    for (const table of [
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
    ]) {
      assert.equal(
        (db.db.prepare(
          `SELECT COUNT(*) AS count FROM ${table}`,
        ).get() as any).count,
        0,
        table,
      );
    }
  });

  it('enforces append-only closure claim storage and detects candidate or source tampering', async () => {
    let db = await freshDb('closure-claim-ledger-tamper');
    const issueNumber = 64104;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    const stored = db.insertClosureClaimCandidates(extracted.candidates);
    const candidateId = stored.candidateIds[0];

    for (const [table, updateColumn] of [
      ['closure_claim_source_snapshots', 'canonical_source_json'],
      ['closure_claim_candidates', 'canonical_candidate_json'],
    ] as const) {
      assert.throws(
        () => db.db.prepare(
          `UPDATE ${table} SET ${updateColumn}=${updateColumn}`,
        ).run(),
        new RegExp(`${table} is append-only`),
      );
      assert.throws(
        () => db.db.prepare(`DELETE FROM ${table}`).run(),
        new RegExp(`${table} is append-only`),
      );
    }

    const candidateTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger' AND name='closure_claim_candidates_no_update'
    `).get() as { sql: string };
    db.db.exec('DROP TRIGGER closure_claim_candidates_no_update');
    try {
      db.db.prepare(`
        UPDATE closure_claim_candidates
        SET canonical_claim_json='{"tampered":true}'
        WHERE candidate_id=?
      `).run(candidateId);
    } finally {
      db.db.exec(candidateTrigger.sql);
    }
    assert.throws(
      () => db.getClosureClaimCandidate(candidateId),
      /failed immutable verification/,
    );

    db = await freshDb('closure-claim-ledger-source-tamper');
    seedClosureClaimIssueIdentity(db, issueNumber);
    const sourceStored = db.insertClosureClaimCandidates(extracted.candidates);
    const sourceCandidateId = sourceStored.candidateIds[0];
    const sourceTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger'
        AND name='closure_claim_source_snapshots_no_update'
    `).get() as { sql: string };
    db.db.exec('DROP TRIGGER closure_claim_source_snapshots_no_update');
    try {
      db.db.prepare(`
        UPDATE closure_claim_source_snapshots
        SET content_hash=?
      `).run('0'.repeat(64));
    } finally {
      db.db.exec(sourceTrigger.sql);
    }
    assert.throws(
      () => db.getClosureClaimCandidate(sourceCandidateId),
      /source failed immutable verification/,
    );
  });

  it('persists and replays one exact current closure-claim extraction receipt', async () => {
    const db = await freshDb('closure-claim-extraction-receipt-replay');
    const issueNumber = 641041;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);

    const first = persistClosureClaimFixture(db, issueNumber, extracted);
    assert.equal(first.insertedReceiptCount, 1);
    assert.equal(first.replayedReceiptCount, 0);
    assert.equal(first.receipt.candidateCount, extracted.candidates.length);
    assert.deepEqual(
      first.receipt.members.map((member: any) => member.candidateId),
      first.candidatePersistence.candidateIds,
    );
    assert.deepEqual(
      db.getCurrentClosureClaimExtractionReceipt(issueNumber),
      first.receipt,
    );

    const replay = db.persistClosureClaimExtraction({
      issueNumber,
      extraction: extracted,
      capturedAt: '2026-07-04T13:05:00Z',
    });
    assert.equal(replay.insertedReceiptCount, 0);
    assert.equal(replay.replayedReceiptCount, 1);
    assert.equal(replay.receipt.receiptId, first.receipt.receiptId);
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM closure_claim_extraction_receipts
        WHERE issue_number=?
      `).get(issueNumber) as any).count,
      1,
    );
    assert.equal(
      (db.db.prepare(`
        SELECT COUNT(*) AS count
        FROM closure_claim_extraction_receipt_members
        WHERE receipt_id=?
      `).get(first.receipt.receiptId) as any).count,
      extracted.candidates.length,
    );
  });

  it('distinguishes an explicit zero-candidate receipt from missing extraction', async () => {
    const db = await freshDb('closure-claim-extraction-receipt-empty');
    const issueNumber = 641042;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const issueUpdatedAt = '2026-07-04T12:00:00Z';
    const body = 'Diagnostic logs are attached.';
    db.db.prepare(`
      UPDATE issues
      SET state='open', closed_at=NULL, comments=0, body=?, updated_at=?
      WHERE number=?
    `).run(body, issueUpdatedAt, issueNumber);
    insertClosureClaimCommentSnapshot(db, {
      issueNumber,
      issueUpdatedAt,
      comments: [],
    });
    insertClosureClaimOpenStateSnapshot(db, issueNumber, issueUpdatedAt);
    const extraction = extractClosureClaimCandidates({
      repository: {
        nodeId: 'R_openclaw',
        nameWithOwner: 'openclaw/openclaw',
      },
      issue: {
        nodeId: `I_closure_claim_${issueNumber}`,
        number: issueNumber,
        author: {
          nodeId: `U_closure_claim_reporter_${issueNumber}`,
          login: 'tester',
          type: 'User',
        },
      },
      issueBody: {
        nodeId: `I_closure_claim_${issueNumber}`,
        url: `https://example.test/issues/${issueNumber}`,
        actor: {
          nodeId: `U_closure_claim_reporter_${issueNumber}`,
          login: 'tester',
          type: 'User',
        },
        createdAt: '2026-06-01T12:00:00Z',
        updatedAt: issueUpdatedAt,
        body,
      },
    });
    assert.equal(extraction.candidates.length, 0);
    assert.equal(
      db.getCurrentClosureClaimExtractionReceipt(issueNumber),
      null,
    );

    const persisted = db.persistClosureClaimExtraction({
      issueNumber,
      extraction,
      capturedAt: '2026-07-04T12:05:00Z',
    });
    assert.equal(persisted.receipt.candidateCount, 0);
    assert.deepEqual(persisted.receipt.members, []);
    assert.equal(
      db.getCurrentClosureClaimExtractionReceipt(issueNumber)?.receiptId,
      persisted.receipt.receiptId,
    );
  });

  it('rolls back candidates and receipt when exact membership cannot commit', async () => {
    const db = await freshDb('closure-claim-extraction-receipt-rollback');
    const issueNumber = 641043;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    const issueUpdatedAt = extracted.fixtureComments[0].updatedAt!;
    db.db.prepare(`
      UPDATE issues
      SET state='open', closed_at=NULL, comments=1, updated_at=?
      WHERE number=?
    `).run(issueUpdatedAt, issueNumber);
    insertClosureClaimCommentSnapshot(db, {
      issueNumber,
      issueUpdatedAt,
      comments: extracted.fixtureComments,
    });
    insertClosureClaimOpenStateSnapshot(db, issueNumber, issueUpdatedAt);
    db.db.exec(`
      CREATE TRIGGER reject_closure_claim_receipt_member
      BEFORE INSERT ON closure_claim_extraction_receipt_members
      BEGIN
        SELECT RAISE(ABORT, 'forced receipt member failure');
      END
    `);
    try {
      assert.throws(
        () => db.persistClosureClaimExtraction({
          issueNumber,
          extraction: extracted,
          capturedAt: '2026-07-04T12:05:00Z',
        }),
        /forced receipt member failure/,
      );
    } finally {
      db.db.exec('DROP TRIGGER reject_closure_claim_receipt_member');
    }
    for (const table of [
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
      'closure_claim_extraction_receipts',
      'closure_claim_extraction_receipt_members',
    ]) {
      assert.equal(
        (db.db.prepare(
          `SELECT COUNT(*) AS count FROM ${table}`,
        ).get() as any).count,
        0,
        table,
      );
    }
  });

  it('detects extraction receipt or membership tampering before authority reconstruction', async () => {
    let db = await freshDb('closure-claim-extraction-receipt-tamper');
    const issueNumber = 641044;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    const candidate = extracted.candidates[0];
    const persisted = persistClosureClaimFixture(db, issueNumber, extracted);

    const receiptTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger'
        AND name='closure_claim_extraction_receipts_no_update'
    `).get() as { sql: string };
    db.db.exec('DROP TRIGGER closure_claim_extraction_receipts_no_update');
    try {
      db.db.prepare(`
        UPDATE closure_claim_extraction_receipts
        SET candidate_set_digest=?
        WHERE receipt_id=?
      `).run('0'.repeat(64), persisted.receipt.receiptId);
    } finally {
      db.db.exec(receiptTrigger.sql);
    }
    assert.throws(
      () => db.closureClaimAuthorityEvidenceForCandidate(candidate.candidateId),
      /failed immutable verification/,
    );

    db = await freshDb('closure-claim-extraction-member-tamper');
    seedClosureClaimIssueIdentity(db, issueNumber);
    const memberExtracted = closureClaimFixture(issueNumber);
    const memberCandidate = memberExtracted.candidates[0];
    const memberPersisted = persistClosureClaimFixture(
      db,
      issueNumber,
      memberExtracted,
    );
    const memberTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger'
        AND name='closure_claim_extraction_receipt_members_no_update'
    `).get() as { sql: string };
    db.db.exec(
      'DROP TRIGGER closure_claim_extraction_receipt_members_no_update',
    );
    try {
      db.db.prepare(`
        UPDATE closure_claim_extraction_receipt_members
        SET candidate_content_hash=?
        WHERE receipt_id=? AND member_ordinal=0
      `).run('0'.repeat(64), memberPersisted.receipt.receiptId);
    } finally {
      db.db.exec(memberTrigger.sql);
    }
    assert.throws(
      () => db.closureClaimAuthorityEvidenceForCandidate(
        memberCandidate.candidateId,
      ),
      /member 0 failed immutable verification/,
    );
  });

  it('reconstructs closure claim authority from immutable candidates and historical repository permission', async () => {
    const db = await freshDb('closure-claim-authority-permission');
    const issueNumber = 64105;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    const candidate = extracted.candidates.find((item) =>
      item.claimKind === 'fix_proof' &&
      item.claim.kind === 'fix_proof' &&
      item.claim.proofType === 'pull_request'
    );
    assert.ok(candidate);
    const persisted = persistClosureClaimFixture(
      db,
      issueNumber,
      extracted,
    );
    insertClosureClaimPermissionSnapshot(
      db,
      candidate.source.actor.nodeId!,
    );

    const evidence = db.closureClaimAuthorityEvidenceForCandidate(
      candidate.candidateId,
    );
    assert.equal(evidence.candidate.candidateId, candidate.candidateId);
    assert.equal(
      evidence.extractionReceiptId,
      persisted.receipt.receiptId,
    );
    assert.equal(
      evidence.issueAuthorNodeId,
      `U_closure_claim_reporter_${issueNumber}`,
    );
    assert.equal(evidence.permissionObservations.length, 1);
    assert.equal(evidence.approvedRosterEntries.length, 0);
    assert.equal(evidence.finalClosure, null);

    const resolution = db.resolveClosureClaimAuthorityForCandidate(
      candidate.candidateId,
    );
    assert.equal(resolution.authorizedForScoring, true);
    assert.equal(resolution.authority, 'maintainer_human');
    assert.equal(resolution.source, 'repository_permission');
    assert.equal(resolution.reason, 'authorized_by_repository_permission');
  });

  it('reconstructs reporter authority only from exact persisted issue-author identity', async () => {
    let db = await freshDb('closure-claim-authority-reporter');
    const issueNumber = 64106;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(
      issueNumber,
      'I refiled this as #64107 with a smaller reproduction.',
      {
        actorNodeId: `U_closure_claim_reporter_${issueNumber}`,
        actorLogin: 'reporter-renamed',
      },
    );
    const candidate = extracted.candidates.find((item) =>
      item.claimKind === 'reporter_action'
    );
    assert.ok(candidate);
    persistClosureClaimFixture(db, issueNumber, extracted);

    const authorized = db.resolveClosureClaimAuthorityForCandidate(
      candidate.candidateId,
    );
    assert.equal(authorized.authorizedForScoring, true);
    assert.equal(authorized.authority, 'independent_human');
    assert.equal(authorized.reason, 'authorized_reporter_action');

    db = await freshDb('closure-claim-authority-reporter-mismatch');
    seedClosureClaimIssueIdentity(
      db,
      issueNumber,
      `I_closure_claim_${issueNumber}`,
      'U_different_reporter',
    );
    assert.throws(
      () => persistClosureClaimFixture(db, issueNumber, extracted),
      /reporter identity does not match/,
    );
  });

  it('reconstructs human field confirmation without granting bots or relying on login', async () => {
    const db = await freshDb('closure-claim-authority-field-confirmation');
    const issueNumber = 64107;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(
      issueNumber,
      'I can reproduce the same failure in production.',
      {
        actorNodeId: 'U_closure_claim_customer',
        actorLogin: 'customer-before-rename',
      },
    );
    const candidate = extracted.candidates.find((item) =>
      item.claimKind === 'field_confirmation'
    );
    assert.ok(candidate);
    persistClosureClaimFixture(db, issueNumber, extracted);

    const resolution = db.resolveClosureClaimAuthorityForCandidate(
      candidate.candidateId,
    );
    assert.equal(resolution.authorizedForScoring, true);
    assert.equal(resolution.authority, 'independent_human');
    assert.equal(resolution.source, 'immutable_candidate_actor');
    assert.equal(resolution.reason, 'authorized_human_field_confirmation');
  });

  it('requires the closure event candidate and final closure to share one current receipt', async () => {
    const db = await freshDb('closure-claim-authority-final-closure');
    const issueNumber = 64108;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureEventClaimFixture(issueNumber);
    const candidate = extracted.candidates.find((item) =>
      item.claimKind === 'closure_rationale'
    );
    assert.ok(candidate);
    persistClosureClaimFixture(db, issueNumber, extracted);
    insertClosureClaimPermissionSnapshot(
      db,
      candidate.source.actor.nodeId!,
    );

    const current = db.resolveClosureClaimAuthorityForCandidate(
      candidate.candidateId,
    );
    assert.equal(current.authorizedForScoring, true);
    assert.equal(
      current.finalClosureEventId,
      `CE_closure_claim_${issueNumber}`,
    );

    db.db.prepare(`
      UPDATE issues
      SET updated_at='2026-07-04T12:30:00Z'
      WHERE number=?
    `).run(issueNumber);
    assert.throws(
      () => db.resolveClosureClaimAuthorityForCandidate(
        candidate.candidateId,
      ),
      /cached comment payload failed validation|evidence identity or revision is not current/,
    );
  });

  it('rejects a historical closure-event candidate after the current receipt changes', async () => {
    const db = await freshDb('closure-claim-authority-final-mismatch');
    const issueNumber = 64109;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureEventClaimFixture(issueNumber, {
      eventId: 'CE_nonfinal_closure_claim',
    });
    const candidate = extracted.candidates.find((item) =>
      item.claimKind === 'closure_rationale'
    );
    assert.ok(candidate);
    persistClosureClaimFixture(db, issueNumber, extracted);
    insertClosureClaimPermissionSnapshot(
      db,
      candidate.source.actor.nodeId!,
    );
    insertClosureClaimStateSnapshot(db, {
      issueNumber,
      eventId: 'CE_authoritative_final_closure',
    });

    assert.throws(
      () => db.resolveClosureClaimAuthorityForCandidate(
        candidate.candidateId,
      ),
      /has no extraction receipt for the current issue, comment, and state evidence revisions/,
    );
  });

  it('rejects candidate or source tampering before reconstructing closure claim authority', async () => {
    let db = await freshDb('closure-claim-authority-candidate-tamper');
    const issueNumber = 64110;
    seedClosureClaimIssueIdentity(db, issueNumber);
    const extracted = closureClaimFixture(issueNumber);
    const candidate = extracted.candidates[0];
    persistClosureClaimFixture(db, issueNumber, extracted);
    const candidateTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger' AND name='closure_claim_candidates_no_update'
    `).get() as { sql: string };
    db.db.exec('DROP TRIGGER closure_claim_candidates_no_update');
    try {
      db.db.prepare(`
        UPDATE closure_claim_candidates
        SET canonical_claim_json='{"tampered":true}'
        WHERE candidate_id=?
      `).run(candidate.candidateId);
    } finally {
      db.db.exec(candidateTrigger.sql);
    }
    assert.throws(
      () => db.closureClaimAuthorityEvidenceForCandidate(candidate.candidateId),
      /failed immutable verification/,
    );

    db = await freshDb('closure-claim-authority-source-tamper');
    seedClosureClaimIssueIdentity(db, issueNumber);
    const sourceExtracted = closureClaimFixture(issueNumber);
    const sourceCandidate = sourceExtracted.candidates[0];
    persistClosureClaimFixture(db, issueNumber, sourceExtracted);
    const sourceTrigger = db.db.prepare(`
      SELECT sql FROM sqlite_master
      WHERE type='trigger'
        AND name='closure_claim_source_snapshots_no_update'
    `).get() as { sql: string };
    db.db.exec('DROP TRIGGER closure_claim_source_snapshots_no_update');
    try {
      db.db.prepare(`
        UPDATE closure_claim_source_snapshots
        SET content_hash=?
      `).run('0'.repeat(64));
    } finally {
      db.db.exec(sourceTrigger.sql);
    }
    assert.throws(
      () => db.closureClaimAuthorityEvidenceForCandidate(
        sourceCandidate.candidateId,
      ),
      /source failed immutable verification/,
    );
  });

  it('persists and seals canonical score authority runs with exact history linkage', async () => {
    const db = await freshDb('authority-v2-production-storage');
    const recordedAt = '2026-07-04T18:00:00.000Z';
    const firstReleaseTag = 'v-authority-storage-1';
    const secondReleaseTag = 'v-authority-storage-2';
    const firstIssueNumber = 6413;
    const secondIssueNumber = 6414;
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        secondReleaseTag,
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid(secondReleaseTag),
      ),
      catalogRelease(
        firstReleaseTag,
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid(firstReleaseTag),
      ),
    ]);
    seedIssue(db, firstIssueNumber, null);
    seedIssue(db, secondIssueNumber, null);
    const sourceIdentity = db.scoreSourceIdentity();

    const permissionBase: RepositoryPermissionObservation = {
      kind: 'repository_permission_observation',
      evidenceId: 'authority-storage-permission-1',
      sourceIdentity: 'authority-storage:permission:1',
      repositoryNodeId: 'R_openclaw',
      repository: 'openclaw/openclaw',
      actorNodeId: 'U_authority_storage',
      actorLogin: 'renamed-maintainer',
      actorType: 'User',
      actorAssociation: 'MEMBER',
      permission: 'maintain',
      observedAt: '2026-07-04T17:30:00Z',
      runHash: 'a'.repeat(64),
    };
    const permission = {
      ...permissionBase,
      rowHash: repositoryPermissionObservationRowHash(permissionBase),
    };
    const evidence: LabelAuthorityEvidence = {
      schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
      event: {
        sourceIdentity: 'authority-storage:label-event:1',
        repositoryNodeId: 'R_openclaw',
        repository: 'openclaw/openclaw',
        issueNumber: firstIssueNumber,
        eventId: 'LE_authority_storage_1',
        action: 'labeled',
        label: 'P0',
        eventTime: recordedAt,
        actor: {
          nodeId: 'U_authority_storage',
          login: 'maintainer-before-rename',
          type: 'User',
          association: 'MEMBER',
        },
      },
      permissionObservations: [permission],
      approvedRosterEntries: [],
    };
    const resolution = buildScoreAuthorityResolution(evidence);
    const commentFixture = authorityCommentFixture(firstIssueNumber);
    const commentResolution = buildScoreCommentAuthorityResolution({
      issueNumber: firstIssueNumber,
      issueNodeId: commentFixture.issueNodeId,
      issueAuthorNodeId: commentFixture.issueAuthorNodeId,
      issueAuthorType: 'User',
      commentNodeId: commentFixture.comment.node_id,
      commentId: commentFixture.comment.id,
      commentUrl: commentFixture.comment.url,
      actorNodeId: commentFixture.comment.user.id,
      actorType: 'User',
      commentCreatedAt: commentFixture.comment.created_at,
      commentUpdatedAt: commentFixture.comment.updated_at,
      commentBodyDigest: scoreCommentBodyDigest(commentFixture.comment.body),
      claimSnippet: commentFixture.comment.body,
    });
    const authorityRun = buildScoreAuthorityResolutionRun({
      authorityRunId: 'authority:production-storage:1',
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      recordedAt,
      previousContentHash: null,
      rows: [
        {
          releaseTag: firstReleaseTag,
          issueNumber: firstIssueNumber,
          subjectKind: 'label_event',
          subjectIdentity: resolution.eventId,
          candidateId: null,
          resolution,
        },
        {
          releaseTag: null,
          issueNumber: firstIssueNumber,
          subjectKind: 'comment',
          subjectIdentity: commentResolution.commentNodeId,
          candidateId: null,
          resolution: commentResolution,
        },
      ],
    });

    assert.equal(db.insertScoreAuthorityResolutionRun(authorityRun).inserted, true);
    assert.equal(db.insertScoreAuthorityResolutionRun(authorityRun).inserted, false);
    assert.deepEqual(db.scoreAuthorityResolutionRunChainProblems(), []);
    assert.deepEqual(db.getScoreAuthorityResolutionRun(
      authorityRun.authorityRunId,
    ), authorityRun);
    assert.throws(
      () => db.insertScoreAuthorityResolutionRun(
        buildScoreAuthorityResolutionRun({
          authorityRunId: 'authority:source-drift',
          sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
          sourceIdentityDigest: '0'.repeat(64),
          recordedAt,
          previousContentHash: authorityRun.contentHash,
          rows: [],
        }),
      ),
      /source identity does not match current score input/,
    );
    assert.throws(
      () => db.insertScoreAuthorityResolutionRun(
        buildScoreAuthorityResolutionRun({
          authorityRunId: 'authority:wrong-chain-tip',
          sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
          sourceIdentityDigest: sourceIdentity.digest,
          recordedAt,
          previousContentHash: null,
          rows: [],
        }),
      ),
      /previous content hash does not match current authority chain tip/,
    );

    const firstAudit = {
      release_tag: firstReleaseTag,
      scored_at: recordedAt,
      score_model_version: 'authority-production-storage-test',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'good',
      recommended: 1,
      input_json: '{"schemaVersion":1}',
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
      source_identity_json: JSON.stringify(sourceIdentity),
      authority_run_id: authorityRun.authorityRunId,
    };
    db.upsertReleaseScoreAudit(firstAudit);
    db.insertReleaseScoreAuditHistory(
      'history:production-storage:1',
      recordedAt,
      firstAudit,
    );
    db.sealReleaseScoreAuditHistoryRun(
      'history:production-storage:1',
      recordedAt,
    );
    const v2Seal = db.sealReleaseScoreAuditHistoryV2({
      historyRunId: 'history:production-storage:1',
      authorityRunId: authorityRun.authorityRunId,
      sealedAt: recordedAt,
    });
    assert.equal(v2Seal.inserted, true);
    assert.equal(db.sealReleaseScoreAuditHistoryV2({
      historyRunId: 'history:production-storage:1',
      authorityRunId: authorityRun.authorityRunId,
      sealedAt: recordedAt,
    }).inserted, false);
    assert.deepEqual(db.releaseScoreAuditHistoryV2SealChainProblems(), []);

    const secondAuthorityRun = buildScoreAuthorityResolutionRun({
      authorityRunId: 'authority:production-storage:2',
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      recordedAt,
      previousContentHash: authorityRun.contentHash,
      rows: [],
    });
    db.insertScoreAuthorityResolutionRun(secondAuthorityRun);
    const unboundAudit = {
      ...firstAudit,
      release_tag: secondReleaseTag,
      recommended: 0,
      authority_run_id: null,
    };
    db.upsertReleaseScoreAudit(unboundAudit);
    db.insertReleaseScoreAuditHistory(
      'history:production-storage:2',
      recordedAt,
      unboundAudit,
    );
    db.sealReleaseScoreAuditHistoryRun(
      'history:production-storage:2',
      recordedAt,
    );
    assert.throws(
      () => db.sealReleaseScoreAuditHistoryV2({
        historyRunId: 'history:production-storage:2',
        authorityRunId: secondAuthorityRun.authorityRunId,
        sealedAt: recordedAt,
      }),
      /does not reference authority run/,
    );
  });

  it('enforces nullable immutable identities and partial uniqueness for identity-bearing rows', async () => {
    const db = await freshDb('authority-v2-identity-constraints');
    seedIssue(db, 6411, null);
    seedIssue(db, 6412, null);
    db.db.prepare(`UPDATE issues SET node_id='I_6411' WHERE number=6411`).run();
    assert.throws(
      () => db.db.prepare(`UPDATE issues SET node_id='I_6411' WHERE number=6412`).run(),
      /UNIQUE constraint failed: issues.node_id/,
    );
    assert.throws(
      () => db.db.prepare(`UPDATE issues SET node_id='I_tampered' WHERE number=6411`).run(),
      /issues\.node_id is immutable once recorded/,
    );

    db.upsertIssueLabelSnapshot({
      issue_number: 6411,
      issue_node_id: 'I_6411',
      snapshot_at: '2026-07-04T12:00:00Z',
      labels_json: '["P1"]',
    });
    assert.throws(
      () => db.db.prepare(`
        UPDATE issue_label_snapshots
        SET issue_node_id='I_tampered'
        WHERE issue_number=6411
      `).run(),
      /issue_label_snapshots\.issue_node_id is immutable once recorded/,
    );

    db.upsertIssuePrLink({
      issue_number: 6411,
      issue_node_id: 'I_6411',
      pr_number: 411,
      pr_node_id: 'PR_411',
      source: 'ClosedEvent.closer',
      source_node_id: 'CE_411',
      will_close_target: 1,
      referenced_at: '2026-07-04T12:00:00Z',
      raw_json: '{"raw":"link"}',
    });
    assert.throws(
      () => db.db.prepare(`
        UPDATE issue_pr_links
        SET source_node_id='CE_tampered'
        WHERE issue_number=6411
      `).run(),
      /issue_pr_links identity is immutable once recorded/,
    );
    assert.throws(
      () => db.upsertIssuePrLink({
        issue_number: 6411,
        issue_node_id: 'I_6411',
        pr_number: 412,
        pr_node_id: 'PR_412',
        source: 'ClosedEvent.closer',
        source_node_id: 'CE_411',
        will_close_target: 1,
        referenced_at: '2026-07-04T12:00:00Z',
        raw_json: '{"raw":"duplicate-link"}',
      }),
      /UNIQUE constraint failed: issue_pr_links.issue_number, issue_pr_links.source_node_id, issue_pr_links.source/,
    );

    for (const indexName of [
      'idx_issues_node_id_unique',
      'idx_issue_comment_snapshots_issue_node_id_unique',
      'idx_issue_state_event_snapshots_issue_node_id_unique',
      'idx_pull_request_fixes_node_id_unique',
      'idx_issue_pr_links_pr_node_source_unique',
      'idx_issue_pr_links_source_node_source_unique',
      'idx_issue_label_snapshots_node_time_unique',
    ]) {
      const index = db.db.prepare(`
        SELECT sql
        FROM sqlite_master
        WHERE type='index' AND name=?
      `).get(indexName) as { sql?: string } | undefined;
      assert.match(index?.sql ?? '', /WHERE .+ IS NOT NULL/i, indexName);
    }
    const closureSourceRevisionIndex = db.db.prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type='index'
        AND name='idx_closure_claim_source_snapshots_revision'
    `).get() as { sql?: string } | undefined;
    assert.match(
      closureSourceRevisionIndex?.sql ?? '',
      /CREATE UNIQUE INDEX.+issue_node_id.+source_kind.+source_node_id.+created_at.+updated_at/is,
    );
    const closureCandidateSourceIndex = db.db.prepare(`
      SELECT sql
      FROM sqlite_master
      WHERE type='index'
        AND name='idx_closure_claim_candidates_source'
    `).get() as { sql?: string } | undefined;
    assert.match(
      closureCandidateSourceIndex?.sql ?? '',
      /CREATE INDEX.+source_identity.+candidate_id/is,
    );
  });

  it('uses the next stable release, not prereleases, for issue attribution windows', async () => {
    const db = await freshDb('stable-attribution-window');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v2', '2026-06-03T00:00:00Z', false, testReleaseCommitOid('v2')),
      catalogRelease(
        'v1-beta',
        '2026-06-02T00:00:00Z',
        true,
        testReleaseCommitOid('v1-beta'),
      ),
      catalogRelease('v1', '2026-06-01T00:00:00Z', false, testReleaseCommitOid('v1')),
    ]);
    seedIssue(db, 7001, null, '2026-06-02T12:00:00Z');

    assert.ok(db.issuesForVersion('v1').some((row: any) => row.number === 7001));
    assert.equal(db.issueCountForVersion('v1'), 1);
  });

  it('does not attribute issues closed before a release until a reopen interval overlaps it', async () => {
    const db = await freshDb('reopen-interval-attribution');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v2', '2026-06-10T00:00:00Z', false, testReleaseCommitOid('v2')),
      catalogRelease('v1', '2026-06-01T00:00:00Z', false, testReleaseCommitOid('v1')),
    ]);
    seedIssue(db, 7002, '2026-06-15T00:00:00Z', '2026-05-01T00:00:00Z');
    seedClosure(db, 7002, 'COMPLETED', '2026-05-02T00:00:00Z');
    seedReopen(db, 7002, '2026-06-12T00:00:00Z');
    db.upsertIssueClosureEvent({
      issue_number: 7002,
      event_id: 'closed-7002-final',
      closed_at: '2026-06-15T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });

    assert.ok(!db.issuesForVersion('v1').some((row: any) => row.number === 7002));
    assert.ok(db.issuesForVersion('v2').some((row: any) => row.number === 7002));
  });

  it('flags reopen intervals that are missing their preceding close evidence', async () => {
    const db = await freshDb('ambiguous-reopen-interval');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v2', '2026-06-10T00:00:00Z', false, testReleaseCommitOid('v2')),
      catalogRelease('v1', '2026-06-01T00:00:00Z', false, testReleaseCommitOid('v1')),
    ]);
    seedIssue(db, 7004, '2026-06-15T00:00:00Z', '2026-05-01T00:00:00Z');
    seedReopen(db, 7004, '2026-06-12T00:00:00Z');

    let report = db.releaseIssueTimelineIntegrity('v1');
    assert.equal(report.ambiguousReopenCount, 1);
    assert.equal(report.issueCount, 1);
    assert.match(db.formatReleaseIssueTimelineIntegrityFailure(report) ?? '', /ambiguous.*#7004/);

    seedClosure(db, 7004, 'COMPLETED', '2026-05-02T00:00:00Z');
    report = db.releaseIssueTimelineIntegrity('v1');
    assert.equal(report.ambiguousReopenCount, 0);
    assert.equal(db.formatReleaseIssueTimelineIntegrityFailure(report), null);
  });

  it('flags missing or duplicate stable release window boundaries', async () => {
    const db = await freshDb('stable-window-integrity');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-window-unique-alias',
        '2016-01-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-window-unique-alias'),
      ),
      catalogRelease(
        'v-window-unique-1',
        '2016-01-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-window-unique-1'),
      ),
    ]);

    const report = db.stableReleaseWindowIntegrity();
    assert.equal(report.missingPublishedAtCount, 0);
    assert.ok(report.duplicatePublishedAtCount >= 1);
    assert.ok(report.duplicateReleaseCount >= 2);
    assert.match(db.formatStableReleaseWindowIntegrityFailure(report) ?? '', /stable release windows are ambiguous/);

    db.db.prepare(`
      UPDATE releases
      SET published_at=NULL
      WHERE tag='v-window-unique-1'
    `).run();
    assert.throws(
      () => db.stableReleaseWindowIntegrity(),
      /Active release catalog v-window-unique-1 has invalid published_at/,
    );
  });

  it('atomically replaces the active catalog and removes stale releases from current chronology', async () => {
    const db = await freshDb('active-release-catalog');
    const first = db.replaceActiveReleaseCatalog([
      catalogRelease('v3', '2026-06-10T00:00:00Z'),
      catalogRelease('v3-1', '2026-06-08T00:00:00Z', true),
      catalogRelease('v-stale', '2026-06-05T00:00:00Z'),
      catalogRelease('v1', '2026-06-01T00:00:00Z'),
    ]);
    assert.equal(first.releaseCount, 4);

    assert.throws(
      () => db.replaceActiveReleaseCatalog([
        catalogRelease('v3', '2026-06-10T00:00:00Z'),
        { ...catalogRelease('v3', '2026-06-09T00:00:00Z'), node_id: 'R_duplicate' },
      ]),
      /duplicate tag v3/,
    );
    assert.deepEqual(
      db.listActiveReleaseCatalogDb().map((release: any) => release.tag),
      ['v3', 'v3-1', 'v-stale', 'v1'],
    );

    seedIssue(db, 7014, '2026-06-08T00:00:00Z', '2026-06-02T00:00:00Z');
    const second = db.replaceActiveReleaseCatalog([
      catalogRelease('v3', '2026-06-10T00:00:00Z'),
      catalogRelease('v3-1', '2026-06-08T00:00:00Z', true),
      catalogRelease('v1', '2026-06-01T00:00:00Z'),
    ]);
    db.db.prepare(`
      UPDATE releases
      SET final_score=10, scored_at='2026-06-11T00:00:00Z', recommended=1
      WHERE tag='v-stale'
    `).run();

    assert.notEqual(first.digest, second.digest);
    assert.equal(db.getRelease('v-stale')?.catalog_active, 0);
    const activeCatalog = db.listActiveReleaseCatalogDb();
    assert.deepEqual(activeCatalog.map((release: any) => release.catalog_rank), [0, 1, 2]);
    assert.ok(activeCatalog.every((release: any) =>
      release.catalog_active === 1 &&
      release.catalog_digest === second.digest &&
      typeof release.node_id === 'string' &&
      typeof release.created_at === 'string' &&
      typeof release.updated_at === 'string' &&
      typeof release.published_at === 'string'));
    assert.deepEqual(db.listReleasesDb(10).map((release: any) => release.tag), ['v3', 'v1']);
    assert.ok(db.closedDuringReign('v1').some((issue: any) => issue.number === 7014));
    assert.equal(db.stableReleaseWindowIntegrity().duplicateReleaseCount, 0);

    const reader = new ReleaseAuditReader(db.db);
    assert.deepEqual(reader.listReleases(10).map((release: any) => release.tag), ['v3', 'v1']);
    assert.ok(reader.rawClosedDuringReign('v1').some((issue: any) => issue.number === 7014));

    const releaseIdentity = db.scoreSourceIdentity().sources
      .find((source: any) => source.source === 'releases');
    assert.equal(releaseIdentity?.count, 3);
    const sourceIdentityBeforeStaleMutation = db.scoreSourceIdentity();
    db.db.prepare(`UPDATE releases SET name='changed stale history' WHERE tag='v-stale'`).run();
    assert.deepEqual(db.scoreSourceIdentity(), sourceIdentityBeforeStaleMutation);
  });

  it('does not let prerelease scores advance the last scored stable timestamp', async () => {
    const db = await freshDb('last-scored-at-stable-only');
    const stableTag = 'v-last-scored-stable';
    const prereleaseTag = 'v-last-scored-beta';
    const stableScoredAt = '2042-06-01T12:00:00Z';
    const prereleaseScoredAt = '2042-06-02T12:00:00Z';
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        prereleaseTag,
        '2042-06-02T00:00:00Z',
        true,
        testReleaseCommitOid(prereleaseTag),
      ),
      catalogRelease(
        stableTag,
        '2042-06-01T00:00:00Z',
        false,
        testReleaseCommitOid(stableTag),
      ),
    ]);
    const scoreRelease = (tag: string, scoredAt: string) => db.updateReleaseScore({
      tag,
      final_score: 8,
      negative_issues: 0,
      positive_issues: 1,
      state: 'eligible',
      recommended: 0,
      score_reason: 'last scored timestamp fixture',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 0,
      scored_at: scoredAt,
    });

    scoreRelease(stableTag, stableScoredAt);
    assert.equal(db.getLastScoredAt(), stableScoredAt);

    scoreRelease(prereleaseTag, prereleaseScoredAt);
    assert.equal(db.getRelease(prereleaseTag)?.scored_at, prereleaseScoredAt);
    assert.equal(db.getLastScoredAt(), stableScoredAt);
  });

  it('uses open intervals for audit source freshness issue universes', async () => {
    const db = await freshDb('source-freshness-reopen-interval');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-source-new',
        '2026-06-10T00:00:00Z',
        false,
        testReleaseCommitOid('v-source-new'),
      ),
      catalogRelease(
        'v-source-old',
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-source-old'),
      ),
    ]);
    seedIssue(db, 7011, null, '2026-06-09T00:00:00Z');
    seedIssue(db, 7012, '2026-06-15T00:00:00Z', '2026-05-01T00:00:00Z');
    seedClosure(db, 7012, 'COMPLETED', '2026-05-02T00:00:00Z');
    seedReopen(db, 7012, '2026-06-12T00:00:00Z');
    db.upsertIssue({
      ...(db.getIssue(7012) as any),
      updated_at: '2026-06-15T00:00:00Z',
      closed_at: '2026-06-15T00:00:00Z',
    });
    db.upsertClassification(7012, classification(), '2026-06-15T00:00:00Z', 1);

    const reader = new ReleaseAuditReader(db.db);
    const oldIssueRows = reader.sourceFreshnessFor('v-source-old').find((row: any) => row.source === 'issue_rows');
    const newIssueRows = reader.sourceFreshnessFor('v-source-new').find((row: any) => row.source === 'issue_rows');
    assert.equal(oldIssueRows.max_ts, '2026-06-09T00:00:00Z');
    assert.equal(newIssueRows.max_ts, '2026-06-15T00:00:00Z');
  });

  it('falls back to issue closed_at when closure timeline events are missing', async () => {
    const db = await freshDb('interval-fallback');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v2', '2026-06-10T00:00:00Z', false, testReleaseCommitOid('v2')),
      catalogRelease('v1', '2026-06-01T00:00:00Z', false, testReleaseCommitOid('v1')),
    ]);
    seedIssue(db, 7003, '2026-06-02T00:00:00Z', '2026-05-01T00:00:00Z');

    assert.ok(db.issuesForVersion('v1').some((row: any) => row.number === 7003));
    assert.ok(!db.issuesForVersion('v2').some((row: any) => row.number === 7003));
  });

  it('round-trips issue community signal columns through issue and release views', async () => {
    const db = await freshDb('issue-community');
    seedRelease(db, 'v1');
    db.upsertIssue({
      number: 9001,
      state: 'open',
      title: 'community-backed issue',
      author: 'reporter',
      author_association: 'NONE',
      html_url: 'https://example.test/issues/9001',
      created_at: '2026-06-01T12:00:00Z',
      updated_at: '2026-06-02T12:00:00Z',
      closed_at: null,
      comments: 12,
      unique_human_commenters: 4,
      maintainer_commenters: 1,
      contributor_commenters: 2,
      commenter_scan_truncated: 1,
      reaction_total: 9,
      positive_reactions: 7,
      labels: '["bug"]',
      is_bot: 0,
    });
    db.upsertClassification(9001, classification(), '2026-06-02T12:00:00Z', 1);

    const issue = db.getIssue(9001) as any;
    assert.equal(issue.author_association, 'NONE');
    assert.equal(issue.unique_human_commenters, 4);
    assert.equal(issue.maintainer_commenters, 1);
    assert.equal(issue.contributor_commenters, 2);
    assert.equal(issue.commenter_scan_truncated, 1);
    assert.equal(issue.reaction_total, 9);
    assert.equal(issue.positive_reactions, 7);

    const releaseIssue = db.issuesForVersion('v1').find((row: any) => row.number === 9001);
    assert.equal(releaseIssue?.unique_human_commenters, 4);
    assert.equal(releaseIssue?.positive_reactions, 7);
  });

  it('stores reachability per tag and updates by tag/pr', async () => {
    const db = await freshDb('reachability');

    db.upsertReleasePrReachability({
      tag: 'v1',
      pr_number: 11,
      tag_commit_oid: null,
      merge_commit_oid: null,
      base_ref_name: 'main',
      status: 'unknown',
      evidence_json: '{"missing":true}',
    });
    db.upsertReleasePrReachability({
      tag: 'v1',
      pr_number: 10,
      tag_commit_oid: 'v1-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'unknown',
      evidence_json: '{"first":true}',
    });
    db.upsertReleasePrReachability({
      tag: 'v2',
      pr_number: 10,
      tag_commit_oid: 'v2-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'not_reachable',
      evidence_json: '{}',
    });
    db.upsertReleasePrReachability({
      tag: 'v1',
      pr_number: 10,
      tag_commit_oid: 'v1-commit',
      merge_commit_oid: 'merge-10',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{"updated":true}',
    });

    const rows = db.db.prepare(`
      SELECT tag, pr_number, tag_commit_oid, merge_commit_oid, status, method, evidence_json
      FROM release_pr_reachability
      ORDER BY tag, pr_number
    `).all().map((row: any) => ({ ...row }));
    assert.deepEqual(rows, [
      { tag: 'v1', pr_number: 10, tag_commit_oid: 'v1-commit', merge_commit_oid: 'merge-10', status: 'reachable', method: 'git-merge-base', evidence_json: '{"updated":true}' },
      { tag: 'v1', pr_number: 11, tag_commit_oid: null, merge_commit_oid: null, status: 'unknown', method: 'git-merge-base', evidence_json: '{"missing":true}' },
      { tag: 'v2', pr_number: 10, tag_commit_oid: 'v2-commit', merge_commit_oid: 'merge-10', status: 'not_reachable', method: 'git-merge-base', evidence_json: '{}' },
    ]);
  });

  it('replaces release reachability rows atomically after validation', async () => {
    const db = await freshDb('reachability-replace');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-replace-2',
        '2026-06-03T00:00:00Z',
        false,
        testReleaseCommitOid('v-replace-2'),
      ),
      catalogRelease(
        'v-replace-1',
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-replace-1'),
      ),
    ]);
    const tagOid = testReleaseCommitOid('v-replace-1');
    const mergeOne = 'b'.repeat(40);
    const mergeTwo = 'c'.repeat(40);
    const catalogProof = testReleaseCatalogProof(db, 'v-replace-1');
    const reachableEvidence = JSON.stringify(strictPrReachabilityEvidence(
      'reachable',
      tagOid,
      mergeOne,
      catalogProof,
    ));
    const unknownEvidence = JSON.stringify(strictUnknownPrReachabilityEvidence(
      tagOid,
      'merge_commit_oid_unavailable',
      catalogProof,
    ));

    db.upsertReleasePrReachability({
      tag: 'v-replace-1',
      pr_number: 10,
      tag_commit_oid: 'old-tag',
      merge_commit_oid: 'old-merge',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{"legacy":true}',
    });
    db.upsertReleasePrReachability({
      tag: 'v-replace-2',
      pr_number: 20,
      tag_commit_oid: 'v-replace-2-commit',
      merge_commit_oid: 'merge-20',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{"other":true}',
    });

    db.replaceReleasePrReachabilityForRelease('v-replace-1', [
      {
        tag: 'v-replace-1',
        pr_number: 11,
        tag_commit_oid: tagOid,
        merge_commit_oid: mergeOne,
        base_ref_name: 'main',
        status: 'reachable',
        evidence_json: reachableEvidence,
      },
      {
        tag: 'v-replace-1',
        pr_number: 12,
        tag_commit_oid: tagOid,
        merge_commit_oid: null,
        base_ref_name: 'main',
        status: 'unknown',
        evidence_json: unknownEvidence,
      },
    ]);

    const afterReplace = db.db.prepare(`
      SELECT tag, pr_number, tag_commit_oid, merge_commit_oid, status, evidence_json
      FROM release_pr_reachability
      WHERE tag IN ('v-replace-1', 'v-replace-2')
      ORDER BY tag, pr_number
    `).all().map((row: any) => ({ ...row }));
    assert.deepEqual(afterReplace, [
      { tag: 'v-replace-1', pr_number: 11, tag_commit_oid: tagOid, merge_commit_oid: mergeOne, status: 'reachable', evidence_json: reachableEvidence },
      { tag: 'v-replace-1', pr_number: 12, tag_commit_oid: tagOid, merge_commit_oid: null, status: 'unknown', evidence_json: unknownEvidence },
      { tag: 'v-replace-2', pr_number: 20, tag_commit_oid: 'v-replace-2-commit', merge_commit_oid: 'merge-20', status: 'reachable', evidence_json: '{"other":true}' },
    ]);

    assert.throws(
      () => db.replaceReleasePrReachabilityForRelease('v-replace-1', [
        {
          tag: 'v-replace-1',
          pr_number: 13,
          tag_commit_oid: tagOid,
          merge_commit_oid: mergeTwo,
          base_ref_name: 'main',
          status: 'reachable',
          evidence_json: '{}',
        },
      ]),
      /invalid evidence JSON/,
    );

    const afterFailedReplace = db.db.prepare(`
      SELECT tag, pr_number, tag_commit_oid, merge_commit_oid, status, evidence_json
      FROM release_pr_reachability
      WHERE tag IN ('v-replace-1', 'v-replace-2')
      ORDER BY tag, pr_number
    `).all().map((row: any) => ({ ...row }));
    assert.deepEqual(afterFailedReplace, afterReplace);
  });

  it('persists exact source comments for closure-comment PR links', async () => {
    const db = await freshDb('pr-link-source-comment');
    db.upsertIssuePrLink({
      issue_number: 9300,
      pr_number: 9400,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-06-02T00:00:00Z',
      source_comment_database_id: 123456,
      source_comment_url: 'https://github.com/openclaw/openclaw/issues/9300#issuecomment-123456',
    });
    const row = db.db.prepare(`
      SELECT source_comment_database_id, source_comment_url
      FROM issue_pr_links
      WHERE issue_number=9300 AND pr_number=9400
    `).get() as any;
    assert.equal(row.source_comment_database_id, 123456);
    assert.equal(row.source_comment_url, 'https://github.com/openclaw/openclaw/issues/9300#issuecomment-123456');
  });

  it('reports stale or missing release reachability evidence', async () => {
    const db = await freshDb('reachability-integrity');
    const tagCommitOid = 'a'.repeat(40);
    const mergeCommitOid = 'b'.repeat(40);
    seedRelease(
      db,
      'v-integrity',
      '2026-06-01T00:00:00Z',
      false,
      tagCommitOid,
    );
    seedIssue(db, 9301);
    seedPr(db, 9301, true);
    db.upsertReleaseCommit({
      tag: 'v-integrity',
      tag_commit_oid: tagCommitOid,
      committed_at: '2026-06-01T00:00:00Z',
    });
    db.upsertPullRequestFix({
      pr_number: 9301,
      title: 'PR 9301',
      url: 'https://example.test/pull/9301',
      state: 'MERGED',
      merged: 1,
      merged_at: '2026-05-31T00:00:00Z',
      merge_commit_oid: mergeCommitOid,
      base_ref_name: 'main',
    });
    db.upsertIssuePrLink({
      issue_number: 9301,
      pr_number: 9301,
      source: 'closedByPullRequestsReferences',
      will_close_target: 1,
      referenced_at: '2026-06-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-integrity',
      pr_number: 9301,
      tag_commit_oid: tagCommitOid,
      merge_commit_oid: mergeCommitOid,
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'reachable',
        tagCommitOid,
        mergeCommitOid,
        testReleaseCatalogProof(db, 'v-integrity'),
      )),
    });

    let report = db.releasePrReachabilityIntegrity('v-integrity');
    assert.equal(db.formatReleasePrReachabilityIntegrityFailure(report), null);

    db.db.prepare(`
      UPDATE release_pr_reachability
      SET checked_at='2000-01-01T00:00:00Z'
      WHERE tag='v-integrity' AND pr_number=9301
    `).run();
    report = db.releasePrReachabilityIntegrity('v-integrity');
    assert.equal(report.staleCount, 1);
    assert.match(db.formatReleasePrReachabilityIntegrityFailure(report) ?? '', /stale=1/);

    db.db.prepare(`DELETE FROM release_pr_reachability WHERE tag='v-integrity'`).run();
    report = db.releasePrReachabilityIntegrity('v-integrity');
    assert.equal(report.missingCount, 1);
    assert.match(db.formatReleasePrReachabilityIntegrityFailure(report) ?? '', /missing=1/);
  });

  it('reports stale or missing closure proof evidence', async () => {
    const db = await freshDb('closure-proof-integrity');
    seedRelease(db, 'v-proof-integrity', '2030-01-01T00:00:00Z');
    seedIssue(db, 9501, '2030-01-02T00:00:00Z', '2030-01-01T12:00:00Z');
    seedClosure(db, 9501, 'COMPLETED', '2030-01-02T00:00:00Z');
    db.upsertIssueClosureProof({
      release_tag: 'v-proof-integrity',
      issue_number: 9501,
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      evidence_json: JSON.stringify({ proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION }),
    });
    db.db.prepare(`
      UPDATE issue_closure_proofs
      SET checked_at='2030-01-03T00:00:00Z'
      WHERE release_tag='v-proof-integrity'
        AND issue_number=9501
    `).run();
    db.replaceReleaseClosureDependencySnapshot(
      db.releaseClosureDependencyIdentity('v-proof-integrity', [9501]),
    );

    let report = db.releaseClosureProofIntegrity('v-proof-integrity');
    assert.equal(db.formatReleaseClosureProofIntegrityFailure(report), null);

    db.db.prepare(`
      UPDATE issue_closure_proofs
      SET checked_at='2000-01-01T00:00:00Z'
      WHERE release_tag='v-proof-integrity'
        AND issue_number=9501
    `).run();
    report = db.releaseClosureProofIntegrity('v-proof-integrity');
    assert.equal(report.staleCount, 1);
    assert.match(db.formatReleaseClosureProofIntegrityFailure(report) ?? '', /stale=1/);

    db.db.prepare(`
      DELETE FROM issue_closure_proofs
      WHERE release_tag='v-proof-integrity'
        AND issue_number=9501
    `).run();
    report = db.releaseClosureProofIntegrity('v-proof-integrity');
    assert.equal(report.missingCount, 1);
    assert.match(db.formatReleaseClosureProofIntegrityFailure(report) ?? '', /missing=1/);
  });

  it('derives closure dependency membership from proof evidence instead of the snapshot', async () => {
    const db = await freshDb('closure-proof-membership');
    const tag = 'v-proof-membership';
    seedRelease(db, tag, '2030-01-01T00:00:00Z');
    seedIssue(db, 9601, '2030-01-02T00:00:00Z', '2030-01-01T12:00:00Z');
    seedClosure(db, 9601, 'COMPLETED', '2030-01-02T00:00:00Z');
    for (const issueNumber of [9602, 9603, 9604]) {
      seedIssue(db, issueNumber, null, '2030-01-01T12:00:00Z');
    }
    const evidence = {
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
      canonicalIssues: [9602, 9603, 9604],
      canonicalIssueDetails: [
        { number: 9602 },
        { number: 9603 },
        { number: 9604 },
      ],
      canonicalFixCommitProof: [{ sourceIssueNumber: 9604 }],
      canonicalResolution: {
        path: [9601, 9602, 9604, 9602],
        blockingBranch: [9601, 9602, 9604, 9602],
        terminalIssue: { number: 9602 },
        terminalIssues: [{ number: 9602 }, { number: 9603 }],
        cycleTerminalIssue: { number: 9602 },
        terminalProof: {
          crossRelease: true,
          issueNumber: 9602,
          releaseTag: 'v-older',
        },
        branches: [
          {
            path: [9601, 9602, 9604, 9602],
            terminalIssue: { number: 9602 },
            terminalProof: {
              crossRelease: true,
              terminalIssueNumber: 9602,
              releaseTag: 'v-older',
            },
          },
          {
            path: [9601, 9603],
            terminalIssue: { number: 9603 },
          },
        ],
      },
    };
    seedClosureProof(db, tag, 9601, 'canonical_cycle_or_self_reference', evidence);
    db.db.prepare(`
      UPDATE issue_closure_proofs
      SET checked_at='2030-01-03T00:00:00Z'
      WHERE release_tag=? AND issue_number=9601
    `).run(tag);
    db.replaceReleaseClosureDependencySnapshot(
      db.releaseClosureDependencyIdentity(tag, [9601, 9602, 9603, 9604]),
    );

    let report = db.releaseClosureProofIntegrity(tag);
    assert.equal(db.formatReleaseClosureProofIntegrityFailure(report), null);

    const overwriteSnapshot = (issueNumbers: number[]) => {
      const identity = db.releaseClosureDependencyIdentity(tag, issueNumbers);
      db.db.prepare(`
        UPDATE release_closure_dependency_snapshots
        SET issue_numbers_json=?, dependency_digest=?, dependency_row_count=?
        WHERE release_tag=?
      `).run(
        JSON.stringify(identity.issueNumbers),
        identity.digest,
        identity.rowCount,
        tag,
      );
    };

    overwriteSnapshot([9601, 9602, 9603]);
    report = db.releaseClosureProofIntegrity(tag);
    assert.equal(report.dependencySnapshotMembershipMismatchCount, 1);
    assert.equal(report.dependencySnapshotMismatchCount, 1);
    let auditReport = new ReleaseAuditReader(db.db)
      .closureDependencySnapshotIntegrityForRelease(tag);
    assert.equal(auditReport.membershipMismatchCount, 1);
    assert.equal(auditReport.identityMismatchCount, 1);

    seedIssue(db, 9699, null, '2030-01-01T12:00:00Z');
    overwriteSnapshot([9601, 9602, 9603, 9604, 9699]);
    report = db.releaseClosureProofIntegrity(tag);
    assert.equal(report.dependencySnapshotMembershipMismatchCount, 1);
    assert.equal(report.dependencySnapshotMismatchCount, 1);
    auditReport = new ReleaseAuditReader(db.db)
      .closureDependencySnapshotIntegrityForRelease(tag);
    assert.equal(auditReport.membershipMismatchCount, 1);
    assert.equal(auditReport.identityMismatchCount, 1);

    const missingIssueNumber = 999_999;
    seedClosureProof(db, tag, 9601, 'canonical_cycle_or_self_reference', {
      ...evidence,
      canonicalIssues: [...evidence.canonicalIssues, missingIssueNumber],
    });
    db.db.prepare(`
      UPDATE issue_closure_proofs
      SET checked_at='2030-01-03T00:00:00Z'
      WHERE release_tag=? AND issue_number=9601
    `).run(tag);
    overwriteSnapshot([9601, 9602, 9603, 9604, missingIssueNumber]);
    report = db.releaseClosureProofIntegrity(tag);
    assert.equal(report.dependencySnapshotMembershipMismatchCount, 0);
    assert.equal(report.dependencyReferencedIssueMissingCount, 1);
    assert.equal(report.dependencySnapshotMismatchCount, 1);
    auditReport = new ReleaseAuditReader(db.db)
      .closureDependencySnapshotIntegrityForRelease(tag);
    assert.equal(auditReport.membershipMismatchCount, 0);
    assert.equal(auditReport.referencedIssueMissingCount, 1);
    assert.equal(auditReport.identityMismatchCount, 0);
    assert.match(
      db.formatReleaseClosureProofIntegrityFailure(report) ?? '',
      /dependencyMissingIssues=1/,
    );
    db.db.prepare(`
      DELETE FROM release_closure_dependency_snapshots
      WHERE release_tag=?
    `).run(tag);
    auditReport = new ReleaseAuditReader(db.db)
      .closureDependencySnapshotIntegrityForRelease(tag);
    assert.equal(auditReport.missingCount, 1);
    assert.equal(auditReport.referencedIssueMissingCount, 1);
    assert.equal(auditReport.failedCount, 2);
  });

  it('excludes prerelease cross-release proofs and tracks active stable proof releases in closure dependency digests', async () => {
    const db = await freshDb('closure-dependency-active-stable-cross-proof');
    const targetRelease = catalogRelease(
      'v-dependency-target',
      '2031-03-01T00:00:00Z',
      false,
      testReleaseCommitOid('v-dependency-target'),
    );
    const prereleaseProofRelease = catalogRelease(
      'v-dependency-beta',
      '2031-02-15T00:00:00Z',
      true,
      testReleaseCommitOid('v-dependency-beta'),
    );
    const stableProofRelease = catalogRelease(
      'v-dependency-proof',
      '2031-02-01T00:00:00Z',
      false,
      testReleaseCommitOid('v-dependency-proof'),
    );
    const issueNumber = 9698;
    seedAuthorizedReleaseCatalog(db, [
      targetRelease,
      prereleaseProofRelease,
      stableProofRelease,
    ]);
    seedIssue(db, issueNumber, null, '2031-03-01T12:00:00Z');
    seedClosureProof(db, stableProofRelease.tag, issueNumber, 'fixed_in_release', {
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
    });

    const withStableProof = db.releaseClosureDependencyIdentity(
      targetRelease.tag,
      [issueNumber],
    );
    seedClosureProof(db, prereleaseProofRelease.tag, issueNumber, 'fixed_in_release', {
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
    });
    const withPrereleaseProof = db.releaseClosureDependencyIdentity(
      targetRelease.tag,
      [issueNumber],
    );
    assert.equal(withPrereleaseProof.digest, withStableProof.digest);
    assert.equal(withPrereleaseProof.rowCount, withStableProof.rowCount);

    db.replaceActiveReleaseCatalog([
      targetRelease,
      prereleaseProofRelease,
    ]);
    const withoutActiveStableProof = db.releaseClosureDependencyIdentity(
      targetRelease.tag,
      [issueNumber],
    );
    assert.notEqual(withoutActiveStableProof.digest, withStableProof.digest);
    assert.equal(withoutActiveStableProof.rowCount, withStableProof.rowCount - 1);
  });

  it('binds closure dependency snapshots to canonical provenance in both integrity engines', async () => {
    const db = await freshDb('closure-dependency-provenance');
    const tag = 'v-dependency-provenance';
    const issueNumber = 9701;
    const prNumber = 9702;
    const repositoryNodeId = 'R_dependency_openclaw';
    const issueNodeId = 'I_dependency_9701';
    const issueAuthorNodeId = 'U_dependency_reporter';
    const issueUpdatedAt = '2032-01-02T00:00:00Z';
    const repository = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
    };
    seedRelease(db, tag, '2032-01-01T00:00:00Z');
    db.upsertIssue({
      number: issueNumber,
      node_id: issueNodeId,
      state: 'closed',
      title: 'Canonical dependency provenance',
      body: 'The release dependency must bind exact source identities.',
      author: 'reporter',
      author_node_id: issueAuthorNodeId,
      author_type: 'User',
      html_url: `https://example.test/issues/${issueNumber}`,
      created_at: '2032-01-01T12:00:00Z',
      updated_at: issueUpdatedAt,
      closed_at: issueUpdatedAt,
      comments: 1,
      labels: '["bug"]',
      is_bot: 0,
    });

    const comments = [{
      id: 97010,
      node_id: 'IC_dependency_97010',
      node_type: 'IssueComment',
      body: 'Confirmed fixed by the linked change.',
      created_at: '2032-01-01T18:00:00Z',
      updated_at: '2032-01-01T18:00:00Z',
      author_association: 'MEMBER',
      url: `https://example.test/issues/${issueNumber}#issuecomment-97010`,
      user: {
        id: 'U_dependency_maintainer',
        login: 'maintainer',
        __typename: 'User',
      },
    }];
    const commentSnapshotIdentity = {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
      issueAuthor: {
        nodeId: issueAuthorNodeId,
        login: 'reporter',
        actorType: 'User',
      },
    };
    const commentSweepInput = {
      issueUpdatedAt,
      totalCount: comments.length,
      comments,
      snapshotIdentity: commentSnapshotIdentity,
    };
    const commentFirstSweep = commentEvidenceSweepIdentity({
      ...commentSweepInput,
      sweepOrdinal: 1,
    });
    const commentSecondSweep = commentEvidenceSweepIdentity({
      ...commentSweepInput,
      sweepOrdinal: 2,
    });
    const commentStabilization = commentEvidenceStabilizationIdentity(
      commentFirstSweep,
      commentSecondSweep,
      2,
    );
    const commentsDigest = commentEvidenceDigest(comments.length, comments);
    db.upsertIssueCommentSnapshot({
      issue_number: issueNumber,
      repository_node_id: repositoryNodeId,
      issue_node_id: issueNodeId,
      issue_author_node_id: issueAuthorNodeId,
      issue_author_login: 'reporter',
      issue_author_type: 'User',
      schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
      comment_count: comments.length,
      fetched_comment_count: comments.length,
      latest_comment_updated_at: comments[0].updated_at,
      comments_digest: commentsDigest,
      authority_digest: commentSecondSweep.authorityDigest,
      issue_updated_at: issueUpdatedAt,
      comments_json: serializeCommentEvidence(comments),
      stabilization_json: JSON.stringify(commentStabilization),
      stabilization_identity_digest: commentStabilization.identityDigest,
    });
    db.upsertClassification(
      issueNumber,
      classification(),
      issueUpdatedAt,
      1,
      commentsDigest,
    );

    const closure = {
      issue_number: issueNumber,
      issue_node_id: issueNodeId,
      event_id: 'CE_dependency_9701',
      closed_at: issueUpdatedAt,
      connection_ordinal: 0,
      actor_node_id: 'U_dependency_maintainer',
      actor_login: 'maintainer',
      actor_type: 'User',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: prNumber,
      closer_node_id: 'PR_dependency_9702',
      closer_oid: 'b'.repeat(40),
      raw_json: JSON.stringify({
        id: 'CE_dependency_9701',
        __typename: 'ClosedEvent',
        actor: {
          id: 'U_dependency_maintainer',
          login: 'maintainer',
          __typename: 'User',
        },
        closer: {
          id: 'PR_dependency_9702',
          number: prNumber,
          __typename: 'PullRequest',
        },
      }),
    };
    const stateEvents = normalizeIssueStateEvents([{
      eventId: closure.event_id,
      eventNodeType: 'ClosedEvent',
      type: 'closed',
      occurredAt: closure.closed_at,
      connectionOrdinal: closure.connection_ordinal,
      actorNodeId: closure.actor_node_id,
      actorLogin: closure.actor_login,
      actorType: closure.actor_type,
      stateReason: closure.state_reason,
      closerNodeId: closure.closer_node_id,
      closerType: closure.closer_type,
      closerNumber: closure.closer_number,
      closerOid: closure.closer_oid,
    }]);
    const stateSnapshot = authoritativeStateSnapshotFields({
      repositoryNodeId,
      issueNumber,
      issueNodeId,
      issueState: 'closed',
      issueUpdatedAt,
      events: stateEvents,
    });
    db.replaceIssueStateEventSnapshot({
      issue_number: issueNumber,
      issue_state: 'closed',
      issue_updated_at: issueUpdatedAt,
      total_count: stateEvents.length,
      fetched_count: stateEvents.length,
      sweep_count: 2,
      stabilized: true,
      closure_events: [closure],
      reopen_events: [],
      ...stateSnapshot,
    });
    db.upsertIssuePrLink({
      issue_number: issueNumber,
      issue_node_id: issueNodeId,
      ...repository,
      pr_number: prNumber,
      pr_node_id: 'PR_dependency_9702',
      source: 'ClosedEvent.closer',
      source_node_id: closure.event_id,
      will_close_target: 1,
      referenced_at: issueUpdatedAt,
      raw_json: '{"source":"ClosedEvent.closer"}',
    });
    db.upsertIssueCommitReference({
      issue_number: issueNumber,
      issue_node_id: issueNodeId,
      event_id: 'RE_dependency_9701',
      commit_oid: 'c'.repeat(40),
      commit_message_headline: 'Fix canonical dependency provenance',
      commit_repository_owner: repository.pr_repository_owner,
      commit_repository_name: repository.pr_repository_name,
      commit_repository_name_with_owner: repository.pr_repository_name_with_owner,
      is_cross_repository: 0,
      is_direct_reference: 1,
      referenced_at: issueUpdatedAt,
      actor_node_id: 'U_dependency_maintainer',
      actor_login: 'maintainer',
      raw_json: '{"source":"ReferencedEvent"}',
    });
    db.upsertPullRequestFix({
      ...repository,
      pr_number: prNumber,
      node_id: 'PR_dependency_9702',
      repository_node_id: repositoryNodeId,
      title: 'Fix canonical dependency provenance',
      url: `https://example.test/pull/${prNumber}`,
      state: 'MERGED',
      merged: 1,
      merged_at: issueUpdatedAt,
      merge_commit_oid: 'b'.repeat(40),
      base_ref_name: 'main',
      raw_json: '{"source":"PullRequest"}',
    });
    seedClosureProof(db, tag, issueNumber, 'fixed_in_release', {
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
    });
    db.db.prepare(`
      UPDATE issue_closure_proofs
      SET checked_at='2040-01-01T00:00:00Z'
      WHERE release_tag=? AND issue_number=?
    `).run(tag, issueNumber);
    db.replaceReleaseClosureDependencySnapshot(
      db.releaseClosureDependencyIdentity(tag, [issueNumber]),
    );

    const reader = new ReleaseAuditReader(db.db);
    const assertClean = (context: string) => {
      const report = db.releaseClosureProofIntegrity(tag);
      assert.equal(report.dependencySnapshotMismatchCount, 0, context);
      assert.equal(report.dependencySnapshotMembershipMismatchCount, 0, context);
      const auditReport = reader.closureDependencySnapshotIntegrityForRelease(tag);
      assert.equal(auditReport.identityMismatchCount, 0, context);
      assert.equal(auditReport.membershipMismatchCount, 0, context);
    };
    const assertDrift = (context: string) => {
      const report = db.releaseClosureProofIntegrity(tag);
      assert.equal(report.dependencySnapshotMismatchCount, 1, context);
      const auditReport = reader.closureDependencySnapshotIntegrityForRelease(tag);
      assert.equal(auditReport.identityMismatchCount, 1, context);
    };
    assertClean('sealed baseline');

    const immutableTriggerNames = [
      'issues_node_id_immutable',
      'issues_author_identity_immutable',
      'issue_comment_snapshots_repository_node_id_immutable',
      'issue_comment_snapshots_issue_node_id_immutable',
      'issue_comment_snapshots_author_identity_immutable',
      'issue_state_event_snapshots_repository_node_id_immutable',
      'issue_state_event_snapshots_issue_node_id_immutable',
      'issue_state_event_snapshots_issue_node_type_immutable',
      'issue_closure_events_identity_immutable',
      'issue_pr_links_identity_immutable',
      'issue_commit_references_identity_immutable',
      'pull_request_fixes_node_id_immutable',
      'pull_request_fixes_repository_node_id_immutable',
    ];
    const immutableTriggers = db.db.prepare(`
      SELECT name, sql
      FROM sqlite_master
      WHERE type='trigger'
        AND name IN (SELECT CAST(value AS TEXT) FROM json_each(?))
      ORDER BY name
    `).all(JSON.stringify(immutableTriggerNames)) as Array<{ name: string; sql: string }>;
    assert.equal(immutableTriggers.length, immutableTriggerNames.length);
    for (const trigger of immutableTriggers) {
      db.db.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    try {
      const mutations = [
        {
          label: 'issue node identity',
          sql: 'UPDATE issues SET node_id=? WHERE number=?',
          key: issueNumber,
          tampered: 'I_dependency_tampered',
          original: issueNodeId,
        },
        {
          label: 'issue author node identity',
          sql: 'UPDATE issues SET author_node_id=? WHERE number=?',
          key: issueNumber,
          tampered: 'U_dependency_reporter_tampered',
          original: issueAuthorNodeId,
        },
        {
          label: 'comment repository node identity',
          sql: 'UPDATE issue_comment_snapshots SET repository_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'R_comment_dependency_tampered',
          original: repositoryNodeId,
        },
        {
          label: 'comment issue node identity',
          sql: 'UPDATE issue_comment_snapshots SET issue_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'I_comment_dependency_tampered',
          original: issueNodeId,
        },
        {
          label: 'comment issue author node identity',
          sql: 'UPDATE issue_comment_snapshots SET issue_author_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'U_dependency_comment_author_tampered',
          original: issueAuthorNodeId,
        },
        {
          label: 'comment source node identity',
          sql: 'UPDATE issue_comment_snapshots SET comments_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: serializeCommentEvidence([{
            ...comments[0],
            node_id: 'IC_dependency_tampered',
          }]),
          original: serializeCommentEvidence(comments),
        },
        {
          label: 'comment actor node identity',
          sql: 'UPDATE issue_comment_snapshots SET comments_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: serializeCommentEvidence([{
            ...comments[0],
            user: {
              ...comments[0].user,
              id: 'U_dependency_comment_actor_tampered',
            },
          }]),
          original: serializeCommentEvidence(comments),
        },
        {
          label: 'comment authority digest',
          sql: 'UPDATE issue_comment_snapshots SET authority_digest=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'd'.repeat(64),
          original: commentSecondSweep.authorityDigest,
        },
        {
          label: 'comment stabilization JSON',
          sql: 'UPDATE issue_comment_snapshots SET stabilization_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: '{"schemaVersion":1,"tampered":true}',
          original: JSON.stringify(commentStabilization),
        },
        {
          label: 'comment stabilization identity',
          sql: 'UPDATE issue_comment_snapshots SET stabilization_identity_digest=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'e'.repeat(64),
          original: commentStabilization.identityDigest,
        },
        {
          label: 'state repository node identity',
          sql: 'UPDATE issue_state_event_snapshots SET repository_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'R_state_dependency_tampered',
          original: repositoryNodeId,
        },
        {
          label: 'state issue node identity',
          sql: 'UPDATE issue_state_event_snapshots SET issue_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'I_state_dependency_tampered',
          original: issueNodeId,
        },
        {
          label: 'state issue node type',
          sql: 'UPDATE issue_state_event_snapshots SET issue_node_type=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'Discussion',
          original: 'Issue',
        },
        {
          label: 'state event digest',
          sql: 'UPDATE issue_state_event_snapshots SET events_digest=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'f'.repeat(64),
          original: stateSnapshot.events_digest,
        },
        {
          label: 'state authority digest',
          sql: 'UPDATE issue_state_event_snapshots SET authority_digest=? WHERE issue_number=?',
          key: issueNumber,
          tampered: '1'.repeat(64),
          original: stateSnapshot.authority_digest,
        },
        {
          label: 'state stabilization JSON',
          sql: 'UPDATE issue_state_event_snapshots SET stabilization_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: '{"schemaVersion":1,"tampered":true}',
          original: JSON.stringify(stateSnapshot.stabilization),
        },
        {
          label: 'state stabilization identity',
          sql: 'UPDATE issue_state_event_snapshots SET stabilization_identity_digest=? WHERE issue_number=?',
          key: issueNumber,
          tampered: '2'.repeat(64),
          original: stateSnapshot.stabilization.identityDigest,
        },
        {
          label: 'state normalized event projection',
          sql: 'UPDATE issue_state_event_snapshots SET events_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: JSON.stringify([{
            ...stateEvents[0],
            closerNodeId: 'PR_dependency_state_tampered',
          }]),
          original: JSON.stringify(stateEvents),
        },
        {
          label: 'closure issue node identity',
          sql: 'UPDATE issue_closure_events SET issue_node_id=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'I_dependency_closure_tampered',
          original: issueNodeId,
        },
        {
          label: 'closure connection ordinal',
          sql: 'UPDATE issue_closure_events SET connection_ordinal=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 1,
          original: closure.connection_ordinal,
        },
        {
          label: 'closure actor node identity',
          sql: 'UPDATE issue_closure_events SET actor_node_id=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'U_dependency_actor_tampered',
          original: closure.actor_node_id,
        },
        {
          label: 'closure actor type',
          sql: 'UPDATE issue_closure_events SET actor_type=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'Bot',
          original: closure.actor_type,
        },
        {
          label: 'closure closer node identity',
          sql: 'UPDATE issue_closure_events SET closer_node_id=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'PR_dependency_closer_tampered',
          original: closure.closer_node_id,
        },
        {
          label: 'closure closer type',
          sql: 'UPDATE issue_closure_events SET closer_type=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'Issue',
          original: closure.closer_type,
        },
        {
          label: 'closure closer number',
          sql: 'UPDATE issue_closure_events SET closer_number=? WHERE event_id=?',
          key: closure.event_id,
          tampered: prNumber + 1,
          original: closure.closer_number,
        },
        {
          label: 'closure closer oid',
          sql: 'UPDATE issue_closure_events SET closer_oid=? WHERE event_id=?',
          key: closure.event_id,
          tampered: 'd'.repeat(40),
          original: closure.closer_oid,
        },
        {
          label: 'closure raw evidence',
          sql: 'UPDATE issue_closure_events SET raw_json=? WHERE event_id=?',
          key: closure.event_id,
          tampered: '{"source":"tampered-closure"}',
          original: closure.raw_json,
        },
        {
          label: 'PR link issue node identity',
          sql: 'UPDATE issue_pr_links SET issue_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'I_dependency_link_tampered',
          original: issueNodeId,
        },
        {
          label: 'PR link node identity',
          sql: 'UPDATE issue_pr_links SET pr_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'PR_dependency_link_tampered',
          original: 'PR_dependency_9702',
        },
        {
          label: 'PR link source node identity',
          sql: 'UPDATE issue_pr_links SET source_node_id=? WHERE issue_number=?',
          key: issueNumber,
          tampered: 'CE_dependency_source_tampered',
          original: closure.event_id,
        },
        {
          label: 'PR link raw evidence',
          sql: 'UPDATE issue_pr_links SET raw_json=? WHERE issue_number=?',
          key: issueNumber,
          tampered: '{"source":"tampered-link"}',
          original: '{"source":"ClosedEvent.closer"}',
        },
        {
          label: 'PR repository owner',
          sql: 'UPDATE pull_request_fixes SET pr_repository_owner=? WHERE pr_number=?',
          key: prNumber,
          tampered: 'tampered-owner',
          original: repository.pr_repository_owner,
        },
        {
          label: 'PR repository name',
          sql: 'UPDATE pull_request_fixes SET pr_repository_name=? WHERE pr_number=?',
          key: prNumber,
          tampered: 'tampered-repository',
          original: repository.pr_repository_name,
        },
        {
          label: 'PR repository full identity',
          sql: 'UPDATE pull_request_fixes SET pr_repository_name_with_owner=? WHERE pr_number=?',
          key: prNumber,
          tampered: 'tampered-owner/tampered-repository',
          original: repository.pr_repository_name_with_owner,
        },
        {
          label: 'PR node identity',
          sql: 'UPDATE pull_request_fixes SET node_id=? WHERE pr_number=?',
          key: prNumber,
          tampered: 'PR_dependency_tampered',
          original: 'PR_dependency_9702',
        },
        {
          label: 'PR repository node identity',
          sql: 'UPDATE pull_request_fixes SET repository_node_id=? WHERE pr_number=?',
          key: prNumber,
          tampered: 'R_dependency_tampered',
          original: repositoryNodeId,
        },
        {
          label: 'PR raw evidence',
          sql: 'UPDATE pull_request_fixes SET raw_json=? WHERE pr_number=?',
          key: prNumber,
          tampered: '{"source":"tampered-pr"}',
          original: '{"source":"PullRequest"}',
        },
        {
          label: 'commit issue node identity',
          sql: 'UPDATE issue_commit_references SET issue_node_id=? WHERE event_id=?',
          key: 'RE_dependency_9701',
          tampered: 'I_dependency_commit_tampered',
          original: issueNodeId,
        },
        {
          label: 'commit repository identity',
          sql: 'UPDATE issue_commit_references SET commit_repository_name_with_owner=? WHERE event_id=?',
          key: 'RE_dependency_9701',
          tampered: 'tampered-owner/tampered-repository',
          original: repository.pr_repository_name_with_owner,
        },
        {
          label: 'commit actor identity',
          sql: 'UPDATE issue_commit_references SET actor_node_id=? WHERE event_id=?',
          key: 'RE_dependency_9701',
          tampered: 'U_dependency_commit_actor_tampered',
          original: 'U_dependency_maintainer',
        },
        {
          label: 'commit raw evidence',
          sql: 'UPDATE issue_commit_references SET raw_json=? WHERE event_id=?',
          key: 'RE_dependency_9701',
          tampered: '{"source":"tampered-commit"}',
          original: '{"source":"ReferencedEvent"}',
        },
      ];
      for (const mutation of mutations) {
        const statement = db.db.prepare(mutation.sql);
        statement.run(mutation.tampered, mutation.key);
        assertDrift(mutation.label);
        statement.run(mutation.original, mutation.key);
        assertClean(`${mutation.label} restored`);
      }
    } finally {
      for (const trigger of immutableTriggers) db.db.exec(trigger.sql);
    }
  });

  it('preserves pull request freshness when metadata is unchanged', async () => {
    const db = await freshDb('pr-freshness-preserve');
    seedPr(db, 9401, true);
    db.db.prepare(`
      UPDATE pull_request_fixes
      SET fetched_at='2000-01-01T00:00:00Z'
      WHERE pr_number=9401
    `).run();

    seedPr(db, 9401, true);
    let row = db.db.prepare(`
      SELECT title, fetched_at
      FROM pull_request_fixes
      WHERE pr_number=9401
    `).get() as any;
    assert.equal(row.fetched_at, '2000-01-01T00:00:00Z');

    db.upsertPullRequestFix({
      pr_number: 9401,
      title: 'Changed PR title',
      url: 'https://example.test/pull/9401',
      state: 'MERGED',
      merged: 1,
      merged_at: '2026-05-31T00:00:00Z',
      merge_commit_oid: 'merge-9401',
      base_ref_name: 'main',
    });
    row = db.db.prepare(`
      SELECT title, fetched_at
      FROM pull_request_fixes
      WHERE pr_number=9401
    `).get() as any;
    assert.equal(row.title, 'Changed PR title');
    assert.notEqual(row.fetched_at, '2000-01-01T00:00:00Z');
  });

  it('preserves score-input freshness and source identity for semantic no-op upserts', async () => {
    const db = await freshDb('score-input-no-op-upserts');
    seedRelease(db, 'v-no-op', '2031-01-01T00:00:00Z');
    const oldTimestamp = '2000-01-01T00:00:00Z';
    const repository = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
    };
    const closure = {
      issue_number: 9601,
      event_id: 'closed-9601',
      closed_at: '2031-01-02T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 9701,
      closer_oid: 'closer-9701',
      raw_json: '{"type":"ClosedEvent"}',
    };
    const reopen = {
      issue_number: 9601,
      event_id: 'reopened-9601',
      reopened_at: '2031-01-03T00:00:00Z',
      actor_login: 'maintainer',
      raw_json: '{"type":"ReopenedEvent"}',
    };
    const prLink = {
      issue_number: 9601,
      ...repository,
      pr_number: 9701,
      source: 'closedByPullRequestsReferences',
      will_close_target: 1,
      referenced_at: '2031-01-02T00:00:00Z',
      source_comment_database_id: null,
      source_comment_url: null,
    };
    const commitReference = {
      issue_number: 9601,
      event_id: 'commit-9601',
      commit_oid: 'c'.repeat(40),
      commit_message_headline: 'Fix issue 9601',
      commit_repository_owner: 'openclaw',
      commit_repository_name: 'openclaw',
      commit_repository_name_with_owner: 'openclaw/openclaw',
      is_cross_repository: 0,
      is_direct_reference: 1,
      referenced_at: '2031-01-02T00:00:00Z',
      actor_login: 'maintainer',
      raw_json: '{"type":"ReferencedEvent"}',
    };
    const pullRequest = {
      ...repository,
      pr_number: 9701,
      title: 'Fix issue 9601',
      url: 'https://github.com/openclaw/openclaw/pull/9701',
      state: 'MERGED',
      merged: 1,
      merged_at: '2031-01-02T00:00:00Z',
      merge_commit_oid: 'b'.repeat(40),
      base_ref_name: 'main',
    };
    const reachability = {
      tag: 'v-no-op',
      ...repository,
      pr_number: 9701,
      tag_commit_oid: 'a'.repeat(40),
      merge_commit_oid: 'b'.repeat(40),
      base_ref_name: 'main',
      status: 'reachable' as const,
      method: 'git-merge-base',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'reachable',
        'a'.repeat(40),
        'b'.repeat(40),
      )),
    };
    const closureProof = {
      release_tag: 'v-no-op',
      issue_number: 9601,
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      evidence_json: '{"proof":"reachable_pr"}',
    };

    db.upsertIssueClosureEvent(closure);
    db.upsertIssueReopenEvent(reopen);
    db.upsertIssuePrLink(prLink);
    db.upsertIssueCommitReference(commitReference);
    db.upsertPullRequestFix(pullRequest);
    db.upsertReleasePrReachability(reachability);
    db.upsertIssueClosureProof(closureProof);
    db.db.exec(`
      UPDATE issue_closure_events SET fetched_at='${oldTimestamp}' WHERE event_id='closed-9601';
      UPDATE issue_reopen_events SET fetched_at='${oldTimestamp}' WHERE event_id='reopened-9601';
      UPDATE issue_pr_links SET fetched_at='${oldTimestamp}' WHERE issue_number=9601;
      UPDATE issue_commit_references SET fetched_at='${oldTimestamp}' WHERE event_id='commit-9601';
      UPDATE pull_request_fixes SET fetched_at='${oldTimestamp}' WHERE pr_number=9701;
      UPDATE release_pr_reachability SET checked_at='${oldTimestamp}' WHERE tag='v-no-op' AND pr_number=9701;
      UPDATE issue_closure_proofs SET checked_at='${oldTimestamp}' WHERE release_tag='v-no-op' AND issue_number=9601;
    `);
    const before = db.scoreSourceIdentity();

    db.upsertIssueClosureEvent(closure);
    db.upsertIssueReopenEvent(reopen);
    db.upsertIssuePrLink(prLink);
    db.upsertIssueCommitReference(commitReference);
    db.upsertPullRequestFix(pullRequest);
    db.upsertReleasePrReachability(reachability);
    db.upsertIssueClosureProof(closureProof);

    const unchanged = db.db.prepare(`
      SELECT
        (SELECT fetched_at FROM issue_closure_events WHERE event_id='closed-9601') AS closure_event,
        (SELECT fetched_at FROM issue_reopen_events WHERE event_id='reopened-9601') AS reopen_event,
        (SELECT fetched_at FROM issue_pr_links WHERE issue_number=9601) AS pr_link,
        (SELECT fetched_at FROM issue_commit_references WHERE event_id='commit-9601') AS commit_reference,
        (SELECT fetched_at FROM pull_request_fixes WHERE pr_number=9701) AS pull_request,
        (SELECT checked_at FROM release_pr_reachability WHERE tag='v-no-op' AND pr_number=9701) AS reachability,
        (SELECT checked_at FROM issue_closure_proofs WHERE release_tag='v-no-op' AND issue_number=9601) AS closure_proof
    `).get() as Record<string, string>;
    for (const [source, timestamp] of Object.entries(unchanged)) {
      if (source === 'closure_proof') assert.notEqual(timestamp, oldTimestamp);
      else assert.equal(timestamp, oldTimestamp);
    }
    const afterNoOp = db.scoreSourceIdentity();
    for (const source of [
      'issue_closure_events',
      'issue_reopen_events',
      'issue_pr_links',
      'issue_commit_references',
      'pull_request_fixes',
      'release_pr_reachability',
    ]) {
      assert.equal(
        afterNoOp.sources.find((entry: any) => entry.source === source)?.digest,
        before.sources.find((entry: any) => entry.source === source)?.digest,
        `${source} identity should remain stable for semantic no-op upserts`,
      );
    }
    assert.notEqual(
      afterNoOp.sources.find((entry: any) => entry.source === 'issue_closure_proofs')?.digest,
      before.sources.find((entry: any) => entry.source === 'issue_closure_proofs')?.digest,
      'recomputed proof rows must receive a fresh attestation timestamp',
    );

    db.upsertIssueClosureEvent({ ...closure, state_reason: 'NOT_PLANNED' });
    db.upsertIssueReopenEvent({ ...reopen, actor_login: 'different-maintainer' });
    db.upsertIssuePrLink({ ...prLink, will_close_target: 0 });
    db.upsertIssueCommitReference({ ...commitReference, commit_message_headline: 'Changed fix headline' });
    db.upsertPullRequestFix({ ...pullRequest, title: 'Changed PR title' });
    db.upsertReleasePrReachability({
      ...reachability,
      evidence_json: JSON.stringify({ schemaVersion: 1, evidence: 'fix_commit_in_release_history' }),
    });
    db.upsertIssueClosureProof({ ...closureProof, summary: 'Changed closure proof.' });

    const changed = db.db.prepare(`
      SELECT
        (SELECT fetched_at FROM issue_closure_events WHERE event_id='closed-9601') AS closure_event,
        (SELECT fetched_at FROM issue_reopen_events WHERE event_id='reopened-9601') AS reopen_event,
        (SELECT fetched_at FROM issue_pr_links WHERE issue_number=9601) AS pr_link,
        (SELECT fetched_at FROM issue_commit_references WHERE event_id='commit-9601') AS commit_reference,
        (SELECT fetched_at FROM pull_request_fixes WHERE pr_number=9701) AS pull_request,
        (SELECT checked_at FROM release_pr_reachability WHERE tag='v-no-op' AND pr_number=9701) AS reachability,
        (SELECT checked_at FROM issue_closure_proofs WHERE release_tag='v-no-op' AND issue_number=9601) AS closure_proof
    `).get() as Record<string, string>;
    assert.ok(Object.values(changed).every((timestamp) => timestamp !== oldTimestamp));

    const after = db.scoreSourceIdentity();
    for (const source of [
      'issue_closure_events',
      'issue_reopen_events',
      'issue_pr_links',
      'issue_commit_references',
      'pull_request_fixes',
      'release_pr_reachability',
      'issue_closure_proofs',
    ]) {
      assert.notEqual(
        after.sources.find((entry: any) => entry.source === source)?.digest,
        before.sources.find((entry: any) => entry.source === source)?.digest,
        `${source} identity should change with semantic content`,
      );
    }
  });

  it('preserves freshness through atomic no-op evidence replacements', async () => {
    const db = await freshDb('score-input-no-op-replacements');
    seedRelease(
      db,
      'v-replace-no-op',
      '2032-01-01T00:00:00Z',
      false,
      'd'.repeat(40),
    );
    const oldTimestamp = '2000-01-01T00:00:00Z';
    const repository = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
    };
    const prLink = {
      issue_number: 9801,
      ...repository,
      pr_number: 9802,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2032-01-02T00:00:00Z',
      source_comment_database_id: 123456,
      source_comment_url: 'https://github.com/openclaw/openclaw/issues/9801#issuecomment-123456',
    };
    const closureProof = {
      release_tag: 'v-replace-no-op',
      issue_number: 9801,
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      evidence_json: '{"proof":"reachable_pr"}',
    };
    const reachability = {
      tag: 'v-replace-no-op',
      ...repository,
      pr_number: 9802,
      tag_commit_oid: 'd'.repeat(40),
      merge_commit_oid: 'e'.repeat(40),
      base_ref_name: 'main',
      status: 'reachable' as const,
      method: 'git-merge-base',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'reachable',
        'd'.repeat(40),
        'e'.repeat(40),
        testReleaseCatalogProof(db, 'v-replace-no-op'),
      )),
    };

    db.upsertIssuePrLink(prLink);
    db.upsertIssueClosureProof(closureProof);
    db.upsertReleasePrReachability(reachability);
    db.db.exec(`
      UPDATE issue_pr_links SET fetched_at='${oldTimestamp}' WHERE issue_number=9801;
      UPDATE issue_closure_proofs SET checked_at='${oldTimestamp}' WHERE release_tag='v-replace-no-op' AND issue_number=9801;
      UPDATE release_pr_reachability SET checked_at='${oldTimestamp}' WHERE tag='v-replace-no-op' AND pr_number=9802;
    `);
    const before = db.scoreSourceIdentity();

    db.runInWriteTransaction(() => {
      db.deleteIssuePrLinksForIssues([9801]);
      db.upsertIssuePrLink(prLink);
    });
    db.runInWriteTransaction(() => {
      db.deleteIssueClosureProofsForRelease('v-replace-no-op');
      db.upsertIssueClosureProof(closureProof);
    });
    db.replaceReleasePrReachabilityForRelease('v-replace-no-op', [reachability]);

    let timestamps = db.db.prepare(`
      SELECT
        (SELECT fetched_at FROM issue_pr_links WHERE issue_number=9801) AS pr_link,
        (SELECT checked_at FROM issue_closure_proofs WHERE release_tag='v-replace-no-op' AND issue_number=9801) AS closure_proof,
        (SELECT checked_at FROM release_pr_reachability WHERE tag='v-replace-no-op' AND pr_number=9802) AS reachability
    `).get() as Record<string, string>;
    assert.equal(timestamps.pr_link, oldTimestamp);
    assert.equal(timestamps.reachability, oldTimestamp);
    assert.notEqual(timestamps.closure_proof, oldTimestamp);
    const afterNoOpReplacement = db.scoreSourceIdentity();
    for (const source of ['issue_pr_links', 'release_pr_reachability']) {
      assert.equal(
        afterNoOpReplacement.sources.find((entry: any) => entry.source === source)?.digest,
        before.sources.find((entry: any) => entry.source === source)?.digest,
      );
    }
    assert.notEqual(
      afterNoOpReplacement.sources.find((entry: any) => entry.source === 'issue_closure_proofs')?.digest,
      before.sources.find((entry: any) => entry.source === 'issue_closure_proofs')?.digest,
    );

    db.runInWriteTransaction(() => {
      db.deleteIssuePrLinksForIssues([9801]);
      db.upsertIssuePrLink({ ...prLink, source_comment_database_id: 654321 });
    });
    db.runInWriteTransaction(() => {
      db.deleteIssueClosureProofsForRelease('v-replace-no-op');
      db.upsertIssueClosureProof({ ...closureProof, status: 'no_code_proof' });
    });
    db.replaceReleasePrReachabilityForRelease('v-replace-no-op', [{
      ...reachability,
      status: 'not_reachable',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'not_reachable',
        'd'.repeat(40),
        'e'.repeat(40),
        testReleaseCatalogProof(db, 'v-replace-no-op'),
      )),
    }]);

    timestamps = db.db.prepare(`
      SELECT
        (SELECT fetched_at FROM issue_pr_links WHERE issue_number=9801) AS pr_link,
        (SELECT checked_at FROM issue_closure_proofs WHERE release_tag='v-replace-no-op' AND issue_number=9801) AS closure_proof,
        (SELECT checked_at FROM release_pr_reachability WHERE tag='v-replace-no-op' AND pr_number=9802) AS reachability
    `).get() as Record<string, string>;
    assert.ok(Object.values(timestamps).every((timestamp) => timestamp !== oldTimestamp));
    assert.notEqual(db.scoreSourceIdentity().digest, before.digest);
  });

  it('score audit freshness digest changes when audit payload changes', async () => {
    const db = await freshDb('score-audit-freshness');
    seedRelease(db, 'v1');
    const audit = {
      release_tag: 'v1',
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'test-model',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{"rawIssueCount":1}',
      components_json: '{"components":{}}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{"a":1}',
    };
    db.upsertReleaseScoreAudit(audit);
    const first = db.releaseScoreAuditFreshness();
    db.upsertReleaseScoreAudit({
      ...audit,
      gate_evidence_json: '{"a":2}',
    });
    const second = db.releaseScoreAuditFreshness();

    assert.ok(first.count >= 1);
    assert.equal(second.count, first.count);
    assert.equal(first.max_scored_at, audit.scored_at);
    assert.equal(second.max_scored_at, audit.scored_at);
    assert.notEqual(first.digest, second.digest);
  });

  it('retains append-only score audit history across score runs', async () => {
    const db = await freshDb('score-audit-history');
    seedRelease(db, 'v-history');
    const sourceIdentityJson = JSON.stringify(db.scoreSourceIdentity());
    const audit = {
      release_tag: 'v-history',
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{"score":7.5}',
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: sourceIdentityJson,
    };
    db.insertReleaseScoreAuditHistory('run-1', '2026-06-02T00:00:01Z', audit);
    const firstSeal = db.sealReleaseScoreAuditHistoryRun('run-1', '2026-06-02T00:00:01Z');
    assert.equal(firstSeal.inserted, true);
    assert.equal(firstSeal.row.previous_content_hash, null);
    const secondAudit = {
      ...audit,
      scored_at: '2026-06-03T00:00:00Z',
      final_score: 8,
      input_json: '{"score":8}',
      source_identity_json: sourceIdentityJson,
    };
    db.insertReleaseScoreAuditHistory('run-2', '2026-06-03T00:00:01Z', secondAudit);
    assert.equal(
      db.insertReleaseScoreAuditHistory('run-2', '2026-06-03T00:00:01Z', secondAudit),
      false,
    );
    const secondSeal = db.sealReleaseScoreAuditHistoryRun('run-2', '2026-06-03T00:00:01Z');
    assert.equal(secondSeal.inserted, true);
    assert.equal(secondSeal.row.previous_content_hash, firstSeal.row.content_hash);
    assert.equal(
      db.sealReleaseScoreAuditHistoryRun('run-2', '2026-06-03T00:00:01Z').inserted,
      false,
    );

    const rows = db.db.prepare(`
      SELECT run_id, final_score, input_json, source_identity_json
      FROM release_score_audit_history
      WHERE release_tag='v-history'
      ORDER BY recorded_at
    `).all() as any[];
    assert.equal(rows.length, 2);
    assert.deepEqual({ ...rows[0] }, {
      run_id: 'run-1',
      final_score: 7.5,
      input_json: '{"score":7.5}',
      source_identity_json: sourceIdentityJson,
    });
    assert.equal(rows[1].final_score, 8);
    assert.throws(
      () => db.insertReleaseScoreAuditHistory('run-2', '2026-06-03T00:00:02Z', audit),
      /history conflict/,
    );
    assert.throws(
      () => db.insertReleaseScoreAuditHistory('run-2', '2026-06-03T00:00:01Z', {
        ...secondAudit,
        release_tag: 'v-history-extra',
      }),
      /already sealed/,
    );
    assert.throws(
      () => db.db.prepare(`
        UPDATE release_score_audit_history
        SET final_score=10
        WHERE release_tag='v-history'
      `).run(),
      /append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM release_score_audit_history
        WHERE release_tag='v-history'
      `).run(),
      /append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        UPDATE release_score_audit_history_runs
        SET row_count=999
        WHERE run_id='run-1'
      `).run(),
      /append-only/,
    );

    db.db.prepare(`DELETE FROM releases WHERE tag='v-history'`).run();
    const retained = db.db.prepare(`
      SELECT COUNT(*) AS count
      FROM release_score_audit_history
      WHERE release_tag='v-history'
    `).get() as any;
    assert.equal(retained.count, 2);
  });

  it('enables recursive triggers on the real connection and blocks replace deletion', async () => {
    const database = await freshDb('recursive-trigger-runtime');
    const pragma = database.db.prepare('PRAGMA recursive_triggers').get() as
      Record<string, unknown> | undefined;
    assert.equal(
      Number(pragma?.recursive_triggers ?? Object.values(pragma ?? {})[0] ?? 0),
      1,
    );

    database.db.prepare(`
      INSERT INTO advisory_snapshot_history(id, captured_at, row_count, content_hash)
      VALUES(1, '2026-07-05T00:00:00.000Z', 1, ?)
    `).run('a'.repeat(64));
    const original = database.db.prepare(`
      SELECT id, captured_at, row_count, content_hash
      FROM advisory_snapshot_history
      WHERE id=1
    `).get();

    assert.throws(
      () => database.db.prepare(`
        INSERT OR REPLACE INTO advisory_snapshot_history(
          id, captured_at, row_count, content_hash
        ) VALUES(1, '2026-07-05T00:01:00.000Z', 2, ?)
      `).run('b'.repeat(64)),
      /advisory_snapshot_history is append-only/,
    );
    assert.deepEqual(
      database.db.prepare(`
        SELECT id, captured_at, row_count, content_hash
        FROM advisory_snapshot_history
        WHERE id=1
      `).get(),
      original,
    );
  });

  it('publishes current audits only through an exact valid sealed history tip', async () => {
    const db = await freshDb('sealed-current-publication');
    seedRelease(db, 'v-sealed');
    const sourceIdentity = db.scoreSourceIdentity();
    const audit = {
      release_tag: 'v-sealed',
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{"schemaVersion":1}',
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
      source_identity_json: JSON.stringify(sourceIdentity),
    };
    db.upsertReleaseScoreAudit(audit);
    assert.equal(db.getSealedReleaseScoreAuditPublication('v-sealed').valid, false);

    const runId = 'run-sealed';
    const recordedAt = '2026-06-02T00:00:01.000Z';
    const {
      audit: sealedAudit,
      authorityRun,
      seal,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId: runId,
      recordedAt,
      audit,
      upsertCurrent: true,
    });
    db.setMeta('score_persistence_last_run', JSON.stringify({
      schemaVersion: 2,
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      sourceIdentityRowCount: sourceIdentity.rowCount,
      sourceIdentitySourceCount: sourceIdentity.sourceCount,
      historyRunId: runId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
    }));

    const published = db.getSealedReleaseScoreAuditPublication('v-sealed');
    assert.equal(published.valid, true);
    assert.match(published.digest ?? '', /^[0-9a-f]{64}$/);
    assert.equal(published.historyRow?.release_tag, 'v-sealed');
    assert.equal(new ReleaseAuditReader(db.db).scorePublicationIntegrity().failedCount, 0);

    db.upsertReleaseScoreAudit({
      ...sealedAudit,
      components_json: '{"schemaVersion":1,"mutated":true}',
    });
    const mutated = db.getSealedReleaseScoreAuditPublication('v-sealed');
    assert.equal(mutated.valid, false);
    assert.equal(mutated.digest, null);
    assert.ok(mutated.problems.some((problem: string) =>
      /does not match the sealed history row/.test(problem)));
    assert.ok(new ReleaseAuditReader(db.db).scorePublicationIntegrity().failedCount > 0);
  });

  it('blocks refresh score publication until a success receipt links the sealed run', async () => {
    const db = await freshDb('sealed-refresh-receipt');
    seedRelease(db, 'v-receipt', '2026-06-01T00:00:00.000Z');
    const catalogAttestation = forecastCatalogAttestation(
      db,
      'v-receipt',
      '2026-06-01T00:00:00.000Z',
      '2026-07-04T12:00:00.000Z',
    );
    const advisoryMetadata = persistEmptyCompoundAdvisorySnapshot(
      db,
      '2026-07-04T11:59:30.000Z',
    );
    const issueCrawlMetadata = {
      schemaVersion: 2,
      startedAt: '2026-07-04T11:59:00.000Z',
      finishedAt: '2026-07-04T11:59:59.000Z',
      stopReason: 'exhausted',
      scorePersisted: true,
      scorePersistedAt: '2026-07-04T12:00:01.000Z',
    };
    db.setMeta('issue_crawl_last_run', JSON.stringify(issueCrawlMetadata));
    const codeRevision = 'test-revision';
    const operationAttempt = (runId: string) => ({
      run_id: runId,
      operation: 'refresh',
      trigger: 'test',
      started_at: '2026-07-04T11:59:00.000Z',
      lease_name: `refresh-${runId}`,
      lease_holder_id: `holder-${runId}`,
      lease_expires_at: '2026-07-04T12:04:00.000Z',
      code_revision: codeRevision,
      effective_config: { schemaVersion: 1 },
    });
    const successfulAttempt = operationAttempt('receipt-success');
    db.insertRefreshOperationAttempt(successfulAttempt);
    assert.equal(db.acquireRefreshLease(
      successfulAttempt.lease_name,
      successfulAttempt.lease_holder_id,
      new Date().toISOString(),
      300_000,
    ), true);
    persistRecoveryArtifactVerification(db, {
      runId: 'receipt-success',
      observedAt: '2026-07-04T11:59:45.000Z',
      release: {
        repository: 'openclaw/openclaw',
        tag: catalogAttestation.latestStable.tag,
        releaseNodeId: catalogAttestation.latestStable.nodeId,
        catalogTagCommitOid: catalogAttestation.latestStable.tagCommitOid,
        publishedAt: catalogAttestation.latestStable.publishedAt,
      },
    });
    const sourceIdentity = db.scoreSourceIdentity({
      artifactObservationRunId: 'receipt-success',
    });
    const auditInput = {
      release_tag: 'v-receipt',
      scored_at: '2026-07-04T12:00:00.000Z',
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'solid',
      recommended: 1,
      input_json: '{"schemaVersion":1}',
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
      source_identity_json: JSON.stringify(sourceIdentity),
    };
    const historyRunId = 'refresh:receipt-success';
    const historyRecordedAt = '2026-07-04T12:00:01.000Z';
    const {
      audit,
      authorityRun,
      seal,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId,
      recordedAt: historyRecordedAt,
      audit: auditInput,
      upsertCurrent: true,
      artifactObservationRunId: 'receipt-success',
    });
    const scoreCommit = {
      schemaVersion: 4,
      historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      historyRecordedAt,
      commitNotBefore: historyRecordedAt,
      commitNotAfter: historyRecordedAt,
      commitNotBeforeMs: Date.parse(historyRecordedAt),
      commitNotAfterMs: Date.parse(historyRecordedAt),
    };
    const forecastPlan = {
      schemaVersion: 1,
      preflightAt: historyRecordedAt,
      latestReleaseTag: 'v-receipt',
      latestReleasePublishedAt: '2026-06-01T00:00:00.000Z',
      selectedTag: 'v-receipt',
      scoreModelVersion: audit.score_model_version,
      promptVersion: audit.prompt_version,
      policyCode: 'highest_confidence_with_recency_tolerance',
      codeRevision,
      slots: [],
    };
    const scoreMeta = {
      schemaVersion: 2,
      source: 'refresh',
      operationReceiptRequired: true,
      operationRunId: 'receipt-required',
      codeRevision,
      persistedAt: historyRecordedAt,
      scoreModelVersion: audit.score_model_version,
      promptVersion: audit.prompt_version,
      scoredReleaseCount: 1,
      recommendedTag: audit.release_tag,
      recommendationPolicyCode: 'highest_confidence_with_recency_tolerance',
      releaseTags: [audit.release_tag],
      catalogAttestation,
      commitTiming: scoreCommit,
      forecastPlan,
      issueCrawlMetadataDigest: createHash('sha256')
        .update(canonicalOperationJson(issueCrawlMetadata))
        .digest('hex'),
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      sourceIdentityRowCount: sourceIdentity.rowCount,
      sourceIdentitySourceCount: sourceIdentity.sourceCount,
      historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
    };
    db.setMeta('score_persistence_last_run', JSON.stringify(scoreMeta));
    assert.equal(db.getSealedReleaseScoreAuditPublication('v-receipt').valid, false);
    assert.match(
      new ReleaseAuditReader(db.db).scorePublicationIntegrity().failures.join('\n'),
      /current score tip receipt authorization failed/,
    );

    const failedAttempt = operationAttempt('receipt-required');
    db.insertRefreshOperationAttempt(failedAttempt);
    assert.equal(db.acquireRefreshLease(
      failedAttempt.lease_name,
      failedAttempt.lease_holder_id,
      new Date().toISOString(),
      300_000,
    ), true);
    db.appendRefreshCaptureReceipt({
      run_id: 'receipt-required',
      lease_name: failedAttempt.lease_name,
      lease_holder_id: failedAttempt.lease_holder_id,
      status: 'failure',
      finished_at: '2026-07-04T12:00:02.000Z',
      duration_ms: 62_000,
      payload: {
        schemaVersion: 1,
        operation: 'refresh',
        trigger: 'test',
        codeRevision,
        error: { message: 'forecast capture failed after score commit' },
      },
    });
    assert.equal(db.releaseRefreshLease(
      failedAttempt.lease_name,
      failedAttempt.lease_holder_id,
    ), true);
    const failed = db.getSealedReleaseScoreAuditPublication('v-receipt');
    assert.equal(failed.valid, false);
    assert.match(
      failed.problems.join('\n'),
      /terminal receipt is failure/,
    );
    assert.match(
      new ReleaseAuditReader(db.db).scorePublicationIntegrity().failures.join('\n'),
      /operationRunId does not match immutable history\/receipt run receipt-success/,
    );

    db.appendRefreshOperationStageEvent({
      run_id: 'receipt-success',
      lease_name: successfulAttempt.lease_name,
      lease_holder_id: successfulAttempt.lease_holder_id,
      stage: 'score.persist',
      status: 'started',
      occurred_at: '2026-07-04T12:00:00.000Z',
    });
    db.appendRefreshOperationStageEvent({
      run_id: 'receipt-success',
      lease_name: successfulAttempt.lease_name,
      lease_holder_id: successfulAttempt.lease_holder_id,
      stage: 'score.persist',
      status: 'completed',
      occurred_at: '2026-07-04T12:00:01.000Z',
      duration_ms: 1_000,
      counts: { scoredReleases: 1 },
      details: {
        historyRunId,
        historyRunContentHash: seal.row.content_hash,
        authorityRunId: authorityRun.authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
        commitNotBefore: scoreCommit.commitNotBefore,
        commitNotAfter: scoreCommit.commitNotAfter,
      },
    });
    db.appendRefreshOperationStageEvent({
      run_id: 'receipt-success',
      lease_name: successfulAttempt.lease_name,
      lease_holder_id: successfulAttempt.lease_holder_id,
      stage: 'forecast.capture',
      status: 'started',
      occurred_at: '2026-07-04T12:00:02.000Z',
    });
    db.appendRefreshOperationStageEvent({
      run_id: 'receipt-success',
      lease_name: successfulAttempt.lease_name,
      lease_holder_id: successfulAttempt.lease_holder_id,
      stage: 'forecast.capture',
      status: 'completed',
      occurred_at: '2026-07-04T12:00:03.000Z',
      duration_ms: 1_000,
      counts: { validationForecasts: 0 },
      details: { eligibilityOutcome: 'not_eligible' },
    });
    db.appendRefreshCaptureReceipt({
      run_id: 'receipt-success',
      lease_name: successfulAttempt.lease_name,
      lease_holder_id: successfulAttempt.lease_holder_id,
      status: 'success',
      finished_at: '2026-07-04T12:00:03.000Z',
      duration_ms: 63_000,
      payload: {
        schemaVersion: 2,
        operation: 'refresh',
        trigger: 'test',
        codeRevision,
        releaseArtifacts: db.releaseArtifactPublicationForRun(
          'receipt-success',
        ),
        scoreMetadata: {
          ...scoreMeta,
          operationRunId: 'receipt-success',
        },
        scoreHistory: {
          runId: historyRunId,
          contentHash: seal.row.content_hash,
          persistedAt: historyRecordedAt,
        },
        scoreAuthority: {
          runId: authorityRun.authorityRunId,
          contentHash: authorityRun.contentHash,
          historyV2SealContentHash: historyV2Seal.row.contentHash,
        },
        scoreCommit,
        releaseTags: [audit.release_tag],
        recommendation: {
          selectedTag: audit.release_tag,
          decisions: [{
            releaseTag: audit.release_tag,
            decision: null,
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
            .update(canonicalOperationJson(advisoryMetadata))
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
          eligibilityOutcome: 'not_eligible',
          decisionIds: [],
          newDecisionIds: [],
          existingDecisionIds: [],
          captures: [],
          canonicalForecastIds: [],
          canonicalForecastContentHashes: [],
          newCanonicalForecastIds: [],
          existingCanonicalForecastIds: [],
          canonicalCaptures: [],
        },
      },
    });
    assert.equal(db.releaseRefreshLease(
      successfulAttempt.lease_name,
      successfulAttempt.lease_holder_id,
    ), true);
    db.setMeta('score_persistence_last_run', JSON.stringify({
      ...scoreMeta,
      operationRunId: 'receipt-success',
    }));
    const published = db.getSealedReleaseScoreAuditPublication('v-receipt');
    assert.equal(published.valid, true, published.problems.join('; '));
    const publicationIntegrity = new ReleaseAuditReader(db.db).scorePublicationIntegrity();
    assert.equal(
      publicationIntegrity.operationReceiptFailureCount,
      0,
      JSON.stringify(publicationIntegrity),
    );
    assert.deepEqual(
      publicationIntegrity.publicationAuthorityBindings[audit.release_tag],
      {
        authorityRunId: authorityRun.authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
      },
    );

    db.setMeta('score_persistence_last_run', JSON.stringify({
      ...scoreMeta,
      operationRunId: 'receipt-success',
      codeRevision: 'different-revision',
    }));
    assert.match(
      db.getSealedReleaseScoreAuditPublication('v-receipt').problems.join('\n'),
      /code revision/,
    );
    db.setMeta('score_persistence_last_run', JSON.stringify({
      ...scoreMeta,
      operationRunId: 'receipt-success',
      operationReceiptRequired: false,
    }));
    assert.match(
      db.getSealedReleaseScoreAuditPublication('v-receipt').problems.join('\n'),
      /cannot disable operation receipt authorization/,
    );
    db.setMeta('score_persistence_last_run', JSON.stringify({
      ...scoreMeta,
      operationRunId: 'receipt-success',
    }));
    db.setMeta('issue_crawl_last_run', JSON.stringify({
      ...issueCrawlMetadata,
      finishedAt: '2026-07-04T12:00:00.000Z',
    }));
    assert.match(
      db.getSealedReleaseScoreAuditPublication('v-receipt').problems.join('\n'),
      /issue crawl digest is not authoritative/,
    );
  });

  it('clears a receiptless sealed score tip when no prior actionable publication exists', async () => {
    const db = await freshDb('receiptless-score-crash-cleanup');
    const nowMs = Date.now();
    const scoredAt = new Date(nowMs - 120_000).toISOString();
    const recordedAt = new Date(nowMs - 110_000).toISOString();
    const crashedStartedAt = new Date(nowMs - 300_000).toISOString();
    const crashedLeaseExpiresAt = new Date(nowMs + 60_000).toISOString();
    const successorStartedAt = new Date(nowMs).toISOString();
    const leaseName = 'refresh-crash-recovery';
    const crashedRunId = 'refresh-crashed-after-score';
    const successorRunId = 'refresh-crash-successor';
    const historyRunId = 'history-crashed-after-score';

    seedRelease(db, 'v-crash-recovery');
    db.updateReleaseScore({
      tag: 'v-crash-recovery',
      final_score: 8,
      negative_issues: 1,
      positive_issues: 2,
      state: 'eligible',
      recommended: 1,
      score_reason: 'crash recovery fixture',
      broken_surfaces: '[]',
      closed_serious_fixed: 1,
      opened_serious_during_reign: 0,
      scored_at: scoredAt,
    });
    const sourceIdentityJson = JSON.stringify(db.scoreSourceIdentity());
    const audit = {
      release_tag: 'v-crash-recovery',
      scored_at: scoredAt,
      score_model_version: 'model-crash-recovery',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'solid',
      recommended: 1,
      input_json: '{"schemaVersion":1}',
      components_json: '{"schemaVersion":1}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
      source_identity_json: sourceIdentityJson,
    };
    const {
      seal,
      authorityRun,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId,
      recordedAt,
      audit,
      upsertCurrent: true,
    });
    db.setMeta('score_persistence_last_run', JSON.stringify({
      schemaVersion: 2,
      source: 'refresh',
      operationReceiptRequired: true,
      operationRunId: crashedRunId,
      historyRunId,
      historyRunContentHash: seal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      maxScoredAt: scoredAt,
    }));
    db.setMeta('last_scored_at', scoredAt);
    db.setMeta('issue_crawl_last_run', JSON.stringify({
      schemaVersion: 2,
      scorePersisted: true,
      scorePersistedAt: recordedAt,
    }));
    db.insertRefreshOperationAttempt({
      run_id: crashedRunId,
      operation: 'refresh',
      trigger: 'test-crash',
      started_at: crashedStartedAt,
      lease_name: leaseName,
      lease_holder_id: 'crashed-holder',
      lease_expires_at: crashedLeaseExpiresAt,
      code_revision: 'crash-recovery-revision',
      effective_config: { schemaVersion: 1 },
    });
    assert.equal(db.acquireRefreshLease(
      leaseName,
      'successor-holder',
      successorStartedAt,
      300_000,
    ), true);

    const successor = db.beginRefreshOperationAttempt({
      run_id: successorRunId,
      operation: 'refresh',
      trigger: 'test-successor',
      started_at: successorStartedAt,
      lease_name: leaseName,
      lease_holder_id: 'successor-holder',
      lease_expires_at: new Date(nowMs + 300_000).toISOString(),
      code_revision: 'crash-recovery-revision',
      effective_config: { schemaVersion: 1 },
    });

    assert.equal(successor.abandonedReceipts.length, 1);
    assert.deepEqual(successor.scoreRecovery, {
      cleaned: true,
      restored: false,
      releaseRows: 1,
      auditRows: 1,
      historyRunId,
      restoredHistoryRunId: null,
      restoredOperationRunId: null,
    });
    assert.equal(db.getRelease('v-crash-recovery')?.final_score, null);
    assert.equal(db.getReleaseScoreAudit('v-crash-recovery'), undefined);
    assert.equal(db.getMeta('score_persistence_last_run'), null);
    assert.equal(db.getMeta('last_scored_at'), null);
    assert.equal(
      JSON.parse(db.getMeta('issue_crawl_last_run') ?? '{}').scorePersisted,
      false,
    );
    assert.ok(db.getReleaseScoreAuditHistoryRunSeal(historyRunId));
    assert.equal(db.releaseRefreshLease(leaseName, 'successor-holder'), true);
  });

  it('restores the prior actionable publication after receiptless, failed, or abandoned tips', async () => {
    const db = await freshDb('restore-prior-actionable-score');
    for (const [index, terminalStatus] of (
      ['receiptless', 'failure', 'abandoned'] as const
    ).entries()) {
      if (index > 0) resetDatabase(db.db);
      const nowMs = Date.now();
      const tag = `v-restore-${terminalStatus}`;
      const leaseName = `refresh-restore-${terminalStatus}`;
      const priorOperationRunId = `prior-${terminalStatus}`;
      const priorHistoryRunId = `refresh:${priorOperationRunId}`;
      const failedOperationRunId = `failed-${terminalStatus}`;
      const failedHistoryRunId = `refresh:${failedOperationRunId}`;
      const successorRunId = `successor-${terminalStatus}`;
      const successorHolderId = `successor-holder-${terminalStatus}`;
      const prior = seedActionableRefreshPublication(db, {
        tag,
        operationRunId: priorOperationRunId,
        historyRunId: priorHistoryRunId,
        leaseName,
        holderId: `prior-holder-${terminalStatus}`,
        nowMs: nowMs - 20_000,
      });
      const priorHistoryRows = db.listReleaseScoreAuditHistoryForRun(priorHistoryRunId);
      const priorForecasts = db.listReleaseValidationForecasts();
      const priorReceipt = db.getRefreshCaptureReceipt(priorOperationRunId);
      assert.equal(priorForecasts.length, 1, terminalStatus);
      assert.equal(priorForecasts[0].decision_id, prior.forecast.decision_id, terminalStatus);
      assert.deepEqual(
        JSON.parse(prior.audit.components_json).recommendationDecision,
        prior.recommendationDecision,
        terminalStatus,
      );
      assert.deepEqual(priorReceipt, prior.receipt, terminalStatus);
      assert.deepEqual(
        JSON.parse(prior.receipt.payload_json).forecast.decisionIds,
        [prior.forecast.decision_id],
        terminalStatus,
      );
      const failed = overlayUnsuccessfulRefreshScoreTip(db, {
        tag,
        operationRunId: failedOperationRunId,
        historyRunId: failedHistoryRunId,
        leaseName,
        failedHolderId: `failed-holder-${terminalStatus}`,
        successorHolderId,
        nowMs,
        terminalStatus,
      });
      if (!failed.successorLeaseHeld) {
        assert.equal(db.acquireRefreshLease(
          leaseName,
          successorHolderId,
          new Date(nowMs).toISOString(),
          300_000,
        ), true);
      }

      const successor = db.beginRefreshOperationAttempt({
        run_id: successorRunId,
        operation: 'refresh',
        trigger: 'test-successor',
        started_at: new Date(nowMs).toISOString(),
        lease_name: leaseName,
        lease_holder_id: successorHolderId,
        lease_expires_at: new Date(nowMs + 300_000).toISOString(),
        code_revision: 'restorable-revision',
        effective_config: { schemaVersion: 1 },
      });

      assert.deepEqual(successor.scoreRecovery, {
        cleaned: true,
        restored: true,
        releaseRows: 1,
        auditRows: 1,
        historyRunId: failedHistoryRunId,
        restoredHistoryRunId: priorHistoryRunId,
        restoredOperationRunId: priorOperationRunId,
      }, terminalStatus);
      assert.equal(
        successor.abandonedReceipts.length,
        terminalStatus === 'receiptless' ? 1 : 0,
        terminalStatus,
      );
      const release = db.getRelease(tag);
      assert.equal(release?.final_score, 8.5, terminalStatus);
      assert.equal(release?.negative_issues, 2, terminalStatus);
      assert.equal(release?.positive_issues, 5, terminalStatus);
      assert.equal(release?.recommended, 1, terminalStatus);
      assert.equal(release?.score_reason, 'prior actionable publication', terminalStatus);
      assert.equal(release?.broken_surfaces, '[{"label":"CLI","count":2}]', terminalStatus);
      assert.equal(release?.closed_serious_fixed, 3, terminalStatus);
      assert.equal(release?.opened_serious_during_reign, 1, terminalStatus);
      assert.equal(release?.scored_at, prior.scoredAt, terminalStatus);
      assert.deepEqual({ ...db.getReleaseScoreAudit(tag) }, prior.audit, terminalStatus);
      assert.deepEqual(
        JSON.parse(db.getReleaseScoreAudit(tag)?.components_json ?? '{}')
          .recommendationDecision,
        prior.recommendationDecision,
        terminalStatus,
      );
      assert.deepEqual(
        JSON.parse(db.getMeta('issue_crawl_last_run') ?? 'null'),
        prior.issueCrawlMetadata,
        terminalStatus,
      );
      const restoredMeta = JSON.parse(db.getMeta('score_persistence_last_run') ?? 'null');
      assert.equal(restoredMeta.historyRunId, priorHistoryRunId, terminalStatus);
      assert.equal(restoredMeta.operationRunId, priorOperationRunId, terminalStatus);
      assert.equal(
        restoredMeta.recommendationPolicyCode,
        prior.recommendationDecision.policyCode,
        terminalStatus,
      );
      assert.deepEqual(restoredMeta.forecastPlan, prior.scoreMeta.forecastPlan, terminalStatus);
      assert.equal(
        restoredMeta.publicationRecovery.displacedHistoryRunId,
        failedHistoryRunId,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.displacedOperationRunId,
        failedOperationRunId,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.schemaVersion,
        3,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.restoredAuthorityRunId,
        prior.scoreMeta.authorityRunId,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.restoredAuthorityRunContentHash,
        prior.scoreMeta.authorityRunContentHash,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.restoredHistoryV2SealContentHash,
        prior.scoreMeta.historyV2SealContentHash,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.displacedAuthorityRunId,
        failed.authorityRun.authorityRunId,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.displacedAuthorityRunContentHash,
        failed.authorityRun.contentHash,
        terminalStatus,
      );
      assert.equal(
        restoredMeta.publicationRecovery.displacedHistoryV2SealContentHash,
        failed.historyV2Seal.contentHash,
        terminalStatus,
      );
      const displacedReceipt = db.getRefreshCaptureReceipt(failedOperationRunId);
      assert.ok(displacedReceipt, terminalStatus);
      assert.equal(
        restoredMeta.publicationRecovery.displacedPublicationCount,
        1,
        terminalStatus,
      );
      assert.match(
        restoredMeta.publicationRecovery.displacedPublicationDigest,
        /^[0-9a-f]{64}$/,
        terminalStatus,
      );
      assert.deepEqual(
        restoredMeta.publicationRecovery.displacedPublications,
        [{
          operationRunId: failedOperationRunId,
          historyRunId: failedHistoryRunId,
          historyRunContentHash: failed.seal.content_hash,
          authorityRunId: failed.authorityRun.authorityRunId,
          authorityRunContentHash: failed.authorityRun.contentHash,
          historyV2SealContentHash: failed.historyV2Seal.contentHash,
          receiptId: displacedReceipt.receipt_id,
          receiptStatus: displacedReceipt.status,
          receiptContentHash: displacedReceipt.content_hash,
        }],
        terminalStatus,
      );
      const publication = db.getSealedReleaseScoreAuditPublication(tag);
      assert.equal(publication.valid, true, publication.problems.join('; '));
      assert.equal(publication.runSeal?.run_id, priorHistoryRunId, terminalStatus);
      assert.deepEqual(
        JSON.parse(publication.historyRow?.components_json ?? '{}').recommendationDecision,
        prior.recommendationDecision,
        terminalStatus,
      );
      assert.deepEqual(
        db.listReleaseScoreAuditHistoryForRun(priorHistoryRunId),
        priorHistoryRows,
        terminalStatus,
      );
      assert.deepEqual(db.listReleaseValidationForecasts(), priorForecasts, terminalStatus);
      assert.deepEqual(
        db.getRefreshCaptureReceipt(priorOperationRunId),
        priorReceipt,
        terminalStatus,
      );
      assert.equal(
        db.getReleaseScoreAuditHistoryRunSeal(failedHistoryRunId)?.content_hash,
        failed.seal.content_hash,
        terminalStatus,
      );
      const latestSeal = db.db.prepare(`
        SELECT run_id FROM release_score_audit_history_runs ORDER BY id DESC LIMIT 1
      `).get() as { run_id: string };
      assert.equal(latestSeal.run_id, failedHistoryRunId, terminalStatus);
      const attempts = db.listRefreshOperationAttempts();
      const stageEvents = db.listRefreshOperationStageEvents();
      const receipts = db.listRefreshCaptureReceipts();
      const receiptLedger = verifyOperationReceiptLedger({
        attempts,
        stageEvents,
        receipts,
        leases: db.listRefreshLeases(),
        observedAt: new Date().toISOString(),
      });
      assert.deepEqual(receiptLedger.problems, [], terminalStatus);
      const receiptLinks = verifyOperationReceiptSemanticLinks({
        attempts,
        receipts,
        historyRows: db.db.prepare(`
          SELECT * FROM release_score_audit_history ORDER BY run_id, release_tag
        `).all(),
        historyRuns: db.db.prepare(`
          SELECT * FROM release_score_audit_history_runs ORDER BY id
        `).all(),
        forecasts: db.listReleaseValidationForecasts(),
        authorityRuns: db.listScoreAuthorityResolutionRuns(),
        historyV2Seals: db.listReleaseScoreAuditHistoryV2Seals(),
        validationProof: db.readReleaseValidationProofBundle(),
      });
      assert.deepEqual(receiptLinks.problems, [], terminalStatus);
      const untamperedMeta = db.getMeta('score_persistence_last_run');
      assert.ok(untamperedMeta, terminalStatus);
      for (const field of [
        'restoredAuthorityRunId',
        'restoredAuthorityRunContentHash',
        'restoredHistoryV2SealContentHash',
        'displacedAuthorityRunId',
        'displacedAuthorityRunContentHash',
        'displacedHistoryV2SealContentHash',
        'displacedPublicationCount',
        'displacedPublicationDigest',
        'displacedPublications',
      ]) {
        const tamperedMeta = JSON.parse(untamperedMeta);
        tamperedMeta.publicationRecovery[field] = `tampered-${field}`;
        db.setMeta('score_persistence_last_run', JSON.stringify(tamperedMeta));
        assert.match(
          db.getSealedReleaseScoreAuditPublication(tag).problems.join('\n'),
          field.startsWith('displacedPublication')
            ? /displaced publication suffix does not match recovery metadata/
            : /history and authority restoration metadata is invalid/,
          `${terminalStatus}:${field}`,
        );
        db.setMeta('score_persistence_last_run', untamperedMeta);
      }
      assert.equal(db.releaseRefreshLease(leaseName, successorHolderId), true);
    }
  });

  it('restores across an ordered suffix of multiple unsuccessful publications', async () => {
    const db = await freshDb('restore-multiple-unsuccessful-score-tips');
    const nowMs = Date.now();
    const tag = 'v-restore-multiple';
    const leaseName = 'refresh-restore-multiple';
    const priorOperationRunId = 'prior-multiple';
    const priorHistoryRunId = `refresh:${priorOperationRunId}`;
    const firstFailedOperationRunId = 'failed-multiple-a';
    const firstFailedHistoryRunId = `refresh:${firstFailedOperationRunId}`;
    const secondFailedOperationRunId = 'failed-multiple-b';
    const secondFailedHistoryRunId = `refresh:${secondFailedOperationRunId}`;
    const successorRunId = 'successor-multiple';
    const successorHolderId = 'successor-holder-multiple';

    const prior = seedActionableRefreshPublication(db, {
      tag,
      operationRunId: priorOperationRunId,
      historyRunId: priorHistoryRunId,
      leaseName,
      holderId: 'prior-holder-multiple',
      nowMs: nowMs - 120_000,
    });
    const sourceIdentity = db.scoreSourceIdentity();
    const previousAuthorityRun =
      db.listScoreAuthorityResolutionRuns().at(-1) ?? null;
    const nonPublicationAuthorityRun = buildScoreAuthorityResolutionRun({
      authorityRunId: 'score-authority:non-publication-between-failures',
      sourceIdentitySchemaVersion: sourceIdentity.schemaVersion,
      sourceIdentityDigest: sourceIdentity.digest,
      recordedAt: new Date(nowMs - 90_000).toISOString(),
      previousContentHash: previousAuthorityRun?.contentHash ?? null,
      rows: [],
    });
    db.insertScoreAuthorityResolutionRun(nonPublicationAuthorityRun);
    const firstFailed = overlayUnsuccessfulRefreshScoreTip(db, {
      tag,
      operationRunId: firstFailedOperationRunId,
      historyRunId: firstFailedHistoryRunId,
      leaseName,
      failedHolderId: 'failed-holder-multiple-a',
      successorHolderId,
      nowMs: nowMs - 60_000,
      terminalStatus: 'failure',
    });
    const secondFailed = overlayUnsuccessfulRefreshScoreTip(db, {
      tag,
      operationRunId: secondFailedOperationRunId,
      historyRunId: secondFailedHistoryRunId,
      leaseName,
      failedHolderId: 'failed-holder-multiple-b',
      successorHolderId,
      nowMs: nowMs - 20_000,
      terminalStatus: 'failure',
    });
    assert.equal(db.acquireRefreshLease(
      leaseName,
      successorHolderId,
      new Date(nowMs).toISOString(),
      300_000,
    ), true);

    const successor = db.beginRefreshOperationAttempt({
      run_id: successorRunId,
      operation: 'refresh',
      trigger: 'test-successor',
      started_at: new Date(nowMs).toISOString(),
      lease_name: leaseName,
      lease_holder_id: successorHolderId,
      lease_expires_at: new Date(nowMs + 300_000).toISOString(),
      code_revision: 'restorable-revision',
      effective_config: { schemaVersion: 1 },
    });

    assert.equal(successor.scoreRecovery?.restored, true);
    assert.equal(
      successor.scoreRecovery?.restoredHistoryRunId,
      priorHistoryRunId,
    );
    assert.deepEqual({ ...db.getReleaseScoreAudit(tag) }, prior.audit);
    const restoredMeta = JSON.parse(
      db.getMeta('score_persistence_last_run') ?? 'null',
    );
    assert.equal(restoredMeta.publicationRecovery.schemaVersion, 3);
    assert.equal(restoredMeta.publicationRecovery.displacedPublicationCount, 2);
    assert.equal(
      restoredMeta.publicationRecovery.displacedPublications.some(
        (binding: Record<string, unknown>) =>
          binding.authorityRunId ===
            nonPublicationAuthorityRun.authorityRunId,
      ),
      false,
    );
    assert.deepEqual(
      restoredMeta.publicationRecovery.displacedPublications.map(
        (binding: Record<string, unknown>) => binding.operationRunId,
      ),
      [firstFailedOperationRunId, secondFailedOperationRunId],
    );
    assert.deepEqual(
      restoredMeta.publicationRecovery.displacedPublications.map(
        (binding: Record<string, unknown>) => binding.historyRunContentHash,
      ),
      [firstFailed.seal.content_hash, secondFailed.seal.content_hash],
    );
    assert.equal(
      restoredMeta.publicationRecovery.displacedAuthorityRunId,
      secondFailed.authorityRun.authorityRunId,
    );
    const publication = db.getSealedReleaseScoreAuditPublication(tag);
    assert.equal(publication.valid, true, publication.problems.join('; '));

    const untamperedMeta = db.getMeta('score_persistence_last_run');
    assert.ok(untamperedMeta);
    const tamperedMeta = JSON.parse(untamperedMeta);
    tamperedMeta.publicationRecovery.displacedPublications[0]
      .receiptContentHash = 'f'.repeat(64);
    db.setMeta('score_persistence_last_run', JSON.stringify(tamperedMeta));
    assert.match(
      db.getSealedReleaseScoreAuditPublication(tag).problems.join('\n'),
      /displaced publication suffix does not match recovery metadata/,
    );
    db.setMeta('score_persistence_last_run', untamperedMeta);
    assert.equal(db.releaseRefreshLease(leaseName, successorHolderId), true);
  });

  it('opens a pre-history database in read-only mode', () => {
    const path = dbPath('read-only-pre-history');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.db.exec('DROP TABLE release_score_audit_history');
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const readOnly = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        process.env.RADAR_DB_READ_ONLY = '1';
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const row = database.db.prepare(
          'SELECT COUNT(*) AS count FROM releases'
        ).get();
        if (Number(row?.count ?? -1) !== 0) throw new Error('expected an empty release table');
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing', {
        RADAR_DB_READ_ONLY: '1',
      }),
      encoding: 'utf8',
    });
    assert.equal(readOnly.status, 0, `${readOnly.stdout}\n${readOnly.stderr}`);
  });

  it('restores legacy PR identity constraints on first startup and migrates idempotently', () => {
    const path = dbPath('legacy-pr-identity-migration');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.upsertIssue({
          number: 64201,
          node_id: 'I_64201',
          state: 'closed',
          title: 'legacy PR identity issue',
          author: 'legacy-user',
          html_url: 'https://example.test/issues/64201',
          created_at: '2026-07-04T10:00:00Z',
          updated_at: '2026-07-04T11:00:00Z',
          closed_at: '2026-07-04T11:00:00Z',
          comments: 0,
          labels: '[]',
          is_bot: 0,
        });
        database.db.prepare(
          'UPDATE issues SET fetched_at=NULL WHERE number=64201'
        ).run();
        database.setMeta('issue_crawl_last_run', '{malformed-json');
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE issue_pr_links;
          DROP TABLE pull_request_fixes;
          CREATE TABLE pull_request_fixes (
            pr_number INTEGER PRIMARY KEY,
            node_id TEXT,
            repository_node_id TEXT,
            title TEXT,
            url TEXT,
            state TEXT,
            merged INTEGER NOT NULL DEFAULT 0,
            merged_at TEXT,
            merge_commit_oid TEXT,
            base_ref_name TEXT,
            raw_json TEXT,
            fetched_at TEXT NOT NULL
          );
          INSERT INTO pull_request_fixes (
            pr_number, node_id, repository_node_id, title, url, state, merged,
            merged_at, merge_commit_oid, base_ref_name, raw_json, fetched_at
          ) VALUES (
            64202, 'PR_64202', 'R_openclaw', 'legacy pull request',
            'https://github.com/openclaw/openclaw/pull/64202', 'MERGED', 1,
            '2026-07-04T10:55:00Z', 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
            'main', '{"legacy":true}', '2026-07-04T11:01:00Z'
          );
          CREATE TABLE issue_pr_links (
            issue_number INTEGER NOT NULL,
            issue_node_id TEXT,
            pr_number INTEGER NOT NULL,
            pr_node_id TEXT,
            source TEXT NOT NULL,
            source_node_id TEXT,
            will_close_target INTEGER,
            referenced_at TEXT,
            source_comment_database_id INTEGER,
            source_comment_url TEXT,
            raw_json TEXT,
            fetched_at TEXT NOT NULL,
            PRIMARY KEY(issue_number, pr_number, source)
          );
          INSERT INTO issue_pr_links (
            issue_number, issue_node_id, pr_number, pr_node_id, source,
            source_node_id, will_close_target, referenced_at,
            source_comment_database_id, source_comment_url, raw_json, fetched_at
          ) VALUES (
            64201, 'I_64201', 64202, 'PR_64202', 'ClosedEvent.closer',
            'CE_64201', 1, '2026-07-04T11:00:00Z',
            NULL, NULL, '{"legacy":true}', '2026-07-04T11:01:00Z'
          );
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const verifyMigration = () => spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const expectedSchemaNames = [
          'idx_issue_pr_links_source_node_source_unique',
          'issue_pr_links_identity_immutable',
          'pull_request_fixes_repository_node_id_immutable',
        ];
        const schemaObjects = database.db.prepare(
          "SELECT type, name, sql FROM sqlite_schema " +
          "WHERE name IN (" +
          "'idx_issue_pr_links_source_node_source_unique'," +
          "'issue_pr_links_identity_immutable'," +
          "'pull_request_fixes_repository_node_id_immutable'" +
          ") ORDER BY name"
        ).all();
        assert.deepEqual(
          schemaObjects.map((row) => row.name),
          expectedSchemaNames.slice().sort(),
        );
        assert.match(
          schemaObjects.find((row) =>
            row.name === 'idx_issue_pr_links_source_node_source_unique'
          ).sql,
          /WHERE source_node_id IS NOT NULL/i,
        );
        const sourceNodeIndex = database.db.prepare(
          "PRAGMA index_list('issue_pr_links')"
        ).all().find((row) =>
          row.name === 'idx_issue_pr_links_source_node_source_unique'
        );
        assert.equal(sourceNodeIndex.unique, 1);
        assert.equal(sourceNodeIndex.partial, 1);
        assert.deepEqual(
          database.db.prepare(
            "PRAGMA index_xinfo('idx_issue_pr_links_source_node_source_unique')"
          ).all()
            .filter((row) => row.key === 1)
            .sort((left, right) => left.seqno - right.seqno)
            .map((row) => row.name),
          ['issue_number', 'source_node_id', 'source'],
        );
        assert.equal(database.db.prepare(
          "SELECT COUNT(*) AS count FROM sqlite_schema " +
          "WHERE name IN ('issue_pr_links_next', 'pull_request_fixes_next')"
        ).get().count, 0);
        const issue = database.db.prepare(
          'SELECT fetched_at, updated_at FROM issues WHERE number=64201'
        ).get();
        assert.equal(issue.fetched_at, issue.updated_at);
        const link = database.db.prepare(
          'SELECT * FROM issue_pr_links WHERE issue_number=64201'
        ).get();
        const fix = database.db.prepare(
          'SELECT * FROM pull_request_fixes WHERE pr_number=64202'
        ).get();
        assert.equal(link.issue_node_id, 'I_64201');
        assert.equal(link.pr_node_id, 'PR_64202');
        assert.equal(link.source_node_id, 'CE_64201');
        assert.equal(fix.node_id, 'PR_64202');
        assert.equal(fix.repository_node_id, 'R_openclaw');
        assert.throws(
          () => database.db.prepare(\`
            INSERT INTO issue_pr_links (
              issue_number, issue_node_id, pr_repository_owner,
              pr_repository_name, pr_repository_name_with_owner, pr_number,
              pr_node_id, source, source_node_id, fetched_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          \`).run(
            link.issue_number,
            link.issue_node_id,
            link.pr_repository_owner,
            link.pr_repository_name,
            link.pr_repository_name_with_owner,
            64203,
            'PR_64203',
            link.source,
            link.source_node_id,
            link.fetched_at,
          ),
          /UNIQUE constraint failed: issue_pr_links.issue_number, issue_pr_links.source_node_id, issue_pr_links.source/,
        );
        assert.throws(
          () => database.db.prepare(
            "UPDATE issue_pr_links SET source_node_id='CE_changed' " +
            "WHERE issue_number=64201"
          ).run(),
          /issue_pr_links identity is immutable once recorded/,
        );
        assert.throws(
          () => database.db.prepare(
            "UPDATE pull_request_fixes SET repository_node_id='R_changed' " +
            "WHERE pr_number=64202"
          ).run(),
          /pull_request_fixes.repository_node_id is immutable once recorded/,
        );
        const persistedLink = database.db.prepare(
          'SELECT * FROM issue_pr_links WHERE issue_number=64201'
        ).get();
        const persistedFix = database.db.prepare(
          'SELECT * FROM pull_request_fixes WHERE pr_number=64202'
        ).get();
        assert.equal(persistedLink.source_node_id, 'CE_64201');
        assert.equal(persistedFix.repository_node_id, 'R_openclaw');
        assert.equal(database.db.prepare(
          'SELECT COUNT(*) AS count FROM issue_pr_links'
        ).get().count, 1);
        console.log(JSON.stringify({
          schemaObjects,
          issue,
          link: {
            issueNumber: persistedLink.issue_number,
            issueNodeId: persistedLink.issue_node_id,
            repository: persistedLink.pr_repository_name_with_owner,
            prNumber: persistedLink.pr_number,
            prNodeId: persistedLink.pr_node_id,
            source: persistedLink.source,
            sourceNodeId: persistedLink.source_node_id,
          },
          fix: {
            repository: persistedFix.pr_repository_name_with_owner,
            prNumber: persistedFix.pr_number,
            nodeId: persistedFix.node_id,
            repositoryNodeId: persistedFix.repository_node_id,
          },
        }));
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    const migrated = verifyMigration();
    assert.equal(migrated.status, 0, `${migrated.stdout}\n${migrated.stderr}`);
    const restarted = verifyMigration();
    assert.equal(restarted.status, 0, `${restarted.stdout}\n${restarted.stderr}`);
    assert.deepEqual(
      JSON.parse(migrated.stdout.trim().split('\n').at(-1)!),
      JSON.parse(restarted.stdout.trim().split('\n').at(-1)!),
    );
  });

  it('rolls back base schema and column migrations when legacy PR copy fails', () => {
    const path = dbPath('legacy-pr-copy-rollback');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE comparison_releases;
          DROP TABLE comparison_snapshots;
          ALTER TABLE issues DROP COLUMN raw_json;
          DROP TABLE issue_pr_links;
          DROP TABLE pull_request_fixes;
          CREATE TABLE pull_request_fixes (
            pr_number INTEGER PRIMARY KEY,
            title TEXT,
            url TEXT,
            state TEXT,
            merged INTEGER,
            merged_at TEXT,
            merge_commit_oid TEXT,
            base_ref_name TEXT,
            fetched_at TEXT
          );
          INSERT INTO pull_request_fixes (
            pr_number, title, url, state, merged, fetched_at
          ) VALUES (
            64204, 'legacy pull request copied before failure',
            'https://github.com/openclaw/openclaw/pull/64204',
            'OPEN', 0, '2026-07-04T11:01:00Z'
          );
          CREATE TABLE issue_pr_links (
            issue_number INTEGER NOT NULL,
            pr_number INTEGER NOT NULL,
            source TEXT,
            will_close_target INTEGER,
            referenced_at TEXT,
            fetched_at TEXT
          );
          INSERT INTO issue_pr_links (
            issue_number, pr_number, source, will_close_target,
            referenced_at, fetched_at
          ) VALUES (
            64203, 64204, NULL, 1,
            '2026-07-04T11:00:00Z', '2026-07-04T11:01:00Z'
          );
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const migrate = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        await import('./src/lib/db.ts');
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    assert.notEqual(migrate.status, 0);
    assert.match(
      `${migrate.stdout}\n${migrate.stderr}`,
      /NOT NULL constraint failed: issue_pr_links_next\.source/,
    );

    const inspection = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM sqlite_schema
        WHERE type='table'
          AND name IN ('comparison_snapshots', 'comparison_releases')
      `).get() as any).count, 0);
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM pragma_table_info('issues')
        WHERE name='raw_json'
      `).get() as any).count, 0);
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM pragma_table_info('pull_request_fixes')
        WHERE name IN ('node_id', 'repository_node_id', 'raw_json', 'checked_at')
      `).get() as any).count, 0);
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM pragma_table_info('issue_pr_links')
        WHERE name IN (
          'issue_node_id', 'pr_node_id', 'source_node_id', 'raw_json',
          'pr_repository_owner', 'pr_repository_name',
          'pr_repository_name_with_owner'
        )
      `).get() as any).count, 0);
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM sqlite_schema
        WHERE name IN ('pull_request_fixes_next', 'issue_pr_links_next')
      `).get() as any).count, 0);
      assert.equal(
        (inspection.prepare(
          'SELECT pr_number FROM pull_request_fixes',
        ).get() as any).pr_number,
        64204,
      );
      assert.equal(
        (inspection.prepare(
          'SELECT source FROM issue_pr_links',
        ).get() as any).source,
        null,
      );
    } finally {
      inspection.close();
    }
  });

  it('propagates freshness SQL failures and rolls back the whole bootstrap', () => {
    const path = dbPath('freshness-backfill-rollback');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.upsertIssue({
          number: 64205,
          state: 'open',
          title: 'freshness rollback issue',
          author: 'legacy-user',
          html_url: 'https://example.test/issues/64205',
          created_at: '2026-07-04T10:00:00Z',
          updated_at: '2026-07-04T11:00:00Z',
          closed_at: null,
          comments: 0,
          labels: '[]',
          is_bot: 0,
        });
        database.db.prepare(
          'UPDATE issues SET fetched_at=NULL WHERE number=64205'
        ).run();
        database.setMeta(
          'issue_crawl_last_run',
          JSON.stringify({ finishedAt: '2026-07-04T11:02:00Z' }),
        );
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE comparison_releases;
          DROP TABLE comparison_snapshots;
          ALTER TABLE issues DROP COLUMN raw_json;
          CREATE TRIGGER fail_issue_freshness_backfill
          BEFORE UPDATE OF fetched_at ON issues
          WHEN OLD.fetched_at IS NULL
          BEGIN
            SELECT RAISE(ABORT, 'forced freshness backfill failure');
          END;
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const migrate = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        await import('./src/lib/db.ts');
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    assert.notEqual(migrate.status, 0);
    assert.match(
      `${migrate.stdout}\n${migrate.stderr}`,
      /forced freshness backfill failure/,
    );

    const inspection = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM sqlite_schema
        WHERE type='table'
          AND name IN ('comparison_snapshots', 'comparison_releases')
      `).get() as any).count, 0);
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM pragma_table_info('issues')
        WHERE name='raw_json'
      `).get() as any).count, 0);
      assert.equal(
        (inspection.prepare(
          'SELECT fetched_at FROM issues WHERE number=64205'
        ).get() as any).fetched_at,
        null,
      );
      assert.equal((inspection.prepare(`
        SELECT COUNT(*) AS count
        FROM sqlite_schema
        WHERE type='trigger' AND name='fail_issue_freshness_backfill'
      `).get() as any).count, 1);
    } finally {
      inspection.close();
    }
  });

  it('migrates legacy authority storage idempotently without fabricating identities or v2 evidence', () => {
    const path = dbPath('authority-v2-legacy-migration');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.upsertIssue({
          number: 6420,
          state: 'open',
          title: 'legacy issue',
          author: 'legacy-user',
          html_url: 'https://example.test/issues/6420',
          created_at: '2026-07-04T10:00:00Z',
          updated_at: '2026-07-04T10:00:00Z',
          closed_at: null,
          comments: 0,
          labels: '[]',
          is_bot: 0,
        });
        database.upsertIssueLabelEvent({
          issue_number: 6420,
          event_id: 'legacy-label-6420',
          action: 'labeled',
          label_name: 'P1',
          actor_login: 'legacy-user',
          created_at: '2026-07-04T10:00:00Z',
        });
        database.db.prepare(
          "INSERT INTO repository_collaborator_permission_snapshots (" +
          "snapshot_id, schema_version, repository, observed_at, exhaustive, " +
          "complete, total_count, row_count, page_count, pages_fetched, " +
          "sweep_count, content_digest, source_identity" +
          ") VALUES ('legacy-permission', 1, 'openclaw/openclaw', " +
          "'2026-07-04T09:00:00Z', 1, 1, 0, 0, 1, 1, 2, " +
          "'legacy-digest', 'legacy-source')"
        ).run();
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE release_score_audit_history_v2_seals;
          DROP TABLE score_authority_resolution_rows;
          DROP TABLE score_authority_resolution_runs;
          DROP TABLE closure_claim_candidates;
          DROP TABLE closure_claim_source_snapshots;
          DROP TABLE signed_maintainer_roster_entries;
          DROP TABLE signed_maintainer_roster_snapshots;
          DROP TABLE repository_collaborator_permission_rows_v2;
          DROP TABLE repository_collaborator_permission_snapshots_v2;
          DROP TABLE issue_label_evidence_rows;
          DROP TABLE issue_label_evidence_snapshots;
          DROP INDEX idx_issues_node_id_unique;
          DROP TRIGGER issues_node_id_immutable;
          ALTER TABLE issues DROP COLUMN node_id;
          ALTER TABLE issues DROP COLUMN raw_json;
          ALTER TABLE issue_label_events DROP COLUMN issue_node_id;
          ALTER TABLE issue_label_events DROP COLUMN actor_node_id;
          ALTER TABLE issue_label_events DROP COLUMN raw_json;
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const verifyMigration = () => spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const issue = database.db.prepare(
          'SELECT node_id, raw_json FROM issues WHERE number=6420'
        ).get();
        assert.equal(issue.node_id, null);
        assert.equal(issue.raw_json, null);
        const labelEvent = database.db.prepare(
          "SELECT issue_node_id, actor_node_id, raw_json " +
          "FROM issue_label_events WHERE event_id='legacy-label-6420'"
        ).get();
        assert.equal(labelEvent.issue_node_id, null);
        assert.equal(labelEvent.actor_node_id, null);
        assert.equal(labelEvent.raw_json, null);
        assert.equal(database.db.prepare(
          'SELECT COUNT(*) AS count FROM repository_collaborator_permission_snapshots'
        ).get().count, 1);
        for (const table of [
          'issue_label_evidence_snapshots',
          'issue_label_evidence_rows',
          'repository_collaborator_permission_snapshots_v2',
          'repository_collaborator_permission_rows_v2',
          'signed_maintainer_roster_snapshots',
          'signed_maintainer_roster_entries',
          'closure_claim_source_snapshots',
          'closure_claim_candidates',
          'score_authority_resolution_runs',
          'score_authority_resolution_rows',
          'release_score_audit_history_v2_seals',
        ]) {
          assert.equal(
            database.db.prepare('SELECT COUNT(*) AS count FROM ' + table).get().count,
            0,
            table,
          );
        }
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    const migrated = verifyMigration();
    assert.equal(migrated.status, 0, `${migrated.stdout}\n${migrated.stderr}`);
    const restarted = verifyMigration();
    assert.equal(restarted.status, 0, `${restarted.stdout}\n${restarted.stderr}`);
  });

  it('rebuilds an empty closure-claim placeholder while preserving authority foreign-key integrity', () => {
    const path = dbPath('closure-claim-empty-placeholder-migration');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE closure_claim_candidates;
          CREATE TABLE closure_claim_candidates (
            candidate_id TEXT PRIMARY KEY,
            schema_version INTEGER NOT NULL,
            repository TEXT NOT NULL,
            repository_node_id TEXT,
            issue_number INTEGER NOT NULL,
            issue_node_id TEXT,
            candidate_kind TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_node_id TEXT,
            source_comment_database_id INTEGER,
            source_commit_oid TEXT,
            actor_node_id TEXT,
            actor_login TEXT,
            actor_type TEXT,
            claimed_at TEXT,
            target_issue_number INTEGER,
            target_issue_node_id TEXT,
            target_pr_node_id TEXT,
            raw_json TEXT NOT NULL,
            source_identity TEXT NOT NULL UNIQUE,
            content_hash TEXT NOT NULL UNIQUE,
            captured_at TEXT NOT NULL
          );
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const verifyMigration = () => spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const candidateColumns = new Set(
          database.db.prepare(
            "SELECT name FROM pragma_table_info('closure_claim_candidates')"
          ).all().map((row) => row.name)
        );
        for (const column of [
          'candidate_id',
          'source_identity',
          'canonical_claim_json',
          'canonical_candidate_json',
          'content_hash',
        ]) {
          assert.equal(candidateColumns.has(column), true, column);
        }
        assert.equal(candidateColumns.has('repository'), false);
        const sourceColumns = new Set(
          database.db.prepare(
            "SELECT name FROM pragma_table_info('closure_claim_source_snapshots')"
          ).all().map((row) => row.name)
        );
        assert.equal(sourceColumns.has('source_revision_identity'), true);
        const authorityForeignKeys = database.db.prepare(
          'PRAGMA foreign_key_list(score_authority_resolution_rows)'
        ).all();
        assert.equal(
          authorityForeignKeys.some((row) =>
            row.table === 'closure_claim_candidates' &&
            row.from === 'candidate_id'
          ),
          true,
        );
        assert.deepEqual(database.db.prepare('PRAGMA foreign_key_check').all(), []);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    const migrated = verifyMigration();
    assert.equal(migrated.status, 0, `${migrated.stdout}\n${migrated.stderr}`);
    const restarted = verifyMigration();
    assert.equal(restarted.status, 0, `${restarted.stdout}\n${restarted.stderr}`);
  });

  it('refuses to replace a non-empty closure-claim placeholder without mutating it', () => {
    const path = dbPath('closure-claim-nonempty-placeholder-migration');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.db.exec(\`
          PRAGMA foreign_keys=OFF;
          DROP TABLE closure_claim_candidates;
          CREATE TABLE closure_claim_candidates (
            candidate_id TEXT PRIMARY KEY,
            schema_version INTEGER NOT NULL,
            repository TEXT NOT NULL,
            repository_node_id TEXT,
            issue_number INTEGER NOT NULL,
            issue_node_id TEXT,
            candidate_kind TEXT NOT NULL,
            source_kind TEXT NOT NULL,
            source_node_id TEXT,
            source_comment_database_id INTEGER,
            source_commit_oid TEXT,
            actor_node_id TEXT,
            actor_login TEXT,
            actor_type TEXT,
            claimed_at TEXT,
            target_issue_number INTEGER,
            target_issue_node_id TEXT,
            target_pr_node_id TEXT,
            raw_json TEXT NOT NULL,
            source_identity TEXT NOT NULL UNIQUE,
            content_hash TEXT NOT NULL UNIQUE,
            captured_at TEXT NOT NULL
          );
          INSERT INTO closure_claim_candidates (
            candidate_id, schema_version, repository, repository_node_id,
            issue_number, issue_node_id, candidate_kind, source_kind,
            source_node_id, source_comment_database_id, source_commit_oid,
            actor_node_id, actor_login, actor_type, claimed_at,
            target_issue_number, target_issue_node_id, target_pr_node_id,
            raw_json, source_identity, content_hash, captured_at
          ) VALUES (
            'legacy-candidate', 1, 'openclaw/openclaw', 'R_openclaw',
            1, 'I_legacy', 'fix_claim', 'issue_comment',
            'IC_legacy', 1, NULL, 'U_legacy', 'legacy', 'User',
            '2026-07-04T12:00:00Z', NULL, NULL, NULL,
            '{"legacy":true}', 'legacy-source', '${'a'.repeat(64)}',
            '2026-07-04T12:00:01Z'
          );
          PRAGMA foreign_keys=ON;
        \`);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const reopen = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        await import('./src/lib/db.ts');
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    assert.notEqual(reopen.status, 0);
    assert.match(
      `${reopen.stdout}\n${reopen.stderr}`,
      /persisted rows present .*candidates=1.*rebuild a fresh quality database/s,
    );

    const inspection = new DatabaseSync(path, { readOnly: true });
    try {
      assert.equal(
        (inspection.prepare(`
          SELECT COUNT(*) AS count FROM closure_claim_candidates
        `).get() as any).count,
        1,
      );
      const columns = new Set(
        (inspection.prepare(`
          SELECT name FROM pragma_table_info('closure_claim_candidates')
        `).all() as Array<{ name: string }>).map((row) => row.name),
      );
      assert.equal(columns.has('raw_json'), true);
      assert.equal(columns.has('canonical_candidate_json'), false);
    } finally {
      inspection.close();
    }
  });

  it('opens identity-pre-v2 rows read-only without migrating or sealing them', async () => {
    const current = await freshDbWithPath('authority-v2-read-only-source');
    current.db.upsertRelease({
      tag: 'v-legacy-authority',
      name: 'v-legacy-authority',
      published_at: '2026-07-04T08:00:00Z',
      html_url: 'https://example.test/v-legacy-authority',
      prerelease: false,
      body: '',
    });
    current.db.upsertReleaseScoreAudit({
      release_tag: 'v-legacy-authority',
      scored_at: '2026-07-04T09:00:00Z',
      score_model_version: 'legacy-model',
      prompt_version: 1,
      final_score: 7,
      status: 'eligible',
      band: 'good',
      recommended: 0,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: '{"schemaVersion":9,"digest":"legacy"}',
    });
    current.db.upsertIssue({
      number: 6421,
      state: 'open',
      title: 'read-only legacy issue',
      author: 'legacy-user',
      html_url: 'https://example.test/issues/6421',
      created_at: '2026-07-04T10:00:00Z',
      updated_at: '2026-07-04T10:00:00Z',
      closed_at: null,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    const path = dbPath('authority-v2-read-only-legacy');
    await backup(current.db.db, path);
    const legacy = new DatabaseSync(path);
    try {
      legacy.exec(`
        PRAGMA foreign_keys=OFF;
        DROP TABLE release_score_audit_history_v2_seals;
        DROP TABLE score_authority_resolution_rows;
        DROP TABLE score_authority_resolution_runs;
        DROP TABLE closure_claim_candidates;
        DROP TABLE closure_claim_source_snapshots;
        DROP TABLE signed_maintainer_roster_entries;
        DROP TABLE signed_maintainer_roster_snapshots;
        DROP TABLE repository_collaborator_permission_rows_v2;
        DROP TABLE repository_collaborator_permission_snapshots_v2;
        DROP TABLE issue_label_evidence_rows;
        DROP TABLE issue_label_evidence_snapshots;
        DROP INDEX idx_issues_node_id_unique;
        DROP TRIGGER issues_node_id_immutable;
        ALTER TABLE issues DROP COLUMN node_id;
        ALTER TABLE issues DROP COLUMN raw_json;
        PRAGMA foreign_keys=ON;
      `);
    } finally {
      legacy.close();
    }

    const readOnlyEnvironment = {
      ...databaseSubprocessEnv(path, 'existing'),
      RADAR_DB_READ_ONLY: '1',
    };
    const readOnly = spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        process.env.RADAR_DB_READ_ONLY = '1';
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        assert.equal(database.getIssue(6421).title, 'read-only legacy issue');
        assert.equal(
          database.getReleaseScoreAudit('v-legacy-authority').score_model_version,
          'legacy-model',
        );
        assert.equal(database.db.prepare(
          "SELECT COUNT(*) AS count FROM sqlite_master " +
          "WHERE type='table' AND name='score_authority_resolution_runs'"
        ).get().count, 0);
        assert.equal(database.db.prepare(
          "SELECT COUNT(*) AS count FROM sqlite_master " +
          "WHERE type='table' AND name='release_score_audit_history_v2_seals'"
        ).get().count, 0);
        assert.equal(database.db.prepare(
          "SELECT COUNT(*) AS count FROM pragma_table_info('issues') " +
          "WHERE name IN ('node_id', 'raw_json')"
        ).get().count, 0);
        assert.throws(
          () => database.upsertIssue({
            number: 6421,
            state: 'open',
            title: 'mutated',
            author: 'legacy-user',
            html_url: 'https://example.test/issues/6421',
            created_at: '2026-07-04T10:00:00Z',
            updated_at: '2026-07-04T10:00:00Z',
            closed_at: null,
            comments: 0,
            labels: '[]',
            is_bot: 0,
          }),
          /unavailable or read-only/,
        );
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: readOnlyEnvironment,
      encoding: 'utf8',
    });
    assert.equal(readOnly.status, 0, `${readOnly.stdout}\n${readOnly.stderr}`);
  });

  it('migrates current audits into an immutable history baseline without cascade deletion', () => {
    const path = dbPath('history-baseline-migration');
    const setup = spawnTsxEvalSync(`
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        database.upsertRelease({
          tag: 'v-baseline',
          name: 'v-baseline',
          published_at: '2026-06-01T00:00:00Z',
          html_url: 'https://example.test/v-baseline',
          prerelease: false,
          body: '',
        });
        database.upsertReleaseScoreAudit({
          release_tag: 'v-baseline',
          scored_at: '2026-06-02T00:00:00Z',
          score_model_version: 'model-v1',
          prompt_version: 1,
          final_score: 8,
          status: 'eligible',
          band: 'good',
          recommended: 1,
          input_json: '{}',
          components_json: '{}',
          issue_evidence_json: '{}',
          gate_evidence_json: '{}',
          source_identity_json: '{"schemaVersion":1,"digest":"baseline-source"}',
        });
        database.upsertRelease({
          tag: 'v-later',
          name: 'v-later',
          published_at: '2026-06-03T00:00:00Z',
          html_url: 'https://example.test/v-later',
          prerelease: false,
          body: '',
        });
        database.db.exec('DROP TABLE release_score_audit_history');
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'fresh'),
      encoding: 'utf8',
    });
    assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

    const migrate = spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const row = database.db.prepare(
          "SELECT run_id, release_tag, source_identity_json FROM release_score_audit_history"
        ).get();
        assert.equal(row.run_id, 'migration:current-audit-baseline:v1');
        assert.equal(row.release_tag, 'v-baseline');
        assert.equal(JSON.parse(row.source_identity_json).digest, 'baseline-source');
        const seal = database.db.prepare(
          "SELECT run_id, row_count, previous_content_hash, content_hash FROM release_score_audit_history_runs"
        ).get();
        assert.equal(seal.run_id, 'migration:current-audit-baseline:v1');
        assert.equal(seal.row_count, 1);
        assert.equal(seal.previous_content_hash, null);
        assert.match(seal.content_hash, /^[0-9a-f]{64}$/);
        const historyForeignKeys = database.db.prepare(
          'PRAGMA foreign_key_list(release_score_audit_history)'
        ).all();
        assert.deepEqual(
          historyForeignKeys.map((foreignKey) => ({
            table: foreignKey.table,
            from: foreignKey.from,
            to: foreignKey.to,
            onDelete: foreignKey.on_delete,
          })),
          [{
            table: 'score_authority_resolution_runs',
            from: 'authority_run_id',
            to: 'authority_run_id',
            onDelete: 'RESTRICT',
          }],
        );
        assert.throws(
          () => database.db.prepare(
            "UPDATE release_score_audit_history SET final_score=1 WHERE release_tag='v-baseline'"
          ).run(),
          /append-only/,
        );
        database.db.prepare("DELETE FROM releases WHERE tag='v-baseline'").run();
        assert.equal(database.db.prepare(
          "SELECT COUNT(*) AS count FROM release_score_audit_history WHERE release_tag='v-baseline'"
        ).get().count, 1);
        assert.throws(
          () => database.upsertRelease({
            tag: 'v-phantom',
            name: 'v-phantom',
            published_at: '2026-06-03T00:00:00Z',
            html_url: 'https://example.test/v-phantom',
            prerelease: false,
            body: '',
          }),
          /upsertRelease is allowed only for test fixtures in fresh private test databases/,
        );
        assert.equal(database.getRelease('v-phantom'), undefined);
        database.upsertReleaseScoreAudit({
          release_tag: 'v-later',
          scored_at: '2026-06-04T00:00:00Z',
          score_model_version: 'model-v2',
          prompt_version: 2,
          final_score: 7,
          status: 'eligible',
          band: 'good',
          recommended: 1,
          input_json: '{}',
          components_json: '{}',
          issue_evidence_json: '{}',
          gate_evidence_json: '{}',
          source_identity_json: '{"schemaVersion":1,"digest":"later-source"}',
        });
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    assert.equal(migrate.status, 0, `${migrate.stdout}\n${migrate.stderr}`);

    const restart = spawnTsxEvalSync(`
      import assert from 'node:assert/strict';
      (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const imported = await import('./src/lib/db.ts');
        const database = imported.default ?? imported;
        const rows = database.db.prepare(
          "SELECT release_tag FROM release_score_audit_history " +
          "WHERE run_id='migration:current-audit-baseline:v1' ORDER BY release_tag"
        ).all();
        assert.deepEqual(rows.map((row) => row.release_tag), ['v-baseline']);
        const seal = database.db.prepare(
          "SELECT row_count FROM release_score_audit_history_runs " +
          "WHERE run_id='migration:current-audit-baseline:v1'"
        ).get();
        assert.equal(seal.row_count, 1);
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `, {
      cwd: root,
      env: databaseSubprocessEnv(path, 'existing'),
      encoding: 'utf8',
    });
    assert.equal(restart.status, 0, `${restart.stdout}\n${restart.stderr}`);
  });

  it('migrates legacy forecast uniqueness without rewriting ledger rows or outcome links', () => {
    const path = dbPath('forecast-series-migration');
    const dir = dirname(path);
    const legacyForecastSchema = `
      CREATE TABLE release_validation_forecasts_legacy (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        decision_id TEXT NOT NULL UNIQUE,
        opportunity_code TEXT NOT NULL,
        recorded_at TEXT NOT NULL,
        latest_release_tag TEXT NOT NULL,
        latest_release_published_at TEXT NOT NULL,
        selected_tag TEXT,
        audit_history_run_id TEXT NOT NULL,
        score_model_version TEXT NOT NULL,
        prompt_version INTEGER NOT NULL,
        policy_code TEXT NOT NULL,
        candidate_scores_json TEXT NOT NULL,
        decision_json TEXT NOT NULL,
        source_identity_json TEXT NOT NULL,
        code_revision TEXT,
        previous_content_hash TEXT,
        content_hash TEXT NOT NULL UNIQUE,
        UNIQUE(opportunity_code, latest_release_tag)
      );
      INSERT INTO release_validation_forecasts_legacy (
        id, decision_id, opportunity_code, recorded_at, latest_release_tag,
        latest_release_published_at, selected_tag, audit_history_run_id,
        score_model_version, prompt_version, policy_code, candidate_scores_json,
        decision_json, source_identity_json, code_revision, previous_content_hash,
        content_hash
      )
      SELECT
        id, decision_id, opportunity_code, recorded_at, latest_release_tag,
        latest_release_published_at, selected_tag, audit_history_run_id,
        score_model_version, prompt_version, policy_code, candidate_scores_json,
        decision_json, source_identity_json, code_revision, previous_content_hash,
        content_hash
      FROM release_validation_forecasts;
      DROP TABLE release_validation_forecasts;
      ALTER TABLE release_validation_forecasts_legacy RENAME TO release_validation_forecasts;
      CREATE INDEX idx_release_validation_forecasts_recorded
        ON release_validation_forecasts(recorded_at);
      CREATE INDEX idx_release_validation_forecasts_model
        ON release_validation_forecasts(score_model_version, prompt_version);
      CREATE TRIGGER release_validation_forecasts_no_update
      BEFORE UPDATE ON release_validation_forecasts
      BEGIN
        SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
      END;
      CREATE TRIGGER release_validation_forecasts_no_delete
      BEFORE DELETE ON release_validation_forecasts
      BEGIN
        SELECT RAISE(ABORT, 'release_validation_forecasts is append-only');
      END;
      CREATE TRIGGER release_validation_forecasts_after_insert
      AFTER INSERT ON release_validation_forecasts
      BEGIN
        SELECT NEW.id;
      END;
    `;
    try {
      const setup = spawnTsxEvalSync(`
        void (async () => {
          process.env.DB_PATH = ${JSON.stringify(path)};
          const imported = await import('./src/lib/db.ts');
          const database = imported.default ?? imported;
          const authorityImport = await import('./src/lib/scoreAuthorityResolution.ts');
          const authorityModule = authorityImport.default ?? authorityImport;
          const validationBatchImport = await import('./src/lib/releaseValidationBatch.ts');
          const validationBatchModule =
            validationBatchImport.default ?? validationBatchImport;
          const catalogRelease = ${catalogRelease.toString()};
          const forecastCatalogAttestation = ${forecastCatalogAttestation.toString()};
          const forecastDecisionV4 = ${forecastDecisionV4.toString()};
          database.upsertRelease({
            tag: 'v-legacy-forecast',
            name: 'v-legacy-forecast',
            published_at: '2026-06-01T00:00:00.000Z',
            html_url: 'https://example.test/v-legacy-forecast',
            prerelease: false,
            body: '',
          });
          const recordedAt = '2026-06-02T00:00:00.000Z';
          const attestation = forecastCatalogAttestation(
            database,
            'v-legacy-forecast',
            '2026-06-01T00:00:00.000Z',
            recordedAt,
          );
          const sourceIdentityValue = database.scoreSourceIdentity();
          const sourceIdentity = JSON.stringify(sourceIdentityValue);
          const authorityRunId = 'score-authority:run-legacy-forecast';
          const authorityRun = authorityModule.buildScoreAuthorityResolutionRun({
            authorityRunId,
            sourceIdentitySchemaVersion: sourceIdentityValue.schemaVersion,
            sourceIdentityDigest: sourceIdentityValue.digest,
            recordedAt: '2026-06-02T00:00:00.000Z',
            previousContentHash: null,
            rows: [],
          });
          database.insertScoreAuthorityResolutionRun(authorityRun);
          const audit = {
            release_tag: 'v-legacy-forecast',
            scored_at: '2026-06-02T00:00:00.000Z',
            score_model_version: 'evidence-v16',
            prompt_version: 5,
            final_score: 8,
            status: 'eligible',
            band: 'good',
            recommended: 1,
            input_json: '{}',
            components_json: '{}',
            issue_evidence_json: '{}',
            gate_evidence_json: '{}',
            source_identity_json: sourceIdentity,
            authority_run_id: authorityRunId,
          };
          database.insertReleaseScoreAuditHistory('run-legacy-forecast', recordedAt, audit);
          const seal = database.sealReleaseScoreAuditHistoryRun('run-legacy-forecast', recordedAt);
          const historyV2Seal = database.sealReleaseScoreAuditHistoryV2({
            historyRunId: 'run-legacy-forecast',
            authorityRunId,
            sealedAt: recordedAt,
          });
          const recommendationDecision = {
            policyCode: 'highest_confidence_with_recency_tolerance',
            selectedTag: audit.release_tag,
          };
          const inserted = database.insertReleaseValidationForecast({
            opportunity_code: 'first_verified_after_24h',
            recorded_at: recordedAt,
            latest_release_tag: audit.release_tag,
            latest_release_published_at: '2026-06-01T00:00:00.000Z',
            selected_tag: audit.release_tag,
            audit_history_run_id: 'run-legacy-forecast',
            score_model_version: audit.score_model_version,
            prompt_version: audit.prompt_version,
            policy_code: recommendationDecision.policyCode,
            candidate_scores_json: JSON.stringify([{
              releaseTag: audit.release_tag,
              scoreSnapshot: {
                scoredAt: audit.scored_at,
                finalScore: audit.final_score,
                status: audit.status,
                band: audit.band,
                recommended: true,
              },
              auditSnapshot: {
                run_id: 'run-legacy-forecast',
                recorded_at: recordedAt,
                ...audit,
              },
            }]),
            decision_json: JSON.stringify(forecastDecisionV4({
              opportunityCode: 'first_verified_after_24h',
              recordedAt,
              latestReleaseTag: audit.release_tag,
              latestReleasePublishedAt: '2026-06-01T00:00:00.000Z',
              selectedTag: audit.release_tag,
              recommendationDecision,
              historyRunId: 'run-legacy-forecast',
              historyRunContentHash: seal.row.content_hash,
              authorityRunId,
              authorityRunContentHash: authorityRun.contentHash,
              historyV2SealContentHash: historyV2Seal.row.contentHash,
              historyRecordedAt: recordedAt,
              catalogAttestation: attestation,
            })),
            source_identity_json: sourceIdentity,
            code_revision: 'legacy-revision',
          });
          const [legacyOutcome] = validationBatchModule.stageReleaseValidationOutcomeRows([], [{
            decision_id: inserted.row.decision_id,
            horizon_code: 'field_regression_72h',
            observed_at: '2026-06-05T00:00:01.000Z',
            status: 'indeterminate',
            outcome_json: '{"schemaVersion":1,"reason":"fixture"}',
            source_identity_json: sourceIdentity,
          }]);
          database.db.prepare(\`
            INSERT INTO release_validation_outcome_observations (
              id, observation_id, decision_id, horizon_code, observed_at, status,
              outcome_json, source_identity_json, previous_content_hash, content_hash
            )
            VALUES (
              :id, :observation_id, :decision_id, :horizon_code, :observed_at, :status,
              :outcome_json, :source_identity_json, :previous_content_hash, :content_hash
            )
          \`).run(legacyOutcome);
          database.db.exec(${JSON.stringify(legacyForecastSchema)});
          database.db.close();
        })().catch((error) => {
          console.error(error);
          process.exitCode = 1;
        });
      `, {
        cwd: root,
        env: databaseSubprocessEnv(path, 'fresh'),
        encoding: 'utf8',
      });
      assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

      const verifyScript = `
        import assert from 'node:assert/strict';
        void (async () => {
          process.env.DB_PATH = ${JSON.stringify(path)};
          const imported = await import('./src/lib/db.ts');
          const database = imported.default ?? imported;
          const validationModule = await import('./src/lib/releaseValidation.ts');
          const validation = validationModule.default ?? validationModule;
          const forecasts = database.listReleaseValidationForecasts();
          const outcomes = database.listReleaseValidationOutcomeObservations();
          const authorityRuns = database.listScoreAuthorityResolutionRuns();
          const historyV2Seals = database.listReleaseScoreAuditHistoryV2Seals();
          assert.equal(forecasts.length, 1);
          assert.equal(outcomes.length, 1);
          assert.equal(authorityRuns.length, 1);
          assert.equal(historyV2Seals.length, 1);
          assert.equal(
            authorityRuns[0].authorityRunId,
            'score-authority:run-legacy-forecast',
          );
          assert.equal(historyV2Seals[0].historyRunId, 'run-legacy-forecast');
          assert.equal(forecasts[0].id, 1);
          assert.equal(outcomes[0].id, 1);
          assert.equal(outcomes[0].decision_id, forecasts[0].decision_id);
          assert.equal(forecasts[0].score_model_version, 'evidence-v16');
          assert.equal(forecasts[0].prompt_version, 5);
          assert.equal(forecasts[0].previous_content_hash, null);
          assert.match(forecasts[0].content_hash, /^[0-9a-f]{64}$/);
          assert.match(outcomes[0].content_hash, /^[0-9a-f]{64}$/);
          const indexes = database.db.prepare(
            'PRAGMA index_list(release_validation_forecasts)'
          ).all();
          const indexColumns = (name) => database.db.prepare(
            'PRAGMA index_xinfo("' + String(name).replaceAll('"', '""') + '")'
          ).all()
            .filter((column) => Number(column.key) === 1)
            .sort((left, right) => Number(left.seqno) - Number(right.seqno))
            .map((column) => column.name);
          const uniqueIndexes = indexes
            .filter((index) => Number(index.unique) === 1);
          const withoutRevision = uniqueIndexes.find((index) =>
            Number(index.partial) === 1 &&
            JSON.stringify(indexColumns(index.name)) === JSON.stringify([
              'opportunity_code',
              'latest_release_tag',
              'score_model_version',
              'prompt_version',
            ]));
          const withRevision = uniqueIndexes.find((index) =>
            Number(index.partial) === 1 &&
            JSON.stringify(indexColumns(index.name)) === JSON.stringify([
              'opportunity_code',
              'latest_release_tag',
              'score_model_version',
              'prompt_version',
              'code_revision',
            ]));
          assert.ok(withoutRevision);
          assert.ok(withRevision);
          assert.match(database.db.prepare(
            'SELECT sql FROM sqlite_schema WHERE name=?'
          ).get(withoutRevision.name).sql, /WHERE code_revision IS NULL/);
          assert.match(database.db.prepare(
            'SELECT sql FROM sqlite_schema WHERE name=?'
          ).get(withRevision.name).sql, /WHERE code_revision IS NOT NULL/);
          assert.ok(!uniqueIndexes.some((index) =>
            Number(index.partial) === 0 &&
            JSON.stringify(indexColumns(index.name)) === JSON.stringify([
            'opportunity_code',
            'latest_release_tag',
            'score_model_version',
            'prompt_version',
          ])));
          assert.ok(!uniqueIndexes.some((index) =>
            Number(index.partial) === 0 &&
            JSON.stringify(indexColumns(index.name)) === JSON.stringify([
            'opportunity_code',
            'latest_release_tag',
          ])));
          const schemaNames = database.db.prepare(
            "SELECT name FROM sqlite_schema WHERE tbl_name='release_validation_forecasts'"
          ).all().map((row) => row.name);
          assert.ok(schemaNames.includes('idx_release_validation_forecasts_recorded'));
          assert.ok(schemaNames.includes('idx_release_validation_forecasts_model'));
          assert.ok(schemaNames.includes('release_validation_forecasts_no_update'));
          assert.ok(schemaNames.includes('release_validation_forecasts_no_delete'));
          assert.ok(schemaNames.includes('release_validation_forecasts_after_insert'));
          assert.equal(database.db.prepare(
            "SELECT COUNT(*) AS count FROM sqlite_schema WHERE name='release_validation_forecasts_next'"
          ).get().count, 0);
          assert.equal(database.db.prepare(
            "SELECT seq FROM sqlite_sequence WHERE name='release_validation_forecasts'"
          ).get().seq, 1);
          assert.throws(
            () => database.db.prepare(
              "UPDATE release_validation_forecasts SET selected_tag=NULL WHERE id=1"
            ).run(),
            /append-only/,
          );
          const integrity = validation.validateReleaseValidationLedgerIntegrity({
            forecasts,
            observations: outcomes,
            auditHistory: database.db.prepare(
              'SELECT * FROM release_score_audit_history ORDER BY id'
            ).all(),
            auditHistoryRuns: database.db.prepare(
              'SELECT * FROM release_score_audit_history_runs ORDER BY id'
            ).all(),
            authorityRuns,
            historyV2Seals,
            advisorySnapshots: [],
          });
          assert.equal(integrity.ok, true, integrity.errors.join('; '));
          console.log(JSON.stringify({
            forecast: forecasts[0],
            outcome: outcomes[0],
            schemaNames: schemaNames.slice().sort(),
          }));
          database.db.close();
        })().catch((error) => {
          console.error(error);
          process.exitCode = 1;
        });
      `;
      const firstOpen = spawnTsxEvalSync(verifyScript, {
        cwd: root,
        env: databaseSubprocessEnv(path, 'existing'),
        encoding: 'utf8',
      });
      assert.equal(firstOpen.status, 0, `${firstOpen.stdout}\n${firstOpen.stderr}`);
      const secondOpen = spawnTsxEvalSync(verifyScript, {
        cwd: root,
        env: databaseSubprocessEnv(path, 'existing'),
        encoding: 'utf8',
      });
      assert.equal(secondOpen.status, 0, `${secondOpen.stdout}\n${secondOpen.stderr}`);
      assert.deepEqual(
        JSON.parse(firstOpen.stdout.trim().split('\n').at(-1)!),
        JSON.parse(secondOpen.stdout.trim().split('\n').at(-1)!),
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('stores immutable hash-chained validation forecasts and outcome observations', async () => {
    const db = await freshDb('validation-ledger');
    const historyRecordedAt = '2026-06-02T00:00:00.000Z';
    seedRelease(db, 'v-forecast', '2026-06-01T00:00:00Z');
    const forecastAttestation = forecastCatalogAttestation(
      db,
      'v-forecast',
      '2026-06-01T00:00:00Z',
      historyRecordedAt,
    );
    const sourceIdentity = JSON.stringify(db.scoreSourceIdentity());
    const auditInput = {
      release_tag: 'v-forecast',
      scored_at: historyRecordedAt,
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'good',
      recommended: 1,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: sourceIdentity,
    };
    const {
      audit,
      authorityRun,
      seal: forecastSeal,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId: 'run-forecast',
      recordedAt: historyRecordedAt,
      audit: auditInput,
    });
    const recommendationDecision = {
      policyCode: 'highest_confidence_with_recency_tolerance',
      selectedTag: 'v-forecast',
    };
    const candidateScoresJson = JSON.stringify([{
      releaseTag: 'v-forecast',
      scoreSnapshot: {
        scoredAt: audit.scored_at,
        finalScore: audit.final_score,
        status: audit.status,
        band: audit.band,
        recommended: true,
      },
      recommendationDecision,
      auditSnapshot: {
        run_id: 'run-forecast',
        recorded_at: historyRecordedAt,
        ...audit,
      },
    }]);
    const decisionJson = (
      opportunityCode: 'first_verified_after_24h',
      recordedAt: string,
    ) => JSON.stringify(forecastDecisionV4({
      opportunityCode,
      recordedAt,
      latestReleaseTag: 'v-forecast',
      latestReleasePublishedAt: '2026-06-01T00:00:00Z',
      selectedTag: 'v-forecast',
      recommendationDecision,
      historyRunId: 'run-forecast',
      historyRunContentHash: forecastSeal.row.content_hash,
      authorityRunId: authorityRun.authorityRunId,
      authorityRunContentHash: authorityRun.contentHash,
      historyV2SealContentHash: historyV2Seal.row.contentHash,
      historyRecordedAt,
      catalogAttestation: forecastAttestation,
    }));

    const forecastInput = {
      opportunity_code: 'first_verified_after_24h',
      recorded_at: historyRecordedAt,
      latest_release_tag: 'v-forecast',
      latest_release_published_at: '2026-06-01T00:00:00Z',
      selected_tag: 'v-forecast',
      audit_history_run_id: 'run-forecast',
      score_model_version: 'model-v1',
      prompt_version: 1,
      policy_code: 'highest_confidence_with_recency_tolerance',
      candidate_scores_json: candidateScoresJson,
      decision_json: decisionJson(
        'first_verified_after_24h',
        historyRecordedAt,
      ),
      source_identity_json: sourceIdentity,
      code_revision: 'test-revision',
    };
    const legacyDecision = JSON.parse(forecastInput.decision_json);
    legacyDecision.schemaVersion = 3;
    assert.throws(
      () => db.insertReleaseValidationForecast({
        ...forecastInput,
        decision_json: JSON.stringify(legacyDecision),
      }),
      /require decision schemaVersion 4/,
    );
    const first = db.insertReleaseValidationForecast(forecastInput);
    assert.equal(first.status, 'inserted');
    assert.equal(first.inserted, true);
    assert.equal(first.equivalent, false);
    assert.equal(first.row.previous_content_hash, null);

    const duplicateOpportunity = db.insertReleaseValidationForecast({
      ...forecastInput,
      candidate_scores_json: JSON.stringify(JSON.parse(candidateScoresJson), null, 2),
      decision_json: JSON.stringify(JSON.parse(forecastInput.decision_json), null, 2),
      source_identity_json: JSON.stringify(JSON.parse(sourceIdentity), null, 2),
      code_revision: ' test-revision ',
    });
    assert.equal(duplicateOpportunity.status, 'equivalent');
    assert.equal(duplicateOpportunity.inserted, false);
    assert.equal(duplicateOpportunity.equivalent, true);
    assert.equal(duplicateOpportunity.row.decision_id, first.row.decision_id);
    assert.equal(duplicateOpportunity.row.code_revision, 'test-revision');

    const conflicts = [
      ['recorded_at', {
        recorded_at: '2026-06-02T00:00:01Z',
      }],
      ['latest_release_published_at', {
        latest_release_published_at: '2026-05-31T23:59:59Z',
      }],
      ['selected_tag', {
        selected_tag: null,
      }],
      ['audit_history_run_id', {
        audit_history_run_id: 'different-history-run',
      }],
      ['policy_code', {
        policy_code: 'different-policy',
      }],
      ['candidate_scores_json', {
        candidate_scores_json: JSON.stringify([
          ...JSON.parse(candidateScoresJson),
          { releaseTag: 'v-injected' },
        ]),
      }],
      ['decision_json', {
        decision_json: JSON.stringify({
          ...JSON.parse(forecastInput.decision_json),
          selectedTag: null,
        }),
      }],
      ['source_identity_json', {
        source_identity_json: JSON.stringify({
          ...JSON.parse(sourceIdentity),
          digest: 'different-source-digest',
        }),
      }],
    ] as const;
    for (const [field, change] of conflicts) {
      assert.throws(
        () => db.insertReleaseValidationForecast({
          ...forecastInput,
          ...change,
        }),
        new RegExp(
          `Validation forecast capture slot conflict.*differing fields:.*${field}`,
        ),
      );
    }
    assert.throws(
      () => db.insertReleaseValidationForecast({
        ...forecastInput,
        code_revision: '   ',
      }),
      /nonblank deterministic code revision/,
    );

    const second = db.insertReleaseValidationForecast({
      ...forecastInput,
      code_revision: 'test-revision-2',
    });
    assert.equal(second.status, 'inserted');
    assert.equal(second.inserted, true);
    assert.equal(second.row.previous_content_hash, first.row.content_hash);

    const outcomeInput = {
      decision_id: first.row.decision_id,
      horizon_code: 'field_regression_72h',
      observed_at: '2026-06-06T00:00:01Z',
      status: 'matured',
      outcome_json: '{"adverse":false,"fieldRegressionCount":0}',
      source_identity_json: sourceIdentity,
    };
    assert.throws(
      () => db.insertReleaseValidationOutcomeObservation(outcomeInput),
      /Direct release validation outcome writes are disabled/,
    );
    const forecasts = db.listReleaseValidationForecasts();
    const stagedOutcomes = stageReleaseValidationOutcomeRows([], [outcomeInput]);
    const results: ReleaseValidationObservationBatchResult[] = forecasts.flatMap(
      (forecast: any) =>
      (['field_regression_72h', 'security_30d'] as const).map(
        (horizonCode): ReleaseValidationObservationBatchResult => {
        if (
          forecast.decision_id === first.row.decision_id &&
          horizonCode === 'field_regression_72h'
        ) {
          return {
            decisionId: forecast.decision_id,
            opportunityCode: forecast.opportunity_code,
            targetReleaseTag: forecast.latest_release_tag,
            horizonCode,
            status: 'matured',
            persistence: 'inserted',
            adverse: false,
            observationId: stagedOutcomes[0].observation_id,
            observationContentHash: stagedOutcomes[0].content_hash,
          };
        }
        return {
          decisionId: forecast.decision_id,
          opportunityCode: forecast.opportunity_code,
          targetReleaseTag: forecast.latest_release_tag,
          horizonCode,
          status: 'pending',
          persistence: 'not_applicable',
        };
        },
      ),
    );
    const receipt = stageReleaseValidationObservationBatchReceipt(
      [],
      [],
      stagedOutcomes,
      {
        batchId: 'validation-forecast-ledger-outcome',
        observedAt: '2026-06-06T00:00:04Z',
        codeRevision: 'test-revision-2',
        sourceIdentityDigest: JSON.parse(sourceIdentity).digest,
        forecastCount: forecasts.length,
        forecastInputs: releaseValidationObservationBatchForecastInputs(forecasts),
        results,
      },
    );
    const committed = db.commitReleaseValidationObservationBatch({
      outcomes: stagedOutcomes,
      receipt,
    });
    assert.equal(committed.inserted, true);
    const duplicate = db.commitReleaseValidationObservationBatch({
      outcomes: stagedOutcomes,
      receipt,
    });
    assert.equal(duplicate.inserted, false);
    assert.equal(duplicate.equivalent, true);
    const outcome = db.listReleaseValidationOutcomeObservations()[0];
    assert.equal(outcome.observation_id, stagedOutcomes[0].observation_id);
    assert.throws(
      () => stageReleaseValidationOutcomeRows([outcome], [{
        ...outcomeInput,
        observed_at: '2026-06-06T00:00:03Z',
        outcome_json: '{"adverse":true,"fieldRegressionCount":1}',
      }]),
      /Matured validation outcome already exists/,
    );
    assert.throws(
      () => db.db.prepare(`
        INSERT INTO release_validation_outcome_observations (
          observation_id, decision_id, horizon_code, observed_at, status,
          outcome_json, source_identity_json, previous_content_hash, content_hash
        )
        VALUES (?, ?, ?, ?, 'matured', ?, ?, ?, ?)
      `).run(
        'conflicting-observation',
        first.row.decision_id,
        'field_regression_72h',
        '2026-06-06T00:00:03Z',
        '{"adverse":true}',
        sourceIdentity,
        outcome.content_hash,
        'conflicting-content-hash',
      ),
      /UNIQUE constraint failed/,
    );

    assert.throws(
      () => db.db.prepare(`
        UPDATE release_validation_forecasts
        SET selected_tag=NULL
        WHERE decision_id=?
      `).run(first.row.decision_id),
      /append-only/,
    );
    assert.throws(
      () => db.db.prepare(`
        DELETE FROM release_validation_outcome_observations
        WHERE observation_id=?
      `).run(outcome.observation_id),
      /append-only/,
    );
  });

  it('serializes concurrent equivalent forecast writers into one capture slot', async () => {
    const { db, path } = await freshDbWithPath('validation-forecast-concurrency');
    const recordedAt = '2026-06-02T00:00:00.000Z';
    seedRelease(db, 'v-concurrent-forecast', '2026-06-01T00:00:00Z');
    const concurrentAttestation = forecastCatalogAttestation(
      db,
      'v-concurrent-forecast',
      '2026-06-01T00:00:00Z',
      recordedAt,
    );
    const sourceIdentity = JSON.stringify(db.scoreSourceIdentity());
    const auditInput = {
      release_tag: 'v-concurrent-forecast',
      scored_at: recordedAt,
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'good',
      recommended: 1,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: sourceIdentity,
    };
    const {
      audit,
      authorityRun,
      seal: concurrentSeal,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId: 'run-concurrent-forecast',
      recordedAt,
      audit: auditInput,
    });
    const recommendationDecision = {
      policyCode: 'highest_confidence_with_recency_tolerance',
      selectedTag: audit.release_tag,
    };
    const input = {
      opportunity_code: 'first_verified_after_24h',
      recorded_at: recordedAt,
      latest_release_tag: audit.release_tag,
      latest_release_published_at: '2026-06-01T00:00:00Z',
      selected_tag: audit.release_tag,
      audit_history_run_id: 'run-concurrent-forecast',
      score_model_version: audit.score_model_version,
      prompt_version: audit.prompt_version,
      policy_code: recommendationDecision.policyCode,
      candidate_scores_json: JSON.stringify([{
        releaseTag: audit.release_tag,
        scoreSnapshot: {
          scoredAt: audit.scored_at,
          finalScore: audit.final_score,
          status: audit.status,
          band: audit.band,
          recommended: true,
        },
        recommendationDecision,
        auditSnapshot: {
          run_id: 'run-concurrent-forecast',
          recorded_at: recordedAt,
          ...audit,
        },
      }]),
      decision_json: JSON.stringify(forecastDecisionV4({
        opportunityCode: 'first_verified_after_24h',
        recordedAt,
        latestReleaseTag: audit.release_tag,
        latestReleasePublishedAt: '2026-06-01T00:00:00Z',
        selectedTag: audit.release_tag,
        recommendationDecision,
        historyRunId: 'run-concurrent-forecast',
        historyRunContentHash: concurrentSeal.row.content_hash,
        authorityRunId: authorityRun.authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
        historyRecordedAt: recordedAt,
        catalogAttestation: concurrentAttestation,
      })),
      source_identity_json: sourceIdentity,
      code_revision: 'concurrent-forecast-revision',
    };

    const startAt = Date.now() + 3_000;
    const childScript = (worker: number) => `
      void (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const databaseModule = await import('./src/lib/db.ts?forecast-worker=${worker}-' + Date.now());
        const database = databaseModule.default ?? databaseModule;
        while (Date.now() < ${startAt}) {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        const result = database.insertReleaseValidationForecast(
          ${JSON.stringify(input)}
        );
        console.log(JSON.stringify({
          inserted: result.inserted,
          status: result.status,
          id: result.row.decision_id,
        }));
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `;
    const children = [1, 2].map((worker) => spawn(
      process.execPath,
      tsxEvalArgs(childScript(worker)),
      {
        cwd: root,
        env: databaseSubprocessEnv(path, 'existing'),
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ));
    try {
      const results = await Promise.all(children.map(childResult));
      assert.deepEqual(
        results.map((result) => result.status).sort(),
        ['equivalent', 'inserted'],
      );
      assert.equal(new Set(results.map((result) => result.id)).size, 1);
      assert.equal(
        (db.db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_forecasts
          WHERE opportunity_code=?
            AND latest_release_tag=?
            AND score_model_version=?
            AND prompt_version=?
            AND code_revision=?
        `).get(
          input.opportunity_code,
          input.latest_release_tag,
          input.score_model_version,
          input.prompt_version,
          input.code_revision,
        ) as { count: number }).count,
        1,
      );
    } finally {
      for (const child of children) {
        if (child.exitCode == null) child.kill('SIGKILL');
      }
    }
  });

  it('serializes concurrent matured outcome writers without duplicate business keys', async () => {
    const { db, path } = await freshDbWithPath('validation-outcome-concurrency');
    const recordedAt = '2026-06-02T00:00:00.000Z';
    seedRelease(db, 'v-concurrent', '2026-06-01T00:00:00Z');
    const outcomeAttestation = forecastCatalogAttestation(
      db,
      'v-concurrent',
      '2026-06-01T00:00:00Z',
      recordedAt,
    );
    const sourceIdentity = JSON.stringify(db.scoreSourceIdentity());
    const auditInput = {
      release_tag: 'v-concurrent',
      scored_at: recordedAt,
      score_model_version: 'model-v1',
      prompt_version: 1,
      final_score: 8,
      status: 'eligible',
      band: 'good',
      recommended: 1,
      input_json: '{}',
      components_json: JSON.stringify({
        recommendationDecision: {
          policyCode: 'highest_confidence_with_recency_tolerance',
          selectedTag: 'v-concurrent',
        },
      }),
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
      source_identity_json: sourceIdentity,
    };
    const {
      audit,
      authorityRun,
      seal: outcomeSeal,
      historyV2Seal,
    } = insertAuthorityBackedHistory(db, {
      historyRunId: 'run-concurrent',
      recordedAt,
      audit: auditInput,
    });
    const recommendationDecision = {
      policyCode: 'highest_confidence_with_recency_tolerance',
      selectedTag: 'v-concurrent',
    };
    const forecast = db.insertReleaseValidationForecast({
      opportunity_code: 'first_verified_after_24h',
      recorded_at: recordedAt,
      latest_release_tag: 'v-concurrent',
      latest_release_published_at: '2026-06-01T00:00:00Z',
      selected_tag: 'v-concurrent',
      audit_history_run_id: 'run-concurrent',
      score_model_version: 'model-v1',
      prompt_version: 1,
      policy_code: 'highest_confidence_with_recency_tolerance',
      candidate_scores_json: JSON.stringify([{
        releaseTag: 'v-concurrent',
        scoreSnapshot: {
          scoredAt: audit.scored_at,
          finalScore: audit.final_score,
          status: audit.status,
          band: audit.band,
          recommended: true,
        },
        recommendationDecision,
        auditSnapshot: {
          run_id: 'run-concurrent',
          recorded_at: recordedAt,
          ...audit,
        },
      }]),
      decision_json: JSON.stringify(forecastDecisionV4({
        opportunityCode: 'first_verified_after_24h',
        recordedAt,
        latestReleaseTag: 'v-concurrent',
        latestReleasePublishedAt: '2026-06-01T00:00:00Z',
        selectedTag: 'v-concurrent',
        recommendationDecision,
        historyRunId: 'run-concurrent',
        historyRunContentHash: outcomeSeal.row.content_hash,
        authorityRunId: authorityRun.authorityRunId,
        authorityRunContentHash: authorityRun.contentHash,
        historyV2SealContentHash: historyV2Seal.row.contentHash,
        historyRecordedAt: recordedAt,
        catalogAttestation: outcomeAttestation,
      })),
      source_identity_json: sourceIdentity,
      code_revision: 'concurrent-outcome-revision',
    });

    const concurrentForecasts = db.listReleaseValidationForecasts();
    const concurrentOutcomes = stageReleaseValidationOutcomeRows([], [{
      decision_id: forecast.row.decision_id,
      horizon_code: 'field_regression_72h',
      observed_at: '2026-06-06T00:00:01Z',
      status: 'matured',
      outcome_json: JSON.stringify({
        adverse: false,
        observedAt: '2026-06-06T00:00:01Z',
        fieldRegressionCount: 0,
      }),
      source_identity_json: sourceIdentity,
    }]);
    const concurrentResults: ReleaseValidationObservationBatchResult[] = [
      {
        decisionId: forecast.row.decision_id,
        opportunityCode: forecast.row.opportunity_code,
        targetReleaseTag: forecast.row.latest_release_tag,
        horizonCode: 'field_regression_72h',
        status: 'matured',
        persistence: 'inserted',
        adverse: false,
        observationId: concurrentOutcomes[0].observation_id,
        observationContentHash: concurrentOutcomes[0].content_hash,
      },
      {
        decisionId: forecast.row.decision_id,
        opportunityCode: forecast.row.opportunity_code,
        targetReleaseTag: forecast.row.latest_release_tag,
        horizonCode: 'security_30d',
        status: 'pending',
        persistence: 'not_applicable',
      },
    ];
    const concurrentReceipt = stageReleaseValidationObservationBatchReceipt(
      [],
      [],
      concurrentOutcomes,
      {
        batchId: 'concurrent-outcome-batch',
        observedAt: '2026-06-06T00:00:02Z',
        codeRevision: 'concurrent-outcome-revision',
        sourceIdentityDigest: JSON.parse(sourceIdentity).digest,
        forecastCount: concurrentForecasts.length,
        forecastInputs: releaseValidationObservationBatchForecastInputs(
          concurrentForecasts,
        ),
        results: concurrentResults,
      },
    );
    const startAt = Date.now() + 3_000;
    const childScript = (worker: number) => `
      void (async () => {
        process.env.DB_PATH = ${JSON.stringify(path)};
        const databaseModule = await import('./src/lib/db.ts?outcome-worker=${worker}-' + Date.now());
        const database = databaseModule.default ?? databaseModule;
        while (Date.now() < ${startAt}) {
          await new Promise((resolve) => setTimeout(resolve, 10));
        }
        const outcomes = ${JSON.stringify(concurrentOutcomes)};
        const receipt = ${JSON.stringify(concurrentReceipt)};
        const result = database.commitReleaseValidationObservationBatch({
          outcomes,
          receipt,
        });
        console.log(JSON.stringify({
          inserted: result.inserted,
          id: outcomes[0].observation_id,
          receipt: result.row.content_hash,
        }));
        database.db.close();
      })().catch((error) => {
        console.error(error);
        process.exitCode = 1;
      });
    `;
    const children = [1, 2].map((worker) => spawn(
      process.execPath,
      tsxEvalArgs(childScript(worker)),
      {
        cwd: root,
        env: databaseSubprocessEnv(path, 'existing'),
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    ));
    try {
      const results = await Promise.all(children.map(childResult));
      assert.deepEqual(
        results.map((result) => result.inserted).sort(),
        [false, true],
      );
      assert.equal(new Set(results.map((result) => result.id)).size, 1);
      assert.equal(new Set(results.map((result) => result.receipt)).size, 1);
      const rows = db.db.prepare(`
        SELECT *
        FROM release_validation_outcome_observations
        WHERE decision_id=? AND horizon_code=? AND status='matured'
      `).all(forecast.row.decision_id, 'field_regression_72h');
      assert.equal(rows.length, 1);
      assert.equal(
        db.db.prepare(`
          SELECT COUNT(*) AS count
          FROM release_validation_observation_batches
          WHERE batch_id='concurrent-outcome-batch'
        `).get().count,
        1,
      );
    } finally {
      for (const child of children) {
        if (child.exitCode == null) child.kill('SIGKILL');
      }
    }
  });

  it('retains immutable complete advisory snapshots when advisories later disappear', async () => {
    const db = await freshDb('advisory-snapshot-history');
    const advisory = (ghsaId: string) => ({
      advisory_key: advisoryVulnerabilityKey(
        ghsaId,
        'npm',
        'openclaw',
        '<= 2026.6.1',
      ),
      ghsa_id: ghsaId,
      cve_id: null,
      summary: `summary ${ghsaId}`,
      severity: 'high',
      html_url: `https://example.test/${ghsaId}`,
      published_at: '2026-06-01T00:00:00Z',
      package_ecosystem: 'npm',
      package_name: 'openclaw',
      vulnerable_version_range: '<= 2026.6.1',
      patched_versions: '>= 2026.6.2',
    });
    db.replaceAdvisories([advisory('GHSA-one'), advisory('GHSA-two')]);
    db.replaceAdvisories([advisory('GHSA-two')]);

    assert.deepEqual(db.listAdvisories().map((row: any) => row.ghsa_id), ['GHSA-two']);
    const history = db.listAdvisorySnapshotRows();
    assert.equal(history.length, 3);
    assert.equal(history.filter((row: any) => row.ghsa_id === 'GHSA-one').length, 1);
    assert.equal(new Set(history.map((row: any) => row.snapshot_id)).size, 2);
    assert.deepEqual(
      db.db.prepare(`PRAGMA foreign_key_list(advisory_snapshot_rows)`).all()
        .map((row: any) => [row.table, row.from, row.to]),
      [['advisory_snapshot_history', 'snapshot_id', 'id']],
    );
    assert.throws(
      () => db.db.prepare(`
        INSERT INTO advisory_snapshot_rows (
          snapshot_id, advisory_key, ghsa_id, summary, severity, html_url
        )
        VALUES (999999, 'orphan', 'GHSA-orphan', 'orphan', 'high', 'https://example.test/orphan')
      `).run(),
      /FOREIGN KEY constraint failed/,
    );
    assert.throws(
      () => db.replaceAdvisories([{
        ...advisory('GHSA-foreign'),
        advisory_key: advisoryVulnerabilityKey(
          'GHSA-foreign',
          'npm',
          'some-other-package',
          '<= 2026.6.1',
        ),
        package_name: 'some-other-package',
      }]),
      /package_mismatch/,
    );
    assert.throws(
      () => db.db.prepare(`DELETE FROM advisory_snapshot_history`).run(),
      /append-only/,
    );
  });

  it('clears scored releases and audits outside the retained monitored set', async () => {
    const db = await freshDb('score-window-prune');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-current',
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-current'),
      ),
      catalogRelease(
        'v-old',
        '2026-05-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-old'),
      ),
    ]);
    const audit = (tag: string) => ({
      release_tag: tag,
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'test-model',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: tag === 'v-current' ? 1 : 0,
      input_json: '{}',
      components_json: '{}',
      issue_evidence_json: '{}',
      gate_evidence_json: '{}',
    });
    for (const tag of ['v-old', 'v-current']) {
      db.updateReleaseScore({
        tag,
        final_score: 7.5,
        negative_issues: 1,
        positive_issues: 0,
        state: 'eligible',
        recommended: tag === 'v-current' ? 1 : 0,
        score_reason: 'test',
        broken_surfaces: '[]',
        closed_serious_fixed: 1,
        opened_serious_during_reign: 0,
        scored_at: '2026-06-02T00:00:00Z',
      });
      db.upsertReleaseScoreAudit(audit(tag));
      db.insertReleaseScoreAuditHistory('run-prune', '2026-06-02T00:00:01Z', {
        ...audit(tag),
        source_identity_json: '{"schemaVersion":1,"digest":"prune-source"}',
      });
    }

    const cleared = db.runInWriteTransaction(() => db.clearReleaseScoresOutsideTags(['v-current']));
    assert.deepEqual(cleared, { releaseRows: 1, auditRows: 1 });
    assert.equal(db.getRelease('v-old')?.final_score, null);
    assert.equal(db.getRelease('v-old')?.scored_at, null);
    assert.equal(db.getReleaseScoreAudit('v-old'), undefined);
    const retainedHistory = db.db.prepare(`
      SELECT COUNT(*) AS count
      FROM release_score_audit_history
      WHERE release_tag='v-old'
    `).get() as any;
    assert.equal(retainedHistory.count, 1);
    assert.equal(db.getRelease('v-current')?.final_score, 7.5);
    assert.ok(db.getReleaseScoreAudit('v-current'));
  });

  it('tracks deterministic score source identity while excluding score outputs and comparison data', async () => {
    const db = await freshDb('score-source-identity');
    seedRelease(db, 'v1');
    seedIssue(db, 9501, null);

    const first = db.scoreSourceIdentity();
    const repeated = db.scoreSourceIdentity();
    const firstApiRevision = db.scoreApiSourceRevision();
    assert.deepEqual(repeated, first);
    assert.equal(first.sourceCount, 32);
    assert.ok(first.rowCount > 0);

    db.db.prepare(`UPDATE issues SET title='changed without timestamp movement' WHERE number=9501`).run();
    const sourceChanged = db.scoreSourceIdentity();
    const sourceChangedApiRevision = db.scoreApiSourceRevision();
    assert.notEqual(sourceChanged.digest, first.digest);
    assert.ok(sourceChangedApiRevision > firstApiRevision);
    assert.equal(
      sourceChanged.sources.find((source: any) => source.source === 'issues')?.count,
      first.sources.find((source: any) => source.source === 'issues')?.count,
    );

    db.setMeta(ADVISORY_SNAPSHOT_META_KEY, JSON.stringify({
      schemaVersion: 1,
      contentDigest: 'a'.repeat(64),
    }));
    const advisorySnapshotChanged = db.scoreSourceIdentity();
    const advisoryApiRevision = db.scoreApiSourceRevision();
    assert.notEqual(advisorySnapshotChanged.digest, sourceChanged.digest);
    assert.ok(advisoryApiRevision > sourceChangedApiRevision);
    assert.equal(
      advisorySnapshotChanged.sources.find((source: any) => source.source === 'advisory_snapshot')?.count,
      1,
    );

    db.db.prepare(`UPDATE releases SET final_score=8.8, scored_at='2026-06-03T00:00:00Z' WHERE tag='v1'`).run();
    const scoreOutputChanged = db.scoreSourceIdentity();
    const scoreOutputApiRevision = db.scoreApiSourceRevision();
    assert.deepEqual(scoreOutputChanged, advisorySnapshotChanged);
    assert.ok(scoreOutputApiRevision > advisoryApiRevision);

    db.saveComparisonSnapshot({
      source_url: 'https://example.test/source',
      captured_at: '2026-06-03T00:00:00Z',
      page_title: 'Comparison source',
      page_text: 'comparison text',
      raw_html: '<html></html>',
      releases: [{
        tag: 'v1',
        name: 'v1',
        published_at: '2026-06-01T00:00:00Z',
        html_url: 'https://example.test/releases/v1',
        displayed_date: 'Jun 1',
        score: 9.9,
        band: 'solid',
        status: 'eligible',
        recommended: true,
        reason: 'comparison only',
        negative_issues: 0,
        positive_issues: 1,
        total_attributed_issues: 1,
        visible_issues: [],
        raw_card_text: 'comparison card',
      }],
    });
    assert.deepEqual(db.scoreSourceIdentity(), scoreOutputChanged);
    assert.equal(db.scoreApiSourceRevision(), scoreOutputApiRevision);
  });

  it('keeps staged advisory snapshots non-authoritative until atomic activation', async () => {
    const db = await freshDb('advisory-active-pointer');
    seedRelease(db, 'v-advisory-pointer');
    const snapshotA = buildEmptyCompoundAdvisorySnapshot('2026-07-04T12:00:00.000Z');
    const activeA = db.persistCompoundAdvisorySnapshot(snapshotA);
    assert.deepEqual(
      activeA.snapshot.authorityPolicy,
      COMPOUND_ADVISORY_AUTHORITY_POLICY,
    );
    const identityA = db.scoreSourceIdentity();
    assert.deepEqual(
      db.listAuthorizedReleaseValidationAdvisorySnapshots()
        .filter((snapshot: any) => snapshot.schemaVersion === 2),
      [],
    );

    const snapshotB = buildEmptyCompoundAdvisorySnapshot('2026-07-04T12:05:00.000Z');
    const stagedB = db.stageCompoundAdvisorySnapshot(snapshotB);
    assert.notEqual(stagedB.metadata.snapshotId, activeA.metadata.snapshotId);
    assert.equal(
      db.currentCompoundAdvisorySnapshot()?.metadata.snapshotId,
      activeA.metadata.snapshotId,
    );
    assert.deepEqual(db.scoreSourceIdentity(), identityA);
    assert.deepEqual(
      db.listAuthorizedReleaseValidationAdvisorySnapshots()
        .filter((snapshot: any) => snapshot.schemaVersion === 2),
      [],
    );

    const previewRollback = new Error('rollback staged advisory preview');
    assert.throws(
      () => db.runInWriteTransaction(() => {
        db.activateCompoundAdvisorySnapshot(stagedB.metadata.snapshotId);
        assert.equal(
          db.currentCompoundAdvisorySnapshot()?.metadata.snapshotId,
          stagedB.metadata.snapshotId,
        );
        assert.notEqual(db.scoreSourceIdentity().digest, identityA.digest);
        throw previewRollback;
      }),
      (error: unknown) => error === previewRollback,
    );
    assert.equal(
      db.currentCompoundAdvisorySnapshot()?.metadata.snapshotId,
      activeA.metadata.snapshotId,
    );
    assert.deepEqual(db.scoreSourceIdentity(), identityA);

    const activeB = db.activateCompoundAdvisorySnapshot(stagedB.metadata.snapshotId);
    assert.equal(activeB.metadata.snapshotId, stagedB.metadata.snapshotId);
    assert.equal(
      db.currentCompoundAdvisorySnapshot()?.metadata.snapshotId,
      stagedB.metadata.snapshotId,
    );
    assert.notEqual(db.scoreSourceIdentity().digest, identityA.digest);
    assert.deepEqual(
      db.listAuthorizedReleaseValidationAdvisorySnapshots()
        .filter((snapshot: any) => snapshot.schemaVersion === 2),
      [],
    );
  });

  it('round-trips marked and legacy-unmarked advisory authority policies', async () => {
    const db = await freshDb('advisory-authority-policy-round-trip');
    const marked = db.persistCompoundAdvisorySnapshot(
      buildEmptyCompoundAdvisorySnapshot('2026-07-04T13:00:00.000Z'),
    );
    assert.deepEqual(
      db.compoundAdvisorySnapshotById(marked.metadata.snapshotId)
        ?.snapshot.authorityPolicy,
      COMPOUND_ADVISORY_AUTHORITY_POLICY,
    );

    const legacy = db.stageCompoundAdvisorySnapshot(
      buildEmptyCompoundAdvisorySnapshot(
        '2026-07-04T13:05:00.000Z',
        null,
      ),
    );
    assert.equal(Object.hasOwn(legacy.snapshot, 'authorityPolicy'), false);
    assert.equal(
      Object.hasOwn(
        db.compoundAdvisorySnapshotById(legacy.metadata.snapshotId)!.snapshot,
        'authorityPolicy',
      ),
      false,
    );
  });

  it('publishes one identical advisory-v2 audit projection through the DB and independent reader', async () => {
    const db = await freshDb('advisory-public-audit-projection');
    const nowMs = Date.now();
    const operationRunId = 'advisory-public-audit';
    const advisorySnapshot = buildGraphqlOnlyCompoundAdvisorySnapshot(
      new Date(nowMs - 30_000).toISOString(),
    );
    assert.equal(advisorySnapshot.rows.length, 1);
    assert.equal(advisorySnapshot.score.rows.length, 1);
    seedActionableRefreshPublication(db, {
      tag: 'v-advisory-public-audit',
      operationRunId,
      historyRunId: `refresh:${operationRunId}`,
      leaseName: 'refresh-advisory-public-audit',
      holderId: 'holder-advisory-public-audit',
      nowMs,
      advisorySnapshot,
    });

    const databaseProjection =
      db.currentCompoundAdvisorySnapshotAuditProjection();
    assert.equal(
      databaseProjection.verified,
      true,
      databaseProjection.problems.join('; '),
    );
    assert.equal(databaseProjection.failedCount, 0);
    assert.equal(databaseProjection.activeProjectionVerified, true);
    assert.equal(databaseProjection.activeRowCount, 1);
    assert.equal(databaseProjection.activeScoreRowCount, 1);
    assert.equal(
      databaseProjection.authorizingReceipt?.runId,
      operationRunId,
    );
    assert.equal(databaseProjection.authorizedSnapshotCount, 1);
    assert.equal(databaseProjection.stagedSnapshotCount, 0);

    const reader = new ReleaseAuditReader(db.db);
    assert.deepEqual(
      reader.advisorySnapshotAuditProjection(),
      databaseProjection,
    );

    db.setMeta(ADVISORY_SNAPSHOT_META_KEY, JSON.stringify({
      schemaVersion: 1,
      contentDigest: '0'.repeat(64),
    }));
    const integrity = reader.advisorySnapshotIntegrity();
    assert.ok(integrity.legacyCompatibility.failedCount > 0);
    assert.equal(integrity.failedCount, 0);
    assert.deepEqual(integrity.auditProjection, databaseProjection);
  });

  it('binds the current score identity schema to issue bodies, comment bodies, classifier provenance, and state verification', async () => {
    const db = await freshDb('score-source-identity-schema-eleven');
    seedRelease(db, 'v-schema-six', '2040-06-01T00:00:00Z');
    seedIssue(db, 9502, null, '2040-06-01T12:00:00Z');
    const issueNodeId = 'I_score_source_9502';
    db.db.prepare(`
      UPDATE issues
      SET node_id=?, body='original issue body'
      WHERE number=9502
    `).run(issueNodeId);
    const comments = [{
      id: 95020,
      user: { login: 'reporter' },
      body: 'verified comment body',
      created_at: '2040-06-01T12:10:00Z',
      updated_at: '2040-06-01T12:10:00Z',
    }];
    const commentsDigest = commentEvidenceDigest(1, comments);
    db.db.prepare(`UPDATE issues SET comments=1 WHERE number=9502`).run();
    db.upsertIssueCommentSnapshot({
      issue_number: 9502,
      schema_version: 2,
      comment_count: 1,
      fetched_comment_count: 1,
      latest_comment_updated_at: '2040-06-01T12:10:00Z',
      comments_digest: commentsDigest,
      issue_updated_at: '2040-06-01T12:00:00Z',
      comments_json: serializeCommentEvidence(comments),
    });
    const classifierIdentity = db.classifierSourceIdentity(['v-schema-six'], 6);
    db.upsertClassification(
      9502,
      classification(),
      '2040-06-01T12:00:00Z',
      6,
      commentsDigest,
      classifierIdentity,
    );
    db.replaceIssueStateEventSnapshot({
      issue_number: 9502,
      issue_state: 'open',
      issue_updated_at: '2040-06-01T12:00:00Z',
      total_count: 0,
      fetched_count: 0,
      sweep_count: 2,
      stabilized: true,
      closure_events: [],
      reopen_events: [],
      ...authoritativeStateSnapshotFields({
        repositoryNodeId: 'R_score_source_openclaw',
        issueNumber: 9502,
        issueNodeId,
        issueState: 'open',
        issueUpdatedAt: '2040-06-01T12:00:00Z',
        events: [],
      }),
    });

    const baseline = db.scoreSourceIdentity();
    assert.equal(
      baseline.schemaVersion,
      SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
    );
    const sourceDigest = (identity: any, source: string) =>
      identity.sources.find((entry: any) => entry.source === source)?.digest;

    db.db.prepare(`UPDATE issues SET body='changed issue body' WHERE number=9502`).run();
    const issueBodyChanged = db.scoreSourceIdentity();
    assert.notEqual(
      sourceDigest(issueBodyChanged, 'issues'),
      sourceDigest(baseline, 'issues'),
    );
    db.db.prepare(`UPDATE issues SET body='original issue body' WHERE number=9502`).run();

    db.db.prepare(`
      UPDATE issue_comment_snapshots
      SET comments_json=?
      WHERE issue_number=9502
    `).run(serializeCommentEvidence([{ ...comments[0], body: 'tampered comment body' }]));
    const commentChanged = db.scoreSourceIdentity();
    assert.notEqual(
      sourceDigest(commentChanged, 'issue_comment_snapshots'),
      sourceDigest(baseline, 'issue_comment_snapshots'),
    );
    db.db.prepare(`
      UPDATE issue_comment_snapshots
      SET comments_json=?
      WHERE issue_number=9502
    `).run(serializeCommentEvidence(comments));

    db.db.prepare(`
      UPDATE classifications
      SET source_identity_json=?
      WHERE issue_number=9502
    `).run(JSON.stringify({ ...classifierIdentity, model: 'obsolete-model' }));
    const classifierChanged = db.scoreSourceIdentity();
    assert.notEqual(
      sourceDigest(classifierChanged, 'classifications'),
      sourceDigest(baseline, 'classifications'),
    );
    db.db.prepare(`
      UPDATE classifications
      SET source_identity_json=?
      WHERE issue_number=9502
    `).run(JSON.stringify(classifierIdentity));
    db.db.prepare(`
      UPDATE classifications
      SET classification_origin='raw_model'
      WHERE issue_number=9502
    `).run();
    assert.throws(
      () => db.scoreSourceIdentity(),
      /raw-model classification is missing an accepted classifier publication/,
    );
    db.db.prepare(`
      UPDATE classifications
      SET classification_origin='legacy_or_manual'
      WHERE issue_number=9502
    `).run();

    db.db.prepare(`
      UPDATE issue_state_event_snapshots
      SET verified_at='2040-06-01T13:00:00Z'
      WHERE issue_number=9502
    `).run();
    const stateChanged = db.scoreSourceIdentity();
    assert.notEqual(
      sourceDigest(stateChanged, 'issue_state_event_snapshots'),
      sourceDigest(baseline, 'issue_state_event_snapshots'),
    );
  });

  it('invalidates source-identity cache keys for local and external database writes', async () => {
    const { db, path } = await freshDbWithPath('score-source-identity-cache-key');
    seedRelease(db, 'v-cache-key');
    const first = db.scoreSourceIdentityCacheKey();
    assert.equal(db.scoreSourceIdentityCacheKey(), first);

    db.db.prepare(`
      UPDATE releases
      SET name='local semantic change'
      WHERE tag='v-cache-key'
    `).run();
    const localChange = db.scoreSourceIdentityCacheKey();
    assert.notEqual(localChange, first);

    const external = new DatabaseSync(path);
    external.prepare(`
      UPDATE releases
      SET name='external semantic change'
      WHERE tag='v-cache-key'
    `).run();
    external.close();
    assert.notEqual(db.scoreSourceIdentityCacheKey(), localChange);
  });

  it('validates closure-proof gate evidence audit updates', async () => {
    const db = await freshDb('closure-proof-gate-update');
    seedRelease(db, 'v-proof');
    const audit = {
      release_tag: 'v-proof',
      scored_at: '2026-06-02T00:00:00Z',
      score_model_version: 'test-model',
      prompt_version: 1,
      final_score: 7.5,
      status: 'eligible',
      band: 'ok',
      recommended: 1,
      input_json: '{"schemaVersion":1,"rawIssueCount":0,"classifiedIssueCount":0}',
      components_json: '{"schemaVersion":1,"components":{},"explanation":{"schemaVersion":1}}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
    };
    db.upsertReleaseScoreAudit(audit);

    const validGate = {
      schemaVersion: 1,
      fixProvenance: {
        closureProof: {
          schemaVersion: 2,
          creditedCount: 1,
          notCreditedCount: 2,
          analyzedClosedCount: 3,
        },
        releaseFixCredit: {
          schemaVersion: 1,
          countedClosedCount: 1,
          notCountedClosedCount: 2,
          analyzedClosedCount: 3,
        },
      },
    };
    db.updateReleaseScoreAuditClosureProofGateEvidence('v-proof', JSON.stringify(validGate));
    assert.deepEqual(JSON.parse(db.getReleaseScoreAudit('v-proof').gate_evidence_json), validGate);

    seedIssue(db, 101);
    seedClosureProof(db, 'v-proof', 101);
    const withheldDecision = {
      schemaVersion: 1,
      issueNumber: 101,
      status: 'withheld',
      reasonCode: 'predecessor_reachable',
      targetTag: 'v-proof',
      predecessorTag: 'v-boundary',
      proofIdentities: [],
    };
    const detailedGate = {
      schemaVersion: 1,
      fixProvenance: {
        closureProof: {
          schemaVersion: 2,
          creditedCount: 0,
          notCreditedCount: 1,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 1,
        },
        releaseFixCredit: {
          schemaVersion: 1,
          targetTag: 'v-proof',
          predecessorTag: 'v-boundary',
          countedClosedCount: 0,
          notCountedClosedCount: 1,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 1,
          decisionCounts: { credited: 0, withheld: 1, invalid: 0 },
          decisions: [withheldDecision],
        },
      },
    };
    db.updateReleaseScoreAuditClosureProofGateEvidence('v-proof', JSON.stringify(detailedGate));
    assert.deepEqual(
      JSON.parse(db.getReleaseScoreAudit('v-proof').gate_evidence_json),
      detailedGate,
    );

    assert.throws(
      () => db.updateReleaseScoreAuditClosureProofGateEvidence('v-proof', '{"schemaVersion":1}'),
      /Expected object field fixProvenance/,
    );
    assert.throws(
      () => db.updateReleaseScoreAuditClosureProofGateEvidence('v-proof', JSON.stringify({
        ...validGate,
        fixProvenance: {
          ...validGate.fixProvenance,
          releaseFixCredit: {
            ...validGate.fixProvenance.releaseFixCredit,
            countedClosedCount: 99,
          },
        },
      })),
      /releaseFixCredit counts must match closureProof counts/,
    );
    assert.throws(
      () => db.updateReleaseScoreAuditClosureProofGateEvidence('v-proof', JSON.stringify({
        ...detailedGate,
        fixProvenance: {
          ...detailedGate.fixProvenance,
          releaseFixCredit: {
            ...detailedGate.fixProvenance.releaseFixCredit,
            decisionCounts: { credited: 0, withheld: 0, invalid: 1 },
            decisions: [{
              ...withheldDecision,
              status: 'invalid',
              reasonCode: 'missing_predecessor_boundary',
              predecessorTag: null,
            }],
          },
        },
      })),
      /structurally invalid fix-credit decisions cannot be persisted/,
    );
    assert.deepEqual(JSON.parse(db.getReleaseScoreAudit('v-proof').gate_evidence_json), detailedGate);
  });

  it('can refresh closure proof rows without mutating the existing score audit payload', () => {
    const path = dbPath('closure-proof-analysis-audit-mode');
    const dir = dirname(path);
    try {
      const script = `
        import assert from 'node:assert/strict';
        import { mkdirSync } from 'node:fs';
        import { dirname, join } from 'node:path';
        import { spawnSync } from 'node:child_process';
        function git(args, cwd) {
          const result = spawnSync('git', args, { cwd, encoding: 'utf8' });
          assert.equal(result.status, 0, result.stdout + result.stderr);
          return result.stdout.trim();
        }
        (async () => {
        const testDir = dirname(process.env.DB_PATH);
        const workDir = join(testDir, 'work');
        const remoteDir = join(testDir, 'remote.git');
        mkdirSync(workDir, { recursive: true });
        git(['init'], workDir);
        git(['config', 'user.email', 'test@example.test'], workDir);
        git(['config', 'user.name', 'Test User'], workDir);
        git(['commit', '--allow-empty', '-m', 'seed'], workDir);
        const commitOid = git(['rev-parse', 'HEAD'], workDir);
        git(['init', '--bare', remoteDir], testDir);
        git(['remote', 'add', 'origin', remoteDir], workDir);
        git(['push', 'origin', 'HEAD:refs/heads/main'], workDir);
        process.env.OPENCLAW_REPO_URL = remoteDir;
        const dbModule = await import('./src/lib/db.ts');
        const analysisModule = await import('./src/lib/closureProofAnalysis.ts');
        const db = dbModule.default ?? dbModule;
        const analysis = analysisModule.default ?? analysisModule;
        db.replaceActiveReleaseCatalog([{
          node_id: 'release:v-proof-empty',
          catalog_tag_commit_oid: commitOid,
          tag: 'v-proof-empty',
          name: 'v-proof-empty',
          published_at: '2026-06-01T00:00:00Z',
          created_at: '2026-06-01T00:00:00Z',
          updated_at: '2026-06-01T00:00:00Z',
          html_url: 'https://example.test/v-proof-empty',
          prerelease: false,
          body: '',
        }]);
        db.upsertReleaseCommit({
          tag: 'v-proof-empty',
          tag_commit_oid: commitOid,
          committed_at: '2026-06-01T00:00:00Z',
        });
        db.upsertReleaseScoreAudit({
          release_tag: 'v-proof-empty',
          scored_at: '2026-06-02T00:00:00Z',
          score_model_version: 'test-model',
          prompt_version: 1,
          final_score: 7.5,
          status: 'eligible',
          band: 'ok',
          recommended: 1,
          input_json: '{"schemaVersion":1,"rawIssueCount":0,"classifiedIssueCount":0}',
          components_json: '{"schemaVersion":1,"components":{},"explanation":{"schemaVersion":1}}',
          issue_evidence_json: '{"schemaVersion":1}',
          gate_evidence_json: '{"schemaVersion":1,"fixProvenance":{"verifiedFixedCount":0,"unverifiedClosedCount":0}}',
        });
        const originalGateEvidence = db.getReleaseScoreAudit('v-proof-empty').gate_evidence_json;
        const sideTableOnly = await analysis.analyzeClosureProofsForRelease('v-proof-empty', {
          persistScoreAuditPayload: false,
        });
        assert.equal(sideTableOnly.analyzed, 0);
        assert.equal(db.closureProofRows('v-proof-empty').length, 0);
        assert.equal(db.getReleaseScoreAudit('v-proof-empty').gate_evidence_json, originalGateEvidence);
        await assert.rejects(
          () => analysis.analyzeClosureProofsForRelease('v-proof-empty', {
            persistScoreAuditPayload: true,
          }),
          /persistScoreAuditPayload=true is disabled.*rebuilding and sealing the full score run/,
        );
        assert.equal(db.getReleaseScoreAudit('v-proof-empty').gate_evidence_json, originalGateEvidence);
        db.db.close();
        })().catch((error) => {
          console.error(error);
          process.exitCode = 1;
        });
      `;
      const result = spawnTsxEvalSync(script, {
        cwd: root,
        env: { ...process.env, DB_PATH: path },
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('public release row freshness digest changes when emitted score fields change', async () => {
    const db = await freshDb('public-release-row-freshness');
    seedRelease(db, 'v1');
    const score = {
      tag: 'v1',
      final_score: 7.5,
      negative_issues: 1,
      positive_issues: 0,
      state: 'eligible',
      recommended: 1,
      score_reason: 'first reason',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 1,
      scored_at: '2026-06-02T00:00:00Z',
    };
    db.updateReleaseScore(score);
    const first = db.publicReleaseRowsFreshness(10);
    db.updateReleaseScore({
      ...score,
      score_reason: 'second reason',
    });
    const second = db.publicReleaseRowsFreshness(10);

    assert.ok(first.count >= 1);
    assert.equal(second.count, first.count);
    assert.equal(first.max_scored_at, score.scored_at);
    assert.equal(second.max_scored_at, score.scored_at);
    assert.notEqual(first.digest, second.digest);
  });

  it('public issue summary freshness digest changes when emitted issue fields change', async () => {
    const db = await freshDb('public-issue-summary-freshness');
    seedRelease(db, 'v1');
    seedIssue(db, 9101, null, '2026-06-01T12:00:00Z');

    const first = db.publicIssueSummaryFreshness(10);
    db.upsertIssue({
      number: 9101,
      state: 'open',
      title: 'issue 9101 updated title',
      author: 'tester',
      html_url: 'https://example.test/issues/9101',
      created_at: '2026-06-01T12:00:00Z',
      updated_at: '2026-06-01T12:00:00Z',
      closed_at: null,
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    const second = db.publicIssueSummaryFreshness(10);

    assert.ok(first.count >= 2);
    assert.equal(second.count, first.count);
    assert.equal(second.max_ts, first.max_ts);
    assert.notEqual(first.digest, second.digest);
  });

  it('validates comparison snapshots before writing rows', async () => {
    const db = await freshDb('comparison-snapshot-validation');
    const validSnapshot = {
      source_url: 'https://example.test/source',
      captured_at: '2026-06-02T00:00:00Z',
      page_title: 'Comparison source',
      page_text: 'page text',
      raw_html: '<html></html>',
      releases: [{
        tag: 'v1',
        name: 'v1',
        published_at: '2026-06-01T00:00:00Z',
        html_url: 'https://example.test/releases/v1',
        displayed_date: 'Jun 1',
        score: 7.5,
        band: 'ok',
        status: 'eligible',
        recommended: true,
        reason: 'source reason',
        negative_issues: 1,
        positive_issues: 0,
        total_attributed_issues: 3,
        visible_issues: [{ number: 1, title: 'issue' }],
        raw_card_text: 'card',
      }],
    };

    const id = db.saveComparisonSnapshot(validSnapshot);
    assert.equal(typeof id, 'number');
    assert.equal(db.latestComparisonSnapshot()?.source_url, 'https://example.test/source');
    assert.deepEqual(db.comparisonReleases(id).map((row: any) => row.tag), ['v1']);

    assert.throws(
      () => db.saveComparisonSnapshot({
        ...validSnapshot,
        releases: [
          ...validSnapshot.releases,
          { ...validSnapshot.releases[0], tag: 'v2', html_url: 'https://example.test/releases/v2', score: Number.NaN },
        ],
      }),
      /comparison release v2 score must be null or finite number/,
    );
    assert.equal(db.latestComparisonSnapshot()?.id, id);
    assert.deepEqual(db.comparisonReleases().map((row: any) => row.tag), ['v1']);

    assert.throws(
      () => db.saveComparisonSnapshot({
        ...validSnapshot,
        releases: [
          validSnapshot.releases[0],
          { ...validSnapshot.releases[0] },
        ],
      }),
      /appears more than once/,
    );
    assert.equal(db.latestComparisonSnapshot()?.id, id);
  });

  it('stores release check rollup evidence with the release commit', async () => {
    const db = await freshDb('release-checks');
    seedRelease(db, 'v1');

    db.upsertReleaseCommit({
      tag: 'v1',
      tag_commit_oid: 'commit-1',
      committed_at: '2026-06-01T00:00:00Z',
      check_state: 'SUCCESS',
      check_total: 4,
      check_success: 3,
      check_failure: 0,
      check_pending: 0,
      check_skipped: 1,
      check_contexts_json: '[{"name":"build","conclusion":"SUCCESS"}]',
    });

    const row = db.getReleaseCommit('v1') as any;
    assert.equal(row.check_state, 'SUCCESS');
    assert.equal(row.check_total, 4);
    assert.equal(row.check_success, 3);
    assert.equal(row.check_skipped, 1);
    assert.equal(row.check_contexts_json, '[{"name":"build","conclusion":"SUCCESS"}]');
  });

  it('stores release artifact metadata and registry verification', async () => {
    const db = await freshDb('release-artifacts');
    seedRelease(db, 'v1');

    db.updateReleaseDerivedStats({
      tag: 'v1',
      breaking_count: 0,
      fixes_count: 0,
      changes_count: 0,
      highlights_count: 0,
      pr_refs_count: 0,
      beta_count: 0,
      hours_to_next_release: null,
      hours_to_next_stable: null,
      npm_package_url: 'https://www.npmjs.com/package/openclaw/v/1.0.0',
      release_tarball_url: 'https://registry.npmjs.org/openclaw/-/openclaw-1.0.0.tgz',
      release_integrity: 'sha512-test',
      release_sha: 'commit-1',
      full_release_ci_report_url: 'https://example.test/report.md',
      full_release_validation_url: 'https://github.com/openclaw/openclaw/actions/runs/1',
    });
    db.updateReleaseArtifactVerification({
      tag: 'v1',
      registry_version: '1.0.0',
      registry_integrity: 'sha512-test',
      registry_tarball_url: 'https://registry.npmjs.org/openclaw/-/openclaw-1.0.0.tgz',
      ci_report_verified: 1,
      ci_report_mismatch: null,
      release_validation_verified: 1,
      release_validation_mismatch: null,
      artifact_verified: 1,
      artifact_mismatch: null,
    });

    const row = db.getRelease('v1') as any;
    assert.equal(row.release_integrity, 'sha512-test');
    assert.equal(row.release_sha, 'commit-1');
    assert.equal(row.registry_version, '1.0.0');
    assert.equal(row.registry_integrity, 'sha512-test');
    assert.equal(row.ci_report_verified, 1);
    assert.equal(row.full_release_validation_url, 'https://github.com/openclaw/openclaw/actions/runs/1');
    assert.equal(row.release_validation_verified, 1);
    assert.equal(row.artifact_verified, 1);
  });

  it('reconstructs issue labels at a cutoff from label timeline events', async () => {
    const db = await freshDb('label-events');
    seedRelease(db, 'v1');
    seedIssue(db, 7101, null);

    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-1',
      action: 'labeled',
      label_name: 'bug',
      actor_login: 'reporter',
      created_at: '2026-06-01T13:00:00Z',
    });
    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-2',
      action: 'labeled',
      label_name: 'P1',
      actor_login: 'maintainer',
      created_at: '2026-06-02T00:00:00Z',
    });
    db.upsertIssueLabelEvent({
      issue_number: 7101,
      event_id: 'label-3',
      action: 'unlabeled',
      label_name: 'P1',
      actor_login: 'maintainer',
      created_at: '2026-06-03T00:00:00Z',
    });

    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-01T14:00:00Z'), ['bug']);
    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-02T12:00:00Z').sort(), ['P1', 'bug']);
    assert.deepEqual(db.labelsForIssueAt(7101, ['fallback'], '2026-06-04T00:00:00Z'), ['bug']);
    assert.deepEqual({ ...db.latestIssueLabelEventAt(7101, 'P1', '2026-06-02T12:00:00Z') }, {
      event_id: 'label-2',
      action: 'labeled',
      label_name: 'P1',
      actor_login: 'maintainer',
      actor_type: null,
      created_at: '2026-06-02T00:00:00Z',
    });
    assert.equal(
      db.latestIssueLabelEventAt(7101, 'P1', '2026-06-04T00:00:00Z')?.action,
      'unlabeled',
    );
    assert.deepEqual(db.labelsForIssueAt(9999, ['fallback'], '2026-06-04T00:00:00Z'), ['fallback']);
    assert.deepEqual(
      db.labelsForIssueAt(9999, ['fallback'], '2026-06-04T00:00:00Z', { useFallbackWhenNoEvents: false }),
      [],
    );
  });

  it('uses label snapshots at cutoff when timeline events are absent', async () => {
    const db = await freshDb('label-snapshot-cutoff');
    db.upsertIssueLabelSnapshot({
      issue_number: 7201,
      snapshot_at: '2026-06-02T00:00:00Z',
      labels_json: JSON.stringify(['bug', 'P1']),
    });
    db.upsertIssueLabelSnapshot({
      issue_number: 7201,
      snapshot_at: '2026-06-03T00:00:00Z',
      labels_json: JSON.stringify(['bug']),
    });

    assert.deepEqual(
      db.labelsForIssueAt(7201, ['fallback'], '2026-06-02T12:00:00Z', {
        useFallbackWhenNoEvents: false,
        useSnapshotWhenNoEvents: true,
      }).sort(),
      ['P1', 'bug'],
    );
    assert.deepEqual(
      db.labelsForIssueAt(7201, ['fallback'], '2026-06-03T12:00:00Z', {
        useFallbackWhenNoEvents: false,
        useSnapshotWhenNoEvents: true,
      }),
      ['bug'],
    );
  });

  it('counts only completed issues with fixed-in-release proof rows', async () => {
    const db = await freshDb('verified-fixed');
    seedRelease(db, 'v1');

    for (const n of [1, 2, 3, 4]) seedIssue(db, n);
    for (const n of [1, 2, 3]) seedClosure(db, n);
    seedClosure(db, 4, 'NOT_PLANNED');
    seedPr(db, 101, true);
    seedPr(db, 102, true);
    seedPr(db, 103, false);

    for (const [issue, pr, status] of [
      [1, 101, 'reachable'],
      [2, 102, 'not_reachable'],
      [3, 103, 'reachable'],
      [4, 101, 'reachable'],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'closedByPullRequestsReferences',
        will_close_target: 1,
        referenced_at: '2026-06-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v1',
        pr_number: pr,
        tag_commit_oid: testReleaseCommitOid('v1'),
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status,
        evidence_json: '{}',
      });
    }
    seedClosureProof(db, 'v1', 1);

    assert.deepEqual(db.verifiedFixedForRelease('v1').map((row: any) => row.number), [1]);
  });

  it('does not credit the oldest monitored release when its predecessor boundary already contains the fix', async () => {
    const db = await freshDb('first-containing-predecessor-reachable');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9751,
      prNumber: 9851,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'reachable'],
        ['v-oldest-monitored', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });

    const decision = db.releaseFixCreditDecision(
      9751,
      'v-oldest-monitored',
      'v-boundary',
    );
    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'predecessor_reachable');
    assert.equal(decision.targetTag, 'v-oldest-monitored');
    assert.equal(decision.predecessorTag, 'v-boundary');
    assert.equal(decision.proofIdentities[0]?.kind, 'trusted_pull_request');
    assert.equal(
      decision.proofIdentities[0]?.kind === 'trusted_pull_request'
        ? decision.proofIdentities[0].predecessor?.strictValid
        : null,
      true,
    );
  });

  it('credits the oldest monitored release when its predecessor boundary proves the fix absent', async () => {
    const db = await freshDb('first-containing-predecessor-not-reachable');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9752,
      prNumber: 9852,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-oldest-monitored', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });

    const decision = db.releaseFixCreditDecision(
      9752,
      'v-oldest-monitored',
      'v-boundary',
    );
    assert.equal(decision.status, 'credited');
    assert.equal(decision.reasonCode, 'first_containing_trusted_pr');
    assert.equal(
      decision.proofIdentities[0]?.kind === 'trusted_pull_request'
        ? decision.proofIdentities[0].predecessor?.status
        : null,
      'not_reachable',
    );
    assert.equal(
      db.verifiedFixIntroducedInRelease(9752, 'v-oldest-monitored', 'v-boundary'),
      true,
    );
  });

  it('does not credit the oldest monitored release when its predecessor boundary row is missing', async () => {
    const db = await freshDb('first-containing-predecessor-missing');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9753,
      prNumber: 9853,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', null],
        ['v-oldest-monitored', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });

    const decision = db.releaseFixCreditDecision(
      9753,
      'v-oldest-monitored',
      'v-boundary',
    );
    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'predecessor_reachability_missing');
  });

  it('credits a normal first-containing release inside the monitored window', async () => {
    const db = await freshDb('first-containing-normal');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9754,
      prNumber: 9854,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-oldest-monitored', '2026-06-02T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-03T00:00:00Z', 'reachable'],
      ],
    });

    const decision = db.releaseFixCreditDecision(9754, 'v-target', 'v-oldest-monitored');
    assert.equal(decision.status, 'credited');
    assert.equal(decision.reasonCode, 'first_containing_trusted_pr');
  });

  it('withholds credit when predecessor evidence contradicts its stored status', async () => {
    const db = await freshDb('first-containing-contradictory-evidence');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9755,
      prNumber: 9855,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-oldest-monitored', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const predecessor = db.db.prepare(`
      SELECT tag_commit_oid, merge_commit_oid
      FROM release_pr_reachability
      WHERE tag='v-boundary' AND pr_number=9855
    `).get() as { tag_commit_oid: string; merge_commit_oid: string };
    db.db.prepare(`
      UPDATE release_pr_reachability
      SET evidence_json=?
      WHERE tag='v-boundary' AND pr_number=9855
    `).run(JSON.stringify(strictPrReachabilityEvidence(
      'reachable',
      predecessor.tag_commit_oid,
      predecessor.merge_commit_oid,
      testReleaseCatalogProof(db, 'v-boundary'),
    )));

    const decision = db.releaseFixCreditDecision(
      9755,
      'v-oldest-monitored',
      'v-boundary',
    );
    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'predecessor_reachability_invalid');
    assert.equal(
      decision.proofIdentities[0]?.kind === 'trusted_pull_request'
        ? decision.proofIdentities[0].predecessor?.validationReasonCode
        : null,
      'status_reason_mismatch',
    );
  });

  it('rejects reachability rows bound to different PR or release commits', async () => {
    const db = await freshDb('first-containing-identity-mismatch');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9758,
      prNumber: 9859,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const targetTagCommitOid = '2'.repeat(40);
    const storedMergeCommitOid = 'f'.repeat(40);
    const mismatchedMergeCommitOid = 'b'.repeat(40);
    db.upsertReleasePrReachability({
      tag: 'v-target',
      pr_number: 9859,
      tag_commit_oid: targetTagCommitOid,
      merge_commit_oid: mismatchedMergeCommitOid,
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'reachable',
        targetTagCommitOid,
        mismatchedMergeCommitOid,
        testReleaseCatalogProof(db, 'v-target'),
      )),
    });

    let decision = db.releaseFixCreditDecision(9758, 'v-target', 'v-boundary');
    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'target_reachability_invalid');
    assert.equal(
      decision.proofIdentities[0]?.kind === 'trusted_pull_request'
        ? decision.proofIdentities[0].target?.validationReasonCode
        : null,
      'checked_commit_oid_mismatch',
    );

    db.upsertReleasePrReachability({
      tag: 'v-target',
      pr_number: 9859,
      tag_commit_oid: targetTagCommitOid,
      merge_commit_oid: storedMergeCommitOid,
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: JSON.stringify(strictPrReachabilityEvidence(
        'reachable',
        targetTagCommitOid,
        storedMergeCommitOid,
        testReleaseCatalogProof(db, 'v-target'),
      )),
    });
    db.db.prepare(`
      UPDATE release_commits
      SET tag_commit_oid=?
      WHERE tag='v-target'
    `).run('c'.repeat(40));

    assert.throws(
      () => db.releaseFixCreditDecision(9758, 'v-target', 'v-boundary'),
      /Authorized release reachability catalog member "v-target" has incomplete or mismatched immutable identity/,
    );
  });

  it('uses only trusted PR identities persisted by the final closure proof', async () => {
    const db = await freshDb('first-containing-final-proof-identities');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9756,
      prNumber: 9856,
      releases: [
        ['v-oldest', '2026-05-30T00:00:00Z', 'not_reachable'],
        ['v-middle', '2026-05-31T00:00:00Z', 'not_reachable'],
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    seedPr(db, 9857, true);
    db.upsertIssuePrLink({
      issue_number: 9756,
      pr_number: 9857,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-06-02T12:00:00Z',
    });
    seedClosureProof(db, 'v-target', 9756, 'fixed_in_release', {
      linkedPrs: [trustedProofPr(9857)],
    });

    const decision = db.releaseFixCreditDecision(9756, 'v-target', 'v-boundary');

    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'target_reachability_missing');
    assert.deepEqual(
      decision.proofIdentities
        .filter((proof: any) => proof.kind === 'trusted_pull_request')
        .map((proof: any) => proof.prNumber),
      [9857],
    );
  });

  it('does not let a stale pre-reopen PR grant credit to direct-commit-only proof', async () => {
    const db = await freshDb('first-containing-stale-pr-direct-commit');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9757,
      prNumber: 9858,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const directCommit = 'a'.repeat(40);
    seedClosureProof(db, 'v-target', 9757, 'fixed_in_release', {
      linkedPrs: [trustedProofPr(9858, { trustedFixProof: 0 })],
      hasReachableFixCommit: true,
      reachableFixCommits: [directCommit],
      fixCommitProof: [{ commitOid: directCommit, creditEligible: true }],
    });

    const decision = db.releaseFixCreditDecision(9757, 'v-target', 'v-boundary');

    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'direct_commit_first_containing_proof_missing');
    assert.deepEqual(decision.proofIdentities, []);
  });

  it('credits a direct commit only with complete first-containing proof', async () => {
    const db = await freshDb('first-containing-direct-commit');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9791,
      prNumber: 9891,
      releases: [
        ['v-oldest', '2026-05-30T00:00:00Z', 'not_reachable'],
        ['v-middle', '2026-05-31T00:00:00Z', 'not_reachable'],
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const directCommit = 'a'.repeat(40);
    const proof = strictDirectFirstContainingProof(db, { commitOid: directCommit });
    seedClosureProof(db, 'v-target', 9791, 'fixed_in_release', {
      linkedPrs: [trustedProofPr(9891, { trustedFixProof: 0 })],
      ...directCommitClosureEvidence(proof),
    });

    const decision = db.releaseFixCreditDecision(9791, 'v-target', 'v-boundary');

    assert.equal(decision.status, 'credited');
    assert.equal(decision.reasonCode, 'first_containing_direct_commit');
    assert.equal(decision.proofIdentities.length, 1);
    const identity = decision.proofIdentities[0];
    assert.equal(identity?.kind, 'direct_commit');
    assert.equal(identity?.kind === 'direct_commit' && identity.strictValid, true);
    assert.equal(identity?.kind === 'direct_commit' && identity.target?.status, 'reachable');
    assert.equal(identity?.kind === 'direct_commit' && identity.predecessor?.status, 'not_reachable');
    assert.deepEqual(
      identity?.kind === 'direct_commit'
        ? identity.olderReleases.map((release) => [release.tag, release.status])
        : [],
      [
        ['v-oldest', 'not_reachable'],
        ['v-middle', 'not_reachable'],
        ['v-boundary', 'not_reachable'],
      ],
    );
    assert.equal(identity?.kind === 'direct_commit' && identity.releaseAncestry?.status, 'reachable');
  });

  it('withholds a direct commit already contained by the predecessor release', async () => {
    const db = await freshDb('first-containing-direct-predecessor-contained');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9792,
      prNumber: 9892,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const proof = strictDirectFirstContainingProof(db, {
      commitOid: 'b'.repeat(40),
      predecessorContainsCommit: true,
    });
    seedClosureProof(db, 'v-target', 9792, 'fixed_in_release',
      directCommitClosureEvidence(proof));

    const decision = db.releaseFixCreditDecision(9792, 'v-target', 'v-boundary');

    assert.equal(decision.status, 'withheld');
    assert.equal(decision.reasonCode, 'direct_commit_not_first_containing');
    assert.equal(
      decision.proofIdentities[0]?.kind === 'direct_commit'
        ? decision.proofIdentities[0].strictValid
        : false,
      true,
    );
  });

  it('rejects malformed, repository-mismatched, and commit-mismatched direct proof evidence', async () => {
    const cases = [
      {
        name: 'malformed-evidence',
        mutate(proof: any) {
          delete proof.target.evidence.commandStatus;
        },
        expectedValidation: 'reachability_evidence_invalid',
      },
      {
        name: 'repository-mismatch',
        mutate(proof: any) {
          proof.repositoryNameWithOwner = 'fork/openclaw';
        },
        expectedValidation: 'repository_identity_mismatch',
      },
      {
        name: 'commit-mismatch',
        mutate(proof: any) {
          const mismatchedCommit = 'c'.repeat(40);
          proof.target.checkedCommitOid = mismatchedCommit;
          proof.target.evidence.checkedCommitOid = mismatchedCommit;
        },
        expectedValidation: 'reachability_evidence_invalid',
      },
      {
        name: 'older-proof-omitted',
        mutate(proof: any) {
          proof.olderReleases = [];
        },
        expectedValidation: 'older_release_proof_set_mismatch',
      },
      {
        name: 'older-node-mismatch',
        mutate(proof: any) {
          proof.olderReleases[0].releaseNodeId = 'forged-release-node';
        },
        expectedValidation: 'reachability_evidence_invalid',
      },
      {
        name: 'catalog-receipt-mismatch',
        mutate(proof: any) {
          proof.catalogIdentity.catalogReceiptId = 'e'.repeat(64);
        },
        expectedValidation: 'catalog_identity_mismatch',
      },
    ] as const;

    for (const [index, testCase] of cases.entries()) {
      const db = await freshDb(`first-containing-direct-${testCase.name}`);
      seedFirstContainingFixMatrix(db, {
        issueNumber: 9793 + index,
        prNumber: 9893 + index,
        releases: [
          ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
          ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
        ],
      });
      const proof: any = strictDirectFirstContainingProof(db, {
        commitOid: `${index + 4}`.repeat(40),
      });
      testCase.mutate(proof);
      seedClosureProof(
        db,
        'v-target',
        9793 + index,
        'fixed_in_release',
        directCommitClosureEvidence(proof),
      );

      const decision = db.releaseFixCreditDecision(
        9793 + index,
        'v-target',
        'v-boundary',
      );
      assert.equal(decision.status, 'withheld', testCase.name);
      assert.equal(
        decision.reasonCode,
        'direct_commit_first_containing_proof_invalid',
        testCase.name,
      );
      assert.equal(
        decision.proofIdentities[0]?.kind === 'direct_commit'
          ? decision.proofIdentities[0].validationReasonCode
          : null,
        testCase.expectedValidation,
        testCase.name,
      );
    }
  });

  it('keeps mixed trusted-PR and direct-commit siblings auditable and credits only valid proof', async () => {
    const db = await freshDb('first-containing-mixed-pr-direct');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9796,
      prNumber: 9896,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });
    const proof = strictDirectFirstContainingProof(db, { commitOid: '9'.repeat(40) });
    seedClosureProof(db, 'v-target', 9796, 'fixed_in_release', {
      linkedPrs: [trustedProofPr(9896)],
      ...directCommitClosureEvidence(proof),
    });

    const decision = db.releaseFixCreditDecision(9796, 'v-target', 'v-boundary');

    assert.equal(decision.status, 'credited');
    assert.equal(decision.reasonCode, 'first_containing_direct_commit');
    assert.deepEqual(
      decision.proofIdentities.map((identity: any) => identity.kind),
      ['trusted_pull_request', 'direct_commit'],
    );
  });

  it('withholds credit when any merged sibling lacks complete target evidence', async () => {
    const db = await freshDb('first-containing-incomplete-target-sibling');
    const targetTagCommitOid = '2'.repeat(40);
    const predecessorTagCommitOid = '1'.repeat(40);
    const cases = [
      { name: 'metadata', expected: 'target_trusted_pr_missing' },
      { name: 'missing', expected: 'target_reachability_missing' },
      { name: 'unknown', expected: 'target_reachability_unknown' },
      { name: 'invalid', expected: 'target_reachability_invalid' },
      { name: 'not_reachable', expected: 'target_reachability_not_reachable' },
    ] as const;

    for (const [index, testCase] of cases.entries()) {
      const issueNumber = 9760 + index;
      const primaryPr = 9860 + index * 2;
      const siblingPr = primaryPr + 1;
      const siblingMergeCommitOid = `${index + 3}`.repeat(40);
      seedFirstContainingFixMatrix(db, {
        issueNumber,
        prNumber: primaryPr,
        releases: [
          ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
          ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
        ],
      });
      if (testCase.name !== 'metadata') {
        db.upsertIssuePrLink({
          issue_number: issueNumber,
          pr_number: siblingPr,
          source: 'ClosureComment.fixProof',
          will_close_target: null,
          referenced_at: '2026-06-02T00:00:00Z',
        });
        db.upsertPullRequestFix({
          pr_number: siblingPr,
          title: `sibling ${testCase.name}`,
          url: `https://example.test/pull/${siblingPr}`,
          state: 'MERGED',
          merged: 1,
          merged_at: '2026-06-01T12:00:00Z',
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
        });
      }
      db.upsertReleasePrReachability({
        tag: 'v-boundary',
        pr_number: siblingPr,
        tag_commit_oid: predecessorTagCommitOid,
        merge_commit_oid: siblingMergeCommitOid,
        base_ref_name: 'main',
        status: 'not_reachable',
        evidence_json: JSON.stringify(strictPrReachabilityEvidence(
          'not_reachable',
          predecessorTagCommitOid,
          siblingMergeCommitOid,
          testReleaseCatalogProof(db, 'v-boundary'),
        )),
      });
      if (testCase.name === 'unknown') {
        db.upsertReleasePrReachability({
          tag: 'v-target',
          pr_number: siblingPr,
          tag_commit_oid: targetTagCommitOid,
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
          status: 'unknown',
          evidence_json: JSON.stringify(strictUnknownPrReachabilityErrorEvidence(
            targetTagCommitOid,
            siblingMergeCommitOid,
            testReleaseCatalogProof(db, 'v-target'),
          )),
        });
      } else if (testCase.name === 'not_reachable') {
        db.upsertReleasePrReachability({
          tag: 'v-target',
          pr_number: siblingPr,
          tag_commit_oid: targetTagCommitOid,
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
          status: 'not_reachable',
          evidence_json: JSON.stringify(strictPrReachabilityEvidence(
            'not_reachable',
            targetTagCommitOid,
            siblingMergeCommitOid,
            testReleaseCatalogProof(db, 'v-target'),
          )),
        });
      } else if (testCase.name === 'invalid') {
        db.upsertReleasePrReachability({
          tag: 'v-target',
          pr_number: siblingPr,
          tag_commit_oid: targetTagCommitOid,
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
          status: 'reachable',
          evidence_json: JSON.stringify(strictPrReachabilityEvidence(
            'not_reachable',
            targetTagCommitOid,
            siblingMergeCommitOid,
            testReleaseCatalogProof(db, 'v-target'),
          )),
        });
      }
      seedClosureProof(db, 'v-target', issueNumber, 'fixed_in_release', {
        linkedPrs: [trustedProofPr(primaryPr), trustedProofPr(siblingPr)],
      });

      const decision = db.releaseFixCreditDecision(issueNumber, 'v-target', 'v-boundary');
      assert.equal(decision.status, 'withheld', testCase.name);
      assert.equal(decision.reasonCode, testCase.expected, testCase.name);
    }
  });

  it('withholds credit when any merged sibling lacks complete predecessor evidence', async () => {
    const db = await freshDb('first-containing-incomplete-predecessor-sibling');
    const targetTagCommitOid = '2'.repeat(40);
    const predecessorTagCommitOid = '1'.repeat(40);
    const cases = [
      { name: 'missing', expected: 'predecessor_reachability_missing' },
      { name: 'unknown', expected: 'predecessor_reachability_unknown' },
      { name: 'invalid', expected: 'predecessor_reachability_invalid' },
    ] as const;

    for (const [index, testCase] of cases.entries()) {
      const issueNumber = 9770 + index;
      const primaryPr = 9870 + index * 2;
      const siblingPr = primaryPr + 1;
      const siblingMergeCommitOid = `${index + 6}`.repeat(40);
      seedFirstContainingFixMatrix(db, {
        issueNumber,
        prNumber: primaryPr,
        releases: [
          ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
          ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
        ],
      });
      db.upsertIssuePrLink({
        issue_number: issueNumber,
        pr_number: siblingPr,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-06-02T00:00:00Z',
      });
      db.upsertPullRequestFix({
        pr_number: siblingPr,
        title: `sibling ${testCase.name}`,
        url: `https://example.test/pull/${siblingPr}`,
        state: 'MERGED',
        merged: 1,
        merged_at: '2026-06-01T12:00:00Z',
        merge_commit_oid: siblingMergeCommitOid,
        base_ref_name: 'main',
      });
      db.upsertReleasePrReachability({
        tag: 'v-target',
        pr_number: siblingPr,
        tag_commit_oid: targetTagCommitOid,
        merge_commit_oid: siblingMergeCommitOid,
        base_ref_name: 'main',
        status: 'not_reachable',
        evidence_json: JSON.stringify(strictPrReachabilityEvidence(
          'not_reachable',
          targetTagCommitOid,
          siblingMergeCommitOid,
          testReleaseCatalogProof(db, 'v-target'),
        )),
      });
      if (testCase.name === 'unknown') {
        db.upsertReleasePrReachability({
          tag: 'v-boundary',
          pr_number: siblingPr,
          tag_commit_oid: predecessorTagCommitOid,
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
          status: 'unknown',
          evidence_json: JSON.stringify(strictUnknownPrReachabilityErrorEvidence(
            predecessorTagCommitOid,
            siblingMergeCommitOid,
            testReleaseCatalogProof(db, 'v-boundary'),
          )),
        });
      } else if (testCase.name === 'invalid') {
        db.upsertReleasePrReachability({
          tag: 'v-boundary',
          pr_number: siblingPr,
          tag_commit_oid: predecessorTagCommitOid,
          merge_commit_oid: siblingMergeCommitOid,
          base_ref_name: 'main',
          status: 'not_reachable',
          evidence_json: JSON.stringify(strictPrReachabilityEvidence(
            'reachable',
            predecessorTagCommitOid,
            siblingMergeCommitOid,
            testReleaseCatalogProof(db, 'v-boundary'),
          )),
        });
      }
      seedClosureProof(db, 'v-target', issueNumber, 'fixed_in_release', {
        linkedPrs: [trustedProofPr(primaryPr), trustedProofPr(siblingPr)],
      });

      const decision = db.releaseFixCreditDecision(issueNumber, 'v-target', 'v-boundary');
      assert.equal(decision.status, 'withheld', testCase.name);
      assert.equal(decision.reasonCode, testCase.expected, testCase.name);
    }
  });

  it('rejects non-finite publication timestamps at the credit boundary', async () => {
    const db = await freshDb('first-containing-invalid-publication-time');
    seedFirstContainingFixMatrix(db, {
      issueNumber: 9780,
      prNumber: 9880,
      releases: [
        ['v-boundary', '2026-06-01T00:00:00Z', 'not_reachable'],
        ['v-target', '2026-06-02T00:00:00Z', 'reachable'],
      ],
    });

    db.db.prepare(`UPDATE releases SET published_at='not-a-timestamp' WHERE tag='v-target'`).run();
    assert.throws(
      () => db.releaseFixCreditDecision(9780, 'v-target', 'v-boundary'),
      /Active release catalog v-target has invalid published_at not-a-timestamp/,
    );

    db.db.prepare(`
      UPDATE releases
      SET published_at=CASE tag
        WHEN 'v-target' THEN '2026-06-02T00:00:00Z'
        ELSE 'not-a-timestamp'
      END
      WHERE tag IN ('v-target', 'v-boundary')
    `).run();
    assert.throws(
      () => db.releaseFixCreditDecision(9780, 'v-target', 'v-boundary'),
      /Active release catalog v-boundary has invalid published_at not-a-timestamp/,
    );
  });

  it('keeps reachable merged PR links without closure proof unverified', async () => {
    const db = await freshDb('verified-requires-proof');
    seedRelease(db, 'v-proof-required', '2031-06-01T00:00:00Z');
    seedIssue(db, 6, '2031-06-02T00:00:00Z', '2031-06-01T12:00:00Z');
    seedClosure(db, 6, 'COMPLETED', '2031-06-02T00:00:00Z');
    seedPr(db, 206, true);
    db.upsertIssuePrLink({
      issue_number: 6,
      pr_number: 206,
      source: 'closedByPullRequestsReferences',
      will_close_target: 1,
      referenced_at: '2031-06-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-proof-required',
      pr_number: 206,
      tag_commit_oid: testReleaseCommitOid('v-proof-required'),
      merge_commit_oid: 'merge-206',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-proof-required').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-proof-required').map((row: any) => row.number), [6]);
  });

  it('credits completed closures with reachable commit proof rows', async () => {
    const db = await freshDb('verified-commit-proof');
    seedRelease(db, 'v-commit', '2027-01-01T00:00:00Z');
    seedIssue(db, 5, '2027-01-02T00:00:00Z', '2027-01-01T12:00:00Z');
    seedClosure(db, 5, 'COMPLETED', '2027-01-02T00:00:00Z');
    db.upsertIssueClosureProof({
      release_tag: 'v-commit',
      issue_number: 5,
      status: 'fixed_in_release',
      summary: 'Closed by a fix/source commit reachable from this release tag.',
      evidence_json: JSON.stringify({
        stateReasons: ['COMPLETED'],
        hasReachableFixCommit: true,
        reachableFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
      }),
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-commit').map((row: any) => row.number), [5]);
    assert.deepEqual(db.unverifiedClosedForRelease('v-commit').map((row: any) => row.number), []);
  });

  it('does not carry reachable fix credit across release windows', async () => {
    const db = await freshDb('verified-window');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-new',
        '2026-06-10T00:00:00Z',
        false,
        testReleaseCommitOid('v-new'),
      ),
      catalogRelease(
        'v-old',
        '2026-06-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-old'),
      ),
    ]);
    seedIssue(db, 41, '2026-06-11T00:00:00Z', '2026-06-10T12:00:00Z');
    seedClosure(db, 41, 'COMPLETED', '2026-06-11T00:00:00Z');
    seedPr(db, 241, true);
    db.upsertIssuePrLink({
      issue_number: 41,
      pr_number: 241,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-06-11T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-old',
      pr_number: 241,
      tag_commit_oid: testReleaseCommitOid('v-old'),
      merge_commit_oid: 'merge-241',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });
    db.upsertReleasePrReachability({
      tag: 'v-new',
      pr_number: 241,
      tag_commit_oid: testReleaseCommitOid('v-new'),
      merge_commit_oid: 'merge-241',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });
    seedClosureProof(db, 'v-new', 41);

    assert.deepEqual(db.verifiedFixedForRelease('v-old').map((row: any) => row.number), []);
    assert.deepEqual(db.verifiedFixedForRelease('v-new').map((row: any) => row.number), [41]);
  });

  it('does not count neutral completed closures as stability fix credit', async () => {
    const db = await freshDb('neutral-fix-credit');
    seedRelease(db, 'v-neutral', '2026-10-01T00:00:00Z');
    seedIssue(db, 51, '2026-10-02T00:00:00Z', '2026-10-01T12:00:00Z');
    db.upsertClassification(51, classification({ sentiment: 'neutral', severity: 'low' }), '2026-10-02T00:00:00Z', 1);
    seedClosure(db, 51, 'COMPLETED', '2026-10-02T00:00:00Z');
    seedPr(db, 251, true);
    db.upsertIssuePrLink({
      issue_number: 51,
      pr_number: 251,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-10-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-neutral',
      pr_number: 251,
      tag_commit_oid: testReleaseCommitOid('v-neutral'),
      merge_commit_oid: 'merge-251',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-neutral').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-neutral').map((row: any) => row.number), [51]);
  });

  it('credits closure-comment fix proof only when merged and reachable', async () => {
    const db = await freshDb('comment-mentioned-pr');
    seedRelease(db, 'v-comment');

    for (const n of [11, 12, 13, 14]) seedIssue(db, n);
    for (const n of [11, 12, 13]) seedClosure(db, n);
    seedClosure(db, 14, 'NOT_PLANNED');
    seedPr(db, 211, true);
    seedPr(db, 212, true);
    seedPr(db, 213, false);
    seedPr(db, 214, true);

    for (const [issue, pr, status] of [
      [11, 211, 'reachable'],
      [12, 212, 'not_reachable'],
      [13, 213, 'reachable'],
      [14, 214, 'reachable'],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'ClosureComment.fixProof',
        will_close_target: null,
        referenced_at: '2026-06-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v-comment',
        pr_number: pr,
        tag_commit_oid: testReleaseCommitOid('v-comment'),
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status,
        evidence_json: '{}',
      });
    }
    seedClosureProof(db, 'v-comment', 11);

    assert.deepEqual(db.verifiedFixedForRelease('v-comment').map((row: any) => row.number), [11]);
  });

  it('does not credit broad closure-comment PR mentions as fix proof', async () => {
    const db = await freshDb('comment-pr-reference');
    seedRelease(db, 'v-reference', '2026-08-01T00:00:00Z');
    seedIssue(db, 21, '2026-08-02T00:00:00Z', '2026-08-01T12:00:00Z');
    seedClosure(db, 21, 'COMPLETED', '2026-08-02T00:00:00Z');
    seedPr(db, 221, true);
    db.upsertIssuePrLink({
      issue_number: 21,
      pr_number: 221,
      source: 'ClosureComment.prMention',
      will_close_target: null,
      referenced_at: '2026-06-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-reference',
      pr_number: 221,
      tag_commit_oid: testReleaseCommitOid('v-reference'),
      merge_commit_oid: 'merge-221',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-reference').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-reference').map((row: any) => row.number), [21]);
  });

  it('deletes stale closure-comment PR links without removing GitHub closure links', async () => {
    const db = await freshDb('stale-comment-pr-links');
    seedRelease(db, 'v-stale-comment-link');
    seedIssue(db, 61);

    for (const [source, pr] of [
      ['closedByPullRequestsReferences', 261],
      ['ClosureComment.fixProof', 262],
      ['ClosureComment.prMention', 263],
    ] as const) {
      db.upsertIssuePrLink({
        issue_number: 61,
        pr_number: pr,
        source,
        will_close_target: source === 'closedByPullRequestsReferences' ? 1 : null,
        referenced_at: '2026-06-02T00:00:00Z',
      });
    }

    db.deleteCommentIssuePrLinksForIssues([61]);

    const remaining = db.db.prepare(`
      SELECT source
      FROM issue_pr_links
      WHERE issue_number=61
      ORDER BY source
    `).all().map((row: any) => row.source);
    assert.deepEqual(remaining, ['closedByPullRequestsReferences']);
  });

  it('uses the final closure event for fix credit', async () => {
    const db = await freshDb('final-closure');
    seedRelease(db, 'v-final', '2026-09-01T00:00:00Z');
    seedIssue(db, 31, '2026-09-03T00:00:00Z', '2026-09-01T12:00:00Z');
    seedPr(db, 231, true);
    db.upsertIssueClosureEvent({
      issue_number: 31,
      event_id: 'closed-31-first',
      closed_at: '2026-09-02T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssueClosureEvent({
      issue_number: 31,
      event_id: 'closed-31-final',
      closed_at: '2026-09-03T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'NOT_PLANNED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssuePrLink({
      issue_number: 31,
      pr_number: 231,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2026-09-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-final',
      pr_number: 231,
      tag_commit_oid: testReleaseCommitOid('v-final'),
      merge_commit_oid: 'merge-231',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.verifiedFixedForRelease('v-final').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-final').map((row: any) => row.number), [31]);
  });

  it('does not carry fix credit from an earlier close after reopen/reclose', async () => {
    const db = await freshDb('final-close-after-reopen');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-window-new',
        '2028-09-10T00:00:00Z',
        false,
        testReleaseCommitOid('v-window-new'),
      ),
      catalogRelease(
        'v-window-old',
        '2028-09-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-window-old'),
      ),
    ]);
    seedIssue(db, 32, '2028-09-12T00:00:00Z', '2028-09-01T12:00:00Z');
    seedPr(db, 232, true);
    db.upsertIssueClosureEvent({
      issue_number: 32,
      event_id: 'closed-32-window',
      closed_at: '2028-09-02T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    seedReopen(db, 32, '2028-09-03T00:00:00Z');
    db.upsertIssueClosureEvent({
      issue_number: 32,
      event_id: 'closed-32-later',
      closed_at: '2028-09-12T00:00:00Z',
      actor_login: 'maintainer',
      state_reason: 'NOT_PLANNED',
      closer_type: null,
      closer_number: null,
      closer_oid: null,
      raw_json: '{}',
    });
    db.upsertIssuePrLink({
      issue_number: 32,
      pr_number: 232,
      source: 'ClosureComment.fixProof',
      will_close_target: null,
      referenced_at: '2028-09-02T00:00:00Z',
    });
    db.upsertReleasePrReachability({
      tag: 'v-window-old',
      pr_number: 232,
      tag_commit_oid: testReleaseCommitOid('v-window-old'),
      merge_commit_oid: 'merge-232',
      base_ref_name: 'main',
      status: 'reachable',
      evidence_json: '{}',
    });

    assert.deepEqual(db.closedDuringReign('v-window-old').map((row: any) => row.number), []);
    assert.deepEqual(db.verifiedFixedForRelease('v-window-old').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-window-old').map((row: any) => row.number), []);
    assert.deepEqual(db.closedDuringReign('v-window-new').map((row: any) => row.number), [32]);
    assert.deepEqual(db.verifiedFixedForRelease('v-window-new').map((row: any) => row.number), []);
    assert.deepEqual(db.unverifiedClosedForRelease('v-window-new').map((row: any) => row.number), [32]);

    const reader = new ReleaseAuditReader(db.db);
    assert.deepEqual(reader.rawClosedDuringReign('v-window-old').map((row: any) => row.number), []);
    assert.deepEqual(reader.rawClosedDuringReign('v-window-new').map((row: any) => row.number), [32]);
  });

  it('matches final closure events when GitHub timestamps differ by one second', async () => {
    const db = await freshDb('closure-timestamp-skew');
    seedRelease(db, 'v-skew', '2028-10-01T00:00:00Z');
    seedIssue(db, 33, '2028-10-02T00:00:00Z', '2028-10-01T12:00:00Z');
    seedIssue(db, 34, '2028-10-02T00:00:00Z', '2028-10-01T12:00:00Z');
    seedPr(db, 233, true);
    seedPr(db, 234, true);
    db.upsertIssueClosureEvent({
      issue_number: 33,
      event_id: 'closed-33-skew',
      closed_at: '2028-10-02T00:00:01Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 233,
      closer_oid: 'merge-233',
      raw_json: '{}',
    });
    db.upsertIssueClosureEvent({
      issue_number: 34,
      event_id: 'closed-34-real-mismatch',
      closed_at: '2028-10-02T00:00:03Z',
      actor_login: 'maintainer',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 234,
      closer_oid: 'merge-234',
      raw_json: '{}',
    });
    for (const [issue, pr] of [[33, 233], [34, 234]] as const) {
      db.upsertIssuePrLink({
        issue_number: issue,
        pr_number: pr,
        source: 'ClosedEvent.closer',
        will_close_target: 1,
        referenced_at: '2028-10-02T00:00:00Z',
      });
      db.upsertReleasePrReachability({
        tag: 'v-skew',
        pr_number: pr,
        tag_commit_oid: testReleaseCommitOid('v-skew'),
        merge_commit_oid: `merge-${pr}`,
        base_ref_name: 'main',
        status: 'reachable',
        evidence_json: '{}',
      });
    }
    seedClosureProof(db, 'v-skew', 33);

    assert.deepEqual(db.verifiedFixedForRelease('v-skew').map((row: any) => row.number), [33]);
    assert.deepEqual(db.unverifiedClosedForRelease('v-skew').map((row: any) => row.number), [34]);
  });

  it('makes release-audit state projection parity sensitive to ordinal, actor, and closer fields', async () => {
    const db = await freshDb('release-audit-state-projection');
    seedRelease(db, 'v-projection', '2028-11-01T00:00:00Z');
    db.upsertIssue({
      number: 35,
      node_id: 'I_projection_35',
      state: 'closed',
      title: 'state projection parity',
      author: 'reporter',
      author_node_id: 'U_projection_reporter',
      author_type: 'User',
      html_url: 'https://example.test/issues/35',
      created_at: '2028-11-01T12:00:00Z',
      updated_at: '2028-11-02T00:00:00Z',
      closed_at: '2028-11-02T00:00:00Z',
      comments: 0,
      labels: '[]',
      is_bot: 0,
    });
    const closure = {
      issue_number: 35,
      issue_node_id: 'I_projection_35',
      event_id: 'closed-35',
      closed_at: '2028-11-02T00:00:00Z',
      connection_ordinal: 0,
      actor_node_id: 'U_projection_maintainer',
      actor_login: 'maintainer',
      actor_type: 'User',
      state_reason: 'COMPLETED',
      closer_type: 'PullRequest',
      closer_number: 235,
      closer_node_id: 'PR_projection_235',
      closer_oid: 'a'.repeat(40),
      raw_json: '{}',
    };
    const events = normalizeIssueStateEvents([{
      eventId: closure.event_id,
      eventNodeType: 'ClosedEvent',
      type: 'closed',
      occurredAt: closure.closed_at,
      connectionOrdinal: closure.connection_ordinal,
      actorNodeId: closure.actor_node_id,
      actorLogin: closure.actor_login,
      actorType: closure.actor_type,
      stateReason: closure.state_reason,
      closerNodeId: closure.closer_node_id,
      closerType: closure.closer_type,
      closerNumber: closure.closer_number,
      closerOid: closure.closer_oid,
    }]);
    db.replaceIssueStateEventSnapshot({
      issue_number: 35,
      issue_state: 'closed',
      issue_updated_at: '2028-11-02T00:00:00Z',
      total_count: 1,
      fetched_count: 1,
      sweep_count: 2,
      stabilized: true,
      closure_events: [closure],
      reopen_events: [],
      ...authoritativeStateSnapshotFields({
        repositoryNodeId: 'R_projection_openclaw',
        issueNumber: 35,
        issueNodeId: 'I_projection_35',
        issueState: 'closed',
        issueUpdatedAt: '2028-11-02T00:00:00Z',
        events,
      }),
    });
    const reader = new ReleaseAuditReader(db.db);
    assert.equal(
      reader.issueStateSnapshotIntegrityForRelease('v-projection').candidateIssueCount,
      1,
    );
    assert.equal(
      reader.issueStateSnapshotIntegrityForRelease('v-projection').projectionMismatchCount,
      0,
    );

    db.db.prepare(`
      UPDATE issue_closure_events
      SET connection_ordinal=1, actor_login='attacker', closer_number=999
      WHERE event_id='closed-35'
    `).run();
    assert.equal(
      reader.issueStateSnapshotIntegrityForRelease('v-projection').projectionMismatchCount,
      1,
    );
  });

  it('keeps unverified closures visible but excludes verified fixes', async () => {
    const db = await freshDb('unverified-closed');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease('v4', '2026-07-05T00:00:00Z', false, testReleaseCommitOid('v4')),
      catalogRelease('v3', '2026-07-01T00:00:00Z', false, testReleaseCommitOid('v3')),
    ]);

    for (const n of [301, 302, 303, 304]) seedIssue(db, n, '2026-07-02T00:00:00Z', '2026-07-01T12:00:00Z');
    for (const n of [301, 302, 303, 304]) seedClosure(db, n, 'COMPLETED', '2026-07-02T00:00:00Z');
    seedIssue(db, 305, '2026-06-30T00:00:00Z', '2026-06-29T12:00:00Z');
    seedIssue(db, 306, '2026-07-06T00:00:00Z', '2026-07-05T12:00:00Z');
    seedClosure(db, 305, 'COMPLETED', '2026-06-30T00:00:00Z');
    seedClosure(db, 306, 'COMPLETED', '2026-07-06T00:00:00Z');
    seedPr(db, 201, true);
    seedPr(db, 202, true);

    db.upsertIssuePrLink({ issue_number: 301, pr_number: 201, source: 'closedByPullRequestsReferences', will_close_target: 1, referenced_at: null });
    db.upsertReleasePrReachability({ tag: 'v3', pr_number: 201, tag_commit_oid: testReleaseCommitOid('v3'), merge_commit_oid: 'merge-201', base_ref_name: 'main', status: 'reachable', evidence_json: '{}' });
    db.upsertIssuePrLink({ issue_number: 302, pr_number: 202, source: 'closedByPullRequestsReferences', will_close_target: 1, referenced_at: null });
    db.upsertReleasePrReachability({ tag: 'v3', pr_number: 202, tag_commit_oid: testReleaseCommitOid('v3'), merge_commit_oid: 'merge-202', base_ref_name: 'main', status: 'not_reachable', evidence_json: '{}' });
    seedClosureProof(db, 'v3', 301);

    assert.deepEqual(db.verifiedFixedForRelease('v3').map((row: any) => row.number), [301]);
    assert.deepEqual(db.unverifiedClosedForRelease('v3').map((row: any) => row.number).sort((a: number, b: number) => a - b), [302, 303, 304]);
  });

  it('treats null-score audited stable releases as latest audited freshness targets', async () => {
    const db = await freshDb('null-score-audited-stable');
    seedAuthorizedReleaseCatalog(db, [
      catalogRelease(
        'v-wait',
        '2040-06-10T00:00:00Z',
        false,
        testReleaseCommitOid('v-wait'),
      ),
      catalogRelease(
        'v-old',
        '2040-06-01T00:00:00Z',
        false,
        testReleaseCommitOid('v-old'),
      ),
    ]);
    const oldScore = {
      tag: 'v-old',
      final_score: 7.5,
      negative_issues: 0,
      positive_issues: 0,
      state: 'eligible',
      recommended: 1,
      score_reason: 'old stable',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 0,
      scored_at: '2040-06-01T01:00:00Z',
    };
    db.updateReleaseScore(oldScore);
    db.upsertReleaseScoreAudit({
      release_tag: 'v-old',
      scored_at: oldScore.scored_at,
      score_model_version: 'test-model',
      prompt_version: 6,
      final_score: oldScore.final_score,
      status: oldScore.state,
      band: 'ok',
      recommended: 1,
      input_json: '{"schemaVersion":1,"rawIssueCount":0,"classifiedIssueCount":0}',
      components_json: '{"schemaVersion":1,"components":{},"explanation":{"schemaVersion":1}}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
    });
    const waitScore = {
      tag: 'v-wait',
      final_score: null,
      negative_issues: 0,
      positive_issues: 0,
      state: 'wait',
      recommended: 0,
      score_reason: 'settle time gate',
      broken_surfaces: '[]',
      closed_serious_fixed: 0,
      opened_serious_during_reign: 0,
      scored_at: '2040-06-10T01:00:00Z',
    };
    db.updateReleaseScore(waitScore);
    db.upsertReleaseScoreAudit({
      release_tag: 'v-wait',
      scored_at: waitScore.scored_at,
      score_model_version: 'test-model',
      prompt_version: 6,
      final_score: null,
      status: waitScore.state,
      band: 'wait',
      recommended: 0,
      input_json: '{"schemaVersion":1,"rawIssueCount":0,"classifiedIssueCount":0}',
      components_json: '{"schemaVersion":1,"components":{},"explanation":{"schemaVersion":1}}',
      issue_evidence_json: '{"schemaVersion":1}',
      gate_evidence_json: '{"schemaVersion":1}',
    });

    assert.equal(db.latestScoredStableReleaseTag(), 'v-wait');
    const reader = new ReleaseAuditReader(db.db);
    assert.ok(reader.scoredStableReleaseCount() >= 2);
    assert.deepEqual(reader.listReleases(2, { scoredOnly: true }).map((row: any) => row.tag), ['v-wait', 'v-old']);
  });
});

async function childResult(child: ReturnType<typeof spawn>): Promise<{
  inserted: boolean;
  status?: string;
  id: string;
  receipt?: string;
}> {
  let stdout = '';
  let stderr = '';
  child.stdout?.setEncoding('utf8');
  child.stderr?.setEncoding('utf8');
  child.stdout?.on('data', (chunk) => { stdout += chunk; });
  child.stderr?.on('data', (chunk) => { stderr += chunk; });
  const code = await new Promise<number | null>((resolve) => child.on('close', resolve));
  assert.equal(code, 0, stderr || stdout);
  const line = stdout.trim().split('\n').at(-1);
  assert.ok(line, 'child did not emit a result');
  return JSON.parse(line);
}
