import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import {
  CLASSIFICATION_PROMPT_TEMPLATE_HASH,
  PROMPT_VERSION,
  __llmTest,
  type IssueClassification,
} from './llm.ts';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  commentEvidenceStabilizationIdentity,
  commentEvidenceSweepIdentity,
  serializeCommentEvidence,
} from './commentEvidence.ts';
import {
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  type NormalizedIssueStateEvent,
} from './stateEventSnapshot.ts';
import { CLOSURE_PROOF_ANALYZER_VERSION } from './analysisVersions.ts';
import {
  appendClassifierAttempt,
  captureClassifierRawModelOutput,
  captureClassifierRawResponse,
  createClassifierAttemptLedger,
  createClassifierAttemptRun,
  createClassifierAttemptTerminalReceipt,
} from './classifierAttemptLedger.ts';
import { extractClosureClaimCandidates } from './closureClaimCandidates.ts';
import {
  buildRepositoryCollaboratorPermissionSnapshot,
} from './labelAuthorityEvidenceIngestion.ts';
import { buildIssueLabelEvidenceSnapshot } from './issueLabelEvidenceSnapshot.ts';
import { buildScoreAuthorityResolutionRun } from './scoreAuthorityResolution.ts';
import {
  createReleaseClosureAuthorityEvaluationForRun,
} from './closureClaimAuthorityEvaluation.ts';
import { buildArtifactVerificationEvidence } from './artifactVerification.ts';
import {
  buildReleaseArtifactPublicationScope,
} from './releaseArtifactPublicationScope.ts';
import { config } from '../config.ts';

async function freshModules(name: string) {
  const assignedDatabasePath = process.env.RADAR_TEST_WORKER_DB_PATH?.trim();
  assert.ok(
    assignedDatabasePath,
    'release scoring DB bridge requires a runner-assigned database',
  );
  assert.equal(
    process.env.DB_PATH,
    assignedDatabasePath,
    'release scoring DB bridge must use its runner-assigned database',
  );
  if (!sharedModules) {
    sharedModules = (async () => {
      const db = await import('./db.ts');
      const scoring = await import(
        `./releaseScoring.ts?release-scoring-${name}-${Date.now()}-${Math.random()}`
      );
      return { db, scoring };
    })();
  }
  const modules = await sharedModules;
  resetDatabase(modules.db.db);
  return modules;
}

let sharedModules: Promise<{
  db: any;
  scoring: any;
}> | null = null;

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

after(async () => {
  const modules = await sharedModules?.catch(() => null);
  modules?.db.db.close();
});

function classification(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'high',
    scope: 'broad',
    functionality: 'core',
    affectedUsers: 'many',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.95,
    rationale: 'test classification',
    ...overrides,
  };
}

function seedRelease(db: any, tag: string, publishedAt: string, prerelease = false) {
  const tagCommitOid = createHash('sha1').update(`release:${tag}`).digest('hex');
  db.upsertRelease({
    tag,
    node_id: `R_${tag.replace(/[^A-Za-z0-9]/g, '_')}`,
    catalog_tag_commit_oid: tagCommitOid,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/releases/${tag}`,
    prerelease,
    body: '',
  });
  db.upsertReleaseCommit({
    tag,
    tag_commit_oid: tagCommitOid,
    committed_at: publishedAt,
  });
}

function activateCatalog(db: any, tagsNewestFirst: string[]) {
  return db.replaceActiveReleaseCatalog(tagsNewestFirst.map((tag) => {
    const release = db.getRelease(tag);
    const commit = db.getReleaseCommit(tag);
    return {
      node_id: release.node_id,
      catalog_tag_commit_oid: commit.tag_commit_oid,
      tag: release.tag,
      name: release.name,
      published_at: release.published_at,
      created_at: release.created_at,
      updated_at: release.updated_at,
      html_url: release.html_url,
      prerelease: release.prerelease === 1,
      body: release.body,
    };
  }), {
    capture: { source: 'test_fixture' },
  });
}

function catalogAttestation(db: any, scoreBuiltAt: string) {
  const local = db.currentActiveReleaseCatalog();
  const integrity = db.releaseCatalogCaptureReceiptLedgerIntegrity(local);
  assert.deepEqual(integrity.problems, []);
  assert.ok(integrity.latestPayload);
  const activeCatalog = integrity.latestPayload.activeCatalog;
  assert.equal(activeCatalog.digest, local.digest);
  assert.equal(activeCatalog.releaseCount, local.releaseCount);
  const remote = {
    digest: activeCatalog.digest,
    totalCount: activeCatalog.releaseCount,
    nodeCount: activeCatalog.releaseCount,
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
    finalObservedAt: new Date(Date.parse(scoreBuiltAt) + 1).toISOString(),
    projectedActiveCatalog: {
      digest: activeCatalog.digest,
      releaseCount: activeCatalog.releaseCount,
    },
    localActiveCatalog: {
      digest: activeCatalog.digest,
      releaseCount: activeCatalog.releaseCount,
    },
    latestStable: activeCatalog.latestStable,
    scoreBuiltAt,
  };
}

interface RefreshPublicationFixture {
  runId: string;
  operation: string;
  trigger: string;
  codeRevision: string;
  leaseName: string;
  leaseHolderId: string;
  startedAt: string;
  scoreCommitBeforeMs: number;
  scoreCommitAfterMs: number;
  forecastStartedAt: string;
  forecastCompletedAt: string;
}

function beginRefreshPublicationFixture(
  db: any,
  runId: string,
  codeRevision: string,
): RefreshPublicationFixture {
  const nowMs = Date.now();
  const startedAtMs = nowMs - 20_000;
  const acquiredAt = new Date(nowMs).toISOString();
  const leaseTtlMs = 300_000;
  const fixture = {
    runId,
    operation: 'refresh',
    trigger: 'test',
    codeRevision,
    leaseName: `release-scoring-${runId}`,
    leaseHolderId: `release-scoring-holder-${runId}`,
    startedAt: new Date(startedAtMs).toISOString(),
    scoreCommitBeforeMs: startedAtMs + 5_000,
    scoreCommitAfterMs: startedAtMs + 6_000,
    forecastStartedAt: new Date(startedAtMs + 7_000).toISOString(),
    forecastCompletedAt: new Date(startedAtMs + 8_000).toISOString(),
  };
  assert.equal(
    db.acquireRefreshLease(
      fixture.leaseName,
      fixture.leaseHolderId,
      acquiredAt,
      leaseTtlMs,
    ),
    true,
  );
  db.beginRefreshOperationAttempt({
    run_id: fixture.runId,
    operation: fixture.operation,
    trigger: fixture.trigger,
    started_at: fixture.startedAt,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    lease_expires_at: new Date(nowMs + leaseTtlMs).toISOString(),
    code_revision: fixture.codeRevision,
    effective_config: { schemaVersion: 1 },
  });
  return fixture;
}

function persistRefreshArtifactVerification(
  db: any,
  fixture: RefreshPublicationFixture,
  release: any,
): void {
  const repository = `${config.github.owner}/${config.github.repo}`;
  const version = release.tag.replace(/^v/, '');
  const releaseSha = release.catalog_tag_commit_oid;
  const tarballUrl =
    `https://registry.npmjs.org/openclaw/-/openclaw-${version}.tgz`;
  const reportUrl =
    `https://github.com/${repository}/blob/${releaseSha}/release-evidence.json`;
  const rawReportUrl =
    `https://raw.githubusercontent.com/${repository}/${releaseSha}/release-evidence.json`;
  const bytes = Buffer.from(`release-scoring artifact:${fixture.runId}:${release.tag}`);
  const sha512 = createHash('sha512').update(bytes).digest('base64');
  const integrity = `sha512-${sha512}`;
  db.persistReleaseArtifactVerification({
    runId: fixture.runId,
    observedAt: new Date(Date.parse(fixture.startedAt) + 1_000).toISOString(),
    release: {
      repository,
      tag: release.tag,
      releaseNodeId: release.node_id,
      catalogTagCommitOid: releaseSha,
      publishedAt: new Date(release.published_at).toISOString(),
    },
    releaseMetadata: {
      npmPackageUrl: `https://www.npmjs.com/package/openclaw/v/${version}`,
      releaseTarballUrl: tarballUrl,
      releaseIntegrity: integrity,
      releaseSha,
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
      registryGitHead: releaseSha,
      actualDigests: { sha512 },
      tarballByteCount: bytes.length,
      expectedIntegrity: integrity,
      expectedTarballUrl: tarballUrl,
      expectedReleaseSha: releaseSha,
    }),
    evidenceReport: {
      url: reportUrl,
      rawUrl: rawReportUrl,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      contentDigest: '6'.repeat(64),
      fallbackArtifactDigest: null,
      expectedReleaseTag: release.tag,
      expectedReleaseSha: releaseSha,
      verified: true,
      mismatch: null,
    },
  });
}

function scoreCommitClock(fixture: RefreshPublicationFixture) {
  const wallTimes = [fixture.scoreCommitBeforeMs, fixture.scoreCommitAfterMs];
  const monotonicTimes = [1_000, 2_000];
  return {
    wallTimeMs: () => wallTimes.shift()!,
    monotonicTimeMs: () => monotonicTimes.shift()!,
  };
}

function finalizeRefreshPublicationFixture(
  db: any,
  scoring: any,
  fixture: RefreshPublicationFixture,
  run: any,
  persistence: any,
): void {
  scoring.finalizeReleaseScorePublicationMetadata(persistence);
  const forecastCapture = scoring.captureReleaseValidationForecasts({
    run,
    scorePersistence: persistence,
  });
  const scoreMetadata = JSON.parse(db.getMeta('score_persistence_last_run') ?? 'null');
  const scoreDurationMs =
    Date.parse(persistence.commitTiming.commitNotAfter) -
    Date.parse(persistence.commitTiming.commitNotBefore);

  db.appendRefreshOperationStageEvent({
    run_id: fixture.runId,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    stage: 'score.persist',
    status: 'started',
    occurred_at: persistence.commitTiming.commitNotBefore,
  });
  db.appendRefreshOperationStageEvent({
    run_id: fixture.runId,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    stage: 'score.persist',
    status: 'completed',
    occurred_at: persistence.commitTiming.commitNotAfter,
    duration_ms: scoreDurationMs,
    counts: { scoredReleases: run.scored.length },
    details: {
      historyRunId: persistence.historyRunId,
      historyRunContentHash: persistence.historyRunContentHash,
      authorityRunId: persistence.authorityRunId,
      authorityRunContentHash: persistence.authorityRunContentHash,
      historyV2SealContentHash: persistence.historyV2SealContentHash,
      commitNotBefore: persistence.commitTiming.commitNotBefore,
      commitNotAfter: persistence.commitTiming.commitNotAfter,
    },
  });
  db.appendRefreshOperationStageEvent({
    run_id: fixture.runId,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    stage: 'forecast.capture',
    status: 'started',
    occurred_at: fixture.forecastStartedAt,
  });
  db.appendRefreshOperationStageEvent({
    run_id: fixture.runId,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    stage: 'forecast.capture',
    status: 'completed',
    occurred_at: fixture.forecastCompletedAt,
    duration_ms:
      Date.parse(fixture.forecastCompletedAt) -
      Date.parse(fixture.forecastStartedAt),
    counts: { validationForecasts: forecastCapture.forecasts.length },
    details: { eligibilityOutcome: forecastCapture.eligibilityOutcome },
  });

  db.appendRefreshCaptureReceipt({
    run_id: fixture.runId,
    lease_name: fixture.leaseName,
    lease_holder_id: fixture.leaseHolderId,
    status: 'success',
    finished_at: fixture.forecastCompletedAt,
    duration_ms:
      Date.parse(fixture.forecastCompletedAt) - Date.parse(fixture.startedAt),
    payload: {
      schemaVersion: 3,
      operation: fixture.operation,
      trigger: fixture.trigger,
      codeRevision: fixture.codeRevision,
      scoreHistory: {
        runId: persistence.historyRunId,
        contentHash: persistence.historyRunContentHash,
        persistedAt: persistence.persistedAt,
      },
      scoreAuthority: {
        runId: persistence.authorityRunId,
        contentHash: persistence.authorityRunContentHash,
        historyV2SealContentHash: persistence.historyV2SealContentHash,
      },
      scoreCommit: persistence.commitTiming,
      scoreMetadata,
      scoreRows: run.scored.map((result: any) => ({
        tag: result.rel.tag,
        finalScore: result.conf.score,
        negativeIssues: result.neg,
        positiveIssues: result.pos,
        state: result.conf.status,
        recommended: result.rel.tag === run.recommendedTag,
        scoreReason: result.conf.reason,
        brokenSurfaces: result.brokenSurfaces,
        closedSeriousFixed: result.closedSerious,
        openedSeriousDuringReign: result.openedSerious,
        scoredAt: result.scoredAt,
      })),
      releaseTags: run.scored.map((result: any) => result.rel.tag),
      releaseArtifacts: db.releaseArtifactPublicationForRun(fixture.runId),
      releaseArtifactScope: buildReleaseArtifactPublicationScope({
        scoredReleaseTags: run.scored.map((result: any) => result.rel.tag),
        predecessorByReleaseTag: run.predecessorByReleaseTag,
      }),
      releaseCatalog: {
        digest: persistence.catalogAttestation.finalRemoteCatalog.digest,
        nodeCount: persistence.catalogAttestation.finalRemoteCatalog.nodeCount,
        totalCount: persistence.catalogAttestation.finalRemoteCatalog.totalCount,
        sweepCount: persistence.catalogAttestation.finalRemoteCatalog.sweepCount,
        attestation: persistence.catalogAttestation,
      },
      recommendation: {
        selectedTag: run.recommendedTag,
        decisions: run.scored.map((result: any) => ({
          releaseTag: result.rel.tag,
          decision:
            result.recommendationDecision ??
            result.explanation.recommendationDecision ??
            null,
        })),
      },
      forecast: {
        eligibilityOutcome: forecastCapture.eligibilityOutcome,
        decisionIds: forecastCapture.forecasts.map(
          (forecast: any) => forecast.decisionId,
        ),
        newDecisionIds: forecastCapture.forecasts
          .filter((forecast: any) => forecast.status === 'inserted')
          .map((forecast: any) => forecast.decisionId),
        existingDecisionIds: forecastCapture.forecasts
          .filter((forecast: any) => forecast.status === 'already_captured')
          .map((forecast: any) => forecast.decisionId),
        captures: forecastCapture.forecasts,
        canonicalForecastIds: forecastCapture.canonicalForecasts.map(
          (forecast: any) => forecast.forecastId,
        ),
        canonicalForecastContentHashes: forecastCapture.canonicalForecasts.map(
          (forecast: any) => forecast.contentHash,
        ),
        newCanonicalForecastIds: forecastCapture.canonicalForecasts
          .filter((forecast: any) => forecast.status === 'inserted')
          .map((forecast: any) => forecast.forecastId),
        existingCanonicalForecastIds: forecastCapture.canonicalForecasts
          .filter((forecast: any) => forecast.status === 'already_captured')
          .map((forecast: any) => forecast.forecastId),
        canonicalCaptures: forecastCapture.canonicalForecasts,
      },
    },
  });
  assert.equal(
    db.releaseRefreshLease(fixture.leaseName, fixture.leaseHolderId),
    true,
  );
}

function closureEvent(issueNumber: number, closedAt: string) {
  return {
    issue_number: issueNumber,
    issue_node_id: `ISSUE-node-${issueNumber}`,
    event_id: `closed-${issueNumber}`,
    closed_at: closedAt,
    connection_ordinal: 0,
    actor_node_id: 'ACTOR-maintainer',
    actor_login: 'maintainer',
    actor_type: 'User',
    state_reason: 'COMPLETED',
    closer_type: 'Commit',
    closer_number: null,
    closer_node_id: `COMMIT-node-${issueNumber}`,
    closer_oid: createHash('sha1').update(`closure:${issueNumber}`).digest('hex'),
    raw_json: JSON.stringify({
      id: `closed-${issueNumber}`,
      __typename: 'ClosedEvent',
      actor: { id: 'ACTOR-maintainer', __typename: 'User', login: 'maintainer' },
      closer: { id: `COMMIT-node-${issueNumber}`, __typename: 'Commit' },
    }),
  };
}

function reopenEvent(issueNumber: number, reopenedAt: string, ordinal: number) {
  return {
    issue_number: issueNumber,
    issue_node_id: `ISSUE-node-${issueNumber}`,
    event_id: `reopened-${issueNumber}`,
    reopened_at: reopenedAt,
    connection_ordinal: ordinal,
    actor_node_id: 'ACTOR-maintainer',
    actor_login: 'maintainer',
    actor_type: 'User',
    raw_json: JSON.stringify({
      id: `reopened-${issueNumber}`,
      __typename: 'ReopenedEvent',
      actor: { id: 'ACTOR-maintainer', __typename: 'User', login: 'maintainer' },
    }),
  };
}

function normalizedStateEvents(
  closures: Array<ReturnType<typeof closureEvent>>,
  reopens: Array<ReturnType<typeof reopenEvent>>,
): NormalizedIssueStateEvent[] {
  return normalizeIssueStateEvents([
    ...closures.map((event) => ({
      eventId: event.event_id,
      eventNodeType: 'ClosedEvent' as const,
      type: 'closed' as const,
      occurredAt: event.closed_at,
      connectionOrdinal: event.connection_ordinal,
      actorNodeId: event.actor_node_id,
      actorLogin: event.actor_login,
      actorType: event.actor_type,
      stateReason: event.state_reason,
      closerNodeId: event.closer_node_id,
      closerType: event.closer_type,
      closerNumber: event.closer_number,
      closerOid: event.closer_oid,
    })),
    ...reopens.map((event) => ({
      eventId: event.event_id,
      eventNodeType: 'ReopenedEvent' as const,
      type: 'reopened' as const,
      occurredAt: event.reopened_at,
      connectionOrdinal: event.connection_ordinal,
      actorNodeId: event.actor_node_id,
      actorLogin: event.actor_login,
      actorType: event.actor_type,
      stateReason: null,
      closerNodeId: null,
      closerType: null,
      closerNumber: null,
      closerOid: null,
    })),
  ]);
}

function stateSnapshotFields(input: {
  issueNumber: number;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  events: readonly NormalizedIssueStateEvent[];
}) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `ISSUE-node-${input.issueNumber}`;
  const issueNodeType = 'Issue' as const;
  const sweep = {
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId,
    issueNodeType,
    issueState: input.issueState,
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: input.events.length,
    events: input.events,
  };
  const firstSweep = issueStateEventSweepIdentity({ ...sweep, sweepOrdinal: 1 });
  const secondSweep = issueStateEventSweepIdentity({ ...sweep, sweepOrdinal: 2 });
  return {
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_node_type: issueNodeType,
    events_digest: issueStateEventsDigest(input.events, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType,
    }),
    authority_digest: secondSweep.sweepDigest,
    stabilization: issueStateEventStabilizationIdentity(firstSweep, secondSweep, 2),
  };
}

function seedIssue(db: any, input: {
  number: number;
  title: string;
  state: 'open' | 'closed';
  createdAt: string;
  updatedAt?: string;
  closedAt?: string | null;
  labels?: string[];
  classification?: IssueClassification | null;
  body?: string | null;
  commentBody?: string;
  commentCreatedAt?: string;
  commentAuthor?: string;
  affectsVersion?: string | null;
}) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const commentCreatedAt = input.commentCreatedAt ?? input.createdAt;
  const updatedAt = input.updatedAt ?? input.commentCreatedAt ?? input.closedAt ?? input.createdAt;
  const issueNodeId = `ISSUE-node-${input.number}`;
  const issueAuthorNodeId = `ACTOR-reporter-${input.number}`;
  const commentActor = input.commentAuthor ?? 'commenter';
  const comments = [{
    id: input.number * 10,
    node_id: `COMMENT-node-${input.number * 10}`,
    node_type: 'IssueComment',
    url: `https://example.test/issues/${input.number}#comment`,
    user: {
      id: `ACTOR-${commentActor}`,
      login: commentActor,
      type: 'User',
    },
    author_association: 'NONE',
    body: input.commentBody ?? 'fixture comment',
    created_at: commentCreatedAt,
    updated_at: commentCreatedAt,
  }];
  const commentsDigest = commentEvidenceDigest(1, comments);
  db.upsertIssue({
    number: input.number,
    node_id: issueNodeId,
    state: input.state,
    title: input.title,
    body: input.body ?? null,
    author: 'reporter',
    author_node_id: issueAuthorNodeId,
    author_type: 'User',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: updatedAt,
    closed_at: input.closedAt ?? null,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(input.labels ?? ['bug']),
    is_bot: 0,
  });
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
  const commentSweep = {
    issueUpdatedAt: updatedAt,
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
    issue_number: input.number,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_author_node_id: issueAuthorNodeId,
    issue_author_login: 'reporter',
    issue_author_type: 'User',
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: 1,
    fetched_comment_count: 1,
    latest_comment_updated_at: commentCreatedAt,
    comments_digest: commentsDigest,
    authority_digest: secondCommentSweep.authorityDigest,
    issue_updated_at: updatedAt,
    comments_json: serializeCommentEvidence(comments),
    stabilization_json: JSON.stringify(commentStabilization),
    stabilization_identity_digest: commentStabilization.identityDigest,
  });
  if (input.classification !== null) {
    db.upsertClassification(
      input.number,
      input.classification ?? classification({
        affectsVersion: input.affectsVersion ?? null,
      }),
      updatedAt,
      PROMPT_VERSION,
      commentsDigest,
    );
  }
  db.upsertIssueLabelSnapshot({
    issue_number: input.number,
    snapshot_at: '2026-06-10T23:00:00Z',
    labels_json: JSON.stringify(input.labels ?? ['bug']),
  });
  const closureEvents = input.closedAt
    ? [closureEvent(input.number, input.closedAt)]
    : [];
  const normalizedEvents = normalizedStateEvents(closureEvents, []);
  db.replaceIssueStateEventSnapshot({
    issue_number: input.number,
    issue_state: input.state,
    issue_updated_at: updatedAt,
    total_count: normalizedEvents.length,
    fetched_count: normalizedEvents.length,
    sweep_count: 2,
    stabilized: true,
    closure_events: closureEvents,
    reopen_events: [],
    ...stateSnapshotFields({
      issueNumber: input.number,
      issueState: input.state,
      issueUpdatedAt: updatedAt,
      events: normalizedEvents,
    }),
  });
}

function seedAuthorizedLabelEvents(db: any, input: {
  issueNumber: number;
  observedAt: string;
  events: readonly {
    label: string;
    actor: string;
    createdAt: string;
  }[];
}) {
  const repositoryNodeId = 'REPO-node-openclaw';
  const issue = db.getIssue(input.issueNumber);
  assert.ok(issue);
  assert.ok(issue.node_id);
  const events = input.events.map((event) => {
    const eventId = `label-${input.issueNumber}-${event.label}`;
    const labelNodeId = `LABEL-${input.issueNumber}-${event.label}`;
    const actorNodeId = `ACTOR-${event.actor}`;
    const raw = {
      __typename: 'LabeledEvent',
      id: eventId,
      createdAt: event.createdAt,
      label: {
        id: labelNodeId,
        name: event.label,
      },
      actor: {
        __typename: 'User',
        id: actorNodeId,
        login: event.actor,
      },
    };
    db.upsertIssueLabelEvent({
      issue_number: input.issueNumber,
      issue_node_id: issue.node_id,
      event_id: eventId,
      action: 'labeled',
      label_name: event.label,
      actor_node_id: actorNodeId,
      actor_login: event.actor,
      actor_type: 'User',
      created_at: event.createdAt,
      raw_json: JSON.stringify(raw),
    });
    return {
      issueNumber: input.issueNumber,
      issueNodeId: issue.node_id,
      issueNodeType: 'Issue' as const,
      eventId,
      action: 'labeled' as const,
      labelNodeId,
      labelName: event.label,
      actorNodeId,
      actorLogin: event.actor,
      actorType: 'User',
      createdAt: event.createdAt,
      raw,
    };
  });
  db.insertIssueLabelEvidenceSnapshot(buildIssueLabelEvidenceSnapshot({
    schemaVersion: 2,
    repository: 'openclaw/openclaw',
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId: issue.node_id,
    issueNodeType: 'Issue',
    capturedAt: new Date(Date.parse(issue.updated_at) + 1_000).toISOString(),
    issueUpdatedAt: issue.updated_at,
    totalCount: events.length,
    fetchedCount: events.length,
    pageCount: 1,
    sweepCount: 2,
    stabilized: true,
    events,
  }));
  const actors = [...new Map(input.events.map((event) => [
    event.actor,
    {
      nodeId: `ACTOR-${event.actor}`,
      login: event.actor,
      actorType: 'User',
      association: 'MEMBER',
      permission: 'maintain' as const,
    },
  ])).values()];
  db.insertRepositoryCollaboratorPermissionSnapshotV2(
    buildRepositoryCollaboratorPermissionSnapshot({
      repositoryNodeId,
      repository: 'openclaw/openclaw',
      observedAt: input.observedAt,
      exhaustive: true,
      complete: true,
      totalCount: actors.length,
      pageCount: 1,
      pagesFetched: 2,
      sweepCount: 2,
      rows: actors,
    }),
  );
}

function seedClosure(db: any, issueNumber: number, closedAt: string) {
  db.upsertIssueClosureEvent(closureEvent(issueNumber, closedAt));
}

function seedClosureProof(
  db: any,
  releaseTag: string,
  issueNumber: number,
  status: string,
  evidence: Record<string, unknown> = { status },
) {
  db.upsertIssueClosureProof({
    release_tag: releaseTag,
    issue_number: issueNumber,
    status,
    summary: status,
    evidence_json: JSON.stringify({
      ...evidence,
      proofAnalyzerVersion: CLOSURE_PROOF_ANALYZER_VERSION,
    }),
  });
}

function persistCommentClosureClaims(db: any, input: {
  issueNumber: number;
  commentBody: string;
  commentAuthor: string;
  commentCreatedAt: string;
}) {
  const issue = db.getIssue(input.issueNumber);
  assert.ok(issue);
  assert.ok(issue.node_id);
  assert.ok(issue.author_node_id);
  assert.ok(issue.author_type);
  const extraction = extractClosureClaimCandidates({
    repository: {
      nodeId: 'REPO-node-openclaw',
      nameWithOwner: 'openclaw/openclaw',
    },
    issue: {
      nodeId: issue.node_id,
      number: input.issueNumber,
      author: {
        nodeId: issue.author_node_id,
        login: issue.author,
        type: issue.author_type,
      },
    },
    comments: [{
      nodeId: `COMMENT-node-${input.issueNumber * 10}`,
      databaseId: input.issueNumber * 10,
      url: `https://example.test/issues/${input.issueNumber}#comment`,
      actor: {
        nodeId: `ACTOR-${input.commentAuthor}`,
        login: input.commentAuthor,
        type: 'User',
      },
      createdAt: input.commentCreatedAt,
      updatedAt: input.commentCreatedAt,
      body: input.commentBody,
    }],
  });
  assert.deepEqual(extraction.rejections, []);
  const persisted = db.persistClosureClaimExtraction({
    issueNumber: input.issueNumber,
    extraction,
    capturedAt: new Date(
      Date.parse(input.commentCreatedAt) + 60_000,
    ).toISOString(),
  });
  assert.equal(
    persisted.receipt.candidateCount,
    extraction.candidates.length,
  );
  return extraction.candidates;
}

function authorizeClosureClaimActor(db: any, input: {
  actorLogin: string;
  observedAt: string;
}) {
  const snapshot = buildRepositoryCollaboratorPermissionSnapshot({
    repositoryNodeId: 'REPO-node-openclaw',
    repository: 'openclaw/openclaw',
    observedAt: input.observedAt,
    exhaustive: true,
    complete: true,
    totalCount: 1,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    rows: [{
      nodeId: `ACTOR-${input.actorLogin}`,
      login: input.actorLogin,
      actorType: 'User',
      association: 'MEMBER',
      permission: 'maintain',
    }],
  });
  db.insertRepositoryCollaboratorPermissionSnapshotV2(snapshot);
  return snapshot;
}

const BROAD_CORE_CLASSIFIER_GROUNDING_BODY =
  'Regression. High. Broad. CLI. Many users.';
const MODERATE_INTEGRATION_CLASSIFIER_GROUNDING_BODY =
  'Feature request. High. Windows. UI. Some users.';

function bindClassificationsToTags(db: any, knownTags: string[]) {
  const sourceIdentity = db.classifierSourceIdentity(knownTags, PROMPT_VERSION);
  const rows = db.db.prepare(`SELECT * FROM classifications ORDER BY issue_number`).all() as any[];
  for (const row of rows) {
    const issue = db.getIssue(row.issue_number);
    const comments = db.completeIssueComments(row.issue_number);
    const prompt = __llmTest.buildClassifierPromptInput({
      ...issue,
      user: { login: issue.author },
      labels: JSON.parse(issue.labels).map((name: string) => ({ name })),
    }, comments, knownTags);
    const rawModelOutput = JSON.stringify({
      sentiment: row.sentiment,
      severity: row.severity,
      scope: row.scope,
      functionality: row.functionality,
      affected_users: row.affected_users,
      workaroundStatus: row.workaround_status,
      duplicateCluster: row.duplicate_cluster,
      affectsVersion: row.affects_version,
      evidence: {
        sentiment: [{
          source_id: 'issue:body',
          excerpt: row.sentiment === 'neutral' ? 'Feature request' : 'Regression',
        }],
        severity: [{ source_id: 'issue:body', excerpt: 'High' }],
        scope: [{
          source_id: 'issue:body',
          excerpt: row.scope === 'moderate' ? 'Windows' : 'Broad',
        }],
        functionality: [{
          source_id: 'issue:body',
          excerpt: row.functionality === 'integration' ? 'UI' : 'CLI',
        }],
        affected_users: row.affected_users === 'unknown'
          ? []
          : [{
              source_id: 'issue:body',
              excerpt: row.affected_users === 'some' ? 'Some users' : 'Many users',
            }],
        workaroundStatus: [],
        duplicateCluster: [],
        affectsVersion: [],
      },
      rationale: row.rationale || 'Test fixture classification evidence.',
    });
    const parsed = __llmTest.parseRawClassification(
      rawModelOutput,
      knownTags,
      prompt.groundingSources,
      prompt.inputTruncation,
    );
    const provenance = {
      schemaVersion: 2 as const,
      responseId: `chatcmpl-fixture-${row.issue_number}`,
      requestedModel: sourceIdentity.model,
      responseModel: sourceIdentity.model,
      requestedServiceTier: sourceIdentity.serviceTier,
      responseServiceTier: sourceIdentity.serviceTier,
      reasoningEffort: sourceIdentity.reasoningEffort,
      promptVersion: PROMPT_VERSION,
      promptTemplateHash: CLASSIFICATION_PROMPT_TEMPLATE_HASH,
      promptHash: 'a'.repeat(64),
      rawModelOutputHash: createHash('sha256').update(rawModelOutput).digest('hex'),
      rawModelOutput,
      groundingSources: prompt.groundingSources,
      groundingSourcesHash: createHash('sha256')
        .update(stableJson(prompt.groundingSources))
        .digest('hex'),
      inputTruncation: prompt.inputTruncation,
    };
    const acceptedClassifier = recordAcceptedClassifierLedger(db, {
      issueNumber: row.issue_number,
      rawModelOutput,
      responseId: provenance.responseId,
      sourceIdentity,
    });
    db.upsertClassification(
      row.issue_number,
      {
        ...parsed,
        provenance,
      },
      issue.updated_at,
      PROMPT_VERSION,
      (db.db.prepare(`
        SELECT comments_digest
        FROM issue_comment_snapshots
        WHERE issue_number=?
      `).get(row.issue_number) as { comments_digest: string }).comments_digest,
      sourceIdentity,
      acceptedClassifier,
    );
  }
  return sourceIdentity;
}

function recordAcceptedClassifierLedger(db: any, input: {
  issueNumber: number;
  rawModelOutput: string;
  responseId: string;
  sourceIdentity: {
    model: string;
    serviceTier: string;
    promptTemplateHash: string;
  };
}) {
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
  const attempt = appendClassifierAttempt(run, [], {
    attemptId: `classifier-attempt-${input.issueNumber}-${input.responseId}`,
    status: 'accepted_success',
    startedAt: '2040-01-01T00:00:00.000Z',
    finishedAt: '2040-01-01T00:00:01.000Z',
    rawResponse: captureClassifierRawResponse(JSON.stringify({
      id: input.responseId,
      model: input.sourceIdentity.model,
      service_tier: input.sourceIdentity.serviceTier,
      choices: [{ message: { content: input.rawModelOutput } }],
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

function stableJson(value: unknown): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const row = value as Record<string, unknown>;
  return `{${Object.keys(row).sort().map((key) =>
    `${JSON.stringify(key)}:${stableJson(row[key])}`).join(',')}}`;
}

function strictPrReachabilityEvidence(
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
  mergeCommitOid: string,
  catalogProof: Record<string, unknown>,
) {
  return {
    schemaVersion: 1,
    evidence: status === 'reachable'
      ? 'merge_commit_in_release_history'
      : 'not_reachable_from_release_tag',
    method: 'git-merge-base',
    catalogProof,
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

function releaseCatalogProof(db: any, tag: string) {
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

describe('release scoring DB bridge', () => {
  it('uses the active prerelease catalog for production and offline hotfix context', async () => {
    const { db, scoring } = await freshModules('active-prerelease-hotfix');
      seedRelease(db, 'v0', '2026-05-20T00:00:00Z');
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v1-1', '2026-06-02T00:00:00Z', true);
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2', 'v1-1', 'v1', 'v0']);

      const productionRun = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v1')],
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      const { createScoreRunWindowHelpers } = await import(
        `../../scripts/lib/score-run-window-core.mjs?hotfix=${Date.now()}`
      );
      const { monitoredScoreWindowReleases, scoreRunWindowOptions } =
        createScoreRunWindowHelpers({
          getMeta: db.getMeta,
          getRelease: db.getRelease,
          listActiveReleaseCatalogDb: db.listActiveReleaseCatalogDb,
          listReleasesDb: db.listReleasesDb,
        });
      const offlineOptions = scoreRunWindowOptions([db.getRelease('v1')]);
      const offlineRun = scoring.buildReleaseScoreRun({
        ...offlineOptions,
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });

      assert.deepEqual(offlineOptions.allFetchedTags, ['v2', 'v1-1', 'v1', 'v0']);
      assert.deepEqual(offlineOptions.stableTagsNewestFirst, ['v2', 'v1', 'v0']);
      assert.equal(productionRun.scored[0].input.hasHotfixSuccessor, true);
      assert.equal(
        offlineRun.scored[0].input.hasHotfixSuccessor,
        productionRun.scored[0].input.hasHotfixSuccessor,
      );
      db.setMeta('score_persistence_last_run', JSON.stringify({
        schemaVersion: 2,
        releaseTags: ['v1', 'v0'],
      }));
      assert.deepEqual(
        monitoredScoreWindowReleases(1).map((release: any) => release.tag),
        ['v1', 'v0'],
        'manual score writers must retain the complete persisted window instead of truncating to a scoped limit',
      );
      db.setMeta('score_persistence_last_run', JSON.stringify({
        schemaVersion: 1,
        releaseTags: ['v1'],
      }));
      assert.throws(
        () => monitoredScoreWindowReleases(1),
        /must use schemaVersion 2 with a non-empty releaseTags array/,
        'manual writers must not fall back to a truncating window when persistence metadata is malformed',
      );
  });

  it('rejects non-finite publication timestamps before deriving score boundaries', async () => {
    const { db, scoring } = await freshModules('invalid-publication-boundary');
      seedRelease(db, 'v0', '2026-05-20T00:00:00Z');
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      activateCatalog(db, ['v1', 'v0']);
      db.db.prepare(`UPDATE releases SET published_at='not-a-timestamp' WHERE tag='v1'`).run();

      assert.throws(
        () => scoring.buildReleaseScoreRun({
          releases: [db.getRelease('v1')],
          nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
        }),
        /Active release catalog v1 has invalid published_at not-a-timestamp/,
      );
      assert.throws(
        () => scoring.scoreTagWindow([
          { tag: 'v1', published_at: 'not-a-timestamp', prerelease: false },
        ]),
        /invalid published_at timestamp.*v1/,
      );
  });

  it('links closed-before-release exact-version human reproduction into target debt evidence', async () => {
    const { db, scoring } = await freshModules('closed-before-target-reproduction');
    try {
      seedRelease(db, 'v0', '2026-05-01T00:00:00Z');
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2', 'v1', 'v0']);
      seedIssue(db, {
        number: 9301,
        title: 'Gateway loses session state after restart',
        state: 'closed',
        createdAt: '2026-05-10T00:00:00Z',
        closedAt: '2026-05-20T00:00:00Z',
        commentBody: 'I reproduced the same session loss on v1 after a clean install and restart.',
        commentCreatedAt: '2026-06-05T00:00:00Z',
        affectsVersion: 'v0',
      });
      seedIssue(db, {
        number: 9302,
        title: 'Old gateway failure',
        state: 'closed',
        createdAt: '2026-05-10T00:00:00Z',
        closedAt: '2026-05-20T00:00:00Z',
        commentBody: 'v1 is unaffected; this only fails on v0.',
        commentCreatedAt: '2026-06-05T00:00:00Z',
        affectsVersion: 'v1',
      });
      seedIssue(db, {
        number: 9304,
        title: 'v1 is unaffected by the old gateway failure',
        body: 'The v1 release is working and clean.',
        state: 'open',
        createdAt: '2026-06-02T00:00:00Z',
        affectsVersion: 'v1',
      });

      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v1')],
        allFetchedTags: ['v2', 'v1', 'v0'],
        stableTagsNewestFirst: ['v2', 'v1', 'v0'],
        oldestScoredStablePredecessorTag: 'v0',
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      const scored = run.scored[0];
      const targetEvidence = (scored.debtEvidence as any).targetEvidenceAttribution;
      const debtRows = [
        ...(scored.debtEvidence as any).verifiedDebt,
        ...(scored.debtEvidence as any).carryoverDebt,
        ...(scored.debtEvidence as any).staleDebt,
      ];

      assert.deepEqual(targetEvidence.map((row: any) => row.issueNumber), [9301]);
      assert.equal(targetEvidence[0].releaseLocalEvidence.source, 'comment');
      assert.equal(targetEvidence[0].releaseLocalEvidence.version, 'v1');
      assert.equal(targetEvidence[0].releaseLocalEvidence.author, 'commenter');
      assert.ok(debtRows.some((row: any) => row.issueNumber === 9301));
      assert.ok(!debtRows.some((row: any) => row.issueNumber === 9302));
      assert.ok(
        debtRows.some((row: any) => row.issueNumber === 9304),
        'raw unaffected prose must remain debt without an authorized immutable closure claim',
      );
      assert.equal(scored.input.rawIssueCount, 2);
      assert.equal(scored.input.classifiedIssueCount, 2);

      const scoreLedger = scored.scoreLedger;
      const explanationScoreLedger = scored.explanation.scoreLedger;
      (scored as any).scoreLedger = null;
      (scored.explanation as any).scoreLedger = null;
      assert.throws(
        () => scoring.__releaseScorePersistenceTest.assertReleaseScoreRunPersistable(run),
        /ScoreLedgerV2 is invalid: scoreLedger must be a non-null object/,
      );
      (scored as any).scoreLedger = scoreLedger;
      (scored.explanation as any).scoreLedger = explanationScoreLedger;

      (scored.debtEvidence as any).targetEvidenceAttribution = [];
      assert.throws(
        () => scoring.__releaseScorePersistenceTest.assertReleaseScoreRunPersistable(run),
        /post-publication exact-version reproduction issue #9301 is missing from target evidence/,
      );
    } finally {
      db.db.prepare(`DELETE FROM issues WHERE number IN (9301, 9302, 9304)`).run();
    }
  });

  it('uses connection ordinals to pair same-timestamp reopen and close events', async () => {
    const { db, scoring } = await freshModules('same-timestamp-state-order');
    try {
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2', 'v1']);
      seedIssue(db, {
        number: 9303,
        title: 'Same-timestamp reopen and close',
        state: 'closed',
        createdAt: '2026-05-01T00:00:00Z',
        updatedAt: '2026-06-02T00:00:00Z',
        closedAt: '2026-06-02T00:00:00Z',
      });
      const firstClose = {
        ...closureEvent(9303, '2026-05-20T00:00:00Z'),
        event_id: 'closed-9303-first',
        connection_ordinal: 0,
      };
      const reopen = reopenEvent(9303, '2026-06-02T00:00:00Z', 1);
      const finalClose = {
        ...closureEvent(9303, '2026-06-02T00:00:00Z'),
        event_id: 'closed-9303-final',
        connection_ordinal: 2,
      };
      const events = normalizedStateEvents([firstClose, finalClose], [reopen]);
      db.replaceIssueStateEventSnapshot({
        issue_number: 9303,
        issue_state: 'closed',
        issue_updated_at: '2026-06-02T00:00:00Z',
        total_count: events.length,
        fetched_count: events.length,
        sweep_count: 2,
        stabilized: true,
        closure_events: [firstClose, finalClose],
        reopen_events: [reopen],
        ...stateSnapshotFields({
          issueNumber: 9303,
          issueState: 'closed',
          issueUpdatedAt: '2026-06-02T00:00:00Z',
          events,
        }),
      });
      seedIssue(db, {
        number: 9305,
        title: 'Same-timestamp close and reopen',
        state: 'closed',
        createdAt: '2026-05-01T00:00:00Z',
        updatedAt: '2026-06-12T00:00:00Z',
        closedAt: '2026-06-12T00:00:00Z',
      });
      const sameTimeClose = {
        ...closureEvent(9305, '2026-06-02T00:00:00Z'),
        event_id: 'closed-9305-first',
        connection_ordinal: 0,
      };
      const sameTimeReopen = reopenEvent(9305, '2026-06-02T00:00:00Z', 1);
      const laterClose = {
        ...closureEvent(9305, '2026-06-12T00:00:00Z'),
        event_id: 'closed-9305-final',
        connection_ordinal: 2,
      };
      const secondEvents = normalizedStateEvents(
        [sameTimeClose, laterClose],
        [sameTimeReopen],
      );
      db.replaceIssueStateEventSnapshot({
        issue_number: 9305,
        issue_state: 'closed',
        issue_updated_at: '2026-06-12T00:00:00Z',
        total_count: secondEvents.length,
        fetched_count: secondEvents.length,
        sweep_count: 2,
        stabilized: true,
        closure_events: [sameTimeClose, laterClose],
        reopen_events: [sameTimeReopen],
        ...stateSnapshotFields({
          issueNumber: 9305,
          issueState: 'closed',
          issueUpdatedAt: '2026-06-12T00:00:00Z',
          events: secondEvents,
        }),
      });

      assert.equal(db.releaseIssueTimelineIntegrity('v1').ambiguousReopenCount, 0);
      assert.ok(!db.issuesForVersion('v2').some((row: any) => row.number === 9303));
      assert.ok(db.issuesForVersion('v2').some((row: any) => row.number === 9305));
      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v2')],
        allFetchedTags: ['v2', 'v1'],
        stableTagsNewestFirst: ['v2', 'v1'],
        oldestScoredStablePredecessorTag: 'v1',
        nowForRelease: () => Date.parse('2026-06-20T00:00:00Z'),
      });
      assert.equal(run.scored[0].input.rawIssueCount, 1);
      assert.equal(run.scored[0].input.classifiedIssueCount, 1);
    } finally {
      db.db.prepare(`DELETE FROM issues WHERE number IN (9303, 9305)`).run();
    }
  });

  it('applies only authorized closure claims and binds their exact candidates into the score manifest', async () => {
    const { db, scoring } = await freshModules(
      'closure-claim-authority-score-effects',
    );
    const previousTag = 'v2026.5.20';
    const targetTag = 'v2026.6.1';
    const nextTag = 'v2026.6.10';
    const authorizedNotAffectedIssue = 9401;
    const deniedNotAffectedIssue = 9402;
    const authorizedNotPlannedIssue = 9403;
    const deniedNotPlannedIssue = 9404;
      seedRelease(db, previousTag, '2026-05-20T00:00:00Z');
      seedRelease(db, targetTag, '2026-06-01T00:00:00Z');
      seedRelease(db, nextTag, '2026-06-10T00:00:00Z');
      activateCatalog(db, [nextTag, targetTag, previousTag]);

      for (const [number, commentBody, commentAuthor] of [
        [
          authorizedNotAffectedIssue,
          `${targetTag} is not affected by this report.`,
          'maintainer',
        ],
        [
          deniedNotAffectedIssue,
          `${targetTag} is not affected by this report.`,
          'outsider',
        ],
      ] as const) {
        seedIssue(db, {
          number,
          title: `Open target regression ${number}`,
          state: 'open',
          createdAt: '2026-06-02T00:00:00Z',
          commentBody,
          commentAuthor,
          commentCreatedAt: '2026-06-02T01:00:00Z',
          affectsVersion: targetTag,
        });
      }

      for (const [number, commentAuthor] of [
        [authorizedNotPlannedIssue, 'maintainer'],
        [deniedNotPlannedIssue, 'outsider'],
      ] as const) {
        seedIssue(db, {
          number,
          title: `Closed target regression ${number}`,
          state: 'closed',
          createdAt: '2026-06-02T02:00:00Z',
          closedAt: '2026-06-03T00:00:00Z',
          commentBody: 'Closing as not planned.',
          commentAuthor,
          commentCreatedAt: '2026-06-03T00:00:00Z',
          affectsVersion: targetTag,
        });
        seedClosure(db, number, '2026-06-03T00:00:00Z');
        seedClosureProof(db, targetTag, number, 'not_planned');
      }

      const authorizedNotAffectedCandidates = persistCommentClosureClaims(db, {
        issueNumber: authorizedNotAffectedIssue,
        commentBody: `${targetTag} is not affected by this report.`,
        commentAuthor: 'maintainer',
        commentCreatedAt: '2026-06-02T01:00:00Z',
      });
      const deniedNotAffectedCandidates = persistCommentClosureClaims(db, {
        issueNumber: deniedNotAffectedIssue,
        commentBody: `${targetTag} is not affected by this report.`,
        commentAuthor: 'outsider',
        commentCreatedAt: '2026-06-02T01:00:00Z',
      });
      const authorizedNotPlannedCandidates = persistCommentClosureClaims(db, {
        issueNumber: authorizedNotPlannedIssue,
        commentBody: 'Closing as not planned.',
        commentAuthor: 'maintainer',
        commentCreatedAt: '2026-06-03T00:00:00Z',
      });
      const deniedNotPlannedCandidates = persistCommentClosureClaims(db, {
        issueNumber: deniedNotPlannedIssue,
        commentBody: 'Closing as not planned.',
        commentAuthor: 'outsider',
        commentCreatedAt: '2026-06-03T00:00:00Z',
      });

      authorizeClosureClaimActor(db, {
        actorLogin: 'maintainer',
        observedAt: '2026-06-02T00:59:00Z',
      });
      authorizeClosureClaimActor(db, {
        actorLogin: 'maintainer',
        observedAt: '2026-06-02T23:59:00Z',
      });
      db.replaceReleaseClosureDependencySnapshot(
        db.releaseClosureDependencyIdentity(targetTag, [
          authorizedNotPlannedIssue,
          deniedNotPlannedIssue,
        ]),
      );

      const authorizedNotAffectedCandidate =
        authorizedNotAffectedCandidates.find((candidate) =>
          candidate.claim.kind === 'release_local' &&
          candidate.claim.assertion === 'not_affected' &&
          candidate.claim.releaseTag === targetTag);
      const deniedNotAffectedCandidate =
        deniedNotAffectedCandidates.find((candidate) =>
          candidate.claim.kind === 'release_local' &&
          candidate.claim.assertion === 'not_affected' &&
          candidate.claim.releaseTag === targetTag);
      const authorizedNotPlannedCandidate =
        authorizedNotPlannedCandidates.find((candidate) =>
          candidate.claim.kind === 'closure_rationale' &&
          candidate.claim.rationale === 'not_planned');
      const deniedNotPlannedCandidate =
        deniedNotPlannedCandidates.find((candidate) =>
          candidate.claim.kind === 'closure_rationale' &&
          candidate.claim.rationale === 'not_planned');
      assert.ok(authorizedNotAffectedCandidate?.candidateId);
      assert.ok(deniedNotAffectedCandidate?.candidateId);
      assert.ok(authorizedNotPlannedCandidate?.candidateId);
      assert.ok(deniedNotPlannedCandidate?.candidateId);

      const authorizedNotAffectedResolution =
        db.resolveClosureClaimAuthorityForCandidate(
          authorizedNotAffectedCandidate.candidateId,
        );
      const deniedNotAffectedResolution =
        db.resolveClosureClaimAuthorityForCandidate(
          deniedNotAffectedCandidate.candidateId,
        );
      const authorizedNotPlannedResolution =
        db.resolveClosureClaimAuthorityForCandidate(
          authorizedNotPlannedCandidate.candidateId,
        );
      const deniedNotPlannedResolution =
        db.resolveClosureClaimAuthorityForCandidate(
          deniedNotPlannedCandidate.candidateId,
        );
      assert.equal(
        authorizedNotAffectedResolution.authorizedForScoring,
        true,
        JSON.stringify(authorizedNotAffectedResolution),
      );
      assert.equal(
        deniedNotAffectedResolution.authorizedForScoring,
        false,
        JSON.stringify(deniedNotAffectedResolution),
      );
      assert.equal(
        authorizedNotPlannedResolution.authorizedForScoring,
        true,
        JSON.stringify(authorizedNotPlannedResolution),
      );
      assert.equal(
        deniedNotPlannedResolution.authorizedForScoring,
        false,
        JSON.stringify(deniedNotPlannedResolution),
      );

      const run = scoring.buildReleaseScoreRun({
        releases: [db.getRelease(targetTag)],
        allFetchedTags: [nextTag, targetTag, previousTag],
        stableTagsNewestFirst: [nextTag, targetTag, previousTag],
        oldestScoredStablePredecessorTag: previousTag,
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      const scored = run.scored[0];
      const debtIssueNumbers = [
        ...(scored.debtEvidence.verifiedDebt as any[]),
        ...(scored.debtEvidence.carryoverDebt as any[]),
        ...(scored.debtEvidence.staleDebt as any[]),
      ].map((row) => row.issueNumber ?? row.issue?.number);
      assert.ok(!debtIssueNumbers.includes(authorizedNotAffectedIssue));
      assert.ok(debtIssueNumbers.includes(deniedNotAffectedIssue));

      const closureProof =
        (scored.gateEvidence as any).fixProvenance.closureProof;
      const authorizedNotPlannedExample = closureProof.examples.find(
        (row: any) => row.number === authorizedNotPlannedIssue,
      );
      const deniedNotPlannedExample = closureProof.examples.find(
        (row: any) => row.number === deniedNotPlannedIssue,
      );
      assert.equal(
        authorizedNotPlannedExample?.riskDisposition,
        'neutral_or_non_actionable',
      );
      assert.equal(authorizedNotPlannedExample?.riskWeight, 0);
      assert.equal(
        deniedNotPlannedExample?.riskDisposition,
        'unsupported_closure_claim',
      );
      assert.ok(Number(deniedNotPlannedExample?.riskWeight ?? 0) > 0);

      const expectedCandidateIds = [
        authorizedNotAffectedCandidate.candidateId,
        authorizedNotPlannedCandidate.candidateId,
      ].sort();
      const authoritySubjects = run.authoritySubjects.filter(
        (subject) => subject.subjectKind === 'closure_claim',
      );
      assert.deepEqual(
        authoritySubjects.map((subject) => subject.subjectIdentity).sort(),
        expectedCandidateIds,
      );
      assert.ok(authoritySubjects.every((subject) =>
        subject.releaseTag === null &&
        subject.candidateId === subject.subjectIdentity &&
        subject.resolution.authorizedForScoring === true));
      assert.deepEqual(
        scored.authorityReferences
          .filter((reference) => reference.subjectKind === 'closure_claim')
          .map((reference) => reference.subjectIdentity)
          .sort(),
        expectedCandidateIds,
      );
      assert.deepEqual(
        scoring.__releaseScorePersistenceTest.scoreAuthorityManifestProblems(
          run,
        ),
        [],
      );

      const authorityRun = buildScoreAuthorityResolutionRun({
        authorityRunId: 'authority-run-closure-profile-replay',
        sourceIdentitySchemaVersion: run.sourceIdentity.schemaVersion,
        sourceIdentityDigest: run.sourceIdentity.digest,
        recordedAt: '2026-06-11T00:00:01Z',
        previousContentHash:
          db.listScoreAuthorityResolutionRuns().at(-1)?.contentHash ?? null,
        rows: run.authoritySubjects,
      });
      db.insertScoreAuthorityResolutionRun(authorityRun);
      const replay =
        createReleaseClosureAuthorityEvaluationForRun(
          authorityRun.authorityRunId,
        );
      assert.equal(
        replay.releaseExplicitlyUnaffected(
          authorizedNotAffectedIssue,
          targetTag,
        ),
        true,
      );
      assert.equal(
        replay.releaseExplicitlyUnaffected(
          deniedNotAffectedIssue,
          targetTag,
        ),
        false,
      );
      const proofByIssue = new Map(
        db.closureProofRows(targetTag).map((row: any) => [
          row.issue_number,
          row,
        ]),
      );
      assert.equal(
        replay.closureDisposition(
          proofByIssue.get(authorizedNotPlannedIssue)!,
        ),
        'neutral_or_non_actionable',
      );
      assert.equal(
        replay.closureDisposition(
          proofByIssue.get(deniedNotPlannedIssue)!,
        ),
        'unsupported_closure_claim',
      );
  });

  it('turns DB closure/open-debt evidence into install score inputs', async () => {
    const { db, scoring } = await freshModules('score-input-evidence');
      seedRelease(db, 'v0', '2026-05-20T00:00:00Z');
      seedRelease(db, 'v1', '2026-06-01T00:00:00Z');
      seedRelease(db, 'v2', '2026-06-10T00:00:00Z');
      activateCatalog(db, ['v2', 'v1', 'v0']);

      seedIssue(db, {
        number: 9101,
        title: 'verified fixed core regression',
        body: BROAD_CORE_CLASSIFIER_GROUNDING_BODY,
        state: 'closed',
        createdAt: '2026-06-01T12:00:00Z',
        closedAt: '2026-06-02T00:00:00Z',
      });
      seedClosure(db, 9101, '2026-06-02T00:00:00Z');
      seedClosureProof(db, 'v1', 9101, 'fixed_in_release', {
        status: 'fixed_in_release',
        hasReachableFixCommit: true,
        reachableFixCommits: ['a'.repeat(40)],
        fixCommitProof: [{
          commitOid: 'a'.repeat(40),
          creditEligible: true,
        }],
      });

      seedIssue(db, {
        number: 9102,
        title: 'closed after release without tag proof',
        body: BROAD_CORE_CLASSIFIER_GROUNDING_BODY,
        state: 'closed',
        createdAt: '2026-06-01T13:00:00Z',
        closedAt: '2026-06-03T00:00:00Z',
      });
      seedClosure(db, 9102, '2026-06-03T00:00:00Z');
      seedClosureProof(db, 'v1', 9102, 'fixed_after_release');

      seedIssue(db, {
        number: 9103,
        title: 'v1 release local broad regression still open',
        body: BROAD_CORE_CLASSIFIER_GROUNDING_BODY,
        state: 'open',
        createdAt: '2026-06-01T14:00:00Z',
        updatedAt: '2026-06-01T14:31:00Z',
        labels: ['P1', 'bug', 'regression'],
      });
      seedAuthorizedLabelEvents(db, {
        issueNumber: 9103,
        observedAt: '2026-06-01T13:00:00Z',
        events: [
          { label: 'bug', actor: 'triage-human', createdAt: '2026-06-01T14:30:00Z' },
          { label: 'P1', actor: 'priority-human', createdAt: '2026-06-01T14:30:00Z' },
          {
            label: 'regression',
            actor: 'regression-human',
            createdAt: '2026-06-01T14:30:00Z',
          },
        ],
      });

      seedIssue(db, {
        number: 9104,
        title: 'unclassified release issue',
        body: BROAD_CORE_CLASSIFIER_GROUNDING_BODY,
        state: 'open',
        createdAt: '2026-06-01T15:00:00Z',
        classification: null,
      });

      seedIssue(db, {
        number: 9105,
        title: 'messages silently dropped after provider timeout',
        body: MODERATE_INTEGRATION_CLASSIFIER_GROUNDING_BODY,
        state: 'open',
        createdAt: '2026-06-01T16:00:00Z',
        updatedAt: '2026-06-01T16:31:00Z',
        labels: ['stale', 'clawsweeper:source-repro', 'impact:message-loss'],
        classification: classification({
          sentiment: 'neutral',
          severity: 'high',
          functionality: 'integration',
          scope: 'moderate',
          affectedUsers: 'some',
          confidence: 0.8,
        }),
      });
      seedAuthorizedLabelEvents(db, {
        issueNumber: 9105,
        observedAt: '2026-06-01T15:00:00Z',
        events: ['stale', 'clawsweeper:source-repro', 'impact:message-loss'].map(
          (label) => ({
            label,
            actor: 'human-maintainer',
            createdAt: '2026-06-01T16:30:00Z',
          }),
        ),
      });
      seedIssue(db, {
        number: 9106,
        title: 'old product question',
        body: MODERATE_INTEGRATION_CLASSIFIER_GROUNDING_BODY,
        state: 'open',
        createdAt: '2026-06-01T17:00:00Z',
        labels: ['stale'],
        classification: classification({
          sentiment: 'neutral',
          severity: 'high',
          functionality: 'integration',
          scope: 'moderate',
          affectedUsers: 'some',
          confidence: 0.8,
        }),
      });
      db.replaceReleaseClosureDependencySnapshot(
        db.releaseClosureDependencyIdentity('v1', [9101, 9102]),
      );

      const release = db.getRelease('v1');
      const run = scoring.buildReleaseScoreRun({
        releases: [release],
        allFetchedTags: ['v2', 'v1'],
        stableTagsNewestFirst: ['v2', 'v1', 'v0'],
        oldestScoredStablePredecessorTag: 'v0',
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      const scored = run.scored[0];
      const staleDebt = scored.debtEvidence.staleDebt as any[];

      assert.ok(scored.input.verifiedDebtWeight > 0);
      assert.ok(scored.input.staleDebtWeight > 0);
      const riskSummary = scored.gateEvidence.fixProvenance.closureProof.riskSummary;
      const closureProof = scored.gateEvidence.fixProvenance.closureProof;
      const releaseFixCredit = scored.gateEvidence.fixProvenance.releaseFixCredit;
      assert.ok(riskSummary.unresolvedWeightedRisk > 0);
      assert.equal(
        Math.round(scored.input.unresolvedClosureRiskWeight * 1000) / 1000,
        Math.round(riskSummary.unresolvedWeightedRisk * 1000) / 1000,
      );
      assert.equal(
        Math.round(scored.input.affirmativeClosureRiskCeilingWeight * 1000) / 1000,
        Math.round(riskSummary.unresolvedWeightedRisk * 1000) / 1000,
      );
      assert.ok(
        scored.input.verifiedDebtWeight +
        scored.input.carryoverDebtWeight +
        scored.input.staleDebtWeight > 0,
      );
      assert.equal(closureProof.containedFixedCount, 1);
      assert.equal(closureProof.creditedCount, 0);
      assert.equal(closureProof.notCreditedCount, closureProof.analyzedClosedCount);
      assert.equal(closureProof.fixCreditDecisionCounts.withheld, 1);
      assert.equal(
        closureProof.fixCreditDecisions[0].reasonCode,
        'direct_commit_first_containing_proof_missing',
      );
      assert.equal(releaseFixCredit.countedClosedCount, closureProof.creditedCount);
      assert.equal(releaseFixCredit.notCountedClosedCount, closureProof.notCreditedCount);
      assert.equal(releaseFixCredit.analyzedClosedCount, closureProof.analyzedClosedCount);
      assert.deepEqual(releaseFixCredit.decisionCounts, closureProof.fixCreditDecisionCounts);
      assert.ok(scored.debtEvidence.unverifiedClosed.some((issue: any) => issue.number === 9102));
      assert.equal(scored.input.rawIssueCount, 6);
      assert.equal(scored.input.classifiedIssueCount, 5);
      assert.ok((scored.conf.components?.closureRisk ?? 0) < 0);
      assert.ok((scored.conf.components?.coverage ?? 0) < 0);
      assert.ok(staleDebt.some((item) => item.issue?.number === 9105));
      assert.ok(!staleDebt.some((item) => item.issue?.number === 9106));
      const rescued = staleDebt.find((item) => item.issue?.number === 9105);
      assert.equal(rescued.debtClassification.sentiment, 'negative');
      assert.deepEqual(rescued.debtClassificationDiff.sentiment, { raw: 'neutral', effective: 'negative' });
      assert.equal(rescued.issue.classification.sentiment, 'neutral');
      assert.throws(
        () => scoring.persistReleaseScoreRun(run),
        /complete classification coverage: v1 5\/6/,
      );
      assert.equal(db.getRelease('v1')?.final_score, null);

      db.upsertClassification(
        9104,
        classification(),
        '2026-06-01T15:00:00Z',
        PROMPT_VERSION,
        (db.db.prepare(`
          SELECT comments_digest
          FROM issue_comment_snapshots
          WHERE issue_number=9104
        `).get() as { comments_digest: string }).comments_digest,
      );
      seedRelease(db, 'v-tx', '2026-06-05T00:00:00Z');
      const txTagCommitOid = 'd'.repeat(40);
      const boundaryTagCommitOid = 'e'.repeat(40);
      const candidateMergeCommitOid = 'f'.repeat(40);
      db.upsertReleaseCommit({
        tag: 'v-tx',
        tag_commit_oid: txTagCommitOid,
        committed_at: '2026-06-05T00:00:00Z',
      });
      db.upsertReleaseCommit({
        tag: 'v1',
        tag_commit_oid: boundaryTagCommitOid,
        committed_at: '2026-06-01T00:00:00Z',
      });
      db.upsertIssuePrLink({
        issue_number: 9199,
        pr_number: 9299,
        source: 'closedByPullRequestsReferences',
        will_close_target: 1,
        referenced_at: '2026-06-05T00:00:00Z',
      });
      db.upsertPullRequestFix({
        pr_number: 9299,
        title: 'boundary integrity candidate',
        url: 'https://example.test/pull/9299',
        state: 'MERGED',
        merged: 1,
        merged_at: '2026-06-04T00:00:00Z',
        merge_commit_oid: candidateMergeCommitOid,
        base_ref_name: 'main',
      });
      activateCatalog(db, ['v-tx', 'v1']);
      const txCatalogProof = releaseCatalogProof(db, 'v-tx');
      const boundaryCatalogProof = releaseCatalogProof(db, 'v1');
      db.upsertReleasePrReachability({
        tag: 'v-tx',
        pr_number: 9299,
        tag_commit_oid: txTagCommitOid,
        merge_commit_oid: candidateMergeCommitOid,
        base_ref_name: 'main',
        status: 'reachable',
        evidence_json: JSON.stringify(strictPrReachabilityEvidence(
          'reachable',
          txTagCommitOid,
          candidateMergeCommitOid,
          txCatalogProof,
        )),
      });
      db.replaceReleaseClosureDependencySnapshot(
        db.releaseClosureDependencyIdentity('v-tx', []),
      );
      bindClassificationsToTags(db, ['v-tx']);
      const boundaryIntegrityRun = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v-tx')],
        oldestScoredStablePredecessorTag: 'v1',
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      assert.throws(
        () => scoring.persistReleaseScoreRun(boundaryIntegrityRun),
        /v1: PR reachability evidence is not current.*missing=1/,
      );
      db.upsertReleasePrReachability({
        tag: 'v1',
        pr_number: 9299,
        tag_commit_oid: boundaryTagCommitOid,
        merge_commit_oid: candidateMergeCommitOid,
        base_ref_name: 'main',
        status: 'not_reachable',
        evidence_json: JSON.stringify(strictPrReachabilityEvidence(
          'not_reachable',
          boundaryTagCommitOid,
          candidateMergeCommitOid,
          boundaryCatalogProof,
        )),
      });
      const refreshFixture = beginRefreshPublicationFixture(
        db,
        'bridge-test',
        'bridge-test-revision',
      );
      persistRefreshArtifactVerification(
        db,
        refreshFixture,
        db.getRelease('v-tx'),
      );
      persistRefreshArtifactVerification(
        db,
        refreshFixture,
        db.getRelease('v1'),
      );
      const txRun = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v-tx')],
        oldestScoredStablePredecessorTag: 'v1',
        artifactObservationRunId: refreshFixture.runId,
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      assert.throws(
        () => scoring.buildReleaseScoreRun({
          releases: [db.getRelease('v-tx')],
          stableTagsNewestFirst: ['v-tx', 'v0'],
          nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
        }),
        /active stable predecessor is v1, but supplied catalog names v0/,
      );
      const commentRow = db.db.prepare(`
        SELECT comments_json
        FROM issue_comment_snapshots
        WHERE issue_number=9103
      `).get() as { comments_json: string };
      const tamperedComments = JSON.parse(commentRow.comments_json);
      tamperedComments[0].body = 'tampered after score build';
      db.db.prepare(`
        UPDATE issue_comment_snapshots
        SET comments_json=?
        WHERE issue_number=9103
      `).run(JSON.stringify(tamperedComments));
      assert.throws(
        () => scoring.persistReleaseScoreRun(txRun),
        /commentDigestMismatches=1/,
      );
      db.db.prepare(`
        UPDATE issue_comment_snapshots
        SET comments_json=?
        WHERE issue_number=9103
      `).run(commentRow.comments_json);

      const classificationSource = db.db.prepare(`
        SELECT source_identity_json, source_identity_digest
        FROM classifications
        WHERE issue_number=9103
      `).get() as {
        source_identity_json: string;
        source_identity_digest: string;
      };
      const classifierConfig = {
        model: config.openai.model,
        serviceTier: config.openai.serviceTier,
      };
      try {
        config.openai.model = `${classifierConfig.model}-obsolete`;
        const obsoleteModel = db.classifierSourceIdentity(['v-tx'], PROMPT_VERSION);
        config.openai.model = classifierConfig.model;
        db.db.prepare(`
          UPDATE classifications
          SET source_identity_json=?, source_identity_digest=?
          WHERE issue_number=9103
        `).run(JSON.stringify(obsoleteModel), obsoleteModel.digest);
        assert.throws(
          () => scoring.persistReleaseScoreRun(txRun),
          /classifierSourceIdentityMismatches=1/,
        );

        config.openai.serviceTier = classifierConfig.serviceTier === 'priority' ? 'flex' : 'priority';
        const obsoleteTier = db.classifierSourceIdentity(['v-tx'], PROMPT_VERSION);
        config.openai.serviceTier = classifierConfig.serviceTier;
        db.db.prepare(`
          UPDATE classifications
          SET source_identity_json=?, source_identity_digest=?
          WHERE issue_number=9103
        `).run(JSON.stringify(obsoleteTier), obsoleteTier.digest);
        assert.throws(
          () => scoring.persistReleaseScoreRun(txRun),
          /classifierSourceIdentityMismatches=1/,
        );
      } finally {
        config.openai.model = classifierConfig.model;
        config.openai.serviceTier = classifierConfig.serviceTier;
        db.db.prepare(`
          UPDATE classifications
          SET source_identity_json=?, source_identity_digest=?
          WHERE issue_number=9103
        `).run(
          classificationSource.source_identity_json,
          classificationSource.source_identity_digest,
        );
      }
      const validResult = txRun.scored[0];
      const invalidResult = {
        ...validResult,
        rel: { ...validResult.rel, tag: 'v-missing' },
      };
      assert.throws(
        () => scoring.persistReleaseScoreRun({
          ...txRun,
          scored: [validResult, invalidResult],
        }),
        /fix-credit decisions are invalid/,
      );
      assert.equal(db.getRelease('v-tx')?.final_score, null);
      assert.equal(db.getReleaseScoreAudit('v-tx'), undefined);

      const recommendationDriftRun = structuredClone(txRun);
      recommendationDriftRun.scored[0].recommendationDecision!.selectedTag = 'v-missing';
      recommendationDriftRun.scored[0].explanation.recommendationDecision!.selectedTag = 'v-missing';
      assert.throws(
        () => scoring.persistReleaseScoreRun(recommendationDriftRun),
        /recommendation.*selectedTag|selectedTag.*recommendation/i,
      );

      const attestation = catalogAttestation(db, txRun.scored[0].scoredAt);
      assert.throws(
        () => scoring.persistReleaseScoreRun(txRun, {
          source: 'refresh',
          scope: 'v-tx',
          runId: 'bridge-test',
          codeRevision: 'bridge-test-revision',
        }),
        /valid final catalog attestation/,
      );
      assert.equal(db.getRelease('v-tx')?.final_score, null);
      const persistence = scoring.persistReleaseScoreRun(txRun, {
        source: 'refresh',
        scope: 'v-tx',
        runId: refreshFixture.runId,
        codeRevision: refreshFixture.codeRevision,
        catalogAttestation: attestation,
        clock: scoreCommitClock(refreshFixture),
      });
      assert.deepEqual(persistence.catalogAttestation, attestation);
      const rawScoreMeta = db.getMeta('score_persistence_last_run');
      assert.equal(typeof rawScoreMeta, 'string');
      const scoreMeta = JSON.parse(rawScoreMeta);
      assert.equal(scoreMeta.schemaVersion, 2);
      assert.equal(scoreMeta.source, 'refresh');
      assert.equal(scoreMeta.scope, 'v-tx');
      assert.equal(scoreMeta.operationRunId, 'bridge-test');
      assert.equal(scoreMeta.operationReceiptRequired, true);
      assert.equal(scoreMeta.codeRevision, 'bridge-test-revision');
      assert.deepEqual(scoreMeta.catalogAttestation, attestation);
      assert.equal(scoreMeta.scoredReleaseCount, 1);
      assert.deepEqual(scoreMeta.releaseTags, ['v-tx']);
      assert.equal(scoreMeta.recommendedTag, txRun.recommendedTag);
      assert.equal(scoreMeta.maxScoredAt, txRun.scored[0].scoredAt);
      assert.equal(scoreMeta.sourceIdentitySchemaVersion, txRun.sourceIdentity.schemaVersion);
      assert.equal(scoreMeta.sourceIdentityDigest, txRun.sourceIdentity.digest);
      assert.equal(scoreMeta.sourceIdentityRowCount, txRun.sourceIdentity.rowCount);
      assert.equal(scoreMeta.sourceIdentitySourceCount, txRun.sourceIdentity.sourceCount);
      assert.equal(db.getMeta('last_scored_at'), txRun.scored[0].scoredAt);
      assert.deepEqual(
        JSON.parse(db.getReleaseScoreAudit('v-tx')?.source_identity_json ?? 'null'),
        txRun.sourceIdentity,
      );
      finalizeRefreshPublicationFixture(
        db,
        scoring,
        refreshFixture,
        txRun,
        persistence,
      );

      const staleRun = scoring.buildReleaseScoreRun({
        releases: [db.getRelease('v-tx')],
        oldestScoredStablePredecessorTag: 'v1',
        nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
      });
      db.db.prepare(`
        UPDATE issues
        SET raw_json='{"changedAfterScoring":true}'
        WHERE number=9101
      `).run();
      assert.throws(
        () => scoring.persistReleaseScoreRun(staleRun),
        /source rows changed after scores were built and before persistence/,
      );

      db.upsertAdvisory({
        advisory_key: 'GHSA-malformed:npm:openclaw:^2026.6.0',
        ghsa_id: 'GHSA-malformed',
        cve_id: 'CVE-2026-9999',
        summary: 'Malformed advisory range',
        severity: 'medium',
        html_url: 'https://example.test/advisory',
        published_at: '2026-06-01T00:00:00Z',
        package_ecosystem: 'npm',
        package_name: 'openclaw',
        vulnerable_version_range: '^2026.6.0',
        patched_versions: '2026.6.10',
      });

      activateCatalog(db, ['v2', 'v1', 'v0']);
      assert.throws(
        () => scoring.buildReleaseScoreRun({
          releases: [db.getRelease('v1')],
          allFetchedTags: ['v2', 'v1'],
          stableTagsNewestFirst: ['v2', 'v1', 'v0'],
          oldestScoredStablePredecessorTag: 'v0',
          nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
        }),
        /malformed advisory vulnerable_version_range/,
      );
  });

});
