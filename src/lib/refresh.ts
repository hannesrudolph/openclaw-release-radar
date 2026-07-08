import { config } from '../config';
import { createHash, randomUUID } from 'node:crypto';
import { invalidateCache } from './cache';
import {
  AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
  commentEvidenceDigest,
  serializeCommentEvidence,
} from './commentEvidence';
import {
  GhComment,
  type GhRelease,
  type GhReleaseCatalog,
  type GhIssueCatalog,
  type GhIssueCatalogBoundaryVerification,
  type GhIssueCatalogMetadata,
  type GhIssueIncrementalSweepMetadata,
  type GhIssueLabelEvidenceSnapshot,
  type GhIssuePageMetadata,
  type GhIssueSnapshotBoundary,
  type GhAdvisory,
  type GhAdvisoryCatalog,
  type GhIssueCommentSnapshot,
  type GhIssueFixEvidence,
  type GhIssueLabelEvent,
  GhIssue,
  authorizeGithubReleaseCatalogPublication,
  fetchIssueCatalog,
  verifyIssueCatalogBoundary,
  fetchRepositoryCollaboratorPermissionSnapshot,
  fetchReleaseCatalog,
  getReleaseCommit as fetchReleaseCommit,
  listIssueCommentSnapshotsBatch,
  listIssueFixEvidenceBatch,
  listIssueLabelEvidenceSnapshotsBatch,
  listIssuesBatch,
  fetchSecurityAdvisorySourceObservations,
  paginateIssues,
} from './github';
import {
  ClassifierAttemptLedgerTerminalError,
  classifyIssueWithAttemptLedger,
  type ClassifyIssueWithAttemptLedgerResult,
  type IssueClassification,
  PROMPT_VERSION,
} from './llm';
import {
  CLASSIFIER_MODEL_CORRECTABLE_GROUNDING_DIAGNOSTIC_CODES,
} from './classifierAttemptLedger';
import {
  computeAggregateBreaking,
  computeBetaCount,
  computeHoursToNextRelease,
  computeHoursToNextStable,
  parseReleaseNotes,
} from './releaseNotes';
import { verifyNpmArtifact } from './npmRegistry';
import { verifyEvidenceReportUrl } from './releaseEvidence';
import {
  analyzeClosureProofsForRelease,
  closureProofCommentSnapshotDriftIssueNumbers,
  createClosureProofRunContext,
  discoverClosureProofDependenciesForRelease,
  issueStateSnapshotMetadataMatches,
  replaceVerifiedIssueStateEventSnapshot,
  refreshClosureEvidenceForRelease,
  refreshMutablePullRequestMetadata,
  unresolvedCommentSnapshotMetadataDriftIssueNumbers,
  unresolvedStateSnapshotMetadataDriftIssueNumbers,
  type ClosureProofPreparedDependencies,
  type ClosureProofRunContext,
} from './closureProofAnalysis';
import {
  checkReleasePrReachabilityForReleases,
  createReleaseReachabilityRefreshContext,
} from './releaseReachability';
import {
  buildReleaseScoreRun,
  captureReleaseValidationForecasts,
  finalizeReleaseScorePublicationMetadata,
  persistReleaseScoreRun,
  type ReleaseValidationForecastCaptureResult,
} from './releaseScoring';
import { SCORE_MODEL_VERSION } from './score';
import { codeRevisionFromEnv } from './codeRevision';
import {
  canonicalJson,
  operationEffectiveConfig,
  operationErrorDetails,
  type OperationStageStatus,
} from './operationReceipts';
import {
  buildReleaseArtifactPublicationScope,
} from './releaseArtifactPublicationScope';
import {
  buildClosureClaimCandidateLedgerEntry,
  extractClosureClaimCandidates,
  type ClosureClaimClosureEventSource,
  type ClosureClaimExtractionResult,
} from './closureClaimCandidates';
import {
  abortableDelay,
  composeAbortSignals,
  createAbortError,
  isAbortError,
  mapWithConcurrency,
  runCooperativeGroup,
  throwIfAborted,
  type CooperativeTask,
} from './cooperativeCancellation';

// Limited concurrency for LLM classification. During scoring calibration we may
// intentionally raise this through CLASSIFY_CONCURRENCY to burn tokens for speed.
const CLASSIFY_CONCURRENCY = config.refresh.classifyConcurrency;

function createStageTimer(
  now: () => number = Date.now,
  onStageComplete?: (stage: string, durationMs: number) => void,
  onStageEvent?: (event: {
    stage: string;
    status: OperationStageStatus;
    occurredAt: string;
    durationMs: number | null;
    counts: Record<string, unknown> | null;
    details: Record<string, unknown> | null;
  }) => void,
) {
  type FinishStage = (
    status?: OperationStageStatus,
    counts?: Record<string, unknown> | null,
    details?: Record<string, unknown> | null,
  ) => number;
  const completed: Record<string, number> = {};
  const active = new Map<string, {
    startedAt: number;
    baseMs: number;
    emitEvents: boolean;
  }>();
  const finishers = new Map<string, FinishStage>();
  const pendingFailures = new Map<string, unknown>();

  const snapshot = (): Record<string, number> => {
    const at = now();
    const result = { ...completed };
    for (const [stage, timing] of active) {
      result[stage] = timing.baseMs + Math.max(0, at - timing.startedAt);
    }
    return result;
  };

  const ensure = (stage: string): void => {
    completed[stage] ??= 0;
  };

  const start = (
    stage: string,
    options: { accumulate?: boolean; emitEvents?: boolean } = {},
  ): FinishStage => {
    if (active.has(stage)) throw new Error(`Timing stage "${stage}" is already active`);
    pendingFailures.delete(stage);
    const startedAt = now();
    const baseMs = options.accumulate ? completed[stage] ?? 0 : 0;
    const emitEvents = options.emitEvents !== false;
    active.set(stage, { startedAt, baseMs, emitEvents });
    try {
      if (emitEvents) {
        onStageEvent?.({
          stage,
          status: 'started',
          occurredAt: new Date(startedAt).toISOString(),
          durationMs: null,
          counts: null,
          details: options.accumulate ? { accumulate: true } : null,
        });
      }
    } catch (error) {
      active.delete(stage);
      throw error;
    }
    let finished = false;
    const finish: FinishStage = (
      status: OperationStageStatus = 'completed',
      counts: Record<string, unknown> | null = null,
      details: Record<string, unknown> | null = null,
    ) => {
      if (!finished) {
        const occurredAtMs = now();
        const elapsedMs = Math.max(0, occurredAtMs - startedAt);
        if (emitEvents) {
          onStageEvent?.({
            stage,
            status,
            occurredAt: new Date(occurredAtMs).toISOString(),
            durationMs: elapsedMs,
            counts,
            details,
          });
        }
        completed[stage] = baseMs + elapsedMs;
        active.delete(stage);
        finishers.delete(stage);
        pendingFailures.delete(stage);
        finished = true;
        onStageComplete?.(stage, completed[stage]);
      }
      return completed[stage];
    };
    finishers.set(stage, finish);
    return finish;
  };

  const timed = async <T>(
    stage: string,
    work: () => T | Promise<T>,
    options: { accumulate?: boolean; recoverable?: boolean } = {},
  ): Promise<T> => {
    const finish = start(stage, options);
    try {
      const result = await work();
      finish('completed', stageResultCounts(result));
      return result;
    } catch (error) {
      const recoverable = options.recoverable === true && !isAbortError(error);
      if (finishers.has(stage)) pendingFailures.set(stage, error);
      try {
        finish(recoverable ? 'completed' : 'failed', null, {
          outcome: recoverable ? 'degraded' : 'failed',
          error: operationErrorDetails(error),
        });
      } catch {
        throw error;
      }
      throw error;
    }
  };

  const failActive = (error: unknown): void => {
    const activeFinishers = [...finishers.entries()];
    if (activeFinishers.length === 0) return;
    const pendingStages = [...pendingFailures.keys()].filter((stage) =>
      finishers.has(stage));
    const primaryStage = pendingStages.find((stage) =>
      pendingFailures.get(stage) === error
    ) ?? pendingStages[0] ?? activeFinishers[0][0];
    const cleanupErrors: unknown[] = [];

    for (const [stage, finish] of activeFinishers) {
      if (stage === primaryStage) continue;
      const hasStageError = pendingFailures.has(stage);
      const stageError = hasStageError ? pendingFailures.get(stage) : error;
      const outcome = !hasStageError
        ? 'cancelled'
        : isAbortError(stageError) || stageError === error
          ? 'aborted'
          : 'superseded_failure';
      try {
        finish('completed', null, {
          outcome,
          error: operationErrorDetails(stageError),
          ...(stageError !== error
            ? { primaryError: operationErrorDetails(error) }
            : {}),
        });
      } catch (cleanupError) {
        cleanupErrors.push(cleanupError);
      }
    }

    const remainingSiblings = [...finishers.keys()].filter((stage) =>
      stage !== primaryStage);
    if (remainingSiblings.length > 0) {
      throw cleanupErrors[0] ?? new Error(
        `Failed to close active sibling stages: ${remainingSiblings.join(', ')}`,
      );
    }

    const finishPrimary = finishers.get(primaryStage);
    if (!finishPrimary) return;
    const primaryError = pendingFailures.has(primaryStage)
      ? pendingFailures.get(primaryStage)
      : error;
    finishPrimary('failed', null, {
      outcome: 'failed',
      error: operationErrorDetails(primaryError),
    });
  };

  const startCooperative = <const TStages extends readonly string[]>(
    stages: TStages,
  ) => {
    if (new Set(stages).size !== stages.length) {
      throw new Error('Cooperative timing stages must be unique');
    }
    const groupFinishers = new Map<TStages[number], FinishStage>();
    try {
      for (const stage of stages) {
        groupFinishers.set(stage, start(stage));
      }
    } catch (error) {
      try {
        failActive(error);
      } catch {
        // The orchestration failure path retries any stage left active.
      }
      throw error;
    }
    const invoked = new Set<TStages[number]>();

    return {
      async timed<T>(
        stage: TStages[number],
        work: () => T | Promise<T>,
      ): Promise<T> {
        const finish = groupFinishers.get(stage);
        if (!finish) {
          throw new Error(`Unknown cooperative timing stage "${stage}"`);
        }
        if (invoked.has(stage)) {
          throw new Error(`Cooperative timing stage "${stage}" was already invoked`);
        }
        invoked.add(stage);
        try {
          const result = await work();
          finish('completed', stageResultCounts(result));
          return result;
        } catch (error) {
          if (finishers.has(stage)) pendingFailures.set(stage, error);
          throw error;
        }
      },
      fail: failActive,
    };
  };

  return { ensure, snapshot, start, startCooperative, timed, failActive };
}

function stageResultCounts(value: unknown): Record<string, unknown> | null {
  if (Array.isArray(value)) return { items: value.length };
  if (value instanceof Map || value instanceof Set) return { items: value.size };
  if (typeof value === 'number' && Number.isFinite(value)) return { result: value };
  return null;
}

function createRefreshLeaseGuard(args: {
  name: string;
  holderId: string;
  ttlMs: number;
  now: () => string;
  acquire: (name: string, holderId: string, now: string, ttlMs: number) => boolean;
  renew: (name: string, holderId: string, now: string, ttlMs: number) => boolean;
  release: (name: string, holderId: string) => boolean;
  scheduleHeartbeat?: (callback: () => void, intervalMs: number) => unknown;
  cancelHeartbeat?: (handle: unknown) => void;
  onFailure?: (error: Error) => void;
}) {
  let acquired = false;
  let heartbeatHandle: unknown = null;
  let leaseFailure: Error | null = null;
  const scheduleHeartbeat = args.scheduleHeartbeat ?? ((callback: () => void, intervalMs: number) => {
    const handle = setInterval(callback, intervalMs);
    handle.unref();
    return handle;
  });
  const cancelHeartbeat = args.cancelHeartbeat ?? ((handle: unknown) => {
    clearInterval(handle as ReturnType<typeof setInterval>);
  });

  const stopHeartbeat = (): void => {
    if (heartbeatHandle == null) return;
    try {
      cancelHeartbeat(heartbeatHandle);
    } finally {
      heartbeatHandle = null;
    }
  };

  const rememberFailure = (error: unknown): Error => {
    const normalized = error instanceof Error ? error : new Error(String(error));
    if (leaseFailure) return leaseFailure;
    leaseFailure = normalized;
    stopHeartbeat();
    args.onFailure?.(leaseFailure);
    return leaseFailure;
  };

  const assertAcquired = (stage: string): void => {
    if (!acquired) throw new Error(`cannot use refresh lease before ${stage}: lease was not acquired`);
    if (leaseFailure) {
      throw new Error(
        `refresh lease "${args.name}" failed before ${stage}: ${leaseFailure.message}`,
        { cause: leaseFailure },
      );
    }
  };

  const assertHeld = (stage: string): void => {
    assertAcquired(stage);
    try {
      if (!args.renew(args.name, args.holderId, args.now(), args.ttlMs)) {
        throw new Error(`refresh lease "${args.name}" was lost before ${stage}`);
      }
    } catch (error) {
      throw rememberFailure(error);
    }
  };
  const renewNow = assertHeld;

  return {
    acquire(): void {
      if (acquired) return;
      if (!args.acquire(args.name, args.holderId, args.now(), args.ttlMs)) {
        throw new Error(`refresh already running in another process: lease "${args.name}" is held`);
      }
      acquired = true;
    },
    assertHeld,
    renew(stage: string): void {
      renewNow(stage);
    },
    startHeartbeat(intervalMs: number): void {
      assertAcquired('starting heartbeat');
      if (!Number.isFinite(intervalMs) || intervalMs <= 0) {
        throw new Error(`refresh lease heartbeat interval must be positive, got ${intervalMs}`);
      }
      if (heartbeatHandle != null) return;
      heartbeatHandle = scheduleHeartbeat(() => {
        if (!acquired || leaseFailure) return;
        try {
          renewNow('periodic heartbeat');
        } catch {
          // The failure is latched by renewNow and observed by the next guarded write.
        }
      }, intervalMs);
    },
    stopHeartbeat,
    heartbeatFailed(): boolean {
      return leaseFailure != null;
    },
    release(): boolean {
      if (!acquired) return false;
      stopHeartbeat();
      try {
        return args.release(args.name, args.holderId);
      } finally {
        acquired = false;
      }
    },
  };
}

function abortRefreshOnLeaseFailure(
  controller: AbortController,
): (error: Error) => void {
  return (error) => {
    if (!controller.signal.aborted) controller.abort(error);
  };
}

function runIssuePageEvidenceFetchGroup<TMetadata, TComments, TLabels, TState>(
  tasks: readonly [
    CooperativeTask<TMetadata>,
    CooperativeTask<TComments>,
    CooperativeTask<TLabels>,
    CooperativeTask<TState>,
  ],
  signal: AbortSignal,
): Promise<[TMetadata, TComments, TLabels, TState]> {
  return runCooperativeGroup(tasks, { signal });
}

function runLeaseFencedWrite<T>(
  stage: string,
  assertCanWrite: (stage: string) => void,
  write: () => T,
  transaction: typeof runInWriteTransaction = runInWriteTransaction,
): T {
  assertCanWrite(`${stage} persistence`);
  return transaction(() => {
    assertCanWrite(`${stage} transaction`);
    const result = write();
    assertCanWrite(`${stage} commit`);
    return result;
  });
}

type EvidenceFailureRecorder = (
  source: string,
  scope: string | null,
  error: unknown,
  context: Record<string, unknown>,
) => string;

class IssuePaginationFailure extends Error {
  readonly paginationCause: unknown;

  constructor(cause: unknown) {
    const message = cause instanceof Error ? cause.message : String(cause);
    super(`Issue pagination failed: ${message}`);
    this.name = 'IssuePaginationFailure';
    this.paginationCause = cause;
  }
}

async function* withIssuePaginationFailureBoundary<T>(pages: AsyncIterable<T>): AsyncGenerator<T, void, void> {
  const iterator = pages[Symbol.asyncIterator]();
  for (;;) {
    let result: IteratorResult<T, void>;
    try {
      result = await iterator.next();
    } catch (error) {
      throw new IssuePaginationFailure(error);
    }
    if (result.done) return;
    yield result.value;
  }
}

function failIssuePagination(args: {
  cause: unknown;
  scope: string;
  context: Record<string, unknown>;
  recordFailure: EvidenceFailureRecorder;
  buildCrawlMeta: () => Record<string, unknown>;
  persistCrawlMeta: (meta: Record<string, unknown>) => void;
}): never {
  let message: string;
  try {
    message = args.recordFailure('issue-pagination', args.scope, args.cause, args.context);
  } finally {
    args.persistCrawlMeta(args.buildCrawlMeta());
  }
  throw new Error(`${message}; refusing to persist scores from incomplete issue pagination`);
}

import {
  acquireRefreshLease,
  appendReleaseValidationProof,
  appendRefreshCaptureReceipt,
  appendRefreshOperationStageEvent,
  assertIssueEvidenceRevisions,
  beginRefreshOperationAttempt,
  classifierSourceIdentity,
  countStaleClassifications,
  createClassifierAttemptRecorder,
  deleteStaleClassifications,
  detectBot,
  getClassification,
  getClosureClaimCandidate,
  getIssue,
  getIssueCatalogSnapshot,
  getMeta,
  getRelease,
  getRefreshOperationAttempt,
  activateCompoundAdvisorySnapshot,
  compoundAdvisorySnapshotById,
  currentActiveReleaseCatalog,
  consumeIssueCatalogSnapshot,
  findResumableIssueCatalogSnapshot,
  insertIngestionEvidenceFailure,
  insertIssueCatalogSnapshot,
  persistClosureClaimExtraction,
  insertIssueLabelEvidenceSnapshot,
  insertRepositoryCollaboratorPermissionSnapshotV2,
  issueEvidenceRevisions,
  issuesForVersion,
  listReleasesDb,
  listReleaseValidationOpportunityEnrollments,
  openedDuringReign,
  persistReleaseArtifactVerification,
  releaseArtifactPublicationForRun,
  releaseRefreshLease,
  REFRESH_WRITE_LEASE_HEARTBEAT_MS,
  REFRESH_WRITE_LEASE_NAME,
  REFRESH_WRITE_LEASE_TTL_MS,
  releaseClosureProofIntegrity,
  stageCompoundAdvisorySnapshot,
  replaceActiveReleaseCatalog,
  insertReleaseValidationOpportunityEnrollments,
  projectActiveReleaseCatalog,
  readReleaseValidationProofBundle,
  renewRefreshLease,
  runWithPendingReleaseCatalogReadAuthority,
  runInWriteTransaction,
  scoreSourceIdentity,
  setMeta,
  supersedeIngestionEvidenceFailures,
  updateReleaseDerivedStats,
  updateReleaseArtifactVerification,
  validateIssueStateEventSnapshot,
  upsertClassification,
  upsertIssue,
  upsertIssueMetadata,
  upsertIssueCommentSnapshot,
  upsertIssueLabelEvent,
  upsertIssueLabelSnapshot,
  upsertReleaseCommit,
  type IssueRow,
  type IssueEvidenceRevision,
  type AcceptedClassifierClassificationInput,
  type ResumableIssueCatalogSnapshotResult,
} from './db';
import {
  RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
} from './releaseValidationProof';
import {
  planReleaseValidationProofLifecycle,
} from './releaseValidationProofLifecycle';
import {
  planReleaseValidationOpportunityEnrollments,
} from './releaseValidationOpportunityDenominator';
import {
  buildIssueLabelEvidenceSnapshot,
} from './issueLabelEvidenceSnapshot';
import {
  issueCatalogSnapshotCatalog,
  type IssueCatalogSnapshot,
} from './issueCatalogSnapshot';
import {
  releaseCatalogAttestationProblems,
  type ReleaseCatalogAttestation,
} from './releaseValidation';
import {
  ADVISORY_SNAPSHOT_META_KEY,
  ADVISORY_SNAPSHOT_V2_META_KEY,
  advisorySnapshotContentHash,
  advisorySnapshotRowProblems,
  advisoryVulnerabilityKey,
  buildCompoundAdvisorySnapshot,
  compoundAdvisorySnapshotMetadataDigest,
  type CompoundAdvisorySnapshotMetadata,
} from './advisorySnapshot';

interface IssueCatalogSnapshotResolution {
  snapshot: IssueCatalogSnapshot;
  resumed: boolean;
  priorStatus: ResumableIssueCatalogSnapshotResult['status'];
}

interface IssueCatalogSnapshotRunMetadata {
  schemaVersion: 1;
  snapshotId: string;
  contentHash: string;
  capturedAt: string;
  resumed: boolean;
  priorStatus: ResumableIssueCatalogSnapshotResult['status'];
  maxAgeHours: number;
  consumedAt: string | null;
  consumedByRunId: string | null;
  consumptionContentHash: string | null;
}

async function resolveIssueCatalogSnapshotForRefresh(args: {
  repository: string;
  observedAt: string;
  maxAgeMs: number;
  fetchCatalog: () => Promise<Awaited<ReturnType<typeof fetchIssueCatalog>>>;
  findSnapshot?: typeof findResumableIssueCatalogSnapshot;
  persistSnapshot?: typeof insertIssueCatalogSnapshot;
  captureNow?: () => string;
}): Promise<IssueCatalogSnapshotResolution> {
  const findSnapshot = args.findSnapshot ?? findResumableIssueCatalogSnapshot;
  const persistSnapshot = args.persistSnapshot ?? insertIssueCatalogSnapshot;
  const prior = findSnapshot({
    repository: args.repository,
    now: new Date(args.observedAt),
    maxAgeMs: args.maxAgeMs,
  });
  if (prior.status === 'resumable') {
    return {
      snapshot: prior.snapshot,
      resumed: true,
      priorStatus: prior.status,
    };
  }
  let catalog: Awaited<ReturnType<typeof fetchIssueCatalog>> | null =
    await args.fetchCatalog();
  const header = persistSnapshot({
    repository: args.repository,
    capturedAt: (args.captureNow ?? (() => new Date().toISOString()))(),
    catalog,
  });
  catalog = null;
  const snapshot = getIssueCatalogSnapshot(header.snapshotId);
  if (!snapshot) {
    throw new Error(`Persisted issue catalog snapshot ${header.snapshotId} could not be reloaded`);
  }
  return {
    snapshot,
    resumed: false,
    priorStatus: prior.status,
  };
}

function isMaintainerAssociation(association: string | null | undefined): boolean {
  return ['OWNER', 'MEMBER', 'COLLABORATOR'].includes(association ?? '');
}

function isContributorAssociation(association: string | null | undefined): boolean {
  return isMaintainerAssociation(association) || association === 'CONTRIBUTOR';
}

function commentCompleteness(expectedCount: number, comments: GhComment[]): {
  complete: boolean;
  expectedCount: number;
  fetchedCount: number;
  uniqueCount: number;
  invalidIdIndexes: number[];
  duplicateIds: number[];
} {
  const idCounts = new Map<number, number>();
  const invalidIdIndexes: number[] = [];
  comments.forEach((comment, index) => {
    if (!Number.isInteger(comment.id) || comment.id <= 0) {
      invalidIdIndexes.push(index);
      return;
    }
    idCounts.set(comment.id, (idCounts.get(comment.id) ?? 0) + 1);
  });
  const duplicateIds = [...idCounts.entries()]
    .filter(([, count]) => count > 1)
    .map(([id]) => id)
    .sort((a, b) => a - b);
  return {
    complete:
      comments.length === expectedCount &&
      invalidIdIndexes.length === 0 &&
      duplicateIds.length === 0,
    expectedCount,
    fetchedCount: comments.length,
    uniqueCount: idCounts.size,
    invalidIdIndexes,
    duplicateIds,
  };
}

function recordCommentCompletenessFailure(args: {
  snapshot: GhIssueCommentSnapshot;
  pageContext: Record<string, unknown>;
  recordFailure: EvidenceFailureRecorder;
}): string | null {
  const completeness = commentCompleteness(args.snapshot.totalCount, args.snapshot.comments);
  let digestMatches = true;
  if (completeness.complete) {
    try {
      digestMatches =
        commentEvidenceDigest(args.snapshot.totalCount, args.snapshot.comments) === args.snapshot.commentsDigest;
    } catch {
      digestMatches = false;
    }
  }
  const validUpdatedAt =
    typeof args.snapshot.issueUpdatedAt === 'string' &&
    Number.isFinite(Date.parse(args.snapshot.issueUpdatedAt));
  if (completeness.complete && digestMatches && validUpdatedAt) return null;
  const source = completeness.invalidIdIndexes.length > 0
    ? 'issue-comments-invalid-ids'
    : completeness.duplicateIds.length > 0
      ? 'issue-comments-duplicate-ids'
      : !completeness.complete
        ? 'issue-comments-count-mismatch'
        : !digestMatches
          ? 'issue-comments-digest-mismatch'
          : 'issue-comments-invalid-updated-at';
  const invalidIdSummary = completeness.invalidIdIndexes.length > 0
    ? `; missing or invalid comment IDs at indexes: ${completeness.invalidIdIndexes.join(', ')}`
    : '';
  const duplicateSummary = completeness.duplicateIds.length > 0
    ? `; duplicate comment IDs: ${completeness.duplicateIds.join(', ')}`
    : '';
  const digestSummary = digestMatches ? '' : '; snapshot digest did not match comment content';
  const updatedAtSummary = validUpdatedAt ? '' : '; snapshot issueUpdatedAt was invalid';
  return args.recordFailure(
    source,
    `issue #${args.snapshot.issueNumber}`,
    new Error(
      `expected exactly ${completeness.expectedCount} comments from stable snapshot totalCount, ` +
      `fetched ${completeness.fetchedCount} comments with ${completeness.uniqueCount} unique IDs` +
      `${invalidIdSummary}${duplicateSummary}${digestSummary}${updatedAtSummary}`,
    ),
    {
      ...args.pageContext,
      issueNumber: args.snapshot.issueNumber,
      issueUpdatedAt: args.snapshot.issueUpdatedAt,
      expectedCommentCount: completeness.expectedCount,
      fetchedCommentCount: completeness.fetchedCount,
      uniqueCommentCount: completeness.uniqueCount,
      invalidCommentIdIndexes: completeness.invalidIdIndexes,
      duplicateCommentIds: completeness.duplicateIds,
      expectedCountSource: 'snapshot.totalCount',
      fetchedCountSource: 'snapshot.comments',
      digestSource: 'snapshot.commentsDigest',
    },
  );
}

function recordIssueClassificationFailure(args: {
  issue: GhIssue;
  error: unknown;
  pageContext: Record<string, unknown>;
  recordFailure: EvidenceFailureRecorder;
}): string {
  return args.recordFailure(
    'issue-classification',
    `issue #${args.issue.number}`,
    args.error,
    {
      ...args.pageContext,
      phase: 'classify',
      issueNumber: args.issue.number,
      issueUpdatedAt: args.issue.updated_at,
      issueState: args.issue.state,
      issueUrl: args.issue.html_url,
    },
  );
}

function persistIssueStateEvidence(evidence: GhIssueFixEvidence): void {
  replaceVerifiedIssueStateEventSnapshot(evidence);
}

interface ClosureClaimEvidenceInput {
  issue: GhIssue;
  snapshot: GhIssueCommentSnapshot;
  fixEvidence: GhIssueFixEvidence;
  capturedAt: string;
}

function closureEventCloserRepository(
  evidence: GhIssueFixEvidence,
  event: GhIssueFixEvidence['closureEvents'][number],
): string | null {
  if (event.closerType !== 'PullRequest') {
    return event.closerType === 'Commit' ? issueRepositoryIdentity() : null;
  }
  if (!Number.isInteger(event.closerNumber) || Number(event.closerNumber) <= 0) {
    throw new Error(
      `Issue #${event.issueNumber} closure event ${event.eventId} ` +
        'has a pull request closer without a canonical number',
    );
  }
  const repositories = new Set(
    evidence.prLinks
      .filter((link) =>
        link.issueNumber === event.issueNumber &&
        link.source === 'ClosedEvent.closer' &&
        link.prNumber === event.closerNumber &&
        link.referencedAt === event.closedAt)
      .map((link) => link.prRepositoryNameWithOwner)
      .filter((repository): repository is string => repository != null),
  );
  if (repositories.size !== 1) {
    throw new Error(
      `Issue #${event.issueNumber} closure event ${event.eventId} ` +
        `requires one exact pull request repository identity; found ${repositories.size}`,
    );
  }
  return [...repositories][0];
}

function issueAuthorIdentityMatchesSnapshot(
  issue: GhIssue,
  snapshot: GhIssueCommentSnapshot,
): boolean {
  return issue.user != null &&
    snapshot.issueAuthor != null &&
    issue.user.id === snapshot.issueAuthor.nodeId &&
    issue.user.login === snapshot.issueAuthor.login &&
    issue.user.type === snapshot.issueAuthor.actorType;
}

function acceptedClosureClaimExtraction(
  issueNumber: number,
  extraction: ClosureClaimExtractionResult,
): ClosureClaimExtractionResult {
  if (extraction.rejections.length > 0) {
    throw new Error(
      `Issue #${issueNumber} closure claim extraction rejected ` +
        `${extraction.rejections.length} source(s): ` +
        extraction.rejections
          .slice(0, 3)
          .map((rejection) =>
            `${rejection.sourceKind}:${rejection.sourceNodeId ?? '<missing>'}:` +
            `${rejection.code}`)
          .join(', '),
    );
  }
  const displayOnly = extraction.candidates.filter(
    (candidate) => candidate.eligibility !== 'immutable',
  );
  if (displayOnly.length > 0) {
    throw new Error(
      `Issue #${issueNumber} closure claim extraction produced ` +
        `${displayOnly.length} identity-incomplete candidate(s): ` +
        displayOnly
          .slice(0, 3)
          .map((candidate) =>
            `${candidate.claimKind}[${candidate.identityProblems.join('|')}]`)
          .join(', '),
    );
  }
  return extraction;
}

function closureClaimExtractionForIssue(
  input: Omit<ClosureClaimEvidenceInput, 'capturedAt'>,
): ClosureClaimExtractionResult {
  const { issue, snapshot, fixEvidence } = input;
  if (
    snapshot.issueNumber !== issue.number ||
    snapshot.issueNodeId !== issue.node_id ||
    snapshot.issueNodeType !== issue.node_type ||
    fixEvidence.issueNumber !== issue.number ||
    fixEvidence.issueNodeId !== issue.node_id ||
    fixEvidence.issueNodeType !== issue.node_type
  ) {
    throw new Error(
      `Issue #${issue.number} closure claim extraction identity does not match ` +
      'the accepted issue revision',
    );
  }
  const issueUser = issue.user;
  const snapshotAuthor = snapshot.issueAuthor;
  if (
    issueUser == null ||
    snapshotAuthor == null ||
    !issueAuthorIdentityMatchesSnapshot(issue, snapshot)
  ) {
    throw new Error(
      `Issue #${issue.number} closure claim extraction author identity does not match ` +
        'the accepted comment snapshot',
    );
  }
  const repositoryNodeIds = new Set([
    snapshot.repositoryNodeId,
    fixEvidence.repositoryNodeId,
    fixEvidence.stateSnapshot.repositoryNodeId,
  ]);
  if (repositoryNodeIds.size !== 1) {
    throw new Error(
      `Issue #${issue.number} closure claim extraction has conflicting repository identities`,
    );
  }
  if (!issueStateSnapshotMetadataMatches(fixEvidence, issue, snapshot)) {
    throw new Error(
      `Issue #${issue.number} closure claim extraction requires one stabilized ` +
        'comment and state-event revision',
    );
  }
  const issueAuthor = {
    nodeId: issueUser.id,
    login: issueUser.login,
    type: issueUser.type,
  };
  const closureEvents: ClosureClaimClosureEventSource[] =
    fixEvidence.closureEvents.map((event) => ({
      nodeId: event.eventId,
      url: null,
      actor: {
        nodeId: event.actorNodeId,
        login: event.actorLogin,
        type: event.actorType,
      },
      occurredAt: event.closedAt,
      stateReason: event.stateReason,
      closer: event.closerType == null
        ? null
        : {
            nodeId: event.closerNodeId,
            type: event.closerType,
            number: event.closerNumber,
            oid: event.closerOid,
            repositoryNameWithOwner:
              closureEventCloserRepository(fixEvidence, event),
          },
    }));
  const extraction = extractClosureClaimCandidates({
    repository: {
      nodeId: snapshot.repositoryNodeId,
      nameWithOwner: issueRepositoryIdentity(),
    },
    issue: {
      nodeId: issue.node_id,
      number: issue.number,
      author: issueAuthor,
    },
    issueBody: {
      nodeId: issue.node_id,
      databaseId: null,
      url: issue.html_url,
      actor: issueAuthor,
      createdAt: issue.created_at,
      updatedAt: issue.updated_at,
      body: issue.body,
    },
    comments: snapshot.comments.map((comment) => ({
      nodeId: comment.node_id,
      databaseId: comment.id,
      url: comment.url ?? null,
      actor: {
        nodeId: comment.user?.id ?? null,
        login: comment.user?.login ?? null,
        type: comment.user?.type ?? null,
      },
      createdAt: comment.created_at,
      updatedAt: comment.updated_at ?? comment.created_at,
      body: comment.body,
    })),
    closureEvents,
  });
  return acceptedClosureClaimExtraction(issue.number, extraction);
}

function persistClosureClaimEvidenceForIssue(
  input: ClosureClaimEvidenceInput,
): {
  extraction: ClosureClaimExtractionResult;
  persistence: ReturnType<typeof persistClosureClaimExtraction>;
} {
  const extraction = closureClaimExtractionForIssue(input);
  const persistence = persistClosureClaimExtraction({
    issueNumber: input.issue.number,
    extraction,
    capturedAt: input.capturedAt,
  });
  const expectedIds = extraction.candidates
    .map((candidate) => candidate.candidateId)
    .filter((candidateId): candidateId is string => candidateId != null)
    .sort();
  const persistedIds = persistence.candidatePersistence.candidateIds
    .slice()
    .sort();
  if (canonicalJson(expectedIds) !== canonicalJson(persistedIds)) {
    throw new Error(
      `Issue #${input.issue.number} closure claim persistence did not return ` +
        'the exact extracted candidate set',
    );
  }
  const expectedHashes = extraction.candidates
    .map((candidate) => {
      const entry = buildClosureClaimCandidateLedgerEntry(candidate);
      return {
        candidateId: entry.candidateId,
        contentHash: entry.contentHash,
      };
    })
    .sort((left, right) => left.candidateId.localeCompare(right.candidateId));
  const persistedHashes = persistence.candidatePersistence.candidateIds
    .map((candidateId) => {
      const candidate = getClosureClaimCandidate(candidateId);
      if (!candidate) {
        throw new Error(
          `Issue #${input.issue.number} closure claim persistence did not make ` +
            `candidate ${candidateId} readable`,
        );
      }
      const entry = buildClosureClaimCandidateLedgerEntry(candidate);
      return {
        candidateId: entry.candidateId,
        contentHash: entry.contentHash,
      };
    })
    .sort((left, right) => left.candidateId.localeCompare(right.candidateId));
  if (canonicalJson(expectedHashes) !== canonicalJson(persistedHashes)) {
    throw new Error(
      `Issue #${input.issue.number} closure claim persistence did not preserve ` +
        'the exact extracted candidate hashes',
    );
  }
  return { extraction, persistence };
}

type IssueCommentMetadata = Pick<GhIssue, 'number' | 'updated_at' | 'comments'> |
  Pick<IssueRow, 'number' | 'updated_at' | 'comments'>;

interface ReconciledIssueEvidence {
  issue: GhIssue;
  snapshot: GhIssueCommentSnapshot;
  labelEvidenceSnapshot: GhIssueLabelEvidenceSnapshot;
  fixEvidence: GhIssueFixEvidence;
}

type RefreshClassifierResult =
  | IssueClassification
  | ClassifyIssueWithAttemptLedgerResult;

type RefreshClassifier = (
  issue: GhIssue,
  comments: GhComment[],
  knownTags: string[],
  signal?: AbortSignal,
) => Promise<RefreshClassifierResult>;

interface StagedIssueClassification {
  classification: IssueClassification;
  acceptedClassifier: Omit<
    AcceptedClassifierClassificationInput,
    'evidenceRevisions'
  > | null;
}

interface IssueReconciliationDependencies {
  listIssues: typeof listIssuesBatch;
  listSnapshots: typeof listIssueCommentSnapshotsBatch;
  listLabelEvidence: typeof listIssueLabelEvidenceSnapshotsBatch;
  listFixEvidence: typeof listIssueFixEvidenceBatch;
  classify: RefreshClassifier;
  sleep: (ms: number, signal?: AbortSignal) => Promise<void>;
}

const ISSUE_RECONCILE_MAX_ATTEMPTS = 3;
const ISSUE_RECONCILE_RETRY_BASE_MS = 100;

async function classifyIssueDurably(
  issue: GhIssue,
  comments: GhComment[],
  knownTags: string[],
  signal?: AbortSignal,
): Promise<ClassifyIssueWithAttemptLedgerResult> {
  return classifyIssueWithAttemptLedger(issue, comments, knownTags, {
    recorder: createClassifierAttemptRecorder(),
    signal,
  });
}

function cooperativeClassifierAbort(error: unknown): Error | null {
  if (isAbortError(error)) return error;
  if (
    error instanceof ClassifierAttemptLedgerTerminalError &&
    error.terminalStatus === 'abandoned'
  ) {
    return createAbortError(error);
  }
  return null;
}

const ACCUMULABLE_CLASSIFIER_GROUNDING_DIAGNOSTIC_CODES = new Set<string>(
  CLASSIFIER_MODEL_CORRECTABLE_GROUNDING_DIAGNOSTIC_CODES,
);

function accumulableClassifierGroundingFailure(error: unknown): boolean {
  if (
    !(error instanceof ClassifierAttemptLedgerTerminalError) ||
    error.terminalStatus !== 'terminal_failure'
  ) {
    return false;
  }
  const lastAttempt = error.ledger.attempts.at(-1);
  if (
    lastAttempt?.status !== 'semantic_rejection' ||
    lastAttempt.semanticDiagnostics.length === 0
  ) {
    return false;
  }
  if (
    error.ledger.receipt.reason !== 'deterministic_semantic_rejection' &&
    error.ledger.receipt.reason !== 'attempt_budget_exhausted'
  ) {
    return false;
  }
  return lastAttempt.semanticDiagnostics.every((diagnostic) =>
    ACCUMULABLE_CLASSIFIER_GROUNDING_DIAGNOSTIC_CODES.has(diagnostic.code)
  );
}

function stagedIssueClassification(
  result: RefreshClassifierResult,
): StagedIssueClassification {
  if (
    result &&
    typeof result === 'object' &&
    'terminalStatus' in result
  ) {
    if (result.terminalStatus !== 'accepted_success') {
      throw new Error(
        `Classifier returned non-accepted terminal status ${String(result.terminalStatus)}`,
      );
    }
    return {
      classification: result.classification,
      acceptedClassifier: {
        ledger: result.ledger,
        selectedAttemptBinding: result.selectedAttemptBinding,
      },
    };
  }
  if (result.provenance) {
    throw new Error(
      'Raw-model classification is missing its accepted classifier attempt receipt',
    );
  }
  return {
    classification: result,
    acceptedClassifier: null,
  };
}

function acceptedIssueCommentSnapshot(
  requestedIssueNumber: number,
  snapshot: GhIssueCommentSnapshot | undefined,
): GhIssueCommentSnapshot {
  if (!snapshot) {
    throw new Error(`GitHub comment snapshot missing requested issue #${requestedIssueNumber}`);
  }
  if (snapshot.issueNumber !== requestedIssueNumber) {
    throw new Error(
      `GitHub comment snapshot key #${requestedIssueNumber} returned issue #${snapshot.issueNumber}`,
    );
  }
  if (!snapshot.issueUpdatedAt || !Number.isFinite(Date.parse(snapshot.issueUpdatedAt))) {
    throw new Error(`GitHub comment snapshot for issue #${requestedIssueNumber} has invalid issueUpdatedAt`);
  }
  const canonical = {
    ...snapshot,
    comments: [...snapshot.comments].sort(compareClassifierCommentOrder),
  };
  issueCommentSnapshot(canonical);
  return canonical;
}

function compareClassifierCommentOrder(left: GhComment, right: GhComment): number {
  const created = compareNullableCommentField(left.created_at, right.created_at);
  if (created !== 0) return created;
  const updated = compareNullableCommentField(left.updated_at, right.updated_at);
  if (updated !== 0) return updated;
  return left.id - right.id;
}

function compareNullableCommentField(
  left: string | null | undefined,
  right: string | null | undefined,
): number {
  if (left === right) return 0;
  if (left == null) return -1;
  if (right == null) return 1;
  return left < right ? -1 : 1;
}

function issueMetadataMatchesSnapshot(
  issue: IssueCommentMetadata | undefined,
  snapshot: GhIssueCommentSnapshot,
): boolean {
  return !!issue &&
    issue.number === snapshot.issueNumber &&
    issue.updated_at === snapshot.issueUpdatedAt &&
    issue.comments === snapshot.totalCount;
}

function issueStateMetadataMatchesSnapshot(
  issue: IssueCommentMetadata & Pick<GhIssue, 'state'> | undefined,
  snapshot: GhIssueCommentSnapshot,
  evidence: GhIssueFixEvidence | undefined,
): boolean {
  return issueStateSnapshotMetadataMatches(evidence, issue, snapshot);
}

function reconciledIssueEvidenceIdentityMatches(
  requestedIssueNumber: number,
  issue: GhIssue,
  commentSnapshot: GhIssueCommentSnapshot,
  labelSnapshot: GhIssueLabelEvidenceSnapshot,
  fixEvidence: GhIssueFixEvidence,
): boolean {
  const stateSnapshot = fixEvidence.stateSnapshot;
  return issue.number === requestedIssueNumber &&
    commentSnapshot.issueNumber === requestedIssueNumber &&
    labelSnapshot.issueNumber === requestedIssueNumber &&
    fixEvidence.issueNumber === requestedIssueNumber &&
    stateSnapshot.issueNumber === requestedIssueNumber &&
    commentSnapshot.repositoryNodeId === labelSnapshot.repositoryNodeId &&
    commentSnapshot.repositoryNodeId === fixEvidence.repositoryNodeId &&
    commentSnapshot.repositoryNodeId === stateSnapshot.repositoryNodeId &&
    issue.node_id === commentSnapshot.issueNodeId &&
    issue.node_id === labelSnapshot.issueNodeId &&
    issue.node_id === fixEvidence.issueNodeId &&
    issue.node_type === 'Issue' &&
    commentSnapshot.issueNodeType === issue.node_type &&
    labelSnapshot.issueNodeType === issue.node_type &&
    fixEvidence.issueNodeType === issue.node_type &&
    issue.updated_at === commentSnapshot.issueUpdatedAt &&
    issue.updated_at === labelSnapshot.issueUpdatedAt &&
    issue.updated_at === stateSnapshot.issueUpdatedAt &&
    issueMetadataMatchesSnapshot(issue, commentSnapshot) &&
    issueStateMetadataMatchesSnapshot(issue, commentSnapshot, fixEvidence);
}

function reconciledIssueEvidenceIdentityDiagnostics(
  requestedIssueNumber: number,
  issue: GhIssue,
  commentSnapshot: GhIssueCommentSnapshot,
  labelSnapshot: GhIssueLabelEvidenceSnapshot,
  fixEvidence: GhIssueFixEvidence,
): string {
  const stateSnapshot = fixEvidence.stateSnapshot;
  return [
    `requested=(issueNumber=${requestedIssueNumber})`,
    `issue=(repositoryNodeId=<not-exposed>,issueNumber=${issue.number},` +
      `issueNodeId=${issue.node_id},issueNodeType=${issue.node_type},` +
      `issueUpdatedAt=${issue.updated_at})`,
    `commentSnapshot=(repositoryNodeId=${commentSnapshot.repositoryNodeId},` +
      `issueNumber=${commentSnapshot.issueNumber},issueNodeId=${commentSnapshot.issueNodeId},` +
      `issueNodeType=${commentSnapshot.issueNodeType},` +
      `issueUpdatedAt=${commentSnapshot.issueUpdatedAt})`,
    `labelSnapshot=(repositoryNodeId=${labelSnapshot.repositoryNodeId},` +
      `issueNumber=${labelSnapshot.issueNumber},issueNodeId=${labelSnapshot.issueNodeId},` +
      `issueNodeType=${labelSnapshot.issueNodeType},` +
      `issueUpdatedAt=${labelSnapshot.issueUpdatedAt})`,
    `fixEvidence=(repositoryNodeId=${fixEvidence.repositoryNodeId},` +
      `issueNumber=${fixEvidence.issueNumber},issueNodeId=${fixEvidence.issueNodeId},` +
      `issueNodeType=${fixEvidence.issueNodeType},issueUpdatedAt=<state-snapshot>)`,
    `stateSnapshot=(repositoryNodeId=${stateSnapshot.repositoryNodeId},` +
      `issueNumber=${stateSnapshot.issueNumber},issueNodeId=<digest-bound>,` +
      `issueNodeType=<digest-bound>,issueUpdatedAt=${stateSnapshot.issueUpdatedAt})`,
  ].join(' ');
}

function persistedIssueStateMetadataMatchesSnapshot(
  issue: (IssueCommentMetadata & { state: string }) | undefined,
  snapshot: GhIssueCommentSnapshot,
): boolean {
  if (!issue) return false;
  const validation = validateIssueStateEventSnapshot(issue.number);
  const persisted = validation.snapshot;
  return validation.reusable &&
    !!persisted &&
    persisted.repository_node_id === snapshot.repositoryNodeId &&
    persisted.issue_number === issue.number &&
    persisted.issue_state === issue.state &&
    persisted.issue_updated_at === issue.updated_at &&
    persisted.issue_updated_at === snapshot.issueUpdatedAt &&
    persisted.fetched_count === persisted.total_count;
}

function issueRowFromSnapshot(issue: GhIssue, snapshot: GhIssueCommentSnapshot): IssueRow {
  if (
    issue.node_id !== snapshot.issueNodeId ||
    issue.node_type !== snapshot.issueNodeType ||
    !issueAuthorIdentityMatchesSnapshot(issue, snapshot)
  ) {
    throw new Error(
      `Issue #${issue.number} metadata identity does not match its stabilized comment snapshot`,
    );
  }
  const author = issue.user?.login ?? null;
  const labels = JSON.stringify(issue.labels.map((label) => label.name));
  const stats = commentStats(snapshot);
  return {
    number: issue.number,
    node_id: issue.node_id,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    author,
    author_node_id: issue.user?.id ?? null,
    author_type: issue.user?.type ?? null,
    author_association: issue.author_association ?? null,
    html_url: issue.html_url,
    created_at: issue.created_at,
    updated_at: snapshot.issueUpdatedAt,
    closed_at: issue.closed_at,
    comments: snapshot.totalCount,
    unique_human_commenters: stats.unique_human_commenters,
    maintainer_commenters: stats.maintainer_commenters,
    contributor_commenters: stats.contributor_commenters,
    commenter_scan_truncated: stats.commenter_scan_truncated,
    reaction_total: issue.reaction_total ?? 0,
    positive_reactions: issue.positive_reactions ?? 0,
    labels,
    is_bot: detectBot(author, labels) ? 1 : 0,
    raw_json: JSON.stringify(issue),
  };
}

function issueRowFromRemoteMetadata(issue: GhIssue): IssueRow {
  const author = issue.user?.login ?? null;
  const labels = JSON.stringify(issue.labels.map((label) => label.name));
  return {
    number: issue.number,
    node_id: issue.node_id,
    state: issue.state,
    title: issue.title,
    body: issue.body,
    author,
    author_node_id: issue.user?.id ?? null,
    author_type: issue.user?.type ?? null,
    author_association: issue.author_association ?? null,
    html_url: issue.html_url,
    created_at: issue.created_at,
    updated_at: issue.updated_at,
    closed_at: issue.closed_at,
    comments: issue.comments,
    reaction_total: issue.reaction_total ?? 0,
    positive_reactions: issue.positive_reactions ?? 0,
    labels,
    is_bot: detectBot(author, labels) ? 1 : 0,
    raw_json: JSON.stringify(issue),
  };
}

function issueRemoteMetadataMatchesPersisted(
  persisted: IssueRow | undefined,
  remote: IssueRow,
): boolean {
  if (!persisted) return false;
  return (
    persisted.number === remote.number &&
    (persisted.node_id ?? null) === (remote.node_id ?? null) &&
    persisted.state === remote.state &&
    persisted.title === remote.title &&
    (persisted.body ?? null) === (remote.body ?? null) &&
    persisted.author === remote.author &&
    (persisted.author_node_id ?? null) === (remote.author_node_id ?? null) &&
    (persisted.author_type ?? null) === (remote.author_type ?? null) &&
    (persisted.author_association ?? null) === (remote.author_association ?? null) &&
    persisted.html_url === remote.html_url &&
    persisted.created_at === remote.created_at &&
    persisted.updated_at === remote.updated_at &&
    persisted.closed_at === remote.closed_at &&
    persisted.comments === remote.comments &&
    (persisted.reaction_total ?? 0) === (remote.reaction_total ?? 0) &&
    (persisted.positive_reactions ?? 0) === (remote.positive_reactions ?? 0) &&
    persisted.labels === remote.labels &&
    persisted.is_bot === remote.is_bot
  );
}

function stagedIssueRequiresMetadataReconciliation(
  stagedIssue: GhIssue,
  remoteIssue: GhIssue,
  snapshot: GhIssueCommentSnapshot,
  stateEvidence: GhIssueFixEvidence | undefined,
): boolean {
  return !issueRemoteMetadataMatchesPersisted(
    issueRowFromRemoteMetadata(stagedIssue),
    issueRowFromRemoteMetadata(remoteIssue),
  ) ||
    !issueMetadataMatchesSnapshot(remoteIssue, snapshot) ||
    !issueStateMetadataMatchesSnapshot(remoteIssue, snapshot, stateEvidence);
}

function issuePageEvidenceTargets(
  page: GhIssue[],
  overlapsMonitoredWindow: (issue: GhIssue) => boolean,
): {
  commentIssueNumbers: number[];
  metadataOnlyIssueNumbers: number[];
} {
  const commentIssueNumbers: number[] = [];
  const metadataOnlyIssueNumbers: number[] = [];
  for (const issue of page) {
    if (overlapsMonitoredWindow(issue)) commentIssueNumbers.push(issue.number);
    else metadataOnlyIssueNumbers.push(issue.number);
  }
  return { commentIssueNumbers, metadataOnlyIssueNumbers };
}

function persistReconciledIssueEvidence(
  evidence: ReconciledIssueEvidence,
  snapshotAt: string,
  stagedClassification?: StagedIssueClassification,
  sourceIdentity?: ReturnType<typeof classifierSourceIdentity>,
): void {
  const row = issueRowFromSnapshot(evidence.issue, evidence.snapshot);
  upsertIssueCommentSnapshot(issueCommentSnapshot(evidence.snapshot));
  upsertIssue(row);
  for (const event of evidence.labelEvidenceSnapshot.events) {
    upsertIssueLabelEvent({
      issue_number: event.issueNumber,
      issue_node_id: event.issueNodeId,
      event_id: event.eventId,
      action: event.action,
      label_name: event.labelName,
      actor_node_id: event.actorNodeId,
      actor_login: event.actorLogin,
      actor_type: event.actorType,
      created_at: event.createdAt,
      raw_json: JSON.stringify(event.raw),
    });
  }
  insertIssueLabelEvidenceSnapshot(
    buildIssueLabelEvidenceSnapshot(evidence.labelEvidenceSnapshot),
  );
  upsertIssueLabelSnapshot({
    issue_number: row.number,
    issue_node_id: row.node_id ?? null,
    snapshot_at: snapshotAt,
    labels_json: row.labels,
  });
  persistIssueStateEvidence(evidence.fixEvidence);
  persistClosureClaimEvidenceForIssue({
    issue: evidence.issue,
    snapshot: evidence.snapshot,
    fixEvidence: evidence.fixEvidence,
    capturedAt: snapshotAt,
  });
  if (stagedClassification) {
    if (!sourceIdentity) throw new Error(`Missing classifier source identity for issue #${row.number}`);
    const revisions = issueEvidenceRevisions([row.number]).get(row.number);
    if (!revisions) {
      throw new Error(`Missing persisted classifier source revisions for issue #${row.number}`);
    }
    upsertClassificationForSnapshot(
      row.number,
      stagedClassification,
      evidence.snapshot,
      sourceIdentity,
      revisions,
    );
  }
}

async function fetchReconciledIssueEvidence(
  issueNumbers: number[],
  options: {
    maxAttempts?: number;
    dependencies?: Partial<IssueReconciliationDependencies>;
    signal?: AbortSignal;
  } = {},
): Promise<Map<number, ReconciledIssueEvidence>> {
  const requested = [...new Set(issueNumbers)].filter((number) => Number.isInteger(number) && number > 0);
  if (requested.length === 0) return new Map();
  const maxAttempts = options.maxAttempts ?? ISSUE_RECONCILE_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new Error(`Issue reconciliation maxAttempts must be a positive integer, got ${maxAttempts}`);
  }
  const dependencies: IssueReconciliationDependencies = {
    listIssues: listIssuesBatch,
    listSnapshots: listIssueCommentSnapshotsBatch,
    listLabelEvidence: listIssueLabelEvidenceSnapshotsBatch,
    listFixEvidence: listIssueFixEvidenceBatch,
    classify: classifyIssueDurably,
    sleep: abortableDelay,
    ...options.dependencies,
  };
  const reconciled = new Map<number, ReconciledIssueEvidence>();
  let pending = requested;
  let lastError: unknown = null;

  for (let attempt = 1; attempt <= maxAttempts && pending.length > 0; attempt++) {
    throwIfAborted(options.signal);
    try {
      const [issues, snapshots, labelEvidence, fixEvidence] =
        await runCooperativeGroup([
          (signal) => dependencies.listIssues(pending, { signal }),
          (signal) => dependencies.listSnapshots(pending, { signal }),
          (signal) => dependencies.listLabelEvidence(pending, { signal }),
          (signal) => dependencies.listFixEvidence(pending, { signal }),
        ] as const, { signal: options.signal });
      const unresolved: number[] = [];
      const mismatchDetails: string[] = [];
      for (const issueNumber of pending) {
        const issue = issues.get(issueNumber);
        const snapshot = acceptedIssueCommentSnapshot(issueNumber, snapshots.get(issueNumber));
        const labels = labelEvidence.get(issueNumber);
        const stateEvidence = fixEvidence.get(issueNumber);
        if (!issue || !labels || !stateEvidence) {
          unresolved.push(issueNumber);
          mismatchDetails.push(
            `#${issueNumber} missing ${[
              !issue ? 'full issue' : null,
              !labels ? 'label evidence' : null,
              !stateEvidence ? 'fix evidence' : null,
            ].filter(Boolean).join(', ')}`,
          );
          continue;
        }
        if (!reconciledIssueEvidenceIdentityMatches(
          issueNumber,
          issue,
          snapshot,
          labels,
          stateEvidence,
        )) {
          unresolved.push(issueNumber);
          mismatchDetails.push(
            `#${issueNumber} ${reconciledIssueEvidenceIdentityDiagnostics(
              issueNumber,
              issue,
              snapshot,
              labels,
              stateEvidence,
            )}`,
          );
          continue;
        }
        reconciled.set(issueNumber, {
          issue,
          snapshot,
          labelEvidenceSnapshot: labels,
          fixEvidence: stateEvidence,
        });
      }
      if (unresolved.length === 0) return reconciled;
      pending = unresolved;
      lastError = new Error(`Issue metadata did not match stable comment/state snapshots: ${mismatchDetails.join('; ')}`);
    } catch (error) {
      lastError = error;
    }
    if (attempt < maxAttempts) {
      await dependencies.sleep(
        ISSUE_RECONCILE_RETRY_BASE_MS * attempt,
        options.signal,
      );
    }
  }

  const message = lastError instanceof Error ? lastError.message : String(lastError);
  throw new Error(
    `Failed to reconcile issue metadata for ${pending.map((number) => `#${number}`).join(', ')} ` +
    `after ${maxAttempts} attempts: ${message}`,
    { cause: lastError },
  );
}

export async function reconcileIssueCommentSnapshots(args: {
  issueNumbers: number[];
  releaseTags: string[];
  snapshotsByIssue?: Map<number, GhIssueCommentSnapshot>;
  classifyIssueNumbers?: number[];
  accumulateGroundingFailures?: boolean;
  classificationConcurrency?: number;
  snapshotAt?: string;
  maxAttempts?: number;
  assertCanWrite?: (stage: string) => void;
  expectedRevisions?: Map<number, IssueEvidenceRevision>;
  signal?: AbortSignal;
  dependencies?: Partial<IssueReconciliationDependencies>;
}): Promise<{
  snapshotsByIssue: Map<number, GhIssueCommentSnapshot>;
  issuesByNumber: Map<number, GhIssue>;
  labelEventsByIssue: Map<number, GhIssueLabelEvent[]>;
  labelEvidenceSnapshotsByIssue: Map<number, GhIssueLabelEvidenceSnapshot>;
  stateEvidenceByIssue: Map<number, GhIssueFixEvidence>;
  reconciledIssueNumbers: number[];
  classifiedIssueNumbers: number[];
  classificationFailures: Array<{
    issueNumber: number;
    issue: GhIssue;
    error: unknown;
  }>;
}> {
  const requested = [...new Set(args.issueNumbers)].filter((number) => Number.isInteger(number) && number > 0);
  const expectedRevisions = args.expectedRevisions ?? issueEvidenceRevisions(requested);
  const sourceIdentity = classifierSourceIdentity(args.releaseTags, PROMPT_VERSION);
  const snapshots = new Map(args.snapshotsByIssue ?? []);
  const missingSnapshots = requested.filter((issueNumber) => !snapshots.has(issueNumber));
  if (missingSnapshots.length > 0) {
    const fetched = await (
      args.dependencies?.listSnapshots ?? listIssueCommentSnapshotsBatch
    )(missingSnapshots, { signal: args.signal });
    for (const [issueNumber, snapshot] of fetched) snapshots.set(issueNumber, snapshot);
  }
  for (const issueNumber of requested) {
    snapshots.set(
      issueNumber,
      acceptedIssueCommentSnapshot(issueNumber, snapshots.get(issueNumber)),
    );
  }

  const persistedMismatches = requested.filter((issueNumber) =>
    !issueMetadataMatchesSnapshot(getIssue(issueNumber), snapshots.get(issueNumber)!),
  );
  const stateSnapshotMismatches = requested.filter((issueNumber) =>
    !persistedIssueStateMetadataMatchesSnapshot(
      getIssue(issueNumber),
      snapshots.get(issueNumber)!,
    ),
  );
  const staleClassifications = requested.filter((issueNumber) =>
    !classificationMatchesSnapshot(
      getClassification(issueNumber),
      snapshots.get(issueNumber)!,
      sourceIdentity.digest,
    ),
  );
  const forcedClassification = new Set(
    (args.classifyIssueNumbers ?? [])
      .filter((issueNumber) => requested.includes(issueNumber)),
  );
  const reconcileNumbers = [...new Set([
    ...persistedMismatches,
    ...stateSnapshotMismatches,
    ...staleClassifications,
    ...forcedClassification,
  ])];
  const classificationTargets = new Set([
    ...staleClassifications,
    ...forcedClassification,
  ]);
  const evidence = await fetchReconciledIssueEvidence(reconcileNumbers, {
    maxAttempts: args.maxAttempts,
    dependencies: args.dependencies,
    signal: args.signal,
  });
  for (const [issueNumber, item] of evidence) snapshots.set(issueNumber, item.snapshot);

  const dependencies: IssueReconciliationDependencies = {
    listIssues: listIssuesBatch,
    listSnapshots: listIssueCommentSnapshotsBatch,
    listLabelEvidence: listIssueLabelEvidenceSnapshotsBatch,
    listFixEvidence: listIssueFixEvidenceBatch,
    classify: classifyIssueDurably,
    sleep: abortableDelay,
    ...args.dependencies,
  };
  const classificationNumbers = [...evidence.keys()]
    .filter((issueNumber) => classificationTargets.has(issueNumber));
  const classifications = new Map<number, StagedIssueClassification>();
  const classificationFailures = new Map<number, {
    issueNumber: number;
    issue: GhIssue;
    error: unknown;
  }>();
  const classificationConcurrency = args.classificationConcurrency ?? CLASSIFY_CONCURRENCY;
  if (!Number.isInteger(classificationConcurrency) || classificationConcurrency <= 0) {
    throw new Error(
      `Issue reconciliation classificationConcurrency must be a positive integer, ` +
      `got ${classificationConcurrency}`,
    );
  }
  let classificationFailure: unknown = null;
  try {
    await mapWithConcurrency(
      classificationNumbers,
      classificationConcurrency,
      async (issueNumber, _index, signal) => {
        const item = evidence.get(issueNumber);
        if (!item) throw new Error(`Missing reconciled issue evidence for #${issueNumber}`);
        try {
          const classification = stagedIssueClassification(await dependencies.classify(
            item.issue,
            item.snapshot.comments,
            args.releaseTags,
            signal,
          ));
          classifications.set(issueNumber, classification);
        } catch (error) {
          const abortError = cooperativeClassifierAbort(error);
          if (abortError) throw abortError;
          if (
            args.accumulateGroundingFailures &&
            accumulableClassifierGroundingFailure(error)
          ) {
            classificationFailures.set(issueNumber, {
              issueNumber,
              issue: item.issue,
              error,
            });
            return;
          }
          throw new Error(
            `Failed to classify reconciled issue #${issueNumber}: ` +
            `${error instanceof Error ? error.message : String(error)}`,
            { cause: error },
          );
        }
      },
      { signal: args.signal },
    );
  } catch (error) {
    classificationFailure = error;
  }

  throwIfAborted(args.signal);
  const persistableIssueNumbers = requested.filter((issueNumber) =>
    !classificationTargets.has(issueNumber) || classifications.has(issueNumber),
  );
  const persistableExpectedRevisions = new Map<number, IssueEvidenceRevision>();
  for (const issueNumber of persistableIssueNumbers) {
    const expectedRevision = expectedRevisions.get(issueNumber);
    if (!expectedRevision) {
      throw new Error(`Missing expected issue evidence revision for #${issueNumber}`);
    }
    persistableExpectedRevisions.set(issueNumber, expectedRevision);
  }

  const snapshotAt = args.snapshotAt ?? new Date().toISOString();
  if (persistableIssueNumbers.length > 0) {
    args.assertCanWrite?.('reconciled issue evidence persistence');
    runInWriteTransaction(() => {
      throwIfAborted(args.signal);
      args.assertCanWrite?.('reconciled issue evidence transaction');
      assertIssueEvidenceRevisions(persistableExpectedRevisions);
      for (const issueNumber of persistableIssueNumbers) {
        const item = evidence.get(issueNumber);
        if (item) {
          const classification = classifications.get(issueNumber);
          if (classificationTargets.has(issueNumber) && !classification) {
            throw new Error(`Missing staged classification for reconciled issue #${issueNumber}`);
          }
          persistReconciledIssueEvidence(item, snapshotAt, classification, sourceIdentity);
        } else {
          upsertIssueCommentSnapshot(issueCommentSnapshot(snapshots.get(issueNumber)!));
        }
      }
      throwIfAborted(args.signal);
      args.assertCanWrite?.('reconciled issue evidence commit');
    });
  }
  if (classificationFailure) throw classificationFailure;

  const persistableIssueNumberSet = new Set(persistableIssueNumbers);
  return {
    snapshotsByIssue: snapshots,
    issuesByNumber: new Map([...evidence].map(([issueNumber, item]) => [issueNumber, item.issue])),
    labelEventsByIssue: new Map([...evidence].map(([issueNumber, item]) => [
      issueNumber,
      item.labelEvidenceSnapshot.events,
    ])),
    labelEvidenceSnapshotsByIssue: new Map([...evidence].map(([issueNumber, item]) => [
      issueNumber,
      item.labelEvidenceSnapshot,
    ])),
    stateEvidenceByIssue: new Map([...evidence].map(([issueNumber, item]) => [issueNumber, item.fixEvidence])),
    reconciledIssueNumbers: [...new Set([
      ...persistedMismatches,
      ...stateSnapshotMismatches,
    ])]
      .filter((issueNumber) => persistableIssueNumberSet.has(issueNumber))
      .sort((a, b) => a - b),
    classifiedIssueNumbers: [...classifications.keys()].sort((a, b) => a - b),
    classificationFailures: [...classificationFailures.values()]
      .sort((left, right) => left.issueNumber - right.issueNumber),
  };
}

const TARGET_RECONCILIATION_CHUNK_SIZE = 100;

async function reconcileIssueCommentSnapshotChunks(
  args: Parameters<typeof reconcileIssueCommentSnapshots>[0] & {
    chunkSize?: number;
    onChunk?: (progress: {
      completed: number;
      total: number;
      classified: number;
    }) => void;
    reconcile?: typeof reconcileIssueCommentSnapshots;
  },
): Promise<Awaited<ReturnType<typeof reconcileIssueCommentSnapshots>>> {
  const issueNumbers = [...new Set(args.issueNumbers)]
    .filter((number) => Number.isInteger(number) && number > 0);
  const chunkSize = args.chunkSize ?? TARGET_RECONCILIATION_CHUNK_SIZE;
  if (!Number.isInteger(chunkSize) || chunkSize <= 0) {
    throw new Error(`Target reconciliation chunkSize must be a positive integer, got ${chunkSize}`);
  }
  const aggregate: Awaited<ReturnType<typeof reconcileIssueCommentSnapshots>> = {
    snapshotsByIssue: new Map(),
    issuesByNumber: new Map(),
    labelEventsByIssue: new Map(),
    labelEvidenceSnapshotsByIssue: new Map(),
    stateEvidenceByIssue: new Map(),
    reconciledIssueNumbers: [],
    classifiedIssueNumbers: [],
    classificationFailures: [],
  };
  const reconciled = new Set<number>();
  const classified = new Set<number>();
  const snapshotAt = args.snapshotAt ?? new Date().toISOString();
  const reconcile = args.reconcile ?? reconcileIssueCommentSnapshots;

  for (let offset = 0; offset < issueNumbers.length; offset += chunkSize) {
    throwIfAborted(args.signal);
    const chunk = issueNumbers.slice(offset, offset + chunkSize);
    const chunkSnapshots = args.snapshotsByIssue
      ? new Map(chunk.flatMap((issueNumber) => {
          const snapshot = args.snapshotsByIssue?.get(issueNumber);
          return snapshot ? [[issueNumber, snapshot] as const] : [];
        }))
      : undefined;
    const chunkExpectedRevisions = args.expectedRevisions
      ? new Map(chunk.flatMap((issueNumber) => {
          const revision = args.expectedRevisions?.get(issueNumber);
          return revision ? [[issueNumber, revision] as const] : [];
        }))
      : undefined;
    const result = await reconcile({
      ...args,
      issueNumbers: chunk,
      snapshotsByIssue: chunkSnapshots,
      expectedRevisions: chunkExpectedRevisions,
      classifyIssueNumbers: args.classifyIssueNumbers?.filter((issueNumber) =>
        chunk.includes(issueNumber)),
      snapshotAt,
    });
    for (const [key, value] of result.snapshotsByIssue) aggregate.snapshotsByIssue.set(key, value);
    for (const [key, value] of result.issuesByNumber) aggregate.issuesByNumber.set(key, value);
    for (const [key, value] of result.labelEventsByIssue) aggregate.labelEventsByIssue.set(key, value);
    for (const [key, value] of result.labelEvidenceSnapshotsByIssue) {
      aggregate.labelEvidenceSnapshotsByIssue.set(key, value);
    }
    for (const [key, value] of result.stateEvidenceByIssue) aggregate.stateEvidenceByIssue.set(key, value);
    for (const issueNumber of result.reconciledIssueNumbers) reconciled.add(issueNumber);
    for (const issueNumber of result.classifiedIssueNumbers) classified.add(issueNumber);
    aggregate.classificationFailures.push(...result.classificationFailures);
    args.onChunk?.({
      completed: Math.min(offset + chunk.length, issueNumbers.length),
      total: issueNumbers.length,
      classified: result.classifiedIssueNumbers.length,
    });
  }

  aggregate.reconciledIssueNumbers = [...reconciled].sort((a, b) => a - b);
  aggregate.classifiedIssueNumbers = [...classified].sort((a, b) => a - b);
  return aggregate;
}

const CLOSURE_DRIFT_RECONCILE_MAX_ATTEMPTS = 3;

function seedClosureRunContextFromReconciliation(
  runContext: ClosureProofRunContext,
  reconciliation: Awaited<ReturnType<typeof reconcileIssueCommentSnapshots>>,
): void {
  for (const [issueNumber, snapshot] of reconciliation.snapshotsByIssue) {
    runContext.commentSnapshotsByIssue.set(issueNumber, snapshot);
    runContext.commentsByIssue.set(issueNumber, snapshot.comments);
  }
  for (const [issueNumber, evidence] of reconciliation.stateEvidenceByIssue) {
    runContext.fixEvidenceByIssue.set(issueNumber, evidence);
    if (issueStateMetadataMatchesSnapshot(
      reconciliation.issuesByNumber.get(issueNumber),
      reconciliation.snapshotsByIssue.get(issueNumber)!,
      evidence,
    )) {
      runContext.stateSnapshotMetadataDriftIssueNumbers.delete(issueNumber);
    } else {
      runContext.stateSnapshotMetadataDriftIssueNumbers.add(issueNumber);
    }
  }
  for (const [issueNumber, revision] of issueEvidenceRevisions(
    [...reconciliation.snapshotsByIssue.keys()],
  )) {
    (runContext.issueEvidenceRevisionsByIssue ??= new Map()).set(issueNumber, revision);
  }
}

function unresolvedClosureSnapshotDriftIssueNumbers(
  runContext: ClosureProofRunContext,
): number[] {
  const candidates = closureProofCommentSnapshotDriftIssueNumbers(runContext);
  return [...new Set([
    ...unresolvedCommentSnapshotMetadataDriftIssueNumbers(runContext, candidates),
    ...unresolvedStateSnapshotMetadataDriftIssueNumbers(runContext),
  ])].sort((a, b) => a - b);
}

function closureTargetsForReleases<T extends { tag: string }>(
  releases: T[],
  lookup: (tag: string) => Array<{ number: number }> = issuesForVersion,
): {
  issueNumbers: number[];
  issueNumbersByTag: Map<string, Set<number>>;
} {
  const issueNumbersByTag = new Map(
    releases.map((release) => [
      release.tag,
      new Set(
        lookup(release.tag)
          .map((issue) => Number(issue.number))
          .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0),
      ),
    ]),
  );
  return {
    issueNumbers: [...new Set(
      [...issueNumbersByTag.values()].flatMap((issueNumbers) => [...issueNumbers]),
    )],
    issueNumbersByTag,
  };
}

export async function reconcileClosureSnapshotDrift(args: {
  runContext: ClosureProofRunContext;
  releaseTags: string[];
  rerunAffected: (issueNumbers: number[], attempt: number) => Promise<void>;
  maxAttempts?: number;
  classificationConcurrency?: number;
  assertCanWrite?: (stage: string) => void;
  reconcile?: typeof reconcileIssueCommentSnapshots;
  unresolved?: (runContext: ClosureProofRunContext) => number[];
  signal?: AbortSignal;
}): Promise<{
  attempts: number;
  reconciledIssueNumbers: number[];
  classifiedIssueNumbers: number[];
}> {
  const maxAttempts = args.maxAttempts ?? CLOSURE_DRIFT_RECONCILE_MAX_ATTEMPTS;
  if (!Number.isInteger(maxAttempts) || maxAttempts <= 0) {
    throw new Error(`Closure drift maxAttempts must be a positive integer, got ${maxAttempts}`);
  }
  const reconcile = args.reconcile ?? reconcileIssueCommentSnapshots;
  const unresolved = args.unresolved ?? unresolvedClosureSnapshotDriftIssueNumbers;
  const reconciled = new Set<number>();
  const classified = new Set<number>();

  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    throwIfAborted(args.signal);
    const driftedIssueNumbers = unresolved(args.runContext);
    if (driftedIssueNumbers.length === 0) {
      return {
        attempts: attempt - 1,
        reconciledIssueNumbers: [...reconciled].sort((a, b) => a - b),
        classifiedIssueNumbers: [...classified].sort((a, b) => a - b),
      };
    }
    const snapshotsByIssue = new Map<number, GhIssueCommentSnapshot>();
    for (const issueNumber of driftedIssueNumbers) {
      const snapshot = args.runContext.commentSnapshotsByIssue.get(issueNumber);
      if (!snapshot) {
        throw new Error(`Closure drift issue #${issueNumber} has no accepted run snapshot`);
      }
      snapshotsByIssue.set(issueNumber, snapshot);
    }
    const reconciliation = await reconcile({
      issueNumbers: driftedIssueNumbers,
      releaseTags: args.releaseTags,
      snapshotsByIssue,
      expectedRevisions: new Map(driftedIssueNumbers.flatMap((issueNumber) => {
        const revisions = args.runContext.issueEvidenceRevisionsByIssue ??= new Map();
        const revision = revisions.get(issueNumber);
        return revision ? [[issueNumber, revision] as const] : [];
      })),
      classificationConcurrency: args.classificationConcurrency,
      maxAttempts: ISSUE_RECONCILE_MAX_ATTEMPTS,
      assertCanWrite: args.assertCanWrite,
      signal: args.signal,
    });
    seedClosureRunContextFromReconciliation(args.runContext, reconciliation);
    for (const issueNumber of driftedIssueNumbers) reconciled.add(issueNumber);
    for (const issueNumber of reconciliation.classifiedIssueNumbers) classified.add(issueNumber);
    await args.rerunAffected(driftedIssueNumbers, attempt);
  }

  const unresolvedAfterRetries = unresolved(args.runContext);
  if (unresolvedAfterRetries.length > 0) {
    throw new Error(
      `Closure comment snapshot metadata drift did not converge after ${maxAttempts} attempts for ` +
      `${unresolvedAfterRetries.map((issueNumber) => `#${issueNumber}`).join(', ')}`,
    );
  }
  return {
    attempts: maxAttempts,
    reconciledIssueNumbers: [...reconciled].sort((a, b) => a - b),
    classifiedIssueNumbers: [...classified].sort((a, b) => a - b),
  };
}

function commentStats(snapshot: GhIssueCommentSnapshot): {
  unique_human_commenters: number;
  maintainer_commenters: number;
  contributor_commenters: number;
  commenter_scan_truncated: number;
} {
  const humans = new Set<string>();
  const maintainers = new Set<string>();
  const contributors = new Set<string>();
  const completeness = commentCompleteness(snapshot.totalCount, snapshot.comments);
  for (const comment of snapshot.comments) {
    const login = comment.user?.login;
    if (!login || detectBot(login, '[]')) continue;
    humans.add(login);
    if (isMaintainerAssociation(comment.author_association)) maintainers.add(login);
    if (isContributorAssociation(comment.author_association)) contributors.add(login);
  }
  return {
    unique_human_commenters: humans.size,
    maintainer_commenters: maintainers.size,
    contributor_commenters: contributors.size,
    commenter_scan_truncated: completeness.complete ? 0 : 1,
  };
}

function issueCommentSnapshot(snapshot: GhIssueCommentSnapshot): {
  issue_number: number;
  repository_node_id: string;
  issue_node_id: string;
  issue_author_node_id: string;
  issue_author_login: string;
  issue_author_type: string;
  schema_version: number;
  comment_count: number;
  fetched_comment_count: number;
  latest_comment_updated_at: string | null;
  comments_digest: string;
  authority_digest: string;
  issue_updated_at: string;
  comments_json: string;
  stabilization_json: string;
  stabilization_identity_digest: string;
} {
  const completeness = commentCompleteness(snapshot.totalCount, snapshot.comments);
  if (!completeness.complete) {
    throw new Error(
      `Refusing incomplete comment snapshot for issue #${snapshot.issueNumber}: expected ${completeness.expectedCount}, ` +
      `fetched ${completeness.fetchedCount}, unique ${completeness.uniqueCount}, ` +
      `invalid ID indexes ${completeness.invalidIdIndexes.join(',') || 'none'}, ` +
      `duplicate IDs ${completeness.duplicateIds.join(',') || 'none'}`,
    );
  }
  const digest = commentEvidenceDigest(snapshot.totalCount, snapshot.comments);
  if (digest !== snapshot.commentsDigest) {
    throw new Error(
      `Refusing comment snapshot for issue #${snapshot.issueNumber}: ` +
      `snapshot digest ${snapshot.commentsDigest} did not match computed digest ${digest}`,
    );
  }
  if (!snapshot.issueAuthor) {
    throw new Error(
      `Refusing authoritative comment snapshot for issue #${snapshot.issueNumber}: missing issue author identity`,
    );
  }
  const authorityDigest = commentEvidenceDigest(
    snapshot.totalCount,
    snapshot.comments,
    {
      repositoryNodeId: snapshot.repositoryNodeId,
      issueNodeId: snapshot.issueNodeId,
      issueNodeType: snapshot.issueNodeType,
      issueAuthor: snapshot.issueAuthor,
    },
  );
  if (authorityDigest !== snapshot.authorityDigest) {
    throw new Error(
      `Refusing comment snapshot for issue #${snapshot.issueNumber}: ` +
      `authority digest ${snapshot.authorityDigest} did not match computed digest ${authorityDigest}`,
    );
  }
  return {
    issue_number: snapshot.issueNumber,
    repository_node_id: snapshot.repositoryNodeId,
    issue_node_id: snapshot.issueNodeId,
    issue_author_node_id: snapshot.issueAuthor.nodeId,
    issue_author_login: snapshot.issueAuthor.login,
    issue_author_type: snapshot.issueAuthor.actorType,
    schema_version: AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: snapshot.totalCount,
    fetched_comment_count: snapshot.comments.length,
    latest_comment_updated_at: maxTimestamp(
      snapshot.comments.map((comment) => comment.updated_at ?? comment.created_at ?? null),
    ),
    comments_digest: snapshot.commentsDigest,
    authority_digest: snapshot.authorityDigest,
    issue_updated_at: snapshot.issueUpdatedAt,
    comments_json: serializeCommentEvidence(snapshot.comments),
    stabilization_json: JSON.stringify(snapshot.stabilization),
    stabilization_identity_digest: snapshot.stabilization.identityDigest,
  };
}

function upsertClassificationForSnapshot(
  issueNumber: number,
  staged: StagedIssueClassification,
  snapshot: GhIssueCommentSnapshot,
  sourceIdentity: ReturnType<typeof classifierSourceIdentity>,
  evidenceRevisions: IssueEvidenceRevision,
): void {
  upsertClassification(
    issueNumber,
    staged.classification,
    snapshot.issueUpdatedAt,
    PROMPT_VERSION,
    snapshot.commentsDigest,
    sourceIdentity,
    staged.acceptedClassifier
      ? {
          ...staged.acceptedClassifier,
          evidenceRevisions: {
            issueRevision: evidenceRevisions.issueRevision,
            snapshotRevision: evidenceRevisions.snapshotRevision,
            stateSnapshotRevision: evidenceRevisions.stateSnapshotRevision ?? null,
          },
        }
      : null,
  );
}

function classificationMatchesSnapshot(
  classification: {
    classified_updated_at: string;
    classified_comments_digest: string | null;
    prompt_version: number;
    source_identity_digest?: string | null;
    classification_origin?: string | null;
    accepted_classifier_receipt_id?: string | null;
  } | undefined,
  snapshot: GhIssueCommentSnapshot,
  sourceIdentityDigest: string,
): boolean {
  return !!classification &&
    classification.classified_updated_at === snapshot.issueUpdatedAt &&
    classification.classified_comments_digest === snapshot.commentsDigest &&
    classification.prompt_version === PROMPT_VERSION &&
    classification.source_identity_digest === sourceIdentityDigest &&
    (
      classification.classification_origin !== 'raw_model' ||
      typeof classification.accepted_classifier_receipt_id === 'string'
    );
}

function classificationCanDeferLegacyCommentBinding(
  classification: {
    classified_updated_at: string;
    classified_comments_digest: string | null;
    prompt_version: number;
    source_identity_digest?: string | null;
    classification_origin?: string | null;
    accepted_classifier_receipt_id?: string | null;
  } | undefined,
  snapshot: GhIssueCommentSnapshot,
  sourceIdentityDigest: string,
): boolean {
  return !!classification &&
    classification.classified_updated_at === snapshot.issueUpdatedAt &&
    classification.classified_comments_digest == null &&
    classification.prompt_version === PROMPT_VERSION &&
    classification.source_identity_digest === sourceIdentityDigest &&
    (
      classification.classification_origin !== 'raw_model' ||
      typeof classification.accepted_classifier_receipt_id === 'string'
    );
}

function maxTimestamp(values: Array<string | null | undefined>): string | null {
  return values
    .filter((value): value is string => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

const BACKFILL_FLAG = 'backfill_completed_at';
export const ISSUE_CRAWL_META_KEY = 'issue_crawl_last_run';
export const ISSUE_CRAWL_BASELINE_META_KEY = 'issue_crawl_exhaustive_baseline';
const ISSUE_CRAWL_SCHEMA_VERSION = 4;
const ISSUE_CRAWL_BASELINE_SCHEMA_VERSION = 2;
const ISSUE_PAGINATION_SCHEMA_VERSION = 2;
const REFRESH_LEASE_NAME = REFRESH_WRITE_LEASE_NAME;
const REFRESH_LEASE_TTL_MS = REFRESH_WRITE_LEASE_TTL_MS;
const REFRESH_LEASE_HEARTBEAT_MS = REFRESH_WRITE_LEASE_HEARTBEAT_MS;
type IssuePaginationStopReason = 'exhausted' | 'early_stop' | 'page_cap' | 'evidence_failure';
const FAILURE_EXAMPLE_LIMIT = 25;

interface IssueCrawlBaseline {
  schemaVersion: 2;
  source: 'github.repository.issues';
  repository: string;
  sourceOrder: 'CREATED_AT_ASC';
  establishedAt: string;
  crawlStartedAt: string;
  boundaryTotalCount: number;
  observedTotalCount: number;
  postBoundaryGrowthCount: number;
  asOfBoundary: GhIssueSnapshotBoundary;
  fetchedCount: number;
  uniqueCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  digest: string;
  membershipDigest: string;
  contentDigest: string;
  identity: string;
}

interface IssueCrawlPagination {
  schemaVersion: 2;
  source: 'github.repository.issues';
  repository: string;
  sourceOrder: 'CREATED_AT_ASC' | 'UPDATED_AT_DESC';
  completeness:
    | 'exhaustive_stable'
    | 'incremental_exhaustive'
    | 'incremental_partial'
    | 'failed';
  boundaryTotalCount: number | null;
  observedTotalCount: number | null;
  postBoundaryGrowthCount: number | null;
  asOfBoundary: GhIssueSnapshotBoundary | null;
  fetchedCount: number;
  uniqueCount: number;
  pageCount: number;
  pagesFetched: number;
  sweepCount: number;
  exhausted: boolean;
  stabilized: boolean;
  digest: string | null;
  membershipDigest: string | null;
  contentDigest: string | null;
  lastRequestCursor: string | null;
  nextCursor: string | null;
  hasNextPage: boolean | null;
}

interface IssueCatalogPublicationAttestation {
  schemaVersion: 1;
  snapshotId: string;
  snapshotContentHash: string;
  observedAt: string;
  totalCount: number;
  membershipDigest: string;
  contentDigest: string;
  finalSweepCount: number;
  finalPagesFetched: number;
}

function issueRepositoryIdentity(): string {
  return `${config.github.owner}/${config.github.repo}`;
}

function finalIssueCatalogAttestation(input: {
  snapshot: IssueCatalogSnapshot;
  finalCatalog: GhIssueCatalogBoundaryVerification;
  observedAt: string;
}): IssueCatalogPublicationAttestation {
  const { snapshot, finalCatalog, observedAt } = input;
  if (!Number.isFinite(Date.parse(observedAt))) {
    throw new Error('Final issue catalog observation time is invalid');
  }
  if (
    finalCatalog.boundary.totalCount !== finalCatalog.fetchedCount ||
    finalCatalog.observedTotalCount < finalCatalog.boundary.totalCount ||
    finalCatalog.pageCount <= 0
  ) {
    throw new Error('Final issue catalog verification did not collect its frozen boundary');
  }
  const expected = snapshot.header;
  const mismatches: string[] = [];
  if (finalCatalog.boundary.totalCount !== expected.boundaryTotalCount) {
    mismatches.push(
      `totalCount changed from ${expected.boundaryTotalCount} ` +
      `to ${finalCatalog.boundary.totalCount}`,
    );
  }
  if (finalCatalog.membershipDigest !== expected.membershipDigest) {
    mismatches.push('membershipDigest changed');
  }
  if (
    JSON.stringify(finalCatalog.boundary) !== JSON.stringify({
      totalCount: expected.boundaryTotalCount,
      terminalIssue: expected.terminalNodeId == null
        ? null
        : {
            nodeId: expected.terminalNodeId,
            issueNumber: expected.terminalIssueNumber,
            createdAt: expected.terminalCreatedAt,
          },
      membershipDigest: expected.membershipDigest,
    })
  ) {
    mismatches.push('immutable terminal boundary changed');
  }
  if (mismatches.length > 0) {
    throw new Error(
      `Issue catalog changed after evidence processing: ${mismatches.join('; ')}`,
    );
  }
  return {
    schemaVersion: 1,
    snapshotId: expected.snapshotId,
    snapshotContentHash: expected.contentHash,
    observedAt,
    totalCount: expected.boundaryTotalCount,
    membershipDigest: expected.membershipDigest,
    contentDigest: expected.contentDigest,
    finalSweepCount: 1,
    finalPagesFetched: finalCatalog.pageCount,
  };
}

function issueCrawlBaselineIdentity(input: {
  repository: string;
  sourceOrder: string;
  asOfBoundary: GhIssueSnapshotBoundary;
}): string {
  return createHash('sha256')
    .update(JSON.stringify([
      input.repository,
      input.sourceOrder,
      input.asOfBoundary.totalCount,
      input.asOfBoundary.terminalIssue?.nodeId ?? null,
      input.asOfBoundary.terminalIssue?.issueNumber ?? null,
      input.asOfBoundary.terminalIssue?.createdAt ?? null,
      input.asOfBoundary.membershipDigest,
    ]))
    .digest('hex');
}

function issueCrawlBaselineProblems(
  baseline: unknown,
  repository = issueRepositoryIdentity(),
): string[] {
  const problems: string[] = [];
  if (!baseline || typeof baseline !== 'object' || Array.isArray(baseline)) {
    return ['baseline must be an object'];
  }
  const value = baseline as Partial<IssueCrawlBaseline>;
  if (value.schemaVersion !== ISSUE_CRAWL_BASELINE_SCHEMA_VERSION) {
    problems.push(`schemaVersion must equal ${ISSUE_CRAWL_BASELINE_SCHEMA_VERSION}`);
  }
  if (value.source !== 'github.repository.issues') {
    problems.push('source must equal github.repository.issues');
  }
  if (value.repository !== repository) {
    problems.push(`repository must equal ${repository}`);
  }
  if (value.sourceOrder !== 'CREATED_AT_ASC') {
    problems.push('sourceOrder must equal CREATED_AT_ASC');
  }
  if (typeof value.establishedAt !== 'string' || !Number.isFinite(Date.parse(value.establishedAt))) {
    problems.push('establishedAt must be a valid timestamp');
  }
  if (typeof value.crawlStartedAt !== 'string' || !Number.isFinite(Date.parse(value.crawlStartedAt))) {
    problems.push('crawlStartedAt must be a valid timestamp');
  }
  const counts = [
    ['boundaryTotalCount', value.boundaryTotalCount],
    ['observedTotalCount', value.observedTotalCount],
    ['postBoundaryGrowthCount', value.postBoundaryGrowthCount],
    ['fetchedCount', value.fetchedCount],
    ['uniqueCount', value.uniqueCount],
    ['pageCount', value.pageCount],
    ['pagesFetched', value.pagesFetched],
    ['sweepCount', value.sweepCount],
  ] as const;
  for (const [name, count] of counts) {
    if (!Number.isInteger(count) || Number(count) < 0) {
      problems.push(`${name} must be a non-negative integer`);
    }
  }
  if (
    Number.isInteger(value.boundaryTotalCount) &&
    (value.fetchedCount !== value.boundaryTotalCount || value.uniqueCount !== value.boundaryTotalCount)
  ) {
    problems.push('fetchedCount and uniqueCount must equal boundaryTotalCount');
  }
  if (
    Number.isInteger(value.boundaryTotalCount) &&
    Number.isInteger(value.observedTotalCount) &&
    Number(value.observedTotalCount) < Number(value.boundaryTotalCount)
  ) {
    problems.push('observedTotalCount cannot be less than boundaryTotalCount');
  }
  if (
    Number.isInteger(value.boundaryTotalCount) &&
    Number.isInteger(value.observedTotalCount) &&
    Number.isInteger(value.postBoundaryGrowthCount) &&
    Number(value.postBoundaryGrowthCount) !==
      Number(value.observedTotalCount) - Number(value.boundaryTotalCount)
  ) {
    problems.push('postBoundaryGrowthCount must equal observedTotalCount minus boundaryTotalCount');
  }
  if (!Number.isInteger(value.sweepCount) || Number(value.sweepCount) < 2) {
    problems.push('sweepCount must be at least 2');
  }
  if (typeof value.digest !== 'string' || !/^[0-9a-f]{64}$/.test(value.digest)) {
    problems.push('digest must be a lowercase SHA-256 hex string');
  }
  if (typeof value.membershipDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.membershipDigest)) {
    problems.push('membershipDigest must be a lowercase SHA-256 hex string');
  }
  if (typeof value.contentDigest !== 'string' || !/^[0-9a-f]{64}$/.test(value.contentDigest)) {
    problems.push('contentDigest must be a lowercase SHA-256 hex string');
  }
  if (
    typeof value.digest === 'string' &&
    typeof value.membershipDigest === 'string' &&
    value.digest !== value.membershipDigest
  ) {
    problems.push('digest must equal membershipDigest');
  }
  const boundary = value.asOfBoundary;
  if (!boundary || typeof boundary !== 'object' || Array.isArray(boundary)) {
    problems.push('asOfBoundary must be an object');
  } else {
    if (!Number.isInteger(boundary.totalCount) || boundary.totalCount < 0) {
      problems.push('asOfBoundary.totalCount must be a non-negative integer');
    }
    if (boundary.totalCount !== value.boundaryTotalCount) {
      problems.push('asOfBoundary.totalCount must equal boundaryTotalCount');
    }
    if (
      typeof boundary.membershipDigest !== 'string' ||
      !/^[0-9a-f]{64}$/.test(boundary.membershipDigest)
    ) {
      problems.push('asOfBoundary.membershipDigest must be a lowercase SHA-256 hex string');
    } else if (boundary.membershipDigest !== value.membershipDigest) {
      problems.push('asOfBoundary.membershipDigest must equal membershipDigest');
    }
    if (boundary.totalCount === 0 && boundary.terminalIssue !== null) {
      problems.push('asOfBoundary.terminalIssue must be null for an empty boundary');
    }
    if (boundary.totalCount > 0) {
      const terminal = boundary.terminalIssue;
      if (!terminal || typeof terminal !== 'object' || Array.isArray(terminal)) {
        problems.push('asOfBoundary.terminalIssue must identify the terminal issue');
      } else {
        if (typeof terminal.nodeId !== 'string' || terminal.nodeId.length === 0) {
          problems.push('asOfBoundary.terminalIssue.nodeId must be a non-empty string');
        }
        if (!Number.isInteger(terminal.issueNumber) || terminal.issueNumber <= 0) {
          problems.push('asOfBoundary.terminalIssue.issueNumber must be a positive integer');
        }
        if (
          typeof terminal.createdAt !== 'string' ||
          !Number.isFinite(Date.parse(terminal.createdAt))
        ) {
          problems.push('asOfBoundary.terminalIssue.createdAt must be a valid timestamp');
        }
      }
    }
  }
  if (typeof value.identity !== 'string' || !/^[0-9a-f]{64}$/.test(value.identity)) {
    problems.push('identity must be a lowercase SHA-256 hex string');
  } else if (
    typeof value.repository === 'string' &&
    typeof value.sourceOrder === 'string' &&
    value.asOfBoundary != null
  ) {
    const expectedIdentity = issueCrawlBaselineIdentity({
      repository: value.repository,
      sourceOrder: value.sourceOrder,
      asOfBoundary: value.asOfBoundary as GhIssueSnapshotBoundary,
    });
    if (value.identity !== expectedIdentity) {
      problems.push('identity does not match repository, source order, and immutable as-of boundary');
    }
  }
  return problems;
}

function parseIssueCrawlBaseline(raw: string | null): IssueCrawlBaseline | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  return issueCrawlBaselineProblems(parsed).length === 0
    ? parsed as IssueCrawlBaseline
    : null;
}

function issueCrawlBaselineFromCatalog(
  metadata: GhIssueCatalogMetadata,
  establishedAt: string,
  crawlStartedAt: string,
): IssueCrawlBaseline {
  const repository = issueRepositoryIdentity();
  const baseline = {
    schemaVersion: ISSUE_CRAWL_BASELINE_SCHEMA_VERSION,
    source: 'github.repository.issues',
    repository,
    sourceOrder: metadata.sourceOrder,
    establishedAt,
    crawlStartedAt,
    boundaryTotalCount: metadata.totalCount,
    observedTotalCount: metadata.observedTotalCount,
    postBoundaryGrowthCount: metadata.postBoundaryGrowthCount,
    asOfBoundary: metadata.snapshotBoundary,
    fetchedCount: metadata.nodeCount,
    uniqueCount: metadata.uniqueCount,
    pageCount: metadata.pageCount,
    pagesFetched: metadata.pagesFetched,
    sweepCount: metadata.sweepCount,
    digest: metadata.digest,
    membershipDigest: metadata.membershipDigest,
    contentDigest: metadata.contentDigest,
    identity: '',
  } satisfies IssueCrawlBaseline;
  baseline.identity = issueCrawlBaselineIdentity(baseline);
  return baseline;
}

function issuePaginationFromCatalog(metadata: GhIssueCatalogMetadata): IssueCrawlPagination {
  return {
    schemaVersion: ISSUE_PAGINATION_SCHEMA_VERSION,
    source: 'github.repository.issues',
    repository: issueRepositoryIdentity(),
    sourceOrder: metadata.sourceOrder,
    completeness: 'exhaustive_stable',
    boundaryTotalCount: metadata.totalCount,
    observedTotalCount: metadata.observedTotalCount,
    postBoundaryGrowthCount: metadata.postBoundaryGrowthCount,
    asOfBoundary: metadata.snapshotBoundary,
    fetchedCount: metadata.nodeCount,
    uniqueCount: metadata.uniqueCount,
    pageCount: metadata.pageCount,
    pagesFetched: metadata.pagesFetched,
    sweepCount: metadata.sweepCount,
    exhausted: metadata.exhausted,
    stabilized: metadata.stabilized,
    digest: metadata.digest,
    membershipDigest: metadata.membershipDigest,
    contentDigest: metadata.contentDigest,
    lastRequestCursor: metadata.lastRequestCursor,
    nextCursor: metadata.nextCursor,
    hasNextPage: metadata.hasNextPage,
  };
}

function issuePaginationFromPage(
  metadata: GhIssuePageMetadata,
  baseline: IssueCrawlBaseline,
): IssueCrawlPagination {
  if (metadata.totalCount < baseline.boundaryTotalCount) {
    throw new Error(
      `GitHub GraphQL repository.issues totalCount ${metadata.totalCount} is below ` +
      `stored exhaustive boundary ${baseline.boundaryTotalCount}`,
    );
  }
  return {
    schemaVersion: ISSUE_PAGINATION_SCHEMA_VERSION,
    source: 'github.repository.issues',
    repository: issueRepositoryIdentity(),
    sourceOrder: metadata.sourceOrder,
    completeness: metadata.exhausted ? 'failed' : 'incremental_partial',
    boundaryTotalCount: baseline.boundaryTotalCount,
    observedTotalCount: metadata.totalCount,
    postBoundaryGrowthCount: metadata.totalCount - baseline.boundaryTotalCount,
    asOfBoundary: baseline.asOfBoundary,
    fetchedCount: metadata.fetchedCount,
    uniqueCount: metadata.uniqueCount,
    pageCount: metadata.pageCount,
    pagesFetched: metadata.pageCount,
    sweepCount: 1,
    exhausted: metadata.exhausted,
    stabilized: false,
    digest: metadata.digest,
    membershipDigest: metadata.membershipDigest,
    contentDigest: metadata.contentDigest,
    lastRequestCursor: metadata.requestCursor,
    nextCursor: metadata.nextCursor,
    hasNextPage: metadata.hasNextPage,
  };
}

function issuePaginationFromIncrementalSweep(
  metadata: GhIssueIncrementalSweepMetadata,
  baseline: IssueCrawlBaseline,
): IssueCrawlPagination {
  if (metadata.totalCount < baseline.boundaryTotalCount) {
    throw new Error(
      `GitHub GraphQL repository.issues totalCount ${metadata.totalCount} is below ` +
      `stored exhaustive boundary ${baseline.boundaryTotalCount}`,
    );
  }
  return {
    schemaVersion: ISSUE_PAGINATION_SCHEMA_VERSION,
    source: 'github.repository.issues',
    repository: issueRepositoryIdentity(),
    sourceOrder: metadata.sourceOrder,
    completeness: 'incremental_exhaustive',
    boundaryTotalCount: baseline.boundaryTotalCount,
    observedTotalCount: metadata.totalCount,
    postBoundaryGrowthCount: metadata.totalCount - baseline.boundaryTotalCount,
    asOfBoundary: baseline.asOfBoundary,
    fetchedCount: metadata.nodeCount,
    uniqueCount: metadata.uniqueCount,
    pageCount: metadata.pageCount,
    pagesFetched: metadata.pagesFetched,
    sweepCount: metadata.sweepCount,
    exhausted: true,
    stabilized: false,
    digest: metadata.digest,
    membershipDigest: metadata.membershipDigest,
    contentDigest: metadata.contentDigest,
    lastRequestCursor: metadata.lastRequestCursor,
    nextCursor: null,
    hasNextPage: false,
  };
}

function issueCrawlMetadataProblems(
  issueCrawl: unknown,
  storedBaseline: unknown,
  {
    repository = issueRepositoryIdentity(),
    forScorePersistence = false,
  }: {
    repository?: string;
    forScorePersistence?: boolean;
  } = {},
): string[] {
  const problems: string[] = [];
  if (!issueCrawl || typeof issueCrawl !== 'object' || Array.isArray(issueCrawl)) {
    return ['issue crawl metadata must be an object'];
  }
  const crawl = issueCrawl as Record<string, any>;
  if (crawl.schemaVersion !== ISSUE_CRAWL_SCHEMA_VERSION) {
    problems.push(`schemaVersion must equal ${ISSUE_CRAWL_SCHEMA_VERSION}`);
  }
  if (crawl.repository !== repository) {
    problems.push(`repository must equal ${repository}`);
  }
  const baselineProblems = issueCrawlBaselineProblems(crawl.baseline, repository);
  const storedBaselineProblems = issueCrawlBaselineProblems(storedBaseline, repository);
  problems.push(...baselineProblems.map((problem) => `embedded baseline ${problem}`));
  problems.push(...storedBaselineProblems.map((problem) => `stored baseline ${problem}`));
  const baseline = baselineProblems.length === 0
    ? crawl.baseline as IssueCrawlBaseline
    : null;
  const stored = storedBaselineProblems.length === 0
    ? storedBaseline as IssueCrawlBaseline
    : null;
  if (
    baseline &&
    stored &&
    (
      baseline.identity !== stored.identity ||
      baseline.repository !== stored.repository ||
      JSON.stringify(baseline.asOfBoundary) !== JSON.stringify(stored.asOfBoundary)
    )
  ) {
    problems.push('embedded baseline does not match stored exhaustive baseline');
  }

  const pagination = crawl.pagination;
  if (!pagination || typeof pagination !== 'object' || Array.isArray(pagination)) {
    problems.push('pagination must be an object');
    return problems;
  }
  if (pagination.schemaVersion !== ISSUE_PAGINATION_SCHEMA_VERSION) {
    problems.push(`pagination schemaVersion must equal ${ISSUE_PAGINATION_SCHEMA_VERSION}`);
  }
  if (pagination.source !== 'github.repository.issues') {
    problems.push('pagination source must equal github.repository.issues');
  }
  if (pagination.repository !== repository) {
    problems.push(`pagination repository must equal ${repository}`);
  }
  if (baseline && pagination.repository !== baseline.repository) {
    problems.push('pagination repository must match exhaustive baseline repository');
  }
  for (const field of ['fetchedCount', 'uniqueCount', 'pageCount', 'pagesFetched', 'sweepCount']) {
    if (!Number.isInteger(pagination[field]) || pagination[field] < 0) {
      problems.push(`pagination ${field} must be a non-negative integer`);
    }
  }
  if (pagination.fetchedCount !== pagination.uniqueCount) {
    problems.push('pagination fetchedCount must equal uniqueCount');
  }
  if (
    Number.isInteger(pagination.pageCount) &&
    Number.isInteger(pagination.pagesFetched) &&
    pagination.pagesFetched < pagination.pageCount
  ) {
    problems.push('pagination pagesFetched cannot be less than pageCount');
  }
  if (baseline) {
    if (pagination.boundaryTotalCount !== baseline.boundaryTotalCount) {
      problems.push('pagination boundaryTotalCount must match exhaustive baseline');
    }
    if (JSON.stringify(pagination.asOfBoundary) !== JSON.stringify(baseline.asOfBoundary)) {
      problems.push('pagination asOfBoundary must match exhaustive baseline');
    }
    if (
      !Number.isInteger(pagination.observedTotalCount) ||
      pagination.observedTotalCount < baseline.boundaryTotalCount
    ) {
      problems.push('pagination observedTotalCount cannot be below exhaustive boundary');
    } else if (
      pagination.postBoundaryGrowthCount !==
      pagination.observedTotalCount - baseline.boundaryTotalCount
    ) {
      problems.push(
        'pagination postBoundaryGrowthCount must equal observedTotalCount minus boundaryTotalCount',
      );
    }
  }

  const stopReason = crawl.stopReason;
  if (stopReason === 'exhausted' && crawl.crawlMode === 'exhaustive') {
    if (pagination.completeness !== 'exhaustive_stable') {
      problems.push('exhaustive crawl completeness must equal exhaustive_stable');
    }
    if (pagination.sourceOrder !== 'CREATED_AT_ASC') {
      problems.push('exhaustive crawl sourceOrder must equal CREATED_AT_ASC');
    }
    if (pagination.exhausted !== true || pagination.stabilized !== true) {
      problems.push('exhaustive crawl must be exhausted and stabilized');
    }
    if (pagination.hasNextPage !== false || pagination.nextCursor !== null) {
      problems.push('exhaustive crawl must terminate at its frozen boundary');
    }
    if (!baseline || pagination.fetchedCount !== baseline.boundaryTotalCount) {
      problems.push('exhaustive crawl fetchedCount must equal boundaryTotalCount');
    }
    if (
      !isSha256Hex(pagination.membershipDigest) ||
      pagination.membershipDigest !== pagination.digest
    ) {
      problems.push('exhaustive crawl digest must equal a valid membershipDigest');
    }
    if (!isSha256Hex(pagination.contentDigest)) {
      problems.push('exhaustive crawl contentDigest must be a lowercase SHA-256 hex string');
    }
    if (
      baseline &&
      (
        pagination.membershipDigest !== baseline.membershipDigest ||
        pagination.contentDigest !== baseline.contentDigest
      )
    ) {
      problems.push('exhaustive pagination digests must match the accepted baseline');
    }
    if (!Number.isInteger(pagination.sweepCount) || pagination.sweepCount < 2) {
      problems.push('exhaustive crawl sweepCount must be at least 2');
    }
  } else if (stopReason === 'exhausted' && crawl.crawlMode === 'incremental') {
    if (pagination.completeness !== 'incremental_exhaustive') {
      problems.push('naturally exhausted incremental completeness must equal incremental_exhaustive');
    }
    if (pagination.sourceOrder !== 'UPDATED_AT_DESC') {
      problems.push('incremental crawl sourceOrder must equal UPDATED_AT_DESC');
    }
    if (pagination.exhausted !== true || pagination.stabilized !== false) {
      problems.push('naturally exhausted incremental crawl must be exhausted and unstabilized');
    }
    if (pagination.hasNextPage !== false || pagination.nextCursor !== null) {
      problems.push('naturally exhausted incremental crawl must have no next cursor');
    }
    if (pagination.fetchedCount !== pagination.observedTotalCount) {
      problems.push('naturally exhausted incremental fetchedCount must equal observedTotalCount');
    }
    if (
      !isSha256Hex(pagination.membershipDigest) ||
      pagination.membershipDigest !== pagination.digest
    ) {
      problems.push('naturally exhausted incremental digest must equal membershipDigest');
    }
    if (!isSha256Hex(pagination.contentDigest)) {
      problems.push(
        'naturally exhausted incremental contentDigest must be a lowercase SHA-256 hex string',
      );
    }
    if (pagination.sweepCount !== 1) {
      problems.push('naturally exhausted incremental sweepCount must equal 1');
    }
  } else if (stopReason === 'early_stop') {
    if (crawl.crawlMode !== 'incremental') {
      problems.push('early_stop crawlMode must equal incremental');
    }
    if (pagination.completeness !== 'incremental_partial') {
      problems.push('early_stop completeness must equal incremental_partial');
    }
    if (pagination.sourceOrder !== 'UPDATED_AT_DESC') {
      problems.push('early_stop sourceOrder must equal UPDATED_AT_DESC');
    }
    if (pagination.exhausted !== false || pagination.stabilized !== false) {
      problems.push('early_stop crawl must be partial and unstabilized');
    }
    if (pagination.hasNextPage !== true || typeof pagination.nextCursor !== 'string') {
      problems.push('early_stop crawl must retain a next cursor');
    }
    if (
      Number.isInteger(pagination.observedTotalCount) &&
      pagination.fetchedCount >= pagination.observedTotalCount
    ) {
      problems.push('early_stop fetchedCount must be less than observedTotalCount');
    }
    if (
      pagination.digest !== null ||
      pagination.membershipDigest !== null ||
      pagination.contentDigest !== null
    ) {
      problems.push('early_stop digests must be null');
    }
    if (pagination.sweepCount !== 1) {
      problems.push('early_stop sweepCount must equal 1');
    }
  } else if (forScorePersistence) {
    problems.push(`stopReason ${String(stopReason)} cannot support score persistence`);
  }

  if (
    forScorePersistence &&
    !(stopReason === 'exhausted' && crawl.crawlMode === 'exhaustive')
  ) {
    problems.push('score persistence requires an exhaustive stabilized issue crawl');
  }
  if (
    (stopReason === 'exhausted' || stopReason === 'early_stop') &&
    crawl.backfillCompleteAfterRun !== true
  ) {
    problems.push('crawl must retain a proven exhaustive baseline');
  }
  if (forScorePersistence) {
    if (Array.isArray(crawl.evidenceRefreshFailures) && crawl.evidenceRefreshFailures.length > 0) {
      problems.push('evidenceRefreshFailures must be empty before score persistence');
    }
    if (Array.isArray(crawl.classificationFailures) && crawl.classificationFailures.length > 0) {
      problems.push('classificationFailures must be empty before score persistence');
    }
    const snapshot = crawl.catalogSnapshot;
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
      problems.push('catalogSnapshot must be an object before score persistence');
    } else {
      if (snapshot.schemaVersion !== 1) {
        problems.push('catalogSnapshot schemaVersion must equal 1');
      }
      if (!isSha256Hex(snapshot.snapshotId) || snapshot.snapshotId !== snapshot.contentHash) {
        problems.push('catalogSnapshot snapshotId/contentHash must be the same SHA-256');
      }
      if (
        typeof snapshot.capturedAt !== 'string' ||
        !Number.isFinite(Date.parse(snapshot.capturedAt))
      ) {
        problems.push('catalogSnapshot capturedAt must be a valid timestamp');
      }
      if (typeof snapshot.resumed !== 'boolean') {
        problems.push('catalogSnapshot resumed must be boolean');
      }
      if (
        !['missing', 'invalid', 'stale', 'consumed', 'resumable'].includes(
          snapshot.priorStatus,
        )
      ) {
        problems.push('catalogSnapshot priorStatus is invalid');
      }
      if (snapshot.resumed !== (snapshot.priorStatus === 'resumable')) {
        problems.push('catalogSnapshot resumed must match priorStatus resumable');
      }
      if (
        !Number.isInteger(snapshot.maxAgeHours) ||
        snapshot.maxAgeHours <= 0
      ) {
        problems.push('catalogSnapshot maxAgeHours must be a positive integer');
      }
      if (
        typeof snapshot.consumedAt !== 'string' ||
        !Number.isFinite(Date.parse(snapshot.consumedAt))
      ) {
        problems.push('catalogSnapshot consumedAt must be a valid timestamp');
      }
      if (
        typeof snapshot.consumedByRunId !== 'string' ||
        snapshot.consumedByRunId.length === 0
      ) {
        problems.push('catalogSnapshot consumedByRunId must be non-empty');
      }
      if (!isSha256Hex(snapshot.consumptionContentHash)) {
        problems.push('catalogSnapshot consumptionContentHash must be SHA-256');
      }
    }

    const attestation = crawl.catalogAttestation;
    if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
      problems.push('catalogAttestation must be an object before score persistence');
    } else {
      if (attestation.schemaVersion !== 1) {
        problems.push('catalogAttestation schemaVersion must equal 1');
      }
      if (
        !snapshot ||
        attestation.snapshotId !== snapshot.snapshotId ||
        attestation.snapshotContentHash !== snapshot.contentHash
      ) {
        problems.push('catalogAttestation must bind the consumed catalog snapshot');
      }
      if (
        typeof attestation.observedAt !== 'string' ||
        !Number.isFinite(Date.parse(attestation.observedAt))
      ) {
        problems.push('catalogAttestation observedAt must be a valid timestamp');
      } else if (
        snapshot &&
        typeof snapshot.consumedAt === 'string' &&
        Number.isFinite(Date.parse(snapshot.consumedAt)) &&
        Date.parse(attestation.observedAt) < Date.parse(snapshot.consumedAt)
      ) {
        problems.push('catalogAttestation cannot predate snapshot consumption');
      }
      if (attestation.totalCount !== pagination.boundaryTotalCount) {
        problems.push('catalogAttestation totalCount must match exhaustive pagination');
      }
      if (attestation.membershipDigest !== pagination.membershipDigest) {
        problems.push('catalogAttestation membershipDigest must match exhaustive pagination');
      }
      if (attestation.contentDigest !== pagination.contentDigest) {
        problems.push('catalogAttestation contentDigest must match exhaustive pagination');
      }
      if (
        !Number.isInteger(attestation.finalSweepCount) ||
        attestation.finalSweepCount < 1
      ) {
        problems.push('catalogAttestation finalSweepCount must be at least 1');
      }
      if (
        !Number.isInteger(attestation.finalPagesFetched) ||
        attestation.finalPagesFetched < attestation.finalSweepCount
      ) {
        problems.push(
          'catalogAttestation finalPagesFetched must cover every final sweep',
        );
      }
    }
  }
  return problems;
}

function isSha256Hex(value: unknown): value is string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}

let refreshing = false;
let processLastRefreshAt: string | null = null;
let lastError: string | null = null;
let activeRefresh: {
  promise: Promise<void>;
  resolve: () => void;
  controller: AbortController;
} | null = null;

export function waitForActiveRefresh(): Promise<void> {
  return activeRefresh?.promise ?? Promise.resolve();
}

export function cancelActiveRefresh(
  reason: unknown = new Error('Active refresh cancelled'),
): boolean {
  const current = activeRefresh;
  if (!current || current.controller.signal.aborted) return false;
  current.controller.abort(reason);
  return true;
}

function createRefreshLeaseRegistry() {
  let active: { release(): boolean } | null = null;
  return {
    set(lease: { release(): boolean }): void {
      active = lease;
    },
    clear(lease: { release(): boolean }): void {
      if (active === lease) active = null;
    },
    release(): boolean {
      const lease = active;
      active = null;
      return lease?.release() ?? false;
    },
  };
}

const refreshLeaseRegistry = createRefreshLeaseRegistry();

export function releaseActiveRefreshLease(): boolean {
  return refreshLeaseRegistry.release();
}

export function getRefreshState() {
  return { refreshing, processLastRefreshAt, lastError };
}

class AdvisoryFlatteningError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AdvisoryFlatteningError';
  }
}

class ReleaseRefreshStageError extends Error {
  readonly stage: string;
  readonly releaseTag: string;
  readonly stageCause: unknown;

  constructor(stage: string, releaseTag: string, cause: unknown) {
    super(
      `${stage} failed for ${releaseTag}: ` +
      `${cause instanceof Error ? cause.message : String(cause)}`,
      { cause },
    );
    this.name = 'ReleaseRefreshStageError';
    this.stage = stage;
    this.releaseTag = releaseTag;
    this.stageCause = cause;
  }
}

function flattenAdvisoryVulnerabilityRows(
  advisories: GhAdvisory[],
  expected: { ecosystem: string; packageName: string } = {
    ecosystem: 'npm',
    packageName: config.github.repo,
  },
) {
  const expectedEcosystem = expected.ecosystem.trim().toLowerCase();
  const expectedPackageName = expected.packageName.trim().toLowerCase();

  const rows = advisories.flatMap((adv) => {
    if (adv.state === 'withdrawn') return [];
    if (adv.state !== 'published') {
      throw new AdvisoryFlatteningError(
        `GitHub advisory ${adv.ghsa_id} has unsupported state "${adv.state}" for scoring storage`,
      );
    }
    if (adv.vulnerabilities.length === 0) {
      throw new AdvisoryFlatteningError(`GitHub advisory ${adv.ghsa_id} has no vulnerability rows`);
    }
    return adv.vulnerabilities.map((v) => {
      const ecosystem = v.package?.ecosystem?.trim().toLowerCase() ?? '';
      const packageName = v.package?.name?.trim().toLowerCase() ?? '';
      if (!ecosystem || !packageName) {
        throw new AdvisoryFlatteningError(
          `GitHub advisory ${adv.ghsa_id} vulnerability is missing package identity`,
        );
      }
      if (ecosystem !== expectedEcosystem || packageName !== expectedPackageName) {
        throw new AdvisoryFlatteningError(
          `GitHub advisory ${adv.ghsa_id} vulnerability package ${ecosystem}:${packageName} ` +
          `does not match expected ${expectedEcosystem}:${expectedPackageName}`,
        );
      }
      return {
        advisory_key: advisoryVulnerabilityKey(adv.ghsa_id, ecosystem, packageName, v.vulnerable_version_range),
        ghsa_id: adv.ghsa_id,
        cve_id: adv.cve_id,
        summary: adv.summary,
        severity: adv.severity,
        html_url: adv.html_url,
        published_at: adv.published_at,
        package_ecosystem: ecosystem,
        package_name: packageName,
        vulnerable_version_range: v.vulnerable_version_range,
        patched_versions: v.patched_versions,
      };
    });
  });
  const rowProblems = advisorySnapshotRowProblems(rows, expected);
  if (rowProblems.length > 0) {
    throw new AdvisoryFlatteningError(
      `GitHub advisory snapshot contains invalid vulnerability rows: ` +
      `${JSON.stringify(rowProblems.slice(0, 10))}`,
    );
  }
  return rows;
}

function advisoryIngestionProvenance(
  snapshot: GhAdvisoryCatalog,
  rows: ReturnType<typeof flattenAdvisoryVulnerabilityRows>,
  capturedAt: string,
) {
  const advisories = snapshot.advisories;
  return {
    schemaVersion: 1,
    source: 'github-security-vulnerabilities',
    sourceOrder: snapshot.metadata.sourceOrder,
    ecosystem: 'npm',
    packageName: config.github.repo.toLowerCase(),
    capturedAt,
    exhausted: snapshot.metadata.exhausted,
    stabilized: snapshot.metadata.stabilized,
    totalCount: snapshot.metadata.totalCount,
    nodeCount: snapshot.metadata.nodeCount,
    pageCount: snapshot.metadata.pageCount,
    pagesFetched: snapshot.metadata.pagesFetched,
    sweepCount: snapshot.metadata.sweepCount,
    sourceDigest: snapshot.metadata.digest,
    advisoryCount: advisories.length,
    activeAdvisoryCount: advisories.filter((advisory) => advisory.state === 'published').length,
    withdrawnAdvisoryCount: advisories.filter((advisory) => advisory.state === 'withdrawn').length,
    rowCount: rows.length,
    contentDigest: advisorySnapshotContentHash(rows),
    fetchedAdvisoryCount: advisories.length,
    activeAdvisoryIds: advisories
      .filter((advisory) => advisory.state === 'published')
      .map((advisory) => advisory.ghsa_id)
      .sort(),
    withdrawnAdvisories: advisories
      .filter((advisory) => advisory.state === 'withdrawn')
      .map((advisory) => ({
        ghsaId: advisory.ghsa_id,
        cveId: advisory.cve_id,
        withdrawnAt: advisory.withdrawn_at,
        htmlUrl: advisory.html_url,
        vulnerabilities: advisory.vulnerabilities.map((vulnerability) => ({
          ecosystem: vulnerability.package?.ecosystem ?? null,
          packageName: vulnerability.package?.name ?? null,
          vulnerableVersionRange: vulnerability.vulnerable_version_range,
          patchedVersions: vulnerability.patched_versions,
        })),
      }))
      .sort((a, b) => a.ghsaId.localeCompare(b.ghsaId)),
  };
}

function advisoryIngestionFailurePhase(error: unknown): 'flatten' | 'snapshot-replace' {
  return error instanceof AdvisoryFlatteningError ? 'flatten' : 'snapshot-replace';
}

function recordAdvisoryIngestionFailure(args: {
  error: unknown;
  scope: string;
  packageName: string;
  advisoryCount: number;
  withdrawnAdvisoryCount: number;
  recordFailure: EvidenceFailureRecorder;
}): string {
  return args.recordFailure('advisories', args.scope, args.error, {
    phase: advisoryIngestionFailurePhase(args.error),
    package: args.packageName,
    ecosystem: 'npm',
    advisoryCount: args.advisoryCount,
    withdrawnAdvisoryCount: args.withdrawnAdvisoryCount,
  });
}

export interface RefreshOptions {
  operation?: string;
  trigger?: string;
  signal?: AbortSignal;
}

function refreshOperationLabel(value: string | undefined, fallback: string, field: string): string {
  const normalized = value?.trim() || fallback;
  if (!/^[A-Za-z0-9][A-Za-z0-9._:/+-]{0,127}$/.test(normalized)) {
    throw new Error(`Refresh ${field} must be a stable non-empty identifier`);
  }
  return normalized;
}

function refreshEffectiveConfig(): Record<string, unknown> {
  return operationEffectiveConfig({
    github: {
      owner: config.github.owner,
      repo: config.github.repo,
      graphql: { ...config.github.graphql },
    },
    openai: {
      model: config.openai.model,
      reasoningEffort: config.openai.reasoningEffort,
      serviceTier: config.openai.serviceTier,
      requestTimeoutMs: config.openai.requestTimeoutMs,
      maxAttempts: config.openai.maxAttempts,
      retryBaseMs: config.openai.retryBaseMs,
      retryMaxMs: config.openai.retryMaxMs,
    },
    refresh: { ...config.refresh },
    limits: {
      releases: config.limits.releases,
    },
  });
}

function activeCatalogInputs(
  releases: GhRelease[],
) {
  return releases.map((release) => ({
    node_id: release.node_id,
    catalog_tag_commit_oid: release.tag_commit_oid,
    tag: release.tag_name,
    name: release.name,
    published_at: release.published_at!,
    created_at: release.created_at,
    updated_at: release.updated_at,
    html_url: release.html_url,
    prerelease: release.prerelease,
    body: release.body ?? null,
  }));
}

function finalReleaseCatalogAttestation(args: {
  initialCatalog: GhReleaseCatalog;
  finalCatalog: GhReleaseCatalog;
  monitoredReleaseCount: number;
  scoreRun: ReturnType<typeof buildReleaseScoreRun>;
  scoreBuiltAt: string;
  finalObservedAt: string;
}): ReleaseCatalogAttestation {
  const initialWindow = releaseWindowCompleteness(
    args.initialCatalog,
    args.monitoredReleaseCount,
  );
  if (!initialWindow.complete) {
    throw new Error(initialWindow.reason ?? 'initial release catalog window is incomplete');
  }
  const finalWindow = releaseWindowCompleteness(
    args.finalCatalog,
    args.monitoredReleaseCount,
  );
  if (!finalWindow.complete) {
    throw new Error(finalWindow.reason ?? 'final release catalog window is incomplete');
  }
  if (
    args.initialCatalog.metadata.digest !== args.finalCatalog.metadata.digest ||
    args.initialCatalog.metadata.totalCount !== args.finalCatalog.metadata.totalCount ||
    args.initialCatalog.metadata.nodeCount !== args.finalCatalog.metadata.nodeCount
  ) {
    throw new Error(
      `Release catalog drifted after score construction: ` +
      `${args.initialCatalog.metadata.digest}/${args.initialCatalog.metadata.nodeCount} -> ` +
      `${args.finalCatalog.metadata.digest}/${args.finalCatalog.metadata.nodeCount}`,
    );
  }
  const finalSelection = selectReleaseWindow(
    args.finalCatalog,
    args.monitoredReleaseCount,
  );
  const projected = projectActiveReleaseCatalog(
    activeCatalogInputs(finalSelection.ordered),
  );
  const local = currentActiveReleaseCatalog();
  if (
    projected.digest !== local.digest ||
    projected.releaseCount !== local.releaseCount
  ) {
    throw new Error(
      `Final remote release catalog does not match the active local catalog: ` +
      `${projected.digest}/${projected.releaseCount} != ` +
      `${local.digest}/${local.releaseCount}`,
    );
  }
  const latestFinalStable = finalSelection.monitored[0];
  if (
    !latestFinalStable?.published_at ||
    !local.latestStable ||
    latestFinalStable.node_id !== local.latestStable.nodeId ||
    latestFinalStable.tag_name !== local.latestStable.tag ||
    latestFinalStable.tag_commit_oid !== local.latestStable.tagCommitOid ||
    latestFinalStable.published_at !== local.latestStable.publishedAt
  ) {
    throw new Error('Final remote latest stable does not match the active local catalog');
  }
  const latestScored = args.scoreRun.scored.find((result) =>
    result.rel.tag === latestFinalStable.tag_name);
  if (
    !latestScored ||
    latestScored.rel.node_id !== latestFinalStable.node_id ||
    latestScored.rel.catalog_tag_commit_oid !== latestFinalStable.tag_commit_oid ||
    latestScored.rel.published_at !== latestFinalStable.published_at
  ) {
    throw new Error('Final remote latest stable does not match the constructed score run');
  }
  const attestation: ReleaseCatalogAttestation = {
    schemaVersion: 4,
    initialRemoteCatalog: {
      digest: args.initialCatalog.metadata.digest,
      totalCount: args.initialCatalog.metadata.totalCount,
      nodeCount: args.initialCatalog.metadata.nodeCount,
      pageCount: args.initialCatalog.metadata.pageCount,
      pagesFetched: args.initialCatalog.metadata.pagesFetched,
      sweepCount: args.initialCatalog.metadata.sweepCount,
      exhausted: true,
      stabilized: true,
      sourceOrder: args.initialCatalog.metadata.sourceOrder,
    },
    finalRemoteCatalog: {
      digest: args.finalCatalog.metadata.digest,
      totalCount: args.finalCatalog.metadata.totalCount,
      nodeCount: args.finalCatalog.metadata.nodeCount,
      pageCount: args.finalCatalog.metadata.pageCount,
      pagesFetched: args.finalCatalog.metadata.pagesFetched,
      sweepCount: args.finalCatalog.metadata.sweepCount,
      exhausted: true,
      stabilized: true,
      sourceOrder: args.finalCatalog.metadata.sourceOrder,
    },
    finalObservedAt: args.finalObservedAt,
    projectedActiveCatalog: {
      digest: projected.digest,
      releaseCount: projected.releaseCount,
    },
    localActiveCatalog: {
      digest: local.digest,
      releaseCount: local.releaseCount,
    },
    latestStable: {
      nodeId: latestFinalStable.node_id,
      tag: latestFinalStable.tag_name,
      tagCommitOid: latestFinalStable.tag_commit_oid,
      publishedAt: latestFinalStable.published_at,
    },
    scoreBuiltAt: args.scoreBuiltAt,
  };
  const problems = releaseCatalogAttestationProblems(attestation);
  if (problems.length > 0) {
    throw new Error(`Final release catalog attestation is invalid: ${problems.join('; ')}`);
  }
  return attestation;
}

function successReceiptPayload(args: {
  operation: string;
  trigger: string;
  codeRevision: string;
  scoreRun: ReturnType<typeof buildReleaseScoreRun>;
  scorePersistence: ReturnType<typeof persistReleaseScoreRun>;
  forecastCapture: ReleaseValidationForecastCaptureResult;
  advisoryProvenance: CompoundAdvisorySnapshotMetadata;
  releaseArtifacts: ReturnType<typeof releaseArtifactPublicationForRun>;
}): Record<string, unknown> {
  const issueCrawl = args.scorePersistence.issueCrawlMetadata;
  if (!issueCrawl) {
    throw new Error('Refresh success receipt requires persisted issue crawl metadata');
  }
  const catalogAttestation = args.scorePersistence.catalogAttestation;
  if (!catalogAttestation) {
    throw new Error('Refresh success receipt requires catalog attestation');
  }
  const validationForecasts = args.forecastCapture.forecasts;
  const canonicalValidationForecasts = args.forecastCapture.canonicalForecasts;
  const scoreMetadata = JSON.parse(getMeta('score_persistence_last_run') ?? 'null');
  if (
    !scoreMetadata ||
    typeof scoreMetadata !== 'object' ||
    Array.isArray(scoreMetadata) ||
    scoreMetadata.historyRunId !== args.scorePersistence.historyRunId ||
    scoreMetadata.historyRunContentHash !== args.scorePersistence.historyRunContentHash ||
    scoreMetadata.authorityRunId !== args.scorePersistence.authorityRunId ||
    scoreMetadata.authorityRunContentHash !==
      args.scorePersistence.authorityRunContentHash ||
    scoreMetadata.historyV2SealContentHash !==
      args.scorePersistence.historyV2SealContentHash
  ) {
    throw new Error('Refresh success receipt requires finalized score publication metadata');
  }
  const validationEnrollments =
    listReleaseValidationOpportunityEnrollments().filter((row) =>
      row.release_tag === catalogAttestation.latestStable.tag &&
      row.release_published_at === catalogAttestation.latestStable.publishedAt &&
      row.score_model_version === SCORE_MODEL_VERSION &&
      row.prompt_version === PROMPT_VERSION &&
      row.code_revision === args.codeRevision);
  const forecastCaptures = validationForecasts.map((forecast) => {
    const enrollment = validationEnrollments.find((row) =>
      row.opportunity_code === forecast.opportunityCode);
    if (!enrollment) {
      throw new Error(
        `Refresh success receipt forecast ${forecast.opportunityCode} has no ` +
        `persisted validation opportunity enrollment`,
      );
    }
    return {
      ...forecast,
      opportunityId: enrollment.opportunity_id,
      enrollmentContentHash: enrollment.content_hash,
    };
  });
  return {
    schemaVersion: 3,
    operation: args.operation,
    trigger: args.trigger,
    codeRevision: args.codeRevision,
    scoreHistory: {
      runId: args.scorePersistence.historyRunId,
      contentHash: args.scorePersistence.historyRunContentHash,
      persistedAt: args.scorePersistence.persistedAt,
    },
    scoreAuthority: {
      runId: args.scorePersistence.authorityRunId,
      contentHash: args.scorePersistence.authorityRunContentHash,
      historyV2SealContentHash: args.scorePersistence.historyV2SealContentHash,
    },
    scoreCommit: args.scorePersistence.commitTiming,
    scoreMetadata,
    scoreRows: args.scoreRun.scored.map((result) => ({
      tag: result.rel.tag,
      finalScore: result.conf.score,
      negativeIssues: result.neg,
      positiveIssues: result.pos,
      state: result.conf.status,
      recommended: result.rel.tag === args.scoreRun.recommendedTag,
      scoreReason: result.conf.reason,
      brokenSurfaces: result.brokenSurfaces,
      closedSeriousFixed: result.closedSerious,
      openedSeriousDuringReign: result.openedSerious,
      scoredAt: result.scoredAt,
    })),
    releaseTags: args.scoreRun.scored.map((result) => result.rel.tag),
    releaseArtifacts: args.releaseArtifacts,
    releaseArtifactScope: buildReleaseArtifactPublicationScope({
      scoredReleaseTags: args.scoreRun.scored.map((result) => result.rel.tag),
      predecessorByReleaseTag: args.scoreRun.predecessorByReleaseTag,
    }),
    recommendation: {
      selectedTag: args.scoreRun.recommendedTag,
      decisions: args.scoreRun.scored.map((result) => ({
        releaseTag: result.rel.tag,
        decision: result.recommendationDecision ?? result.explanation.recommendationDecision ?? null,
      })),
    },
    issueCrawl: {
      metaKey: ISSUE_CRAWL_META_KEY,
      metadataDigest: createHash('sha256').update(canonicalJson(issueCrawl)).digest('hex'),
      metadata: issueCrawl,
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
      metadataDigest: compoundAdvisorySnapshotMetadataDigest(
        args.advisoryProvenance,
      ),
      metadata: args.advisoryProvenance,
      snapshotId: args.advisoryProvenance.snapshotId,
      sourceHash: args.advisoryProvenance.sourceHash,
      catalogHash: args.advisoryProvenance.catalogHash,
      scoreHash: args.advisoryProvenance.scoreHash,
      contentHash: args.advisoryProvenance.contentHash,
      contentDigest: args.advisoryProvenance.scoreContentDigest,
      advisoryCount: args.advisoryProvenance.scoreRowCount,
      rowCount: args.advisoryProvenance.scoreRowCount,
      catalogRowCount: args.advisoryProvenance.rowCount,
      scoreRowCount: args.advisoryProvenance.scoreRowCount,
    },
    forecast: {
      eligibilityOutcome: args.forecastCapture.eligibilityOutcome,
      decisionIds: validationForecasts.map((forecast) => forecast.decisionId),
      newDecisionIds: validationForecasts
        .filter((forecast) => forecast.status === 'inserted')
        .map((forecast) => forecast.decisionId),
      existingDecisionIds: validationForecasts
        .filter((forecast) => forecast.status === 'already_captured')
        .map((forecast) => forecast.decisionId),
      captures: forecastCaptures,
      canonicalForecastIds: canonicalValidationForecasts
        .map((forecast) => forecast.forecastId),
      canonicalForecastContentHashes: canonicalValidationForecasts
        .map((forecast) => forecast.contentHash),
      newCanonicalForecastIds: canonicalValidationForecasts
        .filter((forecast) => forecast.status === 'inserted')
        .map((forecast) => forecast.forecastId),
      existingCanonicalForecastIds: canonicalValidationForecasts
        .filter((forecast) => forecast.status === 'already_captured')
        .map((forecast) => forecast.forecastId),
      canonicalCaptures: canonicalValidationForecasts,
    },
  };
}

class AdvisoryScorePreviewRollback extends Error {
  constructor(
    readonly scoreRun: ReturnType<typeof buildReleaseScoreRun>,
  ) {
    super('rollback advisory score preview');
    this.name = 'AdvisoryScorePreviewRollback';
  }
}

function buildReleaseScoreRunForStagedAdvisory(
  snapshotId: number,
  options: Parameters<typeof buildReleaseScoreRun>[0],
  assertCanWrite: (stage: string) => void,
): ReturnType<typeof buildReleaseScoreRun> {
  try {
    return runInWriteTransaction(() => {
      activateCompoundAdvisorySnapshot(snapshotId, { assertCanWrite });
      const scoreRun = buildReleaseScoreRun(options);
      throw new AdvisoryScorePreviewRollback(scoreRun);
    });
  } catch (error) {
    if (error instanceof AdvisoryScorePreviewRollback) return error.scoreRun;
    throw error;
  }
}

type RefreshOrchestrationDependencies = {
  beginAttempt: typeof beginRefreshOperationAttempt;
  appendStageEvent: typeof appendRefreshOperationStageEvent;
  appendReceipt: typeof appendRefreshCaptureReceipt;
  transaction: typeof runInWriteTransaction;
  nowMs: () => number;
  randomId: () => string;
};

function createRefreshOrchestration(args: {
  operation: string;
  trigger: string;
  codeRevision: string;
  effectiveConfig: Record<string, unknown>;
  leaseName: string;
  leaseHolderId: string;
  leaseTtlMs: number;
  startedAt?: string;
  onStageComplete?: (stage: string, durationMs: number) => void;
  dependencies?: Partial<RefreshOrchestrationDependencies>;
}) {
  const dependencies: RefreshOrchestrationDependencies = {
    beginAttempt: beginRefreshOperationAttempt,
    appendStageEvent: appendRefreshOperationStageEvent,
    appendReceipt: appendRefreshCaptureReceipt,
    transaction: runInWriteTransaction,
    nowMs: Date.now,
    randomId: randomUUID,
    ...args.dependencies,
  };
  const startedAt = args.startedAt ?? new Date(dependencies.nowMs()).toISOString();
  const runId = `${startedAt}:${args.leaseHolderId}`;
  let terminalReceiptId: string | null = null;
  dependencies.beginAttempt({
    run_id: runId,
    operation: args.operation,
    trigger: args.trigger,
    started_at: startedAt,
    lease_name: args.leaseName,
    lease_holder_id: args.leaseHolderId,
    lease_expires_at: new Date(
      Date.parse(startedAt) + args.leaseTtlMs,
    ).toISOString(),
    code_revision: args.codeRevision,
    effective_config: args.effectiveConfig,
  });
  const stageTimer = createStageTimer(
    dependencies.nowMs,
    args.onStageComplete,
    (event) => {
      dependencies.appendStageEvent({
        event_id: `stage:${dependencies.randomId()}`,
        run_id: runId,
        lease_name: args.leaseName,
        lease_holder_id: args.leaseHolderId,
        stage: event.stage,
        status: event.status,
        occurred_at: event.occurredAt,
        duration_ms: event.durationMs,
        counts: event.counts,
        details: event.details,
      });
    },
  );

  const appendManualStageEvent = (
    stage: string,
    status: OperationStageStatus,
    occurredAt: string,
    durationMs: number | null,
    counts: Record<string, unknown> | null = null,
    details: Record<string, unknown> | null = null,
  ) => dependencies.appendStageEvent({
    event_id: `stage:${dependencies.randomId()}`,
    run_id: runId,
    lease_name: args.leaseName,
    lease_holder_id: args.leaseHolderId,
    stage,
    status,
    occurred_at: occurredAt,
    duration_ms: durationMs,
    counts,
    details,
  });

  return {
    runId,
    startedAt,
    stageTimer,
    timed: stageTimer.timed,
    snapshot: stageTimer.snapshot,
    terminalReceiptId: () => terminalReceiptId,
    async run<T>(work: (operation: {
      runId: string;
      startedAt: string;
      timed: typeof stageTimer.timed;
      snapshot: typeof stageTimer.snapshot;
    }) => Promise<T>): Promise<T> {
      try {
        return await work({
          runId,
          startedAt,
          timed: stageTimer.timed,
          snapshot: stageTimer.snapshot,
        });
      } catch (error) {
        this.fail(error);
        throw error;
      }
    },
    publishScore<TScoreRun, TScorePersistence, TForecast>(options: {
      scoreRun: TScoreRun;
      scoredReleaseCount: number;
      preparePublication?: () => void;
      assertScorePersistAllowed?: () => void;
      activatePublication?: () => void;
      persistScore: () => TScorePersistence;
      afterPersist?: (scorePersistence: TScorePersistence) => void;
      scorePersistDetails?: (
        scorePersistence: TScorePersistence,
      ) => Record<string, unknown> | null;
      assertForecastAllowed?: () => void;
      assertCommitAllowed?: () => void;
      finalizeScore: (scorePersistence: TScorePersistence) => void;
      captureForecast: (
        scorePersistence: TScorePersistence,
      ) => TForecast;
      forecastCount: (forecast: TForecast) => number;
      forecastDetails: (forecast: TForecast) => Record<string, unknown> | null;
      successPayload: (
        scorePersistence: TScorePersistence,
        forecast: TForecast,
      ) => Record<string, unknown>;
      mapScorePersistError?: (error: unknown) => unknown;
      mapForecastError?: (
        error: unknown,
        scorePersistence: TScorePersistence,
      ) => unknown;
      forecastFailureDetails?: (
        error: unknown,
        scorePersistence: TScorePersistence,
      ) => Record<string, unknown> | null;
    }): {
      scorePersistence: TScorePersistence;
      forecast: TForecast;
      receiptId: string;
    } {
      stageTimer.ensure('score.persist');
      const scorePersistStartedAtMs = dependencies.nowMs();
      const finishScorePersistTiming = stageTimer.start('score.persist', {
        emitEvents: false,
      });
      appendManualStageEvent(
        'score.persist',
        'started',
        new Date(scorePersistStartedAtMs).toISOString(),
        null,
      );
      let scorePersistence: TScorePersistence | undefined;
      let publicationPhase = 'score.persist';
      let finishForecastCaptureTiming: () => number = () => 0;
      try {
        options.preparePublication?.();
        const finalized = dependencies.transaction(() => {
          options.assertScorePersistAllowed?.();
          options.activatePublication?.();
          scorePersistence = options.persistScore();
          options.afterPersist?.(scorePersistence);
          const scorePersistedAtMs = dependencies.nowMs();
          appendManualStageEvent(
            'score.persist',
            'completed',
            new Date(scorePersistedAtMs).toISOString(),
            Math.max(0, scorePersistedAtMs - scorePersistStartedAtMs),
            { scoredReleases: options.scoredReleaseCount },
            options.scorePersistDetails?.(scorePersistence) ?? null,
          );
          finishScorePersistTiming();

          publicationPhase = 'forecast.capture';
          stageTimer.ensure('forecast.capture');
          const forecastCaptureStartedAtMs = dependencies.nowMs();
          finishForecastCaptureTiming = stageTimer.start('forecast.capture', {
            emitEvents: false,
          });
          appendManualStageEvent(
            'forecast.capture',
            'started',
            new Date(forecastCaptureStartedAtMs).toISOString(),
            null,
          );
          options.assertForecastAllowed?.();
          options.finalizeScore(scorePersistence);
          const forecast = options.captureForecast(scorePersistence);
          const finishedAtMs = dependencies.nowMs();
          const finishedAt = new Date(finishedAtMs).toISOString();
          appendManualStageEvent(
            'forecast.capture',
            'completed',
            finishedAt,
            Math.max(0, finishedAtMs - forecastCaptureStartedAtMs),
            { validationForecasts: options.forecastCount(forecast) },
            options.forecastDetails(forecast),
          );
          finishForecastCaptureTiming();
          finishForecastCaptureTiming = () => 0;

          publicationPhase = 'success.receipt';
          const receipt = dependencies.appendReceipt({
            run_id: runId,
            lease_name: args.leaseName,
            lease_holder_id: args.leaseHolderId,
            status: 'success',
            finished_at: finishedAt,
            duration_ms: Math.max(0, finishedAtMs - Date.parse(startedAt)),
            payload: options.successPayload(scorePersistence, forecast),
          });
          publicationPhase = 'commit.fence';
          options.assertCommitAllowed?.();
          return { scorePersistence, forecast, receipt };
        });
        terminalReceiptId = finalized.receipt.row.receipt_id;
        return {
          scorePersistence: finalized.scorePersistence,
          forecast: finalized.forecast,
          receiptId: terminalReceiptId,
        };
      } catch (error) {
        finishForecastCaptureTiming();
        finishForecastCaptureTiming = () => 0;
        finishScorePersistTiming();
        const failedAtMs = dependencies.nowMs();
        try {
          const failureDetails = scorePersistence
            ? options.forecastFailureDetails?.(error, scorePersistence) ?? null
            : null;
          appendManualStageEvent(
            'score.persist',
            'failed',
            new Date(failedAtMs).toISOString(),
            Math.max(0, failedAtMs - scorePersistStartedAtMs),
            null,
            {
              error: operationErrorDetails(error),
              publicationPhase,
              ...(failureDetails ?? {}),
            },
          );
        } catch (stageError) {
          console.error(
            `[refresh:receipt] failed to append score.persist failure event: ` +
            `${(stageError as Error).message}`,
          );
        }
        if (scorePersistence && options.mapForecastError) {
          throw options.mapForecastError(error, scorePersistence);
        }
        throw options.mapScorePersistError
          ? options.mapScorePersistError(error)
          : error;
      }
    },
    fail(error: unknown): string | null {
      if (terminalReceiptId) return terminalReceiptId;
      try {
        stageTimer.failActive(error);
      } catch (stageError) {
        console.error(
          `[refresh:receipt] failed to close active stage events: ` +
          `${(stageError as Error).message}`,
        );
      }
      try {
        const finishedAtMs = dependencies.nowMs();
        terminalReceiptId = dependencies.appendReceipt({
          run_id: runId,
          lease_name: args.leaseName,
          lease_holder_id: args.leaseHolderId,
          status: 'failure',
          finished_at: new Date(finishedAtMs).toISOString(),
          duration_ms: Math.max(0, finishedAtMs - Date.parse(startedAt)),
          payload: {
            schemaVersion: 1,
            operation: args.operation,
            trigger: args.trigger,
            codeRevision: args.codeRevision,
            error: operationErrorDetails(error),
            timings: stageTimer.snapshot(),
          },
        }).row.receipt_id;
      } catch (receiptError) {
        console.error(
          `[refresh:receipt] failed to append failure receipt for ${runId}: ` +
          `${(receiptError as Error).message}`,
        );
      }
      return terminalReceiptId;
    },
  };
}

export async function refresh(options: RefreshOptions = {}): Promise<{
  runId: string;
  receiptId: string;
  classifiedCount: number;
  releaseCount: number;
  durationMs: number;
  timings: Record<string, number>;
  releaseCatalog: GhReleaseCatalog['metadata'];
}> {
  if (refreshing) throw new Error('refresh already running');
  const operation = refreshOperationLabel(options.operation, 'refresh', 'operation');
  const trigger = refreshOperationLabel(options.trigger, 'unspecified', 'trigger');
  const codeRevision = codeRevisionFromEnv();
  if (!codeRevision) {
    throw new Error('Refresh requires deterministic code revision provenance');
  }
  const effectiveConfig = refreshEffectiveConfig();
  throwIfAborted(options.signal);
  refreshing = true;
  const refreshController = new AbortController();
  const composedRefreshSignal = composeAbortSignals([
    options.signal,
    refreshController.signal,
  ]);
  const signal = composedRefreshSignal.signal;
  let resolveActiveRefresh!: () => void;
  const activePromise = new Promise<void>((resolve) => {
    resolveActiveRefresh = resolve;
  });
  activeRefresh = {
    promise: activePromise,
    resolve: resolveActiveRefresh,
    controller: refreshController,
  };
  lastError = null;
  const t0 = Date.now();
  const leaseHolderId = `${process.pid}:${randomUUID()}`;
  let terminalReceiptId: string | null = null;
  let stageTimer: ReturnType<typeof createStageTimer> | null = null;
  let orchestration: ReturnType<typeof createRefreshOrchestration> | null = null;
  const refreshLease = createRefreshLeaseGuard({
    name: REFRESH_LEASE_NAME,
    holderId: leaseHolderId,
    ttlMs: REFRESH_LEASE_TTL_MS,
    now: () => new Date().toISOString(),
    acquire: acquireRefreshLease,
    renew: renewRefreshLease,
    release: releaseRefreshLease,
    onFailure: abortRefreshOnLeaseFailure(refreshController),
  });

  try {
    throwIfAborted(signal);
    refreshLease.acquire();
    const refreshStartedAt = new Date().toISOString();
    orchestration = createRefreshOrchestration({
      operation,
      trigger,
      codeRevision,
      effectiveConfig,
      leaseName: REFRESH_LEASE_NAME,
      leaseHolderId,
      leaseTtlMs: REFRESH_LEASE_TTL_MS,
      startedAt: refreshStartedAt,
      onStageComplete: (stage, durationMs) => {
        console.log(`[refresh:timing] ${stage}: ${durationMs}ms`);
      },
    });
    const runId = orchestration.runId;
    refreshLeaseRegistry.set(refreshLease);
    refreshLease.startHeartbeat(REFRESH_LEASE_HEARTBEAT_MS);
    const activeStageTimer = orchestration.stageTimer;
    stageTimer = activeStageTimer;
    const timed = activeStageTimer.timed;
    const timingSnapshot = activeStageTimer.snapshot;
    const operationAttempt = getRefreshOperationAttempt(runId);
    if (!operationAttempt) {
      throw new Error(
        `Refresh ${runId} is missing its durable operation attempt`,
      );
    }
    const releaseCatalogOperationBinding = {
      operationRunId: runId,
      operation: operationAttempt.operation,
      operationAttemptContentHash: operationAttempt.content_hash,
    };
    return await runWithPendingReleaseCatalogReadAuthority(
      runId,
      async () => {
    const evidenceRefreshFailures: string[] = [];
    let advisoryProvenance: CompoundAdvisorySnapshotMetadata | null = null;
    let releaseCatalogMetadata: GhReleaseCatalog['metadata'] | null = null;
    const issueBaselineAtRefreshStart = parseIssueCrawlBaseline(
      getMeta(ISSUE_CRAWL_BASELINE_META_KEY) ?? null,
    );
    const assertRefreshWriteAllowed = (stage: string): void => {
      throwIfAborted(signal);
      refreshLease.assertHeld(stage);
    };
    const runRefreshWrite = <T>(stage: string, write: () => T): T =>
      runLeaseFencedWrite(stage, assertRefreshWriteAllowed, write);
    const persistIssueCrawlMeta = (meta: Record<string, unknown>): void => {
      runRefreshWrite('issue crawl metadata', () => {
        persistIssueCrawlMetaUnchecked(meta);
      });
    };
    const recordEvidenceRefreshFailure = (
      source: string,
      scope: string | null,
      error: unknown,
      context: Record<string, unknown> = {},
    ): string => {
      const message = evidenceRefreshFailureMessage(source, scope, error);
      evidenceRefreshFailures.push(message);
      runRefreshWrite(`evidence failure ${source}`, () => {
        insertIngestionEvidenceFailure({
          run_id: runId,
          source,
          scope,
          release_tag: typeof context.releaseTag === 'string' ? context.releaseTag : null,
          issue_number: typeof context.issueNumber === 'number' ? context.issueNumber : null,
          pr_repository_name_with_owner: typeof context.prRepositoryNameWithOwner === 'string' ? context.prRepositoryNameWithOwner : null,
          pr_number: typeof context.prNumber === 'number' ? context.prNumber : null,
          message,
          context_json: JSON.stringify({
            ...context,
            timings: timingSnapshot(),
          }),
          scoring_blocking: 1,
        });
      });
      return message;
    };
    const persistEarlyEvidenceFailureCrawlMeta = () => {
      persistIssueCrawlMeta({
        schemaVersion: ISSUE_CRAWL_SCHEMA_VERSION,
        startedAt: refreshStartedAt,
        finishedAt: new Date().toISOString(),
        fullIssueBackfill: config.refresh.fullIssueBackfill,
        crawlMode: config.refresh.fullIssueBackfill ? 'exhaustive' : 'incremental',
        backfillCompleteAtStart: issueBaselineAtRefreshStart != null,
        backfillCompleteAfterRun: parseIssueCrawlBaseline(
          getMeta(ISSUE_CRAWL_BASELINE_META_KEY) ?? null,
        ) != null,
        baseline: issueBaselineAtRefreshStart,
        pagination: null,
        promptSweep: false,
        staleClassificationsAtStart: countStaleClassifications(PROMPT_VERSION),
        monitoredReleaseCount: config.limits.releases,
        oldestMonitoredAt: null,
        pagesFetched: 0,
        issuesFetched: 0,
        monitoredIssuesFetched: 0,
        maxIssuePages: config.refresh.maxIssuePages,
        stopReason: 'evidence_failure',
        crossedOldestEver: false,
        commenterScanTruncatedCount: 0,
        classificationFailures: [],
        evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
        advisoryProvenance,
        releaseCatalog: releaseCatalogMetadata,
        scorePersisted: false,
        scorePersistedAt: null,
        timings: timingSnapshot(),
      });
    };
    // 1. Pull the complete release connection and accept it only after two
    // consecutive exhaustive sweeps produce the same canonical digest. GitHub
    // orders the connection by createdAt, so publication-order selection happens
    // only after the catalog is complete and stable.
    // Monitor only the latest `config.limits.releases` (default 10). This is the
    // expensive window: it drives the issue-classification cutoff (oldestMonitoredMs
    // below) and thus how many LLM calls a back-fill / prompt-sweep costs. The score
    // chart renders up to SCORE_HISTORY_CHART_LIMIT (20) points, but there's no sense
    // running the long classification pass that wide — the focus is the recent 10.
    // Chart points 11–20 are intentionally frozen rows already scored in past runs
    // (served straight from the DB), kept purely as comparative trend context.
    const monitoredReleaseCount = config.limits.releases;
    let releaseCatalog: GhReleaseCatalog;
    try {
      releaseCatalog = await timed(
        'release.fetch',
        () => fetchReleaseCatalog({
          signal,
          operationBinding: releaseCatalogOperationBinding,
        }),
      );
      releaseCatalogMetadata = releaseCatalog.metadata;
    } catch (e) {
      const message = recordEvidenceRefreshFailure('release-metadata', 'fetchReleaseCatalog', e, {
        monitoredReleaseCount,
      });
      console.warn(`${message}; refusing score persistence before release metadata refresh completes`);
      persistEarlyEvidenceFailureCrawlMeta();
      throw new Error(`${message}; refusing score persistence before release metadata refresh completes`);
    }
    const releaseWindow = releaseWindowCompleteness(releaseCatalog, monitoredReleaseCount);
    if (!releaseWindow.complete) {
      const error = new Error(releaseWindow.reason ?? 'release window is incomplete');
      const message = recordEvidenceRefreshFailure('release-window', 'fetchReleaseCatalog', error, {
        monitoredReleaseCount,
        stableCount: releaseWindow.stableCount,
        fetchedCount: releaseCatalog.metadata.nodeCount,
        exhausted: releaseWindow.exhausted,
        stabilized: releaseCatalog.metadata.stabilized,
        totalCount: releaseCatalog.metadata.totalCount,
        sweepCount: releaseCatalog.metadata.sweepCount,
        digest: releaseCatalog.metadata.digest,
        oldestMonitoredTag: releaseWindow.oldestMonitoredTag,
      });
      console.warn(`${message}; refusing score persistence before release metadata refresh completes`);
      persistEarlyEvidenceFailureCrawlMeta();
      throw new Error(`${message}; refusing score persistence before release metadata refresh completes`);
    }
    let releaseSelection: ReturnType<typeof selectReleaseWindow<GhRelease>>;
    try {
      releaseSelection = selectReleaseWindow(releaseCatalog, monitoredReleaseCount);
    } catch (error) {
      const message = recordEvidenceRefreshFailure('release-window', 'publication-order', error, {
        monitoredReleaseCount,
        releaseCatalog: releaseCatalog.metadata,
      });
      console.warn(`${message}; refusing score persistence before release metadata refresh completes`);
      persistEarlyEvidenceFailureCrawlMeta();
      throw new Error(`${message}; refusing score persistence before release metadata refresh completes`);
    }
    const releases = releaseSelection.monitored;
    const predecessorBoundary = releaseSelection.predecessorBoundary;
    const activeCatalogRows =
      activeCatalogInputs(releaseSelection.ordered);
    const releaseCatalogAuthorization =
      authorizeGithubReleaseCatalogPublication(
        releaseCatalog,
        activeCatalogRows,
      );
    assertRefreshWriteAllowed('release metadata persistence');
    const activeCatalogIdentity = replaceActiveReleaseCatalog(
      activeCatalogRows,
      {
        capture: {
          source: 'github_graphql',
          operationRunId: runId,
          authorization: releaseCatalogAuthorization,
        },
        assertCanWrite: assertRefreshWriteAllowed,
      },
    );
    console.log(
      `[refresh] activated release catalog ${activeCatalogIdentity.digest} ` +
      `(${activeCatalogIdentity.releaseCount} releases)`,
    );
    const validationProofLifecycle = await timed(
      'validation.proof.catalog',
      () => runRefreshWrite('validation proof catalog', () => {
        const observedAt = new Date().toISOString();
        const plan = planReleaseValidationProofLifecycle({
          existing: readReleaseValidationProofBundle(),
          repository: `${config.github.owner}/${config.github.repo}`,
          observedAt,
          source: 'github_graphql_stable_releases',
          releases: releaseSelection.ordered
            .filter((release) => !release.prerelease)
            .map((release) => ({
              repository: `${config.github.owner}/${config.github.repo}`,
              nodeId: release.node_id,
              tagCommitOid: release.tag_commit_oid,
              publishedAt: release.published_at!,
              aliases: [release.tag_name],
            })),
          modelVersion: SCORE_MODEL_VERSION,
          promptVersion: PROMPT_VERSION,
          codeRevision,
          policyCode: 'prospective-release-validation',
          policyVersion: 1,
          developmentArm: 'production',
          developmentReleaseCount:
            RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
        });
        return {
          plan,
          persistence: appendReleaseValidationProof(plan.append),
        };
      }),
    );
    console.log(
      `[refresh] validation proof catalog appended ` +
      `${validationProofLifecycle.persistence.insertedCount} new, ` +
      `${validationProofLifecycle.persistence.equivalentCount} existing ` +
      `(${validationProofLifecycle.plan.admittedReleaseCount} prospective ` +
      `release admission(s))`,
    );
    try {
      refreshLease.renew('repository collaborator authority');
      const collaboratorSnapshot = await timed(
        'authority.collaborators.fetch',
        () => fetchRepositoryCollaboratorPermissionSnapshot({ signal }),
      );
      refreshLease.assertHeld('repository collaborator authority persistence');
      const persistedCollaboratorSnapshot =
        insertRepositoryCollaboratorPermissionSnapshotV2(
          collaboratorSnapshot,
          { assertCanWrite: assertRefreshWriteAllowed },
        );
      console.log(
        `[authority] collaborator snapshot ${persistedCollaboratorSnapshot.snapshotId} ` +
          `covers ${persistedCollaboratorSnapshot.rowCount} actor(s) across ` +
          `${persistedCollaboratorSnapshot.sweepCount} stabilized sweep(s)`,
      );
    } catch (error) {
      const message = recordEvidenceRefreshFailure(
        'repository-collaborator-authority',
        `${config.github.owner}/${config.github.repo}`,
        error,
        {
          requiredEvidence: 'stabilized exhaustive collaborator permission snapshot v2',
        },
      );
      console.warn(
        `${message}; refusing score persistence without immutable maintainer authority`,
      );
      persistEarlyEvidenceFailureCrawlMeta();
      throw new Error(
        `${message}; refusing score persistence without immutable maintainer authority`,
      );
    }
    let validationEnrollmentInsertedCount = 0;
    let validationEnrollmentEquivalentCount = 0;
    const validationEnrollmentRows = await timed(
      'validation.enroll',
      () => {
        refreshLease.assertHeld('validation opportunity enrollment');
        const activeCatalog = currentActiveReleaseCatalog();
        const attempt = getRefreshOperationAttempt(runId);
        if (!activeCatalog.latestStable || !attempt) {
          throw new Error(
            'Validation opportunity enrollment requires the active latest stable ' +
            'and durable refresh attempt',
          );
        }
        const enrolledAt = new Date().toISOString();
        const persistedEnrollments =
          listReleaseValidationOpportunityEnrollments();
        const cohortInceptionAt = persistedEnrollments
          .filter((row) =>
            row.score_model_version === SCORE_MODEL_VERSION &&
            row.prompt_version === PROMPT_VERSION &&
            row.code_revision === codeRevision)
          .map((row) => row.cohort_inception_at)
          .filter((value) => Number.isFinite(Date.parse(value)))
          .sort((left, right) => Date.parse(left) - Date.parse(right))[0] ??
          enrolledAt;
        const enrollments = listReleasesDb(activeCatalog.releaseCount)
          .filter((release) =>
            release.catalog_active === 1 &&
            release.prerelease === 0 &&
            release.node_id &&
            release.catalog_tag_commit_oid &&
            release.published_at)
          .flatMap((release) =>
            planReleaseValidationOpportunityEnrollments({
              enrolledAt,
              cohortInceptionAt,
              release: {
                nodeId: release.node_id!,
                tag: release.tag,
                tagCommitOid: release.catalog_tag_commit_oid!,
                publishedAt: release.published_at!,
              },
              cohort: {
                modelVersion: SCORE_MODEL_VERSION,
                promptVersion: PROMPT_VERSION,
                codeRevision,
              },
              evidence: {
                enrollmentRunId: runId,
                operationAttemptContentHash: attempt.content_hash,
                catalogDigest: activeCatalogIdentity.digest,
                catalogReleaseCount: activeCatalogIdentity.releaseCount,
              },
            }));
        const result = insertReleaseValidationOpportunityEnrollments({
          enrollments,
          lease_name: REFRESH_LEASE_NAME,
          lease_holder_id: leaseHolderId,
        });
        validationEnrollmentInsertedCount = result.insertedCount;
        validationEnrollmentEquivalentCount = result.equivalentCount;
        return result.rows;
      },
    );
    console.log(
      `[refresh] validation denominator enrolled ` +
      `${validationEnrollmentInsertedCount} new, ` +
      `${validationEnrollmentEquivalentCount} existing ` +
      `(${validationEnrollmentRows.length} prospective slots)`,
    );
    const tags = releases.map((r) => r.tag_name);
    const classifierIdentity = classifierSourceIdentity(tags, PROMPT_VERSION);

    // Derived stats per stable: parse maintainer-signal counts from the body,
    // count preceding prereleases and time-to-next-release. No new API calls —
    // all data comes from the publication-ordered catalog context. Failure here
    // is a code bug, not a network
    // issue, so we don't try/catch — let it surface during dev.
    //
    // releasesForCalc carries `breakingCount` from each context body (including
    // prereleases) so `computeAggregateBreaking` can roll a stable's preceding
    // beta chain into its stored `breaking_count`. Without this, a `### Breaking`
    // bullet that only appears in a beta body (and is not repeated in the stable
    // body at promotion time) would be invisible — see comment on
    // computeAggregateBreaking in releaseNotes.ts.
    const releasesForCalc = releaseSelection.ordered.map((r) => ({
      tag: r.tag_name,
      published_at: r.published_at,
      prerelease: r.prerelease,
      breakingCount: parseReleaseNotes(r.body).breakingCount,
    }));
    assertRefreshWriteAllowed('release derived-stat persistence');
    runInWriteTransaction(() => {
      assertRefreshWriteAllowed('release derived-stat persistence transaction');
      for (const r of releases) {
        const stats = parseReleaseNotes(r.body);
        updateReleaseDerivedStats({
          tag: r.tag_name,
          // Aggregated: own + breaking bullets from each preceding beta until the
          // previous stable. Other counts (fixes/changes/highlights) are NOT
          // aggregated — the changelog generator re-lists them in the stable body
          // at promotion time, so they're already counted once.
          breaking_count: computeAggregateBreaking(releasesForCalc, r.tag_name),
          fixes_count: stats.fixesCount,
          changes_count: stats.changesCount,
          highlights_count: stats.highlightsCount,
          pr_refs_count: stats.prRefsCount,
          beta_count: computeBetaCount(releasesForCalc, r.tag_name),
          hours_to_next_release: computeHoursToNextRelease(releasesForCalc, r.tag_name),
          hours_to_next_stable: computeHoursToNextStable(releasesForCalc, r.tag_name),
          npm_package_url: stats.npmPackageUrl,
          release_tarball_url: stats.registryTarballUrl,
          release_integrity: stats.integrity,
          release_sha: stats.releaseSha,
          full_release_ci_report_url: stats.fullReleaseCiReportUrl,
          full_release_validation_url: stats.fullReleaseValidationUrl,
        });
      }
      assertRefreshWriteAllowed('release derived-stat persistence commit');
    });

    refreshLease.renew('release evidence');
    const releaseNetworkConcurrency = config.refresh.releaseNetworkConcurrency;
    const artifactResults: Array<{
      release: (typeof releases)[number];
      stats: ReturnType<typeof parseReleaseNotes>;
      artifact: Awaited<ReturnType<typeof verifyNpmArtifact>>;
      evidenceReport: Awaited<ReturnType<typeof verifyEvidenceReportUrl>>;
      observedAt: string;
    }> = [];
    const releaseCommitResults: Array<{
      release: (typeof releaseSelection.reachability)[number];
      commit: Awaited<ReturnType<typeof fetchReleaseCommit>>;
    }> = [];
    const advisorySnapshots: Array<
      Awaited<ReturnType<typeof fetchSecurityAdvisorySourceObservations>>
    > = [];
    let releaseEvidenceFailure: unknown = null;
    try {
      await timed(
        'release.evidence',
        async () => runCooperativeGroup([
          (groupSignal) => mapWithConcurrency(
            releaseSelection.reachability,
            releaseNetworkConcurrency,
            async (r, _index, releaseBatchSignal) => {
              const stats = parseReleaseNotes(r.body);
              try {
                const [artifact, evidenceReport] = await runCooperativeGroup([
                  (releaseSignal) => verifyNpmArtifact({
                    tag: r.tag_name,
                    expectedNpmPackageUrl: stats.npmPackageUrl,
                    expectedIntegrity: stats.integrity,
                    expectedTarballUrl: stats.registryTarballUrl,
                    expectedReleaseSha: stats.releaseSha,
                    expectedCatalogReleaseSha: r.tag_commit_oid,
                  }, { signal: releaseSignal }),
                  (releaseSignal) => verifyEvidenceReportUrl(
                    stats.fullReleaseCiReportUrl,
                    stats.fullReleaseValidationUrl,
                    {
                      expectedReleaseTag: r.tag_name,
                      expectedReleaseSha: r.tag_commit_oid,
                      signal: releaseSignal,
                    },
                  ),
                ] as const, { signal: releaseBatchSignal });
                const observedAt = new Date().toISOString();
                artifactResults.push({
                  release: r,
                  stats,
                  artifact,
                  evidenceReport,
                  observedAt,
                });
              } catch (error) {
                throw new ReleaseRefreshStageError(
                  'artifact-verification',
                  r.tag_name,
                  error,
                );
              }
            },
            { signal: groupSignal },
          ),
          (groupSignal) => mapWithConcurrency(
            releaseSelection.reachability,
            releaseNetworkConcurrency,
            async (r, _index, releaseBatchSignal) => {
              try {
                const commit = await fetchReleaseCommit(r.tag_name, {
                  expectedTagOid: r.tag_commit_oid,
                  signal: releaseBatchSignal,
                });
                if (commit.oid !== r.tag_commit_oid) {
                  throw new Error(
                    `Release ${r.tag_name} tag OID changed after catalog attestation: ` +
                    `${r.tag_commit_oid} -> ${commit.oid ?? 'missing'}`,
                  );
                }
                releaseCommitResults.push({ release: r, commit });
              } catch (error) {
                throw new ReleaseRefreshStageError(
                  'release-checks',
                  r.tag_name,
                  error,
                );
              }
            },
            { signal: groupSignal },
          ),
          async (groupSignal) => {
            try {
              advisorySnapshots.push(
                await fetchSecurityAdvisorySourceObservations({
                  signal: groupSignal,
                }),
              );
            } catch (error) {
              throw new ReleaseRefreshStageError(
                'advisories',
                `npm:${config.github.repo}`,
                error,
              );
            }
          },
        ] as const, { signal }),
        { recoverable: true },
      );
    } catch (error) {
      throwIfAborted(signal);
      releaseEvidenceFailure = error;
    }

    const advisorySnapshot = advisorySnapshots[0] ?? null;
    throwIfAborted(signal);
    assertRefreshWriteAllowed('release evidence persistence');
    runInWriteTransaction(() => {
      assertRefreshWriteAllowed('release evidence persistence transaction');
      for (const result of artifactResults) {
        const { release: r, stats, artifact, evidenceReport, observedAt } = result;
        persistReleaseArtifactVerification({
          runId,
          observedAt,
          release: {
            repository: `${config.github.owner}/${config.github.repo}`,
            tag: r.tag_name,
            releaseNodeId: r.node_id,
            catalogTagCommitOid: r.tag_commit_oid,
            publishedAt: new Date(r.published_at!).toISOString(),
          },
          releaseMetadata: {
            npmPackageUrl: stats.npmPackageUrl,
            releaseTarballUrl: stats.registryTarballUrl,
            releaseIntegrity: stats.integrity,
            releaseSha: stats.releaseSha,
            ciReportUrl: stats.fullReleaseCiReportUrl,
            fullReleaseValidationUrl: stats.fullReleaseValidationUrl,
          },
          artifact,
          evidenceReport,
          assertCanWrite: assertRefreshWriteAllowed,
        });
        updateReleaseArtifactVerification({
          tag: r.tag_name,
          registry_version: artifact.version,
          registry_integrity: artifact.integrity,
          registry_tarball_url: artifact.tarballUrl,
          ci_report_verified: evidenceReport.verified ? 1 : 0,
          ci_report_mismatch: evidenceReport.mismatch,
          release_validation_verified: evidenceReport.fallbackKind === 'github_actions_run' && evidenceReport.verified ? 1 : 0,
          release_validation_mismatch: evidenceReport.fallbackKind === 'github_actions_run' ? evidenceReport.mismatch : null,
          artifact_verified: artifact.verified ? 1 : 0,
          artifact_mismatch: artifact.mismatch,
        });
      }

      for (const result of releaseCommitResults) {
        const { release: r, commit } = result;
        upsertReleaseCommit({
          tag: r.tag_name,
          tag_commit_oid: commit.oid,
          committed_at: commit.committedAt,
          check_state: commit.checkState,
          check_total: commit.checkTotal,
          check_success: commit.checkSuccess,
          check_failure: commit.checkFailure,
          check_pending: commit.checkPending,
          check_skipped: commit.checkSkipped,
          check_contexts_json: JSON.stringify(commit.checkContexts),
        });
      }
      assertRefreshWriteAllowed('release evidence persistence commit');
    });

    // 1b. Pull all security advisories for the repo. One cheap call, backfills
    // historical CVEs automatically. Failure here should still allow issue rows
    // to refresh, but score persistence is refused because stale/absent advisory
    // data changes skip-cve gates and CVE load.
    if (advisorySnapshot) {
      const capturedAt = new Date().toISOString();
      try {
        const compoundSnapshot = buildCompoundAdvisorySnapshot({
          capturedAt,
          repository: {
            owner: config.github.owner,
            name: config.github.repo,
            url: `https://github.com/${config.github.owner}/${config.github.repo}`,
          },
          target: {
            ecosystem: 'npm',
            packageName: config.github.repo,
          },
          observations: advisorySnapshot.observations,
          reconciliation: advisorySnapshot.reconciliation,
        });
        throwIfAborted(signal);
        assertRefreshWriteAllowed('advisory snapshot staging');
        advisoryProvenance =
          stageCompoundAdvisorySnapshot(compoundSnapshot, {
            assertCanWrite: assertRefreshWriteAllowed,
          }).metadata;
      } catch (error) {
        const advisoryScope = `npm:${config.github.repo}`;
        const message = recordAdvisoryIngestionFailure({
          error,
          scope: advisoryScope,
          packageName: config.github.repo,
          advisoryCount: advisorySnapshot.advisories.length,
          withdrawnAdvisoryCount: advisorySnapshot.advisories
            .filter((advisory) => advisory.state === 'withdrawn').length,
          recordFailure: recordEvidenceRefreshFailure,
        });
        console.warn(`${message}; refusing score persistence after advisory ingestion failure`);
      }
    }
    if (releaseEvidenceFailure) {
      const stageError = releaseEvidenceFailure instanceof ReleaseRefreshStageError
        ? releaseEvidenceFailure
        : null;
      const source = stageError?.stage ?? 'release-evidence';
      const scope = stageError?.releaseTag ?? null;
      const failedRelease = scope
        ? releases.find((release) => release.tag_name === scope)
        : undefined;
      const failedStats = failedRelease ? parseReleaseNotes(failedRelease.body) : null;
      const message = recordEvidenceRefreshFailure(
        source,
        scope,
        stageError?.stageCause ?? releaseEvidenceFailure,
        source === 'artifact-verification'
          ? {
              releaseTag: scope,
              npmPackageUrl: failedStats?.npmPackageUrl ?? null,
              ciReportUrl: failedStats?.fullReleaseCiReportUrl ?? null,
              releaseValidationUrl: failedStats?.fullReleaseValidationUrl ?? null,
            }
          : source === 'advisories'
            ? {
                phase: 'fetch',
                package: config.github.repo,
                ecosystem: 'npm',
              }
            : { releaseTag: scope },
      );
      console.warn(
        `${message}; cooperative sibling work drained and score publication is blocked`,
      );
    }

    // 2. Build and process one exhaustive, stabilized issue catalog.
    //
    // Score-producing refreshes never use the old incremental early-stop path.
    // Every run must observe current metadata for every issue before deciding
    // whether it overlaps a monitored release.
    //
    // The immutable first-N boundary makes each score an explicit as-of snapshot.
    // Issues created after that boundary are recorded as growth and are picked up
    // by the next exhaustive refresh instead of restarting this run indefinitely.
    const publishedAts = releases
      .map((r) => r.published_at)
      .filter((p): p is string => !!p)
      .map((p) => Date.parse(p))
      .filter((ms) => Number.isFinite(ms));
    const oldestMonitoredMs = publishedAts.length > 0 ? Math.min(...publishedAts) : -Infinity;
    let issueBaseline = parseIssueCrawlBaseline(
      getMeta(ISSUE_CRAWL_BASELINE_META_KEY) ?? null,
    );
    const backfillDone = issueBaseline != null;
    const monitoredWindows = releases
      .map((release) => {
        const start = release.published_at ? Date.parse(release.published_at) : NaN;
        const next = releases
          .map((candidate) => candidate.published_at ? Date.parse(candidate.published_at) : NaN)
          .filter((ms) => Number.isFinite(ms) && ms > start)
          .sort((a, b) => a - b)[0];
        return { start, end: next ?? Infinity };
      })
      .filter((window) => Number.isFinite(window.start));
    const issueOverlapsMonitoredWindow = (issue: GhIssue): boolean => {
      const created = Date.parse(issue.created_at);
      const closed = issue.closed_at ? Date.parse(issue.closed_at) : Infinity;
      return monitoredWindows.some((window) => created < window.end && closed > window.start);
    };

    // After a PROMPT_VERSION bump, rows written under the old prompt are stale but
    // sit behind the oldest-monitored cutoff — the normal early-stop would skip
    // them forever. Detect this once and do a full sweep this run so the bump
    // actually propagates. Worst case: ~25 pages (~$1) once per prompt change.
    const staleRows = countStaleClassifications(PROMPT_VERSION);
    const promptSweep = backfillDone && staleRows > 0;
    if (promptSweep) {
      console.log(`[refresh] prompt-sweep: ${staleRows} stale classifications, ignoring early-stop this run`);
    }

    const fullIssueBackfill = config.refresh.fullIssueBackfill;
    const exhaustiveIssueCrawl = true;
    const MAX_PAGES = config.refresh.maxIssuePages;
    let pagesFetched = 0;
    let issuesFetched = 0;
    let monitoredIssuesFetched = 0;
    let commentSnapshotIssuesRequested = 0;
    let metadataOnlyIssuesObserved = 0;
    let commenterScanTruncatedCount = 0;
    let classifiedCount = 0;
    const classificationFailures: string[] = [];
    let crossedOldestEver = false;
    let issuePaginationStopReason: IssuePaginationStopReason = 'exhausted';
    let issuePagination: IssueCrawlPagination | null = null;
    let completedIssueCatalog: GhIssueCatalogMetadata | null = null;
    let issueCatalogSnapshot: IssueCatalogSnapshotRunMetadata | null = null;
    let issueCatalogAttestation: IssueCatalogPublicationAttestation | null = null;
    const buildIssueCrawlMeta = () => ({
      schemaVersion: ISSUE_CRAWL_SCHEMA_VERSION,
      repository: issueRepositoryIdentity(),
      startedAt: refreshStartedAt,
      finishedAt: new Date().toISOString(),
      fullIssueBackfill,
      crawlMode: exhaustiveIssueCrawl ? 'exhaustive' : 'incremental',
      backfillCompleteAtStart: backfillDone,
      backfillCompleteAfterRun: parseIssueCrawlBaseline(
        getMeta(ISSUE_CRAWL_BASELINE_META_KEY) ?? null,
      ) != null,
      baseline: issueBaseline,
      pagination: issuePagination,
      catalogSnapshot: issueCatalogSnapshot,
      catalogAttestation: issueCatalogAttestation,
      promptSweep,
      staleClassificationsAtStart: staleRows,
      monitoredReleaseCount,
      oldestMonitoredAt: Number.isFinite(oldestMonitoredMs) ? new Date(oldestMonitoredMs).toISOString() : null,
      pagesFetched,
      issuesFetched,
      monitoredIssuesFetched,
      commentSnapshotIssuesRequested,
      metadataOnlyIssuesObserved,
      maxIssuePages: MAX_PAGES,
      stopReason: issuePaginationStopReason,
      crossedOldestEver,
      commenterScanTruncatedCount,
      classificationFailures,
      evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
      advisoryProvenance,
      releaseCatalog: releaseCatalog.metadata,
      scorePersisted: false,
      scorePersistedAt: null,
      timings: timingSnapshot(),
    });

    if (!exhaustiveIssueCrawl && !issueBaseline) {
      issuePaginationStopReason = 'evidence_failure';
      const rawBaseline = getMeta(ISSUE_CRAWL_BASELINE_META_KEY) ?? null;
      const baselineProblems = rawBaseline == null
        ? ['baseline metadata is missing']
        : (() => {
          try {
            return issueCrawlBaselineProblems(JSON.parse(rawBaseline));
          } catch {
            return ['baseline metadata is malformed JSON'];
          }
        })();
      const message = recordEvidenceRefreshFailure(
        'issue-pagination-baseline',
        issueRepositoryIdentity(),
        new Error(
          `incremental issue crawl requires a previously proven exhaustive baseline: ` +
          baselineProblems.join('; '),
        ),
        {
          fullIssueBackfill,
          promptSweep,
          baselineMetaKey: ISSUE_CRAWL_BASELINE_META_KEY,
          baselineProblems,
        },
      );
      persistIssueCrawlMeta(buildIssueCrawlMeta());
      throw new Error(`${message}; rerun with FULL_ISSUE_BACKFILL=true`);
    }

    async function* issuePagesForRefresh(): AsyncGenerator<GhIssue[], void, void> {
      if (exhaustiveIssueCrawl) {
        const resolution = await resolveIssueCatalogSnapshotForRefresh({
          repository: issueRepositoryIdentity(),
          observedAt: refreshStartedAt,
          maxAgeMs: config.refresh.issueCatalogSnapshotMaxAgeHours * 60 * 60 * 1000,
          fetchCatalog: () => fetchIssueCatalog({
            maxPagesPerConnection: MAX_PAGES,
            perPage: config.refresh.issuePageSize,
            signal,
          }),
        });
        const catalog = issueCatalogSnapshotCatalog(resolution.snapshot);
        issueCatalogSnapshot = {
          schemaVersion: 1,
          snapshotId: resolution.snapshot.header.snapshotId,
          contentHash: resolution.snapshot.header.contentHash,
          capturedAt: resolution.snapshot.header.capturedAt,
          resumed: resolution.resumed,
          priorStatus: resolution.priorStatus,
          maxAgeHours: config.refresh.issueCatalogSnapshotMaxAgeHours,
          consumedAt: null,
          consumedByRunId: null,
          consumptionContentHash: null,
        };
        console.log(
          `[refresh] ${resolution.resumed ? 'resuming' : 'staged'} exhaustive issue catalog ` +
          `${resolution.snapshot.header.snapshotId} ` +
          `(${resolution.snapshot.header.rowCount} issues captured ` +
          `${resolution.snapshot.header.capturedAt})`,
        );
        completedIssueCatalog = catalog.metadata;
        issuePagination = issuePaginationFromCatalog(catalog.metadata);
        for (let offset = 0; offset < catalog.issues.length; offset += 100) {
          yield catalog.issues.slice(offset, offset + 100);
        }
        return;
      }

      const iterator = paginateIssues(config.refresh.issuePageSize, {
        maxPagesPerConnection: MAX_PAGES,
        signal,
      });
      try {
        for (;;) {
          const result = await iterator.next();
          if (result.done) {
            issuePagination = issuePaginationFromIncrementalSweep(
              result.value,
              issueBaseline!,
            );
            return;
          }
          issuePagination = issuePaginationFromPage(
            result.value.metadata,
            issueBaseline!,
          );
          yield result.value.issues;
        }
      } finally {
        await iterator.return?.(undefined as never);
      }
    }

    refreshLease.renew('issue crawl');
    activeStageTimer.ensure('issue.classification');
    const finishIssueCrawlTiming = activeStageTimer.start('issue.crawl');
    try {
      paginate: for await (const page of withIssuePaginationFailureBoundary(issuePagesForRefresh())) {
      pagesFetched++;
      issuesFetched += page.length;

      // Page can be empty after PR filtering — keep going until we hit a real signal
      // or run out of pages.
      let allUnchanged = page.length > 0;
      let crossedOldest = false;
      const toClassify: GhIssue[] = [];
      const initialMonitoredIssueNumbers = page
        .filter((issue) => issueOverlapsMonitoredWindow(issue))
        .map((issue) => issue.number);
      const monitoredIssueNumberSet = new Set(initialMonitoredIssueNumbers);
      const evidenceTargets = {
        commentIssueNumbers: initialMonitoredIssueNumbers,
        metadataOnlyIssueNumbers: page
          .filter((issue) => !monitoredIssueNumberSet.has(issue.number))
          .map((issue) => issue.number),
      };
      const commentIssueNumbers = initialMonitoredIssueNumbers;
      const requiredCommentIssueSet = new Set(commentIssueNumbers);
      commentSnapshotIssuesRequested += commentIssueNumbers.length;
      metadataOnlyIssuesObserved += evidenceTargets.metadataOnlyIssueNumbers.length;
      const pageExpectedRevisions = issueEvidenceRevisions(page.map((issue) => issue.number));
      const evidenceFailureCountBeforePage = evidenceRefreshFailures.length;
      const pageEvidenceScope = `page ${pagesFetched}`;
      const pageEvidenceContext = {
        refreshRunId: runId,
        page: pagesFetched,
        issueCount: page.length,
        monitoredIssueCount: initialMonitoredIssueNumbers.length,
        commentSnapshotIssueCount: commentIssueNumbers.length,
        metadataOnlyIssueCount: evidenceTargets.metadataOnlyIssueNumbers.length,
        commentRequirement: 'monitored_release_overlap',
        requiredCommentIssueNumbers: commentIssueNumbers,
        firstIssueNumber: page[0]?.number ?? null,
        lastIssueNumber: page[page.length - 1]?.number ?? null,
      };
      throwIfAborted(signal);
      let remoteIssuesByIssue: Awaited<ReturnType<typeof listIssuesBatch>>;
      let snapshotsByIssue: Awaited<ReturnType<typeof listIssueCommentSnapshotsBatch>>;
      let labelEvidenceSnapshotsByIssue: Awaited<
        ReturnType<typeof listIssueLabelEvidenceSnapshotsBatch>
      >;
      let stateEvidenceByIssue: Awaited<ReturnType<typeof listIssueFixEvidenceBatch>>;
      try {
        [
          remoteIssuesByIssue,
          snapshotsByIssue,
          labelEvidenceSnapshotsByIssue,
          stateEvidenceByIssue,
        ] = await runIssuePageEvidenceFetchGroup([
          async (groupSignal) => {
            try {
              return await listIssuesBatch(initialMonitoredIssueNumbers, {
                signal: groupSignal,
              });
            } catch (error) {
              throw new ReleaseRefreshStageError(
                'issue-metadata',
                pageEvidenceScope,
                error,
              );
            }
          },
          async (groupSignal) => {
            try {
              return await listIssueCommentSnapshotsBatch(commentIssueNumbers, {
                signal: groupSignal,
                onMissingIssueAlias: ({ issueNumber, aliasIndex }) => {
                  throw new ReleaseRefreshStageError(
                    'issue-comments-missing-alias',
                    `issue #${issueNumber}`,
                    new Error(
                      `GitHub issue alias ${aliasIndex} was missing during comment batch recovery`,
                    ),
                  );
                },
              });
            } catch (error) {
              if (error instanceof ReleaseRefreshStageError) throw error;
              throw new ReleaseRefreshStageError(
                'issue-comments',
                pageEvidenceScope,
                error,
              );
            }
          },
          async (groupSignal) => {
            try {
              return await listIssueLabelEvidenceSnapshotsBatch(
                initialMonitoredIssueNumbers,
                {
                  signal: groupSignal,
                  onMissingIssueAlias: ({ issueNumber, aliasIndex }) => {
                    throw new ReleaseRefreshStageError(
                      'issue-label-events-missing-alias',
                      `issue #${issueNumber}`,
                      new Error(
                        `GitHub issue alias ${aliasIndex} was missing during label timeline batch recovery`,
                      ),
                    );
                  },
                },
              );
            } catch (error) {
              if (error instanceof ReleaseRefreshStageError) throw error;
              throw new ReleaseRefreshStageError(
                'issue-label-events',
                pageEvidenceScope,
                error,
              );
            }
          },
          async (groupSignal) => {
            try {
              return await listIssueFixEvidenceBatch(initialMonitoredIssueNumbers, {
                signal: groupSignal,
                onMissingIssueAlias: ({ issueNumber, aliasIndex }) => {
                  throw new ReleaseRefreshStageError(
                    'issue-fix-evidence-missing-alias',
                    `issue #${issueNumber}`,
                    new Error(
                      `GitHub issue alias ${aliasIndex} was missing during fix evidence batch recovery`,
                    ),
                  );
                },
              });
            } catch (error) {
              if (error instanceof ReleaseRefreshStageError) throw error;
              throw new ReleaseRefreshStageError(
                'issue-fix-evidence',
                pageEvidenceScope,
                error,
              );
            }
          },
        ] as const, signal);
      } catch (error) {
        throwIfAborted(signal);
        const stageError = error instanceof ReleaseRefreshStageError ? error : null;
        const message = recordEvidenceRefreshFailure(
          stageError?.stage ?? 'issue-page-evidence',
          stageError?.releaseTag ?? pageEvidenceScope,
          stageError?.stageCause ?? error,
          pageEvidenceContext,
        );
        console.warn(
          `${message}; cancelled sibling evidence fetches and refusing score persistence`,
        );
        issuePaginationStopReason = 'evidence_failure';
        persistIssueCrawlMeta(buildIssueCrawlMeta());
        throw new Error(
          `${message}; cancelled sibling issue-page evidence fetches; refusing to persist scores`,
          { cause: error },
        );
      }

      let pageEvidenceFailureCount = 0;
      for (const issue of page.filter((candidate) =>
        requiredCommentIssueSet.has(candidate.number)
      )) {
        const snapshot = snapshotsByIssue.get(issue.number);
        if (!snapshot) {
          pageEvidenceFailureCount++;
          const message = recordEvidenceRefreshFailure(
            'issue-comments-missing-snapshot',
            `issue #${issue.number}`,
            new Error('GitHub did not return a stable comment snapshot'),
            pageEvidenceContext,
          );
          console.warn(`${message}; refusing score persistence after incomplete comment evidence`);
          continue;
        }
        const message = recordCommentCompletenessFailure({
          snapshot,
          pageContext: pageEvidenceContext,
          recordFailure: recordEvidenceRefreshFailure,
        });
        if (!message) continue;
        pageEvidenceFailureCount++;
        console.warn(`${message}; refusing score persistence after incomplete comment evidence`);
      }
      for (const issueNumber of initialMonitoredIssueNumbers) {
        if (remoteIssuesByIssue.has(issueNumber)) continue;
        pageEvidenceFailureCount++;
        const message = recordEvidenceRefreshFailure(
          'issue-metadata-missing',
          `issue #${issueNumber}`,
          new Error('GitHub did not return current issue metadata'),
          pageEvidenceContext,
        );
        console.warn(`${message}; refusing score persistence after incomplete metadata refresh`);
      }
      for (const issueNumber of initialMonitoredIssueNumbers) {
        if (stateEvidenceByIssue.has(issueNumber)) continue;
        pageEvidenceFailureCount++;
        const message = recordEvidenceRefreshFailure(
          'issue-fix-evidence-missing',
          `issue #${issueNumber}`,
          new Error('GitHub did not return a stable issue state-event snapshot'),
          pageEvidenceContext,
        );
        console.warn(
          `${message}; refusing score persistence after incomplete state evidence`,
        );
      }
      for (const issueNumber of initialMonitoredIssueNumbers) {
        const issue = remoteIssuesByIssue.get(issueNumber);
        const labelEvidence = labelEvidenceSnapshotsByIssue.get(issueNumber);
        if (
          issue &&
          labelEvidence &&
          labelEvidence.issueNodeId === issue.node_id &&
          labelEvidence.issueUpdatedAt === issue.updated_at &&
          labelEvidence.fetchedCount === labelEvidence.totalCount &&
          labelEvidence.stabilized === true
        ) {
          continue;
        }
        pageEvidenceFailureCount++;
        const message = recordEvidenceRefreshFailure(
          'issue-label-evidence-incomplete',
          `issue #${issueNumber}`,
          new Error(
            'GitHub did not return a complete stabilized label snapshot for the current issue revision',
          ),
          pageEvidenceContext,
        );
        console.warn(
          `${message}; refusing score persistence after incomplete label authority evidence`,
        );
      }
      const pageFailureCount = evidenceRefreshFailures.length - evidenceFailureCountBeforePage;
      if (pageEvidenceFailureCount > 0 || pageFailureCount > 0) {
        issuePaginationStopReason = 'evidence_failure';
        persistIssueCrawlMeta(buildIssueCrawlMeta());
        throw new Error(`Issue page evidence refresh failed for ${Math.max(pageEvidenceFailureCount, pageFailureCount)} source(s); refusing to persist scores`);
      }

      const labelEventsByIssue = new Map(
        [...labelEvidenceSnapshotsByIssue].map(([issueNumber, snapshot]) => [
          issueNumber,
          snapshot.events,
        ]),
      );
      let effectivePage = page.map((issue) =>
        remoteIssuesByIssue.get(issue.number) ?? issue
      );
      const metadataMismatchNumbers = page
        .filter((issue) => requiredCommentIssueSet.has(issue.number))
        .filter((issue) => {
          const remoteIssue = remoteIssuesByIssue.get(issue.number)!;
          const snapshot = snapshotsByIssue.get(issue.number)!;
          return stagedIssueRequiresMetadataReconciliation(
            issue,
            remoteIssue,
            snapshot,
            stateEvidenceByIssue.get(issue.number),
          );
        })
        .map((issue) => issue.number);
      if (metadataMismatchNumbers.length > 0) {
        try {
          const reconciliation = await reconcileIssueCommentSnapshots({
            issueNumbers: metadataMismatchNumbers,
            classifyIssueNumbers: metadataMismatchNumbers,
            accumulateGroundingFailures: true,
            releaseTags: tags,
            snapshotsByIssue,
            classificationConcurrency: CLASSIFY_CONCURRENCY,
            snapshotAt: refreshStartedAt,
            maxAttempts: ISSUE_RECONCILE_MAX_ATTEMPTS,
            assertCanWrite: (stage) => refreshLease.assertHeld(stage),
            signal,
            expectedRevisions: new Map(metadataMismatchNumbers.flatMap((issueNumber) => {
              const revision = pageExpectedRevisions.get(issueNumber);
              return revision ? [[issueNumber, revision] as const] : [];
            })),
          });
          const failedReconciliationIssueNumbers = new Set(
            reconciliation.classificationFailures.map(
              (failure) => failure.issueNumber,
            ),
          );
          for (const failure of reconciliation.classificationFailures) {
            const message = recordIssueClassificationFailure({
              issue: failure.issue,
              error: failure.error,
              pageContext: pageEvidenceContext,
              recordFailure: recordEvidenceRefreshFailure,
            });
            classificationFailures.push(message);
            console.error(message);
          }
          for (const [issueNumber, snapshot] of reconciliation.snapshotsByIssue) {
            if (failedReconciliationIssueNumbers.has(issueNumber)) continue;
            snapshotsByIssue.set(issueNumber, snapshot);
          }
          for (const [issueNumber, events] of reconciliation.labelEventsByIssue) {
            if (failedReconciliationIssueNumbers.has(issueNumber)) continue;
            labelEventsByIssue.set(issueNumber, events);
          }
          for (
            const [issueNumber, labelEvidence]
            of reconciliation.labelEvidenceSnapshotsByIssue
          ) {
            if (failedReconciliationIssueNumbers.has(issueNumber)) continue;
            labelEvidenceSnapshotsByIssue.set(issueNumber, labelEvidence);
          }
          for (const [issueNumber, evidence] of reconciliation.stateEvidenceByIssue) {
            if (failedReconciliationIssueNumbers.has(issueNumber)) continue;
            stateEvidenceByIssue.set(issueNumber, evidence);
          }
          effectivePage = effectivePage
            .filter((issue) =>
              !failedReconciliationIssueNumbers.has(issue.number)
            )
            .map((issue) =>
              reconciliation.issuesByNumber.get(issue.number) ?? issue
            );
          classifiedCount += reconciliation.classifiedIssueNumbers.length;
          for (
            const [issueNumber, revision]
            of issueEvidenceRevisions(reconciliation.reconciledIssueNumbers)
          ) {
            pageExpectedRevisions.set(issueNumber, revision);
          }
          allUnchanged = false;
        } catch (error) {
          const message = recordEvidenceRefreshFailure(
            'issue-metadata-reconciliation',
            pageEvidenceScope,
            error,
            {
              ...pageEvidenceContext,
              mismatchedIssueNumbers: metadataMismatchNumbers,
              maxAttempts: ISSUE_RECONCILE_MAX_ATTEMPTS,
            },
          );
          issuePaginationStopReason = 'evidence_failure';
          persistIssueCrawlMeta(buildIssueCrawlMeta());
          throw new Error(`${message}; refusing to classify or persist mismatched issue metadata`);
        }
      }
      const monitoredIssueNumbers = effectivePage
        .filter((issue) => issueOverlapsMonitoredWindow(issue))
        .map((issue) => issue.number);
      monitoredIssuesFetched += monitoredIssueNumbers.length;

      // Pass 1: upsert + decide what needs LLM. Page evidence writes are atomic:
      // a failed row cannot leave mixed issue/label/state evidence for this page.
      try {
        assertRefreshWriteAllowed(`issue page ${pagesFetched} evidence persistence`);
        runInWriteTransaction(() => {
          assertRefreshWriteAllowed(
            `issue page ${pagesFetched} evidence persistence transaction`,
          );
          assertIssueEvidenceRevisions(pageExpectedRevisions);
          for (const issue of effectivePage) {
            const requiresComments = requiredCommentIssueSet.has(issue.number);
            const snapshot = requiresComments
              ? acceptedIssueCommentSnapshot(issue.number, snapshotsByIssue.get(issue.number))
              : null;
            const row = snapshot
              ? issueRowFromSnapshot(issue, snapshot)
              : issueRowFromRemoteMetadata(issue);
            const remoteMetadata = issueRowFromRemoteMetadata(issue);
            if (!issueRemoteMetadataMatchesPersisted(getIssue(issue.number), remoteMetadata)) {
              allUnchanged = false;
            }
            if (snapshot) {
              if (row.commenter_scan_truncated) commenterScanTruncatedCount++;
              upsertIssueCommentSnapshot(issueCommentSnapshot(snapshot));
              upsertIssue(row);
            } else {
              upsertIssueMetadata(row);
            }
            for (const event of labelEventsByIssue.get(issue.number) ?? []) {
              upsertIssueLabelEvent({
                issue_number: event.issueNumber,
                issue_node_id: event.issueNodeId,
                event_id: event.eventId,
                action: event.action,
                label_name: event.labelName,
                actor_node_id: event.actorNodeId,
                actor_login: event.actorLogin,
                actor_type: event.actorType,
                created_at: event.createdAt,
                raw_json: JSON.stringify(event.raw),
              });
            }
            const labelEvidence = labelEvidenceSnapshotsByIssue.get(
              issue.number,
            );
            if (labelEvidence) {
              insertIssueLabelEvidenceSnapshot(
                buildIssueLabelEvidenceSnapshot(labelEvidence),
              );
            } else if (requiresComments) {
              throw new Error(
                `Required label evidence snapshot missing for issue #${issue.number}`,
              );
            }
            upsertIssueLabelSnapshot({
              issue_number: issue.number,
              issue_node_id: row.node_id ?? null,
              snapshot_at: refreshStartedAt,
              labels_json: row.labels,
            });
            const stateEvidence = stateEvidenceByIssue.get(issue.number);
            if (stateEvidence) persistIssueStateEvidence(stateEvidence);

            const issueUpdatedAt = snapshot?.issueUpdatedAt ?? issue.updated_at;
            if (Date.parse(issueUpdatedAt) < oldestMonitoredMs) crossedOldest = true;

            // Full history is fetched for accurate open/closed linkage, but spend
            // classification tokens only on issues whose lifetime overlaps a release
            // being scored. Closed-before-release issues cannot affect that score.
            if (!requiresComments) continue;
            if (!snapshot) {
              throw new Error(`Required comment snapshot missing for issue #${issue.number}`);
            }
            if (!stateEvidence) {
              throw new Error(
                `Required issue state evidence missing for issue #${issue.number}`,
              );
            }
            persistClosureClaimEvidenceForIssue({
              issue,
              snapshot,
              fixEvidence: stateEvidence,
              capturedAt: refreshStartedAt,
            });

            const existing = getClassification(issue.number);
            const skip = existing && (
              // Back-fill mode: preserve tokens — anything already classified is left as-is,
              // even if updated_at moved on or prompt_version is stale. The next normal run
              // (once the back-fill flag is set) will pick up those rows incrementally.
              (!backfillDone && (
                existing.classification_origin !== 'raw_model' ||
                typeof existing.accepted_classifier_receipt_id === 'string'
              )) ||
              // Normal mode: only skip when the row is fully current.
              classificationMatchesSnapshot(existing, snapshot, classifierIdentity.digest) ||
              // The complete score-universe reconciliation below binds legacy
              // null digests once. Avoid classifying the same row here and there.
              classificationCanDeferLegacyCommentBinding(existing, snapshot, classifierIdentity.digest)
            );
            if (skip) continue;
            allUnchanged = false;
            toClassify.push(issue);
          }
          assertRefreshWriteAllowed(
            `issue page ${pagesFetched} evidence persistence commit`,
          );
        });
      } catch (error) {
        const message = recordEvidenceRefreshFailure('issue-page-write', pageEvidenceScope, error, pageEvidenceContext);
        console.warn(`${message}; rolled back issue page evidence writes and refusing score persistence`);
        issuePaginationStopReason = 'evidence_failure';
        persistIssueCrawlMeta(buildIssueCrawlMeta());
        throw new Error(`${message}; rolled back issue page evidence writes; refusing to persist scores`);
      }
      const classificationExpectedRevisions = issueEvidenceRevisions(
        toClassify.map((issue) => issue.number),
      );

      // Pass 2: classify pending issues cooperatively. A terminal sibling failure
      // aborts queued work, drains started work, and preserves completed rows.
      type StagedClassification = {
        issueNumber: number;
        staged: StagedIssueClassification;
        issueUpdatedAt: string;
        promptVersion: number;
      };
      const stagedClassifications: StagedClassification[] = [];
      const classificationWorkerFailures: Array<{
        issue: GhIssue;
        error: unknown;
      }> = [];
      let classificationStageFailure: unknown = null;
      let persistedClassificationCount = 0;
      const finishClassificationTiming = activeStageTimer.start('issue.classification', { accumulate: true });
      try {
        await mapWithConcurrency(
          toClassify,
          CLASSIFY_CONCURRENCY,
          async (issue, _index, workerSignal) => {
            try {
              const snapshot = acceptedIssueCommentSnapshot(
                issue.number,
                snapshotsByIssue.get(issue.number),
              );
              const staged = stagedIssueClassification(await classifyIssueDurably(
                issue,
                snapshot.comments,
                tags,
                workerSignal,
              ));
              stagedClassifications.push({
                issueNumber: issue.number,
                staged,
                issueUpdatedAt: snapshot.issueUpdatedAt,
                promptVersion: PROMPT_VERSION,
              });
            } catch (error) {
              const abortError = cooperativeClassifierAbort(error);
              if (abortError) throw abortError;
              classificationWorkerFailures.push({ issue, error });
              if (accumulableClassifierGroundingFailure(error)) return;
              throw new Error(
                `Issue #${issue.number} classification failed: ` +
                `${error instanceof Error ? error.message : String(error)}`,
                { cause: error },
              );
            }
          },
          { signal },
        );
      } catch (error) {
        classificationStageFailure = error;
      } finally {
        finishClassificationTiming();
      }
      throwIfAborted(signal);
      classificationWorkerFailures.sort(
        (left, right) => left.issue.number - right.issue.number,
      );
      for (const failure of classificationWorkerFailures) {
        const message = recordIssueClassificationFailure({
          issue: failure.issue,
          error: failure.error,
          pageContext: pageEvidenceContext,
          recordFailure: recordEvidenceRefreshFailure,
        });
        classificationFailures.push(message);
        console.error(message);
      }
      if (stagedClassifications.length > 0) {
        try {
          throwIfAborted(signal);
          refreshLease.assertHeld(`issue page ${pagesFetched} classification persistence`);
          const stagedExpectedRevisions = new Map<number, IssueEvidenceRevision>();
          for (const row of stagedClassifications) {
            const evidenceRevisions = classificationExpectedRevisions.get(row.issueNumber);
            if (!evidenceRevisions) {
              throw new Error(
                `Missing staged classifier source revisions for issue #${row.issueNumber}`,
              );
            }
            stagedExpectedRevisions.set(row.issueNumber, evidenceRevisions);
          }
          runInWriteTransaction(() => {
            assertRefreshWriteAllowed(
              `issue page ${pagesFetched} classification persistence transaction`,
            );
            assertIssueEvidenceRevisions(stagedExpectedRevisions);
            for (const row of stagedClassifications) {
              const evidenceRevisions = stagedExpectedRevisions.get(row.issueNumber);
              if (!evidenceRevisions) {
                throw new Error(
                  `Missing staged classifier source revisions for issue #${row.issueNumber}`,
                );
              }
              upsertClassificationForSnapshot(
                row.issueNumber,
                row.staged,
                acceptedIssueCommentSnapshot(
                  row.issueNumber,
                  snapshotsByIssue.get(row.issueNumber),
                ),
                classifierIdentity,
                evidenceRevisions,
              );
            }
            assertRefreshWriteAllowed(
              `issue page ${pagesFetched} classification persistence commit`,
            );
          });
          classifiedCount += stagedClassifications.length;
          persistedClassificationCount = stagedClassifications.length;
        } catch (error) {
          const message = recordEvidenceRefreshFailure('issue-classification-write', pageEvidenceScope, error, pageEvidenceContext);
          console.warn(`${message}; rolled back issue classification writes and refusing score persistence`);
          classificationFailures.push(message);
        }
      }
      if (classificationStageFailure) {
        issuePaginationStopReason = 'evidence_failure';
        if (classificationWorkerFailures.length === 0) {
          const message = recordEvidenceRefreshFailure(
            'issue-classification',
            pageEvidenceScope,
            classificationStageFailure,
            pageEvidenceContext,
          );
          classificationFailures.push(message);
        }
        throw new Error(
          `Issue classification failed after ${persistedClassificationCount} completed ` +
          `classification(s) were durably persisted; refusing score publication`,
          { cause: classificationStageFailure },
        );
      }

      if (crossedOldest) crossedOldestEver = true;

      // During an exhaustive crawl, do not stop on timestamps or page sameness:
      // older still-open issues are part of the release's current debt.
      const hasUnfetchedIssuePages =
        (issuePagination as IssueCrawlPagination | null)?.hasNextPage === true;
      const canEarlyStop =
        !exhaustiveIssueCrawl && backfillDone && hasUnfetchedIssuePages && allUnchanged;
      const canCrossedOldestStop =
        !exhaustiveIssueCrawl && hasUnfetchedIssuePages && crossedOldest;
      if (canEarlyStop || canCrossedOldestStop) {
        issuePaginationStopReason = 'early_stop';
        break paginate;
      }
      if (
        pagesFetched >= MAX_PAGES &&
        (issuePagination as IssueCrawlPagination | null)?.exhausted !== true
      ) {
        issuePaginationStopReason = 'page_cap';
        break paginate;
      }
      }
    } catch (error) {
      finishIssueCrawlTiming();
      if (error instanceof IssuePaginationFailure) {
        const paginationMessage = error.paginationCause instanceof Error
          ? error.paginationCause.message
          : String(error.paginationCause);
        issuePaginationStopReason = paginationMessage.includes(
          `repository.issues exceeded ${MAX_PAGES} pages`,
        )
          ? 'page_cap'
          : 'evidence_failure';
        const scope = pagesFetched > 0 ? `after page ${pagesFetched}` : 'before first page';
        failIssuePagination({
          cause: error.paginationCause,
          scope,
          context: {
            pagesFetched,
            issuesFetched,
            monitoredIssuesFetched,
            maxIssuePages: MAX_PAGES,
          },
          recordFailure: recordEvidenceRefreshFailure,
          buildCrawlMeta: buildIssueCrawlMeta,
          persistCrawlMeta: persistIssueCrawlMeta,
        });
      }
      if (issuePaginationStopReason === 'evidence_failure') {
        persistIssueCrawlMeta(buildIssueCrawlMeta());
        throw error;
      }
      issuePaginationStopReason = 'evidence_failure';
      const message = recordEvidenceRefreshFailure(
        'issue-crawl',
        pagesFetched > 0 ? `page ${pagesFetched}` : 'before first page',
        error,
        {
          pagesFetched,
          issuesFetched,
          monitoredIssuesFetched,
          maxIssuePages: MAX_PAGES,
        },
      );
      persistIssueCrawlMeta(buildIssueCrawlMeta());
      throw new Error(`${message}; refusing to persist scores after issue crawl failure`);
    } finally {
      finishIssueCrawlTiming();
    }

    if (shouldRefuseScoreAfterTruncatedCommentScans(commenterScanTruncatedCount)) {
      const error = new Error(`${commenterScanTruncatedCount} issue(s) had incomplete comment scans`);
      const message = recordEvidenceRefreshFailure('issue-comments-truncated', null, error, {
        commenterScanTruncatedCount,
      });
      console.warn(`${message}; refusing score persistence until issue comments are fully scanned`);
      issuePaginationStopReason = 'evidence_failure';
      persistIssueCrawlMeta(buildIssueCrawlMeta());
      throw new Error(`${message}; refusing to persist scores from incomplete comment evidence`);
    }

    let issueCrawlMeta = buildIssueCrawlMeta();
    persistIssueCrawlMeta(issueCrawlMeta);
    if (shouldRefuseScoreAfterIssuePagination(issuePaginationStopReason)) {
      const reason = issuePaginationStopReason === 'page_cap'
        ? `Issue pagination stopped at MAX_ISSUE_PAGES=${MAX_PAGES}`
        : 'Issue pagination stopped after evidence refresh failure';
      throw new Error(`${reason}; refusing to persist scores from incomplete crawl`);
    }
    if (shouldRefuseScoreAfterClassificationFailures(classificationFailures)) {
      const summarized = summarizeFailures(classificationFailures);
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        classificationFailures: summarized,
      });
      throw new Error(`Classification failed for ${classificationFailures.length} issue(s); refusing to persist scores`);
    }

    const completedCatalog = completedIssueCatalog as GhIssueCatalogMetadata | null;
    const completedSnapshot = issueCatalogSnapshot as IssueCatalogSnapshotRunMetadata | null;
    if (!completedSnapshot || !completedCatalog) {
      throw new Error('Exhaustive issue crawl completed without a durable catalog snapshot');
    }
    const consumedAt = new Date().toISOString();
    assertRefreshWriteAllowed('issue catalog snapshot consumption');
    const consumption = consumeIssueCatalogSnapshot({
      snapshotId: completedSnapshot.snapshotId,
      repository: issueRepositoryIdentity(),
      runId,
      consumedAt,
      processedRowCount: completedCatalog.nodeCount,
      processedPageCount: completedCatalog.pageCount,
      assertCanWrite: assertRefreshWriteAllowed,
    });
    issueCatalogSnapshot = {
      ...completedSnapshot,
      consumedAt: consumption.consumedAt,
      consumedByRunId: consumption.runId,
      consumptionContentHash: consumption.contentHash,
    };
    issueCrawlMeta = buildIssueCrawlMeta();
    persistIssueCrawlMeta(issueCrawlMeta);

    if (shouldMarkBackfillComplete({
      issuePaginationStopReason,
      paginationExhaustiveStable:
        completedCatalog?.exhausted === true &&
        completedCatalog.stabilized === true &&
        completedCatalog.nodeCount === completedCatalog.totalCount &&
        completedCatalog.uniqueCount === completedCatalog.totalCount,
    })) {
      const establishedAt = new Date().toISOString();
      issueBaseline = issueCrawlBaselineFromCatalog(
        completedCatalog!,
        establishedAt,
        refreshStartedAt,
      );
      assertRefreshWriteAllowed('issue exhaustive baseline persistence');
      runInWriteTransaction(() => {
        assertRefreshWriteAllowed('issue exhaustive baseline persistence transaction');
        setMeta(ISSUE_CRAWL_BASELINE_META_KEY, JSON.stringify(issueBaseline));
        setMeta(BACKFILL_FLAG, establishedAt);
        assertRefreshWriteAllowed('issue exhaustive baseline persistence commit');
      });
      issueCrawlMeta = buildIssueCrawlMeta();
      persistIssueCrawlMeta(issueCrawlMeta);
    } else if (issuePaginationStopReason === 'page_cap') {
      console.warn(`[refresh] issue pagination stopped at MAX_ISSUE_PAGES=${MAX_PAGES}; exhaustive baseline unchanged`);
    }

    // After a prompt-sweep that walked the full pagination: if any rows are
    // STILL on the old prompt version, they're issues whose updated_at is too
    // old for GitHub pagination to reach within MAX_PAGES — they will keep
    // forcing the (expensive) sweep on every refresh forever. Drop them. If
    // GitHub ever surfaces those issues again (new comment), refresh will
    // re-classify them fresh on the next pass.
    if (promptSweep && shouldDropStaleClassificationsAfterPromptSweep(issuePaginationStopReason)) {
      const leftover = countStaleClassifications(PROMPT_VERSION);
      if (leftover > 0) {
        const dropped = runRefreshWrite(
          'stale classification deletion',
          () => deleteStaleClassifications(PROMPT_VERSION),
        );
        console.log(`[refresh] dropped ${dropped} unreachable stale rows after sweep`);
      }
    } else if (promptSweep && issuePaginationStopReason === 'page_cap') {
      console.warn('[refresh] prompt-sweep reached page cap; stale classifications were not dropped');
    }

    refreshLease.renew('closure evidence');
    const allReleases = releases.map((release) => {
      const row = getRelease(release.tag_name);
      if (!row) {
        throw new Error(`Persisted monitored release ${release.tag_name} is missing after catalog upsert`);
      }
      return row;
    });
    const closureReleaseTags = allReleases.map((release) => release.tag);
    const closureTargets = closureTargetsForReleases(allReleases);
    const releaseIssueNumbersByTag = closureTargets.issueNumbersByTag;
    const assertClosureWriteAllowed = (stage: string): void => {
      throwIfAborted(signal);
      refreshLease.assertHeld(stage);
    };
    const closureRunContext = createClosureProofRunContext({
      assertCanWrite: assertClosureWriteAllowed,
      signal,
    });
    const closureContextForSignal = (
      workerSignal: AbortSignal,
    ): ClosureProofRunContext => ({
      ...closureRunContext,
      signal: workerSignal,
    });
    const reachabilityContext = createReleaseReachabilityRefreshContext({ signal });

    refreshLease.renew('pre-closure target reconciliation');
    const closureTargetIssueNumbers = closureTargets.issueNumbers;
    try {
      const targetReconciliation = await timed('closure.target-reconciliation', () =>
        reconcileIssueCommentSnapshotChunks({
          issueNumbers: closureTargetIssueNumbers,
          releaseTags: closureReleaseTags,
          classificationConcurrency: CLASSIFY_CONCURRENCY,
          assertCanWrite: assertClosureWriteAllowed,
          signal,
          onChunk: ({ completed, total, classified }) => {
            console.log(
              `[closure-targets] reconciled ${completed}/${total}; ` +
              `${classified} classification(s) refreshed in latest chunk`,
            );
          },
        }),
      );
      seedClosureRunContextFromReconciliation(closureRunContext, targetReconciliation);
      classifiedCount += targetReconciliation.classifiedIssueNumbers.length;
      console.log(
        `[closure-targets] ${closureTargetIssueNumbers.length} issue snapshot(s) accepted, ` +
        `${targetReconciliation.classifiedIssueNumbers.length} classification(s) refreshed`,
      );
    } catch (error) {
      const message = recordEvidenceRefreshFailure(
        'closure-target-reconciliation',
        null,
        error,
        {
          issueCount: closureTargetIssueNumbers.length,
          releaseTags: closureReleaseTags,
        },
      );
      throw new Error(`${message}; refusing closure proof from unreconciled target issues`);
    }

    let closureEvidenceResults: Array<{
      rel: (typeof allReleases)[number];
      closure: Awaited<ReturnType<typeof refreshClosureEvidenceForRelease>>;
    }>;
    try {
      closureEvidenceResults = await timed('closure.evidence', () =>
        mapWithConcurrency(
          allReleases,
          config.refresh.closureEvidenceConcurrency,
          async (rel, _index, workerSignal) => {
            try {
              return {
                rel,
                closure: await refreshClosureEvidenceForRelease(
                  rel.tag,
                  closureContextForSignal(workerSignal),
                ),
              };
            } catch (error) {
              throw new ReleaseRefreshStageError('closure-evidence', rel.tag, error);
            }
          },
          { signal },
        ),
      );
    } catch (error) {
      throwIfAborted(signal);
      const stageError = error instanceof ReleaseRefreshStageError ? error : null;
      const message = recordEvidenceRefreshFailure(
        'closure-evidence',
        stageError?.releaseTag ?? null,
        stageError?.stageCause ?? error,
        { releaseTag: stageError?.releaseTag ?? null },
      );
      throw new Error(
        `${message}; refusing score publication after cooperative closure evidence failure`,
        { cause: error },
      );
    }
    refreshLease.assertHeld('closure evidence completion');
    try {
      const closureEvidenceDrift = await timed('closure.evidence-drift-reconciliation', () =>
        reconcileClosureSnapshotDrift({
          runContext: closureRunContext,
          releaseTags: closureReleaseTags,
          classificationConcurrency: CLASSIFY_CONCURRENCY,
          assertCanWrite: assertClosureWriteAllowed,
          signal,
          rerunAffected: async (issueNumbers, attempt) => {
            const drifted = new Set(issueNumbers);
            let affected = allReleases.filter((release) => {
              const existing = closureEvidenceResults.find((result) => result.rel.tag === release.tag);
              return (
                existing?.closure.issueMetadataDriftIssueNumbers.some(
                  (issueNumber) => drifted.has(issueNumber),
                )
              ) || [...(releaseIssueNumbersByTag.get(release.tag) ?? [])]
                .some((issueNumber) => drifted.has(issueNumber));
            });
            if (affected.length === 0) affected = allReleases;
            const rerunResults = await mapWithConcurrency(
              affected,
              config.refresh.closureEvidenceConcurrency,
              async (rel, _index, workerSignal) => {
                try {
                  return {
                    rel,
                    closure: await refreshClosureEvidenceForRelease(
                      rel.tag,
                      closureContextForSignal(workerSignal),
                    ),
                  };
                } catch (error) {
                  throw new ReleaseRefreshStageError(
                    'closure-evidence-drift-rerun',
                    rel.tag,
                    error,
                  );
                }
              },
              { signal },
            );
            for (const rerun of rerunResults) {
              const index = closureEvidenceResults.findIndex((result) => result.rel.tag === rerun.rel.tag);
              if (index >= 0) closureEvidenceResults[index] = rerun;
            }
            console.log(
              `[closure-evidence-drift] attempt ${attempt}: reconciled ${issueNumbers.length} issue(s), ` +
              `reran ${affected.length} release(s)`,
            );
          },
        }),
      );
      classifiedCount += closureEvidenceDrift.classifiedIssueNumbers.length;
    } catch (error) {
      const message = recordEvidenceRefreshFailure(
        'closure-evidence-drift-reconciliation',
        null,
        error,
        { releaseTags: closureReleaseTags },
      );
      throw new Error(`${message}; refusing closure proof with unresolved issue snapshot metadata drift`);
    }
    for (const result of closureEvidenceResults) {
      console.log(
        `[closure-evidence] ${result.rel.tag}: ${result.closure.issueCount} closed issues ` +
        `(${result.closure.refreshedIssueCount} refreshed, ${result.closure.reusedIssueCount} reused)`,
      );
    }

    refreshLease.renew('closure dependency discovery');
    const preparedByTag = new Map<string, ClosureProofPreparedDependencies>();
    let dependencyResults: Array<{
      rel: (typeof allReleases)[number];
      prepared: ClosureProofPreparedDependencies;
    }>;
    try {
      dependencyResults = await timed('closure.dependencies', () =>
        mapWithConcurrency(
          allReleases,
          config.refresh.closureProofConcurrency,
          async (rel, _index, workerSignal) => {
            try {
              const prepared = await discoverClosureProofDependenciesForRelease(rel.tag, {
                runContext: closureContextForSignal(workerSignal),
              });
              return { rel, prepared };
            } catch (error) {
              throw new ReleaseRefreshStageError(
                'closure-dependency-discovery',
                rel.tag,
                error,
              );
            }
          },
          { signal },
        ),
      );
    } catch (error) {
      throwIfAborted(signal);
      const stageError = error instanceof ReleaseRefreshStageError ? error : null;
      const message = recordEvidenceRefreshFailure(
        'closure-dependency-discovery',
        stageError?.releaseTag ?? null,
        stageError?.stageCause ?? error,
        { releaseTag: stageError?.releaseTag ?? null },
      );
      throw new Error(
        `${message}; refusing score publication after cooperative dependency failure`,
        { cause: error },
      );
    }
    refreshLease.assertHeld('closure dependency discovery completion');
    try {
      const dependencyDrift = await timed('closure.dependency-drift-reconciliation', () =>
        reconcileClosureSnapshotDrift({
          runContext: closureRunContext,
          releaseTags: closureReleaseTags,
          classificationConcurrency: CLASSIFY_CONCURRENCY,
          assertCanWrite: assertClosureWriteAllowed,
          signal,
          rerunAffected: async (issueNumbers, attempt) => {
            const drifted = new Set(issueNumbers);
            let affected = allReleases.filter((release) => {
              const existing = dependencyResults.find((result) => result.rel.tag === release.tag);
              return !existing ||
                existing.prepared.analysisIssueNumbers.some((issueNumber) => drifted.has(issueNumber)) ||
                [...(releaseIssueNumbersByTag.get(release.tag) ?? [])]
                  .some((issueNumber) => drifted.has(issueNumber));
            });
            if (affected.length === 0) affected = allReleases;

            const closureReruns = await mapWithConcurrency(
              affected,
              config.refresh.closureEvidenceConcurrency,
              async (rel, _index, workerSignal) => {
                try {
                  return {
                    rel,
                    closure: await refreshClosureEvidenceForRelease(
                      rel.tag,
                      closureContextForSignal(workerSignal),
                    ),
                  };
                } catch (error) {
                  throw new ReleaseRefreshStageError(
                    'closure-evidence-dependency-drift-rerun',
                    rel.tag,
                    error,
                  );
                }
              },
              { signal },
            );
            for (const rerun of closureReruns) {
              const index = closureEvidenceResults.findIndex((result) => result.rel.tag === rerun.rel.tag);
              if (index >= 0) closureEvidenceResults[index] = rerun;
            }

            const dependencyReruns = await mapWithConcurrency(
              affected,
              config.refresh.closureProofConcurrency,
              async (rel, _index, workerSignal) => {
                try {
                  const prepared = await discoverClosureProofDependenciesForRelease(rel.tag, {
                    runContext: closureContextForSignal(workerSignal),
                  });
                  return { rel, prepared };
                } catch (error) {
                  throw new ReleaseRefreshStageError(
                    'closure-dependency-drift-rerun',
                    rel.tag,
                    error,
                  );
                }
              },
              { signal },
            );
            for (const rerun of dependencyReruns) {
              const index = dependencyResults.findIndex((result) => result.rel.tag === rerun.rel.tag);
              if (index >= 0) dependencyResults[index] = rerun;
            }
            console.log(
              `[closure-dependency-drift] attempt ${attempt}: reconciled ${issueNumbers.length} issue(s), ` +
              `reran ${affected.length} release(s)`,
            );
          },
        }),
      );
      classifiedCount += dependencyDrift.classifiedIssueNumbers.length;
    } catch (error) {
      const message = recordEvidenceRefreshFailure(
        'closure-dependency-drift-reconciliation',
        null,
        error,
        { releaseTags: closureReleaseTags },
      );
      throw new Error(`${message}; refusing closure proof with unresolved dependency snapshot drift`);
    }
    for (const result of dependencyResults) {
      preparedByTag.set(result.rel.tag, result.prepared);
      console.log(
        `[closure-dependencies] ${result.rel.tag}: ` +
        `${result.prepared.issueNumbers.length} source issues prepared`,
      );
    }

    const closureDependencyIssueNumbers = [...new Set(
      dependencyResults.flatMap((result) => result.prepared.analysisIssueNumbers),
    )].sort((left, right) => left - right);
    if (closureDependencyIssueNumbers.length > 0) {
      try {
        const dependencyReconciliation = await timed(
          'closure.dependency-classification-reconciliation',
          () => reconcileIssueCommentSnapshotChunks({
            issueNumbers: closureDependencyIssueNumbers,
            releaseTags: closureReleaseTags,
            snapshotsByIssue: closureRunContext.commentSnapshotsByIssue,
            classificationConcurrency: CLASSIFY_CONCURRENCY,
            assertCanWrite: assertClosureWriteAllowed,
            signal,
          }),
        );
        seedClosureRunContextFromReconciliation(
          closureRunContext,
          dependencyReconciliation,
        );
        classifiedCount += dependencyReconciliation.classifiedIssueNumbers.length;
        const missingCurrentClassifications = closureDependencyIssueNumbers.filter(
          (issueNumber) => {
            const snapshot = closureRunContext.commentSnapshotsByIssue.get(issueNumber);
            return !snapshot || !classificationMatchesSnapshot(
              getClassification(issueNumber),
              snapshot,
              classifierIdentity.digest,
            );
          },
        );
        if (missingCurrentClassifications.length > 0) {
          throw new Error(
            `Canonical closure dependencies lack current classification: ` +
            missingCurrentClassifications.map((issueNumber) => `#${issueNumber}`).join(', '),
          );
        }
        console.log(
          `[closure-dependency-classification] ${closureDependencyIssueNumbers.length} ` +
          `dependency issue(s) current; ` +
          `${dependencyReconciliation.classifiedIssueNumbers.length} refreshed`,
        );
      } catch (error) {
        const message = recordEvidenceRefreshFailure(
          'closure-dependency-classification',
          null,
          error,
          {
            issueNumbers: closureDependencyIssueNumbers,
            releaseTags: closureReleaseTags,
          },
        );
        throw new Error(
          `${message}; refusing closure proof with unclassified canonical dependencies`,
          { cause: error },
        );
      }
    }

    refreshLease.renew('mutable pull request metadata');
    let mutablePullRequestMetadataComplete = true;
    try {
      const refreshedPullRequests = await timed('closure.mutable-pr-metadata', () =>
        refreshMutablePullRequestMetadata(closureRunContext),
      { recoverable: true },
      );
      refreshLease.assertHeld('mutable pull request metadata completion');
      console.log(`[closure-pr-metadata] ${refreshedPullRequests} mutable or missing PR(s) refreshed`);
    } catch (error) {
      mutablePullRequestMetadataComplete = false;
      const message = recordEvidenceRefreshFailure('pull-request-metadata', null, error);
      console.warn(`${message}; refusing score persistence after evidence refresh failures`);
    }

    const closureDependenciesComplete = mutablePullRequestMetadataComplete;
    const reachabilityReleaseTags = [
      ...allReleases.map((release) => release.tag),
      ...(predecessorBoundary ? [predecessorBoundary.tag_name] : []),
    ];
    let reachabilityReady = false;
    if (closureDependenciesComplete) {
      refreshLease.renew('release reachability');
      try {
        const reachability = await timed('closure.reachability', () =>
          checkReleasePrReachabilityForReleases(
            reachabilityReleaseTags,
            {
              context: reachabilityContext,
              signal,
              assertCanWrite: assertClosureWriteAllowed,
            },
          ),
          { recoverable: true },
        );
        refreshLease.assertHeld('release reachability completion');
        for (const releaseTag of reachabilityReleaseTags) {
          const result = reachability.get(releaseTag);
          if (result) {
            const role = releaseTag === predecessorBoundary?.tag_name ? ' predecessor-boundary' : '';
            console.log(`[reachability${role}] ${releaseTag}: ${result.reachable}/${result.candidates} reachable`);
          }
        }
        reachabilityReady = reachability.size === reachabilityReleaseTags.length;
        if (!reachabilityReady) {
          throw new Error(
            `Bulk reachability returned ${reachability.size}/${reachabilityReleaseTags.length} ` +
            'monitored releases plus predecessor boundary',
          );
        }
      } catch (error) {
        for (const releaseTag of reachabilityReleaseTags) {
          const message = recordEvidenceRefreshFailure('reachability', releaseTag, error, {
            releaseTag,
            releaseRole: releaseTag === predecessorBoundary?.tag_name ? 'predecessor_boundary' : 'monitored',
          });
          console.warn(`${message}; refusing score persistence after evidence refresh failures`);
        }
      }
    }

    const releasesNeedingInitialProof = reachabilityReady ? allReleases.filter((release) => {
      const integrity = releaseClosureProofIntegrity(release.tag, 1);
      return integrity.missingCount > 0 ||
        integrity.extraCount > 0 ||
        integrity.staleCount > 0 ||
        integrity.analyzerVersionMismatchCount > 0;
    }) : [];
    const proofRecomputationRequired = releasesNeedingInitialProof.length > 0;
    let initialProofComplete = reachabilityReady && !proofRecomputationRequired;
    if (initialProofComplete) {
      console.log('[closure-proof] all monitored proof rows are current; proof calculation and stabilization reused');
    }
    if (reachabilityReady && proofRecomputationRequired) {
      refreshLease.renew('initial closure proof analysis');
      console.log(
        `[closure-proof] ${releasesNeedingInitialProof.length}/${allReleases.length} release(s) require direct proof recomputation before stabilization`,
      );
      let initialProofResults: Array<{
        rel: (typeof allReleases)[number];
        proof: Awaited<ReturnType<typeof analyzeClosureProofsForRelease>>;
      }>;
      try {
        initialProofResults = await timed('closure.proof.initial', () =>
          mapWithConcurrency(
            releasesNeedingInitialProof,
            config.refresh.closureProofConcurrency,
            async (rel, _index, workerSignal) => {
              try {
                const preparedDependencies = preparedByTag.get(rel.tag);
                if (!preparedDependencies) {
                  throw new Error(`Missing prepared closure dependencies for ${rel.tag}`);
                }
                const proof = await analyzeClosureProofsForRelease(rel.tag, {
                  persistScoreAuditPayload: false,
                  refreshCommentPrMentionEvidence: false,
                  refreshPrReachability: false,
                  runContext: closureContextForSignal(workerSignal),
                  preparedDependencies,
                  reachabilityContext,
                });
                return { rel, proof };
              } catch (error) {
                throw new ReleaseRefreshStageError(
                  'closure-proof-discovery',
                  rel.tag,
                  error,
                );
              }
            },
            { signal },
          ),
        );
      } catch (error) {
        throwIfAborted(signal);
        const stageError = error instanceof ReleaseRefreshStageError ? error : null;
        const message = recordEvidenceRefreshFailure(
          'closure-proof-discovery',
          stageError?.releaseTag ?? null,
          stageError?.stageCause ?? error,
          { releaseTag: stageError?.releaseTag ?? null },
        );
        throw new Error(
          `${message}; refusing score publication after cooperative proof failure`,
          { cause: error },
        );
      }
      refreshLease.assertHeld('initial closure proof analysis completion');
      for (const result of initialProofResults) {
        console.log(
          `[closure-proof-initial] ${result.rel.tag}: ${result.proof.analyzed} analyzed`,
        );
      }
      initialProofComplete = true;
    }

    if (initialProofComplete && proofRecomputationRequired) {
      refreshLease.renew('closure proof stabilization');
      await timed('closure.proof.stabilize', async () => {
        const maxStabilizationPasses = 3;
        let unsettledTags = allReleases.map((release) => release.tag);
        for (let pass = 1; pass <= maxStabilizationPasses && unsettledTags.length > 0; pass++) {
          throwIfAborted(signal);
          for (const rel of allReleases) {
            throwIfAborted(signal);
            try {
              const preparedDependencies = preparedByTag.get(rel.tag);
              if (!preparedDependencies) throw new Error(`Missing prepared closure dependencies for ${rel.tag}`);
              const proof = await analyzeClosureProofsForRelease(rel.tag, {
                persistScoreAuditPayload: false,
                refreshCommentPrMentionEvidence: false,
                refreshPrReachability: false,
                runContext: closureRunContext,
                preparedDependencies,
                reachabilityContext,
              });
              console.log(
                `[closure-proof] pass ${pass} ${rel.tag}: ${proof.analyzed} analyzed after candidate stabilization`,
              );
            } catch (error) {
              throwIfAborted(signal);
              if (isAbortError(error)) throw error;
              const message = recordEvidenceRefreshFailure('closure-proof', rel.tag, error, {
                releaseTag: rel.tag,
                stabilizationPass: pass,
              });
              console.warn(`${message}; refusing score persistence after evidence refresh failures`);
            }
          }
          unsettledTags = allReleases
            .filter((release) => {
              const integrity = releaseClosureProofIntegrity(release.tag, 1);
              return integrity.missingCount > 0 ||
                integrity.extraCount > 0 ||
                integrity.staleCount > 0 ||
                integrity.analyzerVersionMismatchCount > 0;
            })
            .map((release) => release.tag);
          if (unsettledTags.length > 0) {
            console.log(
              `[closure-proof] stabilization pass ${pass} left ${unsettledTags.length} ` +
              `release(s) unsettled: ${unsettledTags.join(', ')}`,
            );
          }
        }
        if (unsettledTags.length > 0) {
          const error = new Error(
            `Closure proof dependencies did not stabilize after 3 passes: ${unsettledTags.join(', ')}`,
          );
          for (const releaseTag of unsettledTags) {
            const message = recordEvidenceRefreshFailure('closure-proof-stabilization', releaseTag, error, {
              releaseTag,
              maxStabilizationPasses,
            });
            console.warn(`${message}; refusing score persistence after evidence refresh failures`);
          }
        }
      });
      refreshLease.assertHeld('closure proof stabilization completion');
    }
    if (shouldRefuseScoreAfterEvidenceFailures(evidenceRefreshFailures)) {
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
        timings: timingSnapshot(),
      });
      throw new Error(`Evidence refresh failed for ${evidenceRefreshFailures.length} step(s); refusing to persist scores`);
    }

    // 4. Score every monitored release with the Install Confidence model — a single
    //    pass answering "should I install this stable?" from age/cadence-invariant
    //    signals (CVE, settle age, hotfix succession, stable-to-stable survival, beta
    //    shakeout, serious-regression balance). No peer median, no carry-forward
    //    attribution in the score itself. See lib/score.ts for the full rationale.
    refreshLease.renew('score build');
    const scoreScope = `monitored:${allReleases.map((release) => release.tag).join(',')}`;
    let scoreRun: ReturnType<typeof buildReleaseScoreRun>;
    let scoreBuiltAt: string;
    try {
      if (!advisoryProvenance) {
        throw new Error('Staged compound advisory snapshot is missing before score build');
      }
      const persistedAdvisorySnapshot = compoundAdvisorySnapshotById(
        advisoryProvenance.snapshotId,
      );
      if (!persistedAdvisorySnapshot) {
        throw new Error(
          `Staged compound advisory snapshot ${advisoryProvenance.snapshotId} is missing`,
        );
      }
      if (
        canonicalJson(persistedAdvisorySnapshot.metadata) !==
        canonicalJson(advisoryProvenance)
      ) {
        throw new Error(
          'Staged compound advisory snapshot changed after advisory ingestion',
        );
      }
      scoreRun = await timed(
        'score.build',
        () => buildReleaseScoreRunForStagedAdvisory(
          advisoryProvenance!.snapshotId,
          {
            releases: allReleases,
            artifactObservationRunId: runId,
          },
          assertRefreshWriteAllowed,
        ),
      );
      scoreBuiltAt = new Date().toISOString();
      refreshLease.assertHeld('score build completion');
    } catch (error) {
      const message = recordEvidenceRefreshFailure('score-build', scoreScope, error, {
        releaseTags: allReleases.map((release) => release.tag),
      });
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
        timings: timingSnapshot(),
      });
      throw new Error(`${message}; refusing to persist scores after score build failure`);
    }
    let finalIssueCatalog: GhIssueCatalogBoundaryVerification;
    let finalReleaseCatalog: GhReleaseCatalog;
    let catalogAttestation: ReleaseCatalogAttestation;
    const publicationIssueCatalogSnapshot =
      issueCatalogSnapshot as IssueCatalogSnapshotRunMetadata | null;
    if (!publicationIssueCatalogSnapshot) {
      throw new Error('Issue catalog snapshot metadata is missing before publication attestation');
    }
    try {
      refreshLease.renew('final publication catalog attestation');
      const finalAttestationStages = activeStageTimer.startCooperative([
        'issue.final-attest',
        'release.final-attest',
      ] as const);
      try {
        [finalIssueCatalog, finalReleaseCatalog] = await runCooperativeGroup([
          (groupSignal) => finalAttestationStages.timed(
            'issue.final-attest',
            () => verifyIssueCatalogBoundary(
              completedCatalog.snapshotBoundary,
              {
                maxPagesPerConnection: MAX_PAGES,
                perPage: 100,
                signal: groupSignal,
              },
            ),
          ),
          (groupSignal) => finalAttestationStages.timed(
            'release.final-attest',
            () => fetchReleaseCatalog({
              signal: groupSignal,
              operationBinding: releaseCatalogOperationBinding,
            }),
          ),
        ] as const, { signal });
      } catch (error) {
        try {
          finalAttestationStages.fail(error);
        } catch (stageError) {
          console.error(
            `[refresh:receipt] failed to close final attestation stages: ` +
            `${(stageError as Error).message}`,
          );
        }
        throw error;
      }
      const finalObservedAt = new Date().toISOString();
      const consumedSnapshot = getIssueCatalogSnapshot(
        publicationIssueCatalogSnapshot.snapshotId,
      );
      if (!consumedSnapshot) {
        throw new Error(
          `Consumed issue catalog snapshot ${publicationIssueCatalogSnapshot.snapshotId} is missing`,
        );
      }
      issueCatalogAttestation = finalIssueCatalogAttestation({
        snapshot: consumedSnapshot,
        finalCatalog: finalIssueCatalog,
        observedAt: finalObservedAt,
      });
      catalogAttestation = finalReleaseCatalogAttestation({
        initialCatalog: releaseCatalog,
        finalCatalog: finalReleaseCatalog,
        monitoredReleaseCount,
        scoreRun,
        scoreBuiltAt,
        finalObservedAt,
      });
      releaseCatalogMetadata = finalReleaseCatalog.metadata;
      issueCrawlMeta = buildIssueCrawlMeta();
      assertRefreshWriteAllowed('final publication catalog attestation persistence');
      persistIssueCrawlMeta(issueCrawlMeta);
      assertRefreshWriteAllowed('final publication catalog attestation completion');
    } catch (error) {
      const message = recordEvidenceRefreshFailure(
        'publication-catalog-attestation',
        'final-issue-and-release-catalogs',
        error,
        {
          initialReleaseDigest: releaseCatalog.metadata.digest,
          initialIssueMembershipDigest: completedCatalog?.membershipDigest ?? null,
          initialIssueContentDigest: completedCatalog?.contentDigest ?? null,
          issueCatalogSnapshotId: publicationIssueCatalogSnapshot.snapshotId,
          initialNodeCount: releaseCatalog.metadata.nodeCount,
          releaseTags: scoreRun.scored.map((result) => result.rel.tag),
          scoreBuiltAt,
        },
      );
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
        releaseCatalog: releaseCatalogMetadata,
        timings: timingSnapshot(),
      });
      throw new Error(`${message}; refusing score publication after final catalog attestation failure`);
    }
    refreshLease.renew('score persistence');
    activeStageTimer.ensure('score.persist');
    issueCrawlMeta = {
      ...issueCrawlMeta,
      evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
      get timings() {
        return timingSnapshot();
      },
    };
    const issueCrawlMetadataValidationProblems = issueCrawlMetadataProblems(
      issueCrawlMeta,
      issueBaseline,
      { forScorePersistence: true },
    );
    if (issueCrawlMetadataValidationProblems.length > 0) {
      const error = new Error(issueCrawlMetadataValidationProblems.join('; '));
      const message = recordEvidenceRefreshFailure(
        'issue-crawl-metadata',
        issueRepositoryIdentity(),
        error,
        {
          issueCrawlMetadataValidationProblems,
          baselineIdentity: issueBaseline?.identity ?? null,
        },
      );
      persistIssueCrawlMeta({
        ...issueCrawlMeta,
        evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
        timings: timingSnapshot(),
      });
      throw new Error(`${message}; refusing score persistence from invalid crawl metadata`);
    }
    if (!advisoryProvenance) {
      throw new Error('Advisory provenance is missing before score persistence');
    }
    if (!orchestration) {
      throw new Error(`Refresh ${runId} has no durable orchestration controller`);
    }
    const publication = orchestration.publishScore({
      scoreRun,
      scoredReleaseCount: scoreRun.scored.length,
      preparePublication: () => {
        throwIfAborted(signal);
        refreshLease.renew('atomic score publication');
      },
      assertScorePersistAllowed: () => {
        throwIfAborted(signal);
        refreshLease.assertHeld('score persistence transaction');
      },
      activatePublication: () => {
        activateCompoundAdvisorySnapshot(advisoryProvenance.snapshotId, {
          assertCanWrite: assertRefreshWriteAllowed,
        });
      },
      persistScore: () => persistReleaseScoreRun(scoreRun, {
        source: 'refresh',
        runId,
        codeRevision,
        scope: scoreScope,
        issueCrawl: issueCrawlMeta,
        catalogAttestation,
      }),
      afterPersist: () => {
        supersedeIngestionEvidenceFailures({
          successfulRunId: runId,
        });
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
      assertForecastAllowed: () => {
        throwIfAborted(signal);
        refreshLease.assertHeld('forecast publication transaction');
      },
      assertCommitAllowed: () => {
        throwIfAborted(signal);
        refreshLease.assertHeld('score publication commit');
        const publishedSourceIdentity = scoreSourceIdentity();
        if (
          canonicalJson(publishedSourceIdentity) !==
          canonicalJson(scoreRun.sourceIdentity)
        ) {
          throw new Error(
            `Published score source identity ${publishedSourceIdentity.digest} ` +
            `does not match staged identity ${scoreRun.sourceIdentity.digest}`,
          );
        }
      },
      finalizeScore: finalizeReleaseScorePublicationMetadata,
      captureForecast: (scorePersistence) => captureReleaseValidationForecasts({
        run: scoreRun,
        scorePersistence,
      }),
      forecastCount: (forecastCapture) => forecastCapture.forecasts.length,
      forecastDetails: (forecastCapture) => ({
        eligibilityOutcome: forecastCapture.eligibilityOutcome,
      }),
      successPayload: (scorePersistence, forecastCapture) => successReceiptPayload({
        operation,
        trigger,
        codeRevision,
        scoreRun,
        scorePersistence,
        forecastCapture,
        advisoryProvenance,
        releaseArtifacts: releaseArtifactPublicationForRun(runId),
      }),
      forecastFailureDetails: (_error, scorePersistence) => {
        const plan = scorePersistence.forecastPlan;
        const enrollments = plan
          ? listReleaseValidationOpportunityEnrollments()
            .filter((row) =>
              row.release_tag === plan.latestReleaseTag &&
              row.release_published_at === plan.latestReleasePublishedAt &&
              row.score_model_version === plan.scoreModelVersion &&
              row.prompt_version === plan.promptVersion &&
              row.code_revision === plan.codeRevision &&
              plan.slots.some((slot) =>
                slot.opportunityCode === row.opportunity_code))
            .map((row) => ({
              opportunityId: row.opportunity_id,
              opportunityCode: row.opportunity_code,
              enrollmentContentHash: row.content_hash,
            }))
          : [];
        return {
          historyRunId: scorePersistence.historyRunId,
          historyRunContentHash: scorePersistence.historyRunContentHash,
          forecastPlan: plan,
          enrollments,
        };
      },
      mapScorePersistError: (error) => {
        const message = recordEvidenceRefreshFailure('score-persist', scoreScope, error, {
          releaseTags: allReleases.map((release) => release.tag),
        });
        persistIssueCrawlMeta({
          ...issueCrawlMeta,
          evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
          timings: timingSnapshot(),
        });
        return new Error(`${message}; score persistence did not complete`);
      },
      mapForecastError: (error, scorePersistence) => {
        const message = recordEvidenceRefreshFailure(
          'forecast-publication',
          scoreScope,
          error,
          {
            historyRunId: scorePersistence.historyRunId,
            historyRunContentHash: scorePersistence.historyRunContentHash,
            releaseTags: allReleases.map((release) => release.tag),
          },
        );
        persistIssueCrawlMeta({
          ...issueCrawlMeta,
          evidenceRefreshFailures: summarizeFailures(evidenceRefreshFailures),
          timings: timingSnapshot(),
        });
        return new Error(
          `${message}; atomic score/forecast/success receipt publication rolled back`,
        );
      },
    });
    terminalReceiptId = publication.receiptId;

    processLastRefreshAt = new Date().toISOString();
    invalidateCache();
    if (!terminalReceiptId) {
      throw new Error(`Refresh ${runId} completed without a capture receipt`);
    }
    return {
      runId,
      receiptId: terminalReceiptId,
      classifiedCount,
      releaseCount: allReleases.length,
      durationMs: Date.now() - t0,
      timings: timingSnapshot(),
      releaseCatalog: finalReleaseCatalog.metadata,
    };
      },
    );
  } catch (e) {
    lastError = (e as Error).message;
    terminalReceiptId = orchestration?.fail(e) ?? terminalReceiptId;
    throw e;
  } finally {
    composedRefreshSignal.cleanup();
    try {
      refreshLease.release();
    } catch (error) {
      console.error(`[refresh:lease] failed to release ${REFRESH_LEASE_NAME} for ${leaseHolderId}: ${(error as Error).message}`);
    } finally {
      refreshLeaseRegistry.clear(refreshLease);
    }
    refreshing = false;
    activeRefresh?.resolve();
    if (activeRefresh?.promise === activePromise) {
      activeRefresh = null;
    }
  }
}

function shouldMarkBackfillComplete({
  issuePaginationStopReason,
  paginationExhaustiveStable,
}: {
  issuePaginationStopReason: IssuePaginationStopReason;
  paginationExhaustiveStable: boolean;
}): boolean {
  return issuePaginationStopReason === 'exhausted' && paginationExhaustiveStable;
}

function shouldDropStaleClassificationsAfterPromptSweep(issuePaginationStopReason: IssuePaginationStopReason): boolean {
  return issuePaginationStopReason === 'exhausted';
}

function shouldRefuseScoreAfterIssuePagination(issuePaginationStopReason: IssuePaginationStopReason): boolean {
  return issuePaginationStopReason !== 'exhausted';
}

function shouldRefuseScoreAfterEvidenceFailures(failures: unknown[]): boolean {
  return failures.length > 0;
}

function shouldRefuseScoreAfterTruncatedCommentScans(count: number): boolean {
  return count > 0;
}

type ReleaseCatalogLike<T> = {
  releases: T[];
  metadata: Pick<
    GhReleaseCatalog['metadata'],
    'exhausted' | 'stabilized' | 'totalCount' | 'nodeCount'
  >;
};

type PublicationOrderedRelease = {
  node_id: string;
  tag_name: string;
  published_at: string | null;
  prerelease: boolean;
  draft: boolean;
};

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function requiredPublicationTimestamp(release: PublicationOrderedRelease): number {
  if (typeof release.published_at !== 'string' || release.published_at.length === 0) {
    throw new Error(`release ${release.tag_name} (${release.node_id}) is missing published_at`);
  }
  const timestamp = Date.parse(release.published_at);
  if (!Number.isFinite(timestamp)) {
    throw new Error(
      `release ${release.tag_name} (${release.node_id}) has malformed published_at ${release.published_at}`,
    );
  }
  return timestamp;
}

function orderReleaseCatalogByPublication<T extends PublicationOrderedRelease>(releases: T[]): T[] {
  const published = releases.filter((release) => !release.draft);
  const timestamps = new Map<T, number>();
  for (const release of published) {
    timestamps.set(release, requiredPublicationTimestamp(release));
  }
  return published.slice().sort((left, right) => {
    const publishedDifference = (timestamps.get(right) ?? 0) - (timestamps.get(left) ?? 0);
    return publishedDifference ||
      compareBinary(left.tag_name, right.tag_name) ||
      compareBinary(left.node_id, right.node_id);
  });
}

function assertUnambiguousStablePublicationContext<T extends PublicationOrderedRelease>(releases: T[]): void {
  const byTimestamp = new Map<number, T>();
  for (const release of releases.filter((candidate) => !candidate.prerelease)) {
    const timestamp = requiredPublicationTimestamp(release);
    const existing = byTimestamp.get(timestamp);
    if (existing) {
      throw new Error(
        `release publication timestamp ambiguity at ${release.published_at}: ` +
        `${existing.tag_name} (${existing.node_id}) and ${release.tag_name} (${release.node_id})`,
      );
    }
    byTimestamp.set(timestamp, release);
  }
}

function releaseWindowCompleteness<T extends PublicationOrderedRelease>(
  catalog: ReleaseCatalogLike<T>,
  monitoredReleaseCount: number,
): {
  complete: boolean;
  reason: string | null;
  stableCount: number;
  exhausted: boolean;
  oldestMonitoredTag: string | null;
} {
  const exhausted = catalog.metadata.exhausted;
  const stableCount = catalog.releases.filter((release) => !release.draft && !release.prerelease).length;
  if (!exhausted) {
    return {
      complete: false,
      reason: 'release catalog did not explicitly exhaust repository.releases',
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  if (!catalog.metadata.stabilized) {
    return {
      complete: false,
      reason: 'release catalog did not stabilize across consecutive exhaustive sweeps',
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  if (catalog.metadata.nodeCount !== catalog.metadata.totalCount) {
    return {
      complete: false,
      reason:
        `release catalog metadata count mismatch: ` +
        `${catalog.metadata.nodeCount} nodes vs totalCount ${catalog.metadata.totalCount}`,
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  if (!Number.isInteger(monitoredReleaseCount) || monitoredReleaseCount <= 0) {
    return {
      complete: false,
      reason: `monitored release count must be a positive integer, got ${monitoredReleaseCount}`,
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  let selection: ReturnType<typeof selectReleaseWindow<T>>;
  try {
    selection = selectReleaseWindow(catalog, monitoredReleaseCount);
  } catch (error) {
    return {
      complete: false,
      reason: error instanceof Error ? error.message : String(error),
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  if (selection.monitored.length === 0) {
    return {
      complete: false,
      reason: 'release catalog did not return any published stable releases',
      stableCount,
      exhausted,
      oldestMonitoredTag: null,
    };
  }
  return {
    complete: true,
    reason: null,
    stableCount,
    exhausted,
    oldestMonitoredTag: selection.monitored[selection.monitored.length - 1]?.tag_name ?? null,
  };
}

function selectReleaseWindow<T extends PublicationOrderedRelease>(
  catalog: ReleaseCatalogLike<T>,
  monitoredReleaseCount: number,
): {
  ordered: T[];
  monitored: T[];
  predecessorBoundary: T | null;
  reachability: T[];
  derivedContext: T[];
} {
  if (!catalog.metadata.exhausted) {
    throw new Error('release selection requires explicit repository.releases exhaustion metadata');
  }
  if (!catalog.metadata.stabilized) {
    throw new Error('release selection requires a stabilized release catalog');
  }
  if (catalog.metadata.nodeCount !== catalog.metadata.totalCount) {
    throw new Error(
      `release selection metadata count mismatch: ` +
      `${catalog.metadata.nodeCount} nodes vs totalCount ${catalog.metadata.totalCount}`,
    );
  }
  if (!Number.isInteger(monitoredReleaseCount) || monitoredReleaseCount <= 0) {
    throw new Error(`monitored release count must be a positive integer, got ${monitoredReleaseCount}`);
  }
  const ordered = orderReleaseCatalogByPublication(catalog.releases);
  const stable = ordered.filter((release) => !release.prerelease);
  const monitored = stable.slice(0, monitoredReleaseCount);
  const predecessorBoundary = stable[monitoredReleaseCount] ?? null;
  const boundaryIndex = predecessorBoundary
    ? ordered.findIndex((release) => release.node_id === predecessorBoundary.node_id)
    : ordered.length - 1;
  let contextEnd = boundaryIndex;
  if (contextEnd >= 0) {
    const boundaryTimestamp = requiredPublicationTimestamp(ordered[contextEnd]);
    while (
      contextEnd + 1 < ordered.length &&
      requiredPublicationTimestamp(ordered[contextEnd + 1]) === boundaryTimestamp
    ) {
      contextEnd++;
    }
  }
  const derivedContext = contextEnd >= 0 ? ordered.slice(0, contextEnd + 1) : [];
  assertUnambiguousStablePublicationContext(stable);
  return {
    ordered,
    monitored,
    predecessorBoundary,
    reachability: predecessorBoundary ? [...monitored, predecessorBoundary] : monitored,
    derivedContext,
  };
}

function evidenceRefreshFailureMessage(source: string, scope: string | null, error: unknown): string {
  const suffix = scope ? ` ${scope}` : '';
  const message = error instanceof Error ? error.message : String(error);
  return `[${source}]${suffix} failed: ${message}`;
}

function shouldRefuseScoreAfterClassificationFailures(failures: unknown[]): boolean {
  return failures.length > 0;
}

function summarizeFailures(failures: string[]): string[] {
  const examples = failures.slice(0, FAILURE_EXAMPLE_LIMIT);
  const omitted = failures.length - examples.length;
  return omitted > 0
    ? [...examples, `[summary] ${omitted} additional failure(s) omitted`]
    : examples;
}

function persistIssueCrawlMetaUnchecked(meta: Record<string, unknown>): void {
  setMeta(ISSUE_CRAWL_META_KEY, JSON.stringify(meta));
}

export const __refreshTest = {
  acceptedClosureClaimExtraction,
  advisoryIngestionFailurePhase,
  advisoryIngestionProvenance,
  classificationMatchesSnapshot,
  classificationCanDeferLegacyCommentBinding,
  abortRefreshOnLeaseFailure,
  closureTargetsForReleases,
  commentCompleteness,
  CLOSURE_DRIFT_RECONCILE_MAX_ATTEMPTS,
  createRefreshOrchestration,
  createRefreshLeaseGuard,
  createStageTimer,
  failIssuePagination,
  fetchReconciledIssueEvidence,
  finalIssueCatalogAttestation,
  finalReleaseCatalogAttestation,
  flattenAdvisoryVulnerabilityRows,
  IssuePaginationFailure,
  issueMetadataMatchesSnapshot,
  issueCrawlBaselineFromCatalog,
  issueCrawlBaselineIdentity,
  issueCrawlBaselineProblems,
  issueCrawlMetadataProblems,
  issuePaginationFromCatalog,
  issuePaginationFromIncrementalSweep,
  issuePaginationFromPage,
  issuePageEvidenceTargets,
  runIssuePageEvidenceFetchGroup,
  runLeaseFencedWrite,
  closureClaimExtractionForIssue,
  issueRowFromRemoteMetadata,
  issueRemoteMetadataMatchesPersisted,
  stagedIssueRequiresMetadataReconciliation,
  issueCommentSnapshot,
  ISSUE_RECONCILE_MAX_ATTEMPTS,
  ISSUE_CRAWL_BASELINE_SCHEMA_VERSION,
  ISSUE_CRAWL_SCHEMA_VERSION,
  ISSUE_PAGINATION_SCHEMA_VERSION,
  mapWithConcurrency,
  accumulableClassifierGroundingFailure,
  recordIssueClassificationFailure,
  REFRESH_LEASE_NAME,
  REFRESH_LEASE_HEARTBEAT_MS,
  REFRESH_LEASE_TTL_MS,
  createRefreshLeaseRegistry,
  recordAdvisoryIngestionFailure,
  recordCommentCompletenessFailure,
  reconcileClosureSnapshotDrift,
  reconcileIssueCommentSnapshotChunks,
  resolveIssueCatalogSnapshotForRefresh,
  refreshEffectiveConfig,
  refreshOperationLabel,
  seedClosureRunContextFromReconciliation,
  successReceiptPayload,
  TARGET_RECONCILIATION_CHUNK_SIZE,
  shouldDropStaleClassificationsAfterPromptSweep,
  shouldMarkBackfillComplete,
  shouldRefuseScoreAfterClassificationFailures,
  shouldRefuseScoreAfterEvidenceFailures,
  shouldRefuseScoreAfterIssuePagination,
  shouldRefuseScoreAfterTruncatedCommentScans,
  orderReleaseCatalogByPublication,
  releaseWindowCompleteness,
  selectReleaseWindow,
  evidenceRefreshFailureMessage,
  persistIssueStateEvidence,
  persistClosureClaimEvidenceForIssue,
  summarizeFailures,
  withIssuePaginationFailureBoundary,
};

export {
  classifyIssueRow,
  classifyIssueRowWithLabels,
  isOpenFeltSeriousIssue,
} from './releaseScoring';
export { getRelease, issuesForVersion, listReleasesDb, openedDuringReign };
