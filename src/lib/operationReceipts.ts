import { createHash } from 'node:crypto';
import {
  releaseValidationDecisionId,
  releaseValidationForecastContentHash,
  validateReleaseValidationForecastProvenance,
  type ReleaseScoreAuditHistoryV2SealEvidence,
  type ReleaseScoreAuditHistoryEvidenceRow,
  type ReleaseScoreAuditHistoryRunSealEvidenceRow,
  type ReleaseScoreAuthorityRunEvidence,
  type ReleaseValidationForecastLedgerRow,
} from './releaseValidation';
import {
  releaseScoreAuditHistoryRowsContentHash,
  releaseScoreAuditHistoryRunContentHash,
} from './scoreHistoryLedger';
import {
  verifyReleaseValidationProofBundle,
  type ReleaseValidationForecastV2,
  type ReleaseValidationProofBundle,
} from './releaseValidationProof';
import {
  releaseArtifactPublicationScopeLinkProblems,
  releaseArtifactPublicationScopeProblems,
  releaseArtifactPublicationScopeScoreProblems,
} from './releaseArtifactPublicationScope';
import type {
  ReleaseArtifactObservation,
  ReleaseArtifactReceipt,
} from './releaseArtifactReceipt';
export {
  operationCaptureReceiptSemanticIdentity,
  type OperationCaptureReceiptSemanticIdentityInput,
} from './operationReceiptIdentity';

export const OPERATION_RECEIPT_SCHEMA_VERSION = 1;

export type OperationTerminalStatus = 'success' | 'failure' | 'abandoned';
export type OperationStageStatus = 'started' | 'completed' | 'failed';

export interface OperationAttemptHashInput {
  runId: string;
  operation: string;
  trigger: string;
  startedAt: string;
  leaseName: string;
  leaseHolderId: string;
  leaseExpiresAt: string;
  codeRevision: string;
  effectiveConfigJson: string;
}

export interface OperationStageEventHashInput {
  eventId: string;
  runId: string;
  sequence: number;
  stage: string;
  status: OperationStageStatus;
  occurredAt: string;
  durationMs: number | null;
  countsJson: string | null;
  detailsJson: string | null;
  previousContentHash: string | null;
}

export interface OperationCaptureReceiptHashInput {
  receiptId: string;
  runId: string;
  status: OperationTerminalStatus;
  finishedAt: string;
  durationMs: number;
  stageEventCount: number;
  stageChainHash: string | null;
  payloadJson: string;
  previousContentHash: string | null;
}

export interface OperationAttemptLedgerRow {
  run_id: string;
  operation: string;
  trigger: string;
  started_at: string;
  lease_name: string;
  lease_holder_id: string;
  lease_expires_at: string;
  code_revision: string;
  effective_config_json: string;
  effective_config_hash: string;
  content_hash: string;
}

export interface OperationStageEventLedgerRow {
  event_id: string;
  run_id: string;
  sequence: number;
  stage: string;
  status: OperationStageStatus;
  occurred_at: string;
  duration_ms: number | null;
  counts_json: string | null;
  details_json: string | null;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface OperationCaptureReceiptLedgerRow {
  receipt_id: string;
  run_id: string;
  status: OperationTerminalStatus;
  finished_at: string;
  duration_ms: number;
  stage_event_count: number;
  stage_chain_hash: string | null;
  payload_json: string;
  previous_content_hash: string | null;
  content_hash: string;
}

export interface OperationLeaseLedgerRow {
  name: string;
  holder_id: string;
  acquired_at: string;
  expires_at: string;
}

export type OperationArtifactReceiptLedgerRow = Pick<
  ReleaseArtifactReceipt,
  | 'receiptId'
  | 'release'
  | 'evidenceIdentity'
  | 'evidenceReportIdentity'
  | 'contentHash'
>;

export type OperationArtifactObservationLedgerRow = Pick<
  ReleaseArtifactObservation,
  | 'observationId'
  | 'runId'
  | 'release'
  | 'receiptId'
  | 'receiptContentHash'
  | 'contentHash'
>;

export type OperationArtifactMembershipPolicy = 'if-present' | 'strict';

export interface OperationHistoryRow extends ReleaseScoreAuditHistoryEvidenceRow {}

export interface OperationHistoryRunLinkRow
  extends ReleaseScoreAuditHistoryRunSealEvidenceRow {}

export interface OperationForecastLinkRow extends ReleaseValidationForecastLedgerRow {}

export type OperationAuthorityRunLinkRow = ReleaseScoreAuthorityRunEvidence;

export type OperationHistoryV2SealLinkRow =
  ReleaseScoreAuditHistoryV2SealEvidence;

export interface OperationReceiptLedgerVerification {
  artifactMembershipPolicy: OperationArtifactMembershipPolicy;
  artifactReceiptCount: number | null;
  artifactObservationCount: number | null;
  attemptCount: number;
  stageEventCount: number;
  receiptCount: number;
  unterminatedRunIds: string[];
  activeUnterminatedRunIds: string[];
  invalidUnterminatedRunIds: string[];
  hashChainProblems: string[];
  semanticProblems: string[];
  problems: string[];
}

export interface OperationReceiptSemanticLinkVerification {
  receiptCount: number;
  problems: string[];
}

type ReceiptForecastCapture = {
  decisionId: string;
  status: 'inserted' | 'already_captured' | null;
};

type ReceiptCanonicalForecastCapture = {
  forecastId: string;
  contentHash: string;
  obligationId: string;
  splitAssignmentId: string;
  cohortId: string;
  opportunityCode: string;
  horizonCode: string;
  legacyDecisionId: string;
  legacyContentHash: string;
  status: 'inserted' | 'already_captured' | null;
};

type ReceiptForecastState = {
  eligibilityOutcome: string | null;
  decisionIds: string[];
  captures: ReceiptForecastCapture[];
  canonicalFieldsDeclared: boolean;
  canonicalForecastIds: string[];
  canonicalForecastContentHashes: string[];
  canonicalCaptures: ReceiptCanonicalForecastCapture[];
  problems: string[];
};

export function canonicalJson(value: unknown): string {
  return JSON.stringify(canonicalValue(value));
}

export function operationEffectiveConfig(input: {
  github: {
    owner: string;
    repo: string;
    graphql: {
      concurrency: number;
      minStartSpacingMs: number;
      retryBaseMs: number;
      retryMaxMs: number;
      cooldownBaseMs: number;
      cooldownMaxMs: number;
    };
  };
  openai: {
    model: string;
    reasoningEffort: string;
    serviceTier: string;
    requestTimeoutMs: number;
    maxAttempts: number;
    retryBaseMs: number;
    retryMaxMs: number;
  };
  refresh: {
    onStartup: boolean;
    intervalMinutes: number;
    fullIssueBackfill: boolean;
    maxIssuePages: number;
    issuePageSize: number;
    issueCatalogSnapshotMaxAgeHours: number;
    classifyConcurrency: number;
    githubPageDelayMs: number;
    releaseNetworkConcurrency: number;
    closureEvidenceConcurrency: number;
    closureProofConcurrency: number;
    gitReachabilityConcurrency: number;
    gitCacheMaxPacks: number;
    gitCacheMaxSizeMiB: number;
    gitCacheMaintenanceTimeoutMs: number;
    openPullRequestRefreshMinutes: number;
    closedPullRequestRefreshMinutes: number;
  };
  limits: {
    releases: number;
  };
}): Record<string, unknown> {
  return {
    schemaVersion: OPERATION_RECEIPT_SCHEMA_VERSION,
    github: {
      owner: input.github.owner,
      repo: input.github.repo,
      graphql: {
        concurrency: input.github.graphql.concurrency,
        minStartSpacingMs: input.github.graphql.minStartSpacingMs,
        retryBaseMs: input.github.graphql.retryBaseMs,
        retryMaxMs: input.github.graphql.retryMaxMs,
        cooldownBaseMs: input.github.graphql.cooldownBaseMs,
        cooldownMaxMs: input.github.graphql.cooldownMaxMs,
      },
    },
    openai: {
      model: input.openai.model,
      reasoningEffort: input.openai.reasoningEffort,
      serviceTier: input.openai.serviceTier,
      requestTimeoutMs: input.openai.requestTimeoutMs,
      maxAttempts: input.openai.maxAttempts,
      retryBaseMs: input.openai.retryBaseMs,
      retryMaxMs: input.openai.retryMaxMs,
    },
    refresh: {
      onStartup: input.refresh.onStartup,
      intervalMinutes: input.refresh.intervalMinutes,
      fullIssueBackfill: input.refresh.fullIssueBackfill,
      maxIssuePages: input.refresh.maxIssuePages,
      issuePageSize: input.refresh.issuePageSize,
      issueCatalogSnapshotMaxAgeHours: input.refresh.issueCatalogSnapshotMaxAgeHours,
      classifyConcurrency: input.refresh.classifyConcurrency,
      githubPageDelayMs: input.refresh.githubPageDelayMs,
      releaseNetworkConcurrency: input.refresh.releaseNetworkConcurrency,
      closureEvidenceConcurrency: input.refresh.closureEvidenceConcurrency,
      closureProofConcurrency: input.refresh.closureProofConcurrency,
      gitReachabilityConcurrency: input.refresh.gitReachabilityConcurrency,
      gitCacheMaxPacks: input.refresh.gitCacheMaxPacks,
      gitCacheMaxSizeMiB: input.refresh.gitCacheMaxSizeMiB,
      gitCacheMaintenanceTimeoutMs: input.refresh.gitCacheMaintenanceTimeoutMs,
      openPullRequestRefreshMinutes: input.refresh.openPullRequestRefreshMinutes,
      closedPullRequestRefreshMinutes: input.refresh.closedPullRequestRefreshMinutes,
    },
    limits: {
      releases: input.limits.releases,
    },
  };
}

export function operationEffectiveConfigJson(
  input: Parameters<typeof operationEffectiveConfig>[0],
): string {
  return canonicalJson(operationEffectiveConfig(input));
}

export function operationAttemptConfigHash(effectiveConfigJson: string): string {
  return sha256(`operation-effective-config-v1\0${effectiveConfigJson}`);
}

export function operationAttemptContentHash(input: OperationAttemptHashInput): string {
  return sha256(
    `operation-attempt-v1\0${canonicalJson([
      input.runId,
      input.operation,
      input.trigger,
      input.startedAt,
      input.leaseName,
      input.leaseHolderId,
      input.leaseExpiresAt,
      input.codeRevision,
      input.effectiveConfigJson,
      operationAttemptConfigHash(input.effectiveConfigJson),
    ])}`,
  );
}

export function operationStageEventId(input: {
  runId: string;
  sequence: number;
  stage: string;
  status: OperationStageStatus;
}): string {
  return sha256(
    `operation-stage-event-id-v1\0${canonicalJson([
      input.runId,
      input.sequence,
      input.stage,
      input.status,
    ])}`,
  );
}

export function operationStageEventContentHash(input: OperationStageEventHashInput): string {
  return sha256(
    `operation-stage-event-v1\0${input.previousContentHash ?? ''}\0${canonicalJson([
      input.eventId,
      input.runId,
      input.sequence,
      input.stage,
      input.status,
      input.occurredAt,
      input.durationMs,
      input.countsJson,
      input.detailsJson,
    ])}`,
  );
}

export function operationCaptureReceiptId(runId: string): string {
  return sha256(`operation-capture-receipt-id-v1\0${runId}`);
}

export function operationCaptureReceiptContentHash(
  input: OperationCaptureReceiptHashInput,
): string {
  return sha256(
    `operation-capture-receipt-v1\0${input.previousContentHash ?? ''}\0${canonicalJson([
      input.receiptId,
      input.runId,
      input.status,
      input.finishedAt,
      input.durationMs,
      input.stageEventCount,
      input.stageChainHash,
      input.payloadJson,
    ])}`,
  );
}

export function operationErrorDetails(error: unknown): Record<string, unknown> {
  const name = redactSensitiveText(
    error instanceof Error && error.name ? error.name : 'Error',
  );
  const message = redactSensitiveText(
    error instanceof Error ? error.message : String(error),
  );
  const cause = error instanceof Error && error.cause != null
    ? redactSensitiveText(
      error.cause instanceof Error ? error.cause.message : String(error.cause),
    )
    : null;
  return {
    name,
    message,
    cause,
  };
}

export function verifyOperationReceiptLedger(input: {
  attempts: OperationAttemptLedgerRow[];
  stageEvents: OperationStageEventLedgerRow[];
  receipts: OperationCaptureReceiptLedgerRow[];
  leases?: OperationLeaseLedgerRow[];
  artifactReceipts?: readonly OperationArtifactReceiptLedgerRow[];
  artifactObservations?: readonly OperationArtifactObservationLedgerRow[];
  artifactMembershipPolicy?: OperationArtifactMembershipPolicy;
  observedAt?: string;
}): OperationReceiptLedgerVerification {
  const hashChainProblems: string[] = [];
  const semanticProblems: string[] = [];
  const artifactMembershipPolicy = normalizedArtifactMembershipPolicy(
    input.artifactMembershipPolicy,
    semanticProblems,
    'operation receipt ledger',
  );
  if (
    artifactMembershipPolicy === 'strict' &&
    (
      input.artifactReceipts === undefined ||
      input.artifactObservations === undefined
    )
  ) {
    semanticProblems.push(
      'operation receipt ledger strict artifact membership verification ' +
      'requires both complete receipt and observation ledgers',
    );
  }
  const attemptsByRun = new Map<string, OperationAttemptLedgerRow>();
  for (const attempt of input.attempts) {
    if (attemptsByRun.has(attempt.run_id)) {
      semanticProblems.push(`duplicate operation attempt run ${JSON.stringify(attempt.run_id)}`);
      continue;
    }
    attemptsByRun.set(attempt.run_id, attempt);
    if (attempt.effective_config_hash !== operationAttemptConfigHash(attempt.effective_config_json)) {
      hashChainProblems.push(`operation attempt ${JSON.stringify(attempt.run_id)} effective config hash mismatch`);
    }
    if (!isJsonObject(attempt.effective_config_json)) {
      semanticProblems.push(`operation attempt ${JSON.stringify(attempt.run_id)} effective config is not an object`);
    }
    if (
      !isTimestamp(attempt.started_at) ||
      !isTimestamp(attempt.lease_expires_at) ||
      Date.parse(attempt.lease_expires_at) <= Date.parse(attempt.started_at)
    ) {
      semanticProblems.push(
        `operation attempt ${JSON.stringify(attempt.run_id)} has invalid lease timing`,
      );
    }
    if (
      operationAttemptContentHash({
        runId: attempt.run_id,
        operation: attempt.operation,
        trigger: attempt.trigger,
        startedAt: attempt.started_at,
        leaseName: attempt.lease_name,
        leaseHolderId: attempt.lease_holder_id,
        leaseExpiresAt: attempt.lease_expires_at,
        codeRevision: attempt.code_revision,
        effectiveConfigJson: attempt.effective_config_json,
      }) !== attemptContentHash(attempt)
    ) {
      hashChainProblems.push(`operation attempt ${JSON.stringify(attempt.run_id)} content hash mismatch`);
    }
  }

  const stageEventsByRun = new Map<string, OperationStageEventLedgerRow[]>();
  for (const event of input.stageEvents) {
    const rows = stageEventsByRun.get(event.run_id) ?? [];
    rows.push(event);
    stageEventsByRun.set(event.run_id, rows);
  }
  for (const [runId, rows] of stageEventsByRun) {
    const attempt = attemptsByRun.get(runId);
    if (!attempt) {
      semanticProblems.push(`operation stage events reference missing attempt ${JSON.stringify(runId)}`);
    }
    rows.sort((left, right) => left.sequence - right.sequence);
    let previousContentHash: string | null = null;
    const activeStages = new Set<string>();
    for (const [index, row] of rows.entries()) {
      const expectedSequence = index + 1;
      if (row.sequence !== expectedSequence) {
        hashChainProblems.push(
          `operation stage run ${JSON.stringify(runId)} sequence ${row.sequence} expected ${expectedSequence}`,
        );
      }
      if (row.previous_content_hash !== previousContentHash) {
        hashChainProblems.push(
          `operation stage run ${JSON.stringify(runId)} sequence ${row.sequence} previous hash mismatch`,
        );
      }
      const expectedHash = operationStageEventContentHash({
        eventId: row.event_id,
        runId: row.run_id,
        sequence: row.sequence,
        stage: row.stage,
        status: row.status,
        occurredAt: row.occurred_at,
        durationMs: row.duration_ms,
        countsJson: row.counts_json,
        detailsJson: row.details_json,
        previousContentHash,
      });
      if (row.content_hash !== expectedHash) {
        hashChainProblems.push(
          `operation stage run ${JSON.stringify(runId)} sequence ${row.sequence} content hash mismatch`,
        );
      }
      if (!isTimestamp(row.occurred_at)) {
        semanticProblems.push(
          `operation stage run ${JSON.stringify(runId)} sequence ${row.sequence} has invalid time`,
        );
      } else if (attempt && Date.parse(row.occurred_at) < Date.parse(attempt.started_at)) {
        semanticProblems.push(
          `operation stage run ${JSON.stringify(runId)} sequence ${row.sequence} predates its attempt`,
        );
      }
      if (row.status === 'started') {
        if (activeStages.has(row.stage)) {
          semanticProblems.push(
            `operation stage run ${JSON.stringify(runId)} starts active stage ${JSON.stringify(row.stage)} twice`,
          );
        }
        activeStages.add(row.stage);
      } else if (!activeStages.delete(row.stage)) {
        semanticProblems.push(
          `operation stage run ${JSON.stringify(runId)} closes inactive stage ${JSON.stringify(row.stage)}`,
        );
      }
      previousContentHash = row.content_hash;
    }
    const receipt = input.receipts.find((row) => row.run_id === runId);
    if (receipt && receipt.status !== 'abandoned' && activeStages.size > 0) {
      semanticProblems.push(
        `operation stage run ${JSON.stringify(runId)} is terminal with active stages: ` +
        [...activeStages].sort().join(', '),
      );
    }
  }

  const receiptsByRun = new Map<string, OperationCaptureReceiptLedgerRow>();
  let previousReceiptHash: string | null = null;
  for (const receipt of input.receipts) {
    if (receiptsByRun.has(receipt.run_id)) {
      semanticProblems.push(`duplicate capture receipt run ${JSON.stringify(receipt.run_id)}`);
    }
    receiptsByRun.set(receipt.run_id, receipt);
    if (!attemptsByRun.has(receipt.run_id)) {
      semanticProblems.push(`capture receipt references missing attempt ${JSON.stringify(receipt.run_id)}`);
    }
    if (receipt.previous_content_hash !== previousReceiptHash) {
      hashChainProblems.push(`capture receipt ${JSON.stringify(receipt.receipt_id)} previous hash mismatch`);
    }
    const expectedHash = operationCaptureReceiptContentHash({
      receiptId: receipt.receipt_id,
      runId: receipt.run_id,
      status: receipt.status,
      finishedAt: receipt.finished_at,
      durationMs: receipt.duration_ms,
      stageEventCount: receipt.stage_event_count,
      stageChainHash: receipt.stage_chain_hash,
      payloadJson: receipt.payload_json,
      previousContentHash: previousReceiptHash,
    });
    if (receipt.content_hash !== expectedHash) {
      hashChainProblems.push(`capture receipt ${JSON.stringify(receipt.receipt_id)} content hash mismatch`);
    }
    const stageRows = (stageEventsByRun.get(receipt.run_id) ?? [])
      .slice()
      .sort((left, right) => left.sequence - right.sequence);
    const stageChainHash = stageRows.at(-1)?.content_hash ?? null;
    if (receipt.stage_event_count !== stageRows.length) {
      hashChainProblems.push(`capture receipt ${JSON.stringify(receipt.receipt_id)} stage event count mismatch`);
    }
    if (receipt.stage_chain_hash !== stageChainHash) {
      hashChainProblems.push(`capture receipt ${JSON.stringify(receipt.receipt_id)} stage chain hash mismatch`);
    }
    const postTerminalStageCount = stageRows.filter((row) =>
      Date.parse(row.occurred_at) > Date.parse(receipt.finished_at)).length;
    if (postTerminalStageCount > 0) {
      semanticProblems.push(
        `capture receipt ${JSON.stringify(receipt.receipt_id)} has ` +
        `${postTerminalStageCount} stage event(s) after terminal time`,
      );
    }
    if (!isJsonObject(receipt.payload_json)) {
      semanticProblems.push(`capture receipt ${JSON.stringify(receipt.receipt_id)} payload is not an object`);
    }
    const attempt = attemptsByRun.get(receipt.run_id);
    if (attempt) {
      semanticProblems.push(...operationReceiptTerminalSemanticProblems({
        attempt,
        stageEvents: stageRows,
        receipt,
        artifactReceipts: input.artifactReceipts,
        artifactObservations: input.artifactObservations,
        artifactMembershipPolicy,
      }));
    }
    previousReceiptHash = receipt.content_hash;
  }

  const unterminatedRunIds = input.attempts
    .map((attempt) => attempt.run_id)
    .filter((runId) => !receiptsByRun.has(runId))
    .sort();
  const activeUnterminatedRunIds: string[] = [];
  const invalidUnterminatedRunIds: string[] = [];
  if (unterminatedRunIds.length > 0) {
    const observedAtMs = Date.parse(input.observedAt ?? '');
    const leaseByName = new Map((input.leases ?? []).map((lease) => [lease.name, lease]));
    for (const runId of unterminatedRunIds) {
      const attempt = attemptsByRun.get(runId);
      const lease = attempt ? leaseByName.get(attempt.lease_name) : undefined;
      const active = !!attempt &&
        Number.isFinite(observedAtMs) &&
        !!lease &&
        lease.holder_id === attempt.lease_holder_id &&
        isTimestamp(lease.acquired_at) &&
        Date.parse(lease.acquired_at) <= observedAtMs &&
        isTimestamp(lease.expires_at) &&
        Date.parse(lease.expires_at) > observedAtMs;
      if (active) {
        activeUnterminatedRunIds.push(runId);
      } else {
        invalidUnterminatedRunIds.push(runId);
        semanticProblems.push(
          `unterminated operation attempt ${JSON.stringify(runId)} is not backed by its active matching lease`,
        );
      }
    }
  }
  for (const attempt of input.attempts) {
    if (receiptsByRun.has(attempt.run_id)) continue;
    semanticProblems.push(...operationReceiptSemanticProblems({
      attempt,
      stageEvents: (stageEventsByRun.get(attempt.run_id) ?? [])
        .slice()
        .sort((left, right) => left.sequence - right.sequence),
      artifactReceipts: input.artifactReceipts,
      artifactObservations: input.artifactObservations,
      artifactMembershipPolicy,
    }));
  }
  const uniqueSemanticProblems = [...new Set(semanticProblems)];
  const problems = [...hashChainProblems, ...uniqueSemanticProblems];
  return {
    artifactMembershipPolicy,
    artifactReceiptCount: input.artifactReceipts?.length ?? null,
    artifactObservationCount: input.artifactObservations?.length ?? null,
    attemptCount: input.attempts.length,
    stageEventCount: input.stageEvents.length,
    receiptCount: input.receipts.length,
    unterminatedRunIds,
    activeUnterminatedRunIds,
    invalidUnterminatedRunIds,
    hashChainProblems,
    semanticProblems: uniqueSemanticProblems,
    problems,
  };
}

export function operationReceiptSemanticProblems(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
  receipt?: OperationCaptureReceiptLedgerRow | null;
  artifactReceipts?: readonly OperationArtifactReceiptLedgerRow[];
  artifactObservations?: readonly OperationArtifactObservationLedgerRow[];
  artifactMembershipPolicy?: OperationArtifactMembershipPolicy;
}): string[] {
  const { attempt, receipt = null } = input;
  const prefixState = operationReceiptStagePrefixState({
    attempt,
    stageEvents: input.stageEvents,
  });
  const {
    activeStages,
    failedTerminalStage,
    previousOccurredAtMs,
    problems,
    stages,
  } = prefixState;
  const runPrefix = `operation run ${JSON.stringify(attempt.run_id)}`;
  const artifactMembershipPolicy = normalizedArtifactMembershipPolicy(
    input.artifactMembershipPolicy,
    problems,
    runPrefix,
  );
  if (
    artifactMembershipPolicy === 'strict' &&
    (
      input.artifactReceipts === undefined ||
      input.artifactObservations === undefined
    )
  ) {
    problems.push(
      `${runPrefix} strict artifact membership verification requires both ` +
      'complete receipt and observation ledgers',
    );
  }
  const attemptStartedAtMs = Date.parse(attempt.started_at);

  if (!receipt) return problems;
  const prefix = `capture receipt ${JSON.stringify(receipt.receipt_id)}`;
  const finishedAtMs = Date.parse(receipt.finished_at);
  if (receipt.run_id !== attempt.run_id) {
    problems.push(`${prefix} belongs to a different operation attempt`);
  }
  if (!Number.isFinite(finishedAtMs)) {
    problems.push(`${prefix} has an invalid finish time`);
  } else {
    if (Number.isFinite(previousOccurredAtMs) && finishedAtMs < previousOccurredAtMs) {
      problems.push(`${prefix} finishes before its final stage event`);
    }
    if (
      Number.isFinite(attemptStartedAtMs) &&
      receipt.duration_ms !== finishedAtMs - attemptStartedAtMs
    ) {
      problems.push(`${prefix} duration does not match its attempt timestamps`);
    }
  }
  if (!Number.isInteger(receipt.duration_ms) || receipt.duration_ms < 0) {
    problems.push(`${prefix} duration must be a non-negative integer`);
  }
  if (receipt.status !== 'abandoned' && activeStages.size > 0) {
    problems.push(
      `${runPrefix} is terminal with active stages: ${[...activeStages.keys()].sort().join(', ')}`,
    );
  }
  if (receipt.status === 'success' && failedTerminalStage) {
    problems.push(`${prefix} cannot succeed after a failed terminal stage`);
  }
  if (receipt.status === 'success') {
    problems.push(...operationReceiptSuccessSemanticProblems({
      attempt,
      stageEvents: stages,
      receipt,
      artifactReceipts: input.artifactReceipts,
      artifactObservations: input.artifactObservations,
      artifactMembershipPolicy,
    }));
  }
  return problems;
}

export function operationReceiptStagePrefixSemanticProblems(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
}): string[] {
  return operationReceiptStagePrefixState(input).problems;
}

export function assertOperationReceiptStagePrefix(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
}): void {
  const problems = operationReceiptStagePrefixSemanticProblems(input);
  if (problems.length > 0) {
    throw new Error(
      `Refresh operation stage prefix semantic validation failed: ${problems.join('; ')}`,
    );
  }
}

function operationReceiptStagePrefixState(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
}): {
  activeStages: Map<string, OperationStageEventLedgerRow>;
  failedTerminalStage: boolean;
  previousOccurredAtMs: number;
  problems: string[];
  stages: OperationStageEventLedgerRow[];
} {
  const { attempt } = input;
  const runPrefix = `operation run ${JSON.stringify(attempt.run_id)}`;
  const problems: string[] = [];
  const stages = input.stageEvents.slice();
  const attemptStartedAtMs = Date.parse(attempt.started_at);
  const activeStages = new Map<string, OperationStageEventLedgerRow>();
  let previousOccurredAtMs = attemptStartedAtMs;
  let failedTerminalStage = false;

  if (!Number.isFinite(attemptStartedAtMs)) {
    problems.push(`${runPrefix} has an invalid start time`);
  }
  for (const [index, stage] of stages.entries()) {
    const stagePrefix = `${runPrefix} stage sequence ${stage.sequence}`;
    const occurredAtMs = Date.parse(stage.occurred_at);
    if (failedTerminalStage) {
      problems.push(`${stagePrefix} occurs after a failed terminal stage`);
    }
    if (stage.run_id !== attempt.run_id) {
      problems.push(`${stagePrefix} belongs to a different run`);
    }
    if (stage.sequence !== index + 1) {
      problems.push(`${runPrefix} stage chronology is incomplete at sequence ${stage.sequence}`);
    }
    if (!stage.stage.trim()) {
      problems.push(`${stagePrefix} has an empty stage name`);
    }
    if (!Number.isFinite(occurredAtMs)) {
      problems.push(`${stagePrefix} has an invalid time`);
    } else {
      if (Number.isFinite(attemptStartedAtMs) && occurredAtMs < attemptStartedAtMs) {
        problems.push(`${stagePrefix} predates its attempt`);
      }
      if (Number.isFinite(previousOccurredAtMs) && occurredAtMs < previousOccurredAtMs) {
        problems.push(`${runPrefix} stage timestamps are not nondecreasing`);
      }
      previousOccurredAtMs = occurredAtMs;
    }

    if (stage.status === 'started') {
      if (stage.duration_ms != null) {
        problems.push(`${stagePrefix} started event must omit duration`);
      }
      if (activeStages.has(stage.stage)) {
        problems.push(`${stagePrefix} starts active stage ${JSON.stringify(stage.stage)} twice`);
      } else {
        activeStages.set(stage.stage, stage);
      }
      continue;
    }
    if (stage.status !== 'completed' && stage.status !== 'failed') {
      problems.push(`${stagePrefix} has invalid status ${JSON.stringify(stage.status)}`);
      continue;
    }
    if (
      stage.duration_ms == null ||
      !Number.isInteger(stage.duration_ms) ||
      stage.duration_ms < 0
    ) {
      problems.push(`${stagePrefix} terminal event requires a non-negative integer duration`);
    }
    const started = activeStages.get(stage.stage);
    if (!started) {
      problems.push(`${stagePrefix} closes inactive stage ${JSON.stringify(stage.stage)}`);
    } else {
      const startedAtMs = Date.parse(started.occurred_at);
      if (
        Number.isFinite(startedAtMs) &&
        Number.isFinite(occurredAtMs) &&
        Number.isInteger(stage.duration_ms) &&
        stage.duration_ms !== occurredAtMs - startedAtMs
      ) {
        problems.push(
          `${stagePrefix} duration does not match its started/completed timestamps`,
        );
      }
      activeStages.delete(stage.stage);
    }
    if (stage.status === 'failed') failedTerminalStage = true;
  }

  return {
    activeStages,
    failedTerminalStage,
    previousOccurredAtMs,
    problems,
    stages,
  };
}

export function operationReceiptTerminalSemanticProblems(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
  receipt: OperationCaptureReceiptLedgerRow;
  artifactReceipts?: readonly OperationArtifactReceiptLedgerRow[];
  artifactObservations?: readonly OperationArtifactObservationLedgerRow[];
  artifactMembershipPolicy?: OperationArtifactMembershipPolicy;
}): string[] {
  return operationReceiptSemanticProblems(input);
}

function operationReceiptSuccessSemanticProblems(input: {
  attempt: OperationAttemptLedgerRow;
  stageEvents: OperationStageEventLedgerRow[];
  receipt: OperationCaptureReceiptLedgerRow;
  artifactReceipts?: readonly OperationArtifactReceiptLedgerRow[];
  artifactObservations?: readonly OperationArtifactObservationLedgerRow[];
  artifactMembershipPolicy: OperationArtifactMembershipPolicy;
}): string[] {
  const { attempt, receipt } = input;
  const prefix = `capture receipt ${JSON.stringify(receipt.receipt_id)}`;
  const problems: string[] = [];
  const stages = input.stageEvents;
  const publicationStages = stages.filter((stage) =>
    stage.stage === 'score.persist' || stage.stage === 'forecast.capture');
  const expected = [
    ['score.persist', 'started'],
    ['score.persist', 'completed'],
    ['forecast.capture', 'started'],
    ['forecast.capture', 'completed'],
  ];
  const actual = publicationStages.map((stage) => [stage.stage, stage.status]);
  const finalStages = stages.slice(-expected.length)
    .map((stage) => [stage.stage, stage.status]);
  if (
    canonicalJson(actual) !== canonicalJson(expected) ||
    canonicalJson(finalStages) !== canonicalJson(expected)
  ) {
    problems.push(
      `${prefix} successful refresh requires score.persist then forecast.capture start/completion`,
    );
    return problems;
  }
  const scoreCompleted = publicationStages[1];
  const forecastCompleted = publicationStages[3];
  const terminalStage = stages.at(-1);
  if (
    terminalStage?.event_id !== forecastCompleted.event_id ||
    receipt.finished_at !== forecastCompleted.occurred_at
  ) {
    problems.push(
      `${prefix} successful refresh publication must terminate on forecast.capture completion`,
    );
  }
  const payload = parseJsonObject(receipt.payload_json);
  if (!payload) return [...problems, `${prefix} success payload must be an object`];
  if (
    payload.schemaVersion !== 1 &&
    payload.schemaVersion !== 2 &&
    payload.schemaVersion !== 3
  ) {
    problems.push(`${prefix} success payload schema is unsupported`);
  }
  if (payload.operation !== attempt.operation || payload.trigger !== attempt.trigger) {
    problems.push(`${prefix} operation/trigger does not match its attempt`);
  }
  const scoreHistory = asRecord(payload.scoreHistory);
  const scoreAuthority = asRecord(payload.scoreAuthority);
  const scoreCommit = asRecord(payload.scoreCommit);
  const scoreDetails = parseNullableJsonObject(scoreCompleted.details_json);
  const historyRunId = nonEmptyString(scoreHistory?.runId);
  const historyContentHash = nonEmptyString(scoreHistory?.contentHash);
  const authorityRunId = nonEmptyString(scoreAuthority?.runId);
  const authorityContentHash = nonEmptyString(scoreAuthority?.contentHash);
  const historyV2SealContentHash = nonEmptyString(
    scoreAuthority?.historyV2SealContentHash,
  );
  const commitHistoryRunId = nonEmptyString(scoreCommit?.historyRunId);
  const commitHistoryContentHash = nonEmptyString(scoreCommit?.historyRunContentHash);
  const commitAuthorityRunId = nonEmptyString(scoreCommit?.authorityRunId);
  const commitAuthorityContentHash = nonEmptyString(
    scoreCommit?.authorityRunContentHash,
  );
  const commitHistoryV2SealContentHash = nonEmptyString(
    scoreCommit?.historyV2SealContentHash,
  );
  const commitNotBefore = timestampString(scoreCommit?.commitNotBefore);
  const commitNotAfter = timestampString(scoreCommit?.commitNotAfter);
  if (
    !scoreHistory ||
    !scoreAuthority ||
    !scoreCommit ||
    !scoreDetails ||
    !historyRunId ||
    !historyContentHash ||
    !isSha256(historyContentHash) ||
    !authorityRunId ||
    !authorityContentHash ||
    !isSha256(authorityContentHash) ||
    !historyV2SealContentHash ||
    !isSha256(historyV2SealContentHash) ||
    commitHistoryRunId !== historyRunId ||
    commitHistoryContentHash !== historyContentHash ||
    commitAuthorityRunId !== authorityRunId ||
    commitAuthorityContentHash !== authorityContentHash ||
    commitHistoryV2SealContentHash !== historyV2SealContentHash ||
    !commitNotBefore ||
    !commitNotAfter ||
    Date.parse(commitNotAfter) < Date.parse(commitNotBefore) ||
    scoreDetails.historyRunId !== historyRunId ||
    scoreDetails.historyRunContentHash !== historyContentHash ||
    scoreDetails.authorityRunId !== authorityRunId ||
    scoreDetails.authorityRunContentHash !== authorityContentHash ||
    scoreDetails.historyV2SealContentHash !== historyV2SealContentHash ||
    scoreDetails.commitNotBefore !== commitNotBefore ||
    scoreDetails.commitNotAfter !== commitNotAfter
  ) {
    problems.push(`${prefix} score.persist completion does not bind the durable score commit`);
  }
  const releaseTags = Array.isArray(payload.releaseTags)
    ? payload.releaseTags.filter((value) => typeof value === 'string')
    : [];
  const scoreCounts = parseNullableJsonObject(scoreCompleted.counts_json);
  if (Number(scoreCounts?.scoredReleases) !== releaseTags.length || releaseTags.length === 0) {
    problems.push(`${prefix} score.persist count does not match receipt release tags`);
  }
  if (payload.schemaVersion === 2 || payload.schemaVersion === 3) {
    const releaseArtifacts = asRecord(payload.releaseArtifacts);
    const artifactLinks = Array.isArray(releaseArtifacts?.links)
      ? releaseArtifacts.links
      : null;
    if (
      !releaseArtifacts ||
      releaseArtifacts.schemaVersion !== 1 ||
      !artifactLinks ||
      !Number.isInteger(releaseArtifacts.linkCount) ||
      releaseArtifacts.linkCount !== artifactLinks.length ||
      typeof releaseArtifacts.contentDigest !== 'string' ||
      !isSha256(releaseArtifacts.contentDigest)
    ) {
      problems.push(
        `${prefix} release artifact publication shape is invalid`,
      );
    } else if (
      payload.schemaVersion === 2 &&
      artifactLinks.length !== releaseTags.length
    ) {
      problems.push(
        `${prefix} legacy release artifact publication does not match score releases`,
      );
    } else if (payload.schemaVersion === 3) {
      const scopeProblems = releaseArtifactPublicationScopeProblems(
        payload.releaseArtifactScope,
      );
      const scoreMetadata = asRecord(payload.scoreMetadata);
      const metadataReleaseTags = strictStringArray(scoreMetadata?.releaseTags);
      const predecessorByReleaseTag = asRecord(
        scoreMetadata?.predecessorByReleaseTag,
      );
      if (
        !metadataReleaseTags ||
        !sameStringSet(metadataReleaseTags, releaseTags) ||
        !predecessorByReleaseTag
      ) {
        scopeProblems.push(
          'release artifact scope has no matching durable score metadata',
        );
      } else {
        scopeProblems.push(...releaseArtifactPublicationScopeScoreProblems(
          payload.releaseArtifactScope,
          {
            scoredReleaseTags: releaseTags,
            predecessorByReleaseTag:
              predecessorByReleaseTag as Record<string, string | null>,
          },
        ));
      }
      scopeProblems.push(...releaseArtifactPublicationScopeLinkProblems(
        releaseArtifacts,
        payload.releaseArtifactScope,
      ));
      if (scopeProblems.length > 0) {
        problems.push(
          `${prefix} release artifact publication scope is invalid: ` +
          `${[...new Set(scopeProblems)].join('; ')}`,
        );
      }
    }
  }
  if (
    (payload.schemaVersion === 2 || payload.schemaVersion === 3) &&
    (
      input.artifactMembershipPolicy === 'strict' ||
      input.artifactReceipts !== undefined ||
      input.artifactObservations !== undefined
    )
  ) {
    if (
      input.artifactReceipts === undefined ||
      input.artifactObservations === undefined
    ) {
      problems.push(
        `${prefix} artifact publication semantic validation requires both ` +
        'receipt and observation ledger rows',
      );
    } else {
      problems.push(...operationReceiptArtifactPublicationSemanticProblems({
        receipt,
        artifactReceipts: input.artifactReceipts,
        artifactObservations: input.artifactObservations,
      }));
    }
  }
  const forecastState = receiptForecastState(payload.forecast);
  const forecastDetails = parseNullableJsonObject(forecastCompleted.details_json);
  const forecastCounts = parseNullableJsonObject(forecastCompleted.counts_json);
  if (
    forecastState.problems.length > 0 ||
    forecastDetails?.eligibilityOutcome !== forecastState.eligibilityOutcome ||
    Number(forecastCounts?.validationForecasts) !== forecastState.captures.length
  ) {
    problems.push(`${prefix} forecast.capture completion does not match receipt forecast output`);
  }
  return problems;
}

function normalizedArtifactMembershipPolicy(
  value: unknown,
  problems: string[],
  prefix: string,
): OperationArtifactMembershipPolicy {
  if (value === undefined || value === 'if-present') return 'if-present';
  if (value === 'strict') return 'strict';
  problems.push(
    `${prefix} has unsupported artifact membership policy ${JSON.stringify(value)}`,
  );
  return 'strict';
}

type CanonicalOperationArtifactPublicationLink = {
  release: OperationArtifactReceiptLedgerRow['release'];
  observationId: string;
  observationContentHash: string;
  receiptId: string;
  receiptContentHash: string;
  evidenceIdentity: string;
  evidenceReportIdentity: string;
};

export function operationReceiptArtifactPublicationSemanticProblems(input: {
  receipt: OperationCaptureReceiptLedgerRow;
  artifactReceipts: readonly OperationArtifactReceiptLedgerRow[];
  artifactObservations: readonly OperationArtifactObservationLedgerRow[];
}): string[] {
  const prefix = `capture receipt ${JSON.stringify(input.receipt.receipt_id)}`;
  const payload = parseJsonObject(input.receipt.payload_json);
  if (!payload) return [`${prefix} success payload must be an object`];
  if (payload.schemaVersion !== 2 && payload.schemaVersion !== 3) return [];

  const publication = asRecord(payload.releaseArtifacts);
  if (!publication) {
    return [`${prefix} release artifact publication must be an object`];
  }

  const problems: string[] = [];
  if (!sameRecordKeys(
    publication,
    ['schemaVersion', 'linkCount', 'links', 'contentDigest'],
  )) {
    problems.push(`${prefix} release artifact publication keys are not canonical`);
  }
  if (publication.schemaVersion !== 1) {
    problems.push(`${prefix} release artifact publication schema is invalid`);
  }

  const rawLinks = Array.isArray(publication.links) ? publication.links : null;
  if (!rawLinks) {
    problems.push(`${prefix} release artifact publication links must be an array`);
    return [...new Set(problems)];
  }
  if (
    !Number.isInteger(publication.linkCount) ||
    publication.linkCount !== rawLinks.length
  ) {
    problems.push(`${prefix} release artifact publication link count does not match`);
  }

  const links: CanonicalOperationArtifactPublicationLink[] = [];
  for (const [index, value] of rawLinks.entries()) {
    const link = canonicalOperationArtifactPublicationLink(
      value,
      `${prefix} release artifact publication link ${index}`,
      problems,
    );
    if (link) links.push(link);
  }

  if (new Set(links.map((link) => link.observationId)).size !== links.length) {
    problems.push(`${prefix} release artifact publication has duplicate observation IDs`);
  }
  if (new Set(links.map((link) => link.receiptId)).size !== links.length) {
    problems.push(`${prefix} release artifact publication has duplicate receipt IDs`);
  }
  if (new Set(links.map((link) => link.release.tag)).size !== links.length) {
    problems.push(`${prefix} release artifact publication has duplicate release tags`);
  }

  const allLinksCanonical = links.length === rawLinks.length;
  const canonicalLinks = links.slice().sort(compareOperationArtifactPublicationLinks);
  if (
    allLinksCanonical &&
    canonicalJson(links) !== canonicalJson(canonicalLinks)
  ) {
    problems.push(`${prefix} release artifact publication links are not in canonical order`);
  }
  if (
    typeof publication.contentDigest !== 'string' ||
    !isSha256(publication.contentDigest)
  ) {
    problems.push(`${prefix} release artifact publication digest is invalid`);
  } else if (
    allLinksCanonical &&
    publication.contentDigest !==
      operationArtifactPublicationDigest(canonicalLinks)
  ) {
    problems.push(
      `${prefix} release artifact publication digest does not match canonical links`,
    );
  }

  const receiptRowsById = groupOperationArtifactRows(
    input.artifactReceipts,
    (row) => row.receiptId,
  );
  for (const [receiptId, rows] of receiptRowsById) {
    if (rows.length > 1) {
      problems.push(
        `${prefix} supplied artifact receipt ledger has duplicate receipt ID ` +
        JSON.stringify(receiptId),
      );
    }
    for (const row of rows) {
      canonicalOperationArtifactRelease(
        row.release,
        `${prefix} artifact receipt ${JSON.stringify(row.receiptId)} release`,
        problems,
      );
      if (!/^artifact-receipt-v2:[0-9a-f]{64}$/.test(row.receiptId)) {
        problems.push(
          `${prefix} artifact receipt ledger ID ${JSON.stringify(row.receiptId)} ` +
          'is malformed',
        );
      }
      if (!isSha256(row.evidenceIdentity)) {
        problems.push(
          `${prefix} artifact receipt ${JSON.stringify(row.receiptId)} ` +
          'evidence identity is malformed',
        );
      } else if (row.receiptId !== `artifact-receipt-v2:${row.evidenceIdentity}`) {
        problems.push(
          `${prefix} artifact receipt ${JSON.stringify(row.receiptId)} ` +
          'ID does not match its evidence identity',
        );
      }
      if (!isSha256(row.contentHash)) {
        problems.push(
          `${prefix} artifact receipt ${JSON.stringify(row.receiptId)} ` +
          'stored content hash is malformed',
        );
      }
      if (!/^release-evidence-v1:sha256:[0-9a-f]{64}$/.test(
        row.evidenceReportIdentity,
      )) {
        problems.push(
          `${prefix} artifact receipt ${JSON.stringify(row.receiptId)} ` +
          'evidence report identity is malformed',
        );
      }
    }
  }

  const observationRowsById = groupOperationArtifactRows(
    input.artifactObservations,
    (row) => row.observationId,
  );
  for (const [observationId, rows] of observationRowsById) {
    if (rows.length > 1) {
      problems.push(
        `${prefix} supplied artifact observation ledger has duplicate observation ID ` +
        JSON.stringify(observationId),
      );
    }
    for (const row of rows) {
      canonicalOperationArtifactRelease(
        row.release,
        `${prefix} artifact observation ${JSON.stringify(row.observationId)} release`,
        problems,
      );
      if (!/^artifact-observation-v1:[0-9a-f]{64}$/.test(row.observationId)) {
        problems.push(
          `${prefix} artifact observation ledger ID ` +
          `${JSON.stringify(row.observationId)} is malformed`,
        );
      }
      if (!isCanonicalString(row.runId)) {
        problems.push(
          `${prefix} artifact observation ${JSON.stringify(row.observationId)} ` +
          'run ID is malformed',
        );
      }
      if (!/^artifact-receipt-v2:[0-9a-f]{64}$/.test(row.receiptId)) {
        problems.push(
          `${prefix} artifact observation ${JSON.stringify(row.observationId)} ` +
          'receipt ID is malformed',
        );
      }
      if (!isSha256(row.receiptContentHash)) {
        problems.push(
          `${prefix} artifact observation ${JSON.stringify(row.observationId)} ` +
          'stored receipt hash is malformed',
        );
      }
      if (!isSha256(row.contentHash)) {
        problems.push(
          `${prefix} artifact observation ${JSON.stringify(row.observationId)} ` +
          'stored content hash is malformed',
        );
      }
    }
  }

  const expectedLinkByObservationId = new Map<
    string,
    CanonicalOperationArtifactPublicationLink
  >();
  for (const [observationId, rows] of observationRowsById) {
    if (rows.length !== 1) continue;
    const observation = rows[0];
    const matchingReceipts = receiptRowsById.get(observation.receiptId) ?? [];
    if (matchingReceipts.length !== 1) {
      problems.push(
        matchingReceipts.length === 0
          ? `${prefix} artifact observation ${JSON.stringify(observationId)} ` +
            'references a missing immutable receipt'
          : `${prefix} artifact observation ${JSON.stringify(observationId)} ` +
            'references a duplicate immutable receipt ID',
      );
      continue;
    }
    const receipt = matchingReceipts[0];
    if (observation.receiptContentHash !== receipt.contentHash) {
      problems.push(
        `${prefix} artifact observation ${JSON.stringify(observationId)} ` +
        'stored receipt hash does not match its immutable receipt',
      );
    }
    if (canonicalJson(observation.release) !== canonicalJson(receipt.release)) {
      problems.push(
        `${prefix} artifact observation ${JSON.stringify(observationId)} ` +
        'release identity does not match its immutable receipt',
      );
    }
    expectedLinkByObservationId.set(observationId, {
      release: receipt.release,
      observationId,
      observationContentHash: observation.contentHash,
      receiptId: receipt.receiptId,
      receiptContentHash: receipt.contentHash,
      evidenceIdentity: receipt.evidenceIdentity,
      evidenceReportIdentity: receipt.evidenceReportIdentity,
    });
  }

  const runObservations = input.artifactObservations.filter(
    (row) => row.runId === input.receipt.run_id,
  );
  if (
    new Set(runObservations.map((row) => row.release.tag)).size !==
      runObservations.length
  ) {
    problems.push(
      `${prefix} supplied artifact observation ledger has duplicate release tags ` +
      `for run ${JSON.stringify(input.receipt.run_id)}`,
    );
  }
  if (
    new Set(runObservations.map((row) => row.receiptId)).size !==
      runObservations.length
  ) {
    problems.push(
      `${prefix} supplied artifact observation ledger has duplicate receipt IDs ` +
      `for run ${JSON.stringify(input.receipt.run_id)}`,
    );
  }

  const expectedObservationIds = new Set(
    runObservations.map((row) => row.observationId),
  );
  const actualObservationIds = new Set(links.map((link) => link.observationId));
  const missingObservationIds = [...expectedObservationIds]
    .filter((observationId) => !actualObservationIds.has(observationId))
    .sort();
  const extraObservationIds = [...actualObservationIds]
    .filter((observationId) => !expectedObservationIds.has(observationId))
    .sort();
  if (missingObservationIds.length > 0) {
    problems.push(
      `${prefix} release artifact publication is missing immutable observation ` +
      `membership: ${
        missingObservationIds.map((value) => JSON.stringify(value)).join(', ')
      }`,
    );
  }
  if (extraObservationIds.length > 0) {
    problems.push(
      `${prefix} release artifact publication has extra immutable observation ` +
      `membership: ${
        extraObservationIds.map((value) => JSON.stringify(value)).join(', ')
      }`,
    );
  }

  for (const link of links) {
    const matchingObservations =
      observationRowsById.get(link.observationId) ?? [];
    if (matchingObservations.length === 0) {
      problems.push(
        `${prefix} release artifact publication link ` +
        `${JSON.stringify(link.observationId)} has no supplied immutable observation`,
      );
      continue;
    }
    if (matchingObservations.length !== 1) continue;
    const observation = matchingObservations[0];
    if (observation.runId !== input.receipt.run_id) {
      problems.push(
        `${prefix} release artifact publication link ` +
        `${JSON.stringify(link.observationId)} belongs to run ` +
        `${JSON.stringify(observation.runId)}, not ` +
        JSON.stringify(input.receipt.run_id),
      );
    }
    const expectedLink = expectedLinkByObservationId.get(link.observationId);
    if (!expectedLink) continue;
    const mismatches = operationArtifactPublicationLinkMismatches(
      link,
      expectedLink,
    );
    if (mismatches.length > 0) {
      problems.push(
        `${prefix} release artifact publication link ` +
        `${JSON.stringify(link.observationId)} is substituted: ` +
        `${mismatches.join(', ')} do not match immutable ledger rows`,
      );
    }
  }

  return [...new Set(problems)];
}

export function verifyOperationReceiptSemanticLinks(input: {
  attempts: OperationAttemptLedgerRow[];
  receipts: OperationCaptureReceiptLedgerRow[];
  historyRows: OperationHistoryRow[];
  historyRuns: OperationHistoryRunLinkRow[];
  forecasts: OperationForecastLinkRow[];
  authorityRuns: OperationAuthorityRunLinkRow[];
  historyV2Seals: OperationHistoryV2SealLinkRow[];
  validationProof?: ReleaseValidationProofBundle;
}): OperationReceiptSemanticLinkVerification {
  const problems: string[] = [];
  const attemptsByRun = new Map(input.attempts.map((attempt) => [attempt.run_id, attempt]));
  const historyRunsById = groupBy(input.historyRuns, (run) => run.run_id);
  const historyRowsByRun = groupBy(input.historyRows, (row) => row.run_id);
  const forecastsByDecision = groupBy(input.forecasts, (forecast) => forecast.decision_id);
  const authorityRunsById = groupBy(
    input.authorityRuns,
    (run) => run.authorityRunId,
  );
  const historyV2SealsByRun = groupBy(
    input.historyV2Seals,
    (seal) => seal.historyRunId,
  );
  const validationProof = input.validationProof ?? emptyValidationProofBundle();
  const validationProofVerification =
    verifyReleaseValidationProofBundle(validationProof);
  if (!validationProofVerification.valid) {
    problems.push(
      `release validation proof ledger is invalid: ` +
      validationProofVerification.problems.join('; '),
    );
  }
  for (const receipt of input.receipts) {
    const attempt = attemptsByRun.get(receipt.run_id);
    if (receipt.status !== 'success') continue;
    const prefix = `capture receipt ${JSON.stringify(receipt.receipt_id)}`;
    if (!attempt) {
      problems.push(`${prefix} does not reference a refresh operation attempt`);
      continue;
    }
    const payload = parseJsonObject(receipt.payload_json);
    if (!payload) {
      problems.push(`${prefix} success payload must be an object`);
      continue;
    }
    const scoreHistory = asRecord(payload.scoreHistory);
    const scoreAuthority = asRecord(payload.scoreAuthority);
    const scoreCommit = asRecord(payload.scoreCommit);
    const historyRunId = nonEmptyString(scoreHistory?.runId);
    const historyContentHash = nonEmptyString(scoreHistory?.contentHash);
    const authorityRunId = nonEmptyString(scoreAuthority?.runId);
    const authorityContentHash = nonEmptyString(scoreAuthority?.contentHash);
    const historyV2SealContentHash = nonEmptyString(
      scoreAuthority?.historyV2SealContentHash,
    );
    const commitHistoryRunId = nonEmptyString(scoreCommit?.historyRunId);
    const commitHistoryContentHash = nonEmptyString(scoreCommit?.historyRunContentHash);
    const commitAuthorityRunId = nonEmptyString(scoreCommit?.authorityRunId);
    const commitAuthorityContentHash = nonEmptyString(
      scoreCommit?.authorityRunContentHash,
    );
    const commitHistoryV2SealContentHash = nonEmptyString(
      scoreCommit?.historyV2SealContentHash,
    );
    const commitNotBefore = timestampString(scoreCommit?.commitNotBefore);
    const commitNotAfter = timestampString(scoreCommit?.commitNotAfter);
    const historyRunMatches = historyRunId
      ? (historyRunsById.get(historyRunId) ?? [])
      : [];
    const historyRun = uniqueLinkedRow(historyRunMatches);
    if (
      !historyRunId ||
      !historyContentHash ||
      !isSha256(historyContentHash) ||
      !historyRun
    ) {
      problems.push(
        historyRunMatches.length > 1
          ? `${prefix} has conflicting score history seals`
          : `${prefix} has a dangling score history link`,
      );
    } else if (historyRun.content_hash !== historyContentHash) {
      problems.push(`${prefix} score history link hash does not match`);
    }
    if (
      !scoreCommit ||
      !scoreAuthority ||
      !authorityRunId ||
      !authorityContentHash ||
      !isSha256(authorityContentHash) ||
      !historyV2SealContentHash ||
      !isSha256(historyV2SealContentHash) ||
      commitHistoryRunId !== historyRunId ||
      commitHistoryContentHash !== historyContentHash ||
      commitAuthorityRunId !== authorityRunId ||
      commitAuthorityContentHash !== authorityContentHash ||
      commitHistoryV2SealContentHash !== historyV2SealContentHash ||
      !commitNotBefore ||
      !commitNotAfter ||
      Date.parse(commitNotAfter) < Date.parse(commitNotBefore)
    ) {
      problems.push(`${prefix} has malformed or conflicting score history aliases`);
    }
    if (historyRunId) {
      for (const problem of linkedHistoryRunProblems({
        runId: historyRunId,
        historyRowsByRun,
        historyRunsById,
      })) {
        problems.push(`${prefix} current score history ${problem}`);
      }
    }
    const currentHistoryRows = historyRunId
      ? (historyRowsByRun.get(historyRunId) ?? [])
      : [];
    if (
      !authorityRunId ||
      currentHistoryRows.some((row) => row.authority_run_id !== authorityRunId)
    ) {
      problems.push(
        `${prefix} current score history does not reference the receipt authority run`,
      );
    }
    const currentAuthorityRun = authorityRunId
      ? uniqueLinkedRow(authorityRunsById.get(authorityRunId) ?? [])
      : null;
    const currentHistoryV2Seal = historyRunId
      ? uniqueLinkedRow(historyV2SealsByRun.get(historyRunId) ?? [])
      : null;
    if (
      !currentAuthorityRun ||
      currentAuthorityRun.contentHash !== authorityContentHash ||
      !currentHistoryV2Seal ||
      currentHistoryV2Seal.authorityRunId !== authorityRunId ||
      currentHistoryV2Seal.contentHash !== historyV2SealContentHash
    ) {
      problems.push(
        `${prefix} score authority link does not match durable authority evidence`,
      );
    }
    const releaseTags = strictStringArray(payload.releaseTags);
    if (
      !releaseTags ||
      !sameStringSet(
        releaseTags,
        currentHistoryRows.map((row) => row.release_tag),
      )
    ) {
      problems.push(`${prefix} release tags do not exactly match current score history`);
    }
    if (payload.schemaVersion === 3) {
      const historyScope = artifactScopeFromHistoryRows(currentHistoryRows);
      for (const problem of historyScope.problems) {
        problems.push(`${prefix} ${problem}`);
      }
      if (releaseTags && historyScope.problems.length === 0) {
        for (const problem of releaseArtifactPublicationScopeScoreProblems(
          payload.releaseArtifactScope,
          {
            scoredReleaseTags: releaseTags,
            predecessorByReleaseTag: historyScope.predecessorByReleaseTag,
          },
        )) {
          problems.push(`${prefix} ${problem}`);
        }
      }
      for (const problem of releaseArtifactPublicationScopeLinkProblems(
        payload.releaseArtifacts,
        payload.releaseArtifactScope,
      )) {
        problems.push(`${prefix} ${problem}`);
      }
    }
    if (
      historyRun &&
      (
        !commitNotBefore ||
        !commitNotAfter ||
        Date.parse(historyRun.recorded_at) > Date.parse(commitNotAfter) ||
        Date.parse(historyRun.recorded_at) > Date.parse(receipt.finished_at)
      )
    ) {
      problems.push(`${prefix} current score history link is chronologically invalid`);
    }

    const forecastState = receiptForecastState(payload.forecast);
    for (const problem of forecastState.problems) {
      problems.push(`${prefix} ${problem}`);
    }
    if (
      Number.isInteger(payload.schemaVersion) &&
      Number(payload.schemaVersion) >= 2 &&
      !forecastState.canonicalFieldsDeclared
    ) {
      problems.push(
        `${prefix} schema-v2 forecast output omits canonical forecast proof links`,
      );
    }
    const capturesByDecision = new Map(
      forecastState.captures.map((capture) => [capture.decisionId, capture]),
    );
    for (const decisionId of forecastState.decisionIds) {
      const rows = forecastsByDecision.get(decisionId) ?? [];
      const row = uniqueLinkedRow(rows);
      const capture = capturesByDecision.get(decisionId);
      if (!row) {
        problems.push(
          rows.length > 1
            ? `${prefix} has conflicting forecast link ${JSON.stringify(decisionId)}`
            : `${prefix} has dangling forecast link ${JSON.stringify(decisionId)}`,
        );
        continue;
      }
      const originalRunId = nonEmptyString(row.audit_history_run_id);
      const originalRunMatches = originalRunId
        ? (historyRunsById.get(originalRunId) ?? [])
        : [];
      const originalRun = uniqueLinkedRow(originalRunMatches);
      const originalHistoryRows = originalRunId
        ? (historyRowsByRun.get(originalRunId) ?? [])
        : [];
      if (!originalRunId || !originalRun) {
        problems.push(
          originalRunMatches.length > 1
            ? `${prefix} forecast link ${JSON.stringify(decisionId)} ` +
              `has conflicting original score run seals`
            : `${prefix} forecast link ${JSON.stringify(decisionId)} ` +
              `does not reference its original sealed score run`,
        );
        continue;
      }
      for (const problem of linkedHistoryRunProblems({
        runId: originalRunId,
        historyRowsByRun,
        historyRunsById,
      })) {
        problems.push(
          `${prefix} forecast link ${JSON.stringify(decisionId)} original score history ${problem}`,
        );
      }
      if (
        releaseValidationForecastContentHash(row) !== row.content_hash ||
        releaseValidationDecisionId(row, row.content_hash) !== row.decision_id
      ) {
        problems.push(`${prefix} forecast link ${JSON.stringify(decisionId)} has invalid identity`);
      }
      const originalAuthorityRunIds = new Set(
        originalHistoryRows.map((historyRow) => historyRow.authority_run_id),
      );
      const originalAuthorityRunId =
        originalAuthorityRunIds.size === 1 &&
          typeof [...originalAuthorityRunIds][0] === 'string'
          ? [...originalAuthorityRunIds][0] as string
          : null;
      const originalAuthorityRun = originalAuthorityRunId
        ? uniqueLinkedRow(authorityRunsById.get(originalAuthorityRunId) ?? [])
        : null;
      const originalHistoryV2Seal = uniqueLinkedRow(
        historyV2SealsByRun.get(originalRunId) ?? [],
      );
      if (
        !originalAuthorityRun ||
        !originalHistoryV2Seal ||
        originalHistoryV2Seal.authorityRunId !== originalAuthorityRunId
      ) {
        problems.push(
          `${prefix} forecast link ${JSON.stringify(decisionId)} ` +
          'does not reference durable authority evidence',
        );
      }
      for (const problem of validateReleaseValidationForecastProvenance(
        [row],
        originalHistoryRows,
        [originalRun],
        originalAuthorityRun ? [originalAuthorityRun] : [],
        originalHistoryV2Seal ? [originalHistoryV2Seal] : [],
      )) {
        problems.push(`${prefix} ${problem}`);
      }
      const forecastRecordedAtMs = Date.parse(row.recorded_at);
      const originalRecordedAtMs = Date.parse(originalRun.recorded_at);
      const currentRecordedAtMs = Date.parse(historyRun?.recorded_at ?? '');
      if (
        !Number.isFinite(forecastRecordedAtMs) ||
        !Number.isFinite(originalRecordedAtMs) ||
        forecastRecordedAtMs < originalRecordedAtMs ||
        forecastRecordedAtMs > Date.parse(receipt.finished_at)
      ) {
        problems.push(
          `${prefix} forecast link ${JSON.stringify(decisionId)} is chronologically invalid`,
        );
      }
      if (capture?.status === 'already_captured') {
        const sameRunRetry = originalRunId === historyRunId;
        if (
          !historyRun ||
          !Number.isFinite(currentRecordedAtMs) ||
          originalRecordedAtMs > currentRecordedAtMs ||
          (
            !sameRunRetry &&
            commitNotBefore != null &&
            forecastRecordedAtMs > Date.parse(commitNotBefore)
          )
        ) {
          problems.push(
            `${prefix} reused forecast link ${JSON.stringify(decisionId)} ` +
            `is not an earlier capture`,
          );
        }
        if (!historyRowsSemanticallyEquivalent(originalHistoryRows, currentHistoryRows)) {
          problems.push(
            `${prefix} reused forecast link ${JSON.stringify(decisionId)} ` +
            `is not semantically equivalent to current score history`,
          );
        }
        if (
          !originalAuthorityRun ||
          !currentAuthorityRun ||
          !authorityRunsSemanticallyEquivalent(
            originalAuthorityRun,
            currentAuthorityRun,
          )
        ) {
          problems.push(
            `${prefix} reused forecast link ${JSON.stringify(decisionId)} ` +
            'is not semantically equivalent to current score authority',
          );
        }
      } else if (!historyRunId || originalRunId !== historyRunId) {
        problems.push(
          `${prefix} forecast link ${JSON.stringify(decisionId)} targets a different score run`,
        );
      }
    }
    problems.push(...receiptCanonicalForecastLinkProblems({
      prefix,
      state: forecastState,
      validationProof,
      forecastsByDecision,
      historyRunsById,
      authorityRunsById,
      historyV2SealsByRun,
      currentHistoryRunId: historyRunId,
      currentHistoryContentHash: historyContentHash,
      currentAuthorityRunId: authorityRunId,
      currentAuthorityContentHash: authorityContentHash,
      currentHistoryV2SealContentHash: historyV2SealContentHash,
    }));
  }
  return {
    receiptCount: input.receipts.length,
    problems,
  };
}

function receiptCanonicalForecastLinkProblems(input: {
  prefix: string;
  state: ReceiptForecastState;
  validationProof: ReleaseValidationProofBundle;
  forecastsByDecision: Map<string, OperationForecastLinkRow[]>;
  historyRunsById: Map<string, OperationHistoryRunLinkRow[]>;
  authorityRunsById: Map<string, OperationAuthorityRunLinkRow[]>;
  historyV2SealsByRun: Map<string, OperationHistoryV2SealLinkRow[]>;
  currentHistoryRunId: string | null;
  currentHistoryContentHash: string | null;
  currentAuthorityRunId: string | null;
  currentAuthorityContentHash: string | null;
  currentHistoryV2SealContentHash: string | null;
}): string[] {
  if (!input.state.canonicalFieldsDeclared) return [];

  const problems: string[] = [];
  const rowsById = new Map(
    input.validationProof.forecasts.map((row) => [row.forecastId, row]),
  );
  const expectedRows = input.validationProof.forecasts.filter((row) => {
    const link = canonicalForecastLegacyLink(row);
    return link != null && input.state.decisionIds.includes(link.decisionId);
  });
  if (
    !sameStringSet(
      input.state.canonicalForecastIds,
      expectedRows.map((row) => row.forecastId),
    )
  ) {
    problems.push(
      `${input.prefix} canonical forecast links do not exactly match ` +
      `the stored proof ledger`,
    );
  }
  const obligationsById = new Map(
    input.validationProof.obligations.map((row) => [row.obligationId, row]),
  );
  const assignmentsById = new Map(
    input.validationProof.splitAssignments.map((row) => [row.assignmentId, row]),
  );
  const cohortsById = new Map(
    input.validationProof.cohorts.map((row) => [row.cohortId, row]),
  );
  for (const capture of input.state.canonicalCaptures) {
    const row = rowsById.get(capture.forecastId);
    if (!row) {
      problems.push(
        `${input.prefix} has dangling canonical forecast link ` +
        JSON.stringify(capture.forecastId),
      );
      continue;
    }
    const obligation = obligationsById.get(row.obligationId);
    const assignment = assignmentsById.get(row.splitAssignmentId);
    const cohort = cohortsById.get(row.cohortId);
    if (
      row.contentHash !== capture.contentHash ||
      row.obligationId !== capture.obligationId ||
      row.splitAssignmentId !== capture.splitAssignmentId ||
      row.cohortId !== capture.cohortId ||
      !obligation ||
      obligation.opportunityCode !== capture.opportunityCode ||
      obligation.horizonCode !== capture.horizonCode ||
      !assignment ||
      assignment.obligationId !== row.obligationId ||
      !cohort ||
      cohort.policyId !== row.policyId ||
      cohort.policyContentHash !== row.policyContentHash
    ) {
      problems.push(
        `${input.prefix} canonical forecast ${JSON.stringify(row.forecastId)} ` +
        `has a mismatched immutable proof link`,
      );
      continue;
    }
    const link = canonicalForecastLegacyLink(row);
    const legacyRow = uniqueLinkedRow(
      input.forecastsByDecision.get(capture.legacyDecisionId) ?? [],
    );
    if (
      !link ||
      link.decisionId !== capture.legacyDecisionId ||
      link.contentHash !== capture.legacyContentHash ||
      !legacyRow ||
      legacyRow.content_hash !== capture.legacyContentHash
    ) {
      problems.push(
        `${input.prefix} canonical forecast ${JSON.stringify(row.forecastId)} ` +
        `does not bind its exact legacy forecast`,
      );
      continue;
    }
    const publication = link.capturePublication;
    const initialHistoryRunId = nonEmptyString(publication?.historyRunId);
    const initialHistoryContentHash = nonEmptyString(
      publication?.historyRunContentHash,
    );
    const initialAuthorityRunId = nonEmptyString(publication?.authorityRunId);
    const initialAuthorityContentHash = nonEmptyString(
      publication?.authorityRunContentHash,
    );
    const initialHistoryV2SealContentHash = nonEmptyString(
      publication?.historyV2SealContentHash,
    );
    const initialHistory = initialHistoryRunId
      ? uniqueLinkedRow(input.historyRunsById.get(initialHistoryRunId) ?? [])
      : null;
    const initialAuthority = initialAuthorityRunId
      ? uniqueLinkedRow(input.authorityRunsById.get(initialAuthorityRunId) ?? [])
      : null;
    const initialHistoryV2Seal = initialHistoryRunId
      ? uniqueLinkedRow(input.historyV2SealsByRun.get(initialHistoryRunId) ?? [])
      : null;
    if (
      !initialHistory ||
      initialHistory.content_hash !== initialHistoryContentHash ||
      !initialAuthority ||
      initialAuthority.contentHash !== initialAuthorityContentHash ||
      !initialHistoryV2Seal ||
      initialHistoryV2Seal.authorityRunId !== initialAuthorityRunId ||
      initialHistoryV2Seal.contentHash !== initialHistoryV2SealContentHash
    ) {
      problems.push(
        `${input.prefix} canonical forecast ${JSON.stringify(row.forecastId)} ` +
        `does not bind durable initial publication seals`,
      );
      continue;
    }
    const expectedStatus =
      initialHistoryRunId === input.currentHistoryRunId
        ? 'inserted'
        : 'already_captured';
    if (capture.status !== expectedStatus) {
      problems.push(
        `${input.prefix} canonical forecast ${JSON.stringify(row.forecastId)} ` +
        `has an invalid insertion/reuse status`,
      );
    }
    if (
      capture.status === 'inserted' &&
      (
        initialHistoryContentHash !== input.currentHistoryContentHash ||
        initialAuthorityRunId !== input.currentAuthorityRunId ||
        initialAuthorityContentHash !== input.currentAuthorityContentHash ||
        initialHistoryV2SealContentHash !==
          input.currentHistoryV2SealContentHash
      )
    ) {
      problems.push(
        `${input.prefix} newly inserted canonical forecast ` +
        `${JSON.stringify(row.forecastId)} targets a different publication`,
      );
    }
  }
  return problems;
}

function canonicalForecastLegacyLink(row: ReleaseValidationForecastV2): {
  decisionId: string;
  contentHash: string;
  capturePublication: Record<string, unknown> | null;
} | null {
  const payload = asRecord(row.forecast);
  const legacy = asRecord(payload?.legacyForecast);
  const decisionId = nonEmptyString(legacy?.decisionId);
  const contentHash = nonEmptyString(legacy?.contentHash);
  if (!decisionId || !contentHash || !isSha256(contentHash)) return null;
  return {
    decisionId,
    contentHash,
    capturePublication: asRecord(payload?.canonicalCapturePublication),
  };
}

function emptyValidationProofBundle(): ReleaseValidationProofBundle {
  return {
    epochs: [],
    retirements: [],
    policies: [],
    cohorts: [],
    catalogObservations: [],
    catalogMembers: [],
    catalogReconciliations: [],
    catalogReconciliationRows: [],
    obligations: [],
    splitAssignments: [],
    forecasts: [],
    outcomes: [],
    observationBatches: [],
    evaluationReceipts: [],
    promotionReceipts: [],
  };
}

function linkedHistoryRunProblems(input: {
  runId: string;
  historyRowsByRun: Map<string, OperationHistoryRow[]>;
  historyRunsById: Map<string, OperationHistoryRunLinkRow[]>;
}): string[] {
  const problems: string[] = [];
  const seals = input.historyRunsById.get(input.runId) ?? [];
  if (seals.length !== 1) {
    return [
      seals.length === 0
        ? `run ${JSON.stringify(input.runId)} is missing its seal`
        : `run ${JSON.stringify(input.runId)} has conflicting seals`,
    ];
  }
  const seal = seals[0];
  const rows = (input.historyRowsByRun.get(input.runId) ?? [])
    .slice()
    .sort((left, right) => left.release_tag.localeCompare(right.release_tag));
  if (rows.length === 0) {
    problems.push(`run ${JSON.stringify(input.runId)} is missing its history rows`);
  }
  if (
    !Number.isInteger(seal.id) ||
    Number(seal.id) <= 0 ||
    !isTimestamp(seal.recorded_at) ||
    !isSha256(seal.rows_content_hash) ||
    !isSha256(seal.content_hash) ||
    (seal.previous_content_hash != null && !isSha256(seal.previous_content_hash))
  ) {
    problems.push(`run ${JSON.stringify(input.runId)} has a malformed seal`);
  }
  if (
    rows.some((row) =>
      row.run_id !== input.runId ||
      !isTimestamp(row.recorded_at) ||
      !row.release_tag.trim())
  ) {
    problems.push(`run ${JSON.stringify(input.runId)} has malformed or cross-run history rows`);
  }
  if (new Set(rows.map((row) => row.release_tag)).size !== rows.length) {
    problems.push(`run ${JSON.stringify(input.runId)} has duplicate history rows`);
  }
  const recordedAts = new Set(rows.map((row) => row.recorded_at));
  if (recordedAts.size !== 1 || !recordedAts.has(seal.recorded_at)) {
    problems.push(`run ${JSON.stringify(input.runId)} has inconsistent recorded_at values`);
  }
  if (seal.row_count !== rows.length) {
    problems.push(`run ${JSON.stringify(input.runId)} seal row count does not match`);
  }
  const rowsContentHash = releaseScoreAuditHistoryRowsContentHash(
    rows as unknown as Array<Record<string, unknown>>,
  );
  if (seal.rows_content_hash !== rowsContentHash) {
    problems.push(`run ${JSON.stringify(input.runId)} row-set hash does not match its rows`);
  }
  if (
    seal.content_hash !== releaseScoreAuditHistoryRunContentHash({
      runId: seal.run_id,
      recordedAt: seal.recorded_at,
      rowCount: seal.row_count,
      rowsContentHash: seal.rows_content_hash,
      previousContentHash: seal.previous_content_hash,
    })
  ) {
    problems.push(`run ${JSON.stringify(input.runId)} seal hash is invalid`);
  }
  return problems;
}

function historyRowsSemanticallyEquivalent(
  left: OperationHistoryRow[],
  right: OperationHistoryRow[],
): boolean {
  const normalize = (rows: OperationHistoryRow[]) => rows
    .map((row) => ({
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
    }))
    .sort((leftRow, rightRow) =>
      leftRow.release_tag.localeCompare(rightRow.release_tag));
  return canonicalJson(normalize(left)) === canonicalJson(normalize(right));
}

function authorityRunsSemanticallyEquivalent(
  left: OperationAuthorityRunLinkRow,
  right: OperationAuthorityRunLinkRow,
): boolean {
  const normalize = (run: OperationAuthorityRunLinkRow) => ({
    schemaVersion: run.schemaVersion,
    policyVersion: run.policyVersion,
    sourceIdentitySchemaVersion: run.sourceIdentitySchemaVersion,
    sourceIdentityDigest: run.sourceIdentityDigest,
    rows: run.rows
      .map((row) => ({
        releaseTag: row.releaseTag,
        issueNumber: row.issueNumber,
        subjectKind: row.subjectKind,
        subjectIdentity: row.subjectIdentity,
        candidateId: row.candidateId,
        authority: row.authority,
        reason: row.reason,
        authorizedForScoring: row.authorizedForScoring,
        evidenceDigest: row.evidenceDigest,
        resolutionJson: row.resolutionJson,
      }))
      .sort((leftRow, rightRow) =>
        leftRow.subjectKind.localeCompare(rightRow.subjectKind) ||
        leftRow.subjectIdentity.localeCompare(rightRow.subjectIdentity)),
  });
  return canonicalJson(normalize(left)) === canonicalJson(normalize(right));
}

function groupBy<T>(
  rows: T[],
  keyOf: (row: T) => string,
): Map<string, T[]> {
  const grouped = new Map<string, T[]>();
  for (const row of rows) {
    const key = keyOf(row);
    const matches = grouped.get(key) ?? [];
    matches.push(row);
    grouped.set(key, matches);
  }
  return grouped;
}

function uniqueLinkedRow<T>(rows: T[] | undefined): T | null {
  return rows?.length === 1 ? rows[0] : null;
}

function artifactScopeFromHistoryRows(
  rows: OperationHistoryRow[],
): {
  predecessorByReleaseTag: Record<string, string | null>;
  problems: string[];
} {
  const predecessorByReleaseTag: Record<string, string | null> = {};
  const problems: string[] = [];
  for (const row of rows) {
    const gateEvidence = parseJsonObject(row.gate_evidence_json);
    const fixProvenance = asRecord(gateEvidence?.fixProvenance);
    const boundary = asRecord(fixProvenance?.predecessorBoundary);
    const targetTag = nonEmptyString(boundary?.targetTag);
    const predecessorTag = boundary?.predecessorTag;
    if (
      !boundary ||
      targetTag !== row.release_tag ||
      (
        predecessorTag !== null &&
        (
          typeof predecessorTag !== 'string' ||
          !predecessorTag ||
          predecessorTag.trim() !== predecessorTag
        )
      )
    ) {
      problems.push(
        `score history ${JSON.stringify(row.release_tag)} has no valid ` +
        'predecessor-boundary evidence',
      );
      continue;
    }
    predecessorByReleaseTag[row.release_tag] = predecessorTag as string | null;
  }
  if (
    Object.keys(predecessorByReleaseTag).length !== rows.length ||
    new Set(rows.map((row) => row.release_tag)).size !== rows.length
  ) {
    problems.push(
      'score history does not provide one predecessor-boundary row per release',
    );
  }
  return { predecessorByReleaseTag, problems: [...new Set(problems)] };
}

function sameStringSet(left: string[], right: string[]): boolean {
  return left.length === right.length &&
    new Set(left).size === left.length &&
    new Set(right).size === right.length &&
    left.every((value) => right.includes(value));
}

function canonicalOperationArtifactPublicationLink(
  value: unknown,
  label: string,
  problems: string[],
): CanonicalOperationArtifactPublicationLink | null {
  const link = asRecord(value);
  if (!link) {
    problems.push(`${label} must be an object`);
    return null;
  }
  const linkProblems: string[] = [];
  if (!sameRecordKeys(link, [
    'release',
    'observationId',
    'observationContentHash',
    'receiptId',
    'receiptContentHash',
    'evidenceIdentity',
    'evidenceReportIdentity',
  ])) {
    linkProblems.push('keys are not canonical');
  }
  const release = canonicalOperationArtifactRelease(
    link.release,
    `${label} release`,
    linkProblems,
  );
  const observationId = isCanonicalString(link.observationId)
    ? link.observationId
    : null;
  const observationContentHash = isCanonicalString(link.observationContentHash)
    ? link.observationContentHash
    : null;
  const receiptId = isCanonicalString(link.receiptId) ? link.receiptId : null;
  const receiptContentHash = isCanonicalString(link.receiptContentHash)
    ? link.receiptContentHash
    : null;
  const evidenceIdentity = isCanonicalString(link.evidenceIdentity)
    ? link.evidenceIdentity
    : null;
  const evidenceReportIdentity = isCanonicalString(link.evidenceReportIdentity)
    ? link.evidenceReportIdentity
    : null;
  if (!observationId ||
      !/^artifact-observation-v1:[0-9a-f]{64}$/.test(observationId)) {
    linkProblems.push('observation ID is malformed');
  }
  if (!observationContentHash || !isSha256(observationContentHash)) {
    linkProblems.push('observation content hash is malformed');
  }
  if (!receiptId || !/^artifact-receipt-v2:[0-9a-f]{64}$/.test(receiptId)) {
    linkProblems.push('receipt ID is malformed');
  }
  if (!receiptContentHash || !isSha256(receiptContentHash)) {
    linkProblems.push('receipt content hash is malformed');
  }
  if (!evidenceIdentity || !isSha256(evidenceIdentity)) {
    linkProblems.push('evidence identity is malformed');
  } else if (
    receiptId &&
    receiptId !== `artifact-receipt-v2:${evidenceIdentity}`
  ) {
    linkProblems.push('receipt ID does not match evidence identity');
  }
  if (
    !evidenceReportIdentity ||
    !/^release-evidence-v1:sha256:[0-9a-f]{64}$/.test(evidenceReportIdentity)
  ) {
    linkProblems.push('evidence report identity is malformed');
  }
  if (
    !release ||
    !observationId ||
    !observationContentHash ||
    !receiptId ||
    !receiptContentHash ||
    !evidenceIdentity ||
    !evidenceReportIdentity ||
    linkProblems.length > 0
  ) {
    problems.push(`${label} is invalid: ${[...new Set(linkProblems)].join('; ')}`);
    return null;
  }
  return {
    release,
    observationId,
    observationContentHash,
    receiptId,
    receiptContentHash,
    evidenceIdentity,
    evidenceReportIdentity,
  };
}

function canonicalOperationArtifactRelease(
  value: unknown,
  label: string,
  problems: string[],
): OperationArtifactReceiptLedgerRow['release'] | null {
  const release = asRecord(value);
  if (!release) {
    problems.push(`${label} must be an object`);
    return null;
  }
  const releaseProblems: string[] = [];
  if (!sameRecordKeys(release, [
    'repository',
    'tag',
    'releaseNodeId',
    'catalogTagCommitOid',
    'publishedAt',
  ])) {
    releaseProblems.push('keys are not canonical');
  }
  const repository = isCanonicalString(release.repository)
    ? release.repository
    : null;
  const tag = isCanonicalString(release.tag) ? release.tag : null;
  const releaseNodeId = isCanonicalString(release.releaseNodeId)
    ? release.releaseNodeId
    : null;
  const catalogTagCommitOid = isCanonicalString(release.catalogTagCommitOid)
    ? release.catalogTagCommitOid
    : null;
  const publishedAt = isCanonicalString(release.publishedAt)
    ? release.publishedAt
    : null;
  if (!repository || !/^[^/\s]+\/[^/\s]+$/.test(repository)) {
    releaseProblems.push('repository is malformed');
  }
  if (!tag) releaseProblems.push('tag is malformed');
  if (!releaseNodeId) releaseProblems.push('release node ID is malformed');
  if (
    !catalogTagCommitOid ||
    !/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(catalogTagCommitOid)
  ) {
    releaseProblems.push('tag commit OID is malformed');
  }
  if (
    !publishedAt ||
    !Number.isFinite(Date.parse(publishedAt)) ||
    new Date(publishedAt).toISOString() !== publishedAt
  ) {
    releaseProblems.push('publishedAt is not canonical ISO-8601');
  }
  if (
    !repository ||
    !tag ||
    !releaseNodeId ||
    !catalogTagCommitOid ||
    !publishedAt ||
    releaseProblems.length > 0
  ) {
    problems.push(`${label} is invalid: ${[...new Set(releaseProblems)].join('; ')}`);
    return null;
  }
  return {
    repository,
    tag,
    releaseNodeId,
    catalogTagCommitOid,
    publishedAt,
  };
}

function compareOperationArtifactPublicationLinks(
  left: CanonicalOperationArtifactPublicationLink,
  right: CanonicalOperationArtifactPublicationLink,
): number {
  return (
    left.release.repository.localeCompare(right.release.repository) ||
    left.release.tag.localeCompare(right.release.tag) ||
    left.release.releaseNodeId.localeCompare(right.release.releaseNodeId) ||
    left.release.catalogTagCommitOid.localeCompare(
      right.release.catalogTagCommitOid,
    ) ||
    left.release.publishedAt.localeCompare(right.release.publishedAt) ||
    left.observationId.localeCompare(right.observationId)
  );
}

function operationArtifactPublicationDigest(
  links: readonly CanonicalOperationArtifactPublicationLink[],
): string {
  return sha256(
    `release_artifact_publication_v1\0${canonicalJson(links)}`,
  );
}

function operationArtifactPublicationLinkMismatches(
  actual: CanonicalOperationArtifactPublicationLink,
  expected: CanonicalOperationArtifactPublicationLink,
): string[] {
  const mismatches: string[] = [];
  if (canonicalJson(actual.release) !== canonicalJson(expected.release)) {
    mismatches.push('release identity');
  }
  for (const [label, field] of [
    ['observation content hash', 'observationContentHash'],
    ['receipt ID', 'receiptId'],
    ['receipt content hash', 'receiptContentHash'],
    ['evidence identity', 'evidenceIdentity'],
    ['evidence report identity', 'evidenceReportIdentity'],
  ] as const) {
    if (actual[field] !== expected[field]) mismatches.push(label);
  }
  return mismatches;
}

function groupOperationArtifactRows<T>(
  rows: readonly T[],
  keyOf: (row: T) => string,
): Map<string, T[]> {
  const grouped = new Map<string, T[]>();
  for (const row of rows) {
    const key = keyOf(row);
    const matches = grouped.get(key) ?? [];
    matches.push(row);
    grouped.set(key, matches);
  }
  return grouped;
}

function sameRecordKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  return canonicalJson(Object.keys(value).sort()) ===
    canonicalJson([...expected].sort());
}

function isCanonicalString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.trim() === value;
}

function receiptForecastState(value: unknown): ReceiptForecastState {
  const problems: string[] = [];
  const forecast = asRecord(value);
  if (!forecast) {
    return {
      eligibilityOutcome: null,
      decisionIds: [],
      captures: [],
      canonicalFieldsDeclared: false,
      canonicalForecastIds: [],
      canonicalForecastContentHashes: [],
      canonicalCaptures: [],
      problems: ['forecast output must be an object'],
    };
  }
  const eligibilityOutcome = typeof forecast.eligibilityOutcome === 'string'
    ? forecast.eligibilityOutcome
    : null;
  const decisionIds = strictStringArray(forecast.decisionIds);
  if (!decisionIds) {
    problems.push('forecast decision links must be non-empty strings');
  }
  const captures: ReceiptForecastCapture[] = [];
  if (!Array.isArray(forecast.captures)) {
    problems.push('forecast captures must be an array');
  } else {
    for (const value of forecast.captures) {
      const capture = asRecord(value);
      const decisionId = nonEmptyString(capture?.decisionId);
      const status = capture?.status === 'inserted' || capture?.status === 'already_captured'
        ? capture.status
        : null;
      if (!capture || !decisionId) {
        problems.push('forecast capture has an invalid decision link');
        continue;
      }
      if (!status) {
        problems.push(
          `forecast capture ${JSON.stringify(decisionId)} has an invalid reuse status`,
        );
      }
      captures.push({ decisionId, status });
    }
  }
  const normalizedDecisionIds = decisionIds ?? [];
  const captureDecisionIds = captures.map((capture) => capture.decisionId);
  if (canonicalJson(normalizedDecisionIds) !== canonicalJson(captureDecisionIds)) {
    problems.push('forecast decision links do not match its captures');
  }
  if (new Set(normalizedDecisionIds).size !== normalizedDecisionIds.length) {
    problems.push('forecast decision links contain duplicates');
  }
  const canonicalFields = [
    'canonicalForecastIds',
    'canonicalForecastContentHashes',
    'canonicalCaptures',
    'newCanonicalForecastIds',
    'existingCanonicalForecastIds',
  ] as const;
  const hasCanonicalFields = canonicalFields.some((field) =>
    forecast[field] !== undefined);
  let canonicalForecastIds: string[] = [];
  let canonicalForecastContentHashes: string[] = [];
  const canonicalCaptures: ReceiptCanonicalForecastCapture[] = [];
  if (hasCanonicalFields) {
    canonicalForecastIds = strictStringArray(forecast.canonicalForecastIds) ?? [];
    canonicalForecastContentHashes =
      strictStringArray(forecast.canonicalForecastContentHashes) ?? [];
    if (
      !Array.isArray(forecast.canonicalForecastIds) ||
      canonicalForecastIds.length !== forecast.canonicalForecastIds.length
    ) {
      problems.push('canonical forecast IDs must be non-empty strings');
    }
    if (
      !Array.isArray(forecast.canonicalForecastContentHashes) ||
      canonicalForecastContentHashes.length !==
        forecast.canonicalForecastContentHashes.length ||
      canonicalForecastContentHashes.some((hash) => !isSha256(hash))
    ) {
      problems.push('canonical forecast content hashes must be SHA-256 strings');
    }
    if (!Array.isArray(forecast.canonicalCaptures)) {
      problems.push('canonical forecast captures must be an array');
    } else {
      for (const value of forecast.canonicalCaptures) {
        const capture = asRecord(value);
        const forecastId = nonEmptyString(capture?.forecastId);
        const contentHash = nonEmptyString(capture?.contentHash);
        const obligationId = nonEmptyString(capture?.obligationId);
        const splitAssignmentId = nonEmptyString(capture?.splitAssignmentId);
        const cohortId = nonEmptyString(capture?.cohortId);
        const opportunityCode = nonEmptyString(capture?.opportunityCode);
        const horizonCode = nonEmptyString(capture?.horizonCode);
        const legacyDecisionId = nonEmptyString(capture?.legacyDecisionId);
        const legacyContentHash = nonEmptyString(capture?.legacyContentHash);
        const status =
          capture?.status === 'inserted' ||
          capture?.status === 'already_captured'
            ? capture.status
            : null;
        if (
          !forecastId ||
          !contentHash ||
          !isSha256(contentHash) ||
          !obligationId ||
          !splitAssignmentId ||
          !cohortId ||
          !opportunityCode ||
          !horizonCode ||
          !legacyDecisionId ||
          !legacyContentHash ||
          !isSha256(legacyContentHash)
        ) {
          problems.push('canonical forecast capture has an invalid immutable link');
          continue;
        }
        if (!status) {
          problems.push(
            `canonical forecast capture ${JSON.stringify(forecastId)} ` +
            `has an invalid reuse status`,
          );
        }
        canonicalCaptures.push({
          forecastId,
          contentHash,
          obligationId,
          splitAssignmentId,
          cohortId,
          opportunityCode,
          horizonCode,
          legacyDecisionId,
          legacyContentHash,
          status,
        });
      }
    }
    if (
      canonicalJson(canonicalForecastIds) !==
        canonicalJson(canonicalCaptures.map((capture) => capture.forecastId)) ||
      canonicalJson(canonicalForecastContentHashes) !==
        canonicalJson(canonicalCaptures.map((capture) => capture.contentHash))
    ) {
      problems.push('canonical forecast links do not match canonical captures');
    }
    if (
      new Set(canonicalForecastIds).size !== canonicalForecastIds.length
    ) {
      problems.push('canonical forecast links contain duplicates');
    }
    const expectedNewCanonicalIds = canonicalCaptures
      .filter((capture) => capture.status === 'inserted')
      .map((capture) => capture.forecastId);
    const expectedExistingCanonicalIds = canonicalCaptures
      .filter((capture) => capture.status === 'already_captured')
      .map((capture) => capture.forecastId);
    for (const [field, expected] of [
      ['newCanonicalForecastIds', expectedNewCanonicalIds],
      ['existingCanonicalForecastIds', expectedExistingCanonicalIds],
    ] as const) {
      const declared = strictStringArray(forecast[field]);
      if (!declared || canonicalJson(declared) !== canonicalJson(expected)) {
        problems.push(`forecast ${field} does not match canonical capture statuses`);
      }
    }
    if (canonicalCaptures.some((capture) =>
      !normalizedDecisionIds.includes(capture.legacyDecisionId))) {
      problems.push('canonical forecast captures reference undeclared legacy decisions');
    }
  }

  const expectedNewDecisionIds = captures
    .filter((capture) => capture.status === 'inserted')
    .map((capture) => capture.decisionId);
  const expectedExistingDecisionIds = captures
    .filter((capture) => capture.status === 'already_captured')
    .map((capture) => capture.decisionId);
  for (const [field, expected] of [
    ['newDecisionIds', expectedNewDecisionIds],
    ['existingDecisionIds', expectedExistingDecisionIds],
  ] as const) {
    if (forecast[field] === undefined) continue;
    const declared = strictStringArray(forecast[field]);
    if (!declared || canonicalJson(declared) !== canonicalJson(expected)) {
      problems.push(`forecast ${field} does not match capture statuses`);
    }
  }
  const expectedOutcome = captures.length === 0
    ? 'not_eligible'
    : expectedNewDecisionIds.length > 0
      ? 'eligible_and_captured'
      : 'already_captured';
  if (eligibilityOutcome !== expectedOutcome) {
    problems.push('forecast eligibility outcome does not match capture statuses');
  }
  return {
    eligibilityOutcome,
    decisionIds: normalizedDecisionIds,
    captures,
    canonicalFieldsDeclared: hasCanonicalFields,
    canonicalForecastIds,
    canonicalForecastContentHashes,
    canonicalCaptures,
    problems,
  };
}

function attemptContentHash(attempt: OperationAttemptLedgerRow): string {
  return attempt.content_hash;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value && typeof value === 'object') {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalValue(nested)]),
    );
  }
  if (typeof value === 'number' && !Number.isFinite(value)) {
    throw new Error('Canonical JSON does not support non-finite numbers');
  }
  if (value === undefined) return null;
  return value;
}

export function redactSensitiveText(value: string): string {
  return value
    .replace(
      /\b([a-z][a-z0-9+.-]*:\/\/)([^/\s:@]+):([^@\s/]+)@/gi,
      '$1[redacted]@',
    )
    .replace(
      /(["'](?:authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|token|secret|password)["']\s*:\s*["'])[^"']*(["'])/gi,
      '$1[redacted]$2',
    )
    .replace(
      /\b(Bearer\s+)[A-Za-z0-9._~+\/=-]+/gi,
      '$1[redacted]',
    )
    .replace(
      /\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b/g,
      '[redacted]',
    )
    .replace(/\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})\b/g, '[redacted]')
    .replace(/\bsk-[A-Za-z0-9_-]{16,}\b/g, '[redacted]')
    .replace(
      /((?:authorization|api[_ -]?key|access[_ -]?token|refresh[_ -]?token|token|secret|password)\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/gi,
      '$1[redacted]',
    )
    .replace(
      /([?&](?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password)=)[^&#\s]*/gi,
      '$1[redacted]',
    )
    .slice(0, 4_000);
}

function isJsonObject(value: string): boolean {
  try {
    const parsed = JSON.parse(value);
    return parsed != null && typeof parsed === 'object' && !Array.isArray(parsed);
  } catch {
    return false;
  }
}

function parseJsonObject(value: string): Record<string, unknown> | null {
  try {
    return asRecord(JSON.parse(value));
  } catch {
    return null;
  }
}

function parseNullableJsonObject(value: string | null): Record<string, unknown> | null {
  return value == null ? null : parseJsonObject(value);
}

function nonEmptyString(value: unknown): string | null {
  return typeof value === 'string' && value.trim() ? value : null;
}

function timestampString(value: unknown): string | null {
  return typeof value === 'string' && isTimestamp(value) ? value : null;
}

function strictStringArray(value: unknown): string[] | null {
  if (
    !Array.isArray(value) ||
    value.some((item) => typeof item !== 'string' || item.trim().length === 0)
  ) {
    return null;
  }
  return value as string[];
}

function asRecord(value: unknown): Record<string, unknown> | null {
  return value != null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function isTimestamp(value: string): boolean {
  return Number.isFinite(Date.parse(value));
}

function isSha256(value: string): boolean {
  return /^[0-9a-f]{64}$/.test(value);
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
