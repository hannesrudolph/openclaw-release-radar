import { Router, type Request, type Response } from 'express';
import { createHash } from 'node:crypto';
import { existsSync } from 'node:fs';
import {
  Worker,
  isMainThread,
  parentPort,
  workerData,
} from 'node:worker_threads';
import { config } from '../config';
import { getCached, setCached } from '../lib/cache';
import {
  getRefreshState,
  listReleasesDb,
} from '../lib/refresh';
import {
  comparisonReleases,
  currentAuthorizedReleaseCatalog,
  currentCompoundAdvisorySnapshotAuditProjection,
  db,
  formatReleaseClosureProofIntegrityFailure,
  formatStableReleaseWindowIntegrityFailure,
  getLastScoredAt,
  getMeta,
  getRefreshCaptureReceipt,
  getRelease,
  getReleaseScoreAudit,
  getReleaseScoreAuditHistoryRunSeal,
  getSealedReleaseScoreAuditPublication,
  latestScoredStableReleaseTag,
  latestComparisonSnapshot,
  listAdvisories,
  listActiveIngestionEvidenceFailures,
  listRefreshCaptureReceipts,
  listRefreshLeases,
  listRefreshOperationAttempts,
  listRefreshOperationStageEvents,
  listReleaseArtifactVerificationObservations,
  listReleaseArtifactVerificationReceipts,
  listReleaseScoreAuditHistoryForRun,
  listReleaseScoreAuditHistoryV2Seals,
  listReleaseValidationForecasts,
  listReleaseValidationOpportunityEnrollments,
  listScoreAuthorityResolutionRuns,
  openedDatabaseFileIdentity,
  readReleaseValidationProofBundle,
  publicIssuesForVersion,
  publicOpenedDuringReign,
  releaseClosureProofIntegrity,
  releaseDataFreshness,
  runInReadTransaction,
  scoreApiSourceRevision,
  scoreSourceIdentity,
  scoreSourceIdentityCacheKey,
  stableReleaseWindowIntegrity,
  type AdvisoryRow,
  type ClosureProofJoinedRow,
  type RefreshCaptureReceiptRow,
  type RefreshOperationAttemptRow,
  type RefreshOperationStageEventRow,
  type ReleasePrReachabilityRow,
} from '../lib/db';
import {
  CLOSURE_PROOF_STATUS_RANK,
  CLOSURE_RISK_DISPOSITIONS,
  closureRiskWeightForRow,
  effectiveClosureClassification,
  scoreAffectingMissingEvidenceClosureRows,
} from '../lib/closureProofPayload';
import {
  CLOSURE_PROOF_STATUSES,
  closureRiskDispositionLabel,
  closureRiskWeightLabel,
  type ClosureRiskDisposition,
} from '../lib/closureProofTaxonomy';
import {
  createReleaseClosureAuthorityEvaluation,
  createReleaseClosureAuthorityEvaluationForRun,
} from '../lib/closureClaimAuthorityEvaluation';
import {
  API_READ_WORKER_DATABASE_CONTEXT,
  PUBLIC_PAYLOAD_WORKER_TASK,
  RELEASE_API_WORKER_TASK,
  SCORE_READ_WORKER_TASK,
  type ApiReadWorkerDatabaseIdentity,
} from '../lib/databaseWorkerContext';
import type { IssueClassification } from '../lib/llm';
import { releaseLabelCutoff } from '../lib/labelCutoff';
import { compareVersions, matchesRange, firstPatchedVersion } from '../lib/versionMatch';
import {
  bandFor,
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
  SCORE_LEDGER_SCHEMA_VERSION,
  type InstallStatus,
} from '../lib/score';
import { SCORE_HISTORY_CHART_LIMIT } from '../lib/historyWindow';
import { PUBLIC_ISSUES_PER_RELEASE, publicIssueSummariesForRelease } from '../lib/publicIssueSummary';
import { surfaceOf } from '../lib/surfaces';
import {
  GATE_EVIDENCE_SCHEMA_VERSION,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  PROMPT_VERSION,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  SCORE_EXPLANATION_SCHEMA_VERSION,
  SCORE_INPUT_SCHEMA_VERSION,
  SCORE_MODEL_VERSION,
} from '../lib/releaseScoring';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  scoreSourceIdentityManifestProblems,
  scoreSourceRuntimeIdentityCacheKey,
} from '../lib/scoreSourceIdentity';
import {
  RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES,
  RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
  RELEASE_ISSUE_EVIDENCE_TIERS,
  batchIssueLabelInfo,
  createReleaseProfileCommentEvidenceCache,
  releaseIssueEvidencePage,
  releaseProfileEvidenceRows,
  type BatchedIssueLabelInfo,
  type ReleaseIssueEvidenceImpactClass,
  type ReleaseIssueEvidenceRow,
  type ReleaseProfileEvidenceSourceRows,
  type ReleaseIssueEvidenceTier,
} from '../lib/releaseIssueEvidence';
import {
  validateRecommendationDecisionCopies,
  validateRecommendationDecisionRun,
} from '../lib/recommendationDecision';
import { codeRevisionFromEnv } from '../lib/codeRevision';
import {
  buildReleaseValidationOpportunityStatus,
  RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION,
} from '../lib/releaseValidationOpportunityStatus';
import {
  buildReleaseValidationOpportunityDenominatorLedger,
  type ReleaseValidationAuditHistoryForDenominator,
} from '../lib/releaseValidationOpportunityDenominator';
import { verifyScoreAuditPayloadContracts } from '../lib/scoreAuditContracts';
import {
  canonicalJson,
  redactSensitiveText,
  verifyOperationReceiptLedger,
  verifyOperationReceiptSemanticLinks,
  type OperationHistoryRow,
  type OperationHistoryRunLinkRow,
} from '../lib/operationReceipts';
import {
  summarizeReleaseValidationProof,
} from '../lib/releaseValidationProofSummary';

export const api = Router();

function requiresNoStore(path: string): boolean {
  return path === '/health' ||
    path === '/status' ||
    path === '/config' ||
    path === '/receipts' ||
    path.startsWith('/receipts/') ||
    path === '/validation/opportunities' ||
    path === '/releases' ||
    path === '/releases/history' ||
    path === '/public' ||
    path === '/comparison' ||
    /^\/releases\/[^/]+\/review(?:\/|$)/.test(path);
}

api.use((req, res, next) => {
  if (requiresNoStore(req.path)) res.set('Cache-Control', 'no-store');
  next();
});

const CLOSURE_PROOF_AUDIT_SCHEMA_VERSION = 2;
const CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT = 50;
const CLOSURE_PROOF_AUDIT_MAX_LIMIT = 100;
const ISSUE_EVIDENCE_AUDIT_DEFAULT_LIMIT = 50;
const ISSUE_EVIDENCE_AUDIT_MAX_LIMIT = 250;
const PR_REACHABILITY_AUDIT_SCHEMA_VERSION = 1;
const PR_REACHABILITY_AUDIT_DEFAULT_LIMIT = 100;
const PR_REACHABILITY_AUDIT_MAX_LIMIT = 250;
const ISSUE_EVIDENCE_SENTIMENTS = ['negative', 'positive', 'neutral'] as const;
const ISSUE_EVIDENCE_SEVERITIES = ['critical', 'high', 'medium', 'low'] as const;
const ISSUE_EVIDENCE_FUNCTIONALITIES = [
  'core',
  'integration',
  'provider',
  'tooling',
  'docs',
] as const;
const ISSUE_EVIDENCE_SCOPES = ['broad', 'moderate', 'niche'] as const;
const ISSUE_EVIDENCE_AFFECTED_USERS = ['many', 'some', 'few', 'unknown'] as const;
const ISSUE_EVIDENCE_SORTS = ['rank', 'weight', 'updated', 'created', 'closed', 'number'] as const;
type IssueEvidenceSort = (typeof ISSUE_EVIDENCE_SORTS)[number];
type SortDirection = 'asc' | 'desc';
const SEMANTIC_HEALTH_SCHEMA_VERSION = 1;
const SEMANTIC_HEALTH_PROBLEM_LIMIT = 5;
const SEMANTIC_HEALTH_PROBLEM_MAX_LENGTH = 500;
const STALE_ANALYSIS_PREFIX = 'Analysis is stale.';
const STALE_SCORE_AUDIT_SCHEMA_VERSION = 1;

type StaleScoreAuditDiagnostics = {
  schemaVersion: typeof STALE_SCORE_AUDIT_SCHEMA_VERSION;
  state: 'stale';
  message: string;
  previousStatus: string | null;
  auditedAt: string | null;
  causes: string[];
};

type ScorePublicationGuard = {
  causes: string[];
  activeRefresh: boolean;
  activeScoreBlockingIngestionFailureCount: number;
  closureProofFailureTags: string[];
};

let localRefreshingOverrideForTests: boolean | null = null;

function apiRefreshState(): ReturnType<typeof getRefreshState> {
  const state = getRefreshState();
  return localRefreshingOverrideForTests == null
    ? state
    : { ...state, refreshing: localRefreshingOverrideForTests };
}

export function setApiLocalRefreshingForTests(refreshing: boolean | null): void {
  if (!isMainThread) {
    throw new Error('Local refresh test state can only be changed in the API parent process');
  }
  localRefreshingOverrideForTests = refreshing;
}

let cachedScoreSourceIdentity: {
  key: string;
  value: ReturnType<typeof scoreSourceIdentity> | null;
  problem: string | null;
} | null = null;
let cachedScoreRelevantSourceDigest: {
  sourceRevision: number;
  digest: string;
} | null = null;
let cachedApiDbEpoch: string | null = null;
const cachedReleaseFreshness = new Map<string, ReturnType<typeof releaseDataFreshness> & {
  labelCutoffAt: string | null;
}>();
const cachedScoreCompatibility = new Map<string, {
  usable: boolean;
  explanation: Record<string, any> | null;
  staleAudit: StaleScoreAuditDiagnostics | null;
}>();
const cachedSealedScoreAudits = new Map<
  string,
  ReturnType<typeof getSealedReleaseScoreAuditPublication>
>();
let cachedRecommendationRun: {
  key: string;
  failures: string[];
} | null = null;

function scoreApiSourceEpoch(): string {
  const nowMs = Date.now();
  const state = apiRefreshState();
  const sourceRevision = scoreApiSourceRevision();
  const activeLeases = listRefreshLeases()
    .filter((lease) => Date.parse(lease.expires_at) > nowMs)
    .map((lease) => [
      lease.name,
      lease.holder_id,
      lease.acquired_at,
      lease.expires_at,
    ]);
  const publicationStateDigest = createHash('sha256')
    .update(canonicalJson({
      refreshing: state.refreshing,
      processLastRefreshAt: state.processLastRefreshAt,
      lastError: state.lastError,
      activeLeases,
    }))
    .digest('hex');
  return [
    scoreRelevantSourceDigest(),
    sourceRevision,
    scoreSourceRuntimeIdentityCacheKey(),
    publicationStateDigest,
  ].join(':');
}

function scoreRelevantSourceDigest(): string {
  const sourceRevision = scoreApiSourceRevision();
  if (cachedScoreRelevantSourceDigest?.sourceRevision === sourceRevision) {
    return cachedScoreRelevantSourceDigest.digest;
  }
  let digest: string;
  try {
    digest = scoreSourceIdentity().digest;
  } catch {
    digest = createHash('sha256')
      .update(canonicalJson({
        schemaVersion: 1,
        state: 'invalid_score_source',
        sourceRevision,
      }))
      .digest('hex');
  }
  cachedScoreRelevantSourceDigest = { sourceRevision, digest };
  return digest;
}

function currentApiDbEpoch(): string {
  const key = scoreApiSourceEpoch();
  if (cachedApiDbEpoch !== key) {
    cachedApiDbEpoch = key;
    cachedScoreSourceIdentity = null;
    cachedReleaseFreshness.clear();
    cachedScoreCompatibility.clear();
    cachedSealedScoreAudits.clear();
    cachedRecommendationRun = null;
  }
  return key;
}

function currentScoreSourceIdentityResult(): {
  value: ReturnType<typeof scoreSourceIdentity> | null;
  problem: string | null;
} {
  const key = currentApiDbEpoch();
  if (cachedScoreSourceIdentity?.key === key) {
    return {
      value: cachedScoreSourceIdentity.value,
      problem: cachedScoreSourceIdentity.problem,
    };
  }
  try {
    const value = scoreSourceIdentity();
    cachedScoreSourceIdentity = { key, value, problem: null };
  } catch (error) {
    cachedScoreSourceIdentity = {
      key,
      value: null,
      problem:
        `Current score source identity could not be reconstructed: ` +
        `${error instanceof Error ? error.message : String(error)}`,
    };
  }
  return {
    value: cachedScoreSourceIdentity.value,
    problem: cachedScoreSourceIdentity.problem,
  };
}

class ApiSourceSnapshotChangedError extends Error {
  constructor() {
    super('API source rows changed during the read');
    this.name = 'ApiSourceSnapshotChangedError';
  }
}

type ScoreReadEpochSnapshot = {
  localEpoch: string;
  requestEpoch: string;
  publicationGuard: ScorePublicationGuard;
};

function scorePublicationContextSnapshot(): {
  localEpoch: string;
  publicationGuard: ScorePublicationGuard;
} {
  return runInReadTransaction(() => {
    currentAuthorizedReleaseCatalog();
    for (let attempt = 0; attempt < 3; attempt++) {
      const localEpoch = scoreApiSourceEpoch();
      const publicationGuard = scorePublicationGuardSnapshot();
      if (scoreApiSourceEpoch() === localEpoch) {
        return { localEpoch, publicationGuard };
      }
    }
    throw new ApiSourceSnapshotChangedError();
  });
}

function scoreReadEpochSnapshot(
  request: ScoreReadRequest,
): ScoreReadEpochSnapshot {
  const { localEpoch, publicationGuard } = scorePublicationContextSnapshot();
  return {
    localEpoch,
    requestEpoch: request.kind === 'comparison'
      ? [
          localEpoch,
          'comparison',
          scoreSourceIdentityCacheKey(),
        ].join(':')
      : localEpoch,
    publicationGuard,
  };
}

function scoreReadSourceEpoch(request: ScoreReadRequest): string {
  return scoreReadEpochSnapshot(request).requestEpoch;
}

function stableApiRead<T>(
  read: () => T,
  sourceEpoch: () => string = scoreApiSourceEpoch,
): T {
  for (let attempt = 0; attempt < 3; attempt++) {
    const epochBefore = sourceEpoch();
    const value = runInReadTransaction(read);
    if (sourceEpoch() === epochBefore) return value;
    currentApiDbEpoch();
  }
  throw new ApiSourceSnapshotChangedError();
}

function activeStableReleaseFromAuthorizedCatalog(
  tag: string,
): ReturnType<typeof getRelease> {
  return runInReadTransaction(() => {
    currentAuthorizedReleaseCatalog();
    const release = getRelease(tag);
    return release?.catalog_active === 1 && release.prerelease === 0
      ? release
      : undefined;
  });
}

function requireActiveStableRelease(
  res: Response,
  tag: string,
  unavailableError: string,
): boolean {
  try {
    if (activeStableReleaseFromAuthorizedCatalog(tag)) return true;
    res.status(404).json({ error: 'release not found', tag });
  } catch {
    res.status(503).json({ error: unavailableError, tag });
  }
  return false;
}

// Cross-reference each release tag against cached advisories. Every matching
// vulnerable range remains visible; age affects scoring weight, not whether the
// API discloses the advisory. `patched` only credits the first fixed release.
function advisoryStatusFor(tag: string, all: AdvisoryRow[]) {
  const affected: AdvisoryRow[] = [];
  const patched: AdvisoryRow[] = [];
  for (const a of all) {
    if (matchesRange(tag, a.vulnerable_version_range)) affected.push(a);
    const first = firstPatchedVersion(a.patched_versions);
    if (first && compareVersions(first, tag) === 0) patched.push(a);
  }
  return { affected, patched };
}

// Parse the stored broken-surfaces JSON (see lib/surfaces.ts) defensively.
function parseBrokenSurfaces(json: string | null): Array<{ label: string; icon: string; count: number }> {
  if (!json) return [];
  try {
    const v = JSON.parse(json);
    return Array.isArray(v) ? v : [];
  } catch {
    return [];
  }
}

function summarizeAdvisories(list: AdvisoryRow[]) {
  const by = { critical: 0, high: 0, medium: 0, low: 0 } as Record<string, number>;
  const severityRank: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
  const grouped = new Map<string, AdvisoryRow[]>();
  for (const advisory of list) {
    const key = [
      advisory.ghsa_id,
      String(advisory.package_ecosystem ?? '').toLowerCase(),
      String(advisory.package_name ?? '').toLowerCase(),
    ].join('\0');
    const rows = grouped.get(key) ?? [];
    rows.push(advisory);
    grouped.set(key, rows);
  }
  const items = [...grouped.values()].map((rows) => {
    const representative = rows.slice().sort((left, right) =>
      (severityRank[right.severity] ?? 0) - (severityRank[left.severity] ?? 0))[0];
    by[representative.severity] = (by[representative.severity] ?? 0) + 1;
    const matchingRanges = rows
      .map((row) => ({
        vulnerableVersionRange: row.vulnerable_version_range,
        patchedVersion: firstPatchedVersion(row.patched_versions),
      }))
      .sort((left, right) =>
        String(left.vulnerableVersionRange ?? '').localeCompare(String(right.vulnerableVersionRange ?? '')));
    const patchedVersions = [...new Set(
      matchingRanges.map((row) => row.patchedVersion).filter((version): version is string => !!version),
    )];
    return {
      ghsaId: representative.ghsa_id,
      cveId: representative.cve_id,
      severity: representative.severity,
      summary: representative.summary,
      url: representative.html_url,
      patchedVersion: patchedVersions.length === 1 ? patchedVersions[0] : null,
      rangeCount: matchingRanges.length,
      matchingRanges,
    };
  }).sort((left, right) => left.ghsaId.localeCompare(right.ghsaId));
  return {
    total: grouped.size,
    bySeverity: by,
    rangeTotal: list.length,
    items,
  };
}

function parseJson<T>(json: string | null | undefined, fallback: T): T {
  if (!json) return fallback;
  try {
    return JSON.parse(json) as T;
  } catch {
    return fallback;
  }
}

function isRecord(value: unknown): value is Record<string, any> {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function sameNumberOrNull(left: unknown, right: unknown): boolean {
  if (left == null || right == null) return left == null && right == null;
  return typeof left === 'number' &&
    typeof right === 'number' &&
    Number.isFinite(left) &&
    Number.isFinite(right) &&
    left === right;
}

function scoreSourceIdentityMatches(
  persisted: unknown,
  current: ReturnType<typeof scoreSourceIdentity>,
): boolean {
  if (!isRecord(persisted)) return false;
  return scoreSourceIdentityManifestProblems(persisted).length === 0 &&
    canonicalJson(persisted) === canonicalJson(current);
}

function scoreAuditIdentityDigest(
  audit: ReturnType<typeof getReleaseScoreAudit>,
): string | null {
  if (!audit) return null;
  return sealedScoreAuditPublication(audit.release_tag).digest;
}

function sealedScoreAuditPublication(
  tag: string,
): ReturnType<typeof getSealedReleaseScoreAuditPublication> {
  currentApiDbEpoch();
  const cached = cachedSealedScoreAudits.get(tag);
  if (cached) return cached;
  const persisted = getSealedReleaseScoreAuditPublication(tag);
  const missingEvidence = scoreAffectingMissingEvidenceClosureRows(tag);
  const publication = missingEvidence.length === 0
    ? persisted
    : {
      ...persisted,
      valid: false,
      digest: null,
      problems: [
        ...persisted.problems,
        `${tag}: score-affecting negative missing_evidence closure proof remains for ` +
        missingEvidence.map((row) => `#${row.issueNumber}`).join(', '),
      ],
    };
  cachedSealedScoreAudits.set(tag, publication);
  return publication;
}

function validTimestamp(value: unknown): string | null {
  return typeof value === 'string' && Number.isFinite(Date.parse(value)) ? value : null;
}

type TimestampedRefreshError = {
  at: string | null;
  message: string;
};

export function resolveRefreshStatus(input: {
  processLastRefreshAt: string | null;
  processLastError: string | null;
  processLastErrorAt: string | null;
  durableLastRefreshAt: string | null;
  durableErrors: TimestampedRefreshError[];
}): {
  lastRefreshAt: string | null;
  lastError: string | null;
} {
  const successCandidates = [
    validTimestamp(input.processLastRefreshAt),
    validTimestamp(input.durableLastRefreshAt),
  ].filter((value): value is string => value != null);
  const lastRefreshAt = successCandidates.sort(
    (left, right) => Date.parse(right) - Date.parse(left),
  )[0] ?? null;
  const errorCandidates = [
    ...(input.processLastError
      ? [{
          at: validTimestamp(input.processLastErrorAt),
          message: input.processLastError,
        }]
      : []),
    ...input.durableErrors.map((error) => ({
      at: validTimestamp(error.at),
      message: error.message,
    })),
  ];
  const datedErrors = errorCandidates
    .filter((error): error is { at: string; message: string } => error.at != null)
    .sort((left, right) => Date.parse(right.at) - Date.parse(left.at));
  const newestError = datedErrors[0] ??
    (lastRefreshAt == null ? errorCandidates.find((error) => error.at == null) : null);
  return {
    lastRefreshAt,
    lastError:
      newestError &&
      (lastRefreshAt == null || Date.parse(newestError.at) > Date.parse(lastRefreshAt))
        ? newestError.message
        : null,
  };
}

function durableSuccessfulRefreshAt(
  scorePersistence: Record<string, unknown> | null,
  currentScorePublicationValid: boolean,
): string | null {
  if (scorePersistence?.schemaVersion !== 2 || scorePersistence.source !== 'refresh') return null;
  if (!currentScorePublicationValid) return null;
  const persistedAt = validTimestamp(scorePersistence.persistedAt);
  const crawlFinishedAt = validTimestamp(scorePersistence.issueCrawlFinishedAt);
  const scorePersistedAt = validTimestamp(scorePersistence.issueCrawlScorePersistedAt);
  if (!persistedAt || !crawlFinishedAt || scorePersistedAt !== persistedAt) return null;
  if (scorePersistence.issueCrawlStopReason === 'page_cap' ||
      scorePersistence.issueCrawlStopReason === 'evidence_failure') {
    return null;
  }
  return scorePersistedAt;
}

function durableRefreshReceiptFailure(
  scorePersistence: Record<string, unknown> | null,
  currentScorePublicationValid: boolean,
): TimestampedRefreshError | null {
  if (scorePersistence?.schemaVersion !== 2 || scorePersistence.source !== 'refresh') return null;
  const persistedAt = validTimestamp(scorePersistence.persistedAt);
  const runId = typeof scorePersistence.operationRunId === 'string'
    ? scorePersistence.operationRunId
    : null;
  if (!runId) {
    return {
      at: persistedAt,
      message: 'Latest refresh failed: current score is missing its operation run ID.',
    };
  }
  const receipt = getRefreshCaptureReceipt(runId);
  if (!receipt) {
    return {
      at: persistedAt,
      message: `Latest refresh failed: operation ${runId} has no terminal receipt.`,
    };
  }
  if (receipt.status !== 'success') {
    return {
      at: receipt.finished_at,
      message:
        `Latest refresh failed at ${receipt.finished_at}: terminal receipt is ${receipt.status}.`,
    };
  }
  return currentScorePublicationValid
    ? null
    : {
        at: receipt.finished_at,
        message:
          `Latest refresh failed at ${receipt.finished_at}: ` +
          'success receipt did not authorize the current score tip.',
      };
}

function durableRefreshFailure(
  issueCrawl: Record<string, unknown> | null,
): TimestampedRefreshError | null {
  if (!issueCrawl) return null;
  const supportedSchema = [1, 2, 3, 4].includes(Number(issueCrawl.schemaVersion));
  const finishedAt = validTimestamp(issueCrawl.finishedAt);
  if (!finishedAt) {
    return {
      at: null,
      message: supportedSchema
        ? 'Latest refresh failed: issue crawl completion time is missing or invalid.'
        : 'Latest refresh failed: issue crawl metadata is missing a supported schema.',
    };
  }

  const evidenceFailures = Array.isArray(issueCrawl.evidenceRefreshFailures)
    ? issueCrawl.evidenceRefreshFailures.filter((value): value is string =>
        typeof value === 'string' && value.length > 0)
    : [];
  const classificationFailures = Array.isArray(issueCrawl.classificationFailures)
    ? issueCrawl.classificationFailures.filter((value): value is string =>
        typeof value === 'string' && value.length > 0)
    : [];
  const failed = !supportedSchema ||
    issueCrawl.scorePersisted !== true ||
    issueCrawl.stopReason === 'page_cap' ||
    issueCrawl.stopReason === 'evidence_failure' ||
    evidenceFailures.length > 0 ||
    classificationFailures.length > 0;
  if (!failed) return null;

  const detail = evidenceFailures[0] ??
    classificationFailures[0] ??
    (!supportedSchema
      ? `unsupported issue crawl schema ${String(issueCrawl.schemaVersion)}`
      : `crawl stopped with ${String(issueCrawl.stopReason ?? 'unknown')} before score persistence`);
  return {
    at: finishedAt,
    message: `Latest refresh failed at ${finishedAt}: ${detail}`,
  };
}

function activeOperationStage(events: RefreshOperationStageEventRow[]): string | null {
  const active = new Map<string, RefreshOperationStageEventRow>();
  for (const event of events) {
    if (event.status === 'started') active.set(event.stage, event);
    else active.delete(event.stage);
  }
  return [...active.values()].at(-1)?.stage ?? null;
}

function newestByTimestamp<T>(
  rows: readonly T[],
  timestamp: (row: T) => string,
): T | null {
  return rows.reduce<T | null>((newest, row) => {
    if (!newest) return row;
    return Date.parse(timestamp(row)) >= Date.parse(timestamp(newest)) ? row : newest;
  }, null);
}

function durableRefreshActivitySnapshot(
  nowMs = Date.now(),
): {
  active: boolean;
  activeAttempt: RefreshOperationAttemptRow | null;
  activeLease: ReturnType<typeof listRefreshLeases>[number] | null;
} {
  const attempts = listRefreshOperationAttempts();
  const receipts = listRefreshCaptureReceipts();
  const receiptRunIds = new Set(receipts.map((receipt) => receipt.run_id));
  const activeLeases = listRefreshLeases()
    .filter((lease) => Date.parse(lease.expires_at) > nowMs);
  const activeLeaseByName = new Map(activeLeases.map((lease) => [lease.name, lease]));
  const activeAttempt = newestByTimestamp(
    attempts
      .filter((attempt) => !receiptRunIds.has(attempt.run_id))
      .filter((attempt) => {
        const lease = activeLeaseByName.get(attempt.lease_name);
        return lease?.holder_id === attempt.lease_holder_id;
      }),
    (attempt) => attempt.started_at,
  );
  const activeLease = activeAttempt
    ? activeLeaseByName.get(activeAttempt.lease_name) ?? null
    : newestByTimestamp(activeLeases, (lease) => lease.acquired_at);
  return {
    active: activeLeases.length > 0,
    activeAttempt,
    activeLease,
  };
}

export function scorePublicationBlockerCauses(input: {
  closureProofFailureCount: number;
  activeScoreBlockingIngestionFailureCount: number;
  localRefreshing: boolean;
  durableRefreshing: boolean;
}): string[] {
  const causes: string[] = [];
  if (input.closureProofFailureCount > 0) {
    causes.push('closure_proof_integrity_stale');
  }
  if (input.activeScoreBlockingIngestionFailureCount > 0) {
    causes.push('score_blocking_ingestion_failure');
  }
  if (input.localRefreshing || input.durableRefreshing) {
    causes.push('refresh_in_progress');
  }
  return causes;
}

function releaseHasPersistedScoreState(
  release: ReturnType<typeof listReleasesDb>[number],
  audit: ReturnType<typeof getReleaseScoreAudit>,
): boolean {
  return audit != null ||
    release.scored_at != null ||
    release.final_score != null ||
    release.state != null ||
    release.recommended === 1;
}

function scorePublicationGuardSnapshot(): ScorePublicationGuard {
  const closureProofFailureTags = listReleasesDb(config.limits.releases)
    .filter((release) =>
      releaseHasPersistedScoreState(
        release,
        getReleaseScoreAudit(release.tag),
      ))
    .filter((release) =>
      formatReleaseClosureProofIntegrityFailure(
        releaseClosureProofIntegrity(release.tag, 1),
      ) != null)
    .map((release) => release.tag);
  const activeScoreBlockingFailureCount =
    activeScoreBlockingIngestionFailureCount();
  const durableRefresh = durableRefreshActivitySnapshot();
  const localRefreshing = apiRefreshState().refreshing;
  return {
    causes: scorePublicationBlockerCauses({
      closureProofFailureCount: closureProofFailureTags.length,
      activeScoreBlockingIngestionFailureCount:
        activeScoreBlockingFailureCount,
      localRefreshing,
      durableRefreshing: durableRefresh.active,
    }),
    activeRefresh: localRefreshing || durableRefresh.active,
    activeScoreBlockingIngestionFailureCount:
      activeScoreBlockingFailureCount,
    closureProofFailureTags,
  };
}

function scoreAnalysisCompatibility(
  release: ReturnType<typeof listReleasesDb>[number],
  audit: ReturnType<typeof getReleaseScoreAudit>,
  currentSourceIdentity: ReturnType<typeof scoreSourceIdentity> | null,
  publicationGuard: ScorePublicationGuard,
) {
  currentApiDbEpoch();
  const publication = sealedScoreAuditPublication(release.tag);
  const cacheKey = [
    release.tag,
    publication.digest ?? (publication.problems.join('|') || 'missing'),
    currentSourceIdentity?.digest ?? 'current-source-unavailable',
    currentRecommendationRun().key,
    publicationGuard.causes.join(',') || 'publication-ready',
  ].join(':');
  const cached = cachedScoreCompatibility.get(cacheKey);
  if (cached) return cached;

  const input = parseJson<Record<string, any> | null>(audit?.input_json, null);
  const components = parseJson<Record<string, any> | null>(audit?.components_json, null);
  const issueEvidence = parseJson<Record<string, any> | null>(audit?.issue_evidence_json, null);
  const gateEvidence = parseJson<Record<string, any> | null>(audit?.gate_evidence_json, null);
  const sourceIdentity = parseJson<Record<string, any> | null>(audit?.source_identity_json, null);
  const explanation = isRecord(components) ? components.explanation : null;
  const recommendation = isRecord(components) ? components.recommendationDecision : null;
  const explanationRecommendation = isRecord(explanation) ? explanation.recommendationDecision : null;
  const ledger = isRecord(explanation) ? explanation.scoreLedger : null;
  const releaseStatus = release.state as InstallStatus | null;
  const expectedBand = bandFor(release.final_score, releaseStatus ?? 'eligible');
  const releaseRecommended = release.recommended === 1;
  const recommendationFailures = validateRecommendationDecisionCopies({
    tag: release.tag,
    componentsDecision: recommendation,
    explanationDecision: explanationRecommendation,
    expectedStatus: release.state,
    expectedScore: release.final_score,
    expectedSelected: releaseRecommended,
    expectedThreshold: REC_THRESHOLD,
    expectedRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
  });
  recommendationFailures.push(...currentRecommendationRun().failures);
  const auditContractFailures = verifyScoreAuditPayloadContracts({
    tag: release.tag,
    scoredAt: audit?.scored_at,
    input,
    components,
    issueEvidence,
    gateEvidence,
    versions: {
      scoreInput: SCORE_INPUT_SCHEMA_VERSION,
      scoreComponents: SCORE_COMPONENTS_SCHEMA_VERSION,
      issueEvidence: ISSUE_EVIDENCE_SCHEMA_VERSION,
      gateEvidence: GATE_EVIDENCE_SCHEMA_VERSION,
    },
  });

  const auditRecordMatches = !!audit &&
    audit.release_tag === release.tag &&
    audit.score_model_version === SCORE_MODEL_VERSION &&
    audit.prompt_version === PROMPT_VERSION &&
    Number.isFinite(Date.parse(audit.scored_at)) &&
    audit.scored_at === release.scored_at &&
    sameNumberOrNull(audit.final_score, release.final_score) &&
    audit.status === release.state &&
    audit.band === expectedBand &&
    (Number(audit.recommended) === 0 || Number(audit.recommended) === 1) &&
    Number(audit.recommended) === Number(release.recommended);
  const inputCompatible = isRecord(input) &&
    input.schemaVersion === SCORE_INPUT_SCHEMA_VERSION &&
    Number.isInteger(input.rawIssueCount) &&
    input.rawIssueCount >= 0 &&
    Number.isInteger(input.classifiedIssueCount) &&
    input.classifiedIssueCount >= 0 &&
    input.classifiedIssueCount <= input.rawIssueCount;
  const componentsCompatible = isRecord(components) &&
    components.schemaVersion === SCORE_COMPONENTS_SCHEMA_VERSION &&
    components.reason === release.score_reason;
  const explanationCompatible = isRecord(explanation) &&
    explanation.schemaVersion === SCORE_EXPLANATION_SCHEMA_VERSION;
  const issueEvidenceCompatible = isRecord(issueEvidence) &&
    issueEvidence.schemaVersion === ISSUE_EVIDENCE_SCHEMA_VERSION;
  const gateEvidenceCompatible = isRecord(gateEvidence) &&
    gateEvidence.schemaVersion === GATE_EVIDENCE_SCHEMA_VERSION;
  const ledgerCompatible = isRecord(ledger) &&
    ledger.schemaVersion === SCORE_LEDGER_SCHEMA_VERSION &&
    sameNumberOrNull(ledger.finalScore, release.final_score) &&
    ledger.status === release.state &&
    ledger.band === expectedBand;
  const sourceIdentityCompatible =
    currentSourceIdentity != null &&
    scoreSourceIdentityMatches(sourceIdentity, currentSourceIdentity);
  const usable = publication.valid &&
    auditRecordMatches &&
    inputCompatible &&
    componentsCompatible &&
    explanationCompatible &&
    issueEvidenceCompatible &&
    gateEvidenceCompatible &&
    auditContractFailures.length === 0 &&
    recommendationFailures.length === 0 &&
    ledgerCompatible &&
    sourceIdentityCompatible &&
    publicationGuard.causes.length === 0;
  const causes: string[] = [];
  if (!audit) causes.push('audit_missing');
  if (!publication.valid) causes.push('audit_publication_invalid');
  if (audit && audit.score_model_version !== SCORE_MODEL_VERSION) causes.push('score_model_changed');
  if (audit && audit.prompt_version !== PROMPT_VERSION) causes.push('prompt_changed');
  if (audit && !auditRecordMatches) causes.push('release_score_record_mismatch');
  if (
    !inputCompatible ||
    !componentsCompatible ||
    !explanationCompatible ||
    !issueEvidenceCompatible ||
    !gateEvidenceCompatible ||
    auditContractFailures.length > 0
  ) {
    causes.push('audit_payload_incompatible');
  }
  if (recommendationFailures.length > 0) causes.push('recommendation_policy_incompatible');
  if (!ledgerCompatible) causes.push('score_ledger_incompatible');
  if (!sourceIdentityCompatible) causes.push('evidence_source_changed');
  causes.push(...publicationGuard.causes);

  const staleAudit: StaleScoreAuditDiagnostics | null = usable ? null : {
    schemaVersion: STALE_SCORE_AUDIT_SCHEMA_VERSION,
    state: 'stale',
    message: staleAnalysisReason(release.state),
    previousStatus: release.state,
    auditedAt: validTimestamp(audit?.scored_at),
    causes: [...new Set(causes.length ? causes : ['audit_incompatible'])],
  };
  const result = {
    usable,
    explanation: usable ? explanation : null,
    staleAudit,
  };
  cachedScoreCompatibility.set(cacheKey, result);
  return result;
}

function currentRecommendationRun() {
  currentApiDbEpoch();
  if (cachedRecommendationRun) return cachedRecommendationRun;
  const rows = listReleasesDb(config.limits.releases)
    .map((release) => {
      const audit = getReleaseScoreAudit(release.tag);
      if (
        !audit ||
        audit.score_model_version !== SCORE_MODEL_VERSION ||
        audit.prompt_version !== PROMPT_VERSION
      ) {
        return null;
      }
      const components = parseJson<Record<string, any> | null>(audit.components_json, null);
      const explanation = isRecord(components) ? components.explanation : null;
      return {
        tag: release.tag,
        publishedAt: release.published_at ?? '',
        status: release.state,
        score: release.final_score,
        recommended: release.recommended === 1,
        componentsDecision: isRecord(components) ? components.recommendationDecision : null,
        explanationDecision: isRecord(explanation) ? explanation.recommendationDecision : null,
      };
    })
    .filter((row): row is NonNullable<typeof row> => row != null);
  const selectedTags = rows.filter((row) => row.recommended).map((row) => row.tag);
  const failures = validateRecommendationDecisionRun({
    rows,
    expectedSelectedTag: selectedTags.length === 1 ? selectedTags[0] : null,
    expectedThreshold: REC_THRESHOLD,
    expectedRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
  });
  const key = createHash('sha256')
    .update(JSON.stringify(rows.map((row) => [
      row.tag,
      row.status,
      row.score,
      row.recommended,
      row.componentsDecision,
      row.explanationDecision,
    ])))
    .digest('hex');
  cachedRecommendationRun = { key, failures };
  return cachedRecommendationRun;
}

function staleAnalysisReason(status: string | null): string {
  const previous = status ? ` Previous audited status: ${status}.` : '';
  return `${STALE_ANALYSIS_PREFIX}${previous} Refresh before installing.`;
}

function scorePresentation(
  release: ReturnType<typeof listReleasesDb>[number],
  audit: ReturnType<typeof getReleaseScoreAudit>,
  currentSourceIdentity: ReturnType<typeof scoreSourceIdentity> | null,
  publicationGuard = scorePublicationGuardSnapshot(),
) {
  const compatibility = scoreAnalysisCompatibility(
    release,
    audit,
    currentSourceIdentity,
    publicationGuard,
  );
  const score = compatibility.usable ? release.final_score : null;
  const persistedStatus = (release.state ?? 'eligible') as InstallStatus;
  const status: InstallStatus | 'stale' = compatibility.usable ? persistedStatus : 'stale';
  return {
    auditUsable: compatibility.usable,
    score,
    band: compatibility.usable ? bandFor(score, persistedStatus) : 'wait',
    status,
    diagnosticStatus: compatibility.usable ? null : persistedStatus,
    recommended: compatibility.usable && release.recommended === 1,
    reason: compatibility.usable ? release.score_reason : staleAnalysisReason(release.state),
    explanation: compatibility.explanation,
    staleAudit: compatibility.staleAudit,
  };
}

function singleQueryValue(raw: unknown): string | null | undefined {
  if (raw == null) return null;
  if (Array.isArray(raw)) return undefined;
  if (typeof raw !== 'string') return undefined;
  const text = raw.trim();
  return text ? text : null;
}

function boundedInteger(
  raw: unknown,
  fallback: number,
  min: number,
  max: number,
): number | undefined {
  const text = singleQueryValue(raw);
  if (text === undefined) return undefined;
  if (text == null) return fallback;
  if (!/^-?\d+$/.test(text)) return undefined;
  const value = Number(text);
  if (!Number.isSafeInteger(value)) return undefined;
  return Math.max(min, Math.min(max, value));
}

const RECEIPT_API_SCHEMA_VERSION = 1;
const RECEIPT_DEFAULT_LIMIT = 10;
const RECEIPT_MAX_LIMIT = 25;
const RECEIPT_LIST_STAGE_LIMIT = 50;
const RECEIPT_DETAIL_STAGE_LIMIT = 250;
const RECEIPT_LIST_PAYLOAD_CHAR_LIMIT = 8_000;
const RECEIPT_DETAIL_PAYLOAD_CHAR_LIMIT = 32_000;
const RECEIPT_LIST_STAGE_DETAIL_CHAR_LIMIT = 2_000;
const RECEIPT_DETAIL_STAGE_DETAIL_CHAR_LIMIT = 8_000;
const RECEIPT_COUNTS_CHAR_LIMIT = 4_000;
const RECEIPT_JSON_MAX_DEPTH = 8;
const RECEIPT_JSON_MAX_ARRAY_ITEMS = 100;
const RECEIPT_JSON_MAX_OBJECT_KEYS = 100;
const RECEIPT_JSON_MAX_STRING_LENGTH = 2_000;
const RECEIPT_PROBLEM_LIMIT = 20;
const RECEIPT_PROBLEM_MAX_LENGTH = 500;
const RECEIPT_IDENTIFIER_MAX_LENGTH = 256;
const RECEIPT_LABEL_MAX_LENGTH = 200;

type ReceiptLedgerSnapshot = {
  readEpoch: string;
  attempts: RefreshOperationAttemptRow[];
  stageEvents: RefreshOperationStageEventRow[];
  receipts: RefreshCaptureReceiptRow[];
  verification: ReturnType<typeof verifyOperationReceiptLedger>;
  semanticLinkVerification: ReturnType<typeof verifyOperationReceiptSemanticLinks>;
  validationProof: ReturnType<typeof summarizeReleaseValidationProof>;
};

type ReceiptJsonProjection = {
  value: unknown;
  truncated: boolean;
  parseError: boolean;
  sourceByteLength: number;
};

function strictBoundedInteger(
  raw: unknown,
  fallback: number,
  min: number,
  max: number,
): number | undefined {
  const text = singleQueryValue(raw);
  if (text === undefined) return undefined;
  if (text == null) return fallback;
  if (!/^\d+$/.test(text)) return undefined;
  const value = Number(text);
  if (!Number.isSafeInteger(value) || value < min || value > max) return undefined;
  return value;
}

function validReceiptIdentifier(raw: unknown): string | null {
  if (typeof raw !== 'string') return null;
  const value = raw.trim();
  if (
    !value ||
    value.length > RECEIPT_IDENTIFIER_MAX_LENGTH ||
    !/^[A-Za-z0-9][A-Za-z0-9._:@+-]*$/.test(value)
  ) {
    return null;
  }
  return value;
}

function receiptLedgerSnapshot(): ReceiptLedgerSnapshot {
  return stableApiRead(() => {
    const attempts = listRefreshOperationAttempts();
    const stageEvents = listRefreshOperationStageEvents();
    const receipts = listRefreshCaptureReceipts();
    const leases = listRefreshLeases();
    const artifactReceipts = listReleaseArtifactVerificationReceipts();
    const artifactObservations = listReleaseArtifactVerificationObservations();
    const forecasts = listReleaseValidationForecasts();
    const references = receipts.map((receipt) =>
      receiptSemanticReferences(receipt.payload_json));
    const referencedDecisionIds = new Set(
      references.flatMap((reference) => reference.forecastDecisionIds),
    );
    const referencedHistoryRunIds = new Set(
      references
        .map((reference) => reference.historyRunId)
        .filter((runId): runId is string => runId != null),
    );
    for (const forecast of forecasts) {
      if (referencedDecisionIds.has(forecast.decision_id)) {
        referencedHistoryRunIds.add(forecast.audit_history_run_id);
      }
    }
    const historyRows = [...referencedHistoryRunIds]
      .flatMap((runId) => listReleaseScoreAuditHistoryForRun(runId)) as
        unknown as OperationHistoryRow[];
    const historyRuns = db.prepare(`
      SELECT *
      FROM release_score_audit_history_runs
      ORDER BY id
    `).all() as unknown as OperationHistoryRunLinkRow[];
    const validationProof = readReleaseValidationProofBundle();
    const observedAt = new Date().toISOString();
    return {
      readEpoch: scoreSourceIdentityCacheKey(),
      attempts,
      stageEvents,
      receipts,
      verification: verifyOperationReceiptLedger({
        attempts,
        stageEvents,
        receipts,
        leases,
        artifactReceipts,
        artifactObservations,
        artifactMembershipPolicy: 'strict',
        observedAt,
      }),
      semanticLinkVerification: verifyOperationReceiptSemanticLinks({
        attempts,
        receipts,
        historyRows,
        historyRuns,
        forecasts,
        authorityRuns: listScoreAuthorityResolutionRuns(),
        historyV2Seals: listReleaseScoreAuditHistoryV2Seals(),
        validationProof,
      }),
      validationProof: summarizeReleaseValidationProof(
        validationProof,
        observedAt,
      ),
    };
  });
}

function receiptSensitiveKey(key: string): boolean {
  const normalized = key.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
  return /(^|[_ -])(authorization|api_key|access_token|refresh_token|token|secret|password|cookie|credential)([_ -]|$)/
    .test(normalized);
}

function boundedReceiptText(value: string, maxLength = RECEIPT_LABEL_MAX_LENGTH): string {
  const redacted = redactSensitiveText(value);
  return redacted.length > maxLength
    ? `${redacted.slice(0, Math.max(0, maxLength - 3))}...`
    : redacted;
}

function boundedReceiptJson(
  json: string | null,
  charLimit: number,
): ReceiptJsonProjection {
  if (json == null) {
    return {
      value: null,
      truncated: false,
      parseError: false,
      sourceByteLength: 0,
    };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(json);
  } catch {
    return {
      value: null,
      truncated: false,
      parseError: true,
      sourceByteLength: Buffer.byteLength(json),
    };
  }
  const budget = {
    remaining: charLimit,
    truncated: false,
  };
  return {
    value: sanitizeReceiptValue(parsed, budget, 0),
    truncated: budget.truncated,
    parseError: false,
    sourceByteLength: Buffer.byteLength(json),
  };
}

function sanitizeReceiptValue(
  value: unknown,
  budget: { remaining: number; truncated: boolean },
  depth: number,
): unknown {
  if (budget.remaining <= 0 || depth > RECEIPT_JSON_MAX_DEPTH) {
    budget.truncated = true;
    return '[truncated]';
  }
  if (value == null || typeof value === 'boolean' || typeof value === 'number') {
    budget.remaining -= String(value).length;
    return value;
  }
  if (typeof value === 'string') {
    const redacted = redactSensitiveText(value);
    const maximum = Math.max(
      0,
      Math.min(RECEIPT_JSON_MAX_STRING_LENGTH, budget.remaining),
    );
    const truncated = redacted.length > maximum;
    const result = truncated
      ? `${redacted.slice(0, Math.max(0, maximum - 3))}...`
      : redacted;
    budget.remaining -= result.length;
    budget.truncated ||= truncated;
    return result;
  }
  if (Array.isArray(value)) {
    const result: unknown[] = [];
    budget.remaining -= 2;
    for (const item of value.slice(0, RECEIPT_JSON_MAX_ARRAY_ITEMS)) {
      if (budget.remaining <= 0) break;
      result.push(sanitizeReceiptValue(item, budget, depth + 1));
    }
    if (value.length > result.length) budget.truncated = true;
    return result;
  }
  if (typeof value === 'object') {
    const result: Record<string, unknown> = Object.create(null);
    const entries = Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right));
    budget.remaining -= 2;
    for (const [key, nested] of entries.slice(0, RECEIPT_JSON_MAX_OBJECT_KEYS)) {
      const safeKey = boundedReceiptText(key);
      if (budget.remaining <= safeKey.length + 3) {
        budget.truncated = true;
        break;
      }
      budget.remaining -= safeKey.length + 3;
      result[safeKey] = receiptSensitiveKey(key)
        ? '[redacted]'
        : sanitizeReceiptValue(nested, budget, depth + 1);
    }
    if (entries.length > Object.keys(result).length) budget.truncated = true;
    return result;
  }
  budget.remaining -= 4;
  return null;
}

function parseReceiptPayload(json: string): Record<string, unknown> | null {
  try {
    const value = JSON.parse(json);
    return isRecord(value) ? value : null;
  } catch {
    return null;
  }
}

function receiptSemanticReferences(payloadJson: string): {
  historyRunId: string | null;
  forecastDecisionIds: string[];
} {
  const payload = parseReceiptPayload(payloadJson);
  const scoreHistory = isRecord(payload?.scoreHistory) ? payload.scoreHistory : null;
  const forecast = isRecord(payload?.forecast) ? payload.forecast : null;
  const directDecisionIds = Array.isArray(forecast?.decisionIds)
    ? forecast.decisionIds
    : [];
  const captureDecisionIds = Array.isArray(forecast?.captures)
    ? forecast.captures
      .filter(isRecord)
      .map((capture) => capture.decisionId)
    : [];
  return {
    historyRunId: typeof scoreHistory?.runId === 'string' && scoreHistory.runId.trim()
      ? scoreHistory.runId
      : null,
    forecastDecisionIds: [...new Set(
      [...directDecisionIds, ...captureDecisionIds]
        .filter((value): value is string => typeof value === 'string' && value.trim().length > 0),
    )],
  };
}

function boundedReceiptIdentifier(value: unknown): string | null {
  if (typeof value !== 'string' || !value.trim()) return null;
  return redactSensitiveText(value.trim()).slice(0, RECEIPT_IDENTIFIER_MAX_LENGTH);
}

function receiptLinks(payloadJson: string) {
  const payload = parseReceiptPayload(payloadJson);
  const scoreHistory = isRecord(payload?.scoreHistory) ? payload.scoreHistory : null;
  const forecast = isRecord(payload?.forecast) ? payload.forecast : null;
  const directDecisionIds = Array.isArray(forecast?.decisionIds)
    ? forecast.decisionIds
    : [];
  const captureDecisionIds = Array.isArray(forecast?.captures)
    ? forecast.captures
      .filter(isRecord)
      .map((capture) => capture.decisionId)
    : [];
  const forecastDecisionIds = [...new Set(
    [...directDecisionIds, ...captureDecisionIds]
      .map(boundedReceiptIdentifier)
      .filter((value): value is string => value != null),
  )].slice(0, RECEIPT_JSON_MAX_ARRAY_ITEMS);
  return {
    historyRunId: boundedReceiptIdentifier(scoreHistory?.runId),
    historyRunContentHash: boundedReceiptIdentifier(scoreHistory?.contentHash),
    forecastDecisionIds,
  };
}

function boundedReceiptProblems(problems: readonly string[]): string[] {
  return problems.slice(0, RECEIPT_PROBLEM_LIMIT).map((problem) => {
    const redacted = redactSensitiveText(problem);
    return redacted.length > RECEIPT_PROBLEM_MAX_LENGTH
      ? `${redacted.slice(0, RECEIPT_PROBLEM_MAX_LENGTH - 3)}...`
      : redacted;
  });
}

function receiptVerification(
  snapshot: ReceiptLedgerSnapshot,
  receipt: RefreshCaptureReceiptRow,
) {
  const identifiers = [
    JSON.stringify(receipt.run_id),
    JSON.stringify(receipt.receipt_id),
  ];
  const hashChainProblems = snapshot.verification.hashChainProblems.filter((problem) =>
    identifiers.some((identifier) => problem.includes(identifier)));
  const ledgerSemanticProblems = snapshot.verification.semanticProblems.filter((problem) =>
    identifiers.some((identifier) => problem.includes(identifier)));
  const semanticLinkProblems = snapshot.semanticLinkVerification.problems.filter((problem) =>
    identifiers.some((identifier) => problem.includes(identifier)));
  const hashChainVerified = snapshot.verification.hashChainProblems.length === 0;
  const ledgerSemanticsVerified = snapshot.verification.semanticProblems.length === 0;
  const semanticLinksVerified = snapshot.semanticLinkVerification.problems.length === 0;
  const localProblems = [
    ...hashChainProblems,
    ...ledgerSemanticProblems,
    ...semanticLinkProblems,
  ];
  const allVerified = hashChainVerified && ledgerSemanticsVerified && semanticLinksVerified;
  return {
    status: localProblems.length > 0
      ? 'failed'
      : allVerified
        ? 'verified'
        : 'ledger_failed',
    verified: localProblems.length === 0 && allVerified,
    hashChain: {
      verified: hashChainProblems.length === 0 && hashChainVerified,
      ledgerVerified: hashChainVerified,
      problems: boundedReceiptProblems(hashChainProblems),
    },
    ledgerSemantics: {
      verified: ledgerSemanticProblems.length === 0 && ledgerSemanticsVerified,
      ledgerVerified: ledgerSemanticsVerified,
      problems: boundedReceiptProblems(ledgerSemanticProblems),
    },
    semanticLinks: {
      verified: semanticLinkProblems.length === 0 && semanticLinksVerified,
      ledgerVerified: semanticLinksVerified,
      problems: boundedReceiptProblems(semanticLinkProblems),
    },
    problems: boundedReceiptProblems(localProblems),
  };
}

function receiptLedgerVerification(snapshot: ReceiptLedgerSnapshot) {
  const hashChainVerified = snapshot.verification.hashChainProblems.length === 0;
  const ledgerSemanticsVerified = snapshot.verification.semanticProblems.length === 0;
  const semanticLinksVerified = snapshot.semanticLinkVerification.problems.length === 0;
  const verified = hashChainVerified && ledgerSemanticsVerified && semanticLinksVerified;
  return {
    status: verified ? 'verified' : 'failed',
    verified,
    attemptCount: snapshot.verification.attemptCount,
    stageEventCount: snapshot.verification.stageEventCount,
    receiptCount: snapshot.verification.receiptCount,
    unterminatedRunIds: snapshot.verification.unterminatedRunIds
      .slice(0, RECEIPT_PROBLEM_LIMIT),
    activeUnterminatedRunIds: snapshot.verification.activeUnterminatedRunIds
      .slice(0, RECEIPT_PROBLEM_LIMIT),
    invalidUnterminatedRunIds: snapshot.verification.invalidUnterminatedRunIds
      .slice(0, RECEIPT_PROBLEM_LIMIT),
    hashChain: {
      status: hashChainVerified ? 'verified' : 'failed',
      verified: hashChainVerified,
      problems: boundedReceiptProblems(snapshot.verification.hashChainProblems),
    },
    ledgerSemantics: {
      status: ledgerSemanticsVerified ? 'verified' : 'failed',
      verified: ledgerSemanticsVerified,
      problems: boundedReceiptProblems(snapshot.verification.semanticProblems),
    },
    semanticLinks: {
      status: semanticLinksVerified ? 'verified' : 'failed',
      verified: semanticLinksVerified,
      problems: boundedReceiptProblems(snapshot.semanticLinkVerification.problems),
    },
    problems: boundedReceiptProblems([
      ...snapshot.verification.problems,
      ...snapshot.semanticLinkVerification.problems,
    ]),
  };
}

function receiptValidationProof(
  snapshot: ReceiptLedgerSnapshot,
) {
  return {
    ...snapshot.validationProof,
    problems: boundedReceiptProblems(snapshot.validationProof.problems),
  };
}

function normalizeReceiptRecord(
  snapshot: ReceiptLedgerSnapshot,
  receipt: RefreshCaptureReceiptRow,
  options: {
    stageLimit: number;
    payloadCharLimit: number;
    stageDetailCharLimit: number;
  },
) {
  const attempt = snapshot.attempts.find((row) => row.run_id === receipt.run_id) ?? null;
  const allStages = snapshot.stageEvents
    .filter((row) => row.run_id === receipt.run_id)
    .sort((left, right) => left.sequence - right.sequence);
  const payload = boundedReceiptJson(receipt.payload_json, options.payloadCharLimit);
  return {
    receiptId: receipt.receipt_id,
    runId: receipt.run_id,
    outcome: receipt.status,
    attempt: attempt
      ? {
        runId: attempt.run_id,
        operation: boundedReceiptText(attempt.operation),
        trigger: boundedReceiptText(attempt.trigger),
        startedAt: attempt.started_at,
        lease: {
          name: boundedReceiptText(attempt.lease_name),
          expiresAt: attempt.lease_expires_at,
        },
        codeRevision: attempt.code_revision,
        hashes: {
          effectiveConfig: attempt.effective_config_hash,
          content: attempt.content_hash,
        },
      }
      : null,
    stages: allStages.slice(0, options.stageLimit).map((stage) => {
      const counts = boundedReceiptJson(stage.counts_json, RECEIPT_COUNTS_CHAR_LIMIT);
      const details = boundedReceiptJson(
        stage.details_json,
        options.stageDetailCharLimit,
      );
      return {
        eventId: stage.event_id,
        sequence: stage.sequence,
        stage: boundedReceiptText(stage.stage),
        status: stage.status,
        occurredAt: stage.occurred_at,
        durationMs: stage.duration_ms,
        counts: counts.value,
        countsTruncated: counts.truncated,
        countsParseError: counts.parseError,
        details: details.value,
        detailsTruncated: details.truncated,
        detailsParseError: details.parseError,
        hashes: {
          previousContent: stage.previous_content_hash,
          content: stage.content_hash,
        },
      };
    }),
    stageCount: allStages.length,
    stagesTruncated: allStages.length > options.stageLimit,
    terminal: {
      receiptId: receipt.receipt_id,
      status: receipt.status,
      finishedAt: receipt.finished_at,
      durationMs: receipt.duration_ms,
      stageEventCount: receipt.stage_event_count,
      payload: payload.value,
      payloadTruncated: payload.truncated,
      payloadParseError: payload.parseError,
      payloadByteLength: payload.sourceByteLength,
      hashes: {
        stageChain: receipt.stage_chain_hash,
        previousContent: receipt.previous_content_hash,
        content: receipt.content_hash,
      },
    },
    links: receiptLinks(receipt.payload_json),
    verification: receiptVerification(snapshot, receipt),
  };
}

interface ClosureProofAuditItem {
  number: number;
  title: string;
  url: string | null;
  closedAt: string | null;
  status: string;
  summary: string;
  riskDisposition: ClosureRiskDisposition;
  riskWeight: number;
  checkedAt: string;
  labels: string[];
  classification: IssueClassification | null;
  classificationDiff: Record<string, { raw: unknown; effective: unknown }>;
  evidence: Record<string, unknown>;
}

function closureProofAuditResponseRow(row: ClosureProofAuditItem) {
  return {
    issueNumber: row.number,
    title: row.title,
    url: row.url,
    closedAt: row.closedAt,
    status: row.status,
    summary: row.summary,
    riskDisposition: row.riskDisposition,
    riskDispositionLabel: closureRiskDispositionLabel(row.riskDisposition),
    riskWeight: row.riskWeight,
    riskWeightLabel: closureRiskWeightLabel(row.riskWeight),
    checkedAt: row.checkedAt,
    labels: row.labels,
    classification: row.classification,
    classificationDiff: row.classificationDiff,
    evidence: compactClosureProofEvidence(row.evidence),
  };
}

function compactClosureProofEvidence(evidence: unknown) {
  const raw = evidence && typeof evidence === 'object' ? evidence as Record<string, unknown> : {};
  return {
    stateReasons: arrayOf(raw.stateReasons, compactScalar),
    closureActors: arrayOf(raw.closureActors, compactScalar),
    closureContextCommentCount: raw.closureContextCommentCount ?? null,
    hasClosingLink: raw.hasClosingLink === true,
    hasMergedClosingPr: raw.hasMergedClosingPr === true,
    hasReachableClosingPr: raw.hasReachableClosingPr === true,
    hasNotReachableClosingPr: raw.hasNotReachableClosingPr === true,
    hasReachableFixCommit: raw.hasReachableFixCommit === true,
    hasNotReachableFixCommit: raw.hasNotReachableFixCommit === true,
    hasUnknownFixCommit: raw.hasUnknownFixCommit === true,
    canonicalIssues: arrayOf(raw.canonicalIssues, compactScalar),
    canonicalIssueDetails: arrayOf(raw.canonicalIssueDetails, compactIssueRef),
    canonicalResolution: compactCanonicalResolution(raw.canonicalResolution),
    closingPrs: arrayOf(raw.closingPrs, compactScalar),
    linkedPrs: arrayOf(raw.linkedPrs, compactPrRef),
    relatedPrContext: compactRelatedPrContext(raw.relatedPrContext),
    reachableTrustedFixProofPrs: arrayOf(raw.reachableTrustedFixProofPrs, compactPrRef),
    matchingComments: arrayOf(raw.matchingComments, compactCommentRef, 5),
    nonActionableRationaleComments: arrayOf(raw.nonActionableRationaleComments, compactCommentRef, 5),
    laterFixProof: compactLaterFixProof(raw.laterFixProof),
    unscoredFixProof: compactUnscoredFixProof(raw.unscoredFixProof),
    fixCommitProof: arrayOf(raw.fixCommitProof, compactCommitProof),
    canonicalFixCommitProof: arrayOf(raw.canonicalFixCommitProof, compactCommitProof),
    referencedCommitContext: arrayOf(raw.referencedCommitContext, compactCommitProof),
    reachableFixCommits: arrayOf(raw.reachableFixCommits, compactScalar),
    notReachableFixCommits: arrayOf(raw.notReachableFixCommits, compactScalar),
    unknownFixCommits: arrayOf(raw.unknownFixCommits, compactScalar),
  };
}

function compactRelatedPrContext(value: unknown) {
  const raw = value && typeof value === 'object' ? value as Record<string, unknown> : {};
  return {
    externalClosing: arrayOf(raw.externalClosing, compactPrRef),
    open: arrayOf(raw.open, compactPrRef),
    closedUnmerged: arrayOf(raw.closedUnmerged, compactPrRef),
    notReachable: arrayOf(raw.notReachable, compactPrRef),
    reachable: arrayOf(raw.reachable, compactPrRef),
    unknownReachability: arrayOf(raw.unknownReachability, compactPrRef),
  };
}

function compactCanonicalResolution(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    path: arrayOf(raw.path, compactScalar),
    terminalIssue: compactIssueRef(raw.terminalIssue),
    terminalProof: raw.terminalProof && typeof raw.terminalProof === 'object'
      ? {
        status: (raw.terminalProof as Record<string, unknown>).status ?? null,
        summary: (raw.terminalProof as Record<string, unknown>).summary ?? null,
        crossRelease: (raw.terminalProof as Record<string, unknown>).crossRelease === true,
        releaseTag: (raw.terminalProof as Record<string, unknown>).releaseTag ?? null,
        timing: (raw.terminalProof as Record<string, unknown>).timing ?? null,
      }
      : null,
    cycle: raw.cycle === true,
    selfReference: raw.selfReference === true,
  };
}

function arrayOf<T>(value: unknown, mapper: (item: unknown) => T | null, limit = 50): T[] {
  if (!Array.isArray(value)) return [];
  return value.slice(0, limit).map(mapper).filter((item): item is T => item != null);
}

function compactScalar(value: unknown): string | number | boolean | null {
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  return null;
}

function compactIssueRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.issueNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : typeof raw.html_url === 'string' ? raw.html_url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
  };
}

function compactPrRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const number = Number(raw.number ?? raw.prNumber);
  if (!Number.isInteger(number) || number <= 0) return null;
  return {
    number,
    repositoryNameWithOwner: typeof raw.repositoryNameWithOwner === 'string' ? raw.repositoryNameWithOwner : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    willCloseTarget: raw.willCloseTarget === true || raw.willCloseTarget === 1
      ? true
      : raw.willCloseTarget === false || raw.willCloseTarget === 0
        ? false
        : null,
    referencedAt: typeof raw.referencedAt === 'string' ? raw.referencedAt : null,
    sourceCommentDatabaseId: Number.isInteger(Number(raw.sourceCommentDatabaseId)) && Number(raw.sourceCommentDatabaseId) > 0
      ? Number(raw.sourceCommentDatabaseId)
      : null,
    sourceCommentUrl: typeof raw.sourceCommentUrl === 'string' ? raw.sourceCommentUrl : null,
    metadataMissing: raw.metadataMissing === true || raw.metadataMissing === 1,
    title: typeof raw.title === 'string' ? raw.title : null,
    url: typeof raw.url === 'string' ? raw.url : null,
    state: typeof raw.state === 'string' ? raw.state : null,
    merged: raw.merged === 1 || raw.merged === true || typeof raw.mergedAt === 'string',
    mergedAt: typeof raw.mergedAt === 'string' ? raw.mergedAt : null,
    reachabilityStatus: typeof raw.reachabilityStatus === 'string' ? raw.reachabilityStatus : null,
    reachabilityMethod: typeof raw.reachabilityMethod === 'string' ? raw.reachabilityMethod : null,
    reachabilityEvidence: typeof raw.reachabilityEvidence === 'string' ? raw.reachabilityEvidence : null,
    mergeCommitOid: typeof raw.mergeCommitOid === 'string' ? raw.mergeCommitOid : null,
  };
}

function compactCommentRef(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    databaseId: Number.isInteger(Number(raw.databaseId)) && Number(raw.databaseId) > 0
      ? Number(raw.databaseId)
      : null,
    issueNumber: Number.isInteger(Number(raw.issueNumber)) && Number(raw.issueNumber) > 0
      ? Number(raw.issueNumber)
      : null,
    url: typeof raw.url === 'string' ? raw.url : null,
    author: typeof raw.author === 'string' ? raw.author : null,
    createdAt: typeof raw.createdAt === 'string' ? raw.createdAt : null,
    updatedAt: typeof raw.updatedAt === 'string' ? raw.updatedAt : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function compactCommitProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  const commitOid = typeof raw.commitOid === 'string' ? raw.commitOid : null;
  const sourceIssueNumber = Number(raw.sourceIssueNumber);
  return {
    issueNumber: Number.isInteger(Number(raw.issueNumber)) && Number(raw.issueNumber) > 0
      ? Number(raw.issueNumber)
      : null,
    sourceIssueNumber: Number.isInteger(sourceIssueNumber) && sourceIssueNumber > 0 ? sourceIssueNumber : null,
    sourceIssueUrl: Number.isInteger(sourceIssueNumber) && sourceIssueNumber > 0
      ? `https://github.com/${config.github.owner}/${config.github.repo}/issues/${sourceIssueNumber}`
      : null,
    commitOid,
    shortOid: typeof raw.shortOid === 'string' ? raw.shortOid : null,
    commitUrl: commitOid && /^[0-9a-f]{40}$/i.test(commitOid)
      ? `https://github.com/${config.github.owner}/${config.github.repo}/commit/${commitOid}`
      : null,
    status: typeof raw.status === 'string' ? raw.status : null,
    source: typeof raw.source === 'string' ? raw.source : null,
    referencedAt: typeof raw.referencedAt === 'string' ? raw.referencedAt : null,
    author: typeof raw.author === 'string' ? raw.author : null,
    authorAssociation: typeof raw.authorAssociation === 'string' ? raw.authorAssociation : null,
    trustedSource: raw.trustedSource === true,
    tagCommitOid: typeof raw.tagCommitOid === 'string' ? raw.tagCommitOid : null,
    sourceCommentDatabaseId: Number.isInteger(Number(raw.sourceCommentDatabaseId)) && Number(raw.sourceCommentDatabaseId) > 0
      ? Number(raw.sourceCommentDatabaseId)
      : null,
    sourceCommentUrl: typeof raw.sourceCommentUrl === 'string' ? raw.sourceCommentUrl : null,
    evidence: typeof raw.evidence === 'string' ? raw.evidence : null,
    snippet: typeof raw.snippet === 'string' ? raw.snippet : null,
  };
}

function compactLaterFixProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    releaseTag: typeof raw.releaseTag === 'string' ? raw.releaseTag : null,
    publishedAt: typeof raw.publishedAt === 'string' ? raw.publishedAt : null,
    proofType: typeof raw.proofType === 'string' ? raw.proofType : null,
    prNumber: Number.isInteger(Number(raw.prNumber)) ? Number(raw.prNumber) : null,
    prRepositoryNameWithOwner: typeof raw.prRepositoryNameWithOwner === 'string' ? raw.prRepositoryNameWithOwner : null,
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
  };
}

function compactUnscoredFixProof(value: unknown) {
  if (!value || typeof value !== 'object') return null;
  const raw = value as Record<string, unknown>;
  return {
    timing: typeof raw.timing === 'string' ? raw.timing : null,
    proofTime: typeof raw.proofTime === 'string' ? raw.proofTime : null,
    latestScoredReleaseTag: typeof raw.latestScoredReleaseTag === 'string' ? raw.latestScoredReleaseTag : null,
    latestScoredReleasePublishedAt: typeof raw.latestScoredReleasePublishedAt === 'string' ? raw.latestScoredReleasePublishedAt : null,
    proofType: typeof raw.proofType === 'string' ? raw.proofType : null,
    prNumber: Number.isInteger(Number(raw.prNumber)) ? Number(raw.prNumber) : null,
    prRepositoryNameWithOwner: typeof raw.prRepositoryNameWithOwner === 'string' ? raw.prRepositoryNameWithOwner : null,
    commitOid: typeof raw.commitOid === 'string' ? raw.commitOid : null,
  };
}

function parsePrFilter(raw: unknown): { repo: string | null; number: number } | null {
  if (typeof raw !== 'string' || raw.trim() === '') return null;
  const value = raw.trim();
  const match = /^(?:(?<repo>[^#]+)#)?(?<number>\d+)$/.exec(value);
  if (!match?.groups) return null;
  const number = Number(match.groups.number);
  if (!Number.isInteger(number) || number <= 0) return null;
  const repo = match.groups.repo?.trim() || null;
  return { repo, number };
}

function parseIssueNumberFilter(issueRaw: unknown, numberRaw: unknown): number | null | undefined {
  const issue = singleQueryValue(issueRaw);
  const number = singleQueryValue(numberRaw);
  if (issue === undefined || number === undefined) return undefined;
  if (issue == null && number == null) return null;
  const values = [issue, number].filter((value): value is string => value != null);
  const parsed = values.map((value) => Number(value));
  if (parsed.some((value) => !Number.isInteger(value) || value <= 0)) return undefined;
  if (parsed.some((value) => value !== parsed[0])) return undefined;
  return parsed[0];
}

function parseIssueEvidenceTierFilter(raw: unknown): ReleaseIssueEvidenceTier[] | null {
  const tiers = parseCommaList(raw);
  if (!tiers.length) return null;
  const aliases: Record<string, ReleaseIssueEvidenceTier> = {
    openUnconfirmedRisk: 'carryoverDebt',
    weakOrStaleEvidence: 'staleDebt',
    weakOrStaleRisk: 'staleDebt',
  };
  const normalized = tiers.map((tier) => aliases[tier] ?? tier);
  if (normalized.some((tier) => !(RELEASE_ISSUE_EVIDENCE_TIERS as readonly string[]).includes(tier))) return [];
  return [...new Set(normalized)] as ReleaseIssueEvidenceTier[];
}

function parseIssueEvidenceImpactFilter(raw: unknown): ReleaseIssueEvidenceImpactClass[] | null {
  const impacts = parseCommaList(raw);
  if (!impacts.length) return null;
  if (impacts.some((impact) => !(RELEASE_ISSUE_EVIDENCE_IMPACT_CLASSES as readonly string[]).includes(impact))) return [];
  return impacts as ReleaseIssueEvidenceImpactClass[];
}

function parseIssueEvidenceStateFilter(raw: unknown): Array<'open' | 'closed' | 'other'> | null {
  const states = parseCommaList(raw);
  if (!states.length) return null;
  if (states.some((state) => !['open', 'closed', 'other'].includes(state))) return [];
  return states as Array<'open' | 'closed' | 'other'>;
}

function parseIssueEvidenceEnumFilter<T extends string>(raw: unknown, allowed: readonly T[]): T[] | null {
  const values = parseCommaList(raw);
  if (!values.length) return null;
  if (values.some((value) => !allowed.includes(value as T))) return [];
  return values as T[];
}

function parseBooleanFilter(raw: unknown): boolean | null | undefined {
  const value = singleQueryValue(raw);
  if (value === undefined) return undefined;
  if (value == null) return null;
  const text = value.toLowerCase();
  if (['1', 'true', 'yes'].includes(text)) return true;
  if (['0', 'false', 'no'].includes(text)) return false;
  return undefined;
}

function parseNumberFilter(raw: unknown): number | null | undefined {
  const value = singleQueryValue(raw);
  if (value === undefined) return undefined;
  if (value == null) return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : undefined;
}

function parseIssueEvidenceSort(raw: unknown): IssueEvidenceSort | null {
  const value = singleQueryValue(raw);
  if (value === undefined) return null;
  if (value == null) return 'rank';
  const text = value.trim();
  return (ISSUE_EVIDENCE_SORTS as readonly string[]).includes(text) ? text as IssueEvidenceSort : null;
}

function parseSortDirection(raw: unknown, sort: IssueEvidenceSort): SortDirection | null {
  const value = singleQueryValue(raw);
  if (value === undefined) return null;
  if (value == null) return sort === 'rank' ? 'asc' : 'desc';
  const text = value.toLowerCase();
  return text === 'asc' || text === 'desc' ? text : null;
}

function parseCommaList(raw: unknown): string[] {
  const values = Array.isArray(raw) ? raw : typeof raw === 'string' ? [raw] : [];
  return [...new Set(values
    .flatMap((value) => String(value).split(','))
    .map((value) => value.trim())
    .filter(Boolean))];
}

function issueEvidenceState(row: { issue?: { state?: unknown; missing?: unknown } }): 'open' | 'closed' | 'other' {
  const state = row.issue?.state;
  return state === 'open' || state === 'closed' ? state : 'other';
}

function issueClassificationField(row: { issue?: unknown; debtClassification?: unknown }, field: string): string | null {
  const debtClassification = row.debtClassification && typeof row.debtClassification === 'object'
    ? row.debtClassification as Record<string, unknown>
    : null;
  const issue = row.issue && typeof row.issue === 'object' ? row.issue as Record<string, unknown> : null;
  const classification = issue?.classification && typeof issue.classification === 'object'
    ? issue.classification as Record<string, unknown>
    : null;
  const value = classification?.[field] ?? debtClassification?.[field];
  return typeof value === 'string' ? value : null;
}

function issueEvidenceSortValue(row: ReleaseIssueEvidenceRow, sort: IssueEvidenceSort): number | null {
  if (sort === 'weight') {
    const weight = Number(row.weight);
    return Number.isFinite(weight) ? weight : null;
  }
  if (sort === 'number') {
    const number = Number(row.issue?.number);
    return Number.isInteger(number) && number > 0 ? number : null;
  }
  if (sort === 'updated') return timestampValue(row.issue?.updatedAt);
  if (sort === 'created') return timestampValue(row.issue?.createdAt);
  if (sort === 'closed') return timestampValue(row.issue?.closedAt);
  return null;
}

function timestampValue(value: unknown): number | null {
  if (typeof value !== 'string') return null;
  const parsed = Date.parse(value);
  return Number.isFinite(parsed) ? parsed : null;
}

type SqlCountRow = { count: number };
type SqlStatusCountRow = { status: string; count: number };

interface ClosureProofPage {
  unfilteredRows: number;
  filteredRows: number;
  unfilteredDistinctIssues: number;
  filteredDistinctIssues: number;
  unfilteredCountsByStatus: Record<string, number>;
  filteredCountsByStatus: Record<string, number>;
  unfilteredCountsByRiskDisposition: Record<string, number>;
  filteredCountsByRiskDisposition: Record<string, number>;
  rows: ClosureProofAuditItem[];
  nextCursor: number | null;
}

function closureProofPage(input: {
  tag: string;
  labelCutoff: string | null;
  authorityRunId: string | null;
  issueNumber: number | null;
  status: string | null;
  riskDisposition: string | null;
  cursor: number;
  limit: number;
}): ClosureProofPage {
  const closureAuthority = input.authorityRunId
    ? createReleaseClosureAuthorityEvaluationForRun(input.authorityRunId)
    : createReleaseClosureAuthorityEvaluation();
  const allRows = db.prepare(`
    SELECT p.*, i.title, i.html_url, i.closed_at, i.labels,
           c.sentiment, c.severity, c.scope, c.functionality, c.affected_users,
           c.has_workaround, c.workaround_status, c.duplicate_cluster, c.affects_version,
           c.confidence, c.rationale
    FROM issue_closure_proofs p
    JOIN issues i ON i.number=p.issue_number
    LEFT JOIN classifications c ON c.issue_number=p.issue_number
    WHERE p.release_tag=?
  `).all(input.tag) as unknown as ClosureProofJoinedRow[];
  const projected = allRows.map((row) => ({
    row,
    riskDisposition: closureAuthority.closureDisposition(row),
  }));
  const filtered = projected.filter(({ row, riskDisposition }) =>
    (input.issueNumber == null || row.issue_number === input.issueNumber) &&
    (!input.status || row.status === input.status) &&
    (!input.riskDisposition || riskDisposition === input.riskDisposition));
  const labelInfoByIssue = batchIssueLabelInfo(
    filtered.map(({ row }) => ({
      number: row.issue_number,
      labels: row.labels,
    })),
    input.labelCutoff,
  );
  const sortedRows = filtered
    .map(({ row, riskDisposition }) =>
      closureProofAuditItemFromSqlRow(
        row,
        labelInfoByIssue.get(row.issue_number),
        input.labelCutoff,
        riskDisposition,
      ))
    .sort((left, right) =>
      right.riskWeight - left.riskWeight ||
      (
        CLOSURE_PROOF_STATUS_RANK[
          left.status as keyof typeof CLOSURE_PROOF_STATUS_RANK
        ] ?? Number.MAX_SAFE_INTEGER
      ) - (
        CLOSURE_PROOF_STATUS_RANK[
          right.status as keyof typeof CLOSURE_PROOF_STATUS_RANK
        ] ?? Number.MAX_SAFE_INTEGER
      ) ||
      String(right.closedAt ?? '').localeCompare(String(left.closedAt ?? '')) ||
      left.number - right.number);
  const rows = sortedRows.slice(input.cursor, input.cursor + input.limit);
  const unfilteredCountsByStatus = closureStatusCountsForRows(projected);
  const filteredCountsByStatus = closureStatusCountsForRows(filtered);
  const unfilteredRows = projected.length;
  const filteredRows = filtered.length;
  const unfilteredDistinctIssues = distinctClosureIssueCount(projected);
  const filteredDistinctIssues = distinctClosureIssueCount(filtered);
  return {
    unfilteredRows,
    filteredRows,
    unfilteredDistinctIssues,
    filteredDistinctIssues,
    unfilteredCountsByStatus,
    filteredCountsByStatus,
    unfilteredCountsByRiskDisposition: riskDispositionCountsForRows(projected),
    filteredCountsByRiskDisposition: riskDispositionCountsForRows(filtered),
    rows,
    nextCursor: input.cursor + rows.length < filteredRows ? input.cursor + rows.length : null,
  };
}

function closureStatusCountsForRows(
  rows: Array<{ row: Pick<ClosureProofJoinedRow, 'status'> }>,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const { row } of rows) {
    counts[row.status] = (counts[row.status] ?? 0) + 1;
  }
  return counts;
}

function distinctClosureIssueCount(
  rows: Array<{ row: Pick<ClosureProofJoinedRow, 'issue_number'> }>,
): number {
  return new Set(rows.map(({ row }) => row.issue_number)).size;
}

function riskDispositionCountsForRows(
  rows: Array<{ riskDisposition: string }>,
): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const { riskDisposition } of rows) {
    counts[riskDisposition] = (counts[riskDisposition] ?? 0) + 1;
  }
  return counts;
}

function sumCounts(counts: Record<string, number>): number {
  return Object.values(counts).reduce((sum, count) => sum + count, 0);
}

function closureProofAuditItemFromSqlRow(
  row: ClosureProofJoinedRow,
  labelInfo: BatchedIssueLabelInfo | undefined,
  labelCutoff: string | null,
  riskDisposition: ClosureProofAuditItem['riskDisposition'],
): ClosureProofAuditItem {
  const effective = effectiveClosureClassification(
    row,
    labelCutoff,
    labelInfo?.labels,
  );
  const riskWeight = roundMetric(closureRiskWeightForRow({
    status: row.status,
    sentiment: effective?.classification.sentiment ?? row.sentiment,
    severity: effective?.classification.severity ?? row.severity,
    scope: effective?.classification.scope ?? row.scope,
    functionality: effective?.classification.functionality ?? row.functionality,
    affected_users: effective?.classification.affectedUsers ?? row.affected_users,
  }, riskDisposition));
  return {
    number: row.issue_number,
    title: row.title,
    url: row.html_url,
    closedAt: row.closed_at,
    status: row.status,
    summary: row.summary,
    riskDisposition,
    riskWeight,
    checkedAt: row.checked_at,
    labels: effective?.labels ?? parseJson<string[]>(row.labels, []),
    classification: effective?.classification ?? null,
    classificationDiff: effective?.classificationDiff ?? {},
    evidence: parseJson(row.evidence_json, {}),
  };
}

interface ReachabilityPage {
  unfilteredRows: number;
  filteredRows: number;
  unfilteredPullRequests: number;
  filteredPullRequests: number;
  unfilteredCountsByStatus: Record<string, number>;
  filteredCountsByStatus: Record<string, number>;
  rows: ReleasePrReachabilityRow[];
  nextCursor: number | null;
}

function reachabilityPage(input: {
  tag: string;
  status: string | null;
  pr: { repo: string | null; number: number } | null;
  cursor: number;
  limit: number;
}): ReachabilityPage {
  const unfilteredWhere = {
    sql: 'r.tag=?',
    params: [input.tag] as Array<string | number>,
  };
  const clauses = ['r.tag=?'];
  const params: Array<string | number> = [input.tag];
  if (input.status) {
    clauses.push('r.status=?');
    params.push(input.status);
  }
  if (input.pr) {
    clauses.push('r.pr_number=?');
    params.push(input.pr.number);
    if (input.pr.repo) {
      clauses.push('LOWER(r.pr_repository_name_with_owner)=LOWER(?)');
      params.push(input.pr.repo);
    }
  }
  const filteredWhere = { sql: clauses.join(' AND '), params };
  const unfilteredCountsByStatus = reachabilityStatusCounts(unfilteredWhere);
  const filteredCountsByStatus = reachabilityStatusCounts(filteredWhere);
  const unfilteredRows = sumCounts(unfilteredCountsByStatus);
  const filteredRows = sumCounts(filteredCountsByStatus);
  const rows = db.prepare(`
    SELECT r.*,
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
    WHERE ${filteredWhere.sql}
    ORDER BY
      CASE r.status
        WHEN 'not_reachable' THEN 0
        WHEN 'unknown' THEN 1
        WHEN 'reachable' THEN 2
        ELSE 3
      END,
      r.pr_repository_name_with_owner,
      r.pr_number
    LIMIT ? OFFSET ?
  `).all(...filteredWhere.params, input.limit, input.cursor) as unknown as ReleasePrReachabilityRow[];
  return {
    unfilteredRows,
    filteredRows,
    unfilteredPullRequests: reachabilityDistinctCount(unfilteredWhere),
    filteredPullRequests: reachabilityDistinctCount(filteredWhere),
    unfilteredCountsByStatus,
    filteredCountsByStatus,
    rows,
    nextCursor: input.cursor + rows.length < filteredRows ? input.cursor + rows.length : null,
  };
}

function reachabilityStatusCounts(where: {
  sql: string;
  params: Array<string | number>;
}): Record<string, number> {
  const rows = db.prepare(`
    SELECT r.status, COUNT(*) AS count
    FROM release_pr_reachability r
    WHERE ${where.sql}
    GROUP BY r.status
  `).all(...where.params) as SqlStatusCountRow[];
  return Object.fromEntries(rows.map((row) => [row.status, Number(row.count ?? 0)]));
}

function reachabilityDistinctCount(where: {
  sql: string;
  params: Array<string | number>;
}): number {
  const row = db.prepare(`
    SELECT COUNT(DISTINCT LOWER(r.pr_repository_name_with_owner) || '#' || r.pr_number) AS count
    FROM release_pr_reachability r
    WHERE ${where.sql}
  `).get(...where.params) as SqlCountRow | undefined;
  return Number(row?.count ?? 0);
}

function reachabilityAuditResponseRow(row: ReleasePrReachabilityRow) {
  return {
    repositoryNameWithOwner: row.pr_repository_name_with_owner,
    number: row.pr_number,
    title: row.title,
    url: row.url,
    state: row.state,
    merged: row.merged === 1,
    mergedAt: row.merged_at,
    status: row.status,
    method: row.method,
    checkedAt: row.checked_at,
    tagCommitOid: row.tag_commit_oid,
    mergeCommitOid: row.merge_commit_oid,
    prMergeCommitOid: row.pr_merge_commit_oid,
    baseRefName: row.base_ref_name ?? row.pr_base_ref_name,
    evidence: parseJson(row.evidence_json, {}),
  };
}

function normalizeComparison(row: Record<string, unknown> | undefined) {
  if (!row) return null;
  return {
    schemaVersion: COMPARISON_UPSTREAM_SCHEMA_VERSION,
    snapshotId: row.snapshot_id,
    tag: row.tag,
    score: row.score,
    band: row.band,
    status: row.status,
    recommended: row.recommended === 1,
    reason: row.reason,
    negativeIssues: row.negative_issues,
    positiveIssues: row.positive_issues,
    totalAttributedIssues: row.total_attributed_issues,
    visibleIssues: parseJson(String(row.visible_issues_json ?? '[]'), [] as unknown[]),
    rawCardText: row.raw_card_text,
  };
}

function normalizeComparisonSnapshot(row: ReturnType<typeof latestComparisonSnapshot>) {
  if (!row) return null;
  return {
    id: row.id,
    sourceUrl: row.source_url,
    capturedAt: row.captured_at,
    pageTitle: row.page_title,
  };
}

function boundedHealthProblems(problems: string[]): string[] {
  return problems.slice(0, SEMANTIC_HEALTH_PROBLEM_LIMIT).map((problem) =>
    problem.length > SEMANTIC_HEALTH_PROBLEM_MAX_LENGTH
      ? `${problem.slice(0, SEMANTIC_HEALTH_PROBLEM_MAX_LENGTH - 3)}...`
      : problem);
}

function healthReleaseDiagnostics(release: {
  tag: string;
  published_at?: string | null;
  scored_at?: string | null;
  state?: string | null;
  recommended?: number | null;
}) {
  return {
    tag: release.tag,
    publishedAt: release.published_at ?? null,
    diagnosticScoredAt: release.scored_at ?? null,
    diagnosticStatus: release.state ?? null,
    diagnosticPreviouslyRecommended: release.recommended === 1,
  };
}

function activeScoreBlockingIngestionFailureCount(): number {
  const row = db.prepare(`
    SELECT COUNT(*) AS count
    FROM ingestion_evidence_failures
    WHERE scoring_blocking=1
      AND superseded_by_run_id IS NULL
  `).get() as { count: number } | undefined;
  return Number(row?.count ?? 0);
}

function semanticReadinessPayload() {
  const checkedAt = new Date().toISOString();
  const repo = `${config.github.owner}/${config.github.repo}`;
  return stableApiRead(() => {
    const blockers: Array<{ code: string; message: string }> = [];
    const block = (code: string, message: string) => {
      blockers.push({ code, message });
    };
    const releaseWindowProblem = boundedHealthProblems([
      formatStableReleaseWindowIntegrityFailure(stableReleaseWindowIntegrity(3)) ?? '',
    ].filter(Boolean))[0] ?? null;
    if (releaseWindowProblem) {
      block('release_window_invalid', 'Stable release publication windows are ambiguous or incomplete.');
    }
    const publicationGuard = scorePublicationGuardSnapshot();
    if (publicationGuard.activeRefresh) {
      block(
        'refresh_in_progress',
        'A score-input refresh is active; recommendations are withheld until it finishes.',
      );
    }
    const activeIngestionFailures = listActiveIngestionEvidenceFailures(
      SEMANTIC_HEALTH_PROBLEM_LIMIT,
    );
    const activeIngestionFailureCount =
      publicationGuard.activeScoreBlockingIngestionFailureCount;
    if (activeIngestionFailureCount > 0) {
      block(
        'score_blocking_ingestion_failure',
        'Active score-blocking ingestion failures have not been superseded by a clean run.',
      );
    }

    const currentTag =
      currentAuthorizedReleaseCatalog().latestStable?.tag ?? null;
    const latestScoredTag = latestScoredStableReleaseTag();
    const currentRelease = currentTag ? getRelease(currentTag) : undefined;
    if (
      !currentTag ||
      latestScoredTag !== currentTag ||
      !currentRelease
    ) {
      block('current_score_missing', 'No current scored stable release is available.');
      return {
        schemaVersion: SEMANTIC_HEALTH_SCHEMA_VERSION,
        ok: false,
        status: 'not_ready' as const,
        checkedAt,
        repo,
        currentRelease: null,
        checks: {
          database: { ok: true },
          releaseWindow: {
            ok: releaseWindowProblem == null,
            problem: releaseWindowProblem,
          },
          scoreAudit: {
            ok: false,
            causes: ['current_score_missing'],
            publicationProblems: [],
          },
          sourceIdentity: {
            ok: false,
            expectedSchemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
            persistedSchemaVersion: null,
            persistedDigest: null,
            currentDigest: null,
            problems: ['Current scored release is missing.'],
          },
          closureProof: {
            ok: false,
            problem: 'Current scored release is missing.',
          },
          recommendation: {
            ok: false,
            failureCount: 1,
            failures: ['Current scored release is missing.'],
          },
          ingestion: {
            ok: activeIngestionFailureCount === 0,
            activeScoreBlockingFailureCount: activeIngestionFailureCount,
            failures: activeIngestionFailures.map((failure) => ({
              id: failure.id,
              runId: failure.run_id,
              occurredAt: failure.occurred_at,
              source: failure.source,
              scope: failure.scope,
              releaseTag: failure.release_tag,
              issueNumber: failure.issue_number,
            })),
          },
        },
        failures: blockers,
      };
    }

    const currentSourceIdentityResult = currentScoreSourceIdentityResult();
    const currentSourceIdentity = currentSourceIdentityResult.value;
    const candidateContexts = listReleasesDb(config.limits.releases)
      .map((release) => ({
        release,
        audit: getReleaseScoreAudit(release.tag),
      }))
      .filter(({ release, audit }) =>
        audit != null ||
        release.scored_at != null ||
        release.final_score != null ||
        release.state != null ||
        release.recommended === 1)
      .map(({ release, audit }) => {
        const persistedSourceIdentity = parseJson<Record<string, any> | null>(
          audit?.source_identity_json,
          null,
        );
        const sourceIdentityManifestProblems = isRecord(persistedSourceIdentity)
          ? scoreSourceIdentityManifestProblems(persistedSourceIdentity)
          : ['Persisted score source identity is missing.'];
        const sourceIdentityCurrent =
          currentSourceIdentity != null &&
          sourceIdentityManifestProblems.length === 0 &&
          scoreSourceIdentityMatches(persistedSourceIdentity, currentSourceIdentity);
        const sourceIdentityProblems = sourceIdentityCurrent
          ? sourceIdentityManifestProblems
          : [
              ...sourceIdentityManifestProblems,
              ...(currentSourceIdentityResult.problem
                ? [currentSourceIdentityResult.problem]
                : []),
              'Persisted score source identity does not match the current score-input rows.',
            ];
        const publication = sealedScoreAuditPublication(release.tag);
        const compatibility = scoreAnalysisCompatibility(
          release,
          audit,
          currentSourceIdentity,
          publicationGuard,
        );
        const closureProof = releaseClosureProofIntegrity(release.tag, 3);
        const closureProofProblem = boundedHealthProblems([
          formatReleaseClosureProofIntegrityFailure(closureProof) ?? '',
        ].filter(Boolean))[0] ?? null;
        return {
          release,
          audit,
          persistedSourceIdentity,
          sourceIdentityCurrent,
          sourceIdentityProblems,
          publication,
          compatibility,
          closureProof,
          closureProofProblem,
        };
      });
    const currentContext = candidateContexts.find(({ release }) => release.tag === currentTag);
    if (!currentContext) {
      block(
        'current_score_missing',
        'The newest scored stable release is missing from the recommendation candidate set.',
      );
    }
    const incompatibleCandidates = candidateContexts.filter(({ compatibility }) =>
      !compatibility.usable);
    const staleSourceIdentityCandidates = candidateContexts.filter(({ sourceIdentityCurrent }) =>
      !sourceIdentityCurrent);
    const staleClosureProofCandidates = candidateContexts.filter(({ closureProofProblem }) =>
      closureProofProblem != null);
    const recommendation = currentRecommendationRun();

    if (incompatibleCandidates.length > 0) {
      block(
        'score_audit_incompatible',
        'One or more scored recommendation candidates have stale or incompatible audit publications.',
      );
    }
    if (staleSourceIdentityCandidates.length > 0) {
      block(
        'score_source_identity_stale',
        'One or more scored recommendation candidates do not match the current score-input rows.',
      );
    }
    if (staleClosureProofCandidates.length > 0) {
      block(
        'closure_proof_integrity_stale',
        'One or more scored recommendation candidates have stale closure-proof evidence or dependency snapshots.',
      );
    }
    if (recommendation.failures.length > 0) {
      block(
        'recommendation_run_invalid',
        'The persisted recommendation run does not satisfy the current recommendation contract.',
      );
    }

    const ok = blockers.length === 0;
    return {
      schemaVersion: SEMANTIC_HEALTH_SCHEMA_VERSION,
      ok,
      status: ok ? 'ready' as const : 'not_ready' as const,
      checkedAt,
      repo,
      currentRelease: healthReleaseDiagnostics(currentRelease),
      checks: {
        database: { ok: true },
        releaseWindow: {
          ok: releaseWindowProblem == null,
          problem: releaseWindowProblem,
        },
        scoreAudit: {
          ok: incompatibleCandidates.length === 0 && currentContext != null,
          releaseCount: candidateContexts.length,
          staleReleaseTags: incompatibleCandidates.map(({ release }) => release.tag),
          auditDigest: currentContext?.publication.digest ?? null,
          authorityRunId:
            currentContext?.publication.authorityRun?.authorityRunId ?? null,
          authorityRunContentHash:
            currentContext?.publication.authorityRun?.contentHash ?? null,
          historyV2SealContentHash:
            currentContext?.publication.historyV2Seal?.contentHash ?? null,
          modelVersion: currentContext?.audit?.score_model_version ?? null,
          expectedModelVersion: SCORE_MODEL_VERSION,
          promptVersion: currentContext?.audit?.prompt_version ?? null,
          expectedPromptVersion: PROMPT_VERSION,
          causes: [...new Set(candidateContexts.flatMap(({ compatibility }) =>
            compatibility.staleAudit?.causes ?? []))],
          publicationProblems: boundedHealthProblems(candidateContexts.flatMap(
            ({ publication }) => publication.problems,
          )),
          releases: candidateContexts.map(({ release, audit, publication, compatibility }) => ({
            ...healthReleaseDiagnostics(release),
            ok: compatibility.usable,
            auditDigest: publication.digest,
            authorityRunId: publication.authorityRun?.authorityRunId ?? null,
            authorityRunContentHash:
              publication.authorityRun?.contentHash ?? null,
            historyV2SealContentHash:
              publication.historyV2Seal?.contentHash ?? null,
            modelVersion: audit?.score_model_version ?? null,
            promptVersion: audit?.prompt_version ?? null,
            causes: compatibility.staleAudit?.causes ?? [],
            publicationProblems: boundedHealthProblems(publication.problems),
          })),
        },
        sourceIdentity: {
          ok: staleSourceIdentityCandidates.length === 0 && currentContext != null,
          releaseCount: candidateContexts.length,
          staleReleaseTags: staleSourceIdentityCandidates.map(({ release }) => release.tag),
          expectedSchemaVersion: SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
          persistedSchemaVersion: currentContext?.persistedSourceIdentity?.schemaVersion ?? null,
          persistedDigest: currentContext?.persistedSourceIdentity?.digest ?? null,
          currentDigest: currentSourceIdentity?.digest ?? null,
          problems: boundedHealthProblems(candidateContexts.flatMap(
            ({ sourceIdentityProblems }) => sourceIdentityProblems,
          )),
          releases: candidateContexts.map(({
            release,
            persistedSourceIdentity,
            sourceIdentityCurrent,
            sourceIdentityProblems,
          }) => ({
            ...healthReleaseDiagnostics(release),
            ok: sourceIdentityCurrent,
            persistedSchemaVersion: persistedSourceIdentity?.schemaVersion ?? null,
            persistedDigest: persistedSourceIdentity?.digest ?? null,
            problems: boundedHealthProblems(sourceIdentityProblems),
          })),
        },
        closureProof: {
          ok: staleClosureProofCandidates.length === 0 && currentContext != null,
          releaseCount: candidateContexts.length,
          staleReleaseTags: staleClosureProofCandidates.map(({ release }) => release.tag),
          rawClosedCount: currentContext?.closureProof.rawClosedCount ?? 0,
          proofRowCount: currentContext?.closureProof.proofRowCount ?? 0,
          missingCount: currentContext?.closureProof.missingCount ?? 0,
          extraCount: currentContext?.closureProof.extraCount ?? 0,
          staleCount: currentContext?.closureProof.staleCount ?? 0,
          analyzerVersionMismatchCount:
            currentContext?.closureProof.analyzerVersionMismatchCount ?? 0,
          dependencySnapshotMissingCount:
            currentContext?.closureProof.dependencySnapshotMissingCount ?? 0,
          dependencySnapshotMismatchCount:
            currentContext?.closureProof.dependencySnapshotMismatchCount ?? 0,
          problem: currentContext?.closureProofProblem ?? null,
          releases: candidateContexts.map(({ release, closureProof, closureProofProblem }) => ({
            ...healthReleaseDiagnostics(release),
            ok: closureProofProblem == null,
            rawClosedCount: closureProof.rawClosedCount,
            proofRowCount: closureProof.proofRowCount,
            missingCount: closureProof.missingCount,
            extraCount: closureProof.extraCount,
            staleCount: closureProof.staleCount,
            analyzerVersionMismatchCount: closureProof.analyzerVersionMismatchCount,
            dependencySnapshotMissingCount: closureProof.dependencySnapshotMissingCount,
            dependencySnapshotMismatchCount: closureProof.dependencySnapshotMismatchCount,
            problem: closureProofProblem,
          })),
        },
        recommendation: {
          ok: recommendation.failures.length === 0,
          failureCount: recommendation.failures.length,
          failures: boundedHealthProblems(recommendation.failures),
        },
        ingestion: {
          ok: activeIngestionFailureCount === 0,
          activeScoreBlockingFailureCount: activeIngestionFailureCount,
          failures: activeIngestionFailures.map((failure) => ({
            id: failure.id,
            runId: failure.run_id,
            occurredAt: failure.occurred_at,
            source: failure.source,
            scope: failure.scope,
            releaseTag: failure.release_tag,
            issueNumber: failure.issue_number,
          })),
        },
      },
      failures: blockers,
    };
  });
}

api.get('/live', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  res.json({
    ok: true,
    status: 'live',
    repo: `${config.github.owner}/${config.github.repo}`,
  });
});

api.get('/health', (_req, res) => {
  res.set('Cache-Control', 'no-store');
  try {
    const payload = semanticReadinessPayload();
    res.status(payload.ok ? 200 : 503).json(payload);
  } catch {
    res.status(503).json({
      schemaVersion: SEMANTIC_HEALTH_SCHEMA_VERSION,
      ok: false,
      status: 'unavailable',
      checkedAt: new Date().toISOString(),
      repo: `${config.github.owner}/${config.github.repo}`,
      currentRelease: null,
      checks: {
        database: {
          ok: false,
          problem: 'Semantic readiness could not read a stable database snapshot.',
        },
      },
      failures: [{
        code: 'readiness_unavailable',
        message: 'Semantic readiness could not be evaluated.',
      }],
    });
  }
});

// UI config — lets the frontend respect server-side limits without hardcoding.
api.get('/config', (_req, res) => {
  res.json({
    schemaVersion: CONFIG_PAYLOAD_SCHEMA_VERSION,
    releases: config.limits.releases,
    refreshMinutes: config.refresh.intervalMinutes,
  });
});

api.get('/status', (_req, res) => {
  const state = apiRefreshState();
  try {
    const payload = stableApiRead(() => {
      const publicationSnapshotId = releaseSnapshotId(scoreApiSourceEpoch());
      const attempts = listRefreshOperationAttempts();
      const receipts = listRefreshCaptureReceipts();
      const latestAttempt = newestByTimestamp(attempts, (attempt) => attempt.started_at);
      const latestTerminal = newestByTimestamp(receipts, (receipt) => receipt.finished_at);
      const latestSuccess = newestByTimestamp(
        receipts.filter((receipt) => receipt.status === 'success'),
        (receipt) => receipt.finished_at,
      );
      const latestFailure = newestByTimestamp(
        receipts.filter((receipt) => receipt.status === 'failure'),
        (receipt) => receipt.finished_at,
      );
      const durableActivity = durableRefreshActivitySnapshot();
      const activeAttempt = durableActivity.activeAttempt;
      const activeStage = activeAttempt
        ? activeOperationStage(listRefreshOperationStageEvents(activeAttempt.run_id))
        : null;
      const refreshing = state.refreshing || durableActivity.active;
      const latestStableTag =
        currentAuthorizedReleaseCatalog().latestStable?.tag ?? null;
      const latestScoredTag = latestScoredStableReleaseTag();
      const currentScoreTargetsLatestStable =
        latestStableTag != null &&
        latestScoredTag === latestStableTag;
      const lastScoredAt = currentScoreTargetsLatestStable
        ? getLastScoredAt()
        : null;
      const issueCrawl = parseJson<Record<string, unknown> | null>(
        getMeta('issue_crawl_last_run'),
        null,
      );
      const scorePersistence = parseJson<Record<string, unknown> | null>(
        getMeta('score_persistence_last_run'),
        null,
      );
      const currentScoreRunId = typeof scorePersistence?.operationRunId === 'string'
        ? scorePersistence.operationRunId
        : null;
      const currentScoreReceipt = currentScoreRunId
        ? receipts.find((receipt) => receipt.run_id === currentScoreRunId) ?? null
        : null;
      const currentPublication = currentScoreTargetsLatestStable && latestScoredTag
        ? getSealedReleaseScoreAuditPublication(latestScoredTag)
        : null;
      const currentPublicationValid = currentPublication?.valid === true;
      const durableLastRefreshAt = durableSuccessfulRefreshAt(
        scorePersistence,
        currentPublicationValid,
      );
      const durableReceiptError = durableRefreshReceiptFailure(
        scorePersistence,
        currentPublicationValid,
      );
      const durableCrawlError = durableRefreshFailure(issueCrawl);
      const resolvedStatus = resolveRefreshStatus({
        processLastRefreshAt: state.processLastRefreshAt,
        processLastError: state.lastError,
        processLastErrorAt:
          state.lastError && latestTerminal?.status !== 'success'
            ? latestTerminal?.finished_at ?? null
            : null,
        durableLastRefreshAt,
        durableErrors: [durableReceiptError, durableCrawlError]
          .filter((error): error is TimestampedRefreshError => error != null),
      });
      const currentScoreAuthorizationStatus = !currentScoreTargetsLatestStable
        ? 'unavailable'
        : !scorePersistence
        ? 'unavailable'
        // Non-refresh publications have no refresh receipt to authorize them.
        // Keep this exception narrow and let the API, not the UI, decide it.
        : scorePersistence.source !== 'refresh'
          ? 'not_required'
          : !currentScoreRunId || !currentScoreReceipt
            ? 'missing'
            : currentScoreReceipt.status !== 'success' || !currentPublicationValid
              ? 'unauthorized'
              : 'authorized';
      const currentScoreAuthorizationSnapshotId =
        currentScoreAuthorizationStatus === 'authorized' ||
        currentScoreAuthorizationStatus === 'not_required'
          ? publicationSnapshotId
          : null;
      return {
        snapshotId: publicationSnapshotId,
        publicationSnapshotId,
        refreshing,
        lastRefreshAt: resolvedStatus.lastRefreshAt,
        lastError: refreshing ? null : resolvedStatus.lastError,
        lastScoredAt,
        latestStableTag,
        latestScoredTag,
        dataFreshness:
          currentScoreTargetsLatestStable && latestScoredTag
            ? releaseDataFreshness(latestScoredTag)
            : null,
        activeRunId: activeAttempt?.run_id ?? null,
        activeOperation: activeAttempt?.operation ?? null,
        activeTrigger: activeAttempt?.trigger ?? null,
        activeStartedAt: activeAttempt?.started_at ?? null,
        activeLeaseExpiresAt: durableActivity.activeLease?.expires_at ?? null,
        activeStage,
        latestAttemptRunId: latestAttempt?.run_id ?? null,
        latestTerminalReceiptId: latestTerminal?.receipt_id ?? null,
        latestTerminalReceiptStatus: latestTerminal?.status ?? null,
        latestSuccessReceiptId: latestSuccess?.receipt_id ?? null,
        latestSuccessRunId: latestSuccess?.run_id ?? null,
        latestFailureReceiptId: latestFailure?.receipt_id ?? null,
        latestFailureRunId: latestFailure?.run_id ?? null,
        currentScoreRunId,
        currentScoreReceiptId: currentScoreReceipt?.receipt_id ?? null,
        currentScoreReceiptStatus: currentScoreReceipt?.status ?? null,
        currentScoreAuthorizationStatus,
        currentScoreAuthorizationSnapshotId,
      };
    });
    res.set(RELEASE_SNAPSHOT_HEADER, payload.publicationSnapshotId);
    res.json({
      schemaVersion: STATUS_PAYLOAD_SCHEMA_VERSION,
      ...state,
      ...payload,
      processLastRefreshAt: state.processLastRefreshAt,
    });
  } catch (error) {
    if (error instanceof ApiSourceSnapshotChangedError) {
      res.status(409).json({ error: 'source snapshot changed; retry request' });
      return;
    }
    res.status(503).json({
      schemaVersion: STATUS_PAYLOAD_SCHEMA_VERSION,
      error: 'status unavailable',
    });
  }
});

api.get('/receipts', (req, res) => {
  const limit = strictBoundedInteger(
    req.query.limit,
    RECEIPT_DEFAULT_LIMIT,
    1,
    RECEIPT_MAX_LIMIT,
  );
  if (limit == null) {
    res.status(400).json({ error: 'invalid limit', limit: req.query.limit });
    return;
  }
  try {
    const snapshot = receiptLedgerSnapshot();
    const newest = snapshot.receipts.slice().reverse();
    const receipts = newest.slice(0, limit).map((receipt) =>
      normalizeReceiptRecord(snapshot, receipt, {
        stageLimit: RECEIPT_LIST_STAGE_LIMIT,
        payloadCharLimit: RECEIPT_LIST_PAYLOAD_CHAR_LIMIT,
        stageDetailCharLimit: RECEIPT_LIST_STAGE_DETAIL_CHAR_LIMIT,
      }));
    res.json({
      schemaVersion: RECEIPT_API_SCHEMA_VERSION,
      readEpoch: snapshot.readEpoch,
      limit,
      count: receipts.length,
      hasMore: newest.length > receipts.length,
      verification: receiptLedgerVerification(snapshot),
      validationProof: receiptValidationProof(snapshot),
      receipts,
    });
  } catch (error) {
    if (!(error instanceof ApiSourceSnapshotChangedError)) throw error;
    res.status(409).json({ error: 'source snapshot changed; retry request' });
  }
});

api.get('/receipts/:receiptId', (req, res) => {
  const identifier = validReceiptIdentifier(req.params.receiptId);
  if (!identifier) {
    res.status(400).json({ error: 'invalid receipt or run ID' });
    return;
  }
  try {
    const snapshot = receiptLedgerSnapshot();
    const receipt = snapshot.receipts.find((row) => row.receipt_id === identifier) ??
      snapshot.receipts.find((row) => row.run_id === identifier) ??
      null;
    if (!receipt) {
      res.status(404).json({
        error: 'receipt not found',
        receiptOrRunId: identifier,
      });
      return;
    }
    res.json({
      schemaVersion: RECEIPT_API_SCHEMA_VERSION,
      readEpoch: snapshot.readEpoch,
      matchedBy: receipt.receipt_id === identifier ? 'receipt_id' : 'run_id',
      verification: receiptLedgerVerification(snapshot),
      validationProof: receiptValidationProof(snapshot),
      receipt: normalizeReceiptRecord(snapshot, receipt, {
        stageLimit: RECEIPT_DETAIL_STAGE_LIMIT,
        payloadCharLimit: RECEIPT_DETAIL_PAYLOAD_CHAR_LIMIT,
        stageDetailCharLimit: RECEIPT_DETAIL_STAGE_DETAIL_CHAR_LIMIT,
      }),
    });
  } catch (error) {
    if (!(error instanceof ApiSourceSnapshotChangedError)) throw error;
    res.status(409).json({ error: 'source snapshot changed; retry request' });
  }
});

api.get('/validation/opportunities', (_req, res) => {
  try {
    const now = new Date().toISOString();
    const source = runInReadTransaction(() => {
      const latest = listReleasesDb(1)[0];
      const forecasts = listReleaseValidationForecasts();
      const auditHistory: ReleaseValidationAuditHistoryForDenominator[] = db.prepare(`
        SELECT run_id, recorded_at, score_model_version, prompt_version
        FROM release_score_audit_history
        ORDER BY recorded_at, id
      `).all().map((row) => ({
        run_id: String(row.run_id ?? ''),
        recorded_at: String(row.recorded_at ?? ''),
        score_model_version: String(row.score_model_version ?? ''),
        prompt_version: Number(row.prompt_version),
      }));
      return {
        latest,
        audit: latest ? getReleaseScoreAudit(latest.tag) : null,
        forecasts,
        denominatorLedger: buildReleaseValidationOpportunityDenominatorLedger({
          asOf: now,
          enrollments: listReleaseValidationOpportunityEnrollments(),
          forecasts,
          operationLedger: {
            attempts: listRefreshOperationAttempts(),
            stageEvents: listRefreshOperationStageEvents(),
            receipts: listRefreshCaptureReceipts(),
            leases: listRefreshLeases(),
            auditHistory,
          },
        }),
      };
    });
    res.json(buildReleaseValidationOpportunityStatus({
      now,
      denominatorLedger: source.denominatorLedger,
      forecasts: source.forecasts,
      currentSeries: {
        modelVersion: SCORE_MODEL_VERSION,
        promptVersion: PROMPT_VERSION,
        codeRevision: codeRevisionFromEnv() ?? 'unavailable',
      },
      currentAudit: source.audit ? {
        scoreModelVersion: source.audit.score_model_version,
        promptVersion: source.audit.prompt_version,
        scoredAt: source.audit.scored_at,
      } : null,
    }));
  } catch {
    res.status(503).json({
      schemaVersion: RELEASE_VALIDATION_OPPORTUNITY_STATUS_SCHEMA_VERSION,
      error: 'validation opportunity status unavailable',
    });
  }
});

// Maintainer-signal counts mined from the release-notes body + neighbouring releases.
// See lib/releaseNotes.ts. These are exposed for the UI to render without further
// computation, but the UI is intentionally NOT consuming them yet — we want to watch
// the numbers settle across a few refresh cycles before deciding how to surface them.
//
// `breakingCount` semantics: for a stable release, this is the AGGREGATE of its
// own `### Breaking` bullets plus those in every beta in the chain back to the
// previous stable. The maintainer typically lists a breaking change in the beta
// that introduced it and does NOT repeat the bullet when the stable promotes —
// so the stable's own body alone undercounts breakage that ships in it. See
// `computeAggregateBreaking` in lib/releaseNotes.ts. `fixesCount` / `changesCount`
// stay own-only because changelog generators DO re-list those at promotion.
function maintainerSignals(r: {
  breaking_count: number;
  fixes_count: number;
  changes_count: number;
  highlights_count: number;
  pr_refs_count: number;
  beta_count: number;
  hours_to_next_release: number | null;
  hours_to_next_stable: number | null;
}) {
  return {
    breakingCount:      r.breaking_count,
    fixesCount:         r.fixes_count,
    changesCount:       r.changes_count,
    highlightsCount:    r.highlights_count,
    prRefsCount:        r.pr_refs_count,
    betaCount:          r.beta_count,
    hoursToNextRelease: r.hours_to_next_release,
    hoursToNextStable:  r.hours_to_next_stable,
  };
}

const SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 2;
const LOCAL_AUDIT_SCHEMA_VERSION = 1;
const COMPARISON_PAYLOAD_SCHEMA_VERSION = 1;
const COMPARISON_UPSTREAM_SCHEMA_VERSION = 1;
const COMPARISON_DELTA_SCHEMA_VERSION = 1;
const STATUS_PAYLOAD_SCHEMA_VERSION = 1;
const CONFIG_PAYLOAD_SCHEMA_VERSION = 1;
const RELEASE_ROW_SCHEMA_VERSION = 2;
const RELEASE_HISTORY_ROW_SCHEMA_VERSION = 2;
const PROFILE_EVIDENCE_SCHEMA_VERSION = 2;
const PROFILE_EVIDENCE_PUBLICATION_BINDING_SCHEMA_VERSION = 1;
const RELEASE_SNAPSHOT_SCHEMA_VERSION = 1;
const RELEASE_SNAPSHOT_HEADER = 'X-Radar-Snapshot-Id';
const REVIEW_PUBLICATION_SNAPSHOT_PARAM = 'publicationSnapshot';
const REVIEW_AUDIT_DIGEST_PARAM = 'auditDigest';
const REVIEW_AUDIT_UNAVAILABLE = 'unavailable';

function releaseSnapshotId(dbEpoch: string): string {
  return createHash('sha256')
    .update(`release-snapshot:${dbEpoch}`)
    .digest('hex');
}

function releaseSnapshotMetadata(snapshotId: string) {
  return {
    schemaVersion: RELEASE_SNAPSHOT_SCHEMA_VERSION,
    id: snapshotId,
    generatedAt: new Date().toISOString(),
  };
}

type ReviewPublicationBinding = {
  publicationSnapshot: string;
  auditDigest: string;
};

function parseReviewPublicationBinding(
  query: Record<string, unknown>,
): { binding: ReviewPublicationBinding | null; error: 'missing' | 'invalid' | null } {
  const publicationSnapshot = singleQueryValue(
    query[REVIEW_PUBLICATION_SNAPSHOT_PARAM],
  );
  const auditDigest = singleQueryValue(query[REVIEW_AUDIT_DIGEST_PARAM]);
  if (publicationSnapshot === null || auditDigest === null) {
    return { binding: null, error: 'missing' };
  }
  if (
    publicationSnapshot === undefined ||
    auditDigest === undefined ||
    !/^[0-9a-f]{64}$/.test(publicationSnapshot) ||
    (
      auditDigest !== REVIEW_AUDIT_UNAVAILABLE &&
      !/^[0-9a-f]{64}$/.test(auditDigest)
    )
  ) {
    return { binding: null, error: 'invalid' };
  }
  return {
    binding: { publicationSnapshot, auditDigest },
    error: null,
  };
}

function rejectInvalidReviewPublicationBinding(
  res: Response,
  error: 'missing' | 'invalid',
): void {
  res.status(400).json({
    error: error === 'missing'
      ? 'publication snapshot and audit identity are required'
      : 'invalid publication snapshot or audit identity',
  });
}

function rejectChangedReviewPublication(res: Response, tag: string): void {
  res.status(409).json({
    error: 'publication snapshot or audit identity changed; reload parent review',
    tag,
  });
}

function reviewPublicationMatches(
  binding: ReviewPublicationBinding,
  publicationSnapshot: string,
  auditIdentity: string,
): boolean {
  return binding.publicationSnapshot === publicationSnapshot &&
    binding.auditDigest === auditIdentity;
}

function reviewPageLinks(
  req: Request,
  binding: ReviewPublicationBinding,
  cursor: number,
  limit: number,
  nextCursor: number | null,
) {
  const build = (pageCursor: number) => {
    const params = new URLSearchParams();
    for (const [key, value] of Object.entries(req.query)) {
      if (
        key === REVIEW_PUBLICATION_SNAPSHOT_PARAM ||
        key === REVIEW_AUDIT_DIGEST_PARAM ||
        key === 'cursor' ||
        key === 'limit'
      ) {
        continue;
      }
      if (Array.isArray(value)) {
        for (const item of value) {
          if (typeof item === 'string') params.append(key, item);
        }
      } else if (typeof value === 'string') {
        params.append(key, value);
      }
    }
    params.set(REVIEW_PUBLICATION_SNAPSHOT_PARAM, binding.publicationSnapshot);
    params.set(REVIEW_AUDIT_DIGEST_PARAM, binding.auditDigest);
    params.set('limit', String(limit));
    params.set('cursor', String(pageCursor));
    return `${req.baseUrl}${req.path}?${params.toString()}`;
  };
  return {
    self: build(cursor),
    next: nextCursor == null ? null : build(nextCursor),
  };
}

function scoreAuditSummary(
  audit: ReturnType<typeof getReleaseScoreAudit>,
  usable: boolean,
) {
  if (!audit || !usable) return null;
  const components = parseJson(audit.components_json, null) as any;
  const input = parseJson(audit.input_json, null) as any;
  const publication = sealedScoreAuditPublication(audit.release_tag);
  return {
    schemaVersion: SCORE_AUDIT_SUMMARY_SCHEMA_VERSION,
    reviewSchemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
    auditDigest: publication.digest,
    authorityRunId: publication.authorityRun?.authorityRunId ?? null,
    authorityRunContentHash: publication.authorityRun?.contentHash ?? null,
    historyV2SealContentHash: publication.historyV2Seal?.contentHash ?? null,
    modelVersion: audit.score_model_version,
    promptVersion: audit.prompt_version,
    evidenceCoverage: components?.evidenceCoverage ?? null,
    rawIssueCount: input?.rawIssueCount ?? null,
    classifiedIssueCount: input?.classifiedIssueCount ?? null,
  };
}

function freshnessForRelease(
  release: { tag: string; published_at: string | null; hours_to_next_stable?: number | null },
  audit: ReturnType<typeof getReleaseScoreAudit>,
) {
  currentApiDbEpoch();
  const cached = cachedReleaseFreshness.get(release.tag);
  if (cached) return cached;
  const labelRelease = {
    ...release,
    hours_to_next_stable: release.hours_to_next_stable ?? null,
  };
  const value = {
    ...releaseDataFreshness(release.tag),
    labelCutoffAt: releaseLabelCutoff(labelRelease, audit?.scored_at ?? null),
  };
  cachedReleaseFreshness.set(release.tag, value);
  return value;
}

function releaseAuditLinks(
  tag: string,
  snapshotId: string,
  auditDigest: string | null,
) {
  const encodedTag = encodeURIComponent(tag);
  const binding = new URLSearchParams({
    [REVIEW_PUBLICATION_SNAPSHOT_PARAM]: snapshotId,
    [REVIEW_AUDIT_DIGEST_PARAM]: auditDigest ?? REVIEW_AUDIT_UNAVAILABLE,
  }).toString();
  return {
    review: `/api/releases/${encodedTag}/review?${binding}`,
    issues: `/api/releases/${encodedTag}/review/issues?${binding}`,
    closureProofs: `/api/releases/${encodedTag}/review/closure-proofs?${binding}`,
    reachability: `/api/releases/${encodedTag}/review/reachability?${binding}`,
  };
}

function releaseAuditRawRows(
  tag: string,
  snapshotId: string,
  auditDigest: string,
) {
  const { issues, closureProofs, reachability } = releaseAuditLinks(
    tag,
    snapshotId,
    auditDigest,
  );
  return { issues, closureProofs, reachability };
}

function profileEvidenceForRelease(
  tag: string,
  sourceRows: ReleaseProfileEvidenceSourceRows,
  scoreAudit: ReturnType<typeof scoreAuditSummary>,
) {
  const evidence = releaseProfileEvidenceRows(tag, sourceRows);
  const profileRows = evidence?.rows ?? [];
  const profileRowsDigest = createHash('sha256')
    .update('release-profile-evidence-rows-v1\0')
    .update(canonicalJson({
      schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
      tag,
      rows: profileRows,
    }))
    .digest('hex');
  const publicationBinding = profileEvidencePublicationBinding(
    tag,
    scoreAudit,
    profileRowsDigest,
  );
  const bySurface = new Map<string, {
    label: string;
    icon: string;
    count: number;
    weight: number;
    tiers: Record<string, number>;
    weightByTier: Record<string, number>;
  }>();
  let issueCount = 0;
  let weightedIssueCount = 0;
  let surfaceIssueCount = 0;
  for (const row of profileRows) {
    const surface = surfaceOf(row.title);
    if (!surface) continue;
    const weight = row.weight;
    issueCount++;
    weightedIssueCount++;
    surfaceIssueCount++;
    const current = bySurface.get(surface.label) ?? {
      label: surface.label,
      icon: surface.icon,
      count: 0,
      weight: 0,
      tiers: {},
      weightByTier: {},
    };
    current.count += 1;
    current.weight += weight;
    current.tiers[row.tier] = (current.tiers[row.tier] ?? 0) + 1;
    current.weightByTier[row.tier] = (current.weightByTier[row.tier] ?? 0) + weight;
    bySurface.set(surface.label, current);
  }
  const surfaces = [...bySurface.values()]
    .map((surface) => ({
      ...surface,
      weight: roundMetric(surface.weight),
      weightByTier: Object.fromEntries(Object.entries(surface.weightByTier)
        .map(([tier, weight]) => [tier, roundMetric(weight)])),
    }))
    .sort((a, b) => b.weight - a.weight || a.label.localeCompare(b.label));
  const roundedSurfaceWeight = roundMetric(
    surfaces.reduce((sum, surface) => sum + surface.weight, 0),
  );
  return {
    schemaVersion: PROFILE_EVIDENCE_SCHEMA_VERSION,
    sourceMode: publicationBinding
      ? 'sealed_score_replay'
      : 'current_diagnostic_evidence',
    issueEvidenceSchemaVersion: ISSUE_EVIDENCE_SCHEMA_VERSION,
    profileRowCount: profileRows.length,
    profileRowsDigest,
    publicationBinding,
    issueCount,
    weightedIssueCount,
    surfaceIssueCount,
    surfaceWeight: roundedSurfaceWeight,
    surfaces,
  };
}

function profileEvidencePublicationBinding(
  tag: string,
  scoreAudit: ReturnType<typeof scoreAuditSummary>,
  profileRowsDigest: string,
) {
  if (!scoreAudit) return null;
  const audit = getReleaseScoreAudit(tag);
  if (!audit) {
    throw new Error(
      `Cannot bind public profile evidence for ${tag}: score audit is missing`,
    );
  }
  const publication = sealedScoreAuditPublication(tag);
  const sourceIdentity = parseJson<Record<string, unknown> | null>(
    audit.source_identity_json,
    null,
  );
  const sourceIdentityDigest =
    typeof sourceIdentity?.digest === 'string' &&
      /^[0-9a-f]{64}$/.test(sourceIdentity.digest)
      ? sourceIdentity.digest
      : null;
  if (
    publication.digest !== scoreAudit.auditDigest ||
    publication.authorityRun?.authorityRunId !== scoreAudit.authorityRunId ||
    publication.authorityRun?.contentHash !==
      scoreAudit.authorityRunContentHash ||
    publication.historyV2Seal?.contentHash !==
      scoreAudit.historyV2SealContentHash ||
    !sourceIdentityDigest
  ) {
    throw new Error(
      `Cannot bind public profile evidence for ${tag}: sealed publication ` +
        'identity does not match the score summary',
    );
  }
  const content = {
    schemaVersion: PROFILE_EVIDENCE_PUBLICATION_BINDING_SCHEMA_VERSION,
    auditDigest: scoreAudit.auditDigest,
    authorityRunId: scoreAudit.authorityRunId,
    authorityRunContentHash: scoreAudit.authorityRunContentHash,
    historyV2SealContentHash: scoreAudit.historyV2SealContentHash,
    sourceIdentityDigest,
    scoreModelVersion: scoreAudit.modelVersion,
    promptVersion: scoreAudit.promptVersion,
    profileRowsDigest,
  };
  return {
    ...content,
    contentHash: createHash('sha256')
      .update('release-profile-evidence-binding-v1\0')
      .update(canonicalJson(content))
      .digest('hex'),
  };
}

function roundMetric(value: unknown): number {
  const num = Number(value ?? 0);
  return Number.isFinite(num) ? Math.round(num * 1000) / 1000 : 0;
}

function reviewSourceProvenance(
  tag: string,
  snapshotId: string,
  scoredAt: string | null,
  dataFreshness: ReturnType<typeof freshnessForRelease>,
  audit: ReturnType<typeof getReleaseScoreAudit>,
) {
  const publication = audit
    ? sealedScoreAuditPublication(audit.release_tag)
    : null;
  const auditDigest = publication?.digest ?? REVIEW_AUDIT_UNAVAILABLE;
  return {
    sourceMode: 'current_db',
    scoreTable: 'release_score_audits',
    auditDigest: publication?.digest ?? null,
    scoreAuthority: publication
      ? {
          runId: publication.authorityRun?.authorityRunId ?? null,
          contentHash: publication.authorityRun?.contentHash ?? null,
          historyV2SealContentHash:
            publication.historyV2Seal?.contentHash ?? null,
        }
      : null,
    scoredAt,
    dataFreshnessScoredAt: dataFreshness.scoredAt,
    scoreTimestampAligned: scoredAt === dataFreshness.scoredAt,
    scoreSourceIdentity: parseJson(audit?.source_identity_json, null),
    advisorySnapshot: currentCompoundAdvisorySnapshotAuditProjection(),
    sources: dataFreshness.sources,
    rawRows: releaseAuditRawRows(
      tag,
      snapshotId,
      auditDigest,
    ),
  };
}

function buildReleaseApiPayloads(
  snapshotId = releaseSnapshotId(scoreApiSourceEpoch()),
  publicationGuard = scorePublicationGuardSnapshot(),
) {
  const snapshotMetadata = releaseSnapshotMetadata(snapshotId);
  const rows = listReleasesDb(Math.max(config.limits.releases, SCORE_HISTORY_CHART_LIMIT));
  const advisories = listAdvisories();
  const currentSourceIdentity = currentScoreSourceIdentityResult().value;
  const contexts = rows.map((release) => {
    const audit = getReleaseScoreAudit(release.tag);
    const presentation = scorePresentation(
      release,
      audit,
      currentSourceIdentity,
      publicationGuard,
    );
    const scoreAudit = scoreAuditSummary(audit, presentation.auditUsable);
    // Contract anchor: dataFreshness: freshnessForRelease(r, audit)
    // Contract anchor: releaseLabelCutoff(r, audit?.scored_at)
    return {
      release,
      audit,
      presentation,
      scoreAudit,
      dataFreshness: freshnessForRelease(release, presentation.auditUsable ? audit : undefined),
      auditLinks: releaseAuditLinks(
        release.tag,
        snapshotId,
        scoreAudit?.auditDigest ?? null,
      ),
    };
  });
  const focused = contexts.slice(0, config.limits.releases);
  const snapshot = {
    ...snapshotMetadata,
    actionable:
      focused.length > 0 &&
      focused.every((context) => context.presentation.auditUsable),
  };
  const releases = focused.map((context) => {
      const r = context.release;
      const status = advisoryStatusFor(r.tag, advisories);
      return {
        schemaVersion: RELEASE_ROW_SCHEMA_VERSION,
        snapshotId,
        tag: r.tag,
        name: r.name,
        publishedAt: r.published_at,
        htmlUrl: r.html_url,
        finalScore: context.presentation.score,
        band: context.presentation.band,
        status: context.presentation.status,
        diagnosticStatus: context.presentation.diagnosticStatus,
        recommended: context.presentation.recommended,
        reason: context.presentation.reason,
        brokenSurfaces: context.presentation.auditUsable ? parseBrokenSurfaces(r.broken_surfaces) : [],
        negativeIssues: context.presentation.auditUsable ? r.negative_issues : null,
        positiveIssues: context.presentation.auditUsable ? r.positive_issues : null,
        closedSeriousFixed: context.presentation.auditUsable ? r.closed_serious_fixed : null,
        openedSeriousDuringReign: context.presentation.auditUsable
          ? r.opened_serious_during_reign
          : null,
        scoredAt: context.presentation.auditUsable ? r.scored_at : null,
        scoreAudit: context.scoreAudit,
        staleAudit: context.presentation.staleAudit,
        explanation: context.presentation.explanation,
        dataFreshness: context.dataFreshness,
        auditLinks: context.auditLinks,
        advisories: {
          affected: summarizeAdvisories(status.affected),
          patched: summarizeAdvisories(status.patched),
        },
        maintainerSignals: maintainerSignals(r),
      };
    });
  const history = contexts
    .filter((context) => context.release.scored_at != null)
    .slice(0, SCORE_HISTORY_CHART_LIMIT)
    .map((context) => {
      const r = context.release;
      return {
        schemaVersion: RELEASE_HISTORY_ROW_SCHEMA_VERSION,
        snapshotId,
        tag: r.tag,
        publishedAt: r.published_at,
        finalScore: context.presentation.score,
        status: context.presentation.status,
        diagnosticStatus: context.presentation.diagnosticStatus,
        band: context.presentation.band,
        recommended: context.presentation.recommended,
        scoredAt: context.presentation.auditUsable ? r.scored_at : null,
        scoreAudit: context.scoreAudit,
        staleAudit: context.presentation.staleAudit,
        dataFreshness: context.dataFreshness,
        auditLinks: context.auditLinks,
      };
    });
  const publicBase = focused.map((context) => {
    const r = context.release;
    return {
      schemaVersion: PUBLIC_RELEASE_SCHEMA_VERSION,
      snapshotId,
      tag: r.tag,
      publishedAt: r.published_at,
      url: r.html_url,
      score: context.presentation.score,
      band: context.presentation.band,
      status: context.presentation.status,
      diagnosticStatus: context.presentation.diagnosticStatus,
      recommended: context.presentation.recommended,
      reason: context.presentation.reason,
      negativeIssues: context.presentation.auditUsable ? r.negative_issues ?? 0 : null,
      positiveIssues: context.presentation.auditUsable ? r.positive_issues ?? 0 : null,
      scoredAt: context.presentation.auditUsable ? r.scored_at : null,
      scoreAudit: context.scoreAudit,
      staleAudit: context.presentation.staleAudit,
      explanation: context.presentation.explanation,
      dataFreshness: context.dataFreshness,
      auditLinks: context.auditLinks,
    };
  });
  return {
    snapshot,
    releases,
    history,
    publicBase,
    updatedAt: getLastScoredAt(),
  };
}

type ReleaseApiPayloads = ReturnType<typeof buildReleaseApiPayloads>;

api.get('/releases', async (_req, res) => {
  try {
    const payload = await releaseApiPayloadsForCurrentEpoch();
    res.set(RELEASE_SNAPSHOT_HEADER, payload.snapshot.id);
    res.json(payload.releases);
  } catch {
    res.status(503).json({ error: 'release payload unavailable' });
  }
});

api.get('/releases/history', async (_req, res) => {
  try {
    const payload = await releaseApiPayloadsForCurrentEpoch();
    res.set(RELEASE_SNAPSHOT_HEADER, payload.snapshot.id);
    res.json(payload.history);
  } catch {
    res.status(503).json({ error: 'release history unavailable' });
  }
});

function buildComparisonPayload(
  publicationGuard = scorePublicationGuardSnapshot(),
) {
  const snapshot = normalizeComparisonSnapshot(latestComparisonSnapshot());
  const upstreamByTag = new Map(comparisonReleases().map((row) => [String(row.tag), row]));
  const currentSourceIdentity = currentScoreSourceIdentityResult().value;
  const releases = listReleasesDb(config.limits.releases).map((release) => {
    const audit = getReleaseScoreAudit(release.tag);
    const presentation = scorePresentation(
      release,
      audit,
      currentSourceIdentity,
      publicationGuard,
    );
    const upstream = normalizeComparison(upstreamByTag.get(release.tag));
    const localScore = presentation.score;
    const upstreamScore = typeof upstream?.score === 'number' ? upstream.score : null;
    return {
      tag: release.tag,
      local: {
        schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
        score: localScore,
        band: presentation.band,
        status: presentation.status,
        diagnosticStatus: presentation.diagnosticStatus,
        recommended: presentation.recommended,
        reason: presentation.reason,
        staleAudit: presentation.staleAudit,
        negativeIssues: presentation.auditUsable ? release.negative_issues : null,
        positiveIssues: presentation.auditUsable ? release.positive_issues : null,
        scoredAt: presentation.auditUsable ? release.scored_at : null,
        dataFreshness: freshnessForRelease(release, presentation.auditUsable ? audit : undefined),
        modelVersion: presentation.auditUsable ? audit?.score_model_version ?? null : null,
        components: presentation.auditUsable ? parseJson(audit?.components_json, null) : null,
        input: presentation.auditUsable ? parseJson(audit?.input_json, null) : null,
        gateEvidence: presentation.auditUsable ? parseJson(audit?.gate_evidence_json, null) : null,
      },
      upstream,
      delta: {
        schemaVersion: COMPARISON_DELTA_SCHEMA_VERSION,
        score: localScore != null && upstreamScore != null ? Math.round((localScore - upstreamScore) * 10) / 10 : null,
        negativeIssues:
          presentation.auditUsable &&
          release.negative_issues != null &&
          typeof upstream?.negativeIssues === 'number'
            ? release.negative_issues - upstream.negativeIssues
            : null,
      },
    };
  });
  return { schemaVersion: COMPARISON_PAYLOAD_SCHEMA_VERSION, snapshot, releases };
}

function buildParentReviewPayload(
  tag: string,
  snapshotId = releaseSnapshotId(scoreApiSourceEpoch()),
  publicationGuard = scorePublicationGuardSnapshot(),
) {
  const release = activeStableReleaseFromAuthorizedCatalog(tag);
  if (!release) return null;
  const audit = getReleaseScoreAudit(tag);
  const presentation = scorePresentation(
    release,
    audit,
    currentScoreSourceIdentityResult().value,
    publicationGuard,
  );
  const usableAudit = presentation.auditUsable ? audit : undefined;
  const gateEvidence = parseJson(usableAudit?.gate_evidence_json, null);
  const scoredAt = usableAudit ? release.scored_at : null;
  const dataFreshness = freshnessForRelease(release, usableAudit);
  const payload: Record<string, unknown> = {
    snapshotId,
    tag,
    local: {
      schemaVersion: LOCAL_AUDIT_SCHEMA_VERSION,
      score: presentation.score,
      band: presentation.band,
      status: presentation.status,
      diagnosticStatus: presentation.diagnosticStatus,
      recommended: presentation.recommended,
      reason: presentation.reason,
      staleAudit: presentation.staleAudit,
      negativeIssues: usableAudit ? release.negative_issues : null,
      positiveIssues: usableAudit ? release.positive_issues : null,
      scoredAt,
      dataFreshness,
      sourceProvenance: usableAudit
        ? reviewSourceProvenance(tag, snapshotId, scoredAt, dataFreshness, usableAudit)
        : null,
      auditDigest: scoreAuditIdentityDigest(usableAudit),
      modelVersion: usableAudit?.score_model_version ?? null,
      promptVersion: usableAudit?.prompt_version ?? null,
      input: parseJson(usableAudit?.input_json, null),
      components: parseJson(usableAudit?.components_json, null),
      issueEvidence: parseJson(usableAudit?.issue_evidence_json, null),
      gateEvidence,
    },
  };
  payload.auditLinks = releaseAuditLinks(
    tag,
    snapshotId,
    presentation.auditUsable ? scoreAuditIdentityDigest(audit) : null,
  );
  return payload;
}

api.get('/comparison', async (_req, res) => {
  if (!config.comparison.apiEnabled) {
    res.status(404).json({ error: 'comparison api disabled' });
    return;
  }
  try {
    res.json(await scoreReadPayloadForCurrentEpoch({ kind: 'comparison' }));
  } catch {
    res.status(503).json({ error: 'comparison payload unavailable' });
  }
});

api.get('/releases/:tag/review', async (req, res) => {
  const tag = req.params.tag;
  if (!requireActiveStableRelease(res, tag, 'release review unavailable')) {
    return;
  }
  const hasBinding =
    req.query[REVIEW_PUBLICATION_SNAPSHOT_PARAM] != null ||
    req.query[REVIEW_AUDIT_DIGEST_PARAM] != null;
  const parsedBinding = hasBinding
    ? parseReviewPublicationBinding(req.query)
    : { binding: null, error: null };
  if (hasBinding && !parsedBinding.binding) {
    rejectInvalidReviewPublicationBinding(res, parsedBinding.error!);
    return;
  }
  try {
    const payload = await scoreReadPayloadForCurrentEpoch({ kind: 'review', tag });
    if (!payload) {
      res.status(404).json({ error: 'release not found', tag });
      return;
    }
    const local = isRecord(payload.local) ? payload.local : null;
    if (
      parsedBinding.binding &&
      !reviewPublicationMatches(
        parsedBinding.binding,
        String(payload.snapshotId),
        typeof local?.auditDigest === 'string'
          ? local.auditDigest
          : REVIEW_AUDIT_UNAVAILABLE,
      )
    ) {
      rejectChangedReviewPublication(res, tag);
      return;
    }
    res.set(RELEASE_SNAPSHOT_HEADER, String(payload.snapshotId));
    res.json(payload);
  } catch {
    res.status(503).json({ error: 'release review unavailable', tag });
  }
});

api.get('/releases/:tag/review/issues', (req, res) => {
  const tag = req.params.tag;
  if (!requireActiveStableRelease(
    res,
    tag,
    'release issue evidence unavailable',
  )) {
    return;
  }
  const issueNumberFilter = parseIssueNumberFilter(req.query.issue, req.query.number);
  if (issueNumberFilter === undefined) {
    res.status(400).json({ error: 'invalid issue', issue: req.query.issue, number: req.query.number });
    return;
  }
  const tierFilter = parseIssueEvidenceTierFilter(req.query.tier);
  if (tierFilter && tierFilter.length === 0) {
    res.status(400).json({ error: 'invalid tier', tier: req.query.tier });
    return;
  }
  const impactFilter = parseIssueEvidenceImpactFilter(req.query.impact);
  if (impactFilter && impactFilter.length === 0) {
    res.status(400).json({ error: 'invalid impact', impact: req.query.impact });
    return;
  }
  const stateFilter = parseIssueEvidenceStateFilter(req.query.state);
  if (stateFilter && stateFilter.length === 0) {
    res.status(400).json({ error: 'invalid state', state: req.query.state });
    return;
  }
  const sentimentFilter = parseIssueEvidenceEnumFilter(req.query.sentiment, ISSUE_EVIDENCE_SENTIMENTS);
  if (sentimentFilter && sentimentFilter.length === 0) {
    res.status(400).json({ error: 'invalid sentiment', sentiment: req.query.sentiment });
    return;
  }
  const severityFilter = parseIssueEvidenceEnumFilter(req.query.severity, ISSUE_EVIDENCE_SEVERITIES);
  if (severityFilter && severityFilter.length === 0) {
    res.status(400).json({ error: 'invalid severity', severity: req.query.severity });
    return;
  }
  const functionalityFilter = parseIssueEvidenceEnumFilter(req.query.functionality, ISSUE_EVIDENCE_FUNCTIONALITIES);
  if (functionalityFilter && functionalityFilter.length === 0) {
    res.status(400).json({ error: 'invalid functionality', functionality: req.query.functionality });
    return;
  }
  const scopeFilter = parseIssueEvidenceEnumFilter(req.query.scope, ISSUE_EVIDENCE_SCOPES);
  if (scopeFilter && scopeFilter.length === 0) {
    res.status(400).json({ error: 'invalid scope', scope: req.query.scope });
    return;
  }
  const affectedUsersFilter = parseIssueEvidenceEnumFilter(req.query.affectedUsers, ISSUE_EVIDENCE_AFFECTED_USERS);
  if (affectedUsersFilter && affectedUsersFilter.length === 0) {
    res.status(400).json({ error: 'invalid affectedUsers', affectedUsers: req.query.affectedUsers });
    return;
  }
  const fieldConfirmedFilter = parseBooleanFilter(req.query.fieldConfirmed);
  if (fieldConfirmedFilter === undefined) {
    res.status(400).json({ error: 'invalid fieldConfirmed', fieldConfirmed: req.query.fieldConfirmed });
    return;
  }
  const minWeight = parseNumberFilter(req.query.minWeight);
  if (minWeight === undefined) {
    res.status(400).json({ error: 'invalid minWeight', minWeight: req.query.minWeight });
    return;
  }
  const maxWeight = parseNumberFilter(req.query.maxWeight);
  if (maxWeight === undefined) {
    res.status(400).json({ error: 'invalid maxWeight', maxWeight: req.query.maxWeight });
    return;
  }
  if (minWeight != null && maxWeight != null && minWeight > maxWeight) {
    res.status(400).json({ error: 'invalid weight range', minWeight, maxWeight });
    return;
  }
  const sort = parseIssueEvidenceSort(req.query.sort);
  if (!sort) {
    res.status(400).json({ error: 'invalid sort', sort: req.query.sort });
    return;
  }
  const direction = parseSortDirection(req.query.direction, sort);
  if (!direction) {
    res.status(400).json({ error: 'invalid direction', direction: req.query.direction });
    return;
  }
  const summaryOnly = parseBooleanFilter(req.query.summaryOnly);
  if (summaryOnly === undefined) {
    res.status(400).json({ error: 'invalid summaryOnly', summaryOnly: req.query.summaryOnly });
    return;
  }
  const limit = boundedInteger(req.query.limit, ISSUE_EVIDENCE_AUDIT_DEFAULT_LIMIT, 1, ISSUE_EVIDENCE_AUDIT_MAX_LIMIT);
  if (limit === undefined) {
    res.status(400).json({ error: 'invalid limit', limit: req.query.limit });
    return;
  }
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  if (cursor === undefined) {
    res.status(400).json({ error: 'invalid cursor', cursor: req.query.cursor });
    return;
  }
  const parsedBinding = parseReviewPublicationBinding(req.query);
  if (!parsedBinding.binding) {
    rejectInvalidReviewPublicationBinding(res, parsedBinding.error!);
    return;
  }
  const binding = parsedBinding.binding;
  const tierSet = tierFilter ? new Set(tierFilter) : null;
  const impactSet = impactFilter ? new Set(impactFilter) : null;
  const stateSet = stateFilter ? new Set(stateFilter) : null;
  const sentimentSet = sentimentFilter ? new Set(sentimentFilter) : null;
  const severitySet = severityFilter ? new Set(severityFilter) : null;
  const functionalitySet = functionalityFilter ? new Set(functionalityFilter) : null;
  const scopeSet = scopeFilter ? new Set(scopeFilter) : null;
  const affectedUsersSet = affectedUsersFilter ? new Set(affectedUsersFilter) : null;
  let snapshot;
  try {
    snapshot = stableApiRead(() => {
      const release = activeStableReleaseFromAuthorizedCatalog(tag);
      if (!release) return null;
      const audit = getReleaseScoreAudit(tag);
      const presentation = scorePresentation(
        release,
        audit,
        currentScoreSourceIdentityResult().value,
      );
      const evidenceAudit = presentation.auditUsable ? audit : undefined;
      const publicationSnapshot = releaseSnapshotId(scoreApiSourceEpoch());
      const auditDigest = scoreAuditIdentityDigest(evidenceAudit);
      const auditIdentity = auditDigest ?? REVIEW_AUDIT_UNAVAILABLE;
      if (!reviewPublicationMatches(binding, publicationSnapshot, auditIdentity)) {
        return {
          identityMismatch: true as const,
          publicationSnapshot,
          auditDigest,
          auditIdentity,
        };
      }
      const evidence = releaseIssueEvidencePage(tag, {
        cursor,
        limit,
        summaryOnly: summaryOnly === true,
        direction,
        matches: (row) =>
          (!tierSet || tierSet.has(row.tier)) &&
          (!impactSet || impactSet.has(row.installImpactClass as ReleaseIssueEvidenceImpactClass)) &&
          (!stateSet || stateSet.has(issueEvidenceState(row))) &&
          (!sentimentSet || sentimentSet.has(issueClassificationField(row, 'sentiment') as any)) &&
          (!severitySet || severitySet.has(issueClassificationField(row, 'severity') as any)) &&
          (!functionalitySet || functionalitySet.has(issueClassificationField(row, 'functionality') as any)) &&
          (!scopeSet || scopeSet.has(issueClassificationField(row, 'scope') as any)) &&
          (!affectedUsersSet || affectedUsersSet.has(issueClassificationField(row, 'affectedUsers') as any)) &&
          (issueNumberFilter == null || Number(row.issue?.number) === issueNumberFilter) &&
          (fieldConfirmedFilter == null || row.fieldConfirmed === fieldConfirmedFilter) &&
          (minWeight == null || Number(row.weight ?? 0) >= minWeight) &&
          (maxWeight == null || Number(row.weight ?? 0) <= maxWeight),
        sortValue: (row, rank) => sort === 'rank' ? rank : issueEvidenceSortValue(row, sort),
      });
      return evidence
        ? {
            identityMismatch: false as const,
            publicationSnapshot,
            auditDigest,
            auditIdentity,
            release,
            presentation,
            evidence,
            dataFreshness: freshnessForRelease(release, evidenceAudit),
          }
        : null;
    });
  } catch (error) {
    if (error instanceof ApiSourceSnapshotChangedError) {
      res.status(409).json({ error: 'source snapshot changed; retry request', tag });
    } else {
      res.status(503).json({ error: 'release issue evidence unavailable', tag });
    }
    return;
  }
  if (!snapshot) {
    res.status(404).json({ error: 'release evidence not found', tag });
    return;
  }
  if (snapshot.identityMismatch) {
    rejectChangedReviewPublication(res, tag);
    return;
  }
  const {
    publicationSnapshot,
    auditDigest,
    auditIdentity,
    release,
    presentation,
    evidence,
    dataFreshness,
  } = snapshot;
  const links = reviewPageLinks(
    req,
    binding,
    summaryOnly ? 0 : cursor,
    summaryOnly ? 0 : limit,
    evidence.nextCursor,
  );
  res.set(RELEASE_SNAPSHOT_HEADER, publicationSnapshot);
  res.json({
    schemaVersion: RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
    snapshotId: publicationSnapshot,
    auditDigest,
    auditIdentity,
    tag,
    sourceMode: 'current_db',
    scoredAt: presentation.auditUsable ? release.scored_at : null,
    staleAudit: presentation.staleAudit,
    dataFreshness,
    labelCutoffAt: evidence.labelCutoffAt,
    filters: {
      tier: tierFilter?.length === 1 ? tierFilter[0] : null,
      tiers: tierFilter ?? null,
      impact: impactFilter?.length === 1 ? impactFilter[0] : null,
      impacts: impactFilter ?? null,
      state: stateFilter?.length === 1 ? stateFilter[0] : null,
      states: stateFilter ?? null,
      sentiment: sentimentFilter?.length === 1 ? sentimentFilter[0] : null,
      sentiments: sentimentFilter ?? null,
      severity: severityFilter?.length === 1 ? severityFilter[0] : null,
      severities: severityFilter ?? null,
      functionality: functionalityFilter?.length === 1 ? functionalityFilter[0] : null,
      functionalities: functionalityFilter ?? null,
      scope: scopeFilter?.length === 1 ? scopeFilter[0] : null,
      scopes: scopeFilter ?? null,
      affectedUsers: affectedUsersFilter?.length === 1 ? affectedUsersFilter[0] : null,
      affectedUsersList: affectedUsersFilter ?? null,
      issue: issueNumberFilter,
      issueNumber: issueNumberFilter,
      fieldConfirmed: fieldConfirmedFilter,
      minWeight,
      maxWeight,
      sort,
      direction,
      summaryOnly: summaryOnly === true,
    },
    countsByTier: evidence.countsByTier,
    summaryByTier: evidence.summaryByTier,
    unfilteredCountsByTier: evidence.countsByTier,
    unfilteredSummaryByTier: evidence.summaryByTier,
    filteredCountsByTier: evidence.filteredCountsByTier,
    filteredSummaryByTier: evidence.filteredSummaryByTier,
    filteredSummary: evidence.filteredSummary,
    tierInfo: evidence.tierInfo,
    totals: evidence.totals,
    total: evidence.totals.filteredRows,
    totalRows: evidence.totals.filteredRows,
    distinctIssueCount: evidence.totals.filteredDistinctIssues,
    limit: summaryOnly ? 0 : limit,
    cursor: summaryOnly ? 0 : cursor,
    nextCursor: evidence.nextCursor,
    links,
    rows: evidence.rows,
  });
});

api.get('/releases/:tag/review/closure-proofs', (req, res) => {
  const tag = req.params.tag;
  if (!requireActiveStableRelease(
    res,
    tag,
    'release closure proof evidence unavailable',
  )) {
    return;
  }
  const issueNumberFilter = parseIssueNumberFilter(req.query.issue, req.query.number);
  if (issueNumberFilter === undefined) {
    res.status(400).json({ error: 'invalid issue', issue: req.query.issue, number: req.query.number });
    return;
  }
  const statusFilter = singleQueryValue(req.query.status);
  const riskDispositionFilter = singleQueryValue(req.query.riskDisposition);
  if (statusFilter === undefined) {
    res.status(400).json({
      error: 'invalid status',
      status: req.query.status,
      allowedStatuses: CLOSURE_PROOF_STATUSES,
    });
    return;
  }
  if (riskDispositionFilter === undefined) {
    res.status(400).json({
      error: 'invalid riskDisposition',
      riskDisposition: req.query.riskDisposition,
      allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
    });
    return;
  }
  if (statusFilter && !(CLOSURE_PROOF_STATUSES as readonly string[]).includes(statusFilter)) {
    res.status(400).json({
      error: 'invalid status',
      status: statusFilter,
      allowedStatuses: CLOSURE_PROOF_STATUSES,
    });
    return;
  }
  if (riskDispositionFilter && !(CLOSURE_RISK_DISPOSITIONS as readonly string[]).includes(riskDispositionFilter)) {
    res.status(400).json({
      error: 'invalid riskDisposition',
      riskDisposition: riskDispositionFilter,
      allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
    });
    return;
  }
  const limit = boundedInteger(req.query.limit, CLOSURE_PROOF_AUDIT_DEFAULT_LIMIT, 1, CLOSURE_PROOF_AUDIT_MAX_LIMIT);
  if (limit === undefined) {
    res.status(400).json({ error: 'invalid limit', limit: req.query.limit });
    return;
  }
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  if (cursor === undefined) {
    res.status(400).json({ error: 'invalid cursor', cursor: req.query.cursor });
    return;
  }
  const parsedBinding = parseReviewPublicationBinding(req.query);
  if (!parsedBinding.binding) {
    rejectInvalidReviewPublicationBinding(res, parsedBinding.error!);
    return;
  }
  const binding = parsedBinding.binding;
  let snapshot;
  try {
    snapshot = stableApiRead(() => {
      const release = activeStableReleaseFromAuthorizedCatalog(tag);
      if (!release) return null;
      const audit = getReleaseScoreAudit(tag);
      const presentation = scorePresentation(
        release,
        audit,
        currentScoreSourceIdentityResult().value,
      );
      const evidenceAudit = presentation.auditUsable ? audit : undefined;
      const publicationSnapshot = releaseSnapshotId(scoreApiSourceEpoch());
      const auditDigest = scoreAuditIdentityDigest(evidenceAudit);
      const auditIdentity = auditDigest ?? REVIEW_AUDIT_UNAVAILABLE;
      if (!reviewPublicationMatches(binding, publicationSnapshot, auditIdentity)) {
        return {
          identityMismatch: true as const,
          publicationSnapshot,
          auditDigest,
          auditIdentity,
        };
      }
      return {
        identityMismatch: false as const,
        publicationSnapshot,
        auditDigest,
        auditIdentity,
        release,
        presentation,
        dataFreshness: freshnessForRelease(release, evidenceAudit),
        page: closureProofPage({
          tag,
          labelCutoff: releaseLabelCutoff(release, evidenceAudit?.scored_at ?? null),
          authorityRunId: evidenceAudit?.authority_run_id ?? null,
          issueNumber: issueNumberFilter,
          status: statusFilter,
          riskDisposition: riskDispositionFilter,
          cursor,
          limit,
        }),
      };
    });
  } catch (error) {
    if (error instanceof ApiSourceSnapshotChangedError) {
      res.status(409).json({ error: 'source snapshot changed; retry request', tag });
    } else {
      res.status(503).json({
        error: 'release closure proof evidence unavailable',
        tag,
      });
    }
    return;
  }
  if (!snapshot) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  if (snapshot.identityMismatch) {
    rejectChangedReviewPublication(res, tag);
    return;
  }
  const {
    publicationSnapshot,
    auditDigest,
    auditIdentity,
    release,
    presentation,
    dataFreshness,
    page,
  } = snapshot;
  const links = reviewPageLinks(
    req,
    binding,
    cursor,
    limit,
    page.nextCursor,
  );
  res.set(RELEASE_SNAPSHOT_HEADER, publicationSnapshot);
  res.json({
    schemaVersion: CLOSURE_PROOF_AUDIT_SCHEMA_VERSION,
    snapshotId: publicationSnapshot,
    auditDigest,
    auditIdentity,
    tag,
    sourceMode: 'current_db',
    scoredAt: presentation.auditUsable ? release.scored_at : null,
    staleAudit: presentation.staleAudit,
    dataFreshness,
    filters: {
      issue: issueNumberFilter,
      issueNumber: issueNumberFilter,
      status: statusFilter,
      riskDisposition: riskDispositionFilter,
    },
    totals: {
      unfilteredRows: page.unfilteredRows,
      filteredRows: page.filteredRows,
      unfilteredDistinctIssues: page.unfilteredDistinctIssues,
      filteredDistinctIssues: page.filteredDistinctIssues,
    },
    total: page.filteredRows,
    totalRows: page.filteredRows,
    distinctIssueCount: page.filteredDistinctIssues,
    unfilteredCountsByStatus: page.unfilteredCountsByStatus,
    filteredCountsByStatus: page.filteredCountsByStatus,
    unfilteredCountsByRiskDisposition: page.unfilteredCountsByRiskDisposition,
    filteredCountsByRiskDisposition: page.filteredCountsByRiskDisposition,
    limit,
    cursor,
    nextCursor: page.nextCursor,
    links,
    rows: page.rows.map(closureProofAuditResponseRow),
  });
});

api.get('/releases/:tag/review/reachability', (req, res) => {
  const tag = req.params.tag;
  if (!requireActiveStableRelease(
    res,
    tag,
    'release reachability evidence unavailable',
  )) {
    return;
  }
  const statusFilter = singleQueryValue(req.query.status);
  if (statusFilter === undefined) {
    res.status(400).json({ error: 'invalid status', status: req.query.status });
    return;
  }
  if (statusFilter && !['reachable', 'not_reachable', 'unknown'].includes(statusFilter)) {
    res.status(400).json({ error: 'invalid status', status: statusFilter });
    return;
  }
  const prValue = singleQueryValue(req.query.pr);
  const prFilter = prValue ? parsePrFilter(prValue) : null;
  if (prValue === undefined || (prValue && !prFilter)) {
    res.status(400).json({ error: 'invalid pr filter', pr: req.query.pr });
    return;
  }
  const limit = boundedInteger(req.query.limit, PR_REACHABILITY_AUDIT_DEFAULT_LIMIT, 1, PR_REACHABILITY_AUDIT_MAX_LIMIT);
  if (limit === undefined) {
    res.status(400).json({ error: 'invalid limit', limit: req.query.limit });
    return;
  }
  const cursor = boundedInteger(req.query.cursor, 0, 0, Number.MAX_SAFE_INTEGER);
  if (cursor === undefined) {
    res.status(400).json({ error: 'invalid cursor', cursor: req.query.cursor });
    return;
  }
  const parsedBinding = parseReviewPublicationBinding(req.query);
  if (!parsedBinding.binding) {
    rejectInvalidReviewPublicationBinding(res, parsedBinding.error!);
    return;
  }
  const binding = parsedBinding.binding;
  let snapshot;
  try {
    snapshot = stableApiRead(() => {
      const release = activeStableReleaseFromAuthorizedCatalog(tag);
      if (!release) return null;
      const audit = getReleaseScoreAudit(tag);
      const presentation = scorePresentation(
        release,
        audit,
        currentScoreSourceIdentityResult().value,
      );
      const evidenceAudit = presentation.auditUsable ? audit : undefined;
      const publicationSnapshot = releaseSnapshotId(scoreApiSourceEpoch());
      const auditDigest = scoreAuditIdentityDigest(evidenceAudit);
      const auditIdentity = auditDigest ?? REVIEW_AUDIT_UNAVAILABLE;
      if (!reviewPublicationMatches(binding, publicationSnapshot, auditIdentity)) {
        return {
          identityMismatch: true as const,
          publicationSnapshot,
          auditDigest,
          auditIdentity,
        };
      }
      return {
        identityMismatch: false as const,
        publicationSnapshot,
        auditDigest,
        auditIdentity,
        release,
        presentation,
        dataFreshness: freshnessForRelease(release, evidenceAudit),
        page: reachabilityPage({
          tag,
          status: statusFilter,
          pr: prFilter,
          cursor,
          limit,
        }),
      };
    });
  } catch (error) {
    if (error instanceof ApiSourceSnapshotChangedError) {
      res.status(409).json({ error: 'source snapshot changed; retry request', tag });
    } else {
      res.status(503).json({
        error: 'release reachability evidence unavailable',
        tag,
      });
    }
    return;
  }
  if (!snapshot) {
    res.status(404).json({ error: 'release not found', tag });
    return;
  }
  if (snapshot.identityMismatch) {
    rejectChangedReviewPublication(res, tag);
    return;
  }
  const {
    publicationSnapshot,
    auditDigest,
    auditIdentity,
    release,
    presentation,
    dataFreshness,
    page,
  } = snapshot;
  const links = reviewPageLinks(
    req,
    binding,
    cursor,
    limit,
    page.nextCursor,
  );
  res.set(RELEASE_SNAPSHOT_HEADER, publicationSnapshot);
  res.json({
    schemaVersion: PR_REACHABILITY_AUDIT_SCHEMA_VERSION,
    snapshotId: publicationSnapshot,
    auditDigest,
    auditIdentity,
    tag,
    sourceMode: 'current_db',
    scoredAt: presentation.auditUsable ? release.scored_at : null,
    staleAudit: presentation.staleAudit,
    dataFreshness,
    filters: {
      status: statusFilter,
      pr: prFilter ? { repositoryNameWithOwner: prFilter.repo, number: prFilter.number } : null,
    },
    totals: {
      unfilteredRows: page.unfilteredRows,
      filteredRows: page.filteredRows,
      unfilteredPullRequests: page.unfilteredPullRequests,
      filteredPullRequests: page.filteredPullRequests,
    },
    total: page.filteredRows,
    totalRows: page.filteredRows,
    distinctPullRequestCount: page.filteredPullRequests,
    countsByStatus: page.filteredCountsByStatus,
    filteredCountsByStatus: page.filteredCountsByStatus,
    unfilteredCountsByStatus: page.unfilteredCountsByStatus,
    limit,
    cursor,
    nextCursor: page.nextCursor,
    links,
    rows: page.rows.map(reachabilityAuditResponseRow),
  });
});

// ── Public API ────────────────────────────────────────────────────────────────
// Single endpoint answering "which stable should I install right now?".
//
// score:       Install Confidence 0–10 (higher = stronger install confidence under current audit gates). null when 'wait'.
// band:        solid | ok | caution | weak | skip | wait
// status:      eligible | skip-cve | skip-hotfix | wait
// recommended: true for the strongest eligible release, with a bounded preference
//              for a newer release when confidence is within the recency tolerance.
// reason:      short human explanation of the verdict.
// sentiment / severity / scope / hasWorkaround: compact effective issue context.
// Detailed classifier confidence/rationale stays on review/audit endpoints, not /api/public.
//
// The score is NOT issue-volume based (that is confounded by how long/popular a
// release was). It comes from age/cadence-invariant signals: known CVEs, settle
// age, hotfix succession, stable-to-stable survival, beta shakeout depth, and the
// serious-bug close/open balance during the release's reign. See lib/score.ts.
//
// Data refreshes on a configurable interval (REFRESH_MINUTES). scoredAt = last time
// the score was computed for this specific release.

const PUBLIC_PAYLOAD_SCHEMA_VERSION = 4;
const PUBLIC_RELEASE_SCHEMA_VERSION = 4;
const RELEASE_API_WORKER_TIMEOUT_MS = 10_000;
const RELEASE_API_REQUEST_BUDGET_MS = 9_000;
const PUBLIC_PAYLOAD_WORKER_TIMEOUT_MS = 10_000;
const SCORE_READ_WORKER_TIMEOUT_MS = 10_000;
const SCORE_READ_REQUEST_BUDGET_MS = 9_000;
// A cold public request first joins the bounded release-index worker, then
// starts the public enrichment worker. Keep one measured end-to-end budget for
// that serialized path instead of running both memory-heavy workers at once.
const PUBLIC_PAYLOAD_REQUEST_BUDGET_MS = 15_000;
const PUBLIC_RETAINED_FALLBACK_MAX_AGE_MS = 30_000;
const PUBLIC_CURRENT_DIAGNOSTIC_MESSAGE =
  'Analysis is stale. Current public evidence is diagnostic only because the publication snapshot is non-actionable.';
const PUBLIC_RETAINED_DIAGNOSTIC_MESSAGE =
  'Analysis is stale. Retained public evidence is diagnostic only while a current snapshot is rebuilt.';

type PublicPayload = ReturnType<typeof buildPublicPayload>;

interface ReleaseApiWorkerData {
  databaseContext: typeof API_READ_WORKER_DATABASE_CONTEXT;
  databaseIdentity: ApiReadWorkerDatabaseIdentity;
  task: typeof RELEASE_API_WORKER_TASK;
  dbEpoch: string;
  publicationGuard: ScorePublicationGuard;
}

interface PublicPayloadWorkerData {
  databaseContext: typeof API_READ_WORKER_DATABASE_CONTEXT;
  databaseIdentity: ApiReadWorkerDatabaseIdentity;
  task: typeof PUBLIC_PAYLOAD_WORKER_TASK;
  dbEpoch: string;
  processLastRefreshAt: string | null;
  releaseApi: ReleaseApiPayloads;
}

type ScoreReadRequest =
  | { kind: 'comparison' }
  | { kind: 'review'; tag: string };

type ComparisonPayload = ReturnType<typeof buildComparisonPayload>;
type ParentReviewPayload = ReturnType<typeof buildParentReviewPayload>;
type ScoreReadPayload = ComparisonPayload | ParentReviewPayload;

interface ScoreReadWorkerData {
  databaseContext: typeof API_READ_WORKER_DATABASE_CONTEXT;
  databaseIdentity: ApiReadWorkerDatabaseIdentity;
  task: typeof SCORE_READ_WORKER_TASK;
  dbEpoch: string;
  publicationGuard: ScorePublicationGuard;
  request: ScoreReadRequest;
}

type WorkerMemory = {
  heapUsed: number;
  rss: number;
};

type ReleaseApiWorkerMessage = {
  ok: true;
  dbEpoch: string;
  payload: ReleaseApiPayloads;
  memory: WorkerMemory;
} | {
  ok: false;
  kind: 'epoch_changed' | 'error';
  message: string;
};

type PublicPayloadWorkerMessage = {
  ok: true;
  dbEpoch: string;
  payload: PublicPayload;
  memory: WorkerMemory;
} | {
  ok: false;
  kind: 'epoch_changed' | 'error';
  message: string;
};

type ScoreReadWorkerMessage = {
  ok: true;
  dbEpoch: string;
  payload: ScoreReadPayload;
  memory: WorkerMemory;
} | {
  ok: false;
  kind: 'epoch_changed' | 'error';
  message: string;
};

class ReleaseApiEpochChangedError extends Error {
  constructor() {
    super('Release API source rows changed during the build');
    this.name = 'ReleaseApiEpochChangedError';
  }
}

class ReleaseApiBuildSupersededError extends Error {
  constructor() {
    super('Release API build was superseded');
    this.name = 'ReleaseApiBuildSupersededError';
  }
}

class ScoreReadEpochChangedError extends Error {
  constructor() {
    super('Score-bearing API source rows changed during the build');
    this.name = 'ScoreReadEpochChangedError';
  }
}

class ScoreReadBuildSupersededError extends Error {
  constructor() {
    super('Score-bearing API build was superseded');
    this.name = 'ScoreReadBuildSupersededError';
  }
}

interface ManagedReleaseApiBuild {
  dbEpoch: string;
  worker: Worker;
  promise: Promise<ReleaseApiPayloads>;
  cancel: () => Promise<void>;
}

interface ManagedScoreReadBuild {
  key: string;
  requestKey: string;
  localEpoch: string;
  dbEpoch: string;
  worker: Worker;
  promise: Promise<ScoreReadPayload>;
  cancel: () => Promise<void>;
}

interface PayloadWorkerLifecycle {
  spawned: number;
  terminated: number;
  canceled: number;
  active: number;
  maxActive: number;
  lastWorkerHeapUsed: number;
  lastWorkerRss: number;
  lastError: string | null;
}

function emptyPayloadWorkerLifecycle(): PayloadWorkerLifecycle {
  return {
    spawned: 0,
    terminated: 0,
    canceled: 0,
    active: 0,
    maxActive: 0,
    lastWorkerHeapUsed: 0,
    lastWorkerRss: 0,
    lastError: null,
  };
}

function apiWorkerLaunch(filename = __filename): {
  filename: string;
  execArgv: string[];
  eval?: true;
} {
  if (!filename.endsWith('.ts')) {
    return { filename, execArgv: [] };
  }

  return {
    filename: [
      "void import('tsx')",
      `.then(() => require(${JSON.stringify(filename)}))`,
      '.catch((error) => { setImmediate(() => { throw error; }); });',
    ].join(''),
    execArgv: [],
    eval: true,
  };
}

function apiWorkerEnvironment(): NodeJS.ProcessEnv {
  return {
    ...process.env,
    NODE_TEST_CONTEXT: undefined,
  };
}

const releaseApiWorkerLifecycle = emptyPayloadWorkerLifecycle();
let activeReleaseApiBuild: ManagedReleaseApiBuild | null = null;
let releaseApiBuildTransition: Promise<void> = Promise.resolve();
let cachedReleaseApiPayloads: {
  dbEpoch: string;
  payload: ReleaseApiPayloads;
} | null = null;

export function releaseApiWorkerLifecycleSnapshot() {
  return {
    ...releaseApiWorkerLifecycle,
    activeEpoch: activeReleaseApiBuild?.dbEpoch ?? null,
    cachedEpoch: cachedReleaseApiPayloads?.dbEpoch ?? null,
  };
}

export function resetReleaseApiWorkerLifecycleForTests(): void {
  if (releaseApiWorkerLifecycle.active !== 0) {
    throw new Error('Cannot reset release API worker lifecycle while a worker is active');
  }
  Object.assign(releaseApiWorkerLifecycle, emptyPayloadWorkerLifecycle());
  cachedReleaseApiPayloads = null;
}

function createManagedReleaseApiBuild(
  dbEpoch: string,
  publicationGuard: ScorePublicationGuard,
): ManagedReleaseApiBuild {
  const { filename, ...runtimeOptions } = apiWorkerLaunch();
  const worker = new Worker(filename, {
    ...runtimeOptions,
    env: apiWorkerEnvironment(),
    workerData: {
      databaseContext: API_READ_WORKER_DATABASE_CONTEXT,
      databaseIdentity: openedDatabaseFileIdentity(),
      task: RELEASE_API_WORKER_TASK,
      dbEpoch,
      publicationGuard,
    } satisfies ReleaseApiWorkerData,
    resourceLimits: {
      maxOldGenerationSizeMb: 192,
      maxYoungGenerationSizeMb: 16,
      codeRangeSizeMb: 32,
      stackSizeMb: 4,
    },
  });
  releaseApiWorkerLifecycle.spawned++;
  releaseApiWorkerLifecycle.active++;
  releaseApiWorkerLifecycle.maxActive = Math.max(
    releaseApiWorkerLifecycle.maxActive,
    releaseApiWorkerLifecycle.active,
  );

  let settled = false;
  let terminationRecorded = false;
  let terminationPromise: Promise<void> | null = null;
  let resolveBuild!: (payload: ReleaseApiPayloads) => void;
  let rejectBuild!: (error: Error) => void;
  const promise = new Promise<ReleaseApiPayloads>((resolve, reject) => {
    resolveBuild = resolve;
    rejectBuild = reject;
  });
  let build!: ManagedReleaseApiBuild;

  const recordTermination = () => {
    if (terminationRecorded) return;
    terminationRecorded = true;
    releaseApiWorkerLifecycle.terminated++;
    releaseApiWorkerLifecycle.active = Math.max(0, releaseApiWorkerLifecycle.active - 1);
    if (activeReleaseApiBuild === build) activeReleaseApiBuild = null;
  };
  const terminate = (): Promise<void> => {
    if (terminationPromise) return terminationPromise;
    terminationPromise = worker.terminate()
      .then(() => undefined)
      .catch(() => undefined)
      .finally(recordTermination);
    return terminationPromise;
  };
  const settle = async (
    outcome: { payload: ReleaseApiPayloads; memory: WorkerMemory } | { error: Error },
  ): Promise<void> => {
    if (settled) return terminationPromise ?? Promise.resolve();
    settled = true;
    clearTimeout(timeout);
    await terminate();
    if ('payload' in outcome) {
      releaseApiWorkerLifecycle.lastWorkerHeapUsed = outcome.memory.heapUsed;
      releaseApiWorkerLifecycle.lastWorkerRss = outcome.memory.rss;
      resolveBuild(outcome.payload);
    } else {
      rejectBuild(outcome.error);
    }
  };
  const timeout = setTimeout(() => {
    void settle({ error: new Error('Release API worker timed out') });
  }, RELEASE_API_WORKER_TIMEOUT_MS);

  worker.once('message', (message: ReleaseApiWorkerMessage) => {
    if (message.ok) {
      void settle(message.dbEpoch === dbEpoch
        ? { payload: message.payload, memory: message.memory }
        : { error: new ReleaseApiEpochChangedError() });
      return;
    }
    void settle({
      error: message.kind === 'epoch_changed'
        ? new ReleaseApiEpochChangedError()
        : new Error(message.message),
    });
  });
  worker.once('error', (error) => {
    void settle({ error });
  });
  worker.once('exit', (code) => {
    recordTermination();
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    rejectBuild(new Error(`Release API worker exited with code ${code}`));
  });

  build = {
    dbEpoch,
    worker,
    promise,
    cancel: async () => {
      if (settled) {
        await (terminationPromise ?? Promise.resolve());
        return;
      }
      releaseApiWorkerLifecycle.canceled++;
      await settle({ error: new ReleaseApiBuildSupersededError() });
    },
  };
  return build;
}

function serializeReleaseApiBuildTransition<T>(task: () => Promise<T>): Promise<T> {
  const run = releaseApiBuildTransition.then(task, task);
  releaseApiBuildTransition = run.then(() => undefined, () => undefined);
  return run;
}

function rememberReleaseApiPayload(dbEpoch: string, payload: ReleaseApiPayloads): void {
  if (scoreApiSourceEpoch() !== dbEpoch) return;
  cachedReleaseApiPayloads = { dbEpoch, payload };
}

async function ensureManagedReleaseApiBuild(
  dbEpoch: string,
  publicationGuard: ScorePublicationGuard,
): Promise<ManagedReleaseApiBuild> {
  return serializeReleaseApiBuildTransition(async () => {
    if (activeReleaseApiBuild?.dbEpoch === dbEpoch) return activeReleaseApiBuild;
    if (activeReleaseApiBuild) await activeReleaseApiBuild.cancel();
    const build = createManagedReleaseApiBuild(dbEpoch, publicationGuard);
    activeReleaseApiBuild = build;
    void build.promise
      .then((payload) => rememberReleaseApiPayload(dbEpoch, payload))
      .catch(() => undefined);
    return build;
  });
}

async function releaseApiPayloadsForCurrentEpoch(
  deadline = Date.now() + RELEASE_API_REQUEST_BUDGET_MS,
): Promise<ReleaseApiPayloads> {
  while (Date.now() < deadline) {
    const { localEpoch: dbEpoch, publicationGuard } =
      scorePublicationContextSnapshot();
    if (cachedReleaseApiPayloads?.dbEpoch === dbEpoch) {
      return cachedReleaseApiPayloads.payload;
    }
    const build = await ensureManagedReleaseApiBuild(
      dbEpoch,
      publicationGuard,
    );
    try {
      const payload = await publicPayloadWithinBudget(build.promise, deadline);
      if (scoreApiSourceEpoch() !== dbEpoch) throw new ReleaseApiEpochChangedError();
      rememberReleaseApiPayload(dbEpoch, payload);
      return payload;
    } catch (error) {
      if (
        error instanceof ReleaseApiEpochChangedError ||
        error instanceof ReleaseApiBuildSupersededError
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new Error('Release API request budget exceeded');
}

const scoreReadWorkerLifecycle = emptyPayloadWorkerLifecycle();
const activeScoreReadBuilds = new Map<string, ManagedScoreReadBuild>();
const cachedScoreReadPayloads = new Map<string, {
  dbEpoch: string;
  payload: ScoreReadPayload;
}>();
let scoreReadBuildTransition: Promise<void> = Promise.resolve();
const SCORE_READ_CACHE_LIMIT = 64;

function scoreReadRequestKey(request: ScoreReadRequest): string {
  return request.kind === 'comparison'
    ? request.kind
    : `${request.kind}:${request.tag}`;
}

function scoreReadBuildKey(dbEpoch: string, request: ScoreReadRequest): string {
  return `${dbEpoch}:${scoreReadRequestKey(request)}`;
}

export function scoreReadWorkerLifecycleSnapshot() {
  return {
    ...scoreReadWorkerLifecycle,
    activeKeys: [...activeScoreReadBuilds.keys()],
    cachedKeys: [...cachedScoreReadPayloads.keys()],
  };
}

export function resetScoreReadWorkerLifecycleForTests(): void {
  if (scoreReadWorkerLifecycle.active !== 0) {
    throw new Error('Cannot reset score read worker lifecycle while a worker is active');
  }
  Object.assign(scoreReadWorkerLifecycle, emptyPayloadWorkerLifecycle());
  cachedScoreReadPayloads.clear();
}

function createManagedScoreReadBuild(
  dbEpoch: string,
  localEpoch: string,
  publicationGuard: ScorePublicationGuard,
  request: ScoreReadRequest,
): ManagedScoreReadBuild {
  const requestKey = scoreReadRequestKey(request);
  const key = scoreReadBuildKey(dbEpoch, request);
  const { filename, ...runtimeOptions } = apiWorkerLaunch();
  const worker = new Worker(filename, {
    ...runtimeOptions,
    env: apiWorkerEnvironment(),
    workerData: {
      databaseContext: API_READ_WORKER_DATABASE_CONTEXT,
      databaseIdentity: openedDatabaseFileIdentity(),
      task: SCORE_READ_WORKER_TASK,
      dbEpoch,
      publicationGuard,
      request,
    } satisfies ScoreReadWorkerData,
    resourceLimits: {
      maxOldGenerationSizeMb: 192,
      maxYoungGenerationSizeMb: 16,
      codeRangeSizeMb: 32,
      stackSizeMb: 4,
    },
  });
  scoreReadWorkerLifecycle.spawned++;
  scoreReadWorkerLifecycle.active++;
  scoreReadWorkerLifecycle.maxActive = Math.max(
    scoreReadWorkerLifecycle.maxActive,
    scoreReadWorkerLifecycle.active,
  );

  let settled = false;
  let terminationRecorded = false;
  let terminationPromise: Promise<void> | null = null;
  let resolveBuild!: (payload: ScoreReadPayload) => void;
  let rejectBuild!: (error: Error) => void;
  const promise = new Promise<ScoreReadPayload>((resolve, reject) => {
    resolveBuild = resolve;
    rejectBuild = reject;
  });
  let build!: ManagedScoreReadBuild;

  const recordTermination = () => {
    if (terminationRecorded) return;
    terminationRecorded = true;
    scoreReadWorkerLifecycle.terminated++;
    scoreReadWorkerLifecycle.active = Math.max(0, scoreReadWorkerLifecycle.active - 1);
    if (activeScoreReadBuilds.get(key) === build) activeScoreReadBuilds.delete(key);
  };
  const terminate = (): Promise<void> => {
    if (terminationPromise) return terminationPromise;
    terminationPromise = worker.terminate()
      .then(() => undefined)
      .catch(() => undefined)
      .finally(recordTermination);
    return terminationPromise;
  };
  const settle = async (
    outcome: { payload: ScoreReadPayload; memory: WorkerMemory } | { error: Error },
  ): Promise<void> => {
    if (settled) return terminationPromise ?? Promise.resolve();
    settled = true;
    clearTimeout(timeout);
    await terminate();
    if ('payload' in outcome) {
      scoreReadWorkerLifecycle.lastWorkerHeapUsed = outcome.memory.heapUsed;
      scoreReadWorkerLifecycle.lastWorkerRss = outcome.memory.rss;
      resolveBuild(outcome.payload);
    } else {
      scoreReadWorkerLifecycle.lastError = outcome.error.message;
      rejectBuild(outcome.error);
    }
  };
  const timeout = setTimeout(() => {
    void settle({ error: new Error('Score-bearing API worker timed out') });
  }, SCORE_READ_WORKER_TIMEOUT_MS);

  worker.once('message', (message: ScoreReadWorkerMessage) => {
    if (message.ok) {
      void settle(message.dbEpoch === dbEpoch
        ? { payload: message.payload, memory: message.memory }
        : { error: new ScoreReadEpochChangedError() });
      return;
    }
    void settle({
      error: message.kind === 'epoch_changed'
        ? new ScoreReadEpochChangedError()
        : new Error(message.message),
    });
  });
  worker.once('error', (error) => {
    void settle({ error });
  });
  worker.once('exit', (code) => {
    recordTermination();
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    rejectBuild(new Error(`Score-bearing API worker exited with code ${code}`));
  });

  build = {
    key,
    requestKey,
    localEpoch,
    dbEpoch,
    worker,
    promise,
    cancel: async () => {
      if (settled) {
        await (terminationPromise ?? Promise.resolve());
        return;
      }
      scoreReadWorkerLifecycle.canceled++;
      await settle({ error: new ScoreReadBuildSupersededError() });
    },
  };
  return build;
}

function serializeScoreReadBuildTransition<T>(task: () => Promise<T>): Promise<T> {
  const run = scoreReadBuildTransition.then(task, task);
  scoreReadBuildTransition = run.then(() => undefined, () => undefined);
  return run;
}

function rememberScoreReadPayload(
  dbEpoch: string,
  request: ScoreReadRequest,
  payload: ScoreReadPayload,
): void {
  if (scoreReadSourceEpoch(request) !== dbEpoch) return;
  const requestKey = scoreReadRequestKey(request);
  if (
    cachedScoreReadPayloads.size >= SCORE_READ_CACHE_LIMIT &&
    !cachedScoreReadPayloads.has(requestKey)
  ) {
    const oldestKey = cachedScoreReadPayloads.keys().next().value;
    if (oldestKey) cachedScoreReadPayloads.delete(oldestKey);
  }
  cachedScoreReadPayloads.set(requestKey, { dbEpoch, payload });
}

async function ensureManagedScoreReadBuild(
  epochs: ScoreReadEpochSnapshot,
  request: ScoreReadRequest,
): Promise<ManagedScoreReadBuild> {
  return serializeScoreReadBuildTransition(async () => {
    const requestKey = scoreReadRequestKey(request);
    for (const build of [...activeScoreReadBuilds.values()]) {
      if (
        build.localEpoch !== epochs.localEpoch ||
        (
          build.requestKey === requestKey &&
          build.dbEpoch !== epochs.requestEpoch
        )
      ) {
        await build.cancel();
      }
    }
    const key = scoreReadBuildKey(epochs.requestEpoch, request);
    const existing = activeScoreReadBuilds.get(key);
    if (existing) return existing;
    const build = createManagedScoreReadBuild(
      epochs.requestEpoch,
      epochs.localEpoch,
      epochs.publicationGuard,
      request,
    );
    activeScoreReadBuilds.set(key, build);
    void build.promise
      .then((payload) =>
        rememberScoreReadPayload(epochs.requestEpoch, request, payload))
      .catch(() => undefined);
    return build;
  });
}

function scoreReadPayloadForCurrentEpoch(
  request: { kind: 'comparison' },
  deadline?: number,
): Promise<ComparisonPayload>;
function scoreReadPayloadForCurrentEpoch(
  request: { kind: 'review'; tag: string },
  deadline?: number,
): Promise<ParentReviewPayload>;
async function scoreReadPayloadForCurrentEpoch(
  request: ScoreReadRequest,
  deadline = Date.now() + SCORE_READ_REQUEST_BUDGET_MS,
): Promise<ScoreReadPayload> {
  const requestKey = scoreReadRequestKey(request);
  while (Date.now() < deadline) {
    const epochs = scoreReadEpochSnapshot(request);
    const dbEpoch = epochs.requestEpoch;
    const cached = cachedScoreReadPayloads.get(requestKey);
    if (cached?.dbEpoch === dbEpoch) return cached.payload;
    const build = await ensureManagedScoreReadBuild(epochs, request);
    try {
      const payload = await publicPayloadWithinBudget(build.promise, deadline);
      if (scoreReadSourceEpoch(request) !== dbEpoch) {
        throw new ScoreReadEpochChangedError();
      }
      rememberScoreReadPayload(dbEpoch, request, payload);
      return payload;
    } catch (error) {
      if (
        error instanceof ScoreReadEpochChangedError ||
        error instanceof ScoreReadBuildSupersededError
      ) {
        continue;
      }
      throw error;
    }
  }
  throw new Error('Score-bearing API request budget exceeded');
}

class PublicPayloadEpochChangedError extends Error {
  constructor() {
    super('Public payload source rows changed during the build');
    this.name = 'PublicPayloadEpochChangedError';
  }
}

class PublicPayloadBuildSupersededError extends Error {
  constructor() {
    super('Public payload build was superseded');
    this.name = 'PublicPayloadBuildSupersededError';
  }
}

interface ManagedPublicPayloadBuild {
  dbEpoch: string;
  worker: Worker;
  promise: Promise<PublicPayload>;
  cancel: () => Promise<void>;
}

const publicPayloadWorkerLifecycle = emptyPayloadWorkerLifecycle();
let activePublicPayloadBuild: ManagedPublicPayloadBuild | null = null;
let publicPayloadBuildTransition: Promise<void> = Promise.resolve();
let lastKnownGoodPublicPayload: {
  dbEpoch: string;
  payload: PublicPayload;
  retainedAtMs: number;
} | null = null;

export function publicPayloadWorkerLifecycleSnapshot() {
  return {
    ...publicPayloadWorkerLifecycle,
    activeEpoch: activePublicPayloadBuild?.dbEpoch ?? null,
    lastKnownGoodEpoch: lastKnownGoodPublicPayload?.dbEpoch ?? null,
  };
}

export function resetPublicPayloadWorkerLifecycleForTests(): void {
  if (publicPayloadWorkerLifecycle.active !== 0) {
    throw new Error('Cannot reset public payload worker lifecycle while a worker is active');
  }
  Object.assign(publicPayloadWorkerLifecycle, emptyPayloadWorkerLifecycle());
}

export function expireRetainedPublicPayloadForTests(): void {
  if (lastKnownGoodPublicPayload) {
    lastKnownGoodPublicPayload.retainedAtMs =
      Date.now() - PUBLIC_RETAINED_FALLBACK_MAX_AGE_MS - 1;
  }
}

function publicCacheKey(dbEpoch = scoreApiSourceEpoch()): string {
  return `${PUBLIC_PAYLOAD_SCHEMA_VERSION}:${dbEpoch}`;
}

function redactNonActionablePublicRelease<T extends Record<string, any>>(
  release: T,
  options: {
    message: string;
    cause: string;
    preserveExistingStaleAudit: boolean;
  },
): T {
  const previousStatus = (
    release.diagnosticStatus
    ?? release.staleAudit?.previousStatus
    ?? (release.status === 'stale' ? null : release.status)
    ?? null
  ) as InstallStatus | null;
  const existingStaleAudit =
    options.preserveExistingStaleAudit && isRecord(release.staleAudit)
      ? release.staleAudit as StaleScoreAuditDiagnostics
      : null;
  const staleAudit = existingStaleAudit ?? {
    schemaVersion: STALE_SCORE_AUDIT_SCHEMA_VERSION,
    state: 'stale' as const,
    message: options.message,
    previousStatus,
    auditedAt: release.staleAudit?.auditedAt ?? release.scoredAt ?? null,
    causes: [options.cause],
  };
  const profileEvidence = isRecord(release.profileEvidence)
    ? {
        ...release.profileEvidence,
        sourceMode: 'current_diagnostic_evidence',
        publicationBinding: null,
      }
    : release.profileEvidence;
  return {
    ...release,
    score: null,
    band: 'wait',
    status: 'stale',
    diagnosticStatus: previousStatus,
    recommended: false,
    reason: staleAudit.message,
    scoredAt: null,
    scoreAudit: null,
    explanation: null,
    profileEvidence,
    staleAudit,
  } as T;
}

function buildPublicPayload(
  releaseApi: ReleaseApiPayloads,
  processLastRefreshAtOverride?: string | null,
) {
  const processLastRefreshAt = processLastRefreshAtOverride === undefined
    ? apiRefreshState().processLastRefreshAt
    : processLastRefreshAtOverride;
  const actionable = releaseApi.snapshot.actionable;
  const commentEvidenceCache = createReleaseProfileCommentEvidenceCache(
    releaseApi.publicBase.map((release) => release.tag),
  );
  const releases = releaseApi.publicBase.map((base) => {
    const labelCutoff = base.dataFreshness.labelCutoffAt;
    const all = publicIssuesForVersion(base.tag);
    const opened = publicOpenedDuringReign(base.tag);
    const publicLabelInfo = batchIssueLabelInfo(
      [...all, ...opened],
      labelCutoff,
    );
    const { topIssues, watchIssues } = publicIssueSummariesForRelease({
      issues: all,
      openedIssues: opened,
      labelCutoff,
      labelsForIssue: (issueNumber, fallbackLabels) =>
        publicLabelInfo.get(issueNumber)?.labels ??
        (labelCutoff == null ? fallbackLabels : []),
    });
    const scoreAudit = actionable ? base.scoreAudit : null;
    const release = {
      ...base,
      totalAttributedIssues: all.length,
      profileEvidence: profileEvidenceForRelease(base.tag, {
        attributed: all,
        opened,
        commentEvidenceCache,
        closureAuthority: scoreAudit?.authorityRunId
          ? createReleaseClosureAuthorityEvaluationForRun(
              scoreAudit.authorityRunId,
            )
          : createReleaseClosureAuthorityEvaluation(),
      }, scoreAudit),
      issues:            topIssues,
      watchIssues,
    };
    return actionable
      ? release
      : redactNonActionablePublicRelease(release, {
          message: PUBLIC_CURRENT_DIAGNOSTIC_MESSAGE,
          cause: 'public_snapshot_non_actionable',
          preserveExistingStaleAudit: true,
        });
  });

  return {
    schemaVersion: PUBLIC_PAYLOAD_SCHEMA_VERSION,
    snapshotId: releaseApi.snapshot.id,
    snapshot: {
      ...releaseApi.snapshot,
      source: 'current' as 'current' | 'retained',
      retained: false as boolean,
      stale: false as boolean,
      actionable,
      ageMs: 0,
      maxAgeMs: null as number | null,
    },
    repo:      `${config.github.owner}/${config.github.repo}`,
    updatedAt: releaseApi.updatedAt ?? processLastRefreshAt,
    releases,
  };
}

function createManagedPublicPayloadBuild(
  dbEpoch: string,
  processLastRefreshAt: string | null,
  releaseApi: ReleaseApiPayloads,
): ManagedPublicPayloadBuild {
  const { filename, ...runtimeOptions } = apiWorkerLaunch();
  const worker = new Worker(filename, {
    ...runtimeOptions,
    env: apiWorkerEnvironment(),
    workerData: {
      databaseContext: API_READ_WORKER_DATABASE_CONTEXT,
      databaseIdentity: openedDatabaseFileIdentity(),
      task: PUBLIC_PAYLOAD_WORKER_TASK,
      dbEpoch,
      processLastRefreshAt,
      releaseApi,
    } satisfies PublicPayloadWorkerData,
    resourceLimits: {
      maxOldGenerationSizeMb: 160,
      maxYoungGenerationSizeMb: 16,
      codeRangeSizeMb: 32,
      stackSizeMb: 4,
    },
  });
  publicPayloadWorkerLifecycle.spawned++;
  publicPayloadWorkerLifecycle.active++;
  publicPayloadWorkerLifecycle.maxActive = Math.max(
    publicPayloadWorkerLifecycle.maxActive,
    publicPayloadWorkerLifecycle.active,
  );

  let settled = false;
  let terminationRecorded = false;
  let terminationPromise: Promise<void> | null = null;
  let resolveBuild!: (payload: PublicPayload) => void;
  let rejectBuild!: (error: Error) => void;
  const promise = new Promise<PublicPayload>((resolve, reject) => {
    resolveBuild = resolve;
    rejectBuild = reject;
  });
  let build!: ManagedPublicPayloadBuild;

  const recordTermination = () => {
    if (terminationRecorded) return;
    terminationRecorded = true;
    publicPayloadWorkerLifecycle.terminated++;
    publicPayloadWorkerLifecycle.active = Math.max(0, publicPayloadWorkerLifecycle.active - 1);
    if (activePublicPayloadBuild === build) activePublicPayloadBuild = null;
  };
  const terminate = (): Promise<void> => {
    if (terminationPromise) return terminationPromise;
    terminationPromise = worker.terminate()
      .then(() => undefined)
      .catch(() => undefined)
      .finally(recordTermination);
    return terminationPromise;
  };
  const settle = async (
    outcome: { payload: PublicPayload; memory: { heapUsed: number; rss: number } } | { error: Error },
  ): Promise<void> => {
    if (settled) return terminationPromise ?? Promise.resolve();
    settled = true;
    clearTimeout(timeout);
    await terminate();
    if ('payload' in outcome) {
      publicPayloadWorkerLifecycle.lastWorkerHeapUsed = outcome.memory.heapUsed;
      publicPayloadWorkerLifecycle.lastWorkerRss = outcome.memory.rss;
      resolveBuild(outcome.payload);
    } else {
      rejectBuild(outcome.error);
    }
  };
  const timeout = setTimeout(() => {
    void settle({ error: new Error('Public payload worker timed out') });
  }, PUBLIC_PAYLOAD_WORKER_TIMEOUT_MS);

  worker.once('message', (message: PublicPayloadWorkerMessage) => {
    if (message.ok) {
      if (message.dbEpoch !== dbEpoch) {
        void settle({ error: new PublicPayloadEpochChangedError() });
      } else {
        void settle({ payload: message.payload, memory: message.memory });
      }
      return;
    }
    void settle({
      error: message.kind === 'epoch_changed'
        ? new PublicPayloadEpochChangedError()
        : new Error(message.message),
    });
  });
  worker.once('error', (error) => {
    void settle({ error });
  });
  worker.once('exit', (code) => {
    recordTermination();
    if (settled) return;
    settled = true;
    clearTimeout(timeout);
    rejectBuild(new Error(`Public payload worker exited with code ${code}`));
  });

  build = {
    dbEpoch,
    worker,
    promise,
    cancel: async () => {
      if (settled) {
        await (terminationPromise ?? Promise.resolve());
        return;
      }
      publicPayloadWorkerLifecycle.canceled++;
      await settle({ error: new PublicPayloadBuildSupersededError() });
    },
  };
  return build;
}

function serializePublicPayloadBuildTransition<T>(task: () => Promise<T>): Promise<T> {
  const run = publicPayloadBuildTransition.then(task, task);
  publicPayloadBuildTransition = run.then(() => undefined, () => undefined);
  return run;
}

function rememberPublicPayload(dbEpoch: string, payload: PublicPayload): void {
  if (scoreApiSourceEpoch() !== dbEpoch) return;
  setCached(payload, publicCacheKey(dbEpoch));
  lastKnownGoodPublicPayload = {
    dbEpoch,
    payload,
    retainedAtMs: Date.now(),
  };
}

function retainedPublicPayload(
  retained: NonNullable<typeof lastKnownGoodPublicPayload>,
  nowMs = Date.now(),
): PublicPayload | null {
  const ageMs = Math.max(0, nowMs - retained.retainedAtMs);
  if (ageMs > PUBLIC_RETAINED_FALLBACK_MAX_AGE_MS) return null;
  const activeTags = listReleasesDb(config.limits.releases)
    .map((release) => release.tag);
  const retainedTags = retained.payload.releases
    .map((release) => release.tag);
  if (
    activeTags.length !== retainedTags.length ||
    activeTags.some((tag, index) => tag !== retainedTags[index])
  ) {
    return null;
  }
  return {
    ...retained.payload,
    snapshot: {
      ...retained.payload.snapshot,
      source: 'retained',
      retained: true,
      stale: true,
      actionable: false,
      ageMs,
      maxAgeMs: PUBLIC_RETAINED_FALLBACK_MAX_AGE_MS,
    },
    releases: retained.payload.releases.map((release) =>
      redactNonActionablePublicRelease(release, {
        message: PUBLIC_RETAINED_DIAGNOSTIC_MESSAGE,
        cause: 'public_payload_retained',
        preserveExistingStaleAudit: false,
      })),
  };
}

async function ensureManagedPublicPayloadBuild(
  dbEpoch: string,
  releaseApi: ReleaseApiPayloads,
): Promise<ManagedPublicPayloadBuild> {
  return serializePublicPayloadBuildTransition(async () => {
    if (activePublicPayloadBuild?.dbEpoch === dbEpoch) return activePublicPayloadBuild;
    if (activePublicPayloadBuild) await activePublicPayloadBuild.cancel();
    const build = createManagedPublicPayloadBuild(
      dbEpoch,
      apiRefreshState().processLastRefreshAt,
      releaseApi,
    );
    activePublicPayloadBuild = build;
    void build.promise
      .then((payload) => rememberPublicPayload(dbEpoch, payload))
      .catch(() => undefined);
    return build;
  });
}

function publicPayloadWithinBudget<T>(
  promise: Promise<T>,
  deadline: number,
): Promise<T> {
  const remaining = Math.max(1, deadline - Date.now());
  return new Promise<T>((resolve, reject) => {
    const timeout = setTimeout(
      () => reject(new Error('Public payload request budget exceeded')),
      remaining,
    );
    promise.then(
      (value) => {
        clearTimeout(timeout);
        resolve(value);
      },
      (error) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

async function publicPayloadForCurrentEpoch(): Promise<PublicPayload> {
  const deadline = Date.now() + PUBLIC_PAYLOAD_REQUEST_BUDGET_MS;
  while (Date.now() < deadline) {
    const { localEpoch: dbEpoch, publicationGuard } =
      scorePublicationContextSnapshot();
    if (publicationGuard.activeRefresh) {
      const retained = lastKnownGoodPublicPayload
        ? retainedPublicPayload(lastKnownGoodPublicPayload)
        : null;
      if (retained) return retained;
      throw new Error(
        'Public payload is unavailable until the active refresh publishes atomically',
      );
    }
    const cacheKey = publicCacheKey(dbEpoch);
    const cached = getCached(cacheKey);
    if (cached) {
      if (scoreApiSourceEpoch() !== dbEpoch) continue;
      const payload = cached as PublicPayload;
      rememberPublicPayload(dbEpoch, payload);
      return payload;
    }

    const retained = lastKnownGoodPublicPayload?.dbEpoch === dbEpoch
      ? retainedPublicPayload(lastKnownGoodPublicPayload)
      : null;
    const releaseApi = await releaseApiPayloadsForCurrentEpoch(deadline);
    if (scoreApiSourceEpoch() !== dbEpoch) continue;
    const build = await ensureManagedPublicPayloadBuild(dbEpoch, releaseApi);
    if (retained) return retained;

    try {
      const payload = await publicPayloadWithinBudget(build.promise, deadline);
      if (scoreApiSourceEpoch() !== dbEpoch) {
        throw new PublicPayloadEpochChangedError();
      }
      rememberPublicPayload(dbEpoch, payload);
      return payload;
    } catch (error) {
      if (
        error instanceof PublicPayloadEpochChangedError ||
        error instanceof PublicPayloadBuildSupersededError
      ) {
        continue;
      }
      const compatibleRetained = lastKnownGoodPublicPayload?.dbEpoch === scoreApiSourceEpoch()
        ? retainedPublicPayload(lastKnownGoodPublicPayload)
        : null;
      if (compatibleRetained) return compatibleRetained;
      throw error;
    }
  }
  throw new Error('Public payload request budget exceeded');
}

api.get('/public', async (_req, res) => {
  try {
    const payload = await publicPayloadForCurrentEpoch();
    res.set(RELEASE_SNAPSHOT_HEADER, payload.snapshot.id);
    res.json(payload);
  } catch {
    res.status(503).json({ error: 'public payload unavailable' });
  }
});

async function runPublicPayloadWorker(input: PublicPayloadWorkerData): Promise<void> {
  try {
    const testDelayMs = Number(process.env.RADAR_TEST_PUBLIC_WORKER_DELAY_MS ?? 0);
    if (Number.isFinite(testDelayMs) && testDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(testDelayMs, 5_000)));
    }
    const payload = stableApiRead(() =>
      buildPublicPayload(input.releaseApi, input.processLastRefreshAt));
    const memory = process.memoryUsage();
    parentPort?.postMessage({
      ok: true,
      dbEpoch: input.dbEpoch,
      payload,
      memory: {
        heapUsed: memory.heapUsed,
        rss: memory.rss,
      },
    } satisfies PublicPayloadWorkerMessage);
  } catch (error) {
    parentPort?.postMessage({
      ok: false,
      kind:
        error instanceof PublicPayloadEpochChangedError ||
        error instanceof ApiSourceSnapshotChangedError
          ? 'epoch_changed'
          : 'error',
      message: error instanceof Error ? error.message : 'Public payload worker failed',
    } satisfies PublicPayloadWorkerMessage);
  } finally {
    parentPort?.close();
  }
}

async function runReleaseApiWorker(input: ReleaseApiWorkerData): Promise<void> {
  try {
    const testDelayMs = Number(process.env.RADAR_TEST_RELEASE_WORKER_DELAY_MS ?? 0);
    if (Number.isFinite(testDelayMs) && testDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(testDelayMs, 5_000)));
    }
    const payload = stableApiRead(() =>
      buildReleaseApiPayloads(
        releaseSnapshotId(input.dbEpoch),
        input.publicationGuard,
      ));
    const memory = process.memoryUsage();
    parentPort?.postMessage({
      ok: true,
      dbEpoch: input.dbEpoch,
      payload,
      memory: {
        heapUsed: memory.heapUsed,
        rss: memory.rss,
      },
    } satisfies ReleaseApiWorkerMessage);
  } catch (error) {
    parentPort?.postMessage({
      ok: false,
      kind:
        error instanceof ReleaseApiEpochChangedError ||
        error instanceof ApiSourceSnapshotChangedError
          ? 'epoch_changed'
          : 'error',
      message: error instanceof Error ? error.message : 'Release API worker failed',
    } satisfies ReleaseApiWorkerMessage);
  } finally {
    parentPort?.close();
  }
}

async function runScoreReadWorker(input: ScoreReadWorkerData): Promise<void> {
  try {
    const testBarrierPath =
      process.env.RADAR_TEST_SCORE_READ_WORKER_BARRIER;
    if (testBarrierPath) {
      const deadline = Date.now() + 30_000;
      while (existsSync(testBarrierPath)) {
        if (Date.now() >= deadline) {
          throw new Error('Score-bearing API worker test barrier timed out');
        }
        await new Promise((resolve) => setTimeout(resolve, 10));
      }
    }
    const testDelayMs = Number(process.env.RADAR_TEST_SCORE_READ_WORKER_DELAY_MS ?? 0);
    if (Number.isFinite(testDelayMs) && testDelayMs > 0) {
      await new Promise((resolve) => setTimeout(resolve, Math.min(testDelayMs, 5_000)));
    }
    const payload = stableApiRead(
      () =>
        input.request.kind === 'comparison'
          ? buildComparisonPayload(input.publicationGuard)
          : buildParentReviewPayload(
              input.request.tag,
              releaseSnapshotId(input.dbEpoch),
              input.publicationGuard,
            ),
      () => scoreReadSourceEpoch(input.request),
    );
    const memory = process.memoryUsage();
    parentPort?.postMessage({
      ok: true,
      dbEpoch: input.dbEpoch,
      payload,
      memory: {
        heapUsed: memory.heapUsed,
        rss: memory.rss,
      },
    } satisfies ScoreReadWorkerMessage);
  } catch (error) {
    parentPort?.postMessage({
      ok: false,
      kind:
        error instanceof ScoreReadEpochChangedError ||
        error instanceof ApiSourceSnapshotChangedError
          ? 'epoch_changed'
          : 'error',
      message: error instanceof Error ? error.message : 'Score-bearing API worker failed',
    } satisfies ScoreReadWorkerMessage);
  } finally {
    parentPort?.close();
  }
}

if (!isMainThread) {
  if (workerData?.task === RELEASE_API_WORKER_TASK) {
    void runReleaseApiWorker(workerData as ReleaseApiWorkerData);
  } else if (workerData?.task === PUBLIC_PAYLOAD_WORKER_TASK) {
    void runPublicPayloadWorker(workerData as PublicPayloadWorkerData);
  } else if (workerData?.task === SCORE_READ_WORKER_TASK) {
    void runScoreReadWorker(workerData as ScoreReadWorkerData);
  }
}
