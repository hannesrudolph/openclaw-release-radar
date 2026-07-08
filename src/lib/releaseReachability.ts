import { existsSync } from 'node:fs';
import { mkdir, rm } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawn, spawnSync } from 'node:child_process';
import { config } from '../config';
import {
  projectDirectCommitStableReleaseBoundaries,
  type StableReleaseBoundaryRow,
} from './directCommitReleaseCatalog';
import {
  KNOWN_REACHABILITY_EVIDENCE_REASONS,
  REACHABILITY_EVIDENCE_SCHEMA_VERSION,
  REACHABILITY_METHOD,
  validateReachabilityEvidence,
  type ReachabilityCatalogProofIdentity,
  type ReachabilityEvidenceReason,
  type ReachabilityStatus,
} from './reachabilityEvidence';
import { throwIfAborted } from './cooperativeCancellation';

export {
  KNOWN_REACHABILITY_EVIDENCE_REASONS,
  REACHABILITY_EVIDENCE_SCHEMA_VERSION,
  REACHABILITY_METHOD,
  validateReachabilityEvidence,
} from './reachabilityEvidence';
export type {
  DirectCommitReachabilityProofIdentity,
  PullRequestReachabilityProofIdentity,
  ReachabilityEvidence,
  ReachabilityEvidenceReason,
  ReachabilityEvidenceValidationInput,
  ReachabilityEvidenceValidationReasonCode,
  ReachabilityEvidenceValidationResult,
  ReleaseBoundaryReachabilityProofIdentity,
  ReachabilityProofIdentity,
  ReachabilityStatus,
} from './reachabilityEvidence';

export const DIRECT_COMMIT_FIRST_CONTAINING_SCHEMA_VERSION = 1 as const;

export const DIRECT_COMMIT_FIRST_CONTAINING_REASON_CODES = [
  'first_containing_direct_commit',
  'repository_identity_mismatch',
  'invalid_commit_oid',
  'missing_predecessor_boundary',
  'target_release_missing',
  'predecessor_release_missing',
  'invalid_release_boundary',
  'release_retag_conflict',
  'release_alias_conflict',
  'repository_state_unavailable',
  'shallow_repository',
  'release_object_unavailable',
  'commit_object_unavailable',
  'ambiguous_release_ancestry',
  'target_commit_not_reachable',
  'predecessor_contains_commit',
  'git_evidence_unavailable',
] as const;

export type DirectCommitFirstContainingReasonCode =
  typeof DIRECT_COMMIT_FIRST_CONTAINING_REASON_CODES[number];

export interface DirectCommitFirstContainingRequest {
  repositoryNameWithOwner: string;
  commitOid: string;
  targetTag: string;
  predecessorTag: string | null;
}

export interface DirectCommitStrictReachabilityProof {
  releaseNodeId: string;
  tag: string;
  catalogRank: number;
  catalogDigest: string;
  catalogReleaseCount: number;
  catalogProof: ReachabilityCatalogProofIdentity | null;
  status: ReachabilityStatus;
  tagCommitOid: string;
  checkedCommitOid: string;
  method: typeof REACHABILITY_METHOD;
  evidence: ReturnType<typeof reachabilityEvidence>;
  strictValid: boolean;
  validationReasonCode: string | null;
}

export interface DirectCommitReleaseCatalogIdentity {
  catalogDigest: string;
  catalogReceiptId: string | null;
  targetReleaseNodeId: string;
  predecessorReleaseNodeId: string;
}

export interface DirectCommitFirstContainingFailure {
  stage:
    | 'request'
    | 'release_boundary'
    | 'repository_state'
    | 'target_release_object'
    | 'predecessor_release_object'
    | 'commit_object'
    | 'release_ancestry'
    | 'target_reachability'
    | 'predecessor_reachability';
  detail: string;
  command: GitCommandResult | null;
}

export interface DirectCommitFirstContainingResult {
  schemaVersion: typeof DIRECT_COMMIT_FIRST_CONTAINING_SCHEMA_VERSION;
  kind: 'direct_commit';
  repositoryNameWithOwner: string;
  commitOid: string;
  targetTag: string;
  predecessorTag: string | null;
  status: 'credited' | 'withheld';
  reasonCode: DirectCommitFirstContainingReasonCode;
  creditEligible: boolean;
  catalogIdentity: DirectCommitReleaseCatalogIdentity | null;
  target: DirectCommitStrictReachabilityProof | null;
  predecessor: DirectCommitStrictReachabilityProof | null;
  olderReleases: DirectCommitStrictReachabilityProof[];
  releaseAncestry: DirectCommitStrictReachabilityProof | null;
  failure: DirectCommitFirstContainingFailure | null;
}

export interface ReleaseReachabilityResult {
  tag: string;
  releaseCommit: string | null;
  candidates: number;
  reachable: number;
  notReachable: number;
  unknown: number;
}

export interface CommitReachability {
  commitOid: string;
  tagCommitOid: string | null;
  status: ReachabilityStatus;
  evidence: string;
}

interface ReleasePrReachabilityInput {
  tag: string;
  pr_repository_owner?: string | null;
  pr_repository_name?: string | null;
  pr_repository_name_with_owner?: string | null;
  pr_number: number;
  tag_commit_oid: string | null;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
  status: ReachabilityStatus;
  method?: string;
  evidence_json: string;
}

interface ReleasePrReachabilityRow {
  tag: string;
  pr_repository_owner: string;
  pr_repository_name: string;
  pr_repository_name_with_owner: string;
  pr_number: number;
  tag_commit_oid: string | null;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
  status: ReachabilityStatus;
  method: string;
  evidence_json: string;
  checked_at: string;
}

export interface ReleaseCommitReachabilityRequest {
  tag: string;
  commitOids: readonly string[];
}

export interface ReleaseReachabilityCheckOptions {
  concurrency?: number;
  context?: ReleaseReachabilityRefreshContext;
  signal?: AbortSignal;
  assertCanWrite?: (stage: string) => void;
}

export interface GitCommandResult {
  status: number | null;
  stdout: string;
  stderr: string;
  signal: NodeJS.Signals | null;
  timedOut?: boolean;
  outputLimitExceeded?: boolean;
  aborted?: boolean;
  processTreeTerminationFailed?: boolean;
}

export type GitObjectResult =
  | { status: 'available' }
  | { status: 'check_failed'; command: GitCommandResult }
  | { status: 'fetch_failed'; command: GitCommandResult }
  | { status: 'unavailable'; command: GitCommandResult };

export type GitRepositoryStateResult =
  | { status: 'ready'; shallow: false; command: GitCommandResult }
  | { status: 'shallow'; shallow: true; command: GitCommandResult }
  | { status: 'error'; shallow: null; command: GitCommandResult };

export type GitRemoteTagCommitResult =
  | { status: 'resolved'; tagCommitOid: string; command: GitCommandResult }
  | { status: 'missing'; command: GitCommandResult }
  | { status: 'error'; detail: string; command: GitCommandResult };

interface PullRequestCandidate {
  pr_repository_owner: string;
  pr_repository_name: string;
  pr_repository_name_with_owner: string;
  pr_number: number;
  merge_commit_oid: string | null;
  base_ref_name: string | null;
  fetched_at: string;
}

interface StagedReleaseRows {
  tag: string;
  rows: ReleasePrReachabilityInput[];
  result: ReleaseReachabilityResult;
  replace: boolean;
  resetCheckedAtRows: Array<{
    prRepositoryNameWithOwner: string;
    prNumber: number;
  }>;
}

interface ReachabilityContextDependencies {
  ensureReady: () => Promise<void>;
  runGit: (args: string[]) => Promise<GitCommandResult>;
}

interface RunCommandOptions {
  timeoutMs?: number;
  maxOutputBytes?: number;
  signal?: AbortSignal;
}

interface GitCacheStats {
  packs: number;
  sizePackKiB: number;
}

interface GitCacheMaintenanceResult {
  performed: boolean;
  before: GitCacheStats;
  after: GitCacheStats | null;
}

type AsyncGitRunner = (
  args: string[],
  options?: RunCommandOptions,
) => Promise<GitCommandResult>;

interface PrBulkDependencies {
  listCandidates: () => PullRequestCandidate[];
  getReleaseCommit: (tag: string) => string | null;
  catalogProofForTag?: (tag: string) => ReachabilityCatalogProofIdentity | null;
  context: ReleaseReachabilityRefreshContext;
  now?: () => number;
  database?: ReachabilityDatabaseRuntime;
}

interface DirectCommitFirstContainingDependencies {
  listStableReleases: () => StableReleaseBoundaryRow[];
  context: ReleaseReachabilityRefreshContext;
  expectedRepositoryNameWithOwner: string;
}

interface AuthorizedReachabilityCatalogIdentity {
  repositoryNameWithOwner: string;
  digest: string;
  receiptId: string;
  releaseCount: number;
}

interface AuthorizedReachabilityRelease {
  tag: string;
  releaseNodeId: string;
  publishedAt: string;
  catalogRank: number;
  prerelease: boolean;
  catalogTagCommitOid: string;
  resolvedTagCommitOid: string | null;
}

interface AuthorizedReachabilityData {
  catalog: AuthorizedReachabilityCatalogIdentity;
  releases: readonly AuthorizedReachabilityRelease[];
  pullRequestCandidates: readonly PullRequestCandidate[];
}

const remote = process.env.OPENCLAW_REPO_URL ?? 'https://github.com/openclaw/openclaw.git';
const repoDir = resolve('.cache/openclaw.git');
const trackedRepositoryNameWithOwner = `${config.github.owner}/${config.github.repo}`;
const GIT_COMMAND_TIMEOUT_MS = 120_000;
const GIT_CLONE_TIMEOUT_MS = 300_000;
const GIT_COMMAND_OUTPUT_LIMIT_BYTES = 256 * 1024;
const GIT_TERMINATION_GRACE_MS = 1_000;
const GIT_MAINTENANCE_DISABLE_ARGS = ['-c', 'gc.auto=0', '-c', 'maintenance.auto=false'] as const;
const FULL_COMMIT_OID_RE = /^[0-9a-f]{40}$/;
const SHA256_RE = /^[0-9a-f]{64}$/;
const SHORT_COMMIT_OID_RE = /^[0-9a-f]{7,39}$/;
export const UNKNOWN_REACHABILITY_RETRY_MS = 24 * 60 * 60 * 1000;

type ReachabilityDatabaseRuntime =
  Awaited<ReturnType<typeof createReachabilityDatabaseRuntime>>;

let reachabilityDatabaseRuntimePromise: Promise<ReachabilityDatabaseRuntime> | null = null;

function loadReachabilityDatabaseRuntime(): Promise<ReachabilityDatabaseRuntime> {
  if (reachabilityDatabaseRuntimePromise) return reachabilityDatabaseRuntimePromise;
  const pending = createReachabilityDatabaseRuntime();
  reachabilityDatabaseRuntimePromise = pending;
  void pending.catch(() => {
    if (reachabilityDatabaseRuntimePromise === pending) {
      reachabilityDatabaseRuntimePromise = null;
    }
  });
  return pending;
}

async function createReachabilityDatabaseRuntime() {
  const dbModule = await import('./db');
  return {
    readAuthorizedReleaseReachabilityData:
      dbModule.readAuthorizedReleaseReachabilityData,
    deleteReleasePrReachabilityRowStmt: dbModule.db.prepare(`
      DELETE FROM release_pr_reachability
      WHERE tag=?
        AND pr_repository_name_with_owner=?
        AND pr_number=?
    `),
    releasePrReachabilityIntegrity: dbModule.releasePrReachabilityIntegrity,
    releasePrReachabilityRows: dbModule.releasePrReachabilityRows,
    replaceReleasePrReachabilityForRelease:
      dbModule.replaceReleasePrReachabilityForRelease,
    runInWriteTransaction: dbModule.runInWriteTransaction,
  };
}

export interface ReleaseReachabilityRefreshContext {
  readonly concurrency: number;
  ensureObject(oid: string): Promise<GitObjectResult>;
  checkAncestor(commitOid: string, tagCommitOid: string): Promise<GitCommandResult>;
  inspectRepository?(): Promise<GitRepositoryStateResult>;
  resolveRemoteTagCommit?(tag: string): Promise<GitRemoteTagCommitResult>;
}

class DefaultReleaseReachabilityRefreshContext implements ReleaseReachabilityRefreshContext {
  readonly concurrency: number;
  private readonly objectResults = new Map<string, Promise<GitObjectResult>>();
  private readonly ancestorResults = new Map<string, Promise<GitCommandResult>>();
  private readonly remoteTagResults = new Map<string, Promise<GitRemoteTagCommitResult>>();
  private readonly objectCheckLimiter: AsyncLimiter;
  private readonly mergeBaseLimiter: AsyncLimiter;
  private readonly fetchLimiter = new AsyncLimiter(1);
  private ready: Promise<void> | null = null;
  private repositoryState: Promise<GitRepositoryStateResult> | null = null;

  constructor(
    concurrency: number,
    private readonly dependencies: ReachabilityContextDependencies,
  ) {
    this.concurrency = normalizeConcurrency(concurrency);
    this.objectCheckLimiter = new AsyncLimiter(this.concurrency);
    this.mergeBaseLimiter = new AsyncLimiter(this.concurrency);
  }

  ensureObject(oid: string): Promise<GitObjectResult> {
    const normalized = normalizeOid(oid);
    const existing = this.objectResults.get(normalized);
    if (existing) return existing;

    let pending: Promise<GitObjectResult>;
    pending = this.ensureObjectOnce(normalized).then(
      (result) => {
        if ((result.status === 'fetch_failed' || result.status === 'check_failed') &&
          this.objectResults.get(normalized) === pending) {
          this.objectResults.delete(normalized);
        }
        return result;
      },
      (error) => {
        if (this.objectResults.get(normalized) === pending) this.objectResults.delete(normalized);
        throw error;
      },
    );
    this.objectResults.set(normalized, pending);
    return pending;
  }

  checkAncestor(commitOid: string, tagCommitOid: string): Promise<GitCommandResult> {
    const key = `${normalizeOid(commitOid)}\0${normalizeOid(tagCommitOid)}`;
    const existing = this.ancestorResults.get(key);
    if (existing) return existing;
    let pending: Promise<GitCommandResult>;
    pending = this.mergeBaseLimiter.run(async () => {
      await this.ensureReady();
      return this.dependencies.runGit(['merge-base', '--is-ancestor', commitOid, tagCommitOid]);
    }).then(
      (result) => {
        if (result.status !== 0 && result.status !== 1 && this.ancestorResults.get(key) === pending) {
          this.ancestorResults.delete(key);
        }
        return result;
      },
      (error) => {
        if (this.ancestorResults.get(key) === pending) this.ancestorResults.delete(key);
        throw error;
      },
    );
    this.ancestorResults.set(key, pending);
    return pending;
  }

  inspectRepository(): Promise<GitRepositoryStateResult> {
    if (this.repositoryState) return this.repositoryState;
    let pending: Promise<GitRepositoryStateResult>;
    pending = this.inspectRepositoryOnce().then(
      (result) => {
        if (result.status === 'error' && this.repositoryState === pending) {
          this.repositoryState = null;
        }
        return result;
      },
      (error) => {
        if (this.repositoryState === pending) this.repositoryState = null;
        throw error;
      },
    );
    this.repositoryState = pending;
    return pending;
  }

  resolveRemoteTagCommit(tag: string): Promise<GitRemoteTagCommitResult> {
    const existing = this.remoteTagResults.get(tag);
    if (existing) return existing;
    let pending: Promise<GitRemoteTagCommitResult>;
    pending = this.resolveRemoteTagCommitOnce(tag).then(
      (result) => {
        if (result.status === 'error' && this.remoteTagResults.get(tag) === pending) {
          this.remoteTagResults.delete(tag);
        }
        return result;
      },
      (error) => {
        if (this.remoteTagResults.get(tag) === pending) this.remoteTagResults.delete(tag);
        throw error;
      },
    );
    this.remoteTagResults.set(tag, pending);
    return pending;
  }

  private ensureReady(): Promise<void> {
    if (this.ready) return this.ready;
    const pending = this.dependencies.ensureReady();
    this.ready = pending;
    void pending.catch(() => {
      if (this.ready === pending) this.ready = null;
    });
    return pending;
  }

  private async ensureObjectOnce(oid: string): Promise<GitObjectResult> {
    await this.ensureReady();
    const initial = await this.objectCheckLimiter.run(() =>
      this.dependencies.runGit(['cat-file', '-e', `${oid}^{commit}`])
    );
    if (initial.status === 0) return { status: 'available' };
    if (isCommitUnavailableFetch(initial)) return { status: 'unavailable', command: initial };
    if (!gitObjectProbeIsMissing(initial)) return { status: 'check_failed', command: initial };

    return this.fetchLimiter.run(async () => {
      // A previous fetch may have brought this object in as part of its history.
      const current = await this.dependencies.runGit(['cat-file', '-e', `${oid}^{commit}`]);
      if (current.status === 0) return { status: 'available' };
      if (isCommitUnavailableFetch(current)) return { status: 'unavailable', command: current };
      if (!gitObjectProbeIsMissing(current)) return { status: 'check_failed', command: current };

      const fetched = await this.dependencies.runGit([
        'fetch',
        '--filter=blob:none',
        '--no-tags',
        'origin',
        oid,
      ]);
      if (isCommitUnavailableFetch(fetched)) return { status: 'unavailable', command: fetched };
      if (fetched.status !== 0) return { status: 'fetch_failed', command: fetched };

      const verified = await this.dependencies.runGit(['cat-file', '-e', `${oid}^{commit}`]);
      if (verified.status === 0) return { status: 'available' };
      if (!gitObjectProbeIsMissing(verified)) return { status: 'check_failed', command: verified };
      return { status: 'unavailable', command: verified };
    });
  }

  private async inspectRepositoryOnce(): Promise<GitRepositoryStateResult> {
    await this.ensureReady();
    const command = await this.dependencies.runGit(['rev-parse', '--is-shallow-repository']);
    if (!gitCommandHasCleanStatus(command, 0)) {
      return { status: 'error', shallow: null, command };
    }
    const shallow = command.stdout.trim();
    if (shallow === 'false') return { status: 'ready', shallow: false, command };
    if (shallow === 'true') return { status: 'shallow', shallow: true, command };
    return {
      status: 'error',
      shallow: null,
      command: {
        ...command,
        status: null,
        stderr: [
          command.stderr,
          `unexpected git shallow-state output: ${JSON.stringify(shallow)}`,
        ].filter(Boolean).join('\n'),
      },
    };
  }

  private async resolveRemoteTagCommitOnce(tag: string): Promise<GitRemoteTagCommitResult> {
    await this.ensureReady();
    const ref = `refs/tags/${tag}`;
    const command = await this.dependencies.runGit([
      'ls-remote',
      '--exit-code',
      '--tags',
      'origin',
      ref,
      `${ref}^{}`,
    ]);
    return interpretRemoteTagCommit(tag, command);
  }
}

export function createReleaseReachabilityRefreshContext(
  options: Pick<ReleaseReachabilityCheckOptions, 'concurrency' | 'signal'> = {},
): ReleaseReachabilityRefreshContext {
  return createReachabilityRefreshContext({
    concurrency: options.concurrency ?? configuredReachabilityConcurrency(),
    ensureReady: () => prepareRepository(options.signal),
    runGit: (args) => gitAsync(args, { signal: options.signal }),
  });
}

export async function checkReleasePrReachability(
  tag: string,
  options: ReleaseReachabilityCheckOptions = {},
): Promise<ReleaseReachabilityResult> {
  const results = await checkReleasePrReachabilityForReleases([tag], options);
  const result = results.get(tag);
  if (!result) throw new Error(`Release ${tag} was not checked`);
  return result;
}

export async function checkReleasePrReachabilityForReleases(
  tags: string[],
  options: ReleaseReachabilityCheckOptions = {},
): Promise<Map<string, ReleaseReachabilityResult>> {
  const database = await loadReachabilityDatabaseRuntime();
  const context = options.context ?? createReleaseReachabilityRefreshContext(options);
  const authorized = database.readAuthorizedReleaseReachabilityData({
    releaseTags: tags,
    integrityExampleLimit: 1,
  }) as AuthorizedReachabilityData;
  const stableReleaseRows = stableReleaseBoundariesFromAuthorizedCatalog(
    authorized,
    trackedRepositoryNameWithOwner,
  );
  const releasesByTag = new Map(
    authorized.releases.map((release) => [release.tag, release]),
  );
  await assertTrustedPullRequestFirstContainingReleaseBoundaries({
    targetTags: tags,
    rows: stableReleaseRows,
    context,
    repositoryNameWithOwner: trackedRepositoryNameWithOwner,
  });
  const nowMs = Date.now();
  const staged = await stageReleasePrReachabilityBulk(tags, {
    listCandidates: () =>
      authorized.pullRequestCandidates.map((candidate) => ({ ...candidate })),
    getReleaseCommit: (tag) =>
      exactAuthorizedReleaseCommit(releasesByTag.get(tag)),
    catalogProofForTag: (tag) => {
      const release = releasesByTag.get(tag);
      return release
        ? authorizedReleaseCatalogProof(authorized.catalog, release)
        : null;
    },
    context,
    now: () => nowMs,
    database,
  });

  throwIfAborted(options.signal);
  options.assertCanWrite?.('release PR reachability persistence');
  database.runInWriteTransaction(() => {
    throwIfAborted(options.signal);
    options.assertCanWrite?.('release PR reachability transaction');
    for (const { tag, rows, replace, resetCheckedAtRows } of staged) {
      if (!replace) continue;
      for (const row of resetCheckedAtRows) {
        database.deleteReleasePrReachabilityRowStmt.run(
          tag,
          row.prRepositoryNameWithOwner,
          row.prNumber,
        );
      }
      database.replaceReleasePrReachabilityForRelease(tag, rows);
    }
    throwIfAborted(options.signal);
    options.assertCanWrite?.('release PR reachability commit');
  });

  return new Map(staged.map(({ tag, result }) => [tag, result]));
}

async function stageReleasePrReachabilityBulk(
  tags: readonly string[],
  dependencies: PrBulkDependencies,
): Promise<StagedReleaseRows[]> {
  const uniqueTags = sortedUniqueStrings(tags);
  if (!uniqueTags.length) return [];
  const database = dependencies.database ?? await loadReachabilityDatabaseRuntime();
  const nowMs = dependencies.now?.() ?? Date.now();
  if (!Number.isFinite(nowMs)) {
    throw new Error(`Reachability freshness clock must be finite, got ${nowMs}`);
  }

  const candidates = dependencies.listCandidates().slice().sort(compareCandidates);
  const releaseCommits = new Map<string, string>();
  const catalogProofs = new Map<string, ReachabilityCatalogProofIdentity | null>();
  for (const tag of uniqueTags) {
    const releaseCommit = dependencies.getReleaseCommit(tag);
    if (!releaseCommit) {
      throw new Error(`Release ${tag} has no tag commit evidence; refusing to replace PR reachability rows`);
    }
    releaseCommits.set(tag, releaseCommit);
    catalogProofs.set(tag, dependencies.catalogProofForTag?.(tag) ?? null);
  }

  const reused = new Map<string, StagedReleaseRows>();
  const tagsToCheck: string[] = [];
  for (const tag of uniqueTags) {
    const reusable = reusableReleaseReachability(
      tag,
      releaseCommits.get(tag)!,
      candidates,
      nowMs,
      database,
      catalogProofs.get(tag) ?? null,
    );
    if (reusable) reused.set(tag, reusable);
    else tagsToCheck.push(tag);
  }
  if (!tagsToCheck.length) return [...reused.values()].sort((left, right) => compareStrings(left.tag, right.tag));

  const existingRowsByTag = new Map(tagsToCheck.map((tag) => [
    tag,
    new Map(database.releasePrReachabilityRows(tag).map((row) => [
      `${row.pr_repository_name_with_owner}\0${row.pr_number}`,
      row,
    ])),
  ]));
  const checksNeeded = tagsToCheck.flatMap((tag) => {
    const releaseCommit = releaseCommits.get(tag)!;
    const existingRows = existingRowsByTag.get(tag)!;
    const catalogProof = catalogProofs.get(tag) ?? null;
    return candidates.flatMap((candidate) => {
      const existing = existingRows.get(
        `${candidate.pr_repository_name_with_owner}\0${candidate.pr_number}`,
      );
      if (
        existingReachabilityRowIsReusable(
          existing,
          candidate,
          releaseCommit,
          nowMs,
          catalogProof,
        )
      ) {
        return [];
      }
      if (!candidate.merge_commit_oid) return [];
      return [{ tag, candidate, releaseCommit }];
    });
  });

  const objectOids = sortedUniqueStrings([
    ...checksNeeded.map((check) => check.releaseCommit),
    ...checksNeeded.map((check) => check.candidate.merge_commit_oid!),
  ], normalizeOid);
  const objectResults = new Map(
    await Promise.all(objectOids.map(async (oid) => [oid, await dependencies.context.ensureObject(oid)] as const)),
  );

  for (const tag of new Set(checksNeeded.map((check) => check.tag))) {
    const releaseCommit = releaseCommits.get(tag)!;
    assertReleaseObjectAvailable(releaseCommit, objectResults.get(normalizeOid(releaseCommit))!);
  }
  for (const candidate of new Map(checksNeeded.map((check) => [
    normalizeOid(check.candidate.merge_commit_oid!),
    check.candidate,
  ])).values()) {
    const objectResult = objectResults.get(normalizeOid(candidate.merge_commit_oid!))!;
    if (directCommitIsUnavailable(objectResult)) continue;
    assertPrCommitObjectAvailable(
      candidate.merge_commit_oid!,
      objectResult,
    );
  }

  const ancestryChecks = checksNeeded.filter((check) =>
    !directCommitIsUnavailable(objectResults.get(normalizeOid(check.candidate.merge_commit_oid!))!));
  const checks = await Promise.all(ancestryChecks.map(async (check) => ({
    ...check,
    result: await dependencies.context.checkAncestor(check.candidate.merge_commit_oid!, check.releaseCommit),
  })));

  for (const check of checks) {
    if (check.result.status !== 0 && check.result.status !== 1) {
      const args = ['merge-base', '--is-ancestor', check.candidate.merge_commit_oid!, check.releaseCommit];
      throw new Error(gitFailureMessage('merge_base_error', args, check.result));
    }
  }

  const checksByTagAndPr = new Map(
    checks.map((check) => [candidateCheckKey(check.tag, check.candidate), check.result]),
  );
  const refreshed = tagsToCheck.map((tag) => {
    const releaseCommit = releaseCommits.get(tag)!;
    const catalogProof = catalogProofs.get(tag) ?? null;
    const existingRows = existingRowsByTag.get(tag)!;
    const resetCheckedAtRows = candidates.flatMap((candidate) => {
      const existing = existingRows.get(
        `${candidate.pr_repository_name_with_owner}\0${candidate.pr_number}`,
      );
      return confirmedUnavailableRowRequiresCheckedAtReset(
        existing,
        candidate,
        releaseCommit,
        nowMs,
        catalogProof,
      )
        ? [{
            prRepositoryNameWithOwner: candidate.pr_repository_name_with_owner,
            prNumber: candidate.pr_number,
          }]
        : [];
    });
    let reachable = 0;
    let unknown = 0;
    let notReachable = 0;
    const rows = candidates.map((candidate) => {
      const existing = existingRows.get(`${candidate.pr_repository_name_with_owner}\0${candidate.pr_number}`);
      if (
        existingReachabilityRowIsReusable(
          existing,
          candidate,
          releaseCommit,
          nowMs,
          catalogProof,
        )
      ) {
        if (existing.status === 'reachable') reachable++;
        else if (existing.status === 'not_reachable') notReachable++;
        else unknown++;
        return releaseReachabilityInputFromRow(existing);
      }
      const commit = candidate.merge_commit_oid;
      if (!commit) {
        unknown++;
        return reachabilityRow(candidate, tag, {
          tagCommitOid: releaseCommit,
          mergeCommitOid: null,
          status: 'unknown',
          evidence: reachabilityEvidence({
            evidence: 'merge_commit_oid_unavailable',
            tagCommitOid: releaseCommit,
            checkedCommitOid: null,
            baseRefName: candidate.base_ref_name ?? null,
            catalogProof,
          }),
        });
      }

      const objectResult = objectResults.get(normalizeOid(commit))!;
      if (directCommitIsUnavailable(objectResult)) {
        unknown++;
        return reachabilityRow(candidate, tag, {
          tagCommitOid: releaseCommit,
          mergeCommitOid: commit,
          status: 'unknown',
          evidence: {
            ...reachabilityEvidence({
              evidence: 'commit_unavailable',
              tagCommitOid: releaseCommit,
              checkedCommitOid: commit,
              baseRefName: candidate.base_ref_name ?? null,
              catalogProof,
              command: objectResult.status === 'available' ? null : objectResult.command,
            }),
            confirmedUnavailable: true,
          },
        });
      }

      const command = checksByTagAndPr.get(candidateCheckKey(tag, candidate))!;
      const interpreted = interpretMergeBaseResult(command, 'merge_commit_in_release_history');
      if (interpreted.status === 'reachable') reachable++;
      else if (interpreted.status === 'not_reachable') notReachable++;
      else unknown++;
      return reachabilityRow(candidate, tag, {
        tagCommitOid: releaseCommit,
        mergeCommitOid: commit,
        status: interpreted.status,
        evidence: reachabilityEvidence({
          evidence: interpreted.evidence.evidence,
          tagCommitOid: releaseCommit,
          checkedCommitOid: commit,
          baseRefName: candidate.base_ref_name ?? null,
          catalogProof,
          command,
        }),
      });
    });

    return {
      tag,
      rows,
      replace: true,
      resetCheckedAtRows,
      result: {
        tag,
        releaseCommit,
        candidates: candidates.length,
        reachable,
        notReachable,
        unknown,
      },
    };
  });
  return [...reused.values(), ...refreshed].sort((left, right) => compareStrings(left.tag, right.tag));
}

function reusableReleaseReachability(
  tag: string,
  releaseCommit: string,
  candidates: PullRequestCandidate[],
  nowMs: number,
  database: ReachabilityDatabaseRuntime,
  catalogProof: ReachabilityCatalogProofIdentity | null,
): StagedReleaseRows | null {
  const integrity = database.releasePrReachabilityIntegrity(tag, 1);
  if (
    integrity.candidateCount !== candidates.length ||
    integrity.rowCount !== candidates.length ||
    integrity.missingCount !== 0 ||
    integrity.extraCount !== 0 ||
    integrity.mismatchedCount !== 0
  ) {
    return null;
  }
  const rows = database.releasePrReachabilityRows(tag);
  if (rows.length !== candidates.length) return null;
  const candidatesByKey = new Map(candidates.map((candidate) => [
    `${candidate.pr_repository_name_with_owner}\0${candidate.pr_number}`,
    candidate,
  ]));
  let reachable = 0;
  let notReachable = 0;
  let unknown = 0;
  for (const row of rows) {
    const candidate = candidatesByKey.get(`${row.pr_repository_name_with_owner}\0${row.pr_number}`);
    if (
      !candidate ||
      !existingReachabilityRowIsReusable(
        row,
        candidate,
        releaseCommit,
        nowMs,
        catalogProof,
      )
    ) {
      return null;
    }
    if (row.status === 'reachable') reachable++;
    else if (row.status === 'not_reachable') notReachable++;
    else unknown++;
  }
  return {
    tag,
    rows: [],
    replace: false,
    resetCheckedAtRows: [],
    result: {
      tag,
      releaseCommit,
      candidates: candidates.length,
      reachable,
      notReachable,
      unknown,
    },
  };
}

function existingReachabilityRowIsReusable(
  row: ReleasePrReachabilityRow | undefined,
  candidate: PullRequestCandidate,
  releaseCommit: string,
  nowMs = Date.now(),
  catalogProof: ReachabilityCatalogProofIdentity | null = null,
): row is ReleasePrReachabilityRow {
  if (!row) return false;
  if (!reachabilityRowIdentityMatches(row, candidate, releaseCommit)) return false;
  const validation = validateReachabilityEvidence({
    evidence: row.evidence_json,
    method: row.method,
    status: row.status,
    identity: {
      kind: 'pull_request',
      tagCommitOid: releaseCommit,
      checkedCommitOid: candidate.merge_commit_oid,
      baseRefName: candidate.base_ref_name ?? null,
      ...(catalogProof ? { catalogProof } : {}),
    },
  });
  if (!validation.valid) return false;

  const checkedAt = Date.parse(row.checked_at);
  const dependencyFetchedAt = Date.parse(candidate.fetched_at);
  const dependencyIsCurrent = Number.isFinite(checkedAt) &&
    Number.isFinite(dependencyFetchedAt) &&
    checkedAt >= dependencyFetchedAt;
  if (!dependencyIsCurrent) return false;
  if (!validation.confirmedUnavailable) return true;
  return Number.isFinite(nowMs) &&
    checkedAt <= nowMs &&
    nowMs - checkedAt <= UNKNOWN_REACHABILITY_RETRY_MS;
}

function confirmedUnavailableRowRequiresCheckedAtReset(
  row: ReleasePrReachabilityRow | undefined,
  candidate: PullRequestCandidate,
  releaseCommit: string,
  nowMs: number,
  catalogProof: ReachabilityCatalogProofIdentity | null = null,
): boolean {
  if (!row || !reachabilityRowIdentityMatches(row, candidate, releaseCommit)) return false;
  const validation = validateReachabilityEvidence({
    evidence: row.evidence_json,
    method: row.method,
    status: row.status,
    identity: {
      kind: 'pull_request',
      tagCommitOid: releaseCommit,
      checkedCommitOid: candidate.merge_commit_oid,
      baseRefName: candidate.base_ref_name ?? null,
      ...(catalogProof ? { catalogProof } : {}),
    },
  });
  return validation.valid &&
    validation.confirmedUnavailable &&
    !existingReachabilityRowIsReusable(
      row,
      candidate,
      releaseCommit,
      nowMs,
      catalogProof,
    );
}

function reachabilityRowIdentityMatches(
  row: ReleasePrReachabilityRow,
  candidate: PullRequestCandidate,
  releaseCommit: string,
): boolean {
  return normalizeOid(row.tag_commit_oid ?? '') === normalizeOid(releaseCommit) &&
    normalizeOid(row.merge_commit_oid ?? '') === normalizeOid(candidate.merge_commit_oid ?? '') &&
    (row.base_ref_name ?? '') === (candidate.base_ref_name ?? '');
}

function releaseReachabilityInputFromRow(row: ReleasePrReachabilityRow): ReleasePrReachabilityInput {
  return {
    tag: row.tag,
    pr_repository_owner: row.pr_repository_owner,
    pr_repository_name: row.pr_repository_name,
    pr_repository_name_with_owner: row.pr_repository_name_with_owner,
    pr_number: row.pr_number,
    tag_commit_oid: row.tag_commit_oid,
    merge_commit_oid: row.merge_commit_oid,
    base_ref_name: row.base_ref_name,
    status: row.status,
    method: row.method,
    evidence_json: row.evidence_json,
  };
}

function reachabilityRow(candidate: PullRequestCandidate, tag: string, input: {
  tagCommitOid: string | null;
  mergeCommitOid: string | null;
  status: ReachabilityStatus;
  evidence: Record<string, unknown>;
}): ReleasePrReachabilityInput {
  return {
    tag,
    pr_repository_owner: candidate.pr_repository_owner,
    pr_repository_name: candidate.pr_repository_name,
    pr_repository_name_with_owner: candidate.pr_repository_name_with_owner,
    pr_number: candidate.pr_number,
    tag_commit_oid: input.tagCommitOid,
    merge_commit_oid: input.mergeCommitOid,
    base_ref_name: candidate.base_ref_name ?? null,
    status: input.status,
    method: REACHABILITY_METHOD,
    evidence_json: JSON.stringify(input.evidence),
  };
}

export async function checkReleaseCommitReachability(
  tag: string,
  commitOids: string[],
  options: ReleaseReachabilityCheckOptions = {},
): Promise<Map<string, CommitReachability>> {
  const results = await checkReleaseCommitReachabilityBulk([{ tag, commitOids }], options);
  return results.get(tag) ?? new Map();
}

export async function checkReleaseCommitReachabilityBulk(
  requests: readonly ReleaseCommitReachabilityRequest[],
  options: ReleaseReachabilityCheckOptions = {},
): Promise<Map<string, Map<string, CommitReachability>>> {
  const commitsByTag = new Map<string, Set<string>>();
  for (const request of requests) {
    const commits = commitsByTag.get(request.tag) ?? new Set<string>();
    for (const oid of request.commitOids) {
      const normalized = normalizeOid(oid);
      if (FULL_COMMIT_OID_RE.test(normalized) || SHORT_COMMIT_OID_RE.test(normalized)) {
        commits.add(normalized);
      }
    }
    commitsByTag.set(request.tag, commits);
  }
  const requestedTags = [...commitsByTag.keys()].sort(compareStrings);
  const results = new Map(
    requestedTags.map((tag) => [tag, new Map<string, CommitReachability>()]),
  );
  const tags = requestedTags.filter((tag) => commitsByTag.get(tag)!.size > 0);
  if (!tags.length) return results;

  const database = await loadReachabilityDatabaseRuntime();
  const authorized = database.readAuthorizedReleaseReachabilityData({
    releaseTags: tags,
    integrityExampleLimit: 0,
  }) as AuthorizedReachabilityData;
  stableReleaseBoundariesFromAuthorizedCatalog(
    authorized,
    trackedRepositoryNameWithOwner,
  );
  const releasesByTag = new Map(
    authorized.releases.map((release) => [release.tag, release]),
  );
  const releaseCommits = new Map<string, string>();
  for (const tag of tags) {
    const releaseCommit = exactAuthorizedReleaseCommit(releasesByTag.get(tag));
    if (!releaseCommit) {
      throw new Error(`Release ${tag} has no tag commit evidence; refusing to check direct commit reachability`);
    }
    releaseCommits.set(tag, releaseCommit);
  }

  for (const tag of tags) {
    const tagResults = results.get(tag)!;
    const releaseCommit = releaseCommits.get(tag)!;
    for (const commitOid of commitsByTag.get(tag)!) {
      if (FULL_COMMIT_OID_RE.test(commitOid)) continue;
      tagResults.set(commitOid, unresolvedShortCommitReachability(commitOid, releaseCommit));
    }
  }

  const tagsWithFullCommits = tags.filter((tag) =>
    [...commitsByTag.get(tag)!].some((commitOid) => FULL_COMMIT_OID_RE.test(commitOid)));
  if (!tagsWithFullCommits.length) {
    return new Map([...results].map(([tag, tagResults]) => [
      tag,
      new Map([...tagResults].sort(([left], [right]) => compareStrings(left, right))),
    ]));
  }

  const context = options.context ?? createReleaseReachabilityRefreshContext(options);
  const objectOids = sortedUniqueStrings([
    ...tagsWithFullCommits.map((tag) => releaseCommits.get(tag)!),
    ...[...commitsByTag.values()].flatMap((commits) =>
      [...commits].filter((commitOid) => FULL_COMMIT_OID_RE.test(commitOid))),
  ], normalizeOid);
  const objectResults = new Map(
    await Promise.all(objectOids.map(async (oid) => [oid, await context.ensureObject(oid)] as const)),
  );

  for (const tag of tagsWithFullCommits) {
    const releaseCommit = releaseCommits.get(tag)!;
    assertReleaseObjectAvailable(releaseCommit, objectResults.get(normalizeOid(releaseCommit))!);
  }

  const availableChecks: Array<{
    tag: string;
    commitOid: string;
    releaseCommit: string;
  }> = [];
  for (const tag of tagsWithFullCommits) {
    const tagResults = results.get(tag)!;
    const releaseCommit = releaseCommits.get(tag)!;
    const commits = [...commitsByTag.get(tag)!]
      .filter((commitOid) => FULL_COMMIT_OID_RE.test(commitOid))
      .sort(compareStrings);
    for (const commitOid of commits) {
      const objectResult = objectResults.get(commitOid)!;
      if (directCommitIsUnavailable(objectResult)) {
        tagResults.set(commitOid, {
          commitOid,
          tagCommitOid: releaseCommit,
          status: 'unknown',
          evidence: 'commit_unavailable',
        });
        continue;
      }
      if (objectResult.status === 'fetch_failed') {
        const args = ['fetch', '--filter=blob:none', '--no-tags', 'origin', commitOid];
        throw new Error(gitFailureMessage('commit_fetch_failed', args, objectResult.command));
      }
      if (objectResult.status === 'check_failed') {
        const args = ['cat-file', '-e', `${commitOid}^{commit}`];
        throw new Error(gitFailureMessage('commit_unavailable', args, objectResult.command));
      }
      availableChecks.push({
        tag,
        commitOid,
        releaseCommit,
      });
    }
  }

  const checks = await Promise.all(availableChecks.map(async (check) => ({
    ...check,
    result: await context.checkAncestor(check.commitOid, check.releaseCommit),
  })));
  for (const check of checks) {
    const args = ['merge-base', '--is-ancestor', check.commitOid, check.releaseCommit];
    if (check.result.status !== 0 && check.result.status !== 1) {
      throw new Error(gitFailureMessage('merge_base_error', args, check.result));
    }
    const interpreted = interpretMergeBaseResult(check.result, 'fix_commit_in_release_history');
    results.get(check.tag)!.set(check.commitOid, {
      commitOid: check.commitOid,
      tagCommitOid: check.releaseCommit,
      status: interpreted.status,
      evidence: interpreted.evidence.evidence,
    });
  }

  for (const [tag, tagResults] of results) {
    results.set(tag, new Map([...tagResults].sort(([left], [right]) => compareStrings(left, right))));
  }
  return results;
}

export async function checkDirectCommitFirstContainingRelease(
  request: DirectCommitFirstContainingRequest,
  options: ReleaseReachabilityCheckOptions = {},
): Promise<DirectCommitFirstContainingResult> {
  const [result] = await checkDirectCommitFirstContainingReleaseBulk([request], options);
  return result;
}

export async function checkDirectCommitFirstContainingReleaseFromRemoteCatalog(
  request: DirectCommitFirstContainingRequest,
  options: ReleaseReachabilityCheckOptions = {},
): Promise<DirectCommitFirstContainingResult> {
  const context = options.context ?? createReleaseReachabilityRefreshContext(options);
  const dependencies = {
    context,
    expectedRepositoryNameWithOwner: trackedRepositoryNameWithOwner,
  };
  if (!directCommitRequestRequiresReleaseCatalog(request)) {
    return evaluateDirectCommitFirstContainingRelease(request, {
      ...dependencies,
      listStableReleases: () => [],
    });
  }

  const { fetchReleaseCatalog } = await import('./github');
  const catalog = await fetchReleaseCatalog({ signal: options.signal });
  const stableReleases = projectDirectCommitStableReleaseBoundaries(catalog.releases);
  return evaluateDirectCommitFirstContainingRelease(request, {
    ...dependencies,
    listStableReleases: () => stableReleases,
  });
}

export async function checkDirectCommitFirstContainingReleaseBulk(
  requests: readonly DirectCommitFirstContainingRequest[],
  options: ReleaseReachabilityCheckOptions = {},
): Promise<DirectCommitFirstContainingResult[]> {
  if (!requests.length) return [];
  const database = await loadReachabilityDatabaseRuntime();
  const context = options.context ?? createReleaseReachabilityRefreshContext(options);
  const authorized = database.readAuthorizedReleaseReachabilityData({
    integrityExampleLimit: 0,
  }) as AuthorizedReachabilityData;
  const stableReleases = stableReleaseBoundariesFromAuthorizedCatalog(
    authorized,
    trackedRepositoryNameWithOwner,
  );
  const dependencies: DirectCommitFirstContainingDependencies = {
    listStableReleases: () => stableReleases,
    context,
    expectedRepositoryNameWithOwner: trackedRepositoryNameWithOwner,
  };
  return Promise.all(requests.map((request) =>
    evaluateDirectCommitFirstContainingRelease(request, dependencies)));
}

function directCommitRequestRequiresReleaseCatalog(
  request: DirectCommitFirstContainingRequest,
): boolean {
  const expectedRepository = normalizeRepositoryIdentity(trackedRepositoryNameWithOwner);
  const requestedRepository = normalizeRepositoryIdentity(request.repositoryNameWithOwner);
  return expectedRepository != null &&
    requestedRepository === expectedRepository &&
    FULL_COMMIT_OID_RE.test(normalizeOid(request.commitOid)) &&
    request.predecessorTag != null &&
    String(request.predecessorTag).length > 0;
}

function stableReleaseBoundariesFromAuthorizedCatalog(
  authorized: AuthorizedReachabilityData,
  expectedRepositoryNameWithOwner: string,
): StableReleaseBoundaryRow[] {
  const expectedRepository = normalizeRepositoryIdentity(
    expectedRepositoryNameWithOwner,
  );
  const catalogRepository = normalizeRepositoryIdentity(
    authorized.catalog.repositoryNameWithOwner,
  );
  if (!expectedRepository || catalogRepository !== expectedRepository) {
    throw new Error(
      'Authorized release reachability catalog repository identity does not match ' +
      `${JSON.stringify(expectedRepositoryNameWithOwner)}`,
    );
  }
  if (
    !SHA256_RE.test(authorized.catalog.digest) ||
    !SHA256_RE.test(authorized.catalog.receiptId) ||
    !Number.isSafeInteger(authorized.catalog.releaseCount) ||
    authorized.catalog.releaseCount < 1 ||
    authorized.catalog.releaseCount !== authorized.releases.length
  ) {
    throw new Error(
      'Authorized release reachability catalog identity is incomplete or inconsistent',
    );
  }

  const tags = new Set<string>();
  const nodeIds = new Set<string>();
  const ranks = new Set<number>();
  for (const [index, release] of authorized.releases.entries()) {
    if (
      canonicalIdentityText(release.tag) !== release.tag ||
      canonicalIdentityText(release.releaseNodeId) !== release.releaseNodeId ||
      !Number.isFinite(Date.parse(release.publishedAt)) ||
      !Number.isSafeInteger(release.catalogRank) ||
      release.catalogRank !== index ||
      tags.has(release.tag) ||
      nodeIds.has(release.releaseNodeId) ||
      ranks.has(release.catalogRank)
    ) {
      throw new Error(
        'Authorized release reachability catalog did not preserve exact rank, ' +
        'tag, publication, or immutable node identity',
      );
    }
    tags.add(release.tag);
    nodeIds.add(release.releaseNodeId);
    ranks.add(release.catalogRank);
  }

  return authorized.releases.flatMap((release) =>
    release.prerelease
      ? []
      : [{
          node_id: release.releaseNodeId,
          tag: release.tag,
          published_at: release.publishedAt,
          catalog_rank: release.catalogRank,
          catalog_digest: authorized.catalog.digest,
          catalog_receipt_id: authorized.catalog.receiptId,
          catalog_release_count: authorized.catalog.releaseCount,
          catalog_tag_commit_oid: normalizeOid(release.catalogTagCommitOid),
          resolved_tag_commit_oid: normalizeOid(
            release.resolvedTagCommitOid ?? '',
          ),
        }]);
}

function exactAuthorizedReleaseCommit(
  release: AuthorizedReachabilityRelease | undefined,
): string | null {
  if (!release) return null;
  const catalogCommitOid = normalizeOid(release.catalogTagCommitOid);
  const resolvedCommitOid = normalizeOid(release.resolvedTagCommitOid ?? '');
  return FULL_COMMIT_OID_RE.test(catalogCommitOid) &&
    resolvedCommitOid === catalogCommitOid
    ? resolvedCommitOid
    : null;
}

function authorizedReleaseCatalogProof(
  catalog: AuthorizedReachabilityCatalogIdentity,
  release: AuthorizedReachabilityRelease,
  checkedRelease: AuthorizedReachabilityRelease | null = null,
): ReachabilityCatalogProofIdentity {
  return {
    catalogDigest: catalog.digest,
    catalogReceiptId: catalog.receiptId,
    releaseNodeId: release.releaseNodeId,
    checkedReleaseNodeId: checkedRelease?.releaseNodeId ?? null,
  };
}

async function evaluateDirectCommitFirstContainingRelease(
  request: DirectCommitFirstContainingRequest,
  dependencies: DirectCommitFirstContainingDependencies,
): Promise<DirectCommitFirstContainingResult> {
  const expectedRepository = normalizeRepositoryIdentity(
    dependencies.expectedRepositoryNameWithOwner,
  );
  const requestedRepository = normalizeRepositoryIdentity(request.repositoryNameWithOwner);
  const commitOid = normalizeOid(request.commitOid);
  const normalizedRequest = {
    repositoryNameWithOwner: requestedRepository ?? String(request.repositoryNameWithOwner ?? ''),
    commitOid,
    targetTag: String(request.targetTag ?? ''),
    predecessorTag: request.predecessorTag == null ? null : String(request.predecessorTag),
  };

  if (!expectedRepository || requestedRepository !== expectedRepository) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'repository_identity_mismatch',
      {
        stage: 'request',
        detail:
          `direct commit repository ${JSON.stringify(request.repositoryNameWithOwner)} ` +
          `does not match ${JSON.stringify(dependencies.expectedRepositoryNameWithOwner)}`,
        command: null,
      },
    );
  }
  normalizedRequest.repositoryNameWithOwner = expectedRepository;
  if (!FULL_COMMIT_OID_RE.test(commitOid)) {
    return directCommitFirstContainingResult(normalizedRequest, 'invalid_commit_oid', {
      stage: 'request',
      detail: `direct commit proof requires a full 40-character commit OID, got ${JSON.stringify(request.commitOid)}`,
      command: null,
    });
  }
  if (!normalizedRequest.predecessorTag) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'missing_predecessor_boundary',
      {
        stage: 'release_boundary',
        detail: `release ${normalizedRequest.targetTag} has no predecessor stable release boundary`,
        command: null,
      },
    );
  }

  const boundary = resolveDirectCommitReleaseBoundary(
    normalizedRequest.targetTag,
    normalizedRequest.predecessorTag,
    dependencies.listStableReleases(),
  );
  if (!boundary.valid) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      boundary.reasonCode,
      {
        stage: 'release_boundary',
        detail: boundary.detail,
        command: null,
      },
    );
  }

  const inspectRepository = dependencies.context.inspectRepository;
  if (!inspectRepository) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'repository_state_unavailable',
      {
        stage: 'repository_state',
        detail: 'reachability context cannot prove whether the git repository is shallow',
        command: null,
      },
      boundary.catalogIdentity,
    );
  }
  let repositoryState: GitRepositoryStateResult;
  try {
    repositoryState = await inspectRepository.call(dependencies.context);
  } catch (error) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'repository_state_unavailable',
      {
        stage: 'repository_state',
        detail: `git repository state check failed: ${errorMessage(error)}`,
        command: null,
      },
      boundary.catalogIdentity,
    );
  }
  if (repositoryState.status === 'shallow') {
    return directCommitFirstContainingResult(normalizedRequest, 'shallow_repository', {
      stage: 'repository_state',
      detail: 'git repository is shallow; ancestry absence cannot establish first containment',
      command: repositoryState.command,
    }, boundary.catalogIdentity);
  }
  if (repositoryState.status !== 'ready') {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'repository_state_unavailable',
      {
        stage: 'repository_state',
        detail: 'git repository state could not be proven complete',
        command: repositoryState.command,
      },
      boundary.catalogIdentity,
    );
  }

  const remoteBoundary = await attestCurrentRemoteReleaseBoundary(
    boundary,
    dependencies.context,
  );
  if (!remoteBoundary.valid) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      remoteBoundary.reasonCode,
      {
        stage: 'release_boundary',
        detail: remoteBoundary.detail,
        command: remoteBoundary.command,
      },
      boundary.catalogIdentity,
    );
  }

  for (const object of [
    ...boundary.olderReleases.map((older) => ({
      oid: older.commitOid,
      stage: 'predecessor_release_object' as const,
      reasonCode: 'release_object_unavailable' as const,
    })),
    {
      oid: boundary.targetCommitOid,
      stage: 'target_release_object' as const,
      reasonCode: 'release_object_unavailable' as const,
    },
    {
      oid: commitOid,
      stage: 'commit_object' as const,
      reasonCode: 'commit_object_unavailable' as const,
    },
  ]) {
    let result: GitObjectResult;
    try {
      result = await dependencies.context.ensureObject(object.oid);
    } catch (error) {
      return directCommitFirstContainingResult(
        normalizedRequest,
        'git_evidence_unavailable',
        {
          stage: object.stage,
          detail: `git object check for ${object.oid} failed: ${errorMessage(error)}`,
          command: null,
        },
        boundary.catalogIdentity,
      );
    }
    if (result.status !== 'available') {
      return directCommitFirstContainingResult(
        normalizedRequest,
        object.reasonCode,
        {
          stage: object.stage,
          detail: `git object ${object.oid} is not verifiably available`,
          command: result.command,
        },
        boundary.catalogIdentity,
      );
    }
  }

  const releaseAncestry = await firstContainingReleaseAncestryProof({
    context: dependencies.context,
    repositoryNameWithOwner: expectedRepository,
    boundary,
  });
  if (!releaseAncestry.valid) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      releaseAncestry.reasonCode,
      {
        releaseAncestry: releaseAncestry.proof,
        failure: releaseAncestry.failure,
      },
      boundary.catalogIdentity,
    );
  }

  const olderChecks: Array<{
    release: StableReleaseBoundaryRow;
    result: Awaited<ReturnType<typeof directCommitAncestryProof>>;
  }> = [];
  for (const older of boundary.olderReleases) {
    olderChecks.push({
      release: older.release,
      result: await directCommitAncestryProof({
        context: dependencies.context,
        repositoryNameWithOwner: expectedRepository,
        releaseNodeId: older.release.node_id,
        tag: older.release.tag,
        catalogRank: older.release.catalog_rank,
        catalogDigest: older.release.catalog_digest,
        catalogReleaseCount: older.release.catalog_release_count,
        catalogProof: resolvedReleaseCatalogProof(boundary, older.release),
        tagCommitOid: older.commitOid,
        checkedCommitOid: commitOid,
        proofKind: 'direct_commit',
        reachableEvidence: 'fix_commit_in_release_history',
      }),
    });
  }
  const olderReleases = olderChecks.map(({ result }) => result.proof);
  const predecessor = olderReleases.at(-1) ?? null;

  const target = await directCommitAncestryProof({
    context: dependencies.context,
    repositoryNameWithOwner: expectedRepository,
    releaseNodeId: boundary.target.node_id,
    tag: boundary.target.tag,
    catalogRank: boundary.target.catalog_rank,
    catalogDigest: boundary.target.catalog_digest,
    catalogReleaseCount: boundary.target.catalog_release_count,
    catalogProof: resolvedReleaseCatalogProof(boundary, boundary.target),
    tagCommitOid: boundary.targetCommitOid,
    checkedCommitOid: commitOid,
    proofKind: 'direct_commit',
    reachableEvidence: 'fix_commit_in_release_history',
  });
  if (!target.proof.strictValid || target.proof.status === 'unknown') {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'git_evidence_unavailable',
      {
        target: target.proof,
        predecessor,
        olderReleases,
        releaseAncestry: releaseAncestry.proof,
        failure: {
          stage: 'target_reachability',
          detail: target.error ?? 'target release reachability did not produce strict git evidence',
          command: target.command,
        },
      },
      boundary.catalogIdentity,
    );
  }
  if (target.proof.status !== 'reachable') {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'target_commit_not_reachable',
      {
        target: target.proof,
        predecessor,
        olderReleases,
        releaseAncestry: releaseAncestry.proof,
        failure: {
          stage: 'target_reachability',
          detail:
            `commit ${commitOid} is not reachable from target release ${boundary.target.tag}`,
          command: target.command,
        },
      },
      boundary.catalogIdentity,
    );
  }

  const uncertainOlder = olderChecks.find(({ result }) =>
    !result.proof.strictValid || result.proof.status === 'unknown');
  if (uncertainOlder) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'git_evidence_unavailable',
      {
        target: target.proof,
        predecessor,
        olderReleases,
        releaseAncestry: releaseAncestry.proof,
        failure: {
          stage: 'predecessor_reachability',
          detail: uncertainOlder.result.error ??
            `older stable release ${uncertainOlder.release.tag} reachability ` +
              'did not produce strict git evidence',
          command: uncertainOlder.result.command,
        },
      },
      boundary.catalogIdentity,
    );
  }

  const containingOlder = olderChecks.find(({ result }) =>
    result.proof.status === 'reachable');
  if (containingOlder) {
    return directCommitFirstContainingResult(
      normalizedRequest,
      'predecessor_contains_commit',
      {
        target: target.proof,
        predecessor,
        olderReleases,
        releaseAncestry: releaseAncestry.proof,
        failure: {
          stage: 'predecessor_reachability',
          detail:
            `commit ${commitOid} is already reachable from older stable release ` +
            `${containingOlder.release.tag}`,
          command: containingOlder.result.command,
        },
      },
      boundary.catalogIdentity,
    );
  }

  return {
    schemaVersion: DIRECT_COMMIT_FIRST_CONTAINING_SCHEMA_VERSION,
    kind: 'direct_commit',
    repositoryNameWithOwner: expectedRepository,
    commitOid,
    targetTag: boundary.target.tag,
    predecessorTag: boundary.predecessor.tag,
    status: 'credited',
    reasonCode: 'first_containing_direct_commit',
    creditEligible: true,
    catalogIdentity: boundary.catalogIdentity,
    target: target.proof,
    predecessor,
    olderReleases,
    releaseAncestry: releaseAncestry.proof,
    failure: null,
  };
}

type DirectCommitReleaseBoundaryResult =
  | {
      valid: true;
      target: StableReleaseBoundaryRow;
      predecessor: StableReleaseBoundaryRow;
      catalogIdentity: DirectCommitReleaseCatalogIdentity;
      catalogReleases: Array<{
        release: StableReleaseBoundaryRow;
        commitOid: string;
      }>;
      olderReleases: Array<{
        release: StableReleaseBoundaryRow;
        commitOid: string;
      }>;
      targetCommitOid: string;
      predecessorCommitOid: string;
    }
  | {
      valid: false;
      reasonCode:
        | 'target_release_missing'
        | 'predecessor_release_missing'
        | 'invalid_release_boundary'
        | 'release_retag_conflict'
        | 'release_alias_conflict';
      detail: string;
    };

function resolveDirectCommitReleaseBoundary(
  targetTag: string,
  predecessorTag: string,
  rows: readonly StableReleaseBoundaryRow[],
): DirectCommitReleaseBoundaryResult {
  const tags = new Set<string>();
  const nodeIds = new Set<string>();
  for (const row of rows) {
    if (
      !row ||
      canonicalIdentityText(row.tag) !== row.tag ||
      canonicalIdentityText(row.node_id) !== row.node_id ||
      !('catalog_receipt_id' in row) ||
      (
        row.catalog_receipt_id !== null &&
        canonicalIdentityText(row.catalog_receipt_id) !== row.catalog_receipt_id
      )
    ) {
      return {
        valid: false,
        reasonCode: 'invalid_release_boundary',
        detail: 'active stable release catalog tag or node identities are missing or non-canonical',
      };
    }
    if (tags.has(row.tag) || nodeIds.has(row.node_id)) {
      return {
        valid: false,
        reasonCode: 'invalid_release_boundary',
        detail: 'active stable release catalog tag or immutable node identities are not unique',
      };
    }
    tags.add(row.tag);
    nodeIds.add(row.node_id);
  }

  const catalogDigests = new Set(rows.map((row) => row.catalog_digest));
  const catalogReceiptIds = new Set(rows.map((row) => row.catalog_receipt_id));
  const catalogReleaseCounts = new Set(rows.map((row) => row.catalog_release_count));
  const catalogDigest = [...catalogDigests][0] ?? '';
  const catalogReceiptId = [...catalogReceiptIds][0] ?? null;
  if (
    catalogDigests.size !== 1 ||
    !SHA256_RE.test(catalogDigest) ||
    catalogReceiptIds.size !== 1 ||
    (catalogReceiptId !== null && !SHA256_RE.test(catalogReceiptId)) ||
    catalogReleaseCounts.size !== 1
  ) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail:
        'active stable release rows do not share one authoritative catalog ' +
        'digest, receipt identity, and release count',
    };
  }
  const catalogReleaseCount = [...catalogReleaseCounts][0];
  if (
    !Number.isInteger(catalogReleaseCount) ||
    Number(catalogReleaseCount) < rows.length ||
    Number(catalogReleaseCount) < 1
  ) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'active release catalog count is missing or invalid',
    };
  }

  const target = rows.find((row) => row.tag === targetTag);
  if (!target) {
    return {
      valid: false,
      reasonCode: 'target_release_missing',
      detail: `target release ${targetTag} is not an active stable release`,
    };
  }
  const predecessor = rows.find((row) => row.tag === predecessorTag);
  if (!predecessor) {
    return {
      valid: false,
      reasonCode: 'predecessor_release_missing',
      detail: `predecessor release ${predecessorTag} is not an active stable release`,
    };
  }

  const ranks = rows.map((row) => ({
    row,
    rank: row.catalog_rank,
  }));
  if (ranks.some(({ rank }) =>
    !Number.isInteger(rank) ||
    Number(rank) < 0 ||
    Number(rank) >= Number(catalogReleaseCount))) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'active stable release catalog ranks are missing or invalid',
    };
  }
  if (new Set(ranks.map(({ rank }) => rank)).size !== ranks.length) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'active stable release catalog ranks are not unique',
    };
  }
  const catalogOrdered = ranks
    .slice()
    .sort((left, right) =>
      Number(left.rank) - Number(right.rank) ||
      compareBinary(left.row.tag, right.row.tag) ||
      compareBinary(left.row.node_id, right.row.node_id));
  const catalogTargetIndex = catalogOrdered.findIndex(({ row }) => row.tag === targetTag);
  if (catalogTargetIndex < 0 ||
    catalogOrdered[catalogTargetIndex + 1]?.row.tag !== predecessorTag) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail:
        `${predecessorTag} is not the immediate older stable release for ${targetTag} ` +
        'in the active release catalog',
    };
  }

  const timestamps = rows.map((row) => ({
    row,
    timestamp: row.published_at == null ? NaN : Date.parse(row.published_at),
  }));
  if (timestamps.some(({ timestamp }) => !Number.isFinite(timestamp))) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'active stable release publication timestamps are missing or invalid',
    };
  }
  const ordered = timestamps
    .slice()
    .sort((left, right) =>
      right.timestamp - left.timestamp ||
      compareBinary(left.row.tag, right.row.tag) ||
      compareBinary(left.row.node_id, right.row.node_id));
  if (ordered.some(({ row }, index) => row !== catalogOrdered[index]?.row)) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'active stable release catalog rank and publication order do not match',
    };
  }
  const targetIndex = ordered.findIndex(({ row }) => row.tag === targetTag);
  if (targetIndex < 0 || ordered[targetIndex + 1]?.row.tag !== predecessorTag) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail:
        `${predecessorTag} is not the immediate older stable release for ${targetTag} ` +
        'by publication time',
    };
  }

  const resolvedCatalog = catalogOrdered.map(({ row }) => {
    const catalogOid = normalizeOid(row.catalog_tag_commit_oid ?? '');
    const resolvedOid = normalizeOid(row.resolved_tag_commit_oid ?? '');
    return { row, catalogOid, resolvedOid };
  });
  for (const release of resolvedCatalog) {
    if (
      !FULL_COMMIT_OID_RE.test(release.catalogOid) ||
      !FULL_COMMIT_OID_RE.test(release.resolvedOid)
    ) {
      return {
        valid: false,
        reasonCode: 'release_retag_conflict',
        detail:
          `stable release ${release.row.tag} is missing an exact ` +
          'catalog/resolved commit identity',
      };
    }
    if (release.catalogOid !== release.resolvedOid) {
      return {
        valid: false,
        reasonCode: 'release_retag_conflict',
        detail:
          `stable release ${release.row.tag} resolves to a different commit ` +
          'than its catalog identity',
      };
    }
  }

  const aliases = new Map<string, string[]>();
  for (const release of resolvedCatalog) {
    const aliasTags = aliases.get(release.resolvedOid) ?? [];
    aliasTags.push(release.row.tag);
    aliases.set(release.resolvedOid, aliasTags);
  }
  for (const [oid, aliasTags] of aliases) {
    if (aliasTags.length > 1) {
      return {
        valid: false,
        reasonCode: 'release_alias_conflict',
        detail:
          `release commit ${oid} is shared by stable tags ` +
          `${aliasTags.sort(compareBinary).join(', ')}`,
      };
    }
  }

  const targetAndOlder = resolvedCatalog.slice(catalogTargetIndex);
  const targetResolved = targetAndOlder[0];
  const predecessorResolved = targetAndOlder[1];
  if (!targetResolved || !predecessorResolved) {
    return {
      valid: false,
      reasonCode: 'invalid_release_boundary',
      detail: 'target release does not have a complete older stable catalog boundary',
    };
  }

  return {
    valid: true,
    target,
    predecessor,
    catalogIdentity: {
      catalogDigest,
      catalogReceiptId,
      targetReleaseNodeId: target.node_id,
      predecessorReleaseNodeId: predecessor.node_id,
    },
    catalogReleases: resolvedCatalog.map((release) => ({
      release: release.row,
      commitOid: release.resolvedOid,
    })),
    olderReleases: targetAndOlder
      .slice(1)
      .reverse()
      .map((release) => ({
        release: release.row,
        commitOid: release.resolvedOid,
      })),
    targetCommitOid: targetResolved.resolvedOid,
    predecessorCommitOid: predecessorResolved.resolvedOid,
  };
}

type ResolvedReleaseBoundary = Extract<DirectCommitReleaseBoundaryResult, { valid: true }>;

function resolvedReleaseCatalogProof(
  boundary: ResolvedReleaseBoundary,
  release: StableReleaseBoundaryRow,
  checkedRelease: StableReleaseBoundaryRow | null = null,
): ReachabilityCatalogProofIdentity | null {
  const catalogReceiptId = boundary.catalogIdentity.catalogReceiptId;
  if (catalogReceiptId === null) return null;
  return {
    catalogDigest: boundary.catalogIdentity.catalogDigest,
    catalogReceiptId,
    releaseNodeId: release.node_id,
    checkedReleaseNodeId: checkedRelease?.node_id ?? null,
  };
}

type CurrentRemoteReleaseBoundaryAttestation =
  | { valid: true }
  | {
      valid: false;
      reasonCode:
        | 'release_retag_conflict'
        | 'release_alias_conflict'
        | 'git_evidence_unavailable';
      detail: string;
      command: GitCommandResult | null;
    };

async function attestCurrentRemoteReleaseBoundary(
  boundary: ResolvedReleaseBoundary,
  context: ReleaseReachabilityRefreshContext,
): Promise<CurrentRemoteReleaseBoundaryAttestation> {
  const resolveRemoteTagCommit = context.resolveRemoteTagCommit;
  if (!resolveRemoteTagCommit) {
    return {
      valid: false,
      reasonCode: 'git_evidence_unavailable',
      detail: 'reachability context cannot attest current remote release tag identities',
      command: null,
    };
  }

  const currentReleases: Array<{
    tag: string;
    expectedCommitOid: string;
    remoteCommitOid: string;
    command: GitCommandResult;
  }> = [];
  for (const catalogRelease of boundary.catalogReleases) {
    const release = {
      tag: catalogRelease.release.tag,
      expectedCommitOid: catalogRelease.commitOid,
    };
    let result: GitRemoteTagCommitResult;
    try {
      result = await resolveRemoteTagCommit.call(context, release.tag);
    } catch (error) {
      return {
        valid: false,
        reasonCode: 'git_evidence_unavailable',
        detail:
          `current remote tag attestation for ${release.tag} failed: ${errorMessage(error)}`,
        command: null,
      };
    }
    if (result.status === 'error') {
      return {
        valid: false,
        reasonCode: 'git_evidence_unavailable',
        detail: result.detail,
        command: result.command,
      };
    }
    if (result.status === 'missing') {
      return {
        valid: false,
        reasonCode: 'release_retag_conflict',
        detail: `current remote tag ${release.tag} is missing`,
        command: result.command,
      };
    }

    const remoteCommitOid = normalizeOid(result.tagCommitOid);
    if (!FULL_COMMIT_OID_RE.test(remoteCommitOid)) {
      return {
        valid: false,
        reasonCode: 'git_evidence_unavailable',
        detail: `current remote tag ${release.tag} did not resolve to a full commit OID`,
        command: result.command,
      };
    }
    currentReleases.push({
      ...release,
      remoteCommitOid,
      command: result.command,
    });
  }

  const aliases = new Map<string, string[]>();
  for (const release of currentReleases) {
    const tags = aliases.get(release.remoteCommitOid) ?? [];
    tags.push(release.tag);
    aliases.set(release.remoteCommitOid, tags);
  }
  for (const [commitOid, tags] of aliases) {
    if (tags.length > 1) {
      return {
        valid: false,
        reasonCode: 'release_alias_conflict',
        detail:
          `current remote release commit ${commitOid} is shared by stable tags ` +
          tags.sort(compareBinary).join(', '),
        command: currentReleases.find((release) =>
          release.remoteCommitOid === commitOid)?.command ?? null,
      };
    }
  }

  for (const release of currentReleases) {
    if (release.remoteCommitOid !== release.expectedCommitOid) {
      return {
        valid: false,
        reasonCode: 'release_retag_conflict',
        detail:
          `current remote tag ${release.tag} resolves to ${release.remoteCommitOid}, not stored ` +
          `release commit ${release.expectedCommitOid}`,
        command: release.command,
      };
    }
  }
  return { valid: true };
}

type FirstContainingReleaseAncestryResult =
  | {
      valid: true;
      proof: DirectCommitStrictReachabilityProof;
    }
  | {
      valid: false;
      reasonCode: 'git_evidence_unavailable' | 'ambiguous_release_ancestry';
      proof: DirectCommitStrictReachabilityProof;
      failure: DirectCommitFirstContainingFailure;
    };

async function firstContainingReleaseAncestryProof(input: {
  context: ReleaseReachabilityRefreshContext;
  repositoryNameWithOwner: string;
  boundary: ResolvedReleaseBoundary;
}): Promise<FirstContainingReleaseAncestryResult> {
  const ancestry = await directCommitAncestryProof({
    context: input.context,
    repositoryNameWithOwner: input.repositoryNameWithOwner,
    releaseNodeId: input.boundary.target.node_id,
    tag: input.boundary.target.tag,
    catalogRank: input.boundary.target.catalog_rank,
    catalogDigest: input.boundary.target.catalog_digest,
    catalogReleaseCount: input.boundary.target.catalog_release_count,
    catalogProof: resolvedReleaseCatalogProof(
      input.boundary,
      input.boundary.target,
      input.boundary.predecessor,
    ),
    tagCommitOid: input.boundary.targetCommitOid,
    checkedCommitOid: input.boundary.predecessorCommitOid,
    proofKind: 'release_boundary',
    reachableEvidence: 'predecessor_release_in_target_history',
  });
  if (!ancestry.proof.strictValid || ancestry.proof.status === 'unknown') {
    return {
      valid: false,
      reasonCode: 'git_evidence_unavailable',
      proof: ancestry.proof,
      failure: {
        stage: 'release_ancestry',
        detail: ancestry.error ??
          'predecessor-to-target release ancestry did not produce strict git evidence',
        command: ancestry.command,
      },
    };
  }
  if (ancestry.proof.status !== 'reachable') {
    return {
      valid: false,
      reasonCode: 'ambiguous_release_ancestry',
      proof: ancestry.proof,
      failure: {
        stage: 'release_ancestry',
        detail:
          `predecessor release ${input.boundary.predecessor.tag} is not an ancestor of ` +
          `target release ${input.boundary.target.tag}`,
        command: ancestry.command,
      },
    };
  }
  return {
    valid: true,
    proof: ancestry.proof,
  };
}

async function assertTrustedPullRequestFirstContainingReleaseBoundaries(input: {
  targetTags: readonly string[];
  rows: readonly StableReleaseBoundaryRow[];
  context: ReleaseReachabilityRefreshContext;
  repositoryNameWithOwner: string;
}): Promise<void> {
  const pairs = firstContainingReleaseBoundaryPairs(input.targetTags, input.rows);
  if (!pairs.length) return;

  const inspectRepository = input.context.inspectRepository;
  if (!inspectRepository) {
    throw new Error(
      'Trusted PR first-containing proof requires a complete git repository state check',
    );
  }
  let repositoryState: GitRepositoryStateResult;
  try {
    repositoryState = await inspectRepository.call(input.context);
  } catch (error) {
    throw new Error(
      `Trusted PR first-containing repository state check failed: ${errorMessage(error)}`,
    );
  }
  if (repositoryState.status === 'shallow') {
    throw new Error(
      'Trusted PR first-containing proof cannot use a shallow git repository',
    );
  }
  if (repositoryState.status !== 'ready') {
    throw new Error(
      'Trusted PR first-containing proof could not establish a complete git repository',
    );
  }

  for (const pair of pairs) {
    const boundary = resolveDirectCommitReleaseBoundary(
      pair.targetTag,
      pair.predecessorTag,
      input.rows,
    );
    if (!boundary.valid) {
      throw new Error(
        `Trusted PR first-containing release boundary is invalid: ${boundary.detail}`,
      );
    }

    const remoteBoundary = await attestCurrentRemoteReleaseBoundary(
      boundary,
      input.context,
    );
    if (!remoteBoundary.valid) {
      throw new Error(
        `Trusted PR first-containing remote release attestation failed: ` +
        remoteBoundary.detail,
      );
    }

    for (const oid of [boundary.targetCommitOid, boundary.predecessorCommitOid]) {
      let result: GitObjectResult;
      try {
        result = await input.context.ensureObject(oid);
      } catch (error) {
        throw new Error(
          `Trusted PR first-containing git object check for ${oid} failed: ` +
          errorMessage(error),
        );
      }
      assertReleaseObjectAvailable(oid, result);
    }

    const ancestry = await firstContainingReleaseAncestryProof({
      context: input.context,
      repositoryNameWithOwner: input.repositoryNameWithOwner,
      boundary,
    });
    if (!ancestry.valid) {
      throw new Error(
        `Trusted PR first-containing release ancestry failed: ${ancestry.failure.detail}`,
      );
    }
  }
}

function firstContainingReleaseBoundaryPairs(
  targetTags: readonly string[],
  rows: readonly StableReleaseBoundaryRow[],
): Array<{ targetTag: string; predecessorTag: string }> {
  const requested = new Set(targetTags);
  if (!rows.some((row) => requested.has(row.tag))) return [];

  const ranks = rows.map((row) => row.catalog_rank);
  if (
    ranks.some((rank) => !Number.isInteger(rank) || Number(rank) < 0) ||
    new Set(ranks).size !== ranks.length
  ) {
    throw new Error(
      'Trusted PR first-containing proof requires unique active stable release catalog ranks',
    );
  }
  const ordered = rows.slice().sort((left, right) =>
    Number(left.catalog_rank) - Number(right.catalog_rank) ||
    compareBinary(left.tag, right.tag) ||
    compareBinary(left.node_id, right.node_id));
  return ordered.flatMap((row, index) => {
    const predecessor = ordered[index + 1];
    return requested.has(row.tag) && predecessor
      ? [{ targetTag: row.tag, predecessorTag: predecessor.tag }]
      : [];
  });
}

async function directCommitAncestryProof(input: {
  context: ReleaseReachabilityRefreshContext;
  repositoryNameWithOwner: string;
  releaseNodeId: string;
  tag: string;
  catalogRank: number;
  catalogDigest: string;
  catalogReleaseCount: number;
  catalogProof: ReachabilityCatalogProofIdentity | null;
  tagCommitOid: string;
  checkedCommitOid: string;
  proofKind: 'direct_commit' | 'release_boundary';
  reachableEvidence: ReachabilityEvidenceReason;
}): Promise<{
  proof: DirectCommitStrictReachabilityProof;
  command: GitCommandResult | null;
  error: string | null;
}> {
  let command: GitCommandResult;
  try {
    command = await input.context.checkAncestor(input.checkedCommitOid, input.tagCommitOid);
  } catch (error) {
    command = {
      status: null,
      stdout: '',
      stderr: `merge-base check threw: ${errorMessage(error)}`,
      signal: null,
    };
  }
  const interpreted = interpretMergeBaseResult(command, input.reachableEvidence);
  const evidence = reachabilityEvidence({
    evidence: interpreted.evidence.evidence,
    repositoryNameWithOwner: input.repositoryNameWithOwner,
    catalogProof: input.catalogProof,
    tagCommitOid: input.tagCommitOid,
    checkedCommitOid: input.checkedCommitOid,
    command,
  });
  const validation = validateReachabilityEvidence({
    evidence,
    method: REACHABILITY_METHOD,
    status: interpreted.status,
    identity: input.proofKind === 'direct_commit'
      ? {
          kind: 'direct_commit',
          repositoryNameWithOwner: input.repositoryNameWithOwner,
          tagCommitOid: input.tagCommitOid,
          checkedCommitOid: input.checkedCommitOid,
          ...(input.catalogProof ? { catalogProof: input.catalogProof } : {}),
        }
      : {
          kind: 'release_boundary',
          repositoryNameWithOwner: input.repositoryNameWithOwner,
          tagCommitOid: input.tagCommitOid,
          checkedCommitOid: input.checkedCommitOid,
          ...(input.catalogProof ? { catalogProof: input.catalogProof } : {}),
        },
  });
  return {
    proof: {
      releaseNodeId: input.releaseNodeId,
      tag: input.tag,
      catalogRank: input.catalogRank,
      catalogDigest: input.catalogDigest,
      catalogReleaseCount: input.catalogReleaseCount,
      catalogProof: input.catalogProof,
      status: interpreted.status,
      tagCommitOid: input.tagCommitOid,
      checkedCommitOid: input.checkedCommitOid,
      method: REACHABILITY_METHOD,
      evidence,
      strictValid: validation.valid,
      validationReasonCode: validation.valid ? null : validation.reasonCode,
    },
    command,
    error: validation.valid
      ? null
      : `reachability evidence violates the strict contract: ${validation.reasonCode}`,
  };
}

function directCommitFirstContainingResult(
  request: {
    repositoryNameWithOwner: string;
    commitOid: string;
    targetTag: string;
    predecessorTag: string | null;
  },
  reasonCode: Exclude<DirectCommitFirstContainingReasonCode, 'first_containing_direct_commit'>,
  input:
    | DirectCommitFirstContainingFailure
    | {
        target?: DirectCommitStrictReachabilityProof | null;
        predecessor?: DirectCommitStrictReachabilityProof | null;
        olderReleases?: DirectCommitStrictReachabilityProof[];
        releaseAncestry?: DirectCommitStrictReachabilityProof | null;
        failure: DirectCommitFirstContainingFailure;
      },
  catalogIdentity: DirectCommitReleaseCatalogIdentity | null = null,
): DirectCommitFirstContainingResult {
  const detailed = 'failure' in input
    ? input
    : { failure: input };
  return {
    schemaVersion: DIRECT_COMMIT_FIRST_CONTAINING_SCHEMA_VERSION,
    kind: 'direct_commit',
    repositoryNameWithOwner: request.repositoryNameWithOwner,
    commitOid: request.commitOid,
    targetTag: request.targetTag,
    predecessorTag: request.predecessorTag,
    status: 'withheld',
    reasonCode,
    creditEligible: false,
    catalogIdentity,
    target: detailed.target ?? null,
    predecessor: detailed.predecessor ?? null,
    olderReleases: detailed.olderReleases ?? [],
    releaseAncestry: detailed.releaseAncestry ?? null,
    failure: detailed.failure,
  };
}

export function resolveCommitOidPrefix(prefix: string): string | null {
  const normalized = String(prefix ?? '').trim().toLowerCase();
  if (!SHORT_COMMIT_OID_RE.test(normalized)) return null;
  if (!existsSync(repoDir)) return null;
  const res = git(['rev-parse', '--verify', `${normalized}^{commit}`], { allowFailure: true });
  if (res.status !== 0) return null;
  const oid = String(res.stdout ?? '').trim().toLowerCase();
  return FULL_COMMIT_OID_RE.test(oid) ? oid : null;
}

function unresolvedShortCommitReachability(
  commitOid: string,
  tagCommitOid: string | null,
): CommitReachability {
  return {
    commitOid,
    tagCommitOid,
    status: 'unknown',
    evidence: 'short_commit_oid_unresolved_or_ambiguous',
  };
}

function createReachabilityRefreshContext(input: {
  concurrency: number;
  ensureReady?: () => Promise<void>;
  runGit: (args: string[]) => Promise<GitCommandResult>;
}): ReleaseReachabilityRefreshContext {
  return new DefaultReleaseReachabilityRefreshContext(input.concurrency, {
    ensureReady: input.ensureReady ?? (async () => {}),
    runGit: input.runGit,
  });
}

class AsyncLimiter {
  private active = 0;
  private readonly waiting: Array<() => void> = [];

  constructor(private readonly limit: number) {}

  async run<T>(task: () => Promise<T>): Promise<T> {
    if (this.active >= this.limit) {
      await new Promise<void>((resolveWaiting) => this.waiting.push(resolveWaiting));
    }
    this.active++;
    try {
      return await task();
    } finally {
      this.active--;
      this.waiting.shift()?.();
    }
  }
}

function normalizeConcurrency(value: number): number {
  if (!Number.isInteger(value) || value < 1) {
    throw new Error(`git reachability concurrency must be a positive integer, got ${value}`);
  }
  return value;
}

function configuredReachabilityConcurrency(): number {
  return config.refresh.gitReachabilityConcurrency;
}

function normalizeOid(value: string): string {
  return String(value ?? '').trim().toLowerCase();
}

function canonicalIdentityText(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.trim() === value
    ? value
    : null;
}

function normalizeRepositoryIdentity(value: unknown): string | null {
  const normalized = String(value ?? '').trim().toLowerCase();
  return /^[^/\s]+\/[^/\s]+$/.test(normalized) ? normalized : null;
}

function sortedUniqueStrings(
  values: Iterable<string>,
  normalize: (value: string) => string = (value) => value,
): string[] {
  return [...new Set([...values].map(normalize))].sort(compareStrings);
}

function compareStrings(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function compareCandidates(left: PullRequestCandidate, right: PullRequestCandidate): number {
  return compareStrings(left.pr_repository_name_with_owner, right.pr_repository_name_with_owner) ||
    left.pr_number - right.pr_number ||
    compareStrings(left.merge_commit_oid ?? '', right.merge_commit_oid ?? '') ||
    compareStrings(left.base_ref_name ?? '', right.base_ref_name ?? '');
}

function candidateCheckKey(tag: string, candidate: PullRequestCandidate): string {
  return `${tag}\0${candidate.pr_repository_name_with_owner}\0${candidate.pr_number}`;
}

function assertReleaseObjectAvailable(oid: string, result: GitObjectResult): void {
  if (result.status === 'available') return;
  if (result.status === 'fetch_failed') {
    const args = ['fetch', '--filter=blob:none', '--no-tags', 'origin', oid];
    throw new Error(gitFailureMessage('release_commit_fetch_failed', args, result.command));
  }
  const args = ['cat-file', '-e', `${oid}^{commit}`];
  throw new Error(gitFailureMessage('release_commit_unavailable', args, result.command));
}

function assertPrCommitObjectAvailable(oid: string, result: GitObjectResult): void {
  if (result.status === 'available') return;
  if (result.status === 'fetch_failed') {
    const args = ['fetch', '--filter=blob:none', '--no-tags', 'origin', oid];
    throw new Error(gitFailureMessage('commit_fetch_failed', args, result.command));
  }
  const args = ['cat-file', '-e', `${oid}^{commit}`];
  throw new Error(gitFailureMessage('commit_unavailable', args, result.command));
}

function directCommitIsUnavailable(result: GitObjectResult): boolean {
  return result.status === 'unavailable' ||
    ((result.status === 'fetch_failed' || result.status === 'check_failed') &&
      isCommitUnavailableFetch(result.command));
}

function gitObjectProbeIsMissing(result: GitCommandResult): boolean {
  return result.status === 128 &&
    result.timedOut !== true &&
    result.outputLimitExceeded !== true &&
    result.aborted !== true &&
    result.signal === null;
}

function gitCommandHasCleanStatus(result: GitCommandResult, status: number): boolean {
  return result.status === status &&
    result.signal === null &&
    result.timedOut !== true &&
    result.outputLimitExceeded !== true &&
    result.aborted !== true &&
    result.processTreeTerminationFailed !== true &&
    result.stderr.trim() === '';
}

function interpretRemoteTagCommit(
  tag: string,
  command: GitCommandResult,
): GitRemoteTagCommitResult {
  const ref = `refs/tags/${tag}`;
  const peeledRef = `${ref}^{}`;
  if (gitCommandHasCleanStatus(command, 2) && command.stdout.trim() === '') {
    return { status: 'missing', command };
  }
  if (!gitCommandHasCleanStatus(command, 0)) {
    return {
      status: 'error',
      detail: gitFailureMessage(
        'remote_tag_attestation_failed',
        ['ls-remote', '--exit-code', '--tags', 'origin', ref, peeledRef],
        command,
      ),
      command,
    };
  }

  const directOids = new Set<string>();
  const peeledOids = new Set<string>();
  for (const line of command.stdout.split(/\r?\n/).filter(Boolean)) {
    const match = /^([0-9a-fA-F]{40})\t(.+)$/.exec(line);
    if (!match) {
      return {
        status: 'error',
        detail: `remote tag attestation for ${tag} returned malformed output`,
        command,
      };
    }
    const oid = normalizeOid(match[1]);
    if (match[2] === ref) directOids.add(oid);
    else if (match[2] === peeledRef) peeledOids.add(oid);
    else {
      return {
        status: 'error',
        detail:
          `remote tag attestation for ${tag} returned unexpected ref ${match[2]}`,
        command,
      };
    }
  }

  if (directOids.size === 0 && peeledOids.size === 0) {
    return { status: 'missing', command };
  }
  if (directOids.size !== 1 || peeledOids.size > 1) {
    return {
      status: 'error',
      detail: `remote tag attestation for ${tag} returned ambiguous tag identities`,
      command,
    };
  }
  return {
    status: 'resolved',
    tagCommitOid: [...peeledOids][0] ?? [...directOids][0],
    command,
  };
}

async function prepareRepository(signal?: AbortSignal): Promise<void> {
  await ensureRepo(signal);
  const args = ['remote', 'set-url', 'origin', remote];
  const result = await gitAsync(args, { signal });
  if (result.status !== 0) throw new Error(gitFailureMessage('commit_fetch_failed', args, result));
  await maintainGitCacheIfNeeded({
    runGit: gitAsync,
    maxPacks: config.refresh.gitCacheMaxPacks,
    maxSizeKiB: config.refresh.gitCacheMaxSizeMiB * 1_024,
    timeoutMs: config.refresh.gitCacheMaintenanceTimeoutMs,
    signal,
  });
}

async function ensureRepo(signal?: AbortSignal): Promise<void> {
  await mkdir(dirname(repoDir), { recursive: true });
  if (!existsSync(repoDir)) {
    const args = ['clone', '--bare', '--filter=blob:none', remote, repoDir];
    const result = await runAsync(gitCommandArgs(args, false), {
      signal,
      timeoutMs: GIT_CLONE_TIMEOUT_MS,
      maxOutputBytes: GIT_COMMAND_OUTPUT_LIMIT_BYTES,
    });
    if (result.status !== 0) {
      await rm(repoDir, { recursive: true, force: true }).catch(() => {});
      throw new Error(gitFailureMessage('commit_fetch_failed', args, result));
    }
  }
}

async function maintainGitCacheIfNeeded(input: {
  runGit: AsyncGitRunner;
  maxPacks: number;
  maxSizeKiB: number;
  timeoutMs: number;
  signal?: AbortSignal;
  warn?: (message: string) => void;
}): Promise<GitCacheMaintenanceResult> {
  const inspectArgs = ['count-objects', '-v'];
  const commandOptions = {
    signal: input.signal,
    timeoutMs: input.timeoutMs,
    maxOutputBytes: GIT_COMMAND_OUTPUT_LIMIT_BYTES,
  };
  const inspected = await input.runGit(inspectArgs, commandOptions);
  assertGitCommandSucceeded('git_cache_inspection_failed', inspectArgs, inspected);
  const before = parseGitCacheStats(inspected.stdout);
  if (!gitCacheThresholdExceeded(before, input.maxPacks, input.maxSizeKiB)) {
    return { performed: false, before, after: null };
  }

  const warn = input.warn ?? console.warn;
  warn(
    `[git-cache] compacting ${repoDir}: packs=${before.packs}, ` +
    `sizePackMiB=${formatKiBAsMiB(before.sizePackKiB)}`,
  );
  for (const args of [
    ['repack', '-A', '-d', '--write-midx'],
    ['prune', '--expire=now'],
  ]) {
    const result = await input.runGit(args, commandOptions);
    assertGitCommandSucceeded('git_cache_maintenance_failed', args, result);
  }

  const verified = await input.runGit(inspectArgs, commandOptions);
  assertGitCommandSucceeded('git_cache_inspection_failed', inspectArgs, verified);
  const after = parseGitCacheStats(verified.stdout);
  warn(
    `[git-cache] maintenance complete: packs=${after.packs}, ` +
    `sizePackMiB=${formatKiBAsMiB(after.sizePackKiB)}`,
  );
  return { performed: true, before, after };
}

function parseGitCacheStats(output: string): GitCacheStats {
  const values = new Map<string, number>();
  for (const line of output.split(/\r?\n/)) {
    const match = /^([a-z-]+):\s*(\d+)\s*$/.exec(line);
    if (match) values.set(match[1], Number(match[2]));
  }
  const packs = values.get('packs');
  const sizePackKiB = values.get('size-pack');
  if (
    typeof packs !== 'number' ||
    !Number.isInteger(packs) ||
    packs < 0 ||
    typeof sizePackKiB !== 'number' ||
    !Number.isInteger(sizePackKiB) ||
    sizePackKiB < 0
  ) {
    throw new Error(`git count-objects returned invalid pack statistics: ${output.slice(0, 500)}`);
  }
  return { packs, sizePackKiB };
}

function gitCacheThresholdExceeded(
  stats: GitCacheStats,
  maxPacks: number,
  maxSizeKiB: number,
): boolean {
  return stats.packs >= maxPacks || stats.sizePackKiB >= maxSizeKiB;
}

function formatKiBAsMiB(value: number): string {
  return (value / 1_024).toFixed(1);
}

function assertGitCommandSucceeded(
  operation: string,
  args: string[],
  result: GitCommandResult,
): void {
  if (result.status !== 0) throw new Error(gitFailureMessage(operation, args, result));
}

function gitCommandArgs(args: string[], includeRepoDir = true): string[] {
  return [
    'git',
    ...GIT_MAINTENANCE_DISABLE_ARGS,
    ...(includeRepoDir ? [`--git-dir=${repoDir}`] : []),
    ...args,
  ];
}

function git(args: string[], opts: { allowFailure?: boolean; stdio?: any } = {}) {
  return run(gitCommandArgs(args), opts);
}

function gitAsync(args: string[], options: RunCommandOptions = {}): Promise<GitCommandResult> {
  return runAsync(gitCommandArgs(args), options);
}

function interpretMergeBaseResult(
  res: GitCommandResult,
  reachableEvidence: ReachabilityEvidenceReason,
): { status: ReachabilityStatus; evidence: Record<string, unknown> & { evidence: ReachabilityEvidenceReason } } {
  if (res.status === 0) return { status: 'reachable', evidence: { evidence: reachableEvidence } };
  if (res.status === 1) return { status: 'not_reachable', evidence: { evidence: 'not_reachable_from_release_tag' } };
  return {
    status: 'unknown',
    evidence: {
      evidence: 'merge_base_error',
      status: res.status,
      stderr: trimProcessOutput(res.stderr),
      stdout: trimProcessOutput(res.stdout),
      signal: res.signal ?? null,
    },
  };
}

function reachabilityEvidence(input: {
  evidence: ReachabilityEvidenceReason;
  repositoryNameWithOwner?: string;
  catalogProof?: ReachabilityCatalogProofIdentity | null;
  tagCommitOid: string | null;
  checkedCommitOid: string | null;
  baseRefName?: string | null;
  command?: GitCommandResult | null;
}) {
  return {
    schemaVersion: REACHABILITY_EVIDENCE_SCHEMA_VERSION,
    evidence: input.evidence,
    method: REACHABILITY_METHOD,
    ...(input.repositoryNameWithOwner
      ? { repositoryNameWithOwner: input.repositoryNameWithOwner }
      : {}),
    ...(input.catalogProof ? { catalogProof: input.catalogProof } : {}),
    tagCommitOid: input.tagCommitOid,
    checkedCommitOid: input.checkedCommitOid,
    baseRefName: input.baseRefName ?? null,
    commandStatus: input.command?.status ?? null,
    stdout: trimProcessOutput(input.command?.stdout),
    stderr: trimProcessOutput(input.command?.stderr),
    signal: input.command?.signal ?? null,
    timedOut: input.command?.timedOut ?? false,
    outputLimitExceeded: input.command?.outputLimitExceeded ?? false,
    aborted: input.command?.aborted ?? false,
    ...(input.command?.processTreeTerminationFailed === undefined
      ? {}
      : { processTreeTerminationFailed: input.command.processTreeTerminationFailed }),
  };
}

function trimProcessOutput(value: unknown): string | null {
  const text = String(value ?? '').trim();
  return text ? text.slice(0, 1000) : null;
}

function gitFailureMessage(reason: string, args: string[], res: GitCommandResult): string {
  const stderr = trimProcessOutput(res.stderr);
  const stdout = trimProcessOutput(res.stdout);
  return [
    reason,
    `git ${args.join(' ')}`,
    `exited ${res.status ?? 'null'}`,
    stderr ? `stderr: ${stderr}` : null,
    stdout ? `stdout: ${stdout}` : null,
    res.signal ? `signal: ${res.signal}` : null,
    res.timedOut ? 'timed out' : null,
    res.outputLimitExceeded ? 'output limit exceeded' : null,
    res.aborted ? 'aborted' : null,
    res.processTreeTerminationFailed ? 'process tree termination failed' : null,
  ].filter(Boolean).join('; ');
}

function isCommitUnavailableFetch(res: GitCommandResult): boolean {
  const output = `${String(res.stderr ?? '')}\n${String(res.stdout ?? '')}`;
  return /\bnot our ref\b|couldn't find remote ref|could not find remote ref|remote ref .* not found/i.test(output);
}

function run(
  args: string[],
  opts: { allowFailure?: boolean; stdio?: any; timeoutMs?: number; maxOutputBytes?: number } = {},
): GitCommandResult {
  const spawned = spawnSync(args[0], args.slice(1), {
    encoding: 'utf8',
    stdio: opts.stdio ?? ['ignore', 'pipe', 'pipe'],
    timeout: opts.timeoutMs ?? GIT_COMMAND_TIMEOUT_MS,
    maxBuffer: opts.maxOutputBytes ?? GIT_COMMAND_OUTPUT_LIMIT_BYTES,
    killSignal: 'SIGTERM',
  });
  const errorCode = (spawned.error as NodeJS.ErrnoException | undefined)?.code;
  const result: GitCommandResult = {
    status: spawned.status,
    stdout: processOutputText(spawned.stdout),
    stderr: [
      processOutputText(spawned.stderr),
      spawned.error ? `${spawned.error.name}: ${spawned.error.message}` : '',
    ].filter(Boolean).join('\n'),
    signal: spawned.signal,
    timedOut: errorCode === 'ETIMEDOUT',
    outputLimitExceeded: errorCode === 'ENOBUFS',
    aborted: false,
  };
  if (result.status !== 0 && !opts.allowFailure) {
    throw new Error(`${args.join(' ')} failed: ${result.stderr || result.stdout}`);
  }
  return result;
}

function processOutputText(value: unknown): string {
  if (Buffer.isBuffer(value)) return value.toString('utf8');
  return typeof value === 'string' ? value : '';
}

function runAsync(args: string[], options: RunCommandOptions = {}): Promise<GitCommandResult> {
  const timeoutMs = normalizePositiveLimit(options.timeoutMs, GIT_COMMAND_TIMEOUT_MS, 'timeout');
  const maxOutputBytes = normalizePositiveLimit(
    options.maxOutputBytes,
    GIT_COMMAND_OUTPUT_LIMIT_BYTES,
    'output limit',
  );
  const abortSignal = options.signal;
  if (abortSignal?.aborted) {
    return Promise.resolve({
      status: null,
      stdout: '',
      stderr: 'command aborted before spawn',
      signal: null,
      aborted: true,
    });
  }

  return new Promise((resolveCommand) => {
    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(args[0], args.slice(1), {
        stdio: ['ignore', 'pipe', 'pipe'],
        detached: process.platform !== 'win32',
        env: process.env.RADAR_TEST_RUN_ID
          ? {
              ...process.env,
              RADAR_TEST_DETACHED_SCOPE: 'release-reachability',
            }
          : undefined,
        windowsHide: true,
      });
    } catch (error) {
      resolveCommand({
        status: null,
        stdout: '',
        stderr: `spawn failed: ${errorMessage(error)}`,
        signal: null,
      });
      return;
    }

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    let capturedBytes = 0;
    let settled = false;
    let timedOut = false;
    let outputLimitExceeded = false;
    let aborted = false;
    let processTreeTerminationFailed = false;
    let terminationStarted = false;
    let forceKillTimer: NodeJS.Timeout | null = null;
    let hardSettleTimer: NodeJS.Timeout | null = null;
    let pendingClose: {
      status: number | null;
      signal: NodeJS.Signals | null;
    } | null = null;

    const finish = (status: number | null, signal: NodeJS.Signals | null, spawnError?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutTimer);
      if (forceKillTimer) clearTimeout(forceKillTimer);
      if (hardSettleTimer) clearTimeout(hardSettleTimer);
      abortSignal?.removeEventListener('abort', abortListener);
      const diagnostics = [
        spawnError ? `spawn failed: ${errorMessage(spawnError)}` : null,
        timedOut ? `command timed out after ${timeoutMs}ms` : null,
        outputLimitExceeded ? `command output exceeded ${maxOutputBytes} bytes` : null,
        aborted ? 'command aborted' : null,
        processTreeTerminationFailed ? 'process tree termination failed' : null,
      ].filter((value): value is string => Boolean(value));
      const stderr = Buffer.concat(stderrChunks).toString('utf8');
      const cancelled =
        timedOut || outputLimitExceeded || aborted || processTreeTerminationFailed;
      resolveCommand({
        status: cancelled ? null : status,
        stdout: Buffer.concat(stdoutChunks).toString('utf8'),
        stderr: [stderr, ...diagnostics].filter(Boolean).join('\n'),
        signal,
        timedOut,
        outputLimitExceeded,
        aborted,
        processTreeTerminationFailed,
      });
    };

    const terminate = () => {
      if (terminationStarted || settled) return;
      terminationStarted = true;
      signalProcessTree(child, 'SIGTERM');
      forceKillTimer = setTimeout(() => {
        if (settled) return;
        signalProcessTree(child, 'SIGKILL');
        hardSettleTimer = setTimeout(() => {
          if (settled) return;
          if (child.pid !== undefined && posixProcessGroupExists(child.pid)) {
            processTreeTerminationFailed = true;
            finish(null, 'SIGKILL');
            return;
          }
          finish(pendingClose?.status ?? null, pendingClose?.signal ?? 'SIGKILL');
        }, GIT_TERMINATION_GRACE_MS);
      }, GIT_TERMINATION_GRACE_MS);
    };

    const capture = (target: Buffer[], chunk: Buffer | string) => {
      const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
      const remaining = maxOutputBytes - capturedBytes;
      if (remaining > 0) {
        const captured = buffer.length <= remaining ? buffer : buffer.subarray(0, remaining);
        target.push(captured);
        capturedBytes += captured.length;
      }
      if (buffer.length > remaining && !outputLimitExceeded) {
        outputLimitExceeded = true;
        terminate();
      }
    };

    const timeoutTimer = setTimeout(() => {
      timedOut = true;
      terminate();
    }, timeoutMs);
    timeoutTimer.unref();
    const abortListener = () => {
      aborted = true;
      terminate();
    };
    abortSignal?.addEventListener('abort', abortListener, { once: true });
    if (abortSignal?.aborted) abortListener();

    child.stdout!.on('data', (chunk) => capture(stdoutChunks, chunk));
    child.stderr!.on('data', (chunk) => capture(stderrChunks, chunk));
    child.once('error', (error) => finish(null, null, error));
    child.once('close', (status, signal) => {
      if (
        terminationStarted &&
        child.pid !== undefined &&
        posixProcessGroupExists(child.pid)
      ) {
        pendingClose = { status, signal };
        return;
      }
      finish(status, signal);
    });
  });
}

function signalProcessTree(
  child: ReturnType<typeof spawn>,
  signal: NodeJS.Signals,
): void {
  const pid = child.pid;
  if (pid !== undefined && process.platform !== 'win32') {
    try {
      process.kill(-pid, signal);
      return;
    } catch {
      // Fall through if the process group disappeared or could not be signalled.
    }
  }

  if (pid !== undefined && process.platform === 'win32') {
    const taskkill = spawnSync(
      'taskkill.exe',
      ['/pid', String(pid), '/T', '/F'],
      {
        stdio: 'ignore',
        windowsHide: true,
        timeout: GIT_TERMINATION_GRACE_MS,
      },
    );
    if (taskkill.status === 0) return;
  }

  try {
    child.kill(signal);
  } catch {
    // The direct child may already have exited.
  }
}

function posixProcessGroupExists(pid: number): boolean {
  if (process.platform === 'win32') return false;
  try {
    process.kill(-pid, 0);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

function normalizePositiveLimit(value: number | undefined, fallback: number, name: string): number {
  const normalized = value ?? fallback;
  const rounded = Math.floor(normalized);
  if (!Number.isFinite(normalized) || rounded < 1) {
    throw new Error(`git command ${name} must be positive, got ${normalized}`);
  }
  return rounded;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const __releaseReachabilityTest = {
  KNOWN_REACHABILITY_EVIDENCE_REASONS,
  UNKNOWN_REACHABILITY_RETRY_MS,
  assertTrustedPullRequestFirstContainingReleaseBoundaries,
  createReachabilityRefreshContext,
  directCommitIsUnavailable,
  evaluateDirectCommitFirstContainingRelease,
  existingReachabilityRowIsReusable,
  gitCacheThresholdExceeded,
  gitCommandArgs,
  interpretMergeBaseResult,
  maintainGitCacheIfNeeded,
  parseGitCacheStats,
  reachabilityEvidence,
  resolveDirectCommitReleaseBoundary,
  runAsync,
  stageReleasePrReachabilityBulk,
  unresolvedShortCommitReachability,
  validateReachabilityEvidence,
};
