import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { config } from '../config';
import { db, replaceReleasePrReachabilityForRelease, type ReleasePrReachabilityInput } from './db';

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
  status: 'reachable' | 'not_reachable' | 'unknown';
  evidence: string;
}

type ReachabilityStatus = CommitReachability['status'];

type ReachabilityEvidenceReason =
  | 'merge_commit_in_release_history'
  | 'fix_commit_in_release_history'
  | 'not_reachable_from_release_tag'
  | 'release_commit_unavailable'
  | 'release_commit_fetch_failed'
  | 'merge_commit_oid_unavailable'
  | 'commit_fetch_failed'
  | 'commit_unavailable'
  | 'merge_base_error';

const remote = process.env.OPENCLAW_REPO_URL ?? 'https://github.com/openclaw/openclaw.git';
const repoDir = resolve('.cache/openclaw.git');
const trackedRepositoryNameWithOwner = `${config.github.owner}/${config.github.repo}`;
const REACHABILITY_EVIDENCE_SCHEMA_VERSION = 1;
const REACHABILITY_METHOD = 'git-merge-base';

export const KNOWN_REACHABILITY_EVIDENCE_REASONS: readonly ReachabilityEvidenceReason[] = [
  'merge_commit_in_release_history',
  'fix_commit_in_release_history',
  'not_reachable_from_release_tag',
  'release_commit_unavailable',
  'release_commit_fetch_failed',
  'merge_commit_oid_unavailable',
  'commit_fetch_failed',
  'commit_unavailable',
  'merge_base_error',
] as const;

const candidateStmt = db.prepare(`
SELECT DISTINCT
  p.pr_repository_owner,
  p.pr_repository_name,
  p.pr_repository_name_with_owner,
  p.pr_number,
  p.merge_commit_oid,
  p.base_ref_name
FROM pull_request_fixes p
JOIN issue_pr_links l ON l.pr_repository_name_with_owner = p.pr_repository_name_with_owner AND l.pr_number = p.pr_number
WHERE p.merged = 1
  AND p.pr_repository_name_with_owner = ?
`);

const releaseCommitStmt = db.prepare('SELECT tag_commit_oid FROM release_commits WHERE tag=?');

export async function checkReleasePrReachability(tag: string): Promise<ReleaseReachabilityResult> {
  const candidates = candidateStmt.all(trackedRepositoryNameWithOwner) as Array<{
    pr_repository_owner: string;
    pr_repository_name: string;
    pr_repository_name_with_owner: string;
    pr_number: number;
    merge_commit_oid: string | null;
    base_ref_name: string | null;
  }>;
  let reachable = 0;
  let unknown = 0;
  let notReachable = 0;
  const rows: ReleasePrReachabilityInput[] = [];

  const release = releaseCommitStmt.get(tag) as { tag_commit_oid: string | null } | undefined;
  if (!release?.tag_commit_oid) {
    throw new Error(`Release ${tag} has no tag commit evidence; refusing to replace PR reachability rows`);
  }

  await ensureRepo();
  git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
  const releaseFetchArgs = ['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid];
  const releaseFetch = git(releaseFetchArgs, {
    allowFailure: true,
    stdio: 'inherit',
  });
  if (releaseFetch.status !== 0) {
    throw new Error(gitFailureMessage('release_commit_fetch_failed', releaseFetchArgs, releaseFetch));
  }

  for (const candidate of candidates) {
    const commit = candidate.merge_commit_oid;
    if (!commit) {
      rows.push(reachabilityRow(candidate, tag, {
        tagCommitOid: release.tag_commit_oid,
        mergeCommitOid: null,
        status: 'unknown',
        evidence: reachabilityEvidence({
          evidence: 'merge_commit_oid_unavailable',
          tagCommitOid: release.tag_commit_oid,
          checkedCommitOid: null,
          baseRefName: candidate.base_ref_name ?? null,
        }),
      }));
      unknown++;
      continue;
    }
    const commitFetchArgs = ['fetch', '--filter=blob:none', '--no-tags', 'origin', commit];
    const commitFetch = git(commitFetchArgs, { allowFailure: true });
    if (commitFetch.status !== 0) {
      throw new Error(gitFailureMessage('commit_fetch_failed', commitFetchArgs, commitFetch));
    }
    const existsArgs = ['cat-file', '-e', `${commit}^{commit}`];
    const exists = git(existsArgs, { allowFailure: true });
    if (exists.status !== 0) {
      throw new Error(gitFailureMessage('commit_unavailable', existsArgs, exists));
    }

    const mergeBaseArgs = ['merge-base', '--is-ancestor', commit, release.tag_commit_oid];
    const res = git(mergeBaseArgs, { allowFailure: true });
    if (res.status !== 0 && res.status !== 1) {
      throw new Error(gitFailureMessage('merge_base_error', mergeBaseArgs, res));
    }
    const interpreted = interpretMergeBaseResult(res, 'merge_commit_in_release_history');
    rows.push(reachabilityRow(candidate, tag, {
      tagCommitOid: release.tag_commit_oid,
      mergeCommitOid: commit,
      status: interpreted.status,
      evidence: reachabilityEvidence({
        evidence: interpreted.evidence.evidence as ReachabilityEvidenceReason,
        tagCommitOid: release.tag_commit_oid,
        checkedCommitOid: commit,
        baseRefName: candidate.base_ref_name ?? null,
        command: res,
      }),
    }));
    if (interpreted.status === 'reachable') reachable++;
    else if (interpreted.status === 'not_reachable') notReachable++;
    else unknown++;
  }

  replaceReleasePrReachabilityForRelease(tag, rows);

  return {
    tag,
    releaseCommit: release.tag_commit_oid,
    candidates: candidates.length,
    reachable,
    notReachable,
    unknown,
  };
}

function reachabilityRow(candidate: {
  pr_repository_owner: string;
  pr_repository_name: string;
  pr_repository_name_with_owner: string;
  pr_number: number;
  base_ref_name: string | null;
}, tag: string, input: {
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
    evidence_json: JSON.stringify(input.evidence),
  };
}

export async function checkReleaseCommitReachability(
  tag: string,
  commitOids: string[],
): Promise<Map<string, CommitReachability>> {
  const uniqueCommits = [...new Set(commitOids.map((oid) => oid.toLowerCase()))]
    .filter((oid) => /^[0-9a-f]{40}$/.test(oid));
  const results = new Map<string, CommitReachability>();
  if (!uniqueCommits.length) return results;
  const release = releaseCommitStmt.get(tag) as { tag_commit_oid: string | null } | undefined;
  if (!release?.tag_commit_oid) {
    throw new Error(`Release ${tag} has no tag commit evidence; refusing to check direct commit reachability`);
  }

  await ensureRepo();
  git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
  const releaseFetchArgs = ['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid];
  const releaseFetch = git(releaseFetchArgs, {
    allowFailure: true,
    stdio: 'inherit',
  });
  if (releaseFetch.status !== 0) {
    throw new Error(gitFailureMessage('release_commit_fetch_failed', releaseFetchArgs, releaseFetch));
  }

  for (const commitOid of uniqueCommits) {
    const commitFetchArgs = ['fetch', '--filter=blob:none', '--no-tags', 'origin', commitOid];
    const commitFetch = git(commitFetchArgs, { allowFailure: true });
    if (commitFetch.status !== 0) {
      if (isCommitUnavailableFetch(commitFetch)) {
        results.set(commitOid, {
          commitOid,
          tagCommitOid: release.tag_commit_oid,
          status: 'unknown',
          evidence: 'commit_unavailable',
        });
        continue;
      }
      throw new Error(gitFailureMessage('commit_fetch_failed', commitFetchArgs, commitFetch));
    }
    const exists = git(['cat-file', '-e', `${commitOid}^{commit}`], { allowFailure: true });
    if (exists.status !== 0) {
      results.set(commitOid, {
        commitOid,
        tagCommitOid: release.tag_commit_oid,
        status: 'unknown',
        evidence: 'commit_unavailable',
      });
      continue;
    }
    const mergeBaseArgs = ['merge-base', '--is-ancestor', commitOid, release.tag_commit_oid];
    const res = git(mergeBaseArgs, { allowFailure: true });
    if (res.status !== 0 && res.status !== 1) {
      throw new Error(gitFailureMessage('merge_base_error', mergeBaseArgs, res));
    }
    const interpreted = interpretMergeBaseResult(res, 'fix_commit_in_release_history');
    results.set(commitOid, {
      commitOid,
      tagCommitOid: release.tag_commit_oid,
      status: interpreted.status,
      evidence: interpreted.evidence.evidence,
    });
  }

  return results;
}

export function resolveCommitOidPrefix(prefix: string): string | null {
  const normalized = String(prefix ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{7,39}$/.test(normalized)) return null;
  if (!existsSync(repoDir)) return null;
  const res = git(['rev-parse', '--verify', `${normalized}^{commit}`], { allowFailure: true });
  if (res.status !== 0) return null;
  const oid = String(res.stdout ?? '').trim().toLowerCase();
  return /^[0-9a-f]{40}$/.test(oid) ? oid : null;
}

async function ensureRepo(): Promise<void> {
  await mkdir(dirname(repoDir), { recursive: true });
  if (!existsSync(repoDir)) {
    run(['git', 'clone', '--bare', '--filter=blob:none', remote, repoDir], { stdio: 'inherit' });
  }
}

function git(args: string[], opts: { allowFailure?: boolean; stdio?: any } = {}) {
  return run(['git', `--git-dir=${repoDir}`, ...args], opts);
}

function interpretMergeBaseResult(
  res: ReturnType<typeof run>,
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
  tagCommitOid: string | null;
  checkedCommitOid: string | null;
  baseRefName?: string | null;
  command?: ReturnType<typeof run> | null;
}) {
  return {
    schemaVersion: REACHABILITY_EVIDENCE_SCHEMA_VERSION,
    evidence: input.evidence,
    method: REACHABILITY_METHOD,
    tagCommitOid: input.tagCommitOid,
    checkedCommitOid: input.checkedCommitOid,
    baseRefName: input.baseRefName ?? null,
    commandStatus: input.command?.status ?? null,
    stdout: trimProcessOutput(input.command?.stdout),
    stderr: trimProcessOutput(input.command?.stderr),
    signal: input.command?.signal ?? null,
  };
}

function trimProcessOutput(value: unknown): string | null {
  const text = String(value ?? '').trim();
  return text ? text.slice(0, 1000) : null;
}

function gitFailureMessage(reason: ReachabilityEvidenceReason, args: string[], res: ReturnType<typeof run>): string {
  const stderr = trimProcessOutput(res.stderr);
  const stdout = trimProcessOutput(res.stdout);
  return [
    reason,
    `git ${args.join(' ')}`,
    `exited ${res.status ?? 'null'}`,
    stderr ? `stderr: ${stderr}` : null,
    stdout ? `stdout: ${stdout}` : null,
    res.signal ? `signal: ${res.signal}` : null,
  ].filter(Boolean).join('; ');
}

function isCommitUnavailableFetch(res: ReturnType<typeof run>): boolean {
  const output = `${String(res.stderr ?? '')}\n${String(res.stdout ?? '')}`;
  return /\bnot our ref\b|couldn't find remote ref|could not find remote ref|remote ref .* not found/i.test(output);
}

function run(args: string[], opts: { allowFailure?: boolean; stdio?: any } = {}) {
  const res = spawnSync(args[0], args.slice(1), {
    encoding: 'utf8',
    stdio: opts.stdio ?? ['ignore', 'pipe', 'pipe'],
  });
  if (res.status !== 0 && !opts.allowFailure) {
    throw new Error(`${args.join(' ')} failed: ${res.stderr || res.stdout}`);
  }
  return res;
}

export const __releaseReachabilityTest = {
  KNOWN_REACHABILITY_EVIDENCE_REASONS,
  interpretMergeBaseResult,
  reachabilityEvidence,
};
