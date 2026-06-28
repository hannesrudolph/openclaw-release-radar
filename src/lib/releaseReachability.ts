import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { db, deleteReleasePrReachabilityForRelease, upsertReleasePrReachability } from './db';
import { creditedFixLinkSql } from './fixProvenance';

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

const remote = process.env.OPENCLAW_REPO_URL ?? 'https://github.com/openclaw/openclaw.git';
const repoDir = resolve('.cache/openclaw.git');

const candidateStmt = db.prepare(`
SELECT DISTINCT p.pr_number, p.merge_commit_oid, p.base_ref_name
FROM pull_request_fixes p
JOIN issue_pr_links l ON l.pr_number = p.pr_number
JOIN issue_closure_events e ON e.issue_number = l.issue_number
WHERE e.state_reason='COMPLETED'
  AND p.merged = 1
  AND ${creditedFixLinkSql('l')}
`);

const releaseCommitStmt = db.prepare('SELECT tag_commit_oid FROM release_commits WHERE tag=?');

export async function checkReleasePrReachability(tag: string): Promise<ReleaseReachabilityResult> {
  const candidates = candidateStmt.all() as Array<{
    pr_number: number;
    merge_commit_oid: string | null;
    base_ref_name: string | null;
  }>;
  let reachable = 0;
  let unknown = 0;
  let notReachable = 0;
  deleteReleasePrReachabilityForRelease(tag);

  const release = releaseCommitStmt.get(tag) as { tag_commit_oid: string | null } | undefined;
  if (!release?.tag_commit_oid) {
    for (const candidate of candidates) {
      upsertReleasePrReachability({
        tag,
        pr_number: candidate.pr_number,
        tag_commit_oid: null,
        merge_commit_oid: candidate.merge_commit_oid ?? null,
        base_ref_name: candidate.base_ref_name ?? null,
        status: 'unknown',
        evidence_json: JSON.stringify({ evidence: 'release_commit_unavailable' }),
      });
      unknown++;
    }
    return { tag, releaseCommit: null, candidates: candidates.length, reachable: 0, notReachable: 0, unknown };
  }

  await ensureRepo();
  git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
  const releaseFetch = git(['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid], {
    allowFailure: true,
    stdio: 'inherit',
  });
  if (releaseFetch.status !== 0) {
    for (const candidate of candidates) {
      upsertReleasePrReachability({
        tag,
        pr_number: candidate.pr_number,
        tag_commit_oid: release.tag_commit_oid,
        merge_commit_oid: candidate.merge_commit_oid ?? null,
        base_ref_name: candidate.base_ref_name ?? null,
        status: 'unknown',
        evidence_json: JSON.stringify({ evidence: 'release_commit_fetch_failed', status: releaseFetch.status }),
      });
      unknown++;
    }
    return { tag, releaseCommit: release.tag_commit_oid, candidates: candidates.length, reachable: 0, notReachable: 0, unknown };
  }

  for (const candidate of candidates) {
    const commit = candidate.merge_commit_oid;
    if (!commit) {
      upsertReleasePrReachability({
        tag,
        pr_number: candidate.pr_number,
        tag_commit_oid: release.tag_commit_oid,
        merge_commit_oid: null,
        base_ref_name: candidate.base_ref_name ?? null,
        status: 'unknown',
        evidence_json: JSON.stringify({ evidence: 'merge_commit_oid_unavailable' }),
      });
      unknown++;
      continue;
    }
    git(['fetch', '--filter=blob:none', '--no-tags', 'origin', commit], { allowFailure: true });
    const exists = git(['cat-file', '-e', `${commit}^{commit}`], { allowFailure: true });
    if (exists.status !== 0) {
      upsertReleasePrReachability({
        tag,
        pr_number: candidate.pr_number,
        tag_commit_oid: release.tag_commit_oid,
        merge_commit_oid: commit,
        base_ref_name: candidate.base_ref_name ?? null,
        status: 'unknown',
        evidence_json: JSON.stringify({ evidence: 'commit_unavailable' }),
      });
      unknown++;
      continue;
    }

    const res = git(['merge-base', '--is-ancestor', commit, release.tag_commit_oid], { allowFailure: true });
    const interpreted = interpretMergeBaseResult(res, 'merge_commit_in_release_history');
    upsertReleasePrReachability({
      tag,
      pr_number: candidate.pr_number,
      tag_commit_oid: release.tag_commit_oid,
      merge_commit_oid: commit,
      base_ref_name: candidate.base_ref_name ?? null,
      status: interpreted.status,
      evidence_json: JSON.stringify(interpreted.evidence),
    });
    if (interpreted.status === 'reachable') reachable++;
    else if (interpreted.status === 'not_reachable') notReachable++;
    else unknown++;
  }

  return {
    tag,
    releaseCommit: release.tag_commit_oid,
    candidates: candidates.length,
    reachable,
    notReachable,
    unknown,
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
    for (const commitOid of uniqueCommits) {
      results.set(commitOid, {
        commitOid,
        tagCommitOid: null,
        status: 'unknown',
        evidence: 'release_commit_unavailable',
      });
    }
    return results;
  }

  await ensureRepo();
  git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
  const releaseFetch = git(['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid], {
    allowFailure: true,
    stdio: 'inherit',
  });
  if (releaseFetch.status !== 0) {
    for (const commitOid of uniqueCommits) {
      results.set(commitOid, {
        commitOid,
        tagCommitOid: release.tag_commit_oid,
        status: 'unknown',
        evidence: 'release_commit_fetch_failed',
      });
    }
    return results;
  }

  for (const commitOid of uniqueCommits) {
    git(['fetch', '--filter=blob:none', '--no-tags', 'origin', commitOid], { allowFailure: true });
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
    const res = git(['merge-base', '--is-ancestor', commitOid, release.tag_commit_oid], { allowFailure: true });
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
  reachableEvidence: string,
): { status: CommitReachability['status']; evidence: Record<string, unknown> & { evidence: string } } {
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

function trimProcessOutput(value: unknown): string | null {
  const text = String(value ?? '').trim();
  return text ? text.slice(0, 1000) : null;
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
  interpretMergeBaseResult,
};
