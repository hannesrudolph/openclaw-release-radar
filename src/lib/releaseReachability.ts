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

const remote = process.env.OPENCLAW_REPO_URL ?? 'https://github.com/openclaw/openclaw.git';
const repoDir = resolve('.cache/openclaw.git');

const candidateStmt = db.prepare(`
SELECT DISTINCT p.pr_number, p.merge_commit_oid, p.base_ref_name
FROM pull_request_fixes p
JOIN issue_pr_links l ON l.pr_number = p.pr_number
JOIN issue_closure_events e ON e.issue_number = l.issue_number
WHERE e.state_reason='COMPLETED'
  AND p.merged = 1
  AND p.merge_commit_oid IS NOT NULL
  AND ${creditedFixLinkSql('l')}
`);

const releaseCommitStmt = db.prepare('SELECT tag_commit_oid FROM release_commits WHERE tag=?');

export async function checkReleasePrReachability(tag: string): Promise<ReleaseReachabilityResult> {
  const release = releaseCommitStmt.get(tag) as { tag_commit_oid: string | null } | undefined;
  if (!release?.tag_commit_oid) {
    return { tag, releaseCommit: null, candidates: 0, reachable: 0, notReachable: 0, unknown: 0 };
  }

  await ensureRepo();
  git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
  git(['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid], { stdio: 'inherit' });

  const candidates = candidateStmt.all() as Array<{
    pr_number: number;
    merge_commit_oid: string;
    base_ref_name: string | null;
  }>;
  let reachable = 0;
  let unknown = 0;
  deleteReleasePrReachabilityForRelease(tag);

  for (const candidate of candidates) {
    const commit = candidate.merge_commit_oid;
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
    const isReachable = res.status === 0;
    upsertReleasePrReachability({
      tag,
      pr_number: candidate.pr_number,
      tag_commit_oid: release.tag_commit_oid,
      merge_commit_oid: commit,
      base_ref_name: candidate.base_ref_name ?? null,
      status: isReachable ? 'reachable' : 'not_reachable',
      evidence_json: JSON.stringify({
        evidence: isReachable ? 'merge_commit_in_release_history' : 'not_reachable_from_release_tag',
      }),
    });
    if (isReachable) reachable++;
  }

  return {
    tag,
    releaseCommit: release.tag_commit_oid,
    candidates: candidates.length,
    reachable,
    notReachable: candidates.length - reachable - unknown,
    unknown,
  };
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
