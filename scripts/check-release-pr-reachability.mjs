import { existsSync } from 'node:fs';
import { mkdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { db, upsertReleasePrReachability } from '../src/lib/db.ts';

const tag = process.argv[2] ?? 'v2026.6.10';
const remote = process.env.OPENCLAW_REPO_URL ?? 'https://github.com/openclaw/openclaw.git';
const repoDir = resolve('.cache/openclaw.git');

function run(args, opts = {}) {
  const res = spawnSync(args[0], args.slice(1), {
    encoding: 'utf8',
    stdio: opts.stdio ?? ['ignore', 'pipe', 'pipe'],
    ...opts,
  });
  if (res.status !== 0 && !opts.allowFailure) {
    throw new Error(`${args.join(' ')} failed: ${res.stderr || res.stdout}`);
  }
  return res;
}

async function ensureRepo() {
  await mkdir(dirname(repoDir), { recursive: true });
  if (!existsSync(repoDir)) {
    run(['git', 'clone', '--bare', '--filter=blob:none', remote, repoDir], { stdio: 'inherit' });
  }
}

function git(args, opts = {}) {
  return run(['git', `--git-dir=${repoDir}`, ...args], opts);
}

await ensureRepo();

// This table changed shape during calibration; recreate it locally if an older
// checkpoint left the previous columns behind.
db.exec(`DROP TABLE IF EXISTS release_pr_reachability`);
db.exec(`
CREATE TABLE IF NOT EXISTS release_pr_reachability (
  tag TEXT NOT NULL,
  pr_number INTEGER NOT NULL,
  tag_commit_oid TEXT NOT NULL,
  merge_commit_oid TEXT NOT NULL,
  base_ref_name TEXT,
  status TEXT NOT NULL,
  method TEXT NOT NULL DEFAULT 'git-merge-base',
  evidence_json TEXT NOT NULL DEFAULT '{}',
  checked_at TEXT NOT NULL,
  PRIMARY KEY (tag, pr_number)
)`);
db.exec(`CREATE INDEX IF NOT EXISTS idx_release_pr_reachability_tag ON release_pr_reachability(tag)`);

const release = db.prepare('SELECT tag_commit_oid FROM release_commits WHERE tag=?').get(tag);
if (!release?.tag_commit_oid) throw new Error(`missing release commit for ${tag}; run ingest:fix-provenance first`);

const candidates = db.prepare(`
SELECT DISTINCT p.pr_number, p.merge_commit_oid, p.base_ref_name
FROM pull_request_fixes p
JOIN issue_pr_links l ON l.pr_number = p.pr_number
JOIN issue_closure_events e ON e.issue_number = l.issue_number
WHERE p.merged = 1
  AND p.merge_commit_oid IS NOT NULL
`).all();

git(['remote', 'set-url', 'origin', remote], { allowFailure: true });
git(['fetch', '--filter=blob:none', '--no-tags', 'origin', release.tag_commit_oid], { stdio: 'inherit' });

let reachable = 0;
let unknown = 0;
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

console.log(JSON.stringify({
  tag,
  releaseCommit: release.tag_commit_oid,
  candidates: candidates.length,
  reachable,
  notReachable: candidates.length - reachable - unknown,
  unknown,
}, null, 2));
