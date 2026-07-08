import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { execFileSync } from 'node:child_process';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { projectDirectCommitStableReleaseBoundaries } from './directCommitReleaseCatalog.ts';
let __releaseReachabilityTest: typeof import('./releaseReachability.ts').__releaseReachabilityTest;
let checkReleaseCommitReachability: typeof import('./releaseReachability.ts').checkReleaseCommitReachability;
let closureCommentCommitMentions: typeof import('./github.ts').closureCommentCommitMentions;
let testDb: typeof import('./db.ts').db;
let readAuthorizedReleaseReachabilityData: typeof import('./db.ts').readAuthorizedReleaseReachabilityData;
let replaceActiveReleaseCatalog: typeof import('./db.ts').replaceActiveReleaseCatalog;
let replaceReleasePrReachabilityForRelease: typeof import('./db.ts').replaceReleasePrReachabilityForRelease;
let releasePrReachabilityRows: typeof import('./db.ts').releasePrReachabilityRows;
let upsertIssuePrLink: typeof import('./db.ts').upsertIssuePrLink;
let upsertPullRequestFix: typeof import('./db.ts').upsertPullRequestFix;
let upsertReleaseCommit: typeof import('./db.ts').upsertReleaseCommit;

const authorizedReleaseFixtures = [
  {
    tag: 'v-transient-check',
    commitOid: 'd'.repeat(40),
    publishedAt: '2026-07-07T00:00:00Z',
  },
  {
    tag: 'v-transient-fetch',
    commitOid: 'c'.repeat(40),
    publishedAt: '2026-07-06T00:00:00Z',
  },
  {
    tag: 'v-confirmed-reuse',
    commitOid: '7'.repeat(40),
    publishedAt: '2026-07-05T00:00:00Z',
  },
  {
    tag: 'v-confirmed-two',
    commitOid: '5'.repeat(40),
    publishedAt: '2026-07-04T00:00:00Z',
  },
  {
    tag: 'v-confirmed-one',
    commitOid: '4'.repeat(40),
    publishedAt: '2026-07-03T00:00:00Z',
  },
  {
    tag: 'v-short-sha-stale-cache',
    commitOid: 'a'.repeat(40),
    publishedAt: '2026-07-02T00:00:00Z',
  },
  {
    tag: 'v2',
    commitOid: '2'.repeat(40),
    publishedAt: '2026-07-01T00:00:00Z',
  },
  {
    tag: 'v1',
    commitOid: '1'.repeat(40),
    publishedAt: '2026-06-30T00:00:00Z',
  },
] as const;
const authorizedReleaseCommits = new Map<string, string>(
  authorizedReleaseFixtures.map((release) => [release.tag, release.commitOid] as const),
);
const authorizedCatalogProofs = new Map<string, {
  catalogDigest: string;
  catalogReceiptId: string;
  releaseNodeId: string;
  checkedReleaseNodeId: null;
}>();

before(async () => {
  ({
    __releaseReachabilityTest,
    checkReleaseCommitReachability,
  } = await import('./releaseReachability.ts'));
  ({ closureCommentCommitMentions } = await import('./github.ts'));
  ({
    db: testDb,
    readAuthorizedReleaseReachabilityData,
    replaceActiveReleaseCatalog,
    replaceReleasePrReachabilityForRelease,
    releasePrReachabilityRows,
    upsertIssuePrLink,
    upsertPullRequestFix,
    upsertReleaseCommit,
  } = await import('./db.ts'));

  replaceActiveReleaseCatalog(
    authorizedReleaseFixtures.map((release) => ({
      node_id: `release-node:${release.tag}`,
      catalog_tag_commit_oid: release.commitOid,
      tag: release.tag,
      name: release.tag,
      published_at: release.publishedAt,
      created_at: release.publishedAt,
      updated_at: release.publishedAt,
      html_url: `https://example.test/releases/${encodeURIComponent(release.tag)}`,
      prerelease: false,
      body: '',
    })),
    { capture: { source: 'test_fixture' } },
  );
  for (const release of authorizedReleaseFixtures) {
    upsertReleaseCommit({
      tag: release.tag,
      tag_commit_oid: release.commitOid,
      committed_at: release.publishedAt,
    });
  }

  const authorized = readAuthorizedReleaseReachabilityData({
    releaseTags: authorizedReleaseFixtures.map((release) => release.tag),
    integrityExampleLimit: 0,
  });
  assert.equal(authorized.catalog.releaseCount, authorizedReleaseFixtures.length);
  assert.match(authorized.catalog.digest, /^[0-9a-f]{64}$/);
  assert.match(authorized.catalog.receiptId, /^[0-9a-f]{64}$/);
  for (const requested of authorized.requestedReleases) {
    const release = requested.release;
    assert.ok(release, `authorized release fixture ${requested.tag} is missing`);
    authorizedCatalogProofs.set(requested.tag, {
      catalogDigest: authorized.catalog.digest,
      catalogReceiptId: authorized.catalog.receiptId,
      releaseNodeId: release.releaseNodeId,
      checkedReleaseNodeId: null,
    });
  }
  assert.equal(authorizedCatalogProofs.size, authorizedReleaseFixtures.length);
});

after(() => {
  testDb.close();
});

function authorizedReleaseCommitForTag(tag: string): string {
  const commitOid = authorizedReleaseCommits.get(tag);
  assert.ok(commitOid, `authorized release fixture ${tag} has no commit`);
  return commitOid;
}

function authorizedCatalogProofForTag(tag: string) {
  const proof = authorizedCatalogProofs.get(tag);
  assert.ok(proof, `authorized release fixture ${tag} has no catalog proof`);
  return proof;
}

function command(
  status: number | null,
  stderr = '',
  stdout = '',
  extra: Record<string, unknown> = {},
) {
  return { status, stdout, stderr, signal: null, ...extra };
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function processIsRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ESRCH') return false;
    throw error;
  }
}

async function waitForProcessExit(pid: number, timeoutMs: number): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (processIsRunning(pid) && Date.now() < deadline) await delay(20);
  return !processIsRunning(pid);
}

function forceKillIfRunning(pid: number): void {
  try {
    process.kill(pid, 'SIGKILL');
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== 'ESRCH') throw error;
  }
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', args, {
    cwd,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    env: {
      ...process.env,
      GIT_AUTHOR_NAME: 'Release Reachability Test',
      GIT_AUTHOR_EMAIL: 'reachability@example.test',
      GIT_COMMITTER_NAME: 'Release Reachability Test',
      GIT_COMMITTER_EMAIL: 'reachability@example.test',
    },
  }).trim();
}

async function writeCommit(
  worktree: string,
  relativePath: string,
  contents: string,
  message: string,
): Promise<string> {
  await writeFile(join(worktree, relativePath), contents);
  git(worktree, ['add', relativePath]);
  git(worktree, ['commit', '-m', message]);
  return git(worktree, ['rev-parse', 'HEAD']);
}

interface GitFixture {
  root: string;
  worktree: string;
  remote: string;
  cache: string;
  mergeSource: string;
  mergeRelease: string;
  originalSquash: string;
  squashRelease: string;
  originalRebase: string;
  advanceCommit: string;
  rebasedCommit: string;
  rebaseRelease: string;
  lightweightTagCommit: string;
  annotatedTagObject: string;
  annotatedTagCommit: string;
  movedTagOldCommit: string;
  movedTagNewCommit: string;
}

async function createGitFixture(): Promise<GitFixture> {
  const root = await mkdtemp(join(tmpdir(), 'release-reachability-'));
  const worktree = join(root, 'work');
  const remote = join(root, 'remote.git');
  const cache = join(root, 'cache.git');
  git(root, ['init', '--initial-branch=main', worktree]);
  git(worktree, ['config', 'user.name', 'Release Reachability Test']);
  git(worktree, ['config', 'user.email', 'reachability@example.test']);
  await writeCommit(worktree, 'base.txt', 'base\n', 'base');

  git(worktree, ['checkout', '-b', 'merge-feature']);
  const mergeSource = await writeCommit(worktree, 'merge.txt', 'merge feature\n', 'merge feature');
  git(worktree, ['checkout', 'main']);
  await writeCommit(worktree, 'main.txt', 'main side\n', 'main side');
  git(worktree, ['merge', '--no-ff', 'merge-feature', '-m', 'merge feature branch']);
  const mergeRelease = git(worktree, ['rev-parse', 'HEAD']);
  git(worktree, ['tag', 'v-light', mergeRelease]);

  git(worktree, ['checkout', '-b', 'squash-source']);
  const originalSquash = await writeCommit(worktree, 'squash.txt', 'squash source\n', 'squash source');
  git(worktree, ['checkout', 'main']);
  git(worktree, ['merge', '--squash', 'squash-source']);
  git(worktree, ['commit', '-m', 'squashed feature']);
  const squashRelease = git(worktree, ['rev-parse', 'HEAD']);
  git(worktree, ['tag', '-a', 'v-annotated', '-m', 'annotated release', squashRelease]);

  git(worktree, ['checkout', '-b', 'rebase-source']);
  const originalRebase = await writeCommit(worktree, 'rebase.txt', 'before rebase\n', 'before rebase');
  git(worktree, ['branch', 'original-rebase', originalRebase]);
  git(worktree, ['checkout', 'main']);
  const advanceCommit = await writeCommit(worktree, 'advance.txt', 'advance main\n', 'advance main');
  git(worktree, ['checkout', 'rebase-source']);
  git(worktree, ['rebase', 'main']);
  const rebasedCommit = git(worktree, ['rev-parse', 'HEAD']);
  git(worktree, ['checkout', 'main']);
  git(worktree, ['merge', '--ff-only', 'rebase-source']);
  const rebaseRelease = git(worktree, ['rev-parse', 'HEAD']);

  git(worktree, ['tag', 'v-rebase', rebaseRelease]);
  git(worktree, ['tag', 'moving', mergeRelease]);
  const movedTagOldCommit = git(worktree, ['rev-parse', 'moving^{commit}']);
  git(root, ['init', '--bare', remote]);
  git(worktree, ['remote', 'add', 'origin', remote]);
  git(worktree, ['push', 'origin', '--all']);
  git(worktree, ['push', 'origin', '--tags']);
  git(worktree, ['tag', '-f', 'moving', rebaseRelease]);
  git(worktree, ['push', '--force', 'origin', 'refs/tags/moving']);
  const movedTagNewCommit = git(worktree, ['rev-parse', 'moving^{commit}']);

  git(root, ['init', '--bare', cache]);
  git(root, ['--git-dir', cache, 'remote', 'add', 'origin', remote]);

  return {
    root,
    worktree,
    remote,
    cache,
    mergeSource,
    mergeRelease,
    originalSquash,
    squashRelease,
    originalRebase,
    advanceCommit,
    rebasedCommit,
    rebaseRelease,
    lightweightTagCommit: git(worktree, ['rev-parse', 'v-light^{commit}']),
    annotatedTagObject: git(worktree, ['rev-parse', 'v-annotated']),
    annotatedTagCommit: git(worktree, ['rev-parse', 'v-annotated^{commit}']),
    movedTagOldCommit,
    movedTagNewCommit,
  };
}

function runBareGit(gitDir: string, args: string[]) {
  return __releaseReachabilityTest.runAsync(['git', `--git-dir=${gitDir}`, ...args]);
}

function stableReleaseBoundary(
  tag: string,
  publishedAt: string,
  commitOid: string,
  overrides: Record<string, unknown> = {},
) {
  const publishedAtMs = Date.parse(publishedAt);
  return {
    node_id: `release-node:${tag}`,
    tag,
    published_at: publishedAt,
    catalog_rank: Number.isFinite(publishedAtMs)
      ? Math.floor(
          (Date.parse('2100-01-01T00:00:00Z') - publishedAtMs) /
          (24 * 60 * 60 * 1000),
        )
      : null,
    catalog_digest: 'd'.repeat(64),
    catalog_receipt_id: null,
    catalog_release_count: 100_000,
    catalog_tag_commit_oid: commitOid,
    resolved_tag_commit_oid: commitOid,
    ...overrides,
  };
}

function firstContainingContext(input: {
  targetCommit: string;
  predecessorCommit: string;
  directCommit: string;
  repositoryState?: 'ready' | 'shallow' | 'error';
  objectResult?: (oid: string) => any;
  ancestryResult?: (commitOid: string, tagCommitOid: string) => any;
  remoteTagResult?: (tag: string) => any;
  releaseCommits?: Record<string, string>;
}) {
  return {
    concurrency: 2,
    inspectRepository: async () => {
      const state = input.repositoryState ?? 'ready';
      if (state === 'ready') {
        return {
          status: 'ready' as const,
          shallow: false as const,
          command: command(0, '', 'false\n'),
        };
      }
      if (state === 'shallow') {
        return {
          status: 'shallow' as const,
          shallow: true as const,
          command: command(0, '', 'true\n'),
        };
      }
      return {
        status: 'error' as const,
        shallow: null,
        command: command(128, 'fatal: repository state unavailable'),
      };
    },
    ensureObject: async (oid: string) =>
      input.objectResult?.(oid) ?? { status: 'available' as const },
    resolveRemoteTagCommit: async (tag: string) => {
      if (input.remoteTagResult) return input.remoteTagResult(tag);
      const tagCommitOid = input.releaseCommits?.[tag] ??
        (tag === 'v-target'
          ? input.targetCommit
          : tag === 'v-predecessor'
            ? input.predecessorCommit
            : null);
      if (!tagCommitOid) {
        return {
          status: 'error' as const,
          detail: `unexpected remote tag ${tag}`,
          command: command(128, `unexpected remote tag ${tag}`),
        };
      }
      return {
        status: 'resolved' as const,
        tagCommitOid,
        command: command(0, '', `${tagCommitOid}\trefs/tags/${tag}\n`),
      };
    },
    checkAncestor: async (commitOid: string, tagCommitOid: string) => {
      if (input.ancestryResult) return input.ancestryResult(commitOid, tagCommitOid);
      if (commitOid === input.predecessorCommit && tagCommitOid === input.targetCommit) {
        return command(0);
      }
      if (commitOid === input.directCommit && tagCommitOid === input.targetCommit) {
        return command(0);
      }
      if (commitOid === input.directCommit && tagCommitOid === input.predecessorCommit) {
        return command(1);
      }
      throw new Error(`unexpected ancestry check ${commitOid} -> ${tagCommitOid}`);
    },
  };
}

function completeStableFirstContainingFixture() {
  const directCommit = '5'.repeat(40);
  const releases = [
    {
      tag: 'v-target',
      publishedAt: '2026-07-04T00:00:00Z',
      commitOid: '4'.repeat(40),
    },
    {
      tag: 'v-predecessor',
      publishedAt: '2026-07-03T00:00:00Z',
      commitOid: '3'.repeat(40),
    },
    {
      tag: 'v-middle',
      publishedAt: '2026-07-02T00:00:00Z',
      commitOid: '2'.repeat(40),
    },
    {
      tag: 'v-oldest',
      publishedAt: '2026-07-01T00:00:00Z',
      commitOid: '1'.repeat(40),
    },
  ];
  return {
    directCommit,
    targetCommit: releases[0].commitOid,
    predecessorCommit: releases[1].commitOid,
    rows: releases.map((release) =>
      stableReleaseBoundary(
        release.tag,
        release.publishedAt,
        release.commitOid,
      )),
    releaseCommits: Object.fromEntries(
      releases.map((release) => [release.tag, release.commitOid]),
    ),
  };
}

describe('release reachability helpers', () => {
  it('avoids present-object fetches and deduplicates in-flight fetches', async () => {
    const missingOid = 'a'.repeat(40);
    const presentOid = 'b'.repeat(40);
    const available = new Set([presentOid]);
    const fetchCounts = new Map<string, number>();
    let readyCalls = 0;
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 2,
      ensureReady: async () => { readyCalls++; },
      runGit: async (args: string[]) => {
        const oid = String(args.at(-1)).replace(/\^\{commit\}$/, '');
        if (args[0] === 'cat-file') return command(available.has(oid) ? 0 : 128);
        if (args[0] === 'fetch') {
          fetchCounts.set(oid, (fetchCounts.get(oid) ?? 0) + 1);
          await delay(5);
          available.add(oid);
          return command(0);
        }
        throw new Error(`unexpected git command: ${args.join(' ')}`);
      },
    });

    const first = context.ensureObject(missingOid);
    const duplicate = context.ensureObject(missingOid.toUpperCase());
    assert.strictEqual(first, duplicate);
    await Promise.all([first, duplicate, context.ensureObject(missingOid), context.ensureObject(presentOid)]);

    assert.equal(readyCalls, 1);
    assert.equal(fetchCounts.get(missingOid), 1);
    assert.equal(fetchCounts.has(presentOid), false);
  });

  it('retains confirmed-unavailable object results across stabilization passes', async () => {
    const oid = 'c'.repeat(40);
    let calls = 0;
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 2,
      runGit: async (args: string[]) => {
        calls++;
        assert.equal(args[0], 'cat-file');
        return command(
          null,
          `fatal: remote error: upload-pack: not our ref ${oid}\ncommand timed out after 120000ms`,
          '',
          { timedOut: true, signal: 'SIGTERM' },
        );
      },
    });

    assert.equal((await context.ensureObject(oid)).status, 'unavailable');
    assert.equal((await context.ensureObject(oid)).status, 'unavailable');
    assert.equal(calls, 1);
  });

  it('rechecks the local object store after serialized fetches without inventorying the repository', async () => {
    const child = 'a'.repeat(40);
    const parent = 'b'.repeat(40);
    const available = new Set<string>();
    const fetches: string[] = [];
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 4,
      runGit: async (args: string[]) => {
        const oid = String(args.at(-1)).replace(/\^\{commit\}$/, '');
        if (args[0] === 'cat-file') return command(available.has(oid) ? 0 : 128);
        if (args[0] === 'fetch') {
          fetches.push(oid);
          available.add(child);
          available.add(parent);
          return command(0);
        }
        throw new Error(`unexpected git command: ${args.join(' ')}`);
      },
    });

    await Promise.all([
      context.ensureObject(child),
      context.ensureObject(parent),
      context.ensureObject(child),
    ]);
    assert.equal(fetches.length, 1);
    assert.ok(fetches[0] === child || fetches[0] === parent);
  });

  it('bounds asynchronous merge-base checks at the configured concurrency', async () => {
    let active = 0;
    let maxActive = 0;
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 3,
      runGit: async (args: string[]) => {
        assert.equal(args[0], 'merge-base');
        active++;
        maxActive = Math.max(maxActive, active);
        await delay(5);
        active--;
        return command(0);
      },
    });

    await Promise.all(Array.from({ length: 12 }, (_, index) =>
      context.checkAncestor(String(index).padStart(40, '0'), 'f'.repeat(40))));

    assert.equal(maxActive, 3);
  });

  it('deduplicates repeated ancestry checks within one refresh context', async () => {
    let mergeBaseCalls = 0;
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 4,
      runGit: async (args: string[]) => {
        assert.equal(args[0], 'merge-base');
        mergeBaseCalls++;
        await delay(5);
        return command(0);
      },
    });
    const commit = 'a'.repeat(40);
    const release = 'b'.repeat(40);
    const first = context.checkAncestor(commit, release);
    const duplicate = context.checkAncestor(commit.toUpperCase(), release.toUpperCase());

    assert.strictEqual(first, duplicate);
    await Promise.all([first, duplicate, context.checkAncestor(commit, release)]);
    assert.equal(mergeBaseCalls, 1);
  });

  it('matches real Git ancestry across merges, squash/rebase rewrites, and moved tag identities', async (t) => {
    const fixture = await createGitFixture();
    t.after(async () => rm(fixture.root, { recursive: true, force: true }));
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 3,
      runGit: (args: string[]) => runBareGit(fixture.cache, args),
    });

    assert.equal(fixture.lightweightTagCommit, fixture.mergeRelease);
    assert.notEqual(fixture.annotatedTagObject, fixture.annotatedTagCommit);
    assert.equal(fixture.annotatedTagCommit, fixture.squashRelease);
    assert.notEqual(fixture.movedTagOldCommit, fixture.movedTagNewCommit);

    const requiredObjects = [
      fixture.mergeSource,
      fixture.mergeRelease,
      fixture.originalSquash,
      fixture.squashRelease,
      fixture.originalRebase,
      fixture.rebasedCommit,
      fixture.rebaseRelease,
    ];
    const objectResults = await Promise.all(requiredObjects.map((oid) => context.ensureObject(oid)));
    assert.ok(objectResults.every((result) => result.status === 'available'));

    assert.equal((await context.checkAncestor(fixture.mergeSource, fixture.lightweightTagCommit)).status, 0);
    assert.equal((await context.checkAncestor(fixture.originalSquash, fixture.annotatedTagCommit)).status, 1);
    assert.equal((await context.checkAncestor(fixture.squashRelease, fixture.annotatedTagCommit)).status, 0);
    assert.equal((await context.checkAncestor(fixture.originalRebase, fixture.rebaseRelease)).status, 1);
    assert.equal((await context.checkAncestor(fixture.rebasedCommit, fixture.rebaseRelease)).status, 0);

    const movedFetch = await runBareGit(fixture.cache, [
      'fetch',
      'origin',
      '+refs/tags/moving:refs/tags/moving',
    ]);
    assert.equal(movedFetch.status, 0);
    const movedResolved = await runBareGit(fixture.cache, ['rev-parse', 'refs/tags/moving^{commit}']);
    assert.equal(movedResolved.stdout.trim(), fixture.movedTagNewCommit);

    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 7,
      merge_commit_oid: fixture.mergeSource,
      base_ref_name: 'main',
      fetched_at: '2026-01-01T00:00:00Z',
    };
    const cachedRow = {
      tag: 'moving',
      ...candidate,
      tag_commit_oid: fixture.movedTagOldCommit,
      status: 'reachable',
      method: 'git-merge-base',
      evidence_json: JSON.stringify(__releaseReachabilityTest.reachabilityEvidence({
        evidence: 'merge_commit_in_release_history',
        tagCommitOid: fixture.movedTagOldCommit,
        checkedCommitOid: fixture.mergeSource,
        baseRefName: 'main',
        command: command(0),
      })),
      checked_at: '2026-01-02T00:00:00Z',
    } as any;
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        cachedRow,
        candidate,
        fixture.movedTagOldCommit,
      ),
      true,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        cachedRow,
        candidate,
        fixture.movedTagNewCommit,
      ),
      false,
    );
  });

  it('proves a direct commit belongs first to the target stable release', async () => {
    const targetCommit = '2'.repeat(40);
    const predecessorCommit = '1'.repeat(40);
    const directCommit = '3'.repeat(40);
    const result = await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
      {
        repositoryNameWithOwner: 'OpenClaw/OpenClaw',
        commitOid: directCommit.toUpperCase(),
        targetTag: 'v-target',
        predecessorTag: 'v-predecessor',
      },
      {
        expectedRepositoryNameWithOwner: 'openclaw/openclaw',
        listStableReleases: () => [
          stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit),
          stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
        ],
        context: firstContainingContext({
          targetCommit,
          predecessorCommit,
          directCommit,
        }),
      },
    );

    assert.equal(result.status, 'credited');
    assert.equal(result.reasonCode, 'first_containing_direct_commit');
    assert.equal(result.creditEligible, true);
    assert.equal(result.repositoryNameWithOwner, 'openclaw/openclaw');
    assert.equal(result.commitOid, directCommit);
    assert.equal(result.target?.releaseNodeId, 'release-node:v-target');
    assert.equal(result.target?.status, 'reachable');
    assert.equal(result.predecessor?.status, 'not_reachable');
    assert.deepEqual(result.olderReleases.map((proof) => proof.tag), ['v-predecessor']);
    assert.equal(result.releaseAncestry?.status, 'reachable');
    assert.equal(result.target?.strictValid, true);
    assert.equal(
      result.target?.evidence.repositoryNameWithOwner,
      'openclaw/openclaw',
    );
    assert.equal(result.failure, null);
  });

  it('credits only when every older stable release is strictly not reachable', async () => {
    const fixture = completeStableFirstContainingFixture();
    const directCheckOrder: string[] = [];
    const result = await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
      {
        repositoryNameWithOwner: 'openclaw/openclaw',
        commitOid: fixture.directCommit,
        targetTag: 'v-target',
        predecessorTag: 'v-predecessor',
      },
      {
        expectedRepositoryNameWithOwner: 'openclaw/openclaw',
        listStableReleases: () => fixture.rows,
        context: firstContainingContext({
          targetCommit: fixture.targetCommit,
          predecessorCommit: fixture.predecessorCommit,
          directCommit: fixture.directCommit,
          releaseCommits: fixture.releaseCommits,
          ancestryResult: (commitOid, tagCommitOid) => {
            if (
              commitOid === fixture.predecessorCommit &&
              tagCommitOid === fixture.targetCommit
            ) {
              return command(0);
            }
            if (commitOid === fixture.directCommit) {
              directCheckOrder.push(tagCommitOid);
              return tagCommitOid === fixture.targetCommit
                ? command(0)
                : command(1);
            }
            throw new Error(`unexpected ancestry check ${commitOid} -> ${tagCommitOid}`);
          },
        }),
      },
    );

    assert.equal(result.status, 'credited');
    assert.deepEqual(
      result.olderReleases.map((proof) => [proof.tag, proof.status]),
      [
        ['v-oldest', 'not_reachable'],
        ['v-middle', 'not_reachable'],
        ['v-predecessor', 'not_reachable'],
      ],
    );
    assert.equal(result.predecessor?.tag, 'v-predecessor');
    assert.deepEqual(directCheckOrder, [
      fixture.releaseCommits['v-oldest'],
      fixture.releaseCommits['v-middle'],
      fixture.releaseCommits['v-predecessor'],
      fixture.releaseCommits['v-target'],
    ]);
  });

  it('withholds when a non-immediate older stable release already contains the commit', async () => {
    const fixture = completeStableFirstContainingFixture();
    const result = await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
      {
        repositoryNameWithOwner: 'openclaw/openclaw',
        commitOid: fixture.directCommit,
        targetTag: 'v-target',
        predecessorTag: 'v-predecessor',
      },
      {
        expectedRepositoryNameWithOwner: 'openclaw/openclaw',
        listStableReleases: () => fixture.rows,
        context: firstContainingContext({
          targetCommit: fixture.targetCommit,
          predecessorCommit: fixture.predecessorCommit,
          directCommit: fixture.directCommit,
          releaseCommits: fixture.releaseCommits,
          ancestryResult: (commitOid, tagCommitOid) => {
            if (
              commitOid === fixture.predecessorCommit &&
              tagCommitOid === fixture.targetCommit
            ) {
              return command(0);
            }
            if (commitOid === fixture.directCommit) {
              if (tagCommitOid === fixture.releaseCommits['v-oldest']) return command(0);
              if (tagCommitOid === fixture.targetCommit) return command(0);
              return command(1);
            }
            throw new Error(`unexpected ancestry check ${commitOid} -> ${tagCommitOid}`);
          },
        }),
      },
    );

    assert.equal(result.status, 'withheld');
    assert.equal(result.reasonCode, 'predecessor_contains_commit');
    assert.equal(result.predecessor?.status, 'not_reachable');
    assert.equal(result.olderReleases[0]?.status, 'reachable');
    assert.match(result.failure?.detail ?? '', /older stable release v-oldest/);
  });

  it('fails closed when any older stable release reachability is unknown', async () => {
    const fixture = completeStableFirstContainingFixture();
    const result = await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
      {
        repositoryNameWithOwner: 'openclaw/openclaw',
        commitOid: fixture.directCommit,
        targetTag: 'v-target',
        predecessorTag: 'v-predecessor',
      },
      {
        expectedRepositoryNameWithOwner: 'openclaw/openclaw',
        listStableReleases: () => fixture.rows,
        context: firstContainingContext({
          targetCommit: fixture.targetCommit,
          predecessorCommit: fixture.predecessorCommit,
          directCommit: fixture.directCommit,
          releaseCommits: fixture.releaseCommits,
          ancestryResult: (commitOid, tagCommitOid) => {
            if (
              commitOid === fixture.predecessorCommit &&
              tagCommitOid === fixture.targetCommit
            ) {
              return command(0);
            }
            if (
              commitOid === fixture.directCommit &&
              tagCommitOid === fixture.releaseCommits['v-middle']
            ) {
              return command(null, 'merge-base timed out', '', {
                timedOut: true,
                signal: 'SIGTERM',
              });
            }
            if (commitOid === fixture.directCommit) {
              return tagCommitOid === fixture.targetCommit
                ? command(0)
                : command(1);
            }
            throw new Error(`unexpected ancestry check ${commitOid} -> ${tagCommitOid}`);
          },
        }),
      },
    );

    assert.equal(result.status, 'withheld');
    assert.equal(result.reasonCode, 'git_evidence_unavailable');
    assert.deepEqual(
      result.olderReleases.map((proof) => proof.status),
      ['not_reachable', 'unknown', 'not_reachable'],
    );
    assert.equal(result.target?.status, 'reachable');
    assert.match(result.failure?.detail ?? '', /older stable release v-middle/);
  });

  it('projects remote direct-commit boundaries in exact catalog order without betas', () => {
    const targetCommit = 'A'.repeat(40);
    const predecessorCommit = 'B'.repeat(40);
    const rows = projectDirectCommitStableReleaseBoundaries([
      {
        node_id: 'release-predecessor',
        tag_name: 'v-predecessor',
        tag_commit_oid: predecessorCommit,
        published_at: '2026-07-01T00:00:00Z',
        prerelease: false,
        draft: false,
      },
      {
        node_id: 'release-draft',
        tag_name: 'v-draft',
        tag_commit_oid: 'D'.repeat(40),
        published_at: null,
        prerelease: false,
        draft: true,
      },
      {
        node_id: 'release-beta',
        tag_name: 'v-target-beta.1',
        tag_commit_oid: 'C'.repeat(40),
        published_at: '2026-07-02T00:00:00Z',
        prerelease: true,
        draft: false,
      },
      {
        node_id: 'release-target',
        tag_name: 'v-target',
        tag_commit_oid: targetCommit,
        published_at: '2026-07-03T00:00:00Z',
        prerelease: false,
        draft: false,
      },
    ]);

    assert.deepEqual(rows, [
      {
        node_id: 'release-target',
        tag: 'v-target',
        published_at: '2026-07-03T00:00:00Z',
        catalog_rank: 0,
        catalog_digest: rows[0].catalog_digest,
        catalog_receipt_id: null,
        catalog_release_count: 3,
        catalog_tag_commit_oid: targetCommit.toLowerCase(),
        resolved_tag_commit_oid: targetCommit.toLowerCase(),
      },
      {
        node_id: 'release-predecessor',
        tag: 'v-predecessor',
        published_at: '2026-07-01T00:00:00Z',
        catalog_rank: 2,
        catalog_digest: rows[0].catalog_digest,
        catalog_receipt_id: null,
        catalog_release_count: 3,
        catalog_tag_commit_oid: predecessorCommit.toLowerCase(),
        resolved_tag_commit_oid: predecessorCommit.toLowerCase(),
      },
    ]);
    assert.match(rows[0].catalog_digest, /^[0-9a-f]{64}$/);
    assert.equal(
      __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
        'v-target',
        'v-predecessor',
        rows,
      ).valid,
      true,
    );
  });

  it('uses authoritative prerelease flags for legacy stable tag spellings', () => {
    const rows = projectDirectCommitStableReleaseBoundaries([
      {
        node_id: 'release-legacy-stable',
        tag_name: 'v2.0.0-beta5',
        tag_commit_oid: 'A'.repeat(40),
        published_at: '2026-01-03T04:56:30Z',
        prerelease: false,
        draft: false,
      },
      {
        node_id: 'release-current-beta',
        tag_name: `v2026.${'7.1-beta.2'}`,
        tag_commit_oid: 'B'.repeat(40),
        published_at: '2026-07-05T09:10:09Z',
        prerelease: true,
        draft: false,
      },
    ]);

    assert.deepEqual(rows.map((row) => row.tag), ['v2.0.0-beta5']);
  });

  it('rejects immutable node and catalog authority mismatches before git evidence', () => {
    const fixture = completeStableFirstContainingFixture();
    const duplicateNodeRows = fixture.rows.map((row) => ({ ...row }));
    duplicateNodeRows[2].node_id = duplicateNodeRows[1].node_id;
    const duplicateNode =
      __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
        'v-target',
        'v-predecessor',
        duplicateNodeRows,
      );
    assert.equal(duplicateNode.valid, false);
    if (!duplicateNode.valid) {
      assert.match(duplicateNode.detail, /immutable node identities are not unique/);
    }

    const mismatchedCatalogRows = fixture.rows.map((row) => ({ ...row }));
    mismatchedCatalogRows[2].catalog_digest = 'e'.repeat(64);
    const mismatchedCatalog =
      __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
        'v-target',
        'v-predecessor',
        mismatchedCatalogRows,
    );
    assert.equal(mismatchedCatalog.valid, false);
    if (!mismatchedCatalog.valid) {
      assert.match(
        mismatchedCatalog.detail,
        /authoritative catalog digest, receipt identity, and release count/,
      );
    }
  });

  it('orders equal publication timestamps by binary tag and immutable node identity', () => {
    const targetTag = 'v-\uE000';
    const predecessorTag = 'v-\u{10000}';
    const rows = projectDirectCommitStableReleaseBoundaries([
      {
        node_id: 'release-predecessor',
        tag_name: predecessorTag,
        tag_commit_oid: '2'.repeat(40),
        published_at: '2026-07-02T00:00:00Z',
        prerelease: false,
        draft: false,
      },
      {
        node_id: 'release-oldest',
        tag_name: 'v-oldest',
        tag_commit_oid: '1'.repeat(40),
        published_at: '2026-07-01T00:00:00Z',
        prerelease: false,
        draft: false,
      },
      {
        node_id: 'release-target',
        tag_name: targetTag,
        tag_commit_oid: '3'.repeat(40),
        published_at: '2026-07-02T00:00:00Z',
        prerelease: false,
        draft: false,
      },
    ]);

    assert.deepEqual(
      rows.map((row) => [row.tag, row.node_id, row.catalog_rank]),
      [
        [targetTag, 'release-target', 0],
        [predecessorTag, 'release-predecessor', 1],
        ['v-oldest', 'release-oldest', 2],
      ],
    );
    assert.equal(
      __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
        targetTag,
        predecessorTag,
        rows,
      ).valid,
      true,
    );
  });

  it('rejects non-boundary retag and duplicate alias conflicts across the complete catalog', () => {
    const rows = [
      stableReleaseBoundary('v-third-party', '2026-07-06T00:00:00Z', '9'.repeat(40)),
      stableReleaseBoundary('v-newer', '2026-07-05T00:00:00Z', '8'.repeat(40)),
      stableReleaseBoundary('v-target', '2026-07-04T00:00:00Z', '4'.repeat(40)),
      stableReleaseBoundary('v-predecessor', '2026-07-03T00:00:00Z', '3'.repeat(40)),
      stableReleaseBoundary('v-oldest', '2026-07-02T00:00:00Z', '2'.repeat(40)),
    ];

    const retaggedRows = rows.map((row) => ({ ...row }));
    retaggedRows[0].resolved_tag_commit_oid = '7'.repeat(40);
    const retagged = __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
      'v-target',
      'v-predecessor',
      retaggedRows,
    );
    assert.equal(retagged.valid, false);
    if (!retagged.valid) {
      assert.equal(retagged.reasonCode, 'release_retag_conflict');
      assert.match(retagged.detail, /stable release v-third-party/);
    }

    const aliasedRows = rows.map((row) => ({ ...row }));
    aliasedRows[1].catalog_tag_commit_oid = aliasedRows[0].catalog_tag_commit_oid;
    aliasedRows[1].resolved_tag_commit_oid = aliasedRows[0].resolved_tag_commit_oid;
    const aliased = __releaseReachabilityTest.resolveDirectCommitReleaseBoundary(
      'v-target',
      'v-predecessor',
      aliasedRows,
    );
    assert.equal(aliased.valid, false);
    if (!aliased.valid) {
      assert.equal(aliased.reasonCode, 'release_alias_conflict');
      assert.match(aliased.detail, /v-newer, v-third-party|v-third-party, v-newer/);
    }
  });

  it('rejects non-canonical repository identity and abbreviated direct commits before git', async () => {
    const targetCommit = '2'.repeat(40);
    const predecessorCommit = '1'.repeat(40);
    let contextCalls = 0;
    const context = {
      concurrency: 1,
      inspectRepository: async () => {
        contextCalls++;
        throw new Error('must not inspect git');
      },
      ensureObject: async () => {
        contextCalls++;
        throw new Error('must not inspect objects');
      },
      checkAncestor: async () => {
        contextCalls++;
        throw new Error('must not inspect ancestry');
      },
    };
    const dependencies = {
      expectedRepositoryNameWithOwner: 'openclaw/openclaw',
      listStableReleases: () => [
        stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit),
        stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
      ],
      context,
    };

    const wrongRepository =
      await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
        {
          repositoryNameWithOwner: 'fork/openclaw',
          commitOid: '3'.repeat(40),
          targetTag: 'v-target',
          predecessorTag: 'v-predecessor',
        },
        dependencies,
      );
    assert.equal(wrongRepository.reasonCode, 'repository_identity_mismatch');

    const shortCommit =
      await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
        {
          repositoryNameWithOwner: 'openclaw/openclaw',
          commitOid: 'deadbee',
          targetTag: 'v-target',
          predecessorTag: 'v-predecessor',
        },
        dependencies,
      );
    assert.equal(shortCommit.reasonCode, 'invalid_commit_oid');
    assert.equal(contextCalls, 0);
  });

  it('fails closed for missing, non-immediate, retagged, and aliased release boundaries', async () => {
    const targetCommit = '2'.repeat(40);
    const predecessorCommit = '1'.repeat(40);
    const directCommit = '3'.repeat(40);
    const request = {
      repositoryNameWithOwner: 'openclaw/openclaw',
      commitOid: directCommit,
      targetTag: 'v-target',
      predecessorTag: 'v-predecessor',
    };
    const context = firstContainingContext({
      targetCommit,
      predecessorCommit,
      directCommit,
    });
    const evaluate = (rows: any[], overrides: Record<string, unknown> = {}) =>
      __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
        { ...request, ...overrides },
        {
          expectedRepositoryNameWithOwner: 'openclaw/openclaw',
          listStableReleases: () => rows,
          context,
        },
      );

    assert.equal((await evaluate([], { predecessorTag: null })).reasonCode,
      'missing_predecessor_boundary');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
    ])).reasonCode, 'target_release_missing');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit),
    ])).reasonCode, 'predecessor_release_missing');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-target', '2026-07-03T00:00:00Z', targetCommit),
      stableReleaseBoundary('v-between', '2026-07-02T00:00:00Z', '4'.repeat(40)),
      stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
    ])).reasonCode, 'invalid_release_boundary');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-target', '2026-07-03T00:00:00Z', targetCommit, {
        catalog_rank: 0,
      }),
      stableReleaseBoundary('v-catalog-between', '2026-07-01T00:00:00Z', '4'.repeat(40), {
        catalog_rank: 1,
      }),
      stableReleaseBoundary('v-predecessor', '2026-07-02T00:00:00Z', predecessorCommit, {
        catalog_rank: 2,
      }),
    ])).reasonCode, 'invalid_release_boundary');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit, {
        resolved_tag_commit_oid: '5'.repeat(40),
      }),
      stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
    ])).reasonCode, 'release_retag_conflict');
    assert.equal((await evaluate([
      stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit),
      stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', targetCommit),
    ])).reasonCode, 'release_alias_conflict');
  });

  it('fails closed for shallow, unavailable, ambiguous, timed-out, aborted, and process-tree evidence', async () => {
    const targetCommit = '2'.repeat(40);
    const predecessorCommit = '1'.repeat(40);
    const directCommit = '3'.repeat(40);
    const rows = [
      stableReleaseBoundary('v-target', '2026-07-02T00:00:00Z', targetCommit),
      stableReleaseBoundary('v-predecessor', '2026-07-01T00:00:00Z', predecessorCommit),
    ];
    const request = {
      repositoryNameWithOwner: 'openclaw/openclaw',
      commitOid: directCommit,
      targetTag: 'v-target',
      predecessorTag: 'v-predecessor',
    };
    const evaluate = (context: any) =>
      __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(request, {
        expectedRepositoryNameWithOwner: 'openclaw/openclaw',
        listStableReleases: () => rows,
        context,
      });

    assert.equal((await evaluate(firstContainingContext({
      targetCommit,
      predecessorCommit,
      directCommit,
      repositoryState: 'shallow',
    }))).reasonCode, 'shallow_repository');

    let postRemoteEvidenceCalls = 0;
    const remoteUnavailableContext = firstContainingContext({
      targetCommit,
      predecessorCommit,
      directCommit,
      remoteTagResult: () => ({
        status: 'error',
        detail: 'remote tag lookup unavailable',
        command: command(128, 'fatal: unable to access remote'),
      }),
      objectResult: () => {
        postRemoteEvidenceCalls++;
        return { status: 'available' };
      },
      ancestryResult: () => {
        postRemoteEvidenceCalls++;
        return command(0);
      },
    });
    const remoteUnavailable = await evaluate(remoteUnavailableContext);
    assert.equal(remoteUnavailable.reasonCode, 'git_evidence_unavailable');
    assert.equal(remoteUnavailable.failure?.stage, 'release_boundary');
    await assert.rejects(
      __releaseReachabilityTest.assertTrustedPullRequestFirstContainingReleaseBoundaries({
        targetTags: ['v-target'],
        rows,
        context: remoteUnavailableContext,
        repositoryNameWithOwner: 'openclaw/openclaw',
      }),
      /Trusted PR first-containing remote release attestation failed: remote tag lookup unavailable/,
    );
    assert.equal(postRemoteEvidenceCalls, 0);

    assert.equal((await evaluate(firstContainingContext({
      targetCommit,
      predecessorCommit,
      directCommit,
      objectResult: (oid) => oid === directCommit
        ? { status: 'unavailable', command: command(128, 'fatal: not our ref') }
        : { status: 'available' },
    }))).reasonCode, 'commit_object_unavailable');

    assert.equal((await evaluate(firstContainingContext({
      targetCommit,
      predecessorCommit,
      directCommit,
      ancestryResult: (commitOid, tagCommitOid) =>
        commitOid === predecessorCommit && tagCommitOid === targetCommit
          ? command(1)
          : command(0),
    }))).reasonCode, 'ambiguous_release_ancestry');

    const trustedPrAncestryChecks: Array<[string, string]> = [];
    await assert.rejects(
      __releaseReachabilityTest.assertTrustedPullRequestFirstContainingReleaseBoundaries({
        targetTags: ['v-target'],
        rows,
        context: firstContainingContext({
          targetCommit,
          predecessorCommit,
          directCommit,
          ancestryResult: (commitOid, tagCommitOid) => {
            trustedPrAncestryChecks.push([commitOid, tagCommitOid]);
            if (commitOid === predecessorCommit && tagCommitOid === targetCommit) {
              return command(1);
            }
            throw new Error(
              `candidate ancestry must not run: ${commitOid} -> ${tagCommitOid}`,
            );
          },
        }),
        repositoryNameWithOwner: 'openclaw/openclaw',
      }),
      /Trusted PR first-containing release ancestry failed: .* is not an ancestor of /,
    );
    assert.deepEqual(trustedPrAncestryChecks, [[predecessorCommit, targetCommit]]);

    for (const { failure, expectedStatus, expectedStrictValid } of [
      {
        failure: command(null, 'command timed out', '', {
          timedOut: true,
          signal: 'SIGTERM',
        }),
        expectedStatus: 'unknown',
        expectedStrictValid: true,
      },
      {
        failure: command(null, 'command aborted', '', {
          aborted: true,
          signal: 'SIGTERM',
        }),
        expectedStatus: 'unknown',
        expectedStrictValid: true,
      },
      {
        failure: command(0, '', '', { processTreeTerminationFailed: true }),
        expectedStatus: 'reachable',
        expectedStrictValid: false,
      },
    ]) {
      const result = await evaluate(firstContainingContext({
        targetCommit,
        predecessorCommit,
        directCommit,
        ancestryResult: (commitOid, tagCommitOid) => {
          if (commitOid === predecessorCommit && tagCommitOid === targetCommit) {
            return command(0);
          }
          if (commitOid === directCommit && tagCommitOid === targetCommit) {
            return command(0);
          }
          return failure;
        },
      }));
      assert.equal(result.reasonCode, 'git_evidence_unavailable');
      assert.equal(result.creditEligible, false);
      assert.equal(result.predecessor?.status, expectedStatus);
      assert.equal(result.predecessor?.strictValid, expectedStrictValid);
    }
  });

  it('proves first containment against a real bare git cache and rejects moved-tag identity', async (t) => {
    const fixture = await createGitFixture();
    t.after(async () => rm(fixture.root, { recursive: true, force: true }));
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 3,
      runGit: (args: string[]) => runBareGit(fixture.cache, args),
    });
    const request = {
      repositoryNameWithOwner: 'openclaw/openclaw',
      commitOid: fixture.advanceCommit,
      targetTag: 'v-rebase',
      predecessorTag: 'v-annotated',
    };
    const baseDependencies = {
      expectedRepositoryNameWithOwner: 'openclaw/openclaw',
      context,
    };

    const credited =
      await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
        request,
        {
          ...baseDependencies,
          listStableReleases: () => [
            stableReleaseBoundary(
              'v-rebase',
              '2026-07-02T00:00:00Z',
              fixture.rebaseRelease,
            ),
            stableReleaseBoundary(
              'v-annotated',
              '2026-07-01T00:00:00Z',
              fixture.annotatedTagCommit,
            ),
          ],
        },
      );
    assert.equal(credited.status, 'credited');

    const capturedMovingCommit = fixture.movedTagNewCommit;
    const currentMovingCommit = await writeCommit(
      fixture.worktree,
      'move-tag-again.txt',
      'move tag after stored identity capture\n',
      'move tag after stored identity capture',
    );
    git(fixture.worktree, ['tag', '-f', 'moving', currentMovingCommit]);
    git(fixture.worktree, ['push', '--force', 'origin', 'refs/tags/moving']);
    assert.notEqual(capturedMovingCommit, currentMovingCommit);
    const oldObject = await runBareGit(
      fixture.cache,
      ['cat-file', '-e', `${capturedMovingCommit}^{commit}`],
    );
    assert.equal(oldObject.status, 0);
    let movedMergeBaseCalls = 0;
    let movedObjectCalls = 0;
    const movedContext = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 3,
      runGit: (args: string[]) => {
        if (args[0] === 'merge-base') movedMergeBaseCalls++;
        if (args[0] === 'cat-file' || args[0] === 'fetch') movedObjectCalls++;
        return runBareGit(fixture.cache, args);
      },
    });
    const moved =
      await __releaseReachabilityTest.evaluateDirectCommitFirstContainingRelease(
        {
          ...request,
          targetTag: 'moving',
          predecessorTag: 'v-annotated',
        },
        {
          expectedRepositoryNameWithOwner: 'openclaw/openclaw',
          context: movedContext,
          listStableReleases: () => [
            stableReleaseBoundary(
              'moving',
              '2026-07-02T00:00:00Z',
              capturedMovingCommit,
            ),
            stableReleaseBoundary(
              'v-annotated',
              '2026-07-01T00:00:00Z',
              fixture.annotatedTagCommit,
            ),
          ],
        },
      );
    assert.equal(moved.status, 'withheld');
    assert.equal(moved.reasonCode, 'release_retag_conflict');
    assert.equal(moved.creditEligible, false);
    assert.equal(moved.failure?.stage, 'release_boundary');
    assert.match(moved.failure?.detail ?? '', new RegExp(currentMovingCommit));
    assert.equal(movedMergeBaseCalls, 0);
    assert.equal(movedObjectCalls, 0);
  });

  it('retries transient real-Git probe, fetch, readiness, and ancestry failures', async (t) => {
    const fixture = await createGitFixture();
    t.after(async () => rm(fixture.root, { recursive: true, force: true }));

    let failProbe = true;
    const probeContext = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 2,
      runGit: async (args: string[]) => {
        if (failProbe && args[0] === 'cat-file') {
          failProbe = false;
          return command(null, 'transient object probe timeout', '', { timedOut: true });
        }
        return runBareGit(fixture.cache, args);
      },
    });
    assert.equal((await probeContext.ensureObject(fixture.mergeSource)).status, 'check_failed');
    assert.equal((await probeContext.ensureObject(fixture.mergeSource)).status, 'available');

    const fetchCache = join(fixture.root, 'fetch-cache.git');
    git(fixture.root, ['init', '--bare', fetchCache]);
    git(fixture.root, ['--git-dir', fetchCache, 'remote', 'add', 'origin', fixture.remote]);
    let failFetch = true;
    const fetchContext = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 2,
      runGit: async (args: string[]) => {
        if (failFetch && args[0] === 'fetch') {
          failFetch = false;
          return command(128, 'fatal: unable to access repository');
        }
        return runBareGit(fetchCache, args);
      },
    });
    assert.equal((await fetchContext.ensureObject(fixture.originalSquash)).status, 'fetch_failed');
    assert.equal((await fetchContext.ensureObject(fixture.originalSquash)).status, 'available');

    let readyCalls = 0;
    const readyContext = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 1,
      ensureReady: async () => {
        readyCalls++;
        if (readyCalls === 1) throw new Error('transient repository preparation failure');
      },
      runGit: (args: string[]) => runBareGit(fixture.cache, args),
    });
    await assert.rejects(
      readyContext.ensureObject(fixture.rebaseRelease),
      /transient repository preparation failure/,
    );
    assert.equal((await readyContext.ensureObject(fixture.rebaseRelease)).status, 'available');
    assert.equal(readyCalls, 2);

    let failMergeBase = true;
    let mergeBaseCalls = 0;
    const ancestorContext = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 1,
      runGit: async (args: string[]) => {
        if (args[0] === 'merge-base') {
          mergeBaseCalls++;
          if (failMergeBase) {
            failMergeBase = false;
            return command(128, 'fatal: transient object read failure');
          }
        }
        return runBareGit(fixture.cache, args);
      },
    });
    assert.equal(
      (await ancestorContext.checkAncestor(fixture.mergeSource, fixture.rebaseRelease)).status,
      128,
    );
    assert.equal(
      (await ancestorContext.checkAncestor(fixture.mergeSource, fixture.rebaseRelease)).status,
      0,
    );
    assert.equal(mergeBaseCalls, 2);
  });

  it('bounds command duration and output while resolving cancellation as an auditable failure', async () => {
    const timedOut = await __releaseReachabilityTest.runAsync(
      [process.execPath, '-e', 'setTimeout(() => {}, 10_000)'],
      { timeoutMs: 40, maxOutputBytes: 1024 },
    );
    assert.equal(timedOut.timedOut, true);
    assert.equal(timedOut.status, null);
    assert.match(timedOut.stderr, /timed out/);

    const outputLimited = await __releaseReachabilityTest.runAsync(
      [process.execPath, '-e', 'process.stdout.write("x".repeat(64 * 1024)); setTimeout(() => {}, 10_000)'],
      { timeoutMs: 5_000, maxOutputBytes: 1024 },
    );
    assert.equal(outputLimited.outputLimitExceeded, true);
    assert.equal(outputLimited.status, null);
    assert.ok(Buffer.byteLength(outputLimited.stdout) <= 1024);
    assert.match(outputLimited.stderr, /output exceeded 1024 bytes/);

    const controller = new AbortController();
    const cancelled = __releaseReachabilityTest.runAsync(
      [process.execPath, '-e', 'setTimeout(() => {}, 10_000)'],
      { timeoutMs: 5_000, maxOutputBytes: 1024, signal: controller.signal },
    );
    setTimeout(() => controller.abort(), 40);
    const aborted = await cancelled;
    assert.equal(aborted.aborted, true);
    assert.equal(aborted.status, null);
    assert.match(aborted.stderr, /aborted/);
    assert.equal(
      __releaseReachabilityTest.interpretMergeBaseResult(
        aborted,
        'merge_commit_in_release_history',
      ).status,
      'unknown',
    );

    const followUp = await __releaseReachabilityTest.runAsync(
      ['git', '--version'],
      { timeoutMs: 1_000, maxOutputBytes: 1024 },
    );
    assert.equal(followUp.status, 0);
  });

  it(
    'terminates child-spawning process trees after timeout and abort',
    { skip: process.platform === 'win32' },
    async (t) => {
      const childSpawner = `
        const { spawn } = require('node:child_process');
        const grandchild = spawn(
          process.execPath,
          ['-e', 'process.on("SIGTERM", () => {}); setInterval(() => {}, 1000)'],
          { stdio: 'ignore' },
        );
        process.stdout.write(String(grandchild.pid) + '\\n');
        process.on('SIGTERM', () => {});
        setInterval(() => {}, 1000);
      `;

      for (const mode of ['timeout', 'abort'] as const) {
        const controller = new AbortController();
        const pending = __releaseReachabilityTest.runAsync(
          [process.execPath, '-e', childSpawner],
          {
            timeoutMs: mode === 'timeout' ? 500 : 5_000,
            maxOutputBytes: 1024,
            signal: controller.signal,
          },
        );
        if (mode === 'abort') setTimeout(() => controller.abort(), 500);

        const result = await pending;
        const grandchildPid = Number(result.stdout.trim());
        assert.ok(Number.isInteger(grandchildPid) && grandchildPid > 0);
        t.after(() => forceKillIfRunning(grandchildPid));

        assert.equal(result.timedOut, mode === 'timeout');
        assert.equal(result.aborted, mode === 'abort');
        assert.match(result.stderr, mode === 'timeout' ? /timed out/ : /aborted/);
        assert.equal(
          await waitForProcessExit(grandchildPid, 2_000),
          true,
          `${mode} left grandchild ${grandchildPid} running`,
        );
      }
    },
  );

  it('compacts and prunes the Git cache only after a pack threshold is reached', async () => {
    const belowCalls: string[][] = [];
    const below = await __releaseReachabilityTest.maintainGitCacheIfNeeded({
      runGit: async (args: string[]) => {
        belowCalls.push(args);
        return command(0, '', 'count: 0\nsize: 0\nin-pack: 40\npacks: 3\nsize-pack: 1024\n');
      },
      maxPacks: 4,
      maxSizeKiB: 2_048,
      timeoutMs: 1_000,
      warn: () => assert.fail('maintenance should not warn below thresholds'),
    });
    assert.equal(below.performed, false);
    assert.deepEqual(belowCalls, [['count-objects', '-v']]);

    const aboveCalls: string[][] = [];
    const warnings: string[] = [];
    let inspections = 0;
    const above = await __releaseReachabilityTest.maintainGitCacheIfNeeded({
      runGit: async (args: string[]) => {
        aboveCalls.push(args);
        if (args[0] === 'count-objects') {
          inspections++;
          return command(
            0,
            '',
            inspections === 1
              ? 'count: 0\nsize: 0\nin-pack: 80\npacks: 4\nsize-pack: 4096\n'
              : 'count: 0\nsize: 0\nin-pack: 70\npacks: 1\nsize-pack: 1536\n',
          );
        }
        return command(0);
      },
      maxPacks: 4,
      maxSizeKiB: 8_192,
      timeoutMs: 1_000,
      warn: (message: string) => warnings.push(message),
    });
    assert.equal(above.performed, true);
    assert.deepEqual(above.before, { packs: 4, sizePackKiB: 4_096 });
    assert.deepEqual(above.after, { packs: 1, sizePackKiB: 1_536 });
    assert.deepEqual(aboveCalls, [
      ['count-objects', '-v'],
      ['repack', '-A', '-d', '--write-midx'],
      ['prune', '--expire=now'],
      ['count-objects', '-v'],
    ]);
    assert.equal(warnings.length, 2);
  });

  it('runs bounded cache maintenance successfully against a real bare repository', async (t) => {
    const fixture = await createGitFixture();
    t.after(async () => rm(fixture.root, { recursive: true, force: true }));
    const fetched = await runBareGit(fixture.cache, [
      'fetch',
      'origin',
      '+refs/heads/main:refs/heads/main',
    ]);
    assert.equal(fetched.status, 0);
    const packed = await runBareGit(fixture.cache, ['repack', '-a', '-d']);
    assert.equal(packed.status, 0);

    const result = await __releaseReachabilityTest.maintainGitCacheIfNeeded({
      runGit: (args: string[], options?: { timeoutMs?: number; maxOutputBytes?: number }) =>
        __releaseReachabilityTest.runAsync(
          ['git', `--git-dir=${fixture.cache}`, ...args],
          options,
        ),
      maxPacks: 1,
      maxSizeKiB: Number.MAX_SAFE_INTEGER,
      timeoutMs: 10_000,
      warn: () => {},
    });

    assert.equal(result.performed, true);
    assert.ok(result.before.packs >= 1);
    assert.ok((result.after?.packs ?? 0) >= 1);
  });

  it('keeps automatic Git maintenance disabled for cache probes', () => {
    const args = __releaseReachabilityTest.gitCommandArgs(['cat-file', '-e', 'abc^{commit}']);
    assert.deepEqual(args.slice(0, 5), [
      'git',
      '-c',
      'gc.auto=0',
      '-c',
      'maintenance.auto=false',
    ]);
    assert.match(args[5], /^--git-dir=.*\.cache\/openclaw\.git$/);
    assert.deepEqual(args.slice(6), ['cat-file', '-e', 'abc^{commit}']);
  });

  it('keeps unresolved or ambiguous short commit evidence explicit and unknown', () => {
    const result = __releaseReachabilityTest.unresolvedShortCommitReachability(
      'deadbee',
      'a'.repeat(40),
    );
    assert.deepEqual(result, {
      commitOid: 'deadbee',
      tagCommitOid: 'a'.repeat(40),
      status: 'unknown',
      evidence: 'short_commit_oid_unresolved_or_ambiguous',
    });
  });

  it('carries stale-cache short SHA evidence from parsing into unknown reachability', async () => {
    const tag = 'v-short-sha-stale-cache';
    const releaseCommit = 'a'.repeat(40);
    const fullCommit = 'b'.repeat(40);
    const shortCommit = 'deadbee';
    const mentions = closureCommentCommitMentions(42, [{
      body: `Fixed by commit ${shortCommit}.`,
      created_at: '2026-07-04T00:00:00Z',
      node_id: 'IC_short_sha_comment',
      node_type: 'IssueComment',
      user: {
        id: 'U_short_sha_maintainer',
        type: 'User',
        login: 'maintainer',
      },
      author_association: 'MEMBER',
    }], 42, () => null);
    assert.deepEqual(mentions.map(({ commitOid, shortOid }) => ({ commitOid, shortOid })), [{
      commitOid: shortCommit,
      shortOid: shortCommit,
    }]);

    assert.equal(authorizedReleaseCommitForTag(tag), releaseCommit);

    const ensured: string[] = [];
    const ancestryChecks: Array<[string, string]> = [];
    const results = await checkReleaseCommitReachability(
      tag,
      [...mentions.map((mention) => mention.commitOid), fullCommit],
      {
        context: {
          concurrency: 2,
          ensureObject: async (oid: string) => {
            ensured.push(oid);
            return { status: 'available' as const };
          },
          checkAncestor: async (commitOid: string, tagCommitOid: string) => {
            ancestryChecks.push([commitOid, tagCommitOid]);
            return command(0);
          },
        },
      },
    );

    assert.deepEqual(ensured.sort(), [releaseCommit, fullCommit].sort());
    assert.deepEqual(ancestryChecks, [[fullCommit, releaseCommit]]);
    assert.deepEqual(results.get(shortCommit), {
      commitOid: shortCommit,
      tagCommitOid: releaseCommit,
      status: 'unknown',
      evidence: 'short_commit_oid_unresolved_or_ambiguous',
    });
    assert.equal(results.get(fullCommit)?.status, 'reachable');
  });

  it('reuses only candidate rows whose dependency and commit identities still match', () => {
    const releaseCommit = 'a'.repeat(40);
    const mergeCommit = 'b'.repeat(40);
    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 42,
      merge_commit_oid: mergeCommit,
      base_ref_name: 'main',
      fetched_at: '2026-01-01T00:00:00Z',
    };
    const row = {
      tag: 'v1',
      ...candidate,
      tag_commit_oid: releaseCommit,
      status: 'reachable',
      method: 'git-merge-base',
      evidence_json: JSON.stringify(__releaseReachabilityTest.reachabilityEvidence({
        evidence: 'merge_commit_in_release_history',
        tagCommitOid: releaseCommit,
        checkedCommitOid: mergeCommit,
        baseRefName: 'main',
        command: command(0),
      })),
      checked_at: '2026-01-02T00:00:00Z',
    } as any;

    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(row, candidate, releaseCommit),
      true,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        { ...row, checked_at: '2025-12-31T00:00:00Z' },
        candidate,
        releaseCommit,
      ),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        { ...row, merge_commit_oid: 'c'.repeat(40) },
        candidate,
        releaseCommit,
      ),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        { ...row, evidence_json: '{malformed' },
        candidate,
        releaseCommit,
      ),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        {
          ...row,
          status: 'not_reachable',
          evidence_json: JSON.stringify({
            ...JSON.parse(row.evidence_json),
            commandStatus: 1,
          }),
        },
        candidate,
        releaseCommit,
      ),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        {
          ...row,
          evidence_json: JSON.stringify({
            ...JSON.parse(row.evidence_json),
            checkedCommitOid: 'c'.repeat(40),
          }),
        },
        candidate,
        releaseCommit,
      ),
      false,
    );
  });

  it('rejects cache reuse for evidence that violates the shared strict contract', () => {
    const releaseCommit = 'd'.repeat(40);
    const mergeCommit = 'e'.repeat(40);
    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 43,
      merge_commit_oid: mergeCommit,
      base_ref_name: 'main',
      fetched_at: '2026-01-01T00:00:00Z',
    };
    const baseEvidence = __releaseReachabilityTest.reachabilityEvidence({
      evidence: 'merge_commit_in_release_history',
      tagCommitOid: releaseCommit,
      checkedCommitOid: mergeCommit,
      baseRefName: 'main',
      command: command(0),
    });
    const row = {
      tag: 'v-strict',
      ...candidate,
      tag_commit_oid: releaseCommit,
      status: 'reachable',
      method: 'git-merge-base',
      evidence_json: JSON.stringify(baseEvidence),
      checked_at: '2026-01-02T00:00:00Z',
    } as any;

    const inconsistentRows = [
      {
        ...row,
        evidence_json: JSON.stringify({
          ...baseEvidence,
          evidence: 'fix_commit_in_release_history',
        }),
      },
      {
        ...row,
        evidence_json: JSON.stringify({
          ...baseEvidence,
          commandStatus: 1,
        }),
      },
      {
        ...row,
        evidence_json: JSON.stringify({
          ...baseEvidence,
          timedOut: true,
        }),
      },
      {
        ...row,
        evidence_json: JSON.stringify({
          ...baseEvidence,
          confirmedUnavailable: true,
        }),
      },
      {
        ...row,
        status: 'unknown',
        evidence_json: JSON.stringify({
          ...baseEvidence,
          evidence: 'commit_unavailable',
          commandStatus: 128,
        }),
      },
      {
        ...row,
        status: 'unknown',
        evidence_json: JSON.stringify({
          ...baseEvidence,
          evidence: 'merge_base_error',
          commandStatus: 1,
        }),
      },
    ];

    for (const inconsistent of inconsistentRows) {
      assert.equal(
        __releaseReachabilityTest.existingReachabilityRowIsReusable(
          inconsistent,
          candidate,
          releaseCommit,
        ),
        false,
      );
    }
  });

  it('stages multiple releases deterministically after one candidate query and unique object fetches', async () => {
    const releaseOne = '1'.repeat(40);
    const releaseTwo = '2'.repeat(40);
    const mergeCommit = '3'.repeat(40);
    const available = new Set<string>();
    const fetchCounts = new Map<string, number>();
    let candidateQueries = 0;
    let activeMergeBase = 0;
    let maxMergeBase = 0;
    const context = __releaseReachabilityTest.createReachabilityRefreshContext({
      concurrency: 2,
      runGit: async (args: string[]) => {
        const oid = String(args.at(-1)).replace(/\^\{commit\}$/, '');
        if (args[0] === 'cat-file') return command(available.has(oid) ? 0 : 128);
        if (args[0] === 'fetch') {
          fetchCounts.set(oid, (fetchCounts.get(oid) ?? 0) + 1);
          available.add(oid);
          return command(0);
        }
        if (args[0] === 'merge-base') {
          activeMergeBase++;
          maxMergeBase = Math.max(maxMergeBase, activeMergeBase);
          await delay(args[2] === mergeCommit ? 3 : 1);
          activeMergeBase--;
          return command(args[3] === releaseOne ? 0 : 1);
        }
        throw new Error(`unexpected git command: ${args.join(' ')}`);
      },
    });
    const candidates = [
      {
        pr_repository_owner: 'openclaw',
        pr_repository_name: 'openclaw',
        pr_repository_name_with_owner: 'openclaw/openclaw',
        pr_number: 20,
        merge_commit_oid: mergeCommit,
        base_ref_name: 'main',
        fetched_at: '2026-01-01T00:00:00Z',
      },
      {
        pr_repository_owner: 'openclaw',
        pr_repository_name: 'openclaw',
        pr_repository_name_with_owner: 'openclaw/openclaw',
        pr_number: 10,
        merge_commit_oid: null,
        base_ref_name: 'main',
        fetched_at: '2026-01-01T00:00:00Z',
      },
      {
        pr_repository_owner: 'openclaw',
        pr_repository_name: 'openclaw',
        pr_repository_name_with_owner: 'openclaw/openclaw',
        pr_number: 15,
        merge_commit_oid: mergeCommit,
        base_ref_name: 'main',
        fetched_at: '2026-01-01T00:00:00Z',
      },
    ];

    const staged = await __releaseReachabilityTest.stageReleasePrReachabilityBulk(
      ['v2', 'v1', 'v2'],
      {
        listCandidates: () => {
          candidateQueries++;
          return candidates;
        },
        getReleaseCommit: (tag: string) => tag === 'v1' ? releaseOne : releaseTwo,
        catalogProofForTag: authorizedCatalogProofForTag,
        context,
      },
    );

    assert.equal(candidateQueries, 1);
    assert.deepEqual([...fetchCounts], [
      [releaseOne, 1],
      [releaseTwo, 1],
      [mergeCommit, 1],
    ]);
    assert.equal(maxMergeBase, 2);
    assert.deepEqual(staged.map(({ tag }: { tag: string }) => tag), ['v1', 'v2']);
    assert.deepEqual(
      staged.map(({ rows }: { rows: Array<{ pr_number: number }> }) => rows.map((row) => row.pr_number)),
      [[10, 15, 20], [10, 15, 20]],
    );
    assert.deepEqual(
      staged.map(({ rows }: { rows: Array<{ status: string }> }) => rows.map((row) => row.status)),
      [
        ['unknown', 'reachable', 'reachable'],
        ['unknown', 'not_reachable', 'not_reachable'],
      ],
    );
    assert.deepEqual(
      staged.map(({ result }: { result: { reachable: number; notReachable: number; unknown: number } }) => result),
      [
        {
          tag: 'v1',
          releaseCommit: releaseOne,
          candidates: 3,
          reachable: 2,
          notReachable: 0,
          unknown: 1,
        },
        {
          tag: 'v2',
          releaseCommit: releaseTwo,
          candidates: 3,
          reachable: 0,
          notReachable: 2,
          unknown: 1,
        },
      ],
    );
  });

  it('stages and persists confirmed-unavailable merged PR commits as auditable unknown rows', async () => {
    const releaseOne = '4'.repeat(40);
    const releaseTwo = '5'.repeat(40);
    const missingCommit = '6'.repeat(40);
    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 61,
      merge_commit_oid: missingCommit,
      base_ref_name: 'main',
      fetched_at: '2026-01-01T00:00:00Z',
    };
    const ensured: string[] = [];
    let ancestryChecks = 0;
    const context = {
      concurrency: 2,
      ensureObject: async (oid: string) => {
        ensured.push(oid);
        if (oid === missingCommit) {
          return {
            status: 'unavailable' as const,
            command: command(128, `fatal: remote error: upload-pack: not our ref ${missingCommit}`),
          };
        }
        return { status: 'available' as const };
      },
      checkAncestor: async () => {
        ancestryChecks++;
        return command(0);
      },
    };

    const staged = await __releaseReachabilityTest.stageReleasePrReachabilityBulk(
      ['v-confirmed-two', 'v-confirmed-one'],
      {
        listCandidates: () => [candidate],
        getReleaseCommit: (tag: string) => tag === 'v-confirmed-one' ? releaseOne : releaseTwo,
        catalogProofForTag: authorizedCatalogProofForTag,
        context,
      },
    );

    assert.deepEqual(ensured, [releaseOne, releaseTwo, missingCommit]);
    assert.equal(ancestryChecks, 0);
    assert.deepEqual(staged.map(({ result }: any) => result), [
      {
        tag: 'v-confirmed-one',
        releaseCommit: releaseOne,
        candidates: 1,
        reachable: 0,
        notReachable: 0,
        unknown: 1,
      },
      {
        tag: 'v-confirmed-two',
        releaseCommit: releaseTwo,
        candidates: 1,
        reachable: 0,
        notReachable: 0,
        unknown: 1,
      },
    ]);

    const firstRow = staged[0].rows[0];
    assert.deepEqual(firstRow, {
      tag: 'v-confirmed-one',
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 61,
      tag_commit_oid: releaseOne,
      merge_commit_oid: missingCommit,
      base_ref_name: 'main',
      status: 'unknown',
      method: 'git-merge-base',
      evidence_json: firstRow.evidence_json,
    });
    assert.deepEqual(JSON.parse(firstRow.evidence_json), {
      schemaVersion: 1,
      evidence: 'commit_unavailable',
      method: 'git-merge-base',
      catalogProof: authorizedCatalogProofForTag('v-confirmed-one'),
      tagCommitOid: releaseOne,
      checkedCommitOid: missingCommit,
      baseRefName: 'main',
      commandStatus: 128,
      stdout: null,
      stderr: `fatal: remote error: upload-pack: not our ref ${missingCommit}`,
      signal: null,
      timedOut: false,
      outputLimitExceeded: false,
      aborted: false,
      confirmedUnavailable: true,
    });

    replaceReleasePrReachabilityForRelease(staged[0].tag, staged[0].rows);
    const persisted = releasePrReachabilityRows(staged[0].tag);
    assert.equal(persisted.length, 1);
    assert.deepEqual(
      {
        tag: persisted[0].tag,
        pr_repository_owner: persisted[0].pr_repository_owner,
        pr_repository_name: persisted[0].pr_repository_name,
        pr_repository_name_with_owner: persisted[0].pr_repository_name_with_owner,
        pr_number: persisted[0].pr_number,
        tag_commit_oid: persisted[0].tag_commit_oid,
        merge_commit_oid: persisted[0].merge_commit_oid,
        base_ref_name: persisted[0].base_ref_name,
        status: persisted[0].status,
        method: persisted[0].method,
        evidence_json: persisted[0].evidence_json,
      },
      firstRow,
    );
    assert.ok(Number.isFinite(Date.parse(persisted[0].checked_at)));
  });

  it('bounds confirmed-unavailable reuse and retries unknown rows into a decidable state', async () => {
    const releaseCommit = '7'.repeat(40);
    const missingCommit = '8'.repeat(40);
    const tag = 'v-confirmed-reuse';
    const checkedAt = '2030-01-02T00:00:00Z';
    const checkedAtMs = Date.parse(checkedAt);
    const fetchedAt = '2030-01-01T00:00:00Z';
    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 81,
      merge_commit_oid: missingCommit,
      base_ref_name: 'main',
      fetched_at: fetchedAt,
    };
    const first = await __releaseReachabilityTest.stageReleasePrReachabilityBulk([tag], {
      listCandidates: () => [candidate],
      getReleaseCommit: () => releaseCommit,
      catalogProofForTag: authorizedCatalogProofForTag,
      now: () => checkedAtMs,
      context: {
        concurrency: 1,
        ensureObject: async (oid: string) => oid === missingCommit
          ? {
              status: 'unavailable' as const,
              command: command(128, `fatal: remote error: upload-pack: not our ref ${missingCommit}`),
            }
          : { status: 'available' as const },
        checkAncestor: async () => {
          throw new Error('unavailable commits must not reach merge-base');
        },
      },
    });
    replaceReleasePrReachabilityForRelease(tag, first[0].rows);
    upsertPullRequestFix({
      pr_repository_name_with_owner: candidate.pr_repository_name_with_owner,
      pr_number: candidate.pr_number,
      title: 'Confirmed unavailable merge commit',
      url: 'https://example.test/pull/81',
      state: 'MERGED',
      merged: 1,
      merged_at: fetchedAt,
      merge_commit_oid: missingCommit,
      base_ref_name: candidate.base_ref_name,
    });
    upsertIssuePrLink({
      issue_number: 8100,
      pr_repository_name_with_owner: candidate.pr_repository_name_with_owner,
      pr_number: candidate.pr_number,
      source: 'test',
      will_close_target: 1,
      referenced_at: fetchedAt,
    });
    testDb.prepare(`
      UPDATE pull_request_fixes
      SET fetched_at=?
      WHERE pr_repository_name_with_owner=? AND pr_number=?
    `).run(fetchedAt, candidate.pr_repository_name_with_owner, candidate.pr_number);
    testDb.prepare(`
      UPDATE release_pr_reachability
      SET checked_at=?
      WHERE tag=? AND pr_repository_name_with_owner=? AND pr_number=?
    `).run(checkedAt, tag, candidate.pr_repository_name_with_owner, candidate.pr_number);
    const persisted = releasePrReachabilityRows(tag)[0];

    let fetches = 0;
    const reused = await __releaseReachabilityTest.stageReleasePrReachabilityBulk([tag], {
      listCandidates: () => [candidate],
      getReleaseCommit: () => releaseCommit,
      catalogProofForTag: authorizedCatalogProofForTag,
      now: () => checkedAtMs + __releaseReachabilityTest.UNKNOWN_REACHABILITY_RETRY_MS,
      context: {
        concurrency: 1,
        ensureObject: async () => {
          fetches++;
          throw new Error('fresh confirmed-unavailable identity must be reused');
        },
        checkAncestor: async () => {
          throw new Error('fresh confirmed-unavailable identity must not reach merge-base');
        },
      },
    });

    assert.equal(fetches, 0);
    assert.equal(reused[0].result.unknown, 1);
    assert.equal(reused[0].replace, false);
    assert.deepEqual(reused[0].rows, []);
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        persisted,
        candidate,
        releaseCommit,
        checkedAtMs + __releaseReachabilityTest.UNKNOWN_REACHABILITY_RETRY_MS,
        authorizedCatalogProofForTag(tag),
      ),
      true,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        persisted,
        candidate,
        releaseCommit,
        checkedAtMs + __releaseReachabilityTest.UNKNOWN_REACHABILITY_RETRY_MS + 1,
        authorizedCatalogProofForTag(tag),
      ),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.existingReachabilityRowIsReusable(
        persisted,
        {
          ...candidate,
          fetched_at: new Date(checkedAtMs + 1).toISOString(),
        },
        releaseCommit,
        checkedAtMs + 1,
        authorizedCatalogProofForTag(tag),
      ),
      false,
    );

    let ancestryChecks = 0;
    const refreshed = await __releaseReachabilityTest.stageReleasePrReachabilityBulk([tag], {
      listCandidates: () => [candidate],
      getReleaseCommit: () => releaseCommit,
      catalogProofForTag: authorizedCatalogProofForTag,
      now: () => checkedAtMs + __releaseReachabilityTest.UNKNOWN_REACHABILITY_RETRY_MS + 1,
      context: {
        concurrency: 1,
        ensureObject: async () => ({ status: 'available' as const }),
        checkAncestor: async () => {
          ancestryChecks++;
          return command(0);
        },
      },
    });

    assert.equal(ancestryChecks, 1);
    assert.equal(refreshed[0].replace, true);
    assert.equal(refreshed[0].result.reachable, 1);
    assert.equal(refreshed[0].result.unknown, 0);
    assert.equal(refreshed[0].rows[0].status, 'reachable');
    assert.deepEqual(refreshed[0].resetCheckedAtRows, [{
      prRepositoryNameWithOwner: candidate.pr_repository_name_with_owner,
      prNumber: candidate.pr_number,
    }]);
  });

  it('keeps transient merged PR fetch and object-check failures blocking', async () => {
    const mergeCommit = 'b'.repeat(40);
    const candidate = {
      pr_repository_owner: 'openclaw',
      pr_repository_name: 'openclaw',
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 91,
      merge_commit_oid: mergeCommit,
      base_ref_name: 'main',
      fetched_at: '2026-01-01T00:00:00Z',
    };
    const stageWithObjectResult = (tag: string, objectResult: any) =>
      __releaseReachabilityTest.stageReleasePrReachabilityBulk([tag], {
        listCandidates: () => [candidate],
        getReleaseCommit: () => authorizedReleaseCommitForTag(tag),
        catalogProofForTag: authorizedCatalogProofForTag,
        context: {
          concurrency: 1,
          ensureObject: async (oid: string) => oid === mergeCommit
            ? objectResult
            : { status: 'available' as const },
          checkAncestor: async () => command(0),
        },
      });

    await assert.rejects(
      stageWithObjectResult(
        'v-transient-fetch',
        { status: 'fetch_failed', command: command(128, 'fatal: unable to access repository') },
      ),
      (error: unknown) => {
        assert.ok(error instanceof Error);
        assert.match(
          error.message,
          new RegExp(
            `^commit_fetch_failed; git fetch --filter=blob:none --no-tags origin ${mergeCommit};`,
          ),
        );
        return true;
      },
    );
    await assert.rejects(
      stageWithObjectResult(
        'v-transient-check',
        {
          status: 'check_failed',
          command: command(null, 'object probe timed out', '', { timedOut: true, signal: 'SIGTERM' }),
        },
      ),
      /commit_unavailable.*timed out/,
    );
  });

  it('distinguishes true non-ancestry from git errors', () => {
    const reachable = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 0, stdout: '', stderr: '', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(reachable.status, 'reachable');
    assert.equal(reachable.evidence.evidence, 'merge_commit_in_release_history');

    const notReachable = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 1, stdout: '', stderr: '', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(notReachable.status, 'not_reachable');
    assert.equal(notReachable.evidence.evidence, 'not_reachable_from_release_tag');

    const error = __releaseReachabilityTest.interpretMergeBaseResult(
      { status: 128, stdout: '', stderr: 'fatal: bad object', signal: null } as any,
      'merge_commit_in_release_history',
    );
    assert.equal(error.status, 'unknown');
    assert.equal(error.evidence.evidence, 'merge_base_error');
    assert.equal(error.evidence.status, 128);
    assert.equal(error.evidence.stderr, 'fatal: bad object');

    const aborted = __releaseReachabilityTest.interpretMergeBaseResult(
      command(null, 'command aborted', '', { aborted: true, signal: 'SIGTERM' }),
      'merge_commit_in_release_history',
    );
    assert.equal(aborted.status, 'unknown');
    assert.equal(aborted.evidence.evidence, 'merge_base_error');
    assert.equal(aborted.evidence.status, null);
    assert.equal(aborted.evidence.stderr, 'command aborted');
  });

  it('only treats recognized missing-object fetch failures as unavailable', () => {
    assert.equal(
      __releaseReachabilityTest.directCommitIsUnavailable({
        status: 'fetch_failed',
        command: command(128, 'fatal: remote error: upload-pack: not our ref deadbeef'),
      }),
      true,
    );
    assert.equal(
      __releaseReachabilityTest.directCommitIsUnavailable({
        status: 'check_failed',
        command: {
          ...command(null, 'fatal: remote error: upload-pack: not our ref deadbeef'),
          timedOut: true,
          signal: 'SIGTERM',
        },
      }),
      true,
    );
    assert.equal(
      __releaseReachabilityTest.directCommitIsUnavailable({
        status: 'fetch_failed',
        command: command(128, 'fatal: unable to access repository'),
      }),
      false,
    );
    assert.equal(
      __releaseReachabilityTest.directCommitIsUnavailable({
        status: 'unavailable',
        command: command(128, 'fatal: bad object'),
      }),
      true,
    );
  });

  it('emits typed evidence with commit identity and command diagnostics', () => {
    const tagCommitOid = 'a'.repeat(40);
    const checkedCommitOid = 'b'.repeat(40);
    const evidence = __releaseReachabilityTest.reachabilityEvidence({
      evidence: 'commit_fetch_failed',
      tagCommitOid,
      checkedCommitOid,
      baseRefName: 'main',
      command: { status: 128, stdout: '', stderr: 'fatal: bad object', signal: null } as any,
    });

    assert.equal(evidence.schemaVersion, 1);
    assert.equal(evidence.evidence, 'commit_fetch_failed');
    assert.equal(evidence.method, 'git-merge-base');
    assert.equal(evidence.tagCommitOid, tagCommitOid);
    assert.equal(evidence.checkedCommitOid, checkedCommitOid);
    assert.equal(evidence.baseRefName, 'main');
    assert.equal(evidence.commandStatus, 128);
    assert.equal(evidence.stderr, 'fatal: bad object');
  });

  it('exports every persisted reachability evidence reason as known', () => {
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('merge_commit_in_release_history'));
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('not_reachable_from_release_tag'));
    assert.ok(__releaseReachabilityTest.KNOWN_REACHABILITY_EVIDENCE_REASONS.includes('merge_base_error'));
  });

  it('parses the existing PR CLI and explicit direct-commit proof mode', async () => {
    const {
      parseReleaseReachabilityArgs,
      releaseReachabilityUsage,
    } = await import('../../scripts/lib/release-reachability-args.mjs');

    assert.deepEqual(parseReleaseReachabilityArgs(['v-target']), {
      mode: 'pull_requests',
      tag: 'v-target',
    });
    assert.deepEqual(parseReleaseReachabilityArgs([
      'v-target',
      '--direct-commit',
      'a'.repeat(40),
      '--repository',
      'openclaw/openclaw',
      '--predecessor',
      'v-predecessor',
    ]), {
      mode: 'direct_commit',
      tag: 'v-target',
      commitOid: 'a'.repeat(40),
      repositoryNameWithOwner: 'openclaw/openclaw',
      predecessorTag: 'v-predecessor',
    });
    assert.throws(
      () => parseReleaseReachabilityArgs([
        'v-target',
        '--direct-commit',
        'a'.repeat(40),
        '--repository',
        'openclaw/openclaw',
      ]),
      /requires --predecessor/,
    );
    assert.match(releaseReachabilityUsage(), /--direct-commit <oid>/);
  });

  it('keeps the direct-commit CLI path free of runtime DB imports', async () => {
    const script = await readFile(
      join(process.cwd(), 'scripts/check-release-pr-reachability.mjs'),
      'utf8',
    );
    const reachability = await readFile(
      join(process.cwd(), 'src/lib/releaseReachability.ts'),
      'utf8',
    );
    const directStart = script.indexOf("if (args.mode === 'direct_commit')");
    const directEnd = script.indexOf('\nconst tag = args.tag;', directStart);
    assert.ok(directStart >= 0 && directEnd > directStart);
    const directBranch = script.slice(directStart, directEnd);
    assert.match(
      directBranch,
      /checkDirectCommitFirstContainingReleaseFromRemoteCatalog/,
    );
    assert.doesNotMatch(
      directBranch,
      /db\.ts|getRelease|acquireRenewableRefreshLease|insertIngestionEvidenceFailure/,
    );
    assert.doesNotMatch(
      reachability,
      /^import(?! type\b)[^;]+from ['"]\.\/db(?:\.ts)?['"];?/gm,
    );
    assert.match(
      reachability,
      /export async function checkDirectCommitFirstContainingRelease\(/,
    );
    assert.match(
      reachability,
      /export async function checkDirectCommitFirstContainingReleaseBulk\(/,
    );

    const remoteStart = reachability.indexOf(
      'export async function checkDirectCommitFirstContainingReleaseFromRemoteCatalog',
    );
    const bulkStart = reachability.indexOf(
      'export async function checkDirectCommitFirstContainingReleaseBulk',
      remoteStart,
    );
    assert.ok(remoteStart >= 0 && bulkStart > remoteStart);
    const remotePath = reachability.slice(remoteStart, bulkStart);
    assert.match(remotePath, /fetchReleaseCatalog/);
    assert.match(remotePath, /projectDirectCommitStableReleaseBoundaries/);
    assert.doesNotMatch(
      remotePath,
      /loadReachabilityDatabaseRuntime|import\(['"]\.\/db(?:\.ts)?['"]\)/,
    );
  });
});
