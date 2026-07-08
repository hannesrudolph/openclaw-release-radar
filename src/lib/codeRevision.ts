import { createHash } from 'node:crypto';
import { lstatSync, readFileSync, readlinkSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';

const CODE_REVISION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:@/+~-]{0,255}$/;
const GIT_OBJECT_ID_PATTERN = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/i;
const GIT_BUFFER_LIMIT = 64 * 1024 * 1024;

export function normalizeCodeRevision(
  value: string | null | undefined,
): string | null {
  if (typeof value !== 'string') return null;
  const revision = value.trim();
  if (!revision || !CODE_REVISION_PATTERN.test(revision)) return null;
  return GIT_OBJECT_ID_PATTERN.test(revision) ? revision.toLowerCase() : revision;
}

export function codeRevisionFromEnv(
  env: NodeJS.ProcessEnv = process.env,
  cwd: string = process.cwd(),
): string | null {
  for (const value of [
    env.RADAR_CODE_REVISION,
    env.CODE_REVISION,
  ]) {
    const revision = normalizeCodeRevision(value);
    if (revision) return revision;
  }
  for (const value of [
    env.GITHUB_SHA,
    env.RENDER_GIT_COMMIT,
    env.VERCEL_GIT_COMMIT_SHA,
    env.CF_PAGES_COMMIT_SHA,
    env.SOURCE_VERSION,
  ]) {
    const revision = normalizeProviderGitRevision(value);
    if (revision) return revision;
  }
  return localGitCodeRevision(cwd);
}

export function localGitCodeRevision(cwd: string = process.cwd()): string | null {
  const head = gitOutput(cwd, ['rev-parse', '--verify', 'HEAD']);
  if (!head) return null;
  const headRevision = normalizeProviderGitRevision(head.toString('utf8'));
  if (!headRevision) return null;

  const status = gitOutput(cwd, [
    'status',
    '--porcelain=v1',
    '-z',
    '--untracked-files=all',
    '--ignore-submodules=none',
  ]);
  if (status == null) return null;
  if (status.length === 0) return `git:${headRevision}`;

  const trackedDiff = gitOutput(cwd, [
    'diff',
    '--binary',
    '--no-ext-diff',
    '--ignore-submodules=none',
    'HEAD',
    '--',
  ]);
  const untracked = gitOutput(cwd, [
    'ls-files',
    '--others',
    '--exclude-standard',
    '-z',
  ]);
  if (trackedDiff == null || untracked == null) return null;

  const digest = createHash('sha256');
  digest.update('openclaw-release-radar-local-code-v1\0');
  digest.update(status);
  digest.update('\0tracked-diff\0');
  digest.update(trackedDiff);
  for (const relativePath of nulSeparatedPaths(untracked)) {
    const absolutePath = resolve(cwd, relativePath);
    const stat = lstatSync(absolutePath);
    digest.update('\0untracked-path\0');
    digest.update(relativePath);
    if (stat.isSymbolicLink()) {
      digest.update('\0symlink\0');
      digest.update(readlinkSync(absolutePath));
    } else {
      digest.update('\0file\0');
      digest.update(readFileSync(absolutePath));
    }
  }
  return `git:${headRevision}:dirty:${digest.digest('hex')}`;
}

function normalizeProviderGitRevision(
  value: string | null | undefined,
): string | null {
  const revision = typeof value === 'string' ? value.trim() : '';
  return GIT_OBJECT_ID_PATTERN.test(revision) ? revision.toLowerCase() : null;
}

function gitOutput(cwd: string, args: string[]): Buffer | null {
  const result = spawnSync('git', args, {
    cwd,
    encoding: 'buffer',
    maxBuffer: GIT_BUFFER_LIMIT,
    stdio: ['ignore', 'pipe', 'ignore'],
  });
  return result.status === 0 && Buffer.isBuffer(result.stdout)
    ? result.stdout
    : null;
}

function nulSeparatedPaths(value: Buffer): string[] {
  return value
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .sort();
}
