import { existsSync, readFileSync, realpathSync } from 'node:fs';
import { homedir } from 'node:os';
import {
  basename,
  dirname,
  isAbsolute,
  join,
  parse as parsePath,
  resolve,
} from 'node:path';
import { fileURLToPath } from 'node:url';
import { parse } from 'dotenv';

export function resolveConfiguredLiveDatabase({
  root,
  environment = process.env,
  envFilePath,
  envFileText,
} = {}) {
  if (!root) throw new Error('Repository root is required');

  const configuredEnvFilePath = envFilePath ??
    resolveDotenvPath(environment.DOTENV_CONFIG_PATH || '.env', root);
  const fileValues = envFileText === undefined
    ? readEnvironmentFile(configuredEnvFilePath)
    : parse(envFileText);
  const configuredPath = nonEmpty(environment.DB_PATH)
    ?? nonEmpty(fileValues.DB_PATH)
    ?? './data/radar.db';

  return resolveDatabaseLocation(configuredPath, { cwd: root });
}

export function resolveDatabaseLocation(location, { cwd = process.cwd() } = {}) {
  if (location instanceof URL) {
    if (location.protocol !== 'file:') return null;
    return resolve(fileURLToPath(location));
  }

  let value = Buffer.isBuffer(location)
    ? location.toString()
    : typeof location === 'string'
      ? location
      : null;
  if (value === null || value === '' || value === ':memory:') {
    return null;
  }

  if (value.startsWith('file:')) {
    const sqliteLocation = value.slice('file:'.length);
    const queryIndex = sqliteLocation.search(/[?#]/);
    const sqlitePath = queryIndex === -1
      ? sqliteLocation
      : sqliteLocation.slice(0, queryIndex);
    const query = queryIndex === -1
      ? ''
      : sqliteLocation.slice(queryIndex + 1).split('#', 1)[0];
    const parameters = new URLSearchParams(query);
    if (sqlitePath === ':memory:' || parameters.get('mode') === 'memory') {
      return null;
    }
    if (sqlitePath.startsWith('//')) {
      return resolve(fileURLToPath(new URL(value)));
    }
    value = decodeURIComponent(sqlitePath);
  }

  return isAbsolute(value) ? resolve(value) : resolve(cwd, value);
}

export function canonicalizePath(path) {
  const absolute = resolve(path);
  const suffix = [];
  let cursor = absolute;
  const root = parsePath(absolute).root;
  while (cursor !== root && !existsSync(cursor)) {
    suffix.unshift(basename(cursor));
    cursor = dirname(cursor);
  }
  const canonicalParent = realpathSync.native(cursor);
  return resolve(canonicalParent, ...suffix);
}

function readEnvironmentFile(path) {
  if (!existsSync(path)) return {};
  return parse(readFileSync(path));
}

function resolveDotenvPath(path, cwd) {
  const expanded = path.startsWith('~')
    ? join(homedir(), path.slice(1))
    : path;
  return resolve(cwd, expanded);
}

function nonEmpty(value) {
  if (typeof value !== 'string') return null;
  const trimmed = value.trim();
  return trimmed || null;
}
