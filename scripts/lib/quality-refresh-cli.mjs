import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { basename, dirname, isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import dotenv from 'dotenv';

const SQLITE_FAMILY_SUFFIXES = ['', '-wal', '-shm', '-journal'];
const USAGE =
  'Usage: refresh:quality -- --db-path <isolated-quality-database> ' +
  '[--resume-existing]';

export function parseQualityRefreshArgs(argv, { cwd = process.cwd() } = {}) {
  const hasDatabasePath =
    argv[0] === '--db-path' &&
    Boolean(argv[1]) &&
    !argv[1].startsWith('--');
  const freshInvocation = argv.length === 2 && hasDatabasePath;
  const resumeInvocation =
    argv.length === 3 &&
    hasDatabasePath &&
    argv[2] === '--resume-existing';

  if (!freshInvocation && !resumeInvocation) {
    throw new Error(USAGE);
  }

  return {
    databasePath: resolve(cwd, argv[1]),
    resumeExisting: resumeInvocation,
  };
}

export function validateQualityRefreshDatabase({
  databasePath,
  repositoryRoot,
  resumeExisting = false,
  environmentDatabasePath,
  dotenvConfigPath,
  platform = process.platform,
}) {
  const requestedFamily = inspectSqliteFamily(databasePath);
  const applicationDatabasePaths = configuredApplicationDatabasePaths({
    repositoryRoot,
    environmentDatabasePath,
    dotenvConfigPath,
  });

  for (const applicationDatabasePath of applicationDatabasePaths) {
    const applicationFamily = inspectSqliteFamily(applicationDatabasePath);
    for (const requestedMember of requestedFamily) {
      for (const applicationMember of applicationFamily) {
        if (
          pathEntriesAlias(requestedMember, applicationMember, { platform })
        ) {
          throw new Error(
            'refresh:quality refuses configured application database ' +
            'SQLite family aliases; ' +
            `${requestedMember.path} aliases ${applicationMember.path}`,
          );
        }
      }
    }
  }

  if (!resumeExisting) {
    const existingFamilyMember = requestedFamily.find(
      (member) => member.lstat !== null,
    );
    if (existingFamilyMember) {
      throw new Error(
        'refresh:quality requires a fresh database; ' +
        `SQLite family member already exists: ${existingFamilyMember.path}`,
      );
    }
    return;
  }

  const [mainDatabase, ...sidecars] = requestedFamily;
  if (mainDatabase.lstat === null) {
    throw new Error(
      'refresh:quality --resume-existing requires an existing main database: ' +
      mainDatabase.path,
    );
  }
  assertRegularNonSymlink(mainDatabase, 'main database');
  for (const sidecar of sidecars) {
    if (sidecar.lstat !== null) {
      assertRegularNonSymlink(sidecar, 'SQLite sidecar');
    }
  }
}

export function configuredApplicationDatabasePaths({
  repositoryRoot,
  environmentDatabasePath,
  dotenvConfigPath,
}) {
  const protectedPaths = new Set([
    resolve(repositoryRoot, 'data', 'radar.db'),
  ]);
  if (environmentDatabasePath !== undefined) {
    const configuredPath = databaseFilesystemPath(environmentDatabasePath, {
      cwd: repositoryRoot,
      source: 'the inherited environment',
    });
    if (configuredPath !== null) {
      protectedPaths.add(configuredPath);
    }
  }
  const repositoryEnvPath = resolve(repositoryRoot, '.env');
  const environmentFiles = new Map([[repositoryEnvPath, false]]);

  if (dotenvConfigPath !== undefined && dotenvConfigPath !== '') {
    if (
      typeof dotenvConfigPath !== 'string' ||
      dotenvConfigPath.trim() !== dotenvConfigPath
    ) {
      throw new Error(
        'refresh:quality DOTENV_CONFIG_PATH must be a path without ' +
        'leading or trailing whitespace',
      );
    }
    environmentFiles.set(resolve(repositoryRoot, dotenvConfigPath), true);
  }

  for (const [environmentPath, required] of environmentFiles) {
    const configuredLocation = configuredDatabaseLocationFromEnvironmentFile(
      environmentPath,
      { required },
    );
    if (configuredLocation === null) continue;
    const configuredPath = databaseFilesystemPath(configuredLocation, {
      cwd: repositoryRoot,
      source: environmentPath,
    });
    if (configuredPath !== null) protectedPaths.add(configuredPath);
  }

  return [...protectedPaths];
}

function inspectSqliteFamily(databasePath) {
  return SQLITE_FAMILY_SUFFIXES.map((suffix) =>
    inspectPathEntry(`${databasePath}${suffix}`));
}

function inspectPathEntry(path) {
  const absolutePath = resolve(path);
  const initialLstat = lstatIfPresent(
    absolutePath,
    'inspect SQLite family member',
  );
  const resolution = resolveThroughExistingAncestor(absolutePath);
  const lstat = lstatIfPresent(
    absolutePath,
    'reinspect SQLite family member',
  );
  if (!samePathEntry(initialLstat, lstat)) {
    throw new Error(
      'refresh:quality SQLite family member changed during admission: ' +
      absolutePath,
    );
  }
  let ancestorStat;
  try {
    ancestorStat = statSync(resolution.ancestorPath, { bigint: true });
  } catch (error) {
    throw new Error(
      'refresh:quality could not recheck SQLite path ancestor: ' +
      resolution.ancestorPath,
      { cause: error },
    );
  }
  if (
    ancestorStat.dev !== resolution.ancestorIdentity.dev ||
    ancestorStat.ino !== resolution.ancestorIdentity.ino
  ) {
    throw new Error(
      'refresh:quality SQLite path ancestor changed during admission: ' +
      resolution.ancestorPath,
    );
  }
  let stat = null;
  if (lstat !== null) {
    try {
      stat = statSync(absolutePath, { bigint: true });
    } catch (error) {
      throw new Error(
        `refresh:quality could not inspect SQLite family target: ${absolutePath}`,
        { cause: error },
      );
    }
    if (
      resolution.missingSegments.length !== 0 ||
      resolution.ancestorIdentity.dev !== stat.dev ||
      resolution.ancestorIdentity.ino !== stat.ino
    ) {
      throw new Error(
        'refresh:quality SQLite family target changed during admission: ' +
        absolutePath,
      );
    }
  }

  return {
    path: absolutePath,
    resolvedPath: resolution.resolvedPath,
    ancestorIdentity: resolution.ancestorIdentity,
    missingSegments: resolution.missingSegments,
    lstat,
    stat,
  };
}

function resolveThroughExistingAncestor(path) {
  let current = resolve(path);
  const missingSegments = [];

  while (true) {
    try {
      const resolvedAncestor = realpathSync.native(current);
      const ancestorStat = statSync(current, { bigint: true });
      return {
        resolvedPath: resolve(resolvedAncestor, ...missingSegments),
        ancestorPath: current,
        ancestorIdentity: {
          dev: ancestorStat.dev,
          ino: ancestorStat.ino,
        },
        missingSegments,
      };
    } catch (error) {
      if (error?.code !== 'ENOENT') {
        throw new Error(
          `refresh:quality could not resolve SQLite family member: ${path}`,
          { cause: error },
        );
      }
      const unresolvedEntry = lstatIfPresent(
        current,
        'inspect unresolved SQLite path component',
      );
      if (unresolvedEntry !== null) {
        throw new Error(
          'refresh:quality cannot resolve existing SQLite path component: ' +
          current,
          { cause: error },
        );
      }
      const parent = dirname(current);
      if (parent === current) {
        throw new Error(
          `refresh:quality could not resolve an existing ancestor for: ${path}`,
          { cause: error },
        );
      }
      missingSegments.unshift(basename(current));
      current = parent;
    }
  }
}

function pathEntriesAlias(left, right, { platform }) {
  if (
    left.stat !== null &&
    right.stat !== null &&
    left.stat.dev === right.stat.dev &&
    left.stat.ino === right.stat.ino
  ) {
    return true;
  }
  if (
    pathComparisonKey(left.resolvedPath, platform) ===
    pathComparisonKey(right.resolvedPath, platform)
  ) {
    return true;
  }
  return (
    left.ancestorIdentity.dev === right.ancestorIdentity.dev &&
    left.ancestorIdentity.ino === right.ancestorIdentity.ino &&
    pathSegmentsEqual(
      left.missingSegments,
      right.missingSegments,
      platform,
    )
  );
}

function assertRegularNonSymlink(member, label) {
  if (member.lstat.isSymbolicLink() || !member.lstat.isFile()) {
    throw new Error(
      `refresh:quality resume ${label} must be a regular non-symlink file: ` +
      member.path,
    );
  }
}

function configuredDatabaseLocationFromEnvironmentFile(
  environmentPath,
  { required },
) {
  let entry;
  try {
    entry = lstatSync(environmentPath);
  } catch (error) {
    if (error?.code === 'ENOENT' && !required) return null;
    throw new Error(
      'refresh:quality could not inspect configured application ' +
      `environment: ${environmentPath}`,
      { cause: error },
    );
  }
  if (!entry.isFile() && !entry.isSymbolicLink()) {
    throw new Error(
      'refresh:quality configured application environment must be a file: ' +
      environmentPath,
    );
  }

  let contents;
  try {
    contents = readFileSync(environmentPath);
  } catch (error) {
    throw new Error(
      'refresh:quality could not read configured application environment: ' +
      environmentPath,
      { cause: error },
    );
  }
  const values = dotenv.parse(contents);
  if (!Object.prototype.hasOwnProperty.call(values, 'DB_PATH')) return null;
  const configuredLocation = values.DB_PATH;
  if (
    configuredLocation.length === 0 ||
    configuredLocation.trim() !== configuredLocation
  ) {
    throw new Error(
      `refresh:quality invalid DB_PATH in ${environmentPath}`,
    );
  }
  return configuredLocation;
}

function databaseFilesystemPath(location, { cwd, source }) {
  if (
    typeof location !== 'string' ||
    location.length === 0 ||
    location.trim() !== location
  ) {
    throw new Error(
      `refresh:quality invalid configured DB_PATH in ${source}`,
    );
  }
  if (location === ':memory:') return null;
  if (!location.startsWith('file:')) return resolve(cwd, location);

  const sqliteLocation = location.slice('file:'.length);
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

  try {
    if (sqlitePath.startsWith('//')) {
      return resolve(fileURLToPath(new URL(location)));
    }
    const decodedPath = decodeURIComponent(sqlitePath);
    if (decodedPath.length === 0) {
      throw new Error('empty SQLite file URI path');
    }
    return isAbsolute(decodedPath)
      ? resolve(decodedPath)
      : resolve(cwd, decodedPath);
  } catch (error) {
    throw new Error(
      `refresh:quality invalid configured DB_PATH in ${source}: ${location}`,
      { cause: error },
    );
  }
}

function lstatIfPresent(path, action) {
  try {
    return lstatSync(path, { bigint: true });
  } catch (error) {
    if (error?.code === 'ENOENT') return null;
    throw new Error(
      `refresh:quality could not ${action}: ${path}`,
      { cause: error },
    );
  }
}

function samePathEntry(left, right) {
  if (left === null || right === null) return left === right;
  return (
    left.dev === right.dev &&
    left.ino === right.ino &&
    left.mode === right.mode
  );
}

function pathSegmentsEqual(left, right, platform) {
  if (left.length !== right.length) return false;
  return left.every(
    (segment, index) =>
      pathComparisonKey(segment, platform) ===
      pathComparisonKey(right[index], platform),
  );
}

function pathComparisonKey(path, platform) {
  const normalized = path.normalize('NFD');
  return platform === 'darwin' ? normalized.toLowerCase() : normalized;
}
