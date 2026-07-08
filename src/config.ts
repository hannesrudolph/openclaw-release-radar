import dotenv from 'dotenv';
import {
  lstatSync,
  readFileSync,
  realpathSync,
  statSync,
} from 'node:fs';
import { isAbsolute, resolve } from 'node:path';

type ConfigurationEnvironment = Readonly<Record<string, string | undefined>>;

const production = process.env.NODE_ENV === 'production';
const applicationRootPath = production
  ? realpathSync(resolve(__dirname, '..'))
  : resolve(__dirname, '..');
const productionRuntimeEnvPath = resolve(__dirname, '..', '.env');
const productionManagedEnvironmentKeys = [
  'GITHUB_OWNER',
  'GITHUB_REPO',
  'GITHUB_REPOSITORY_NODE_ID',
  'GITHUB_TOKEN',
  'GITHUB_PERSONAL_ACCESS_TOKEN',
  'GITHUB_GRAPHQL_CONCURRENCY',
  'GITHUB_GRAPHQL_MIN_START_SPACING_MS',
  'GITHUB_GRAPHQL_RETRY_BASE_MS',
  'GITHUB_GRAPHQL_RETRY_MAX_MS',
  'GITHUB_GRAPHQL_COOLDOWN_BASE_MS',
  'GITHUB_GRAPHQL_COOLDOWN_MAX_MS',
  'GITHUB_GRAPHQL_REQUEST_TIMEOUT_MS',
  'GITHUB_GRAPHQL_BODY_TIMEOUT_MS',
  'GITHUB_GRAPHQL_MAX_PAGES_PER_CONNECTION',
  'OPENAI_API_KEY',
  'OC_OPENAI_API_KEY',
  'OPENAI_MODEL',
  'OPENAI_REASONING_EFFORT',
  'OPENAI_SERVICE_TIER',
  'OPENAI_REQUEST_TIMEOUT_MS',
  'OPENAI_MAX_ATTEMPTS',
  'OPENAI_RETRY_BASE_MS',
  'OPENAI_RETRY_MAX_MS',
  'PORT',
  'DB_PATH',
  'RADAR_DB_READ_ONLY',
  'RADAR_DB_BOOTSTRAP_MODE',
  'LABEL_AUTHORITY_APPROVED_ROSTER_PATH',
  'LABEL_AUTHORITY_APPROVED_ROSTER_KEYRING_PATH',
  'LABEL_AUTHORITY_APPROVED_ROSTER_STATE_PATH',
  'REFRESH_ON_STARTUP',
  'REFRESH_MINUTES',
  'FULL_ISSUE_BACKFILL',
  'MAX_ISSUE_PAGES',
  'GITHUB_ISSUE_PAGE_SIZE',
  'ISSUE_CATALOG_SNAPSHOT_MAX_AGE_HOURS',
  'CLASSIFY_CONCURRENCY',
  'GITHUB_GRAPHQL_PAGE_DELAY_MS',
  'RELEASE_NETWORK_CONCURRENCY',
  'CLOSURE_EVIDENCE_CONCURRENCY',
  'CLOSURE_PROOF_CONCURRENCY',
  'GIT_REACHABILITY_CONCURRENCY',
  'GIT_CACHE_MAX_PACKS',
  'GIT_CACHE_MAX_SIZE_MIB',
  'GIT_CACHE_MAINTENANCE_TIMEOUT_MS',
  'OPEN_PR_REFRESH_MINUTES',
  'CLOSED_PR_REFRESH_MINUTES',
  'COMPARISON_API_ENABLED',
  'RELEASES_LIMIT',
  'OPENCLAW_REPO_URL',
  'RADAR_CODE_REVISION',
  'CODE_REVISION',
  'GITHUB_SHA',
  'RENDER_GIT_COMMIT',
  'VERCEL_GIT_COMMIT_SHA',
  'CF_PAGES_COMMIT_SHA',
  'SOURCE_VERSION',
] as const;
const forbiddenProductionRuntimeKeys = [
  'NODE_ENV',
  'DOTENV_CONFIG_PATH',
  'DOTENV_CONFIG_OVERRIDE',
  'CODE_REVISION',
] as const;
const releaseRevisionPattern = /^[0-9a-f]{40}(?:[0-9a-f]{24})?$/;

const configurationSource = loadConfigurationSource();
const configurationEnvironment = configurationSource.environment;

function loadConfigurationSource(): {
  kind: 'release-runtime-env' | 'process-env-with-dotenv';
  path: string;
  realPath: string | null;
  environment: ConfigurationEnvironment;
} {
  if (!production) {
    const configuredPath = process.env.DOTENV_CONFIG_PATH || '.env';
    dotenv.config({
      path: configuredPath,
      override: false,
    });
    return {
      kind: 'process-env-with-dotenv',
      path: resolve(configuredPath),
      realPath: null,
      environment: process.env,
    };
  }

  let pathInfo;
  try {
    pathInfo = lstatSync(productionRuntimeEnvPath);
  } catch (error) {
    throw new Error(
      `[config] production runtime env is missing: ${productionRuntimeEnvPath}`,
      { cause: error },
    );
  }
  if (!pathInfo.isFile() && !pathInfo.isSymbolicLink()) {
    throw new Error(
      `[config] production runtime env must be a regular file or file symlink: ` +
      productionRuntimeEnvPath,
    );
  }

  let realPath: string;
  let contents: Buffer;
  try {
    realPath = realpathSync(productionRuntimeEnvPath);
    if (!statSync(realPath).isFile()) {
      throw new Error('resolved target is not a regular file');
    }
    contents = readFileSync(realPath);
  } catch (error) {
    throw new Error(
      `[config] production runtime env cannot be resolved or read: ` +
      productionRuntimeEnvPath,
      { cause: error },
    );
  }

  const parsed = dotenv.parse(contents);
  for (const key of forbiddenProductionRuntimeKeys) {
    if (Object.prototype.hasOwnProperty.call(parsed, key)) {
      throw new Error(
        `[config] production runtime env must not define ${key}: ${realPath}`,
      );
    }
  }

  installProductionProcessEnvironment(parsed);
  return {
    kind: 'release-runtime-env',
    path: productionRuntimeEnvPath,
    realPath,
    environment: Object.freeze({ ...parsed }),
  };
}

function installProductionProcessEnvironment(
  environment: Readonly<Record<string, string>>,
): void {
  for (const key of productionManagedEnvironmentKeys) {
    delete process.env[key];
  }
  delete process.env.DOTENV_CONFIG_PATH;
  delete process.env.DOTENV_CONFIG_OVERRIDE;

  for (const key of productionManagedEnvironmentKeys) {
    const value = environment[key];
    if (value !== undefined) process.env[key] = value;
  }
}

function configurationError(message: string): Error {
  if (!production) return new Error(message);
  return new Error(
    `[config] invalid production runtime env ${configurationSource.realPath}: ${message}`,
  );
}

function value(key: string): string | undefined {
  return configurationEnvironment[key];
}

function env(key: string, fallback?: string): string {
  const configured = value(key) ?? fallback;
  if (configured === undefined) throw configurationError(`Missing env var: ${key}`);
  return configured;
}

function requireProductionValue(key: string): string {
  const configured = value(key);
  if (configured == null || configured === '') {
    throw configurationError(`Missing required production env var: ${key}`);
  }
  if (configured.trim() !== configured) {
    throw configurationError(`${key} must not contain leading or trailing whitespace`);
  }
  return configured;
}

function requireProductionDatabaseSafety(): void {
  const readOnly = requireProductionValue('RADAR_DB_READ_ONLY');
  if (readOnly !== '1' && readOnly !== 'true') {
    throw configurationError(
      `RADAR_DB_READ_ONLY must be true or 1, got ${readOnly}`,
    );
  }

  const bootstrapMode = requireProductionValue('RADAR_DB_BOOTSTRAP_MODE');
  if (bootstrapMode !== 'existing') {
    throw configurationError(
      `RADAR_DB_BOOTSTRAP_MODE must be existing, got ${bootstrapMode}`,
    );
  }
}

function num(key: string, fallback: number): number {
  const raw = value(key);
  if (!raw) return fallback;
  const n = Number(raw);
  if (Number.isNaN(n)) throw configurationError(`Invalid number for ${key}: ${raw}`);
  return n;
}

function intInRange(key: string, fallback: number, min: number, max: number): number {
  const n = num(key, fallback);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw configurationError(
      `${key} must be an integer in [${min}, ${max}], got ${n}`,
    );
  }
  return n;
}

function bool(key: string, fallback = false): boolean {
  const raw = value(key);
  if (raw == null || raw === '') return fallback;
  if (/^(1|true|yes|on)$/i.test(raw)) return true;
  if (/^(0|false|no|off)$/i.test(raw)) return false;
  throw configurationError(`${key} must be true or false, got ${raw}`);
}

function optional(key: string): string | null {
  const configured = value(key);
  if (configured == null || configured === '') return null;
  if (configured.trim() !== configured) {
    throw configurationError(`${key} must not contain leading or trailing whitespace`);
  }
  return configured;
}

function choice<const T extends readonly string[]>(
  key: string,
  fallback: T[number],
  values: T,
): T[number] {
  const configured = env(key, fallback);
  if (!values.includes(configured)) {
    throw configurationError(
      `${key} must be one of ${values.join(', ')}, got ${configured}`,
    );
  }
  return configured;
}

function canonicalProductionDatabasePath(configuredPath: string): string {
  if (!isAbsolute(configuredPath)) {
    throw configurationError(`DB_PATH must be absolute, got ${configuredPath}`);
  }
  let info;
  try {
    info = lstatSync(configuredPath);
  } catch (error) {
    throw new Error(
      `[config] production DB_PATH does not exist: ${configuredPath}`,
      { cause: error },
    );
  }
  if (!info.isFile() || info.isSymbolicLink()) {
    throw configurationError(
      `DB_PATH must be a regular non-symlink file, got ${configuredPath}`,
    );
  }
  return realpathSync(configuredPath);
}

if (production) {
  requireProductionDatabaseSafety();
  for (const key of [
    'PORT',
    'DB_PATH',
    'REFRESH_ON_STARTUP',
    'REFRESH_MINUTES',
    'RADAR_CODE_REVISION',
  ]) {
    requireProductionValue(key);
  }
}

const githubGraphqlRetryBaseMs = intInRange(
  'GITHUB_GRAPHQL_RETRY_BASE_MS',
  15_000,
  100,
  300_000,
);
const githubGraphqlRetryMaxMs = intInRange(
  'GITHUB_GRAPHQL_RETRY_MAX_MS',
  300_000,
  100,
  900_000,
);
const githubGraphqlCooldownBaseMs = intInRange(
  'GITHUB_GRAPHQL_COOLDOWN_BASE_MS',
  30_000,
  100,
  300_000,
);
const githubGraphqlCooldownMaxMs = intInRange(
  'GITHUB_GRAPHQL_COOLDOWN_MAX_MS',
  300_000,
  100,
  900_000,
);
const openaiRetryBaseMs = intInRange(
  'OPENAI_RETRY_BASE_MS',
  1_000,
  100,
  60_000,
);
const openaiRetryMaxMs = intInRange(
  'OPENAI_RETRY_MAX_MS',
  30_000,
  1_000,
  300_000,
);
const serverPort = intInRange('PORT', 8787, 1, 65_535);
const configuredDatabasePath = env('DB_PATH', './data/radar.db');
const databasePath = production
  ? canonicalProductionDatabasePath(configuredDatabasePath)
  : configuredDatabasePath;
const refreshOnStartup = bool('REFRESH_ON_STARTUP', false);
const refreshIntervalMinutes = intInRange('REFRESH_MINUTES', 0, 0, 600);
const releaseRevision = production
  ? requireProductionValue('RADAR_CODE_REVISION')
  : value('RADAR_CODE_REVISION') ?? value('CODE_REVISION') ?? null;

if (production && !releaseRevisionPattern.test(releaseRevision ?? '')) {
  throw configurationError(
    'RADAR_CODE_REVISION must be a lowercase 40- or 64-character Git object ID',
  );
}
if (production && (refreshOnStartup || refreshIntervalMinutes !== 0)) {
  throw configurationError(
    'REFRESH_ON_STARTUP and REFRESH_MINUTES must disable automatic refresh',
  );
}
if (githubGraphqlRetryMaxMs < githubGraphqlRetryBaseMs) {
  throw configurationError(
    'GITHUB_GRAPHQL_RETRY_MAX_MS must be greater than or equal to ' +
    'GITHUB_GRAPHQL_RETRY_BASE_MS',
  );
}
if (githubGraphqlCooldownMaxMs < githubGraphqlCooldownBaseMs) {
  throw configurationError(
    'GITHUB_GRAPHQL_COOLDOWN_MAX_MS must be greater than or equal to ' +
    'GITHUB_GRAPHQL_COOLDOWN_BASE_MS',
  );
}
if (openaiRetryMaxMs < openaiRetryBaseMs) {
  throw configurationError(
    'OPENAI_RETRY_MAX_MS must be greater than or equal to OPENAI_RETRY_BASE_MS',
  );
}

if (production) {
  process.env.DB_PATH = databasePath;
  process.env.PORT = String(serverPort);
  process.env.REFRESH_ON_STARTUP = 'false';
  process.env.REFRESH_MINUTES = '0';
  process.env.RADAR_CODE_REVISION = releaseRevision!;
  delete process.env.CODE_REVISION;
  delete process.env.GITHUB_SHA;
  delete process.env.RENDER_GIT_COMMIT;
  delete process.env.VERCEL_GIT_COMMIT_SHA;
  delete process.env.CF_PAGES_COMMIT_SHA;
  delete process.env.SOURCE_VERSION;
  delete process.env.DOTENV_CONFIG_PATH;
  delete process.env.DOTENV_CONFIG_OVERRIDE;
}

export const config = {
  runtime: {
    mode: production ? 'production' : 'development',
    releaseRevision,
    applicationRootPath,
    configurationSource: {
      kind: configurationSource.kind,
      path: configurationSource.path,
      realPath: configurationSource.realPath,
    },
  },
  github: {
    owner: env('GITHUB_OWNER', 'openclaw'),
    repo: env('GITHUB_REPO', 'openclaw'),
    repositoryNodeId: optional('GITHUB_REPOSITORY_NODE_ID'),
    token: value('GITHUB_TOKEN') || value('GITHUB_PERSONAL_ACCESS_TOKEN') || '',
    graphql: {
      concurrency: intInRange('GITHUB_GRAPHQL_CONCURRENCY', 2, 1, 20),
      minStartSpacingMs: intInRange(
        'GITHUB_GRAPHQL_MIN_START_SPACING_MS',
        250,
        0,
        60_000,
      ),
      retryBaseMs: githubGraphqlRetryBaseMs,
      retryMaxMs: githubGraphqlRetryMaxMs,
      cooldownBaseMs: githubGraphqlCooldownBaseMs,
      cooldownMaxMs: githubGraphqlCooldownMaxMs,
    },
  },
  openai: {
    apiKey: value('OPENAI_API_KEY') || value('OC_OPENAI_API_KEY') || '',
    model: env('OPENAI_MODEL', 'gpt-5.5'),
    reasoningEffort: choice(
      'OPENAI_REASONING_EFFORT',
      'medium',
      ['none', 'minimal', 'low', 'medium', 'high', 'xhigh'] as const,
    ),
    serviceTier: choice(
      'OPENAI_SERVICE_TIER',
      'priority',
      ['auto', 'default', 'flex', 'priority'] as const,
    ),
    requestTimeoutMs: intInRange(
      'OPENAI_REQUEST_TIMEOUT_MS',
      300_000,
      1_000,
      900_000,
    ),
    maxAttempts: intInRange('OPENAI_MAX_ATTEMPTS', 5, 1, 10),
    retryBaseMs: openaiRetryBaseMs,
    retryMaxMs: openaiRetryMaxMs,
  },
  server: {
    port: serverPort,
  },
  db: {
    path: databasePath,
  },
  labelAuthority: {
    approvedRosterPath: optional('LABEL_AUTHORITY_APPROVED_ROSTER_PATH'),
    approvedRosterKeyringPath: optional('LABEL_AUTHORITY_APPROVED_ROSTER_KEYRING_PATH'),
    approvedRosterStatePath: optional('LABEL_AUTHORITY_APPROVED_ROSTER_STATE_PATH'),
  },
  refresh: {
    // Set both to false/0 while calibrating so the web UI never overlaps a
    // manual evidence refresh with another DB-writing job.
    onStartup: refreshOnStartup,
    intervalMinutes: refreshIntervalMinutes,
    fullIssueBackfill: bool('FULL_ISSUE_BACKFILL', false),
    maxIssuePages: intInRange('MAX_ISSUE_PAGES', 4_096, 1, 100_000),
    issuePageSize: intInRange('GITHUB_ISSUE_PAGE_SIZE', 25, 1, 100),
    issueCatalogSnapshotMaxAgeHours: intInRange(
      'ISSUE_CATALOG_SNAPSHOT_MAX_AGE_HOURS',
      24,
      1,
      168,
    ),
    classifyConcurrency: intInRange('CLASSIFY_CONCURRENCY', 5, 1, 100),
    githubPageDelayMs: intInRange(
      'GITHUB_GRAPHQL_PAGE_DELAY_MS',
      0,
      0,
      60_000,
    ),
    releaseNetworkConcurrency: intInRange(
      'RELEASE_NETWORK_CONCURRENCY',
      4,
      1,
      10,
    ),
    closureEvidenceConcurrency: intInRange(
      'CLOSURE_EVIDENCE_CONCURRENCY',
      3,
      1,
      10,
    ),
    closureProofConcurrency: intInRange(
      'CLOSURE_PROOF_CONCURRENCY',
      4,
      1,
      10,
    ),
    gitReachabilityConcurrency: intInRange(
      'GIT_REACHABILITY_CONCURRENCY',
      16,
      1,
      64,
    ),
    gitCacheMaxPacks: intInRange('GIT_CACHE_MAX_PACKS', 64, 2, 10_000),
    gitCacheMaxSizeMiB: intInRange(
      'GIT_CACHE_MAX_SIZE_MIB',
      2_048,
      16,
      1_048_576,
    ),
    gitCacheMaintenanceTimeoutMs: intInRange(
      'GIT_CACHE_MAINTENANCE_TIMEOUT_MS',
      300_000,
      1_000,
      3_600_000,
    ),
    openPullRequestRefreshMinutes: intInRange(
      'OPEN_PR_REFRESH_MINUTES',
      15,
      1,
      1_440,
    ),
    closedPullRequestRefreshMinutes: intInRange(
      'CLOSED_PR_REFRESH_MINUTES',
      1_440,
      15,
      10_080,
    ),
  },
  comparison: {
    apiEnabled: bool('COMPARISON_API_ENABLED', false),
  },
  limits: {
    releases: intInRange('RELEASES_LIMIT', 10, 1, 100),
  },
} as const;

export const effectiveConfigAttestation = {
  schemaVersion: 1,
  mode: config.runtime.mode,
  source: {
    kind: config.runtime.configurationSource.kind,
    path: config.runtime.configurationSource.path,
    realPath: config.runtime.configurationSource.realPath,
  },
  database: {
    path: production ? config.db.path : resolve(config.db.path),
  },
  refresh: {
    onStartup: config.refresh.onStartup,
    intervalMinutes: config.refresh.intervalMinutes,
  },
  release: {
    revision: config.runtime.releaseRevision,
  },
} as const;

export function serializeEffectiveConfigAttestation(): string {
  return JSON.stringify(effectiveConfigAttestation);
}
