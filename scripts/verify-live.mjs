import { fileURLToPath } from 'node:url';
import { resolve } from 'node:path';

const REQUIRED_READINESS_CHECKS = [
  'closureProof',
  'database',
  'ingestion',
  'recommendation',
  'releaseWindow',
  'scoreAudit',
  'sourceIdentity',
];
const LIVE_PAYLOAD_KEYS = ['ok', 'repo', 'status'];
const HEALTH_PAYLOAD_KEYS = [
  'checkedAt',
  'checks',
  'currentRelease',
  'failures',
  'ok',
  'repo',
  'schemaVersion',
  'status',
];
const CURRENT_RELEASE_KEYS = [
  'diagnosticPreviouslyRecommended',
  'diagnosticScoredAt',
  'diagnosticStatus',
  'publishedAt',
  'tag',
];
const SCORE_STATUSES = new Set(['wait', 'skip-cve', 'skip-hotfix', 'eligible']);
const EXPLICIT_LOOPBACK_HOSTS = new Set(['127.0.0.1', '::1', 'localhost']);

export async function verifyLiveEndpoints({
  apiBase,
  fetchImpl = fetch,
  expectedRepository = `${process.env.GITHUB_OWNER ?? 'openclaw'}/${process.env.GITHUB_REPO ?? 'openclaw'}`,
  expectedCurrentReleaseTag = null,
} = {}) {
  const base = normalizeApiBase(
    apiBase ?? process.env.API_BASE ?? 'http://127.0.0.1:8787',
  );
  requireRepository(expectedRepository, 'expected repository');
  const liveResponse = await fetchEndpoint(fetchImpl, `${base}/api/live`);
  if (liveResponse.status !== 200) {
    throw new Error(`/api/live returned HTTP ${liveResponse.status}`);
  }
  const livePayload = await responseJson(liveResponse, '/api/live');
  requireObjectKeys(livePayload, LIVE_PAYLOAD_KEYS, '/api/live');
  if (livePayload.ok !== true) {
    throw new Error(`/api/live ok must equal true, got ${JSON.stringify(livePayload.ok)}`);
  }
  if (livePayload?.status !== 'live') {
    throw new Error(`/api/live status must equal live, got ${JSON.stringify(livePayload?.status)}`);
  }
  if (livePayload.repo !== expectedRepository) {
    throw new Error(
      `/api/live repo must equal ${expectedRepository}, got ${JSON.stringify(livePayload.repo)}`,
    );
  }

  const healthResponse = await fetchEndpoint(fetchImpl, `${base}/api/health`);
  if (healthResponse.status !== 200) {
    throw new Error(`/api/health returned HTTP ${healthResponse.status}`);
  }
  const healthPayload = await responseJson(healthResponse, '/api/health');
  if (healthPayload?.status !== 'ready') {
    throw new Error(
      `/api/health status must equal ready, got ${JSON.stringify(healthPayload?.status)}`,
    );
  }
  requireObjectKeys(healthPayload, HEALTH_PAYLOAD_KEYS, '/api/health');
  if (healthPayload.schemaVersion !== 1) {
    throw new Error(
      `/api/health schemaVersion must equal 1, got ${JSON.stringify(healthPayload.schemaVersion)}`,
    );
  }
  if (healthPayload.ok !== true) {
    throw new Error(`/api/health ok must equal true, got ${JSON.stringify(healthPayload.ok)}`);
  }
  if (!isTimestamp(healthPayload.checkedAt)) {
    throw new Error('/api/health checkedAt must be a valid timestamp');
  }
  if (healthPayload.repo !== expectedRepository || healthPayload.repo !== livePayload.repo) {
    throw new Error(
      `/api/health repo must equal ${expectedRepository} and /api/live repo, got ` +
      `${JSON.stringify(healthPayload.repo)}`,
    );
  }
  verifyCurrentRelease(healthPayload.currentRelease, expectedCurrentReleaseTag);
  if (!Array.isArray(healthPayload.failures) || healthPayload.failures.length !== 0) {
    throw new Error(
      `/api/health failures must be an empty array, got ` +
      `${Array.isArray(healthPayload.failures) ? healthPayload.failures.length : 'non-array'}`,
    );
  }
  requireExactObjectKeys(healthPayload.checks, REQUIRED_READINESS_CHECKS, '/api/health checks');
  const failedChecks = REQUIRED_READINESS_CHECKS.filter(
    (name) => !isPlainObject(healthPayload.checks[name]) ||
      healthPayload.checks[name].ok !== true,
  );
  if (failedChecks.length > 0) {
    throw new Error(`/api/health checks are not all ok: ${failedChecks.join(', ')}`);
  }

  return {
    apiBase: base,
    live: livePayload,
    health: healthPayload,
  };
}

export function normalizeApiBase(value) {
  const raw = String(value);
  if (!raw || raw.trim() !== raw) {
    throw new Error('API base must be a non-empty URL without surrounding whitespace');
  }

  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw new Error(`API base is not a valid absolute URL: ${raw}`);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) {
    throw new Error(`API base must use HTTP or HTTPS, got ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error('API base must not contain credentials, a query, or a fragment');
  }

  const hostname = parsed.hostname
    .toLowerCase()
    .replace(/^\[(.*)\]$/, '$1');
  if (
    parsed.protocol === 'http:' &&
    !EXPLICIT_LOOPBACK_HOSTS.has(hostname)
  ) {
    throw new Error(
      `API base must use HTTPS unless it targets explicit loopback, got ${raw}`,
    );
  }

  const pathname = parsed.pathname.replace(/\/+$/, '');
  return `${parsed.origin}${pathname === '/' ? '' : pathname}`;
}

async function fetchEndpoint(fetchImpl, url) {
  return fetchImpl(url, {
    headers: { accept: 'application/json' },
  });
}

async function responseJson(response, path) {
  let payload;
  try {
    payload = await response.json();
  } catch {
    throw new Error(`${path} did not return valid JSON`);
  }
  return payload;
}

function verifyCurrentRelease(currentRelease, expectedTag) {
  requireObjectKeys(currentRelease, CURRENT_RELEASE_KEYS, '/api/health currentRelease');
  if (typeof currentRelease.tag !== 'string' || currentRelease.tag.trim() !== currentRelease.tag ||
      currentRelease.tag.length === 0) {
    throw new Error('/api/health currentRelease.tag must be a non-empty string');
  }
  if (expectedTag != null && currentRelease.tag !== expectedTag) {
    throw new Error(
      `/api/health currentRelease.tag must equal ${expectedTag}, got ` +
      `${JSON.stringify(currentRelease.tag)}`,
    );
  }
  if (!isTimestamp(currentRelease.publishedAt)) {
    throw new Error('/api/health currentRelease.publishedAt must be a valid timestamp');
  }
  if (!isTimestamp(currentRelease.diagnosticScoredAt)) {
    throw new Error('/api/health currentRelease.diagnosticScoredAt must be a valid timestamp');
  }
  if (!SCORE_STATUSES.has(currentRelease.diagnosticStatus)) {
    throw new Error(
      `/api/health currentRelease.diagnosticStatus is invalid: ` +
      `${JSON.stringify(currentRelease.diagnosticStatus)}`,
    );
  }
  if (typeof currentRelease.diagnosticPreviouslyRecommended !== 'boolean') {
    throw new Error(
      '/api/health currentRelease.diagnosticPreviouslyRecommended must be boolean',
    );
  }
}

function requireObjectKeys(value, requiredKeys, label) {
  if (!isPlainObject(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  const missingKeys = requiredKeys.filter((key) => !Object.prototype.hasOwnProperty.call(value, key));
  if (missingKeys.length > 0) {
    throw new Error(`${label} must include keys: ${missingKeys.join(', ')}`);
  }
}

function requireExactObjectKeys(value, expectedKeys, label) {
  if (!isPlainObject(value)) {
    throw new Error(`${label} must be a JSON object`);
  }
  const actualKeys = Object.keys(value).sort();
  const sortedExpectedKeys = [...expectedKeys].sort();
  if (JSON.stringify(actualKeys) !== JSON.stringify(sortedExpectedKeys)) {
    throw new Error(
      `${label} keys must equal ${sortedExpectedKeys.join(', ')}, got ` +
      `${actualKeys.join(', ') || 'none'}`,
    );
  }
}

function requireRepository(value, label) {
  if (typeof value !== 'string' || !/^[^/\s]+\/[^/\s]+$/.test(value)) {
    throw new Error(`${label} must use owner/name format`);
  }
}

function isPlainObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function isTimestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function parseArgs(argv) {
  const out = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (!['--api-base', '--repository', '--current-release'].includes(arg)) {
      throw new Error(`Unknown option: ${arg}`);
    }
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) throw new Error(`${arg} requires a value`);
    if (arg === '--api-base') out.apiBase = value;
    else if (arg === '--repository') out.expectedRepository = value;
    else out.expectedCurrentReleaseTag = value;
    index++;
  }
  return out;
}

async function main() {
  const result = await verifyLiveEndpoints(parseArgs(process.argv.slice(2)));
  console.log(
    `Live verification passed: ${result.apiBase}/api/live is live; ` +
    `${result.apiBase}/api/health is ready with all checks ok`,
  );
}

if (process.argv[1] && fileURLToPath(import.meta.url) === resolve(process.argv[1])) {
  main().catch((error) => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exitCode = 1;
  });
}
