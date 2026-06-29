import 'dotenv/config';

function env(key: string, fallback?: string): string {
  const v = process.env[key] ?? fallback;
  if (v === undefined) throw new Error(`Missing env var: ${key}`);
  return v;
}

function num(key: string, fallback: number): number {
  const raw = process.env[key];
  if (!raw) return fallback;
  const n = Number(raw);
  if (Number.isNaN(n)) throw new Error(`Invalid number for ${key}: ${raw}`);
  return n;
}

function intInRange(key: string, fallback: number, min: number, max: number): number {
  const n = num(key, fallback);
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new Error(`${key} must be an integer in [${min}, ${max}], got ${n}`);
  }
  return n;
}

function bool(key: string, fallback = false): boolean {
  const raw = process.env[key];
  if (raw == null || raw === '') return fallback;
  if (/^(1|true|yes|on)$/i.test(raw)) return true;
  if (/^(0|false|no|off)$/i.test(raw)) return false;
  throw new Error(`${key} must be true or false, got ${raw}`);
}

export const config = {
  github: {
    owner: env('GITHUB_OWNER', 'openclaw'),
    repo: env('GITHUB_REPO', 'openclaw'),
    token: process.env.GITHUB_TOKEN || process.env.GITHUB_PERSONAL_ACCESS_TOKEN || '',
  },
  openai: {
    apiKey: process.env.OPENAI_API_KEY || process.env.OC_OPENAI_API_KEY || '',
    model: env('OPENAI_MODEL', 'gpt-4o-mini'),
  },
  server: {
    port: num('PORT', 8787),
  },
  db: {
    path: env('DB_PATH', './data/radar.db'),
  },
  refresh: {
    // Set both to false/0 while calibrating so the web UI never overlaps a
    // manual evidence refresh with another DB-writing job.
    onStartup: bool('REFRESH_ON_STARTUP', false),
    intervalMinutes: intInRange('REFRESH_MINUTES', 30, 0, 600),
    fullIssueBackfill: process.env.FULL_ISSUE_BACKFILL === 'true',
    maxIssuePages: intInRange('MAX_ISSUE_PAGES', 500, 1, 500),
    classifyConcurrency: intInRange('CLASSIFY_CONCURRENCY', 5, 1, 50),
    githubPageDelayMs: intInRange('GITHUB_GRAPHQL_PAGE_DELAY_MS', 0, 0, 60_000),
  },
  comparison: {
    apiEnabled: bool('COMPARISON_API_ENABLED', false),
  },
  limits: {
    releases: num('RELEASES_LIMIT', 10),
  },
} as const;
