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

export const config = {
  github: {
    owner: env('GITHUB_OWNER', 'openclaw'),
    repo: env('GITHUB_REPO', 'openclaw'),
    token: process.env.GITHUB_TOKEN || '',
  },
  openai: {
    apiKey: process.env.OPENAI_API_KEY || '',
    model: env('OPENAI_MODEL', 'gpt-4o-mini'),
  },
  server: {
    port: num('PORT', 8787),
  },
  db: {
    path: env('DB_PATH', './data/radar.db'),
  },
  cron: {
    schedule: env('REFRESH_CRON', '*/20 * * * *'),
  },
  limits: {
    issues: num('ISSUES_LIMIT', 80),
    releases: num('RELEASES_LIMIT', 10),
  },
  // If set, POST /api/refresh requires X-Admin-Token header.
  adminToken: process.env.ADMIN_TOKEN || '',
} as const;
