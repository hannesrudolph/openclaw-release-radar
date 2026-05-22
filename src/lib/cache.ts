// Simple in-memory cache for /api/public.
// Separated into its own module to avoid a circular import between api.ts ↔ refresh.ts.

const CACHE_TTL_MS = 35 * 60 * 1000; // 35 min — slightly longer than the 30 min cron

let cached: { data: object; builtAt: number } | null = null;

export function getCached(): object | null {
  if (!cached) return null;
  if (Date.now() - cached.builtAt > CACHE_TTL_MS) return null;
  return cached.data;
}

export function setCached(data: object): void {
  cached = { data, builtAt: Date.now() };
}

export function invalidateCache(): void {
  cached = null;
}
