export function releaseLabelCutoff(rel: {
  published_at: string | null;
  hours_to_next_stable: number | null;
}, now?: number | string | null): string | null {
  if (!rel.published_at) return null;
  if (rel.hours_to_next_stable == null) {
    const millis = typeof now === 'string' ? Date.parse(now) : typeof now === 'number' ? now : NaN;
    return Number.isFinite(millis) ? new Date(millis).toISOString() : null;
  }
  const publishedAt = Date.parse(rel.published_at);
  if (!Number.isFinite(publishedAt)) return null;
  return new Date(publishedAt + rel.hours_to_next_stable * 3_600_000).toISOString();
}
