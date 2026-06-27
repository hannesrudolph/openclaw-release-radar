export function releaseLabelCutoff(rel: {
  published_at: string | null;
  hours_to_next_stable: number | null;
}): string | null {
  if (!rel.published_at || rel.hours_to_next_stable == null) return null;
  const publishedAt = Date.parse(rel.published_at);
  if (!Number.isFinite(publishedAt)) return null;
  return new Date(publishedAt + rel.hours_to_next_stable * 3_600_000).toISOString();
}
