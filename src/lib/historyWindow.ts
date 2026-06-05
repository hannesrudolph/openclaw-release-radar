// Depth of the score-history chart only — how many past points the trend line
// plots. Independent of RELEASES_LIMIT (the main list cap) and deliberately wider
// than the monitored window: points beyond RELEASES_LIMIT are frozen rows from
// earlier runs, shown as comparative trend context. It does NOT widen the
// expensive refresh/classification window — see refresh.ts for why that stays at
// RELEASES_LIMIT.
export const SCORE_HISTORY_CHART_LIMIT = 20;
