// Pure parser over a GitHub release body. Extracts maintainer-signal counts
// directly from the markdown structure that openclaw uses for every release:
//
//   ## <version>
//
//   ### Breaking      (optional, present when API/config shape changed)
//   - bullet
//
//   ### Changes
//   - bullet (may contain `(#12345)` PR ref)
//
//   ### Fixes
//   - bullet
//
//   ### Highlights    (occasional)
//   - bullet
//
// These section counts are an objective signal from the team itself — distinct
// from the user-complaint signal we get out of issues. No LLM involved; if the
// project ever changes section vocabulary the counts simply become zero and the
// rest of the radar keeps working.

export interface ReleaseNotesStats {
  breakingCount: number;
  fixesCount: number;
  changesCount: number;
  highlightsCount: number;
  // Distinct `#NNNNN` PR references mentioned anywhere in the body. Deduped so
  // a single PR mentioned in two bullets counts once.
  prRefsCount: number;
}

const EMPTY: ReleaseNotesStats = {
  breakingCount: 0,
  fixesCount: 0,
  changesCount: 0,
  highlightsCount: 0,
  prRefsCount: 0,
};

// A bullet line: leading `- ` after optional indentation. We intentionally
// don't try to count nested sub-bullets (`  - ...`) — those modify the parent
// thought rather than being independent items.
const BULLET_LINE = /^- /;
// Section heading: h3 (### …) OR h4 (#### …). h4 is used when a release wraps
// everything in an h3 container like "### Detailed 2026.5.18 Changes" and then
// the real fix/change buckets live under "#### Fixes" / "#### Changes". Both
// levels feed the same bucket — there's no useful semantic difference between
// "### Fixes" and "#### Fixes" for counting bullets.
const SECTION_LINE = /^#{3,4}\s+(.+?)\s*$/;
// `#1` is too common as a false positive (e.g. "#1 priority"). Require at
// least 2 digits — openclaw PR numbers are ≥5 digits anyway.
const PR_REF = /#(\d{2,})\b/g;

export function parseReleaseNotes(body: string | null | undefined): ReleaseNotesStats {
  if (!body) return { ...EMPTY };

  const lines = body.split(/\r?\n/);
  const counts: Record<string, number> = {};
  let currentSection: string | null = null;

  for (const line of lines) {
    const sectionMatch = line.match(SECTION_LINE);
    if (sectionMatch) {
      currentSection = sectionMatch[1].trim().toLowerCase();
      counts[currentSection] = counts[currentSection] ?? 0;
      continue;
    }
    if (currentSection && BULLET_LINE.test(line)) {
      counts[currentSection]++;
    }
  }

  const prRefs = new Set<string>();
  for (const match of body.matchAll(PR_REF)) prRefs.add(match[1]);

  return {
    breakingCount:   counts['breaking']   ?? 0,
    fixesCount:      counts['fixes']      ?? 0,
    changesCount:    counts['changes']    ?? 0,
    highlightsCount: counts['highlights'] ?? 0,
    prRefsCount:     prRefs.size,
  };
}

// Count how many prereleases sit between a stable release and the previous
// stable release in the same major.minor band. A high number means the team
// shook the release out through many betas before promoting; a low number
// means the stable went out quickly (less external bake time).
//
// Input: full release list sorted by published_at DESC, including prereleases.
// For each stable, we look at the prereleases whose published_at falls between
// THIS stable and the next-older stable (exclusive of both ends).
export function computeBetaCount(
  allReleasesDescByDate: Array<{ tag: string; published_at: string | null; prerelease: boolean }>,
  targetTag: string,
): number {
  const idx = allReleasesDescByDate.findIndex((r) => r.tag === targetTag);
  if (idx === -1) return 0;
  const target = allReleasesDescByDate[idx];
  if (target.prerelease || !target.published_at) return 0;

  const targetMs = Date.parse(target.published_at);
  if (!Number.isFinite(targetMs)) return 0;

  // Walk DOWN the list (older entries) until the next stable, counting prereleases on the way.
  let count = 0;
  for (let i = idx + 1; i < allReleasesDescByDate.length; i++) {
    const r = allReleasesDescByDate[i];
    if (!r.published_at) continue;
    if (!r.prerelease) break;
    const rMs = Date.parse(r.published_at);
    if (Number.isFinite(rMs) && rMs < targetMs) count++;
  }
  return count;
}

// Hours from a release's publish time to the NEXT (newer) release in the list.
// Useful as a hotfix signal: if 2026.5.4 was superseded by 2026.5.5 four hours
// later, something probably broke in 5.4. Returns null for the latest release
// (no successor yet) or when timestamps are missing.
//
// "Next" here is the chronologically newer one of ANY kind — including a
// prerelease, since a hotfix beta also counts as "we needed to fix something."
export function computeHoursToNextRelease(
  allReleasesDescByDate: Array<{ tag: string; published_at: string | null }>,
  targetTag: string,
): number | null {
  const idx = allReleasesDescByDate.findIndex((r) => r.tag === targetTag);
  if (idx <= 0) return null; // not found, or this IS the newest (idx === 0)
  const target = allReleasesDescByDate[idx];
  const newer = allReleasesDescByDate[idx - 1];
  if (!target.published_at || !newer.published_at) return null;
  const tMs = Date.parse(target.published_at);
  const nMs = Date.parse(newer.published_at);
  if (!Number.isFinite(tMs) || !Number.isFinite(nMs)) return null;
  const hours = (nMs - tMs) / 3_600_000;
  return hours >= 0 ? hours : null;
}
