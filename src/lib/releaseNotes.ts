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

// Aggregate breaking-count across a stable's preceding beta chain.
//
// Background: a beta can introduce a breaking change (e.g. removing a channel
// adapter) that its body documents under `### Breaking`. The stable that ships
// AFTER that beta inherits the breakage — anyone installing the stable hits the
// same incompatibility. But the stable's own body usually doesn't repeat the
// `### Breaking` section verbatim, so its own `breakingCount` is 0.
//
// This function sums the breakingCount of all prereleases sitting between THIS
// stable and the previous stable in the same release lineage, plus the stable's
// own breakingCount. Result: "how many breaking-change bullets will a user
// installing THIS release encounter, including those rolled in via betas".
//
// For a prerelease target the function returns just its own breakingCount —
// we don't attempt to track breakage that propagates further back than the
// previous stable boundary (that's a different question, "delta since
// last stable" vs "what's in the chain up to this point").
export function computeAggregateBreaking(
  allReleasesDescByDate: Array<{
    tag: string;
    published_at: string | null;
    prerelease: boolean;
    breakingCount: number;
  }>,
  targetTag: string,
): number {
  const idx = allReleasesDescByDate.findIndex((r) => r.tag === targetTag);
  if (idx === -1) return 0;
  const target = allReleasesDescByDate[idx];
  // Prerelease: just its own count. Nothing to aggregate forward.
  if (target.prerelease) return target.breakingCount;

  let total = target.breakingCount;
  // Walk older entries; stop at the next stable.
  for (let i = idx + 1; i < allReleasesDescByDate.length; i++) {
    const r = allReleasesDescByDate[i];
    if (!r.prerelease) break;
    total += r.breakingCount;
  }
  return total;
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

// Hours from a STABLE release to the next newer STABLE release, ignoring any
// prereleases in between. This is the right "how long did this stay the current
// version users install?" signal — a beta of the NEXT version dropping soon after
// a stable is forward development, not a reaction to the stable. Returns null for
// the newest stable (no successor) or when timestamps are missing.
//
// Contrast with computeHoursToNextRelease (next-of-any-kind): for v2026.5.19 that
// returns ~3.8h (the next *beta*), wildly understating how long 5.19 actually
// stood as the current stable (~24h until 5.20). The install decision needs the
// stable-to-stable gap.
export function computeHoursToNextStable(
  allReleasesDescByDate: Array<{ tag: string; published_at: string | null; prerelease: boolean }>,
  targetTag: string,
): number | null {
  const idx = allReleasesDescByDate.findIndex((r) => r.tag === targetTag);
  if (idx === -1) return null;
  const target = allReleasesDescByDate[idx];
  if (!target.published_at) return null;
  const tMs = Date.parse(target.published_at);
  if (!Number.isFinite(tMs)) return null;
  // Walk toward newer entries; first stable with a strictly-greater timestamp wins.
  for (let i = idx - 1; i >= 0; i--) {
    const r = allReleasesDescByDate[i];
    if (r.prerelease || !r.published_at) continue;
    const nMs = Date.parse(r.published_at);
    if (Number.isFinite(nMs) && nMs > tMs) return (nMs - tMs) / 3_600_000;
  }
  return null; // no newer stable in the window (this is the latest stable)
}

// True if some release tag is a `<tag>-N` patch of `targetTag` — openclaw's hotfix
// convention (v2026.5.3 -> v2026.5.3-1). An unambiguous "this stable was hotfixed".
export function hasHotfixSuccessor(allTags: string[], targetTag: string): boolean {
  const re = new RegExp(`^${targetTag.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-\\d+$`);
  return allTags.some((t) => re.test(t));
}
