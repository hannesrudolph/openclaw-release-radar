// Version-range matcher for GitHub Security Advisory `vulnerable_version_range`
// and `patched_versions` strings.
//
// GitHub stores these as free-text but maintainers follow a small set of
// patterns. We support the common ones — semver-ish ranges with comparison
// operators. Numeric components are compared component-wise (so this works
// equally well for SemVer "2.5.0" and CalVer "2026.5.20").
//
// Supported syntaxes:
//   "1.2.3"              → exact match
//   "< 1.2.3"            → strictly less
//   "<= 1.2.3"           → less or equal
//   "> 1.2.3"            → strictly greater
//   ">= 1.2.3"           → greater or equal
//   ">= 1.0.0, < 2.0.0"  → comma-separated AND  (both must hold)
//   ">= 1.0.0 < 2.0.0"   → space-separated AND  (GitHub uses this form too)
//
// Unsupported: caret (^), tilde (~), pipe-OR (|). These must not be silently
// treated as non-matches by score writers because that could hide CVE exposure.

export type CompareResult = -1 | 0 | 1;

// Compare two version strings component-wise. Non-numeric suffixes like
// "-beta.1" are extracted and compared lexicographically AFTER numeric parts.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
export function compareVersions(a: string, b: string): CompareResult {
  const splitToParts = (s: string): { nums: number[]; pre: string } => {
    const stripped = s.trim().replace(/^v/i, '');
    const dashIdx = stripped.indexOf('-');
    const numericPart = dashIdx === -1 ? stripped : stripped.slice(0, dashIdx);
    const pre = dashIdx === -1 ? '' : stripped.slice(dashIdx + 1);
    const nums = numericPart.split('.').map((p) => {
      const n = parseInt(p, 10);
      return Number.isFinite(n) ? n : 0;
    });
    return { nums, pre };
  };

  const pa = splitToParts(a);
  const pb = splitToParts(b);
  const maxLen = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < maxLen; i++) {
    const av = pa.nums[i] ?? 0;
    const bv = pb.nums[i] ?? 0;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  // SemVer rule: a version with a prerelease tag is LOWER than one without.
  if (pa.pre && !pb.pre) return -1;
  if (!pa.pre && pb.pre) return 1;
  if (pa.pre < pb.pre) return -1;
  if (pa.pre > pb.pre) return 1;
  return 0;
}

// Apply a single comparison operator. Returns whether `version` satisfies it.
function applyOp(version: string, op: string, target: string): boolean {
  const cmp = compareVersions(version, target);
  switch (op) {
    case '<':  return cmp < 0;
    case '<=': return cmp <= 0;
    case '>':  return cmp > 0;
    case '>=': return cmp >= 0;
    case '=':
    case '==': return cmp === 0;
    default:   return false;
  }
}

// Parse one clause like "< 1.2.3" or "1.2.3" (no operator = exact match).
// Returns null if the clause is malformed.
function parseClause(raw: string): { op: string; target: string } | null {
  const m = raw.trim().match(/^(<=|>=|<|>|==?)?\s*([0-9A-Za-z.\-+]+)$/);
  if (!m) return null;
  return { op: m[1] ?? '=', target: m[2] };
}

function rangeClauses(range: string | null | undefined): { clauses: string[]; error: string | null } {
  if (!range) return { clauses: [], error: null };
  const cleaned = range.trim();
  if (!cleaned) return { clauses: [], error: null };
  const clauses: string[] = [];
  for (const segment of cleaned.replace(/\s+/g, ' ').split(',')) {
    const text = segment.trim();
    if (!text) continue;
    const matches = [...text.matchAll(/(<=|>=|<|>|==?)?\s*[0-9A-Za-z.\-+]+/g)];
    if (matches.length === 0) return { clauses: [], error: `unsupported range segment "${text}"` };
    let cursor = 0;
    for (const match of matches) {
      const start = match.index ?? 0;
      if (text.slice(cursor, start).trim() !== '') {
        return { clauses: [], error: `unsupported range syntax near "${text.slice(cursor, start).trim()}"` };
      }
      clauses.push(match[0].trim());
      cursor = start + match[0].length;
    }
    if (text.slice(cursor).trim() !== '') {
      return { clauses: [], error: `unsupported range syntax near "${text.slice(cursor).trim()}"` };
    }
  }
  for (const clause of clauses) {
    if (!parseClause(clause)) return { clauses: [], error: `unsupported clause "${clause}"` };
  }
  return { clauses, error: null };
}

export function isRangeParseable(range: string | null | undefined): boolean {
  const parsed = rangeClauses(range);
  return parsed.error == null && parsed.clauses.length > 0;
}

// Extract the FIRST version that shipped a fix, from a GHSA `patched_versions`
// string. Examples:
//   "2026.4.23"             → "2026.4.23"
//   ">= 2026.4.14"          → "2026.4.14"
//   ">= 2026.4.10 < 2026.5" → "2026.4.10"
// Returns null when nothing parseable is found.
export function firstPatchedVersion(patched: string | null | undefined): string | null {
  if (!patched) return null;
  const v = patched.trim();
  if (!v) return null;
  if (!/[<>=]/.test(v)) return v;                    // bare version, no operators
  const ge = v.match(/>=\s*([0-9A-Za-z.\-+]+)/);     // earliest version with the fix
  if (ge) return ge[1];
  return v.match(/([0-9][0-9A-Za-z.\-+]*)/)?.[1] ?? null;
}

// Number of STABLE releases strictly between `version` and the version that
// patched a vulnerability — i.e. how many releases sit closer to the fix than this
// one. Returns 0 when `version` is the newest still-affected release, or when the
// patch string can't be parsed (conservative: treat as "right here", full weight).
// Used to decay CVE blame backward from each patch (see score.cveDecayLoad).
export function stableDistance(
  version: string,
  patchedVersions: string | null | undefined,
  stableTagsNewestFirst: string[],
): number {
  const patch = firstPatchedVersion(patchedVersions);
  if (!patch) return 0;
  let d = 0;
  for (const s of stableTagsNewestFirst) {
    if (compareVersions(version, s) < 0 && compareVersions(s, patch) < 0) d++;
  }
  return d;
}

// Match a version against a range string. Range can contain multiple
// clauses joined by comma or whitespace; all must hold (AND semantics).
// Returns `false` for malformed input — safer than guessing.
export function matchesRange(version: string, range: string | null | undefined): boolean {
  if (!version || !range) return false;
  const { clauses, error } = rangeClauses(range);
  if (error) {
    console.warn(`[versionMatch] unsupported range: ${error} in "${range}"`);
    return false;
  }
  if (clauses.length === 0) return false;

  for (const clause of clauses) {
    const parsed = parseClause(clause);
    if (!parsed) {
      console.warn(`[versionMatch] unsupported clause: "${clause}" in range "${range}"`);
      return false;
    }
    if (!applyOp(version, parsed.op, parsed.target)) return false;
  }
  return true;
}
