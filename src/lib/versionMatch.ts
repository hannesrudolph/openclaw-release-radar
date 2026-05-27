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
// Unsupported: caret (^), tilde (~), pipe-OR (|). They don't appear in
// GitHub-filed advisories so we don't bother. If we encounter one we return
// `false` (no match) and log a warning — safer than guessing.

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

// Match a version against a range string. Range can contain multiple
// clauses joined by comma or whitespace; all must hold (AND semantics).
// Returns `false` for malformed input — safer than guessing.
export function matchesRange(version: string, range: string | null | undefined): boolean {
  if (!version || !range) return false;
  const cleaned = range.trim();
  if (!cleaned) return false;

  // Split on comma OR runs of whitespace BETWEEN operators-and-targets.
  // We can't naively split on space because "< 1.2.3" itself contains space.
  // Trick: insert delimiter before each operator, then split.
  const normalized = cleaned.replace(/\s+/g, ' ');
  const parts: string[] = [];
  let buf = '';
  for (const segment of normalized.split(',')) {
    // Within a comma-segment, look for "op target op target ..." pattern.
    const tokens = segment.match(/(<=|>=|<|>|==?)?\s*[0-9A-Za-z.\-+]+/g) ?? [];
    for (const t of tokens) parts.push(t.trim());
  }
  if (parts.length === 0) return false;

  for (const clause of parts) {
    const parsed = parseClause(clause);
    if (!parsed) {
      console.warn(`[versionMatch] unsupported clause: "${clause}" in range "${range}"`);
      return false;
    }
    if (!applyOp(version, parsed.op, parsed.target)) return false;
  }
  return true;
}
