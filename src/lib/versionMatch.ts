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

const VERSION_TOKEN_SOURCE =
  String.raw`[vV]?\d+(?:\.\d+)*(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?`;
const VERSION_TOKEN_RE = new RegExp(`^${VERSION_TOKEN_SOURCE}$`);
const RANGE_CLAUSE_RE = new RegExp(`(<=|>=|<|>|==?)?\\s*${VERSION_TOKEN_SOURCE}`, 'g');

type RangeOperator = '<' | '<=' | '>' | '>=' | '=' | '==';

interface ParsedVersion {
  nums: bigint[];
  prerelease: string[];
}

interface ParsedClause {
  op: RangeOperator;
  target: string;
  bare: boolean;
}

interface VersionBound {
  target: string;
  inclusive: boolean;
}

function parseVersionToken(raw: string): ParsedVersion | null {
  const token = raw.trim();
  if (!VERSION_TOKEN_RE.test(token)) return null;

  const stripped = token.replace(/^v/i, '');
  const withoutBuild = stripped.split('+', 1)[0];
  const dashIdx = withoutBuild.indexOf('-');
  const numericPart = dashIdx === -1 ? withoutBuild : withoutBuild.slice(0, dashIdx);
  const prerelease = dashIdx === -1 ? [] : withoutBuild.slice(dashIdx + 1).split('.');
  return {
    nums: numericPart.split('.').map((part) => BigInt(part)),
    prerelease,
  };
}

export function versionHasPrereleaseIdentifier(raw: string): boolean {
  return (parseVersionToken(raw)?.prerelease.length ?? 0) > 0;
}

function comparePrereleaseIdentifiers(left: string, right: string): CompareResult {
  const leftNumeric = /^\d+$/.test(left);
  const rightNumeric = /^\d+$/.test(right);
  if (leftNumeric && rightNumeric) {
    const leftValue = BigInt(left);
    const rightValue = BigInt(right);
    if (leftValue < rightValue) return -1;
    if (leftValue > rightValue) return 1;
    return 0;
  }
  if (leftNumeric !== rightNumeric) return leftNumeric ? -1 : 1;
  if (left < right) return -1;
  if (left > right) return 1;
  return 0;
}

// Compare two version strings component-wise. Prerelease identifiers follow
// SemVer precedence: numeric identifiers compare numerically, numeric identifiers
// sort before nonnumeric identifiers, and shorter equal prefixes sort first.
// Returns -1 if a < b, 0 if equal, 1 if a > b.
export function compareVersions(a: string, b: string): CompareResult {
  const pa = parseVersionToken(a);
  const pb = parseVersionToken(b);
  if (!pa) throw new Error(`Invalid version token "${a}"`);
  if (!pb) throw new Error(`Invalid version token "${b}"`);
  const maxLen = Math.max(pa.nums.length, pb.nums.length);
  for (let i = 0; i < maxLen; i++) {
    const av = pa.nums[i] ?? 0n;
    const bv = pb.nums[i] ?? 0n;
    if (av < bv) return -1;
    if (av > bv) return 1;
  }
  // SemVer rule: a version with a prerelease tag is LOWER than one without.
  if (pa.prerelease.length > 0 && pb.prerelease.length === 0) return -1;
  if (pa.prerelease.length === 0 && pb.prerelease.length > 0) return 1;
  const prereleaseLength = Math.max(pa.prerelease.length, pb.prerelease.length);
  for (let i = 0; i < prereleaseLength; i++) {
    const left = pa.prerelease[i];
    const right = pb.prerelease[i];
    if (left == null) return -1;
    if (right == null) return 1;
    const comparison = comparePrereleaseIdentifiers(left, right);
    if (comparison !== 0) return comparison;
  }
  return 0;
}

// Apply a single comparison operator. Returns whether `version` satisfies it.
function applyOp(version: string, op: RangeOperator, target: string): boolean {
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
function parseClause(raw: string): ParsedClause | null {
  const m = raw.trim().match(new RegExp(`^(<=|>=|<|>|==?)?\\s*(${VERSION_TOKEN_SOURCE})$`));
  if (!m) return null;
  return {
    op: (m[1] ?? '=') as RangeOperator,
    target: m[2],
    bare: m[1] == null,
  };
}

function tighterLowerBound(current: VersionBound | null, candidate: VersionBound): VersionBound {
  if (!current) return candidate;
  const comparison = compareVersions(candidate.target, current.target);
  if (comparison > 0) return candidate;
  if (comparison < 0) return current;
  return current.inclusive && !candidate.inclusive ? candidate : current;
}

function tighterUpperBound(current: VersionBound | null, candidate: VersionBound): VersionBound {
  if (!current) return candidate;
  const comparison = compareVersions(candidate.target, current.target);
  if (comparison < 0) return candidate;
  if (comparison > 0) return current;
  return current.inclusive && !candidate.inclusive ? candidate : current;
}

function impossibleRangeReason(clauses: ParsedClause[]): string | null {
  let exact: string | null = null;
  let lower: VersionBound | null = null;
  let upper: VersionBound | null = null;

  for (const clause of clauses) {
    if (clause.op === '=' || clause.op === '==') {
      if (exact != null && compareVersions(exact, clause.target) !== 0) {
        return `contradictory exact versions "${exact}" and "${clause.target}"`;
      }
      exact = clause.target;
    } else if (clause.op === '>' || clause.op === '>=') {
      lower = tighterLowerBound(lower, {
        target: clause.target,
        inclusive: clause.op === '>=',
      });
    } else {
      upper = tighterUpperBound(upper, {
        target: clause.target,
        inclusive: clause.op === '<=',
      });
    }
  }

  if (exact != null) {
    if (lower && !applyOp(exact, lower.inclusive ? '>=' : '>', lower.target)) {
      return `exact version "${exact}" contradicts the lower bound`;
    }
    if (upper && !applyOp(exact, upper.inclusive ? '<=' : '<', upper.target)) {
      return `exact version "${exact}" contradicts the upper bound`;
    }
    return null;
  }

  if (lower && upper) {
    const comparison = compareVersions(lower.target, upper.target);
    if (comparison > 0) return 'lower bound is greater than the upper bound';
    if (comparison === 0 && (!lower.inclusive || !upper.inclusive)) {
      return 'equal lower and upper bounds exclude every version';
    }
  }
  return null;
}

function parseRange(
  range: string | null | undefined,
): { clauses: ParsedClause[]; error: string | null } {
  if (!range) return { clauses: [], error: null };
  const cleaned = range.trim();
  if (!cleaned) return { clauses: [], error: null };
  const segments = cleaned.replace(/\s+/g, ' ').split(',');
  if (segments.some((segment) => segment.trim() === '')) {
    return { clauses: [], error: 'empty comma-separated range segment' };
  }

  const clauses: ParsedClause[] = [];
  for (const segment of segments) {
    const text = segment.trim();
    const matches = [...text.matchAll(RANGE_CLAUSE_RE)];
    if (matches.length === 0) return { clauses: [], error: `unsupported range segment "${text}"` };
    let cursor = 0;
    for (const match of matches) {
      const start = match.index ?? 0;
      if (text.slice(cursor, start).trim() !== '') {
        return { clauses: [], error: `unsupported range syntax near "${text.slice(cursor, start).trim()}"` };
      }
      const clause = parseClause(match[0]);
      if (!clause) return { clauses: [], error: `unsupported clause "${match[0].trim()}"` };
      clauses.push(clause);
      cursor = start + match[0].length;
    }
    if (text.slice(cursor).trim() !== '') {
      return { clauses: [], error: `unsupported range syntax near "${text.slice(cursor).trim()}"` };
    }
  }
  if (clauses.length > 1 && clauses.some((clause) => clause.bare)) {
    return { clauses: [], error: 'bare versions cannot be combined with other range clauses' };
  }
  const impossible = impossibleRangeReason(clauses);
  if (impossible) return { clauses: [], error: `range can never match: ${impossible}` };
  return { clauses, error: null };
}

export function rangeValidationError(range: string | null | undefined): string | null {
  const parsed = parseRange(range);
  if (parsed.error) return parsed.error;
  return parsed.clauses.length > 0 ? null : 'range is empty';
}

export function isRangeParseable(range: string | null | undefined): boolean {
  const parsed = parseRange(range);
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
  const parsed = parseRange(v);
  if (parsed.error || parsed.clauses.length === 0) return null;
  const exact = parsed.clauses.find((clause) => clause.op === '=' || clause.op === '==');
  if (exact) return exact.target;
  let lower: VersionBound | null = null;
  for (const clause of parsed.clauses) {
    if (clause.op !== '>' && clause.op !== '>=') continue;
    lower = tighterLowerBound(lower, {
      target: clause.target,
      inclusive: clause.op === '>=',
    });
  }
  return lower?.inclusive ? lower.target : null;
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
  if (!parseVersionToken(version)) {
    console.warn(`[versionMatch] invalid version token: "${version}"`);
    return false;
  }
  const { clauses, error } = parseRange(range);
  if (error) {
    console.warn(`[versionMatch] unsupported range: ${error} in "${range}"`);
    return false;
  }
  if (clauses.length === 0) return false;

  for (const clause of clauses) {
    if (!applyOp(version, clause.op, clause.target)) return false;
  }
  return true;
}
