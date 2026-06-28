// Offline validation of the real scoring path against the real DB. This reads
// existing classifications/evidence only; it does not call GitHub or the LLM.
import { DatabaseSync } from 'node:sqlite';

const args = parseArgs(process.argv.slice(2));
const check = args.check !== false && args['print-only'] !== true;
const dbPath = process.env.DB_PATH ?? './data/radar.db';
process.env.RADAR_DB_READ_ONLY = '1';
const db = new DatabaseSync(dbPath, { readOnly: true });
db.exec('PRAGMA query_only = ON');
const { buildReleaseScoreRun, PROMPT_VERSION, SCORE_MODEL_VERSION } = await import('../src/lib/releaseScoring.ts');

const allRel = db.prepare(
  `SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`,
).all().map((r) => ({ tag: r.tag, published_at: r.published_at, prerelease: r.prerelease === 1 }));
const auditStmt = db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`);
const allFetchedTags = allRel.map((r) => r.tag);
const stableTagsNewestFirst = allRel.filter((r) => !r.prerelease).map((r) => r.tag);
const scoredStableCount = Number((db.prepare(`
  SELECT COUNT(*) AS count
  FROM releases
  WHERE prerelease=0 AND final_score IS NOT NULL
`).get()).count ?? 0);
const limit = args.all ? scoredStableCount : Number(args.limit ?? 10);

const failures = [];
verifyScoredReleaseCoverage(failures);
const { scored, recommendedTag } = buildReleaseScoreRun({
  releaseLimit: limit,
  allFetchedTags,
  stableTagsNewestFirst,
  nowForRelease: (rel) => scoredAtMillis(rel, auditStmt.get(rel.tag), failures),
});
const rows = scored.map((s) => {
  const audit = auditStmt.get(s.rel.tag);
  const recommended = s.rel.tag === recommendedTag;
  comparePersisted({ failures, result: s, audit, recommended });
  return {
    tag: s.rel.tag,
    score: s.conf.score == null ? '-' : s.conf.score,
    persisted: s.rel.final_score == null ? '-' : s.rel.final_score,
    band: s.conf.band,
    status: s.conf.status,
    rec: recommended ? '*' : '',
    reason: s.conf.reason,
  };
});

console.table(rows);
console.log(`\nRecommended: ${recommendedTag}`);

if (check && failures.length > 0) {
  console.error(`\nScore verification failed with ${failures.length} drift(s):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

if (check) console.log(`Score verification passed for ${scored.length} release(s).`);

function verifyScoredReleaseCoverage(failures) {
  const missingAudits = db.prepare(`
    SELECT r.tag
    FROM releases r
    LEFT JOIN release_score_audits a ON a.release_tag=r.tag
    WHERE r.prerelease=0
      AND r.final_score IS NOT NULL
      AND a.release_tag IS NULL
    ORDER BY r.published_at DESC
  `).all();
  for (const row of missingAudits) failures.push(`${row.tag}: scored stable release is missing release_score_audits row`);

  const orphanAudits = db.prepare(`
    SELECT a.release_tag
    FROM release_score_audits a
    LEFT JOIN releases r ON r.tag=a.release_tag
    WHERE r.tag IS NULL OR r.prerelease != 0
    ORDER BY a.release_tag
  `).all();
  for (const row of orphanAudits) failures.push(`${row.release_tag}: score audit points at missing or non-stable release`);

  const recommended = db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND final_score IS NOT NULL
      AND recommended=1
    ORDER BY published_at DESC
  `).all();
  if (scoredStableCount > 0 && recommended.length !== 1) {
    failures.push(`expected exactly one recommended scored stable release, found ${recommended.length}`);
  }
}

function comparePersisted({ failures, result, audit, recommended }) {
  const { rel, conf, input } = result;
  const tag = rel.tag;
  if (!audit) {
    failures.push(`${tag}: missing release_score_audits row`);
    return;
  }

  expectEqual(failures, tag, 'release final_score', rel.final_score, conf.score);
  expectEqual(failures, tag, 'audit final_score', audit.final_score, conf.score);
  expectEqual(failures, tag, 'audit score_model_version', audit.score_model_version, SCORE_MODEL_VERSION);
  expectEqual(failures, tag, 'audit prompt_version', Number(audit.prompt_version), PROMPT_VERSION);
  expectEqual(failures, tag, 'release state', rel.state, conf.status);
  expectEqual(failures, tag, 'audit status', audit.status, conf.status);
  expectEqual(failures, tag, 'audit band', audit.band, conf.band);
  expectEqual(failures, tag, 'release recommended', Number(rel.recommended ?? 0), recommended ? 1 : 0);
  expectEqual(failures, tag, 'audit recommended', Number(audit.recommended ?? 0), recommended ? 1 : 0);
  expectEqual(failures, tag, 'release reason', rel.score_reason, conf.reason);
  expectEqual(failures, tag, 'release scored_at', rel.scored_at, audit.scored_at);
  if (input.classifiedIssueCount > input.rawIssueCount) {
    failures.push(`${tag}: classifiedIssueCount (${input.classifiedIssueCount}) must not exceed rawIssueCount (${input.rawIssueCount})`);
  }
  if (input.rawIssueCount !== input.classifiedIssueCount) {
    failures.push(`${tag}: scored release requires complete classification coverage (${input.classifiedIssueCount}/${input.rawIssueCount})`);
  }

  expectEqual(failures, tag, 'negative issue count', Number(rel.negative_issues ?? 0), result.neg);
  expectEqual(failures, tag, 'positive issue count', Number(rel.positive_issues ?? 0), result.pos);
  expectEqual(failures, tag, 'opened serious count', Number(rel.opened_serious_during_reign ?? 0), result.openedSerious);
  expectEqual(failures, tag, 'closed serious count', Number(rel.closed_serious_fixed ?? 0), result.closedSerious);
  expectJson(failures, tag, 'broken surfaces', parseJson(rel.broken_surfaces, []), parseJson(result.brokenSurfaces, []));

  expectJson(failures, tag, 'audit input_json', parseJson(audit.input_json, null), normalizeJson(input));
  expectJson(failures, tag, 'audit issue_evidence_json', parseJson(audit.issue_evidence_json, null), normalizeJson(result.debtEvidence));
  expectJson(failures, tag, 'audit gate_evidence_json', parseJson(audit.gate_evidence_json, null), normalizeJson(result.gateEvidence));
  const components = parseJson(audit.components_json, null);
  expectJson(failures, tag, 'audit components', components?.components ?? null, normalizeJson(conf.components));
  expectJson(failures, tag, 'audit explanation', components?.explanation ?? null, normalizeJson(result.explanation));
  expectEqual(failures, tag, 'audit evidenceCoverage', components?.evidenceCoverage, conf.evidenceCoverage);
  expectEqual(failures, tag, 'audit hotfix', components?.hotfix, conf.hotfix);
  expectEqual(failures, tag, 'audit reason', components?.reason, conf.reason);
}

function scoredAtMillis(rel, audit, failures) {
  const raw = rel.scored_at ?? audit?.scored_at ?? null;
  const millis = raw ? Date.parse(raw) : NaN;
  if (!Number.isFinite(millis)) {
    failures.push(`${rel.tag}: missing or invalid scored_at`);
    return Date.now();
  }
  return millis;
}

function expectEqual(failures, tag, field, actual, expected) {
  if (sameValue(actual, expected)) return;
  failures.push(`${tag}: ${field} drifted: persisted=${format(actual)} recomputed=${format(expected)}`);
}

function expectJson(failures, tag, field, actual, expected) {
  const normalizedActual = normalizeJson(actual);
  const normalizedExpected = normalizeJson(expected);
  const diffs = [];
  compareJsonValue(normalizedActual, normalizedExpected, field, diffs);
  for (const diff of diffs) failures.push(`${tag}: ${diff}`);
}

function compareJsonValue(actual, expected, path, diffs) {
  if (sameValue(actual, expected)) return;
  if (Array.isArray(actual) || Array.isArray(expected)) {
    if (!Array.isArray(actual) || !Array.isArray(expected)) {
      diffs.push(`${path} type drifted: persisted=${format(actual)} recomputed=${format(expected)}`);
      return;
    }
    if (actual.length !== expected.length) {
      diffs.push(`${path} length drifted: persisted=${actual.length} recomputed=${expected.length}`);
      return;
    }
    for (let i = 0; i < actual.length; i++) compareJsonValue(actual[i], expected[i], `${path}[${i}]`, diffs);
    return;
  }
  if (isPlainObject(actual) || isPlainObject(expected)) {
    if (!isPlainObject(actual) || !isPlainObject(expected)) {
      diffs.push(`${path} type drifted: persisted=${format(actual)} recomputed=${format(expected)}`);
      return;
    }
    const keys = [...new Set([...Object.keys(actual), ...Object.keys(expected)])].sort();
    for (const key of keys) compareJsonValue(actual[key], expected[key], `${path}.${key}`, diffs);
    return;
  }
  diffs.push(`${path} drifted: persisted=${format(actual)} recomputed=${format(expected)}`);
}

function sameValue(actual, expected) {
  if (typeof actual === 'number' || typeof expected === 'number') {
    if (actual == null || expected == null) return actual == null && expected == null;
    return Math.abs(Number(actual) - Number(expected)) <= 1e-9;
  }
  return actual === expected;
}

function parseJson(value, fallback) {
  try {
    return value == null ? fallback : JSON.parse(value);
  } catch {
    return fallback;
  }
}

function normalizeJson(value) {
  return JSON.parse(JSON.stringify(value));
}

function isPlainObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function format(value) {
  return typeof value === 'string' ? JSON.stringify(value) : JSON.stringify(value);
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--check') parsed.check = true;
    else if (arg === '--no-check') parsed.check = false;
    else if (arg === '--print-only') parsed['print-only'] = true;
    else if (arg === '--all') parsed.all = true;
    else if (arg === '--limit') parsed.limit = argv[++i];
    else if (arg.startsWith('--limit=')) parsed.limit = arg.slice('--limit='.length);
  }
  return parsed;
}
