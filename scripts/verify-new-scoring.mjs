// Offline validation of the real scoring path against the real DB. This reads
// existing classifications/evidence only; it does not call GitHub or the LLM.
import { DatabaseSync } from 'node:sqlite';
import {
  cveDecayLoad,
  feltLoad,
  feltSignalMask,
  installConfidence,
  openDebtLoad,
  pickRecommended,
} from '../src/lib/score.ts';
import { topBrokenSurfaces } from '../src/lib/surfaces.ts';
import {
  labelsForIssueAt,
  listReleasesDb,
  openedDuringReign,
  issueCountForVersion,
  issuesForVersion,
  listAdvisories,
  verifiedFixedForRelease,
} from '../src/lib/db.ts';
import { hasHotfixSuccessor } from '../src/lib/releaseNotes.ts';
import { matchesRange, stableDistance } from '../src/lib/versionMatch.ts';
import { applyLabelOverrides, applyTitleFunctionalityHint, applyTitleIssueShapeHint } from '../src/lib/labelOverrides.ts';

const args = parseArgs(process.argv.slice(2));
const limit = Number(args.limit ?? 10);
const check = args.check !== false && args['print-only'] !== true;
const dbPath = process.env.DB_PATH ?? './data/radar.db';
const db = new DatabaseSync(dbPath, { readOnly: true });
db.exec('PRAGMA query_only = ON');

const allRel = db.prepare(
  `SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`,
).all().map((r) => ({ tag: r.tag, published_at: r.published_at, prerelease: r.prerelease === 1 }));
const commitStmt = db.prepare(`SELECT * FROM release_commits WHERE tag=?`);
const auditStmt = db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`);
const allFetchedTags = allRel.map((r) => r.tag);
const stableTagsNewestFirst = allRel.filter((r) => !r.prerelease).map((r) => r.tag);

const advisories = listAdvisories();
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
const cveFor = (tag) => {
  const matching = advisories.filter((a) => matchesRange(tag, a.vulnerable_version_range));
  return {
    affected: matching.some((a) => (SEV[a.severity] ?? 0) >= 2),
    load: cveDecayLoad(
      matching
        .map((a) => ({
          severity: a.severity,
          distance: stableDistance(tag, a.patched_versions, stableTagsNewestFirst),
        }))
        .filter((x) => x.distance <= 0),
    ),
  };
};

function safeLabels(json) {
  try {
    const value = JSON.parse(json);
    return Array.isArray(value) ? value.filter((x) => typeof x === 'string') : [];
  } catch {
    return [];
  }
}

function rowToClassification(row) {
  const knownWorkaround = ['none', 'partial', 'confirmed', 'unknown'];
  const workaroundStatus = knownWorkaround.includes(row.workaround_status)
    ? row.workaround_status
    : (row.has_workaround === 1 ? 'confirmed' : 'unknown');
  return {
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster,
    affectsVersion: row.affects_version,
    confidence: row.confidence,
    rationale: row.rationale ?? '',
  };
}

const classify = (row, labels = safeLabels(row.labels)) =>
  applyTitleIssueShapeHint(
    applyLabelOverrides(applyTitleFunctionalityHint(rowToClassification(row), row.title), labels),
    row.title,
    labels,
  );

const isCoreSerious = (classification) =>
  classification.sentiment === 'negative' &&
  classification.functionality === 'core' &&
  (classification.severity === 'critical' || classification.severity === 'high');

const releaseLabelCutoff = (rel) => rel.published_at && rel.hours_to_next_stable != null
  ? new Date(Date.parse(rel.published_at) + rel.hours_to_next_stable * 3_600_000).toISOString()
  : null;

const releases = listReleasesDb(limit);
const scored = releases.map((rel, index) => scoreRelease(rel, index));
const recommendedTag = pickRecommended(scored.map((s) => ({
  tag: s.rel.tag,
  status: s.conf.status,
  score: s.conf.score,
})));

const failures = [];
const rows = scored.map((s) => {
  const audit = auditStmt.get(s.rel.tag);
  const now = scoredAtMillis(s.rel, audit, failures);
  const conf = installConfidence(s.input, now);
  const recommended = s.rel.tag === recommendedTag;
  comparePersisted({ failures, rel: s.rel, audit, input: s.input, conf, recommended, stats: s.stats });
  return {
    tag: s.rel.tag,
    score: conf.score == null ? '-' : conf.score,
    persisted: s.rel.final_score == null ? '-' : s.rel.final_score,
    band: conf.band,
    status: conf.status,
    rec: recommended ? '*' : '',
    reason: conf.reason,
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

function scoreRelease(rel, index) {
  const labelCutoff = releaseLabelCutoff(rel);
  const labelsFor = (row) => labelsForIssueAt(row.number, safeLabels(row.labels), labelCutoff);
  const classifyAt = (row) => classify(row, labelsFor(row));
  const countCoreSerious = (rows) => rows.reduce((count, row) => count + (isCoreSerious(classifyAt(row)) ? 1 : 0), 0);

  const attributed = issuesForVersion(rel.tag);
  const openedReign = openedDuringReign(rel.tag);
  const verifiedFixed = verifiedFixedForRelease(rel.tag);
  const verifiedFixedNumbers = new Set(verifiedFixed.map((row) => row.number));
  const releaseStart = rel.published_at ? Date.parse(rel.published_at) : NaN;

  let negativeCount = 0;
  let positiveCount = 0;
  for (const row of attributed) {
    const sentiment = classifyAt(row).sentiment;
    if (sentiment === 'negative') negativeCount++;
    else if (sentiment === 'positive') positiveCount++;
  }

  const scoreStateForIssue = (row) => {
    if (verifiedFixedNumbers.has(row.number)) return 'closed';
    return row.state === 'open' ? 'open' : 'closed-unverified';
  };

  const scoredIssue = (row) => ({
    ...classifyAt(row),
    issueNumber: row.number,
    title: row.title,
    duplicateCluster: row.duplicate_cluster,
    author: row.author,
    authorAssociation: row.author_association,
    isBot: row.is_bot,
    comments: row.comments,
    uniqueHumanCommenterCount: row.unique_human_commenters,
    maintainerCommenterCount: row.maintainer_commenters,
    contributorCommenterCount: row.contributor_commenters,
    commenterScanTruncated: row.commenter_scan_truncated,
    reactionTotal: row.reaction_total,
    positiveReactionCount: row.positive_reactions,
    labels: labelsFor(row),
  });

  const debtInputs = attributed.map((row) => ({
    ...scoredIssue(row),
    issueNumber: row.number,
    state: scoreStateForIssue(row),
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    affectsVersion: row.affects_version,
    releaseLocal: Number.isFinite(releaseStart) ? Date.parse(row.created_at) >= releaseStart : false,
  }));
  const debt = openDebtLoad(debtInputs);
  const openedFeltInputs = openedReign.map(scoredIssue);
  const openedFeltMask = feltSignalMask(openedFeltInputs);
  const openedFeltRows = openedReign.filter((_, rowIndex) => openedFeltMask[rowIndex]);
  const cve = cveFor(rel.tag);
  const commit = commitStmt.get(rel.tag);

  const input = {
    publishedAt: rel.published_at,
    isLatest: index === 0,
    hoursToNextStable: rel.hours_to_next_stable,
    hasHotfixSuccessor: hasHotfixSuccessor(allFetchedTags, rel.tag),
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight: feltLoad(openedFeltInputs),
    feltClosedWeight: feltLoad(verifiedFixed.map(scoredIssue)),
    verifiedDebtWeight: debt.verified,
    carryoverDebtWeight: debt.carryover,
    staleDebtWeight: debt.stale,
    rawIssueCount: issueCountForVersion(rel.tag),
    classifiedIssueCount: attributed.length,
    cveAffected: cve.affected,
    cveLoad: cve.load,
    releaseCheckState: commit?.check_state ?? null,
    releaseCheckTotal: commit?.check_total ?? 0,
    releaseCheckSuccess: commit?.check_success ?? 0,
    releaseCheckFailure: commit?.check_failure ?? 0,
    releaseCheckPending: commit?.check_pending ?? 0,
    artifactVerified: rel.artifact_verified === 1,
    artifactMismatch: rel.artifact_mismatch,
    ciReportVerified: rel.ci_report_verified === 1,
    ciReportMismatch: rel.ci_report_mismatch,
    releaseIntegrityPresent: !!rel.release_integrity,
    releaseShaMatches: rel.release_sha && commit?.tag_commit_oid ? rel.release_sha === commit.tag_commit_oid : undefined,
  };

  return {
    rel,
    input,
    conf: installConfidence(input, Date.now()),
    stats: {
      negativeCount,
      positiveCount,
      openedSerious: countCoreSerious(openedReign),
      closedSerious: countCoreSerious(verifiedFixed),
      brokenSurfaces: JSON.stringify(topBrokenSurfaces(openedFeltRows.map((row) => row.title))),
    },
  };
}

function comparePersisted({ failures, rel, audit, input, conf, recommended, stats }) {
  const tag = rel.tag;
  if (!audit) {
    failures.push(`${tag}: missing release_score_audits row`);
    return;
  }

  expectEqual(failures, tag, 'release final_score', rel.final_score, conf.score);
  expectEqual(failures, tag, 'audit final_score', audit.final_score, conf.score);
  expectEqual(failures, tag, 'release state', rel.state, conf.status);
  expectEqual(failures, tag, 'audit status', audit.status, conf.status);
  expectEqual(failures, tag, 'audit band', audit.band, conf.band);
  expectEqual(failures, tag, 'release recommended', Number(rel.recommended ?? 0), recommended ? 1 : 0);
  expectEqual(failures, tag, 'audit recommended', Number(audit.recommended ?? 0), recommended ? 1 : 0);
  expectEqual(failures, tag, 'release reason', rel.score_reason, conf.reason);

  expectEqual(failures, tag, 'negative issue count', Number(rel.negative_issues ?? 0), stats.negativeCount);
  expectEqual(failures, tag, 'positive issue count', Number(rel.positive_issues ?? 0), stats.positiveCount);
  expectEqual(failures, tag, 'opened serious count', Number(rel.opened_serious_during_reign ?? 0), stats.openedSerious);
  expectEqual(failures, tag, 'closed serious count', Number(rel.closed_serious_fixed ?? 0), stats.closedSerious);
  expectJson(failures, tag, 'broken surfaces', parseJson(rel.broken_surfaces, []), parseJson(stats.brokenSurfaces, []));

  expectJson(failures, tag, 'audit input_json', parseJson(audit.input_json, null), normalizeJson(input));
  const components = parseJson(audit.components_json, null);
  expectJson(failures, tag, 'audit components', components?.components ?? null, normalizeJson(conf.components));
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
    else if (arg === '--limit') parsed.limit = argv[++i];
    else if (arg.startsWith('--limit=')) parsed.limit = arg.slice('--limit='.length);
  }
  return parsed;
}
