// Offline validation of the real scoring path against the real DB. This reads
// existing classifications/evidence only; it does not call GitHub or the LLM.
import { DatabaseSync } from 'node:sqlite';
import { existsSync } from 'node:fs';
import { verifyScoreAuditPayloadContracts } from '../src/lib/scoreAuditContracts.ts';

const args = parseArgs(process.argv.slice(2));
const check = args.check !== false && args['print-only'] !== true;
const requestedLimit = args.limit == null ? 10 : positiveIntegerLimit(args.limit);
const dbPath = process.env.DB_PATH ?? './data/radar.db';
process.env.RADAR_DB_READ_ONLY = '1';
if (!existsSync(dbPath)) {
  throw new Error(`Database not found: ${dbPath}`);
}
const { scoreRunWindowOptions } = await import('./lib/score-run-window.mjs');
const { ReleaseAuditReader } = await import('./lib/release-audit-reader.mjs');
const db = new DatabaseSync(dbPath, { readOnly: true });
db.exec('PRAGMA query_only = ON');
const {
  buildReleaseScoreRun,
  currentScoreCompletenessDiagnostic,
  GATE_EVIDENCE_SCHEMA_VERSION,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  PROMPT_VERSION,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  SCORE_INPUT_SCHEMA_VERSION,
  SCORE_MODEL_VERSION,
} = await import('../src/lib/releaseScoring.ts');
const {
  formatReleaseClosureProofIntegrityFailure,
  formatReleasePrReachabilityIntegrityFailure,
  releaseClosureProofIntegrity,
  releasePrReachabilityIntegrity,
} = await import('../src/lib/db.ts');

const auditStmt = db.prepare(`SELECT * FROM release_score_audits WHERE release_tag=?`);
const activeStableRows = db.prepare(`
  SELECT r.*
  FROM releases r
  WHERE r.prerelease=0
    AND r.catalog_active=1
  ORDER BY r.catalog_rank IS NULL, r.catalog_rank, r.published_at IS NULL, r.published_at DESC
`).all();
const scorePersistence = parseJson(
  db.prepare(`SELECT value FROM meta WHERE key='score_persistence_last_run'`).get()?.value,
  null,
);
const persistedReleaseTagsPresent =
  scorePersistence != null &&
  typeof scorePersistence === 'object' &&
  !Array.isArray(scorePersistence) &&
  Object.prototype.hasOwnProperty.call(scorePersistence, 'releaseTags');
const persistedReleaseTags = persistedReleaseTagsPresent && Array.isArray(scorePersistence.releaseTags)
  ? scorePersistence.releaseTags
  : null;
const activeStableTags = activeStableRows.map((row) => row.tag);
const releasesToVerify = args.all
  ? activeStableRows
  : activeStableRows.slice(0, requestedLimit);

const failures = [];
verifyScoredReleaseCoverage(failures, releasesToVerify);
if (args.all) verifyScorePublicationIntegrity(failures);
const {
  scored: allScored,
  recommendedTag,
  sourceIdentity,
} = buildReleaseScoreRun({
  ...scoreRunWindowOptions(activeStableRows),
  nowForRelease: (rel) => scoredAtMillis(rel, auditStmt.get(rel.tag), failures),
});
verifyGlobalRecommendation(failures, recommendedTag);
const releaseTagsToVerify = new Set(releasesToVerify.map((release) => release.tag));
const scored = allScored.filter((result) => releaseTagsToVerify.has(result.rel.tag));
const rows = scored.map((s) => {
  const audit = auditStmt.get(s.rel.tag);
  const recommended = s.rel.tag === recommendedTag;
  comparePersisted({ failures, result: s, audit, recommended, sourceIdentity });
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
  process.exitCode = 1;
} else if (check) {
  console.log(`Score verification passed for ${scored.length} release(s).`);
}

function verifyScoredReleaseCoverage(failures, releases) {
  if (args.all) verifyActiveCatalogEquality(failures);
  if (activeStableRows.length === 0) {
    failures.push('score verification requires at least one active monitored stable release');
  }

  for (const release of releases) {
    const tag = release.tag;
    const audit = auditStmt.get(tag);
    if (!audit) {
      failures.push(`${tag}: audited stable release is missing release_score_audits row`);
      continue;
    }
    if (!isTimestamp(release.scored_at)) {
      failures.push(`${tag}: active monitored stable release is missing valid scored_at`);
    }
    if (!isTimestamp(audit.scored_at)) {
      failures.push(`${tag}: score audit is missing valid scored_at`);
    }
    if (release.scored_at !== audit.scored_at) {
      failures.push(
        `${tag}: release scored_at (${release.scored_at}) must match audit scored_at (${audit.scored_at})`,
      );
    }
    if (!['wait', 'skip-cve', 'skip-hotfix', 'eligible'].includes(release.state)) {
      failures.push(`${tag}: active monitored stable release has invalid disposition ${format(release.state)}`);
    }
    if (release.state !== audit.status) {
      failures.push(
        `${tag}: release disposition (${release.state}) must match audit status (${audit.status})`,
      );
    }
    if (release.final_score == null && release.state !== 'wait') {
      failures.push(
        `${tag}: null final_score is only valid for an audited wait disposition`,
      );
    }
    if (release.final_score != null && release.state === 'wait') {
      failures.push(`${tag}: wait disposition must persist a null final_score`);
    }
    if (!sameValue(release.final_score, audit.final_score)) {
      failures.push(
        `${tag}: release final_score (${format(release.final_score)}) must match ` +
        `audit final_score (${format(audit.final_score)})`,
      );
    }
    const input = parseJson(audit.input_json, null);
    if (
      !Number.isInteger(input?.rawIssueCount) ||
      input.rawIssueCount < 0 ||
      !Number.isInteger(input?.classifiedIssueCount) ||
      input.classifiedIssueCount < 0 ||
      input.classifiedIssueCount !== input.rawIssueCount
    ) {
      failures.push(
        `${tag}: scored release requires complete classification coverage ` +
        `(${input?.classifiedIssueCount ?? 'missing'}/${input?.rawIssueCount ?? 'missing'})`,
      );
    }
  }

  if (!args.all) return;
  const orphanAudits = db.prepare(`
    SELECT a.release_tag
    FROM release_score_audits a
    LEFT JOIN releases r ON r.tag=a.release_tag
    WHERE r.tag IS NULL
      OR (r.catalog_active=1 AND r.prerelease != 0)
    ORDER BY a.release_tag
  `).all();
  for (const row of orphanAudits) failures.push(`${row.release_tag}: score audit points at missing or non-stable release`);
}

function verifyActiveCatalogEquality(failures) {
  if (!persistedReleaseTagsPresent) {
    failures.push('score persistence releaseTags must be present for --all verification');
  } else if (!Array.isArray(scorePersistence?.releaseTags)) {
    failures.push('score persistence releaseTags must be an array when present');
  } else if (
    persistedReleaseTags.some((tag) => typeof tag !== 'string' || tag.length === 0) ||
    new Set(persistedReleaseTags).size !== persistedReleaseTags.length
  ) {
    failures.push('score persistence releaseTags must contain unique non-empty strings');
  } else {
    expectExactTagSet(
      failures,
      'score persistence releaseTags',
      persistedReleaseTags,
      activeStableTags,
    );
  }

  const currentAuditTags = db.prepare(`
    SELECT release_tag
    FROM release_score_audits
    ORDER BY release_tag
  `).all().map((row) => row.release_tag);
  expectExactTagSet(
    failures,
    'current score audits',
    currentAuditTags,
    activeStableTags,
  );
}

function verifyScorePublicationIntegrity(failures) {
  try {
    const publication = new ReleaseAuditReader(db).scorePublicationIntegrity();
    for (const failure of publication.failures.filter(isScoreAuditLineageFailure)) {
      failures.push(`score publication: ${failure}`);
    }
  } catch (error) {
    failures.push(
      `score publication: sealed audit verification failed: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function isScoreAuditLineageFailure(failure) {
  return /^(?:score history|score authority|score persistence|current audit|current history)\b/.test(
    failure,
  );
}

function verifyGlobalRecommendation(failures, recommendedTag) {
  const persistedRecommendedTags = db.prepare(`
    SELECT tag
    FROM releases
    WHERE prerelease=0
      AND catalog_active=1
      AND recommended=1
    ORDER BY tag
  `).all().map((row) => row.tag);
  const expectedRecommendedTags = recommendedTag == null ? [] : [recommendedTag];
  if (!sameTagSet(persistedRecommendedTags, expectedRecommendedTags)) {
    failures.push(
      `persisted global recommendation (${formatTagList(persistedRecommendedTags)}) must match ` +
      `the full active-catalog recommendation (${formatTagList(expectedRecommendedTags)})`,
    );
  }
  if (
    scorePersistence &&
    typeof scorePersistence === 'object' &&
    !Array.isArray(scorePersistence) &&
    Object.prototype.hasOwnProperty.call(scorePersistence, 'recommendedTag') &&
    scorePersistence.recommendedTag !== recommendedTag
  ) {
    failures.push(
      `score persistence recommendedTag (${format(scorePersistence.recommendedTag)}) must match ` +
      `the full active-catalog recommendation (${format(recommendedTag)})`,
    );
  }
}

function expectExactTagSet(failures, label, actual, expected) {
  if (sameTagSet(actual, expected)) return;
  const actualTags = new Set(actual);
  const expectedTags = new Set(expected);
  const missing = expected.filter((tag) => !actualTags.has(tag));
  const extra = actual.filter((tag) => !expectedTags.has(tag));
  failures.push(
    `${label} must exactly match the active stable catalog ` +
    `(missing: ${formatTagList(missing)}; extra: ${formatTagList(extra)})`,
  );
}

function sameTagSet(actual, expected) {
  return actual.length === expected.length &&
    new Set(actual).size === actual.length &&
    new Set(expected).size === expected.length &&
    actual.every((tag) => expected.includes(tag));
}

function formatTagList(tags) {
  return tags.length > 0 ? tags.join(', ') : 'none';
}

function comparePersisted({ failures, result, audit, recommended, sourceIdentity }) {
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
  failures.push(...currentScoreCompletenessDiagnostic({
    tag,
    analysisCompleteness: result.analysisCompleteness,
  }).problems);
  const closureProofFailure = formatReleaseClosureProofIntegrityFailure(releaseClosureProofIntegrity(tag, 3));
  if (closureProofFailure) failures.push(closureProofFailure);
  const reachabilityFailure = formatReleasePrReachabilityIntegrityFailure(releasePrReachabilityIntegrity(tag, 3));
  if (reachabilityFailure) failures.push(reachabilityFailure);

  expectEqual(failures, tag, 'negative issue count', Number(rel.negative_issues ?? 0), result.neg);
  expectEqual(failures, tag, 'positive issue count', Number(rel.positive_issues ?? 0), result.pos);
  expectEqual(failures, tag, 'opened serious count', Number(rel.opened_serious_during_reign ?? 0), result.openedSerious);
  expectEqual(failures, tag, 'closed serious count', Number(rel.closed_serious_fixed ?? 0), result.closedSerious);
  expectJson(failures, tag, 'broken surfaces', parseJson(rel.broken_surfaces, []), parseJson(result.brokenSurfaces, []));

  const persistedInput = parseJson(audit.input_json, null);
  const persistedIssueEvidence = parseJson(audit.issue_evidence_json, null);
  const persistedGateEvidence = parseJson(audit.gate_evidence_json, null);
  const persistedSourceIdentity = parseJson(audit.source_identity_json, null);
  const components = parseJson(audit.components_json, null);
  failures.push(...verifyScoreAuditPayloadContracts({
    tag,
    scoredAt: audit.scored_at,
    input: persistedInput,
    components,
    issueEvidence: persistedIssueEvidence,
    gateEvidence: persistedGateEvidence,
    versions: {
      scoreInput: SCORE_INPUT_SCHEMA_VERSION,
      scoreComponents: SCORE_COMPONENTS_SCHEMA_VERSION,
      issueEvidence: ISSUE_EVIDENCE_SCHEMA_VERSION,
      gateEvidence: GATE_EVIDENCE_SCHEMA_VERSION,
    },
  }));
  expectJson(failures, tag, 'audit input_json', persistedInput, normalizeJson(input));
  expectJson(failures, tag, 'audit issue_evidence_json', persistedIssueEvidence, normalizeJson(result.debtEvidence));
  expectJson(failures, tag, 'audit gate_evidence_json', persistedGateEvidence, normalizeJson(result.gateEvidence));
  expectJson(failures, tag, 'audit source_identity_json', persistedSourceIdentity, normalizeJson(sourceIdentity));
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

function isTimestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
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

function positiveIntegerLimit(value) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`--limit must be a positive integer, received ${format(value)}`);
  }
  return parsed;
}

function parseArgs(argv) {
  const parsed = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === '--check') parsed.check = true;
    else if (arg === '--no-check') parsed.check = false;
    else if (arg === '--print-only') parsed['print-only'] = true;
    else if (arg === '--all') parsed.all = true;
    else if (arg === '--limit') {
      const value = argv[++i];
      if (value == null || value.startsWith('--')) {
        throw new Error('--limit must be followed by a positive integer');
      }
      parsed.limit = value;
    }
    else if (arg.startsWith('--limit=')) parsed.limit = arg.slice('--limit='.length);
  }
  return parsed;
}
