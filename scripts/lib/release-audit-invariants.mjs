export const knownProofStatuses = new Set([
  'fixed_in_release',
  'fixed_after_release',
  'duplicate_to_open_canonical',
  'duplicate_to_closed_canonical',
  'canonical_cycle_or_self_reference',
  'duplicate_or_superseded',
  'not_planned',
  'already_present_claim',
  'main_only_claim',
  'reporter_replaced',
  'reporter_withdrawn',
  'reporter_self_closed',
  'no_code_proof',
  'no_timeline_event',
  'non_bug_neutral',
  'unknown',
]);

const knownCommitProofStatuses = new Set(['reachable', 'not_reachable', 'unknown']);
const fullCommitOidRe = /^[0-9a-f]{40}$/;
const scoreExplanationSchemaVersion = 1;
const knownExplanationCodes = new Set([
  'field_visible_reports_opened',
  'source_carryover_risk',
  'stale_low_confidence_evidence',
  'closed_issues_not_counted_as_release_fixes',
  'unverified_closed_fix_reachability',
  'missing_full_release_evidence_report',
  'model_ceiling_and_capped_confidence',
  'no_verified_field_blocker_debt',
  'release_checks_passed',
  'artifact_verified',
  'release_recommended',
  'hard_gates_passed',
]);

export async function verifyReleaseAudit({ reader, apiBase = null, fetchJson = defaultFetchJson, limit = 10, scoredOnly = false }) {
  const releases = reader.listReleases(limit, { scoredOnly });
  const failures = [];
  const rows = [];

  for (const release of releases) {
    const tag = release.tag;
    const closed = reader.closedDuringReign(tag);
    const verified = reader.verifiedFixedForRelease(tag);
    const unverified = reader.unverifiedClosedForRelease(tag);
    const proofRows = reader.proofRowsFor(tag);
    const fixedProof = proofRows.filter((row) => row.status === 'fixed_in_release');
    const notCountedProof = proofRows.filter((row) => row.status !== 'fixed_in_release');

    rows.push({
      tag,
      closed: closed.length,
      verified: verified.length,
      unverified: unverified.length,
      proof: proofRows.length,
      counted: fixedProof.length,
      notCounted: notCountedProof.length,
    });

    expect(failures, tag, closed.length === verified.length + unverified.length,
      `closedDuringReign (${closed.length}) must equal verified + unverified (${verified.length + unverified.length})`);
    expect(failures, tag, proofRows.length === closed.length,
      `closure proofs (${proofRows.length}) must cover closed release-window issues (${closed.length})`);
    expect(failures, tag, fixedProof.length + notCountedProof.length === proofRows.length,
      'counted + not-counted proof rows must equal all proof rows');

    const verifiedNumbers = new Set(verified.map((row) => row.number));
    const proofByNumber = new Map(proofRows.map((row) => [row.issue_number, row]));
    for (const row of fixedProof) {
      expect(failures, tag, verifiedNumbers.has(row.issue_number),
        `fixed_in_release issue #${row.issue_number} must be present in verifiedFixedForRelease`);
    }

    for (const row of verified) {
      const proof = proofByNumber.get(row.number);
      if (!proof) continue;
      const evidence = parseJson(proof.evidence_json, {});
      if (proof.status !== 'fixed_in_release') {
        expect(failures, tag, row.sentiment !== 'negative',
          `verified issue #${row.number} has proof status ${proof.status}; only non-negative verified closures may avoid fixed_in_release`);
      }
      expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
        `verified issue #${row.number} must have final COMPLETED closure evidence`);
    }

    for (const row of proofRows) {
      expect(failures, tag, knownProofStatuses.has(row.status), `unknown proof status ${row.status} for issue #${row.issue_number}`);
      const evidence = parseJson(row.evidence_json, {});
      verifyProofEvidenceShape({ failures, tag, row, evidence });
      if (row.status === 'fixed_in_release') {
        expect(failures, tag, evidence.hasReachableClosingPr === true || evidence.hasReachableFixCommit === true,
          `fixed_in_release issue #${row.issue_number} must have reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_after_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_after_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'duplicate_to_open_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
          `duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
      }
      if (row.status === 'duplicate_to_closed_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
      }
      if (row.status === 'canonical_cycle_or_self_reference') {
        expect(failures, tag, evidence.canonicalResolution?.cycle === true || evidence.canonicalResolution?.selfReference === true,
          `canonical_cycle_or_self_reference issue #${row.issue_number} must record cycle/self-reference evidence`);
      }
    }

    const audit = reader.getReleaseScoreAudit(tag);
    if (audit) {
    const gate = parseJson(audit.gate_evidence_json, {});
    verifyLabelTimelineGate({ failures, tag, labelTimeline: gate.labelTimeline });
    const fix = gate.fixProvenance ?? {};
    expect(failures, tag, fix.verifiedFixedCount === verified.length,
      `audit verifiedFixedCount (${fix.verifiedFixedCount}) must match verifiedFixedForRelease (${verified.length})`);
    expect(failures, tag, fix.unverifiedClosedCount === unverified.length,
      `audit unverifiedClosedCount (${fix.unverifiedClosedCount}) must match unverifiedClosedForRelease (${unverified.length})`);
    if (proofRows.length) {
      expect(failures, tag, !!fix.closureProof && !!fix.releaseFixCredit,
        'persisted audit gateEvidence must include closureProof and releaseFixCredit when proof rows exist');
      if (fix.closureProof && fix.releaseFixCredit) {
        expect(failures, tag, fix.releaseFixCredit.countedClosedCount === fixedProof.length,
          `persisted countedClosedCount (${fix.releaseFixCredit.countedClosedCount}) must match fixed_in_release proof rows (${fixedProof.length})`);
        expect(failures, tag, fix.releaseFixCredit.notCountedClosedCount === notCountedProof.length,
          `persisted notCountedClosedCount (${fix.releaseFixCredit.notCountedClosedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
        expect(failures, tag, fix.releaseFixCredit.analyzedClosedCount === proofRows.length,
          `persisted analyzedClosedCount (${fix.releaseFixCredit.analyzedClosedCount}) must match proof rows (${proofRows.length})`);
        expect(failures, tag, fix.closureProof.creditedCount === fixedProof.length,
          `persisted closureProof creditedCount (${fix.closureProof.creditedCount}) must match fixed proof rows (${fixedProof.length})`);
        expect(failures, tag, fix.closureProof.notCreditedCount === notCountedProof.length,
          `persisted closureProof notCreditedCount (${fix.closureProof.notCreditedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
      }
    }
  } else {
      expect(failures, tag, false, 'release score audit row is missing');
    }
  }

  if (apiBase) {
    await verifyApi({ apiBase: apiBase.replace(/\/$/, ''), fetchJson, releases, failures });
  }

  return { releases, rows, failures };
}

function verifyLabelTimelineGate({ failures, tag, labelTimeline }) {
  expect(failures, tag, isObject(labelTimeline), 'persisted audit gateEvidence must include labelTimeline coverage');
  if (!isObject(labelTimeline)) return;
  for (const key of ['issueCount', 'currentLabelCount', 'timelineLabelCount', 'missingTimelineCount', 'missingTimelineWithCurrentLabelsCount']) {
    expect(failures, tag, Number.isInteger(labelTimeline[key]) && labelTimeline[key] >= 0,
      `labelTimeline ${key} must be a non-negative integer`);
  }
  const sourceTotal = Number(labelTimeline.currentLabelCount ?? -1) +
    Number(labelTimeline.timelineLabelCount ?? -1) +
    Number(labelTimeline.missingTimelineCount ?? -1);
  expect(failures, tag, sourceTotal === labelTimeline.issueCount,
    `labelTimeline source counts (${sourceTotal}) must equal issueCount (${labelTimeline.issueCount})`);
  expect(failures, tag, labelTimeline.missingTimelineWithCurrentLabelsCount <= labelTimeline.missingTimelineCount,
    'labelTimeline missingTimelineWithCurrentLabelsCount must not exceed missingTimelineCount');
  expect(failures, tag, typeof labelTimeline.historicalCurrentLabelFallbackAllowed === 'boolean',
    'labelTimeline historicalCurrentLabelFallbackAllowed must be boolean');
  if (labelTimeline.cutoffAt != null) {
    expect(failures, tag, labelTimeline.historicalCurrentLabelFallbackAllowed === false,
      'historical label cutoffs must not allow current-label fallback');
  }
}

function verifyProofEvidenceShape({ failures, tag, row, evidence }) {
  expect(failures, tag, isObject(evidence),
    `proof issue #${row.issue_number} evidence_json must parse to an object`);
  if (!isObject(evidence)) return;

  if ('stateReasons' in evidence) {
    expect(failures, tag, isStringArray(evidence.stateReasons),
      `proof issue #${row.issue_number} stateReasons must be a string array`);
  }
  for (const flag of ['hasReachableFixCommit', 'hasNotReachableFixCommit']) {
    expect(failures, tag, typeof evidence[flag] === 'boolean',
      `proof issue #${row.issue_number} ${flag} must be boolean`);
  }

  const reachableFixCommits = normalizeStringArray(evidence.reachableFixCommits);
  const notReachableFixCommits = normalizeStringArray(evidence.notReachableFixCommits);
  const fixCommitProof = Array.isArray(evidence.fixCommitProof) ? evidence.fixCommitProof : [];

  expect(failures, tag, Array.isArray(evidence.reachableFixCommits),
    `proof issue #${row.issue_number} reachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.notReachableFixCommits),
    `proof issue #${row.issue_number} notReachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.fixCommitProof),
    `proof issue #${row.issue_number} fixCommitProof must be an array`);

  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'reachableFixCommits', commits: reachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'notReachableFixCommits', commits: notReachableFixCommits });
  expect(failures, tag, intersection(reachableFixCommits, notReachableFixCommits).length === 0,
    `proof issue #${row.issue_number} reachable and not-reachable fix commit arrays must not overlap`);

  const proofReachable = [];
  const proofNotReachable = [];
  for (const proof of fixCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} fixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} fixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0,
      `proof issue #${row.issue_number} fixCommitProof sourceIssueNumber must be a positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} fixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} fixCommitProof has unknown status ${proof.status}`);
    expect(failures, tag, proof.tagCommitOid == null || (typeof proof.tagCommitOid === 'string' && fullCommitOidRe.test(proof.tagCommitOid)),
      `proof issue #${row.issue_number} fixCommitProof tagCommitOid must be null or full lowercase 40-hex SHA`);
    expect(failures, tag, typeof proof.evidence === 'string' && proof.evidence.length > 0,
      `proof issue #${row.issue_number} fixCommitProof evidence must be present`);
    expect(failures, tag, typeof proof.snippet === 'string' && proof.snippet.length > 0,
      `proof issue #${row.issue_number} fixCommitProof snippet must be present`);
    if (proof.source === 'ClosureComment.fixProof') {
      expect(failures, tag, proof.trustedSource === true,
        `proof issue #${row.issue_number} closure-comment commit proof must come from a trusted source`);
      expect(failures, tag, typeof proof.author === 'string' && proof.author.length > 0,
        `proof issue #${row.issue_number} closure-comment commit proof must record an author`);
    }
    if (proof.status === 'reachable' && typeof proof.commitOid === 'string') proofReachable.push(proof.commitOid);
    if (proof.status === 'not_reachable' && typeof proof.commitOid === 'string') proofNotReachable.push(proof.commitOid);
  }

  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} reachableFixCommits`, reachableFixCommits, uniqueSorted(proofReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} notReachableFixCommits`, notReachableFixCommits, uniqueSorted(proofNotReachable));
  expect(failures, tag, evidence.hasReachableFixCommit === (reachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasReachableFixCommit must match reachableFixCommits`);
  expect(failures, tag, evidence.hasNotReachableFixCommit === (notReachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasNotReachableFixCommit must match notReachableFixCommits`);
}

function verifyCommitArray({ failures, tag, issueNumber, name, commits }) {
  for (const commit of commits) {
    expect(failures, tag, fullCommitOidRe.test(commit),
      `proof issue #${issueNumber} ${name} entries must be full lowercase 40-hex SHAs`);
  }
  expectArrayEqual(failures, tag, `proof issue #${issueNumber} ${name}`, commits, uniqueSorted(commits));
}

function parseJson(raw, fallback) {
  try {
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function expect(failures, tag, condition, message) {
  if (!condition) failures.push(`${tag}: ${message}`);
}

function expectArrayEqual(failures, tag, label, actual, expected) {
  expect(failures, tag, actual.length === expected.length && actual.every((item, idx) => item === expected[idx]),
    `${label} must equal sorted unique proof commits; got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function expectJsonEqual(failures, tag, message, actual, expected) {
  expect(failures, tag, stableJson(actual) === stableJson(expected), message);
}

function stableJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
}

function isObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function normalizeStringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function intersection(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => rightSet.has(item));
}

async function verifyApi({ apiBase, fetchJson, releases, failures }) {
  const status = await fetchJson(`${apiBase}/api/status`);
  expect(failures, 'api/status', status.refreshing === false, `refreshing must be false, got ${status.refreshing}`);
  expect(failures, 'api/status', status.lastError == null, `lastError must be null, got ${status.lastError}`);
  if (status.lastScoredAt) {
    expect(failures, 'api/status', status.lastRefreshAt === status.lastScoredAt,
      `lastRefreshAt (${status.lastRefreshAt}) must equal lastScoredAt (${status.lastScoredAt})`);
  }

  const publicPayload = await fetchJson(`${apiBase}/api/public`);
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('comparison'), 'public payload must not include comparison data');
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('upstream'), 'public payload must not include upstream data');
  if (status.lastScoredAt) {
    expect(failures, 'api/public', publicPayload.updatedAt === status.lastScoredAt,
      `public updatedAt (${publicPayload.updatedAt}) must equal status lastScoredAt (${status.lastScoredAt})`);
  }

  const releasesPayload = await fetchJson(`${apiBase}/api/releases`);
  const releaseApiByTag = new Map((Array.isArray(releasesPayload) ? releasesPayload : []).map((release) => [release.tag, release]));
  const publicByTag = new Map((publicPayload.releases ?? []).map((release) => [release.tag, release]));
  const comparisonPayload = await fetchJson(`${apiBase}/api/comparison`);
  verifyComparisonSnapshot({ failures, label: 'api/comparison', snapshot: comparisonPayload.snapshot });
  const comparisonByTag = new Map((comparisonPayload.releases ?? []).map((release) => [release.tag, release]));

  for (const release of releases) {
    const releaseApi = releaseApiByTag.get(release.tag);
    expect(failures, release.tag, !!releaseApi, 'releases API must include monitored release');
    if (releaseApi) {
      expect(failures, release.tag, releaseApi.finalScore === release.final_score,
        `releases finalScore (${releaseApi.finalScore}) must match DB final_score (${release.final_score})`);
      expect(failures, release.tag, releaseApi.status === release.state,
        `releases status (${releaseApi.status}) must match DB state (${release.state})`);
      expect(failures, release.tag, releaseApi.recommended === (release.recommended === 1),
        `releases recommended (${releaseApi.recommended}) must match DB recommended (${release.recommended === 1})`);
      expect(failures, release.tag, releaseApi.scoredAt === release.scored_at,
        `releases scoredAt (${releaseApi.scoredAt}) must match DB scored_at (${release.scored_at})`);
      verifyScoreAuditSummary({ failures, tag: release.tag, summary: releaseApi.scoreAudit });
      verifyScoreExplanation({
        failures,
        tag: release.tag,
        explanation: releaseApi.explanation,
        recommended: release.recommended === 1,
        source: 'releases',
      });
    }

    const publicRelease = publicByTag.get(release.tag);
    expect(failures, release.tag, !!publicRelease, 'public API must include monitored release');
    if (publicRelease) {
      expect(failures, release.tag, publicRelease.score === release.final_score,
        `public score (${publicRelease.score}) must match DB final_score (${release.final_score})`);
      expect(failures, release.tag, publicRelease.status === release.state,
        `public status (${publicRelease.status}) must match DB state (${release.state})`);
      expect(failures, release.tag, publicRelease.recommended === (release.recommended === 1),
        `public recommended (${publicRelease.recommended}) must match DB recommended (${release.recommended === 1})`);
      expect(failures, release.tag, publicRelease.scoredAt === release.scored_at,
        `public scoredAt (${publicRelease.scoredAt}) must match DB scored_at (${release.scored_at})`);
      verifyScoreAuditSummary({ failures, tag: release.tag, summary: publicRelease.scoreAudit });
      const issueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
      if (publicRelease.totalAttributedIssues > 0) {
        expect(failures, release.tag, issueCount > 0,
          'public release with attributed issues must expose capped issue summaries');
      }
      verifyScoreExplanation({
        failures,
        tag: release.tag,
        explanation: publicRelease.explanation,
        recommended: release.recommended === 1,
        source: 'public',
      });
    }

    const comparison = comparisonByTag.get(release.tag);
    expect(failures, release.tag, !!comparison?.local && 'upstream' in comparison && !!comparison?.delta,
      'comparison payload must include local, upstream, and delta objects');

    const review = await fetchJson(`${apiBase}/api/releases/${encodeURIComponent(release.tag)}/review`);
    verifyComparisonSnapshot({ failures, label: `${release.tag} review`, snapshot: review.snapshot });
    expect(failures, release.tag, review.local?.score === release.final_score,
      `review score (${review.local?.score}) must match DB final_score (${release.final_score})`);
    expect(failures, release.tag, review.local?.status === release.state,
      `review status (${review.local?.status}) must match DB state (${release.state})`);
    expect(failures, release.tag, review.local?.recommended === (release.recommended === 1),
      `review recommended (${review.local?.recommended}) must match DB recommended (${release.recommended === 1})`);
    verifyScoreExplanation({
      failures,
      tag: release.tag,
      explanation: review.local?.components?.explanation,
      recommended: release.recommended === 1,
      source: 'review',
    });
    if (releaseApi) {
      expectJsonEqual(failures, release.tag, 'releases explanation must match review explanation',
        releaseApi.explanation, review.local?.components?.explanation);
    }
    if (publicRelease) {
      expectJsonEqual(failures, release.tag, 'public explanation must match review explanation',
        publicRelease.explanation, review.local?.components?.explanation);
    }
    if (comparison?.local) {
      expectJsonEqual(failures, release.tag, 'comparison local explanation must match review explanation',
        comparison.local.components?.explanation, review.local?.components?.explanation);
    }

    const proof = review.local?.gateEvidence?.fixProvenance?.closureProof;
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (proof || credit) {
      expect(failures, release.tag, !!proof && !!credit, 'review must expose closureProof and releaseFixCredit together');
      expect(failures, release.tag, credit.countedClosedCount === proof.creditedCount,
        'releaseFixCredit countedClosedCount must match closureProof creditedCount');
      expect(failures, release.tag, credit.notCountedClosedCount === proof.notCreditedCount,
        'releaseFixCredit notCountedClosedCount must match closureProof notCreditedCount');
      expect(failures, release.tag, credit.analyzedClosedCount === proof.creditedCount + proof.notCreditedCount,
        'releaseFixCredit analyzedClosedCount must equal credited + notCredited');
      expect(failures, release.tag, (proof.byStatus?.fixed_in_release ?? 0) === proof.creditedCount,
        'closureProof creditedCount must equal fixed_in_release bucket');

      const comparisonFix = comparison?.local?.gateEvidence?.fixProvenance;
      const comparisonProof = comparisonFix?.closureProof;
      const comparisonCredit = comparisonFix?.releaseFixCredit;
      expect(failures, release.tag, !!comparisonProof && !!comparisonCredit,
        'comparison local gateEvidence must expose closureProof and releaseFixCredit when review does');
      expect(failures, release.tag, comparisonCredit?.countedClosedCount === credit.countedClosedCount,
        'comparison countedClosedCount must match review countedClosedCount');
      expect(failures, release.tag, comparisonCredit?.notCountedClosedCount === credit.notCountedClosedCount,
        'comparison notCountedClosedCount must match review notCountedClosedCount');
      expect(failures, release.tag, comparisonProof?.creditedCount === proof.creditedCount,
        'comparison closureProof creditedCount must match review');
      expect(failures, release.tag, comparisonProof?.notCreditedCount === proof.notCreditedCount,
        'comparison closureProof notCreditedCount must match review');
    }
  }
}

function verifyComparisonSnapshot({ failures, label, snapshot }) {
  if (snapshot == null) return;
  expect(failures, label, typeof snapshot.id === 'number', 'comparison snapshot id must be numeric');
  expect(failures, label, typeof snapshot.sourceUrl === 'string' && snapshot.sourceUrl.length > 0,
    'comparison snapshot sourceUrl must be present');
  expect(failures, label, typeof snapshot.capturedAt === 'string' && snapshot.capturedAt.length > 0,
    'comparison snapshot capturedAt must be present');
  expect(failures, label, typeof snapshot.pageTitle === 'string',
    'comparison snapshot pageTitle must be present');
  expect(failures, label, !('source_url' in snapshot) && !('captured_at' in snapshot) && !('page_text' in snapshot),
    'comparison snapshot must use normalized camelCase fields and omit page_text');
}

async function defaultFetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}

function verifyScoreAuditSummary({ failures, tag, summary }) {
  expect(failures, tag, !!summary, 'scoreAudit summary must be present');
  if (!summary) return;
  expect(failures, tag, typeof summary.modelVersion === 'string' && summary.modelVersion.length > 0,
    'scoreAudit modelVersion must be present');
  expect(failures, tag, Number.isInteger(summary.promptVersion),
    'scoreAudit promptVersion must be an integer');
  expect(failures, tag, typeof summary.evidenceCoverage === 'number' && summary.evidenceCoverage >= 0 && summary.evidenceCoverage <= 1,
    `scoreAudit evidenceCoverage must be in [0,1], got ${summary.evidenceCoverage}`);
  expect(failures, tag, Number.isInteger(summary.rawIssueCount) && summary.rawIssueCount >= 0,
    `scoreAudit rawIssueCount must be a non-negative integer, got ${summary.rawIssueCount}`);
  expect(failures, tag, Number.isInteger(summary.classifiedIssueCount) && summary.classifiedIssueCount >= 0,
    `scoreAudit classifiedIssueCount must be a non-negative integer, got ${summary.classifiedIssueCount}`);
}

function verifyScoreExplanation({ failures, tag, explanation, recommended, source }) {
  expect(failures, tag, isObject(explanation), `${source} score explanation must be present`);
  if (!isObject(explanation)) return;
  expect(failures, tag, explanation.schemaVersion === scoreExplanationSchemaVersion,
    `${source} score explanation schemaVersion must be ${scoreExplanationSchemaVersion}, got ${JSON.stringify(explanation.schemaVersion)}`);
  expect(failures, tag, explanation.title === 'Why not 10?',
    `${source} score explanation title must be "Why not 10?", got ${JSON.stringify(explanation.title)}`);
  expect(failures, tag, isStringArray(explanation.positives) && explanation.positives.length > 0,
    `${source} score explanation positives must be a non-empty string array`);
  expect(failures, tag, isStringArray(explanation.limits) && explanation.limits.length > 0,
    `${source} score explanation limits must be a non-empty string array`);
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'positiveDetails',
    details: explanation.positiveDetails,
    text: explanation.positives,
  });
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'limitDetails',
    details: explanation.limitDetails,
    text: explanation.limits,
  });
  expect(failures, tag, typeof explanation.verdict === 'string' && explanation.verdict.length > 0,
    `${source} score explanation verdict must be present`);
  if (recommended) {
    expect(failures, tag, explanation.positives.some((line) => /recommended/i.test(line)),
      `${source} recommended release explanation must include a recommended positive signal`);
  }
  expect(failures, tag, !/looks safe to install|safe target|broadly safe/i.test(explanation.verdict),
    `${source} score explanation verdict must not overclaim safety`);
  for (const line of [...explanation.positives, ...explanation.limits]) {
    expect(failures, tag, !/\.\.\.\./.test(line), `${source} score explanation lines must not contain four-dot truncation`);
  }
}

function verifyExplanationDetails({ failures, tag, source, label, details, text }) {
  expect(failures, tag, Array.isArray(details),
    `${source} score explanation ${label} must be an array`);
  if (!Array.isArray(details)) return;
  expect(failures, tag, details.length === text.length,
    `${source} score explanation ${label} length (${details.length}) must match text length (${text.length})`);
  for (let idx = 0; idx < details.length; idx++) {
    const detail = details[idx];
    expect(failures, tag, isObject(detail),
      `${source} score explanation ${label}[${idx}] must be an object`);
    if (!isObject(detail)) continue;
    expect(failures, tag, typeof detail.code === 'string' && /^[a-z0-9_]+$/.test(detail.code),
      `${source} score explanation ${label}[${idx}] code must be snake_case`);
    expect(failures, tag, knownExplanationCodes.has(detail.code),
      `${source} score explanation ${label}[${idx}] code ${JSON.stringify(detail.code)} must be known`);
    expect(failures, tag, detail.text === text[idx],
      `${source} score explanation ${label}[${idx}] text must match prose line`);
    if ('metrics' in detail) {
      expect(failures, tag, isObject(detail.metrics),
        `${source} score explanation ${label}[${idx}] metrics must be an object when present`);
    }
    if ('buckets' in detail) {
      expect(failures, tag, isObject(detail.buckets),
        `${source} score explanation ${label}[${idx}] buckets must be an object when present`);
    }
    if ('issueRefs' in detail) {
      expect(failures, tag, Array.isArray(detail.issueRefs),
        `${source} score explanation ${label}[${idx}] issueRefs must be an array when present`);
      if (Array.isArray(detail.issueRefs)) {
        for (const issue of detail.issueRefs) {
          expect(failures, tag, isObject(issue) && Number.isInteger(issue.number) && issue.number > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a positive issue number`);
          expect(failures, tag, isObject(issue) && typeof issue.title === 'string' && issue.title.length > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a title`);
          expect(failures, tag, isObject(issue) && (issue.url == null || typeof issue.url === 'string'),
            `${source} score explanation ${label}[${idx}] issueRefs url must be null or string`);
        }
      }
    }
  }
}
