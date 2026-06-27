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
  'no_code_proof',
  'no_timeline_event',
  'non_bug_neutral',
  'unknown',
]);

export async function verifyReleaseAudit({ reader, apiBase = null, fetchJson = defaultFetchJson, limit = 10 }) {
  const releases = reader.listReleases(limit);
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
      if (row.status === 'fixed_in_release') {
        expect(failures, tag, evidence.hasReachableClosingPr === true,
          `fixed_in_release issue #${row.issue_number} must have reachable PR evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_after_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true,
          `fixed_after_release issue #${row.issue_number} must have not-reachable PR evidence`);
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
