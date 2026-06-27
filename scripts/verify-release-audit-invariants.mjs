import {
  closedDuringReign,
  db,
  getReleaseScoreAudit,
  listReleasesDb,
  unverifiedClosedForRelease,
  verifiedFixedForRelease,
} from '../src/lib/db.ts';

const limit = Number(process.env.RELEASES_LIMIT ?? 10);
const apiBase = process.argv.includes('--api-base')
  ? process.argv[process.argv.indexOf('--api-base') + 1]
  : process.env.API_BASE;
const releases = listReleasesDb(limit);
const failures = [];
const rows = [];

const knownStatuses = new Set([
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

for (const release of releases) {
  const tag = release.tag;
  const closed = closedDuringReign(tag);
  const verified = verifiedFixedForRelease(tag);
  const unverified = unverifiedClosedForRelease(tag);
  const proofRows = proofRowsFor(tag);
  const proofCounts = countBy(proofRows, (row) => row.status);
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

  expect(tag, closed.length === verified.length + unverified.length,
    `closedDuringReign (${closed.length}) must equal verified + unverified (${verified.length + unverified.length})`);
  expect(tag, proofRows.length === closed.length,
    `closure proofs (${proofRows.length}) must cover closed release-window issues (${closed.length})`);
  expect(tag, fixedProof.length + notCountedProof.length === proofRows.length,
    'counted + not-counted proof rows must equal all proof rows');

  const verifiedNumbers = new Set(verified.map((row) => row.number));
  const proofByNumber = new Map(proofRows.map((row) => [row.issue_number, row]));
  for (const row of fixedProof) {
    expect(tag, verifiedNumbers.has(row.issue_number),
      `fixed_in_release issue #${row.issue_number} must be present in verifiedFixedForRelease`);
  }

  for (const row of verified) {
    const proof = proofByNumber.get(row.number);
    if (!proof) continue;
    const evidence = parseJson(proof.evidence_json, {});
    if (proof.status !== 'fixed_in_release') {
      expect(tag, row.sentiment !== 'negative',
        `verified issue #${row.number} has proof status ${proof.status}; only non-negative verified closures may avoid fixed_in_release`);
    }
    expect(tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
      `verified issue #${row.number} must have final COMPLETED closure evidence`);
  }

  for (const row of proofRows) {
    expect(tag, knownStatuses.has(row.status), `unknown proof status ${row.status} for issue #${row.issue_number}`);
    const evidence = parseJson(row.evidence_json, {});
    if (row.status === 'fixed_in_release') {
      expect(tag, evidence.hasReachableClosingPr === true,
        `fixed_in_release issue #${row.issue_number} must have reachable PR evidence`);
      expect(tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
        `fixed_in_release issue #${row.issue_number} must have COMPLETED state reason`);
    }
    if (row.status === 'fixed_after_release') {
      expect(tag, evidence.hasNotReachableClosingPr === true,
        `fixed_after_release issue #${row.issue_number} must have not-reachable PR evidence`);
      expect(tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
        `fixed_after_release issue #${row.issue_number} must have COMPLETED state reason`);
    }
    if (row.status === 'duplicate_to_open_canonical') {
      expect(tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
        `duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
    }
    if (row.status === 'duplicate_to_closed_canonical') {
      expect(tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
        `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
    }
    if (row.status === 'canonical_cycle_or_self_reference') {
      expect(tag, evidence.canonicalResolution?.cycle === true || evidence.canonicalResolution?.selfReference === true,
        `canonical_cycle_or_self_reference issue #${row.issue_number} must record cycle/self-reference evidence`);
    }
  }

  const audit = getReleaseScoreAudit(tag);
  if (audit) {
    const gate = parseJson(audit.gate_evidence_json, {});
    const fix = gate.fixProvenance ?? {};
    expect(tag, fix.verifiedFixedCount === verified.length,
      `audit verifiedFixedCount (${fix.verifiedFixedCount}) must match verifiedFixedForRelease (${verified.length})`);
    expect(tag, fix.unverifiedClosedCount === unverified.length,
      `audit unverifiedClosedCount (${fix.unverifiedClosedCount}) must match unverifiedClosedForRelease (${unverified.length})`);
  } else {
    expect(tag, false, 'release score audit row is missing');
  }

  for (const [status, count] of Object.entries(proofCounts)) {
    if (count < 0) expect(tag, false, `invalid negative count for ${status}`);
  }
}

if (apiBase) {
  await verifyApi(apiBase.replace(/\/$/, ''));
}

console.table(rows);
if (failures.length) {
  console.error(`\n${failures.length} release audit invariant failure(s):`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log(`\nRelease audit invariants passed for ${releases.length} release(s).`);

function proofRowsFor(tag) {
  return db.prepare(`
    SELECT release_tag, issue_number, status, summary, evidence_json, checked_at
    FROM issue_closure_proofs
    WHERE release_tag=?
    ORDER BY issue_number
  `).all(tag);
}

function parseJson(raw, fallback) {
  try {
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function countBy(items, fn) {
  const counts = {};
  for (const item of items) {
    const key = fn(item);
    counts[key] = (counts[key] ?? 0) + 1;
  }
  return counts;
}

function expect(tag, condition, message) {
  if (!condition) failures.push(`${tag}: ${message}`);
}

async function verifyApi(base) {
  const status = await fetchJson(`${base}/api/status`);
  expect('api/status', status.refreshing === false, `refreshing must be false, got ${status.refreshing}`);
  expect('api/status', status.lastError == null, `lastError must be null, got ${status.lastError}`);
  if (status.lastScoredAt) {
    expect('api/status', status.lastRefreshAt === status.lastScoredAt,
      `lastRefreshAt (${status.lastRefreshAt}) must equal lastScoredAt (${status.lastScoredAt})`);
  }

  const publicPayload = await fetchJson(`${base}/api/public`);
  expect('api/public', !JSON.stringify(publicPayload).includes('comparison'), 'public payload must not include comparison data');
  expect('api/public', !JSON.stringify(publicPayload).includes('upstream'), 'public payload must not include upstream data');

  for (const release of releases) {
    const review = await fetchJson(`${base}/api/releases/${encodeURIComponent(release.tag)}/review`);
    expect(release.tag, review.local?.score === release.final_score,
      `review score (${review.local?.score}) must match DB final_score (${release.final_score})`);
    expect(release.tag, review.local?.status === release.state,
      `review status (${review.local?.status}) must match DB state (${release.state})`);
    expect(release.tag, review.local?.recommended === (release.recommended === 1),
      `review recommended (${review.local?.recommended}) must match DB recommended (${release.recommended === 1})`);

    const proof = review.local?.gateEvidence?.fixProvenance?.closureProof;
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (proof || credit) {
      expect(release.tag, !!proof && !!credit, 'review must expose closureProof and releaseFixCredit together');
      expect(release.tag, credit.countedClosedCount === proof.creditedCount,
        'releaseFixCredit countedClosedCount must match closureProof creditedCount');
      expect(release.tag, credit.notCountedClosedCount === proof.notCreditedCount,
        'releaseFixCredit notCountedClosedCount must match closureProof notCreditedCount');
      expect(release.tag, credit.analyzedClosedCount === proof.creditedCount + proof.notCreditedCount,
        'releaseFixCredit analyzedClosedCount must equal credited + notCredited');
      expect(release.tag, (proof.byStatus?.fixed_in_release ?? 0) === proof.creditedCount,
        'closureProof creditedCount must equal fixed_in_release bucket');
    }
  }
}

async function fetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}`);
  return res.json();
}
