import {
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
} from '../../src/lib/labelOverrides.ts';

export const knownProofStatuses = new Set([
  'fixed_in_release',
  'fixed_after_release',
  'duplicate_to_fixed_in_release',
  'duplicate_to_open_canonical',
  'duplicate_to_closed_canonical',
  'duplicate_to_fixed_after_release',
  'canonical_cycle_or_self_reference',
  'duplicate_or_superseded',
  'not_planned',
  'already_present_claim',
  'main_only_claim',
  'reporter_replaced',
  'reporter_withdrawn',
  'reporter_self_closed',
  'repro_requested',
  'no_code_proof',
  'no_timeline_event',
  'non_bug_neutral',
  'unknown',
]);

const knownCommitProofStatuses = new Set(['reachable', 'not_reachable', 'unknown']);
const knownRiskDispositions = new Set([
  'credited_release_fix',
  'resolved_by_canonical_release_fix',
  'known_not_in_release',
  'open_canonical_risk',
  'unsupported_closure_claim',
  'neutral_or_non_actionable',
  'missing_evidence',
]);
const riskDispositionByProofStatus = new Map([
  ['fixed_in_release', 'credited_release_fix'],
  ['duplicate_to_fixed_in_release', 'resolved_by_canonical_release_fix'],
  ['fixed_after_release', 'known_not_in_release'],
  ['main_only_claim', 'known_not_in_release'],
  ['duplicate_to_fixed_after_release', 'known_not_in_release'],
  ['duplicate_to_open_canonical', 'open_canonical_risk'],
  ['duplicate_to_closed_canonical', 'unsupported_closure_claim'],
  ['canonical_cycle_or_self_reference', 'unsupported_closure_claim'],
  ['duplicate_or_superseded', 'unsupported_closure_claim'],
  ['already_present_claim', 'unsupported_closure_claim'],
  ['repro_requested', 'unsupported_closure_claim'],
  ['no_code_proof', 'unsupported_closure_claim'],
  ['non_bug_neutral', 'neutral_or_non_actionable'],
  ['not_planned', 'neutral_or_non_actionable'],
  ['reporter_replaced', 'neutral_or_non_actionable'],
  ['reporter_withdrawn', 'neutral_or_non_actionable'],
  ['reporter_self_closed', 'neutral_or_non_actionable'],
  ['no_timeline_event', 'missing_evidence'],
  ['unknown', 'missing_evidence'],
]);
const riskDispositionWeights = new Map([
  ['credited_release_fix', 0],
  ['resolved_by_canonical_release_fix', 0],
  ['known_not_in_release', 1],
  ['open_canonical_risk', 1.2],
  ['unsupported_closure_claim', 0.8],
  ['neutral_or_non_actionable', 0],
  ['missing_evidence', 1.5],
]);
const severityRiskWeights = new Map([
  ['critical', 4],
  ['high', 2.5],
  ['medium', 0.8],
  ['low', 0],
]);
const functionalityRiskWeights = new Map([
  ['core', 1.25],
  ['integration', 1],
  ['provider', 0.8],
  ['docs', 0],
]);
const scopeRiskWeights = new Map([
  ['broad', 1.5],
  ['moderate', 1],
  ['niche', 0.4],
]);
const affectedUserRiskWeights = new Map([
  ['many', 1.3],
  ['some', 0.85],
  ['few', 0.35],
  ['unknown', 0.65],
]);
const fullCommitOidRe = /^[0-9a-f]{40}$/;
const knownCommitProofSources = new Set(['ClosureComment.fixProof', 'ClosedEvent.closer', 'ReferencedEvent.commit']);
const bugShapedTitleRe = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall)\b/i;
const scoreInputSchemaVersion = 1;
const scoreComponentsSchemaVersion = 1;
const gateEvidenceSchemaVersion = 1;
const closureProofSchemaVersion = 1;
const releaseFixCreditSchemaVersion = 1;
const issueEvidenceSchemaVersion = 1;
const labelTimelineSchemaVersion = 1;
const releaseChecksSchemaVersion = 1;
const artifactVerificationSchemaVersion = 1;
const scoreExplanationSchemaVersion = 1;
const publicPayloadSchemaVersion = 1;
const knownExplanationCodes = new Set([
  'field_visible_reports_opened',
  'source_carryover_risk',
  'stale_low_confidence_evidence',
  'incomplete_classification_coverage',
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
const publicTopLevelKeys = new Set(['repo', 'releases', 'schemaVersion', 'updatedAt']);
const publicReleaseKeys = new Set([
  'band',
  'explanation',
  'issues',
  'negativeIssues',
  'positiveIssues',
  'publishedAt',
  'reason',
  'recommended',
  'score',
  'scoreAudit',
  'scoredAt',
  'status',
  'tag',
  'totalAttributedIssues',
  'url',
  'watchIssues',
]);
const publicIssueKeys = new Set([
  'affectedUsers',
  'closedAt',
  'confidence',
  'hasWorkaround',
  'number',
  'rationale',
  'scope',
  'sentiment',
  'severity',
  'state',
  'surface',
  'title',
  'url',
]);
const publicSentimentRank = new Map([['negative', 0], ['positive', 1], ['neutral', 2]]);
const publicSeverityRank = new Map([['critical', 0], ['high', 1], ['medium', 2], ['low', 3]]);
const publicScopeRank = new Map([['broad', 0], ['moderate', 1], ['niche', 2]]);
const publicAffectedUsersRank = new Map([['many', 0], ['some', 1], ['few', 2], ['unknown', 3]]);
const forbiddenPublicKeys = new Set([
  'comparison',
  'delta',
  'local',
  'pageText',
  'rawCardText',
  'snapshot',
  'sourceUrl',
  'upstream',
]);

export async function verifyReleaseAudit({ reader, apiBase = null, fetchJson = defaultFetchJson, limit = 10, scoredOnly = false }) {
  const releases = reader.listReleases(limit, { scoredOnly });
  const failures = [];
  const rows = [];

  for (const release of releases) {
    const tag = release.tag;
    const closed = reader.closedDuringReign(tag);
    const rawClosed = typeof reader.rawClosedDuringReign === 'function'
      ? reader.rawClosedDuringReign(tag)
      : closed;
    const verified = reader.verifiedFixedForRelease(tag);
    const unverified = reader.unverifiedClosedForRelease(tag);
    const proofRows = reader.proofRowsFor(tag);
    const sourceFreshnessRows = typeof reader.sourceFreshnessFor === 'function'
      ? reader.sourceFreshnessFor(tag)
      : [];
    const fixedProof = proofRows.filter((row) => row.status === 'fixed_in_release');
    const notCountedProof = proofRows.filter((row) => row.status !== 'fixed_in_release');
    const releaseIsScored = release.final_score != null || release.score != null ||
      release.scored_at != null || release.scoredAt != null;
    const enforceRawClosedCoverage = releaseIsScored || proofRows.length > 0;

    rows.push({
      tag,
      closed: closed.length,
      verified: verified.length,
      unverified: unverified.length,
      proof: proofRows.length,
      counted: fixedProof.length,
      notCounted: notCountedProof.length,
    });

    if (enforceRawClosedCoverage) {
      expect(failures, tag, rawClosed.length === closed.length,
        `raw closed release-window issues (${rawClosed.length}) must equal classified closed issues (${closed.length})`);
    }
    expect(failures, tag, closed.length === verified.length + unverified.length,
      `closedDuringReign (${closed.length}) must equal verified + unverified (${verified.length + unverified.length})`);
    expect(failures, tag, proofRows.length === (enforceRawClosedCoverage ? rawClosed.length : closed.length),
      enforceRawClosedCoverage
        ? `closure proofs (${proofRows.length}) must cover raw closed release-window issues (${rawClosed.length})`
        : `closure proofs (${proofRows.length}) must cover classified closed release-window issues (${closed.length})`);
    expect(failures, tag, fixedProof.length + notCountedProof.length === proofRows.length,
      'counted + not-counted proof rows must equal all proof rows');

    const verifiedNumbers = new Set(verified.map((row) => row.number));
    const rawClosedNumbers = new Set(rawClosed.map((row) => row.number));
    const proofByNumber = new Map(proofRows.map((row) => [row.issue_number, row]));
    for (const row of proofRows) {
      expect(failures, tag, rawClosedNumbers.has(row.issue_number),
        `proof issue #${row.issue_number} must belong to the raw closed release window`);
    }
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
      const prEvidence = typeof reader.prReachabilityEvidenceForIssue === 'function'
        ? reader.prReachabilityEvidenceForIssue(tag, row.issue_number)
        : [];
      verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence });
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
      if (row.status === 'duplicate_to_fixed_after_release') {
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_after_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'not_reachable'),
          `duplicate_to_fixed_after_release issue #${row.issue_number} must resolve to fixed-after canonical proof`);
      }
      if (row.status === 'duplicate_to_fixed_in_release') {
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_in_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'reachable'),
        `duplicate_to_fixed_in_release issue #${row.issue_number} must resolve to fixed-in-release canonical proof`);
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
      const scoreInput = parseJson(audit.input_json, {});
      const scoreComponents = parseJson(audit.components_json, {});
      const gate = parseJson(audit.gate_evidence_json, {});
      const issueEvidence = parseJson(audit.issue_evidence_json, {});
      expect(failures, tag, scoreInput.schemaVersion === scoreInputSchemaVersion,
        `persisted score input schemaVersion (${scoreInput.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
      expect(failures, tag, scoreComponents.schemaVersion === scoreComponentsSchemaVersion,
        `persisted score components schemaVersion (${scoreComponents.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
      expect(failures, tag, gate.schemaVersion === gateEvidenceSchemaVersion,
        `persisted gateEvidence schemaVersion (${gate.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
      verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit });
      verifyLabelTimelineGate({ failures, tag, labelTimeline: gate.labelTimeline });
      verifyReleaseChecksGate({ failures, tag, releaseChecks: gate.releaseChecks });
      verifyArtifactVerificationGate({ failures, tag, artifactVerification: gate.artifactVerification });
      verifyClosedClassificationPromptVersion({ failures, tag, closed, audit });
      verifyProofFreshness({ failures, tag, proofRows, audit });
      expect(failures, tag, issueEvidence.schemaVersion === issueEvidenceSchemaVersion,
        `persisted issueEvidence schemaVersion (${issueEvidence.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    const fix = gate.fixProvenance ?? {};
    expect(failures, tag, fix.verifiedFixedCount === verified.length,
      `audit verifiedFixedCount (${fix.verifiedFixedCount}) must match verifiedFixedForRelease (${verified.length})`);
    expect(failures, tag, fix.unverifiedClosedCount === unverified.length,
      `audit unverifiedClosedCount (${fix.unverifiedClosedCount}) must match unverifiedClosedForRelease (${unverified.length})`);
    if (proofRows.length) {
      expect(failures, tag, !!fix.closureProof && !!fix.releaseFixCredit,
        'persisted audit gateEvidence must include closureProof and releaseFixCredit when proof rows exist');
      if (fix.closureProof && fix.releaseFixCredit) {
        const expectedRisk = riskSummaryForProofRows(proofRows);
        expect(failures, tag, fix.closureProof.schemaVersion === closureProofSchemaVersion,
          `persisted closureProof schemaVersion (${fix.closureProof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
        expect(failures, tag, fix.releaseFixCredit.schemaVersion === releaseFixCreditSchemaVersion,
          `persisted releaseFixCredit schemaVersion (${fix.releaseFixCredit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
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
        expectJsonEqual(failures, tag, 'persisted closureProof byRiskDisposition must match proof row dispositions',
          fix.closureProof.byRiskDisposition, expectedRisk.counts);
        expectJsonEqual(failures, tag, 'persisted closureProof riskSummary must match proof row dispositions',
          fix.closureProof.riskSummary, expectedRisk.summary);
        for (const [disposition] of Object.entries(fix.closureProof.byRiskDisposition ?? {})) {
          expect(failures, tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
        verifyClosureProofExamplesByStatus({
          failures,
          tag,
          proof: fix.closureProof,
          label: 'persisted closureProof',
        });
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

function verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  for (const row of sourceFreshnessRows ?? []) {
    if (!row?.max_ts) continue;
    const sourceAt = Date.parse(row.max_ts);
    expect(failures, tag, Number.isFinite(sourceAt),
      `${row.source} max timestamp must be valid, got ${row.max_ts}`);
    if (!Number.isFinite(sourceAt)) continue;
    expect(failures, tag, sourceAt <= scoredAt,
      `${row.source} changed at ${row.max_ts}, newer than audit scored_at ${audit.scored_at}`);
  }
}

function verifyLabelTimelineGate({ failures, tag, labelTimeline }) {
  expect(failures, tag, isObject(labelTimeline), 'persisted audit gateEvidence must include labelTimeline coverage');
  if (!isObject(labelTimeline)) return;
  expect(failures, tag, labelTimeline.schemaVersion === labelTimelineSchemaVersion,
    `labelTimeline schemaVersion (${labelTimeline.schemaVersion}) must equal ${labelTimelineSchemaVersion}`);
  for (const key of ['issueCount', 'currentLabelCount', 'timelineLabelCount', 'snapshotLabelCount', 'missingTimelineCount', 'missingTimelineWithCurrentLabelsCount']) {
    expect(failures, tag, Number.isInteger(labelTimeline[key]) && labelTimeline[key] >= 0,
      `labelTimeline ${key} must be a non-negative integer`);
  }
  const sourceTotal = Number(labelTimeline.currentLabelCount ?? -1) +
    Number(labelTimeline.timelineLabelCount ?? -1) +
    Number(labelTimeline.snapshotLabelCount ?? -1) +
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

function verifyReleaseChecksGate({ failures, tag, releaseChecks }) {
  if (releaseChecks == null) return;
  expect(failures, tag, isObject(releaseChecks), 'releaseChecks must be an object or null');
  if (!isObject(releaseChecks)) return;
  expect(failures, tag, releaseChecks.schemaVersion === releaseChecksSchemaVersion,
    `releaseChecks schemaVersion (${releaseChecks.schemaVersion}) must equal ${releaseChecksSchemaVersion}`);
  for (const key of ['total', 'success', 'failure', 'pending', 'skipped']) {
    expect(failures, tag, Number.isInteger(releaseChecks[key]) && releaseChecks[key] >= 0,
      `releaseChecks ${key} must be a non-negative integer`);
  }
  const counted = Number(releaseChecks.success ?? -1) + Number(releaseChecks.failure ?? -1) +
    Number(releaseChecks.pending ?? -1) + Number(releaseChecks.skipped ?? -1);
  expect(failures, tag, counted === releaseChecks.total,
    `releaseChecks counted contexts (${counted}) must equal total (${releaseChecks.total})`);
  expect(failures, tag, Array.isArray(releaseChecks.contexts),
    'releaseChecks contexts must be an array');
}

function verifyArtifactVerificationGate({ failures, tag, artifactVerification }) {
  expect(failures, tag, isObject(artifactVerification), 'artifactVerification must be an object');
  if (!isObject(artifactVerification)) return;
  expect(failures, tag, artifactVerification.schemaVersion === artifactVerificationSchemaVersion,
    `artifactVerification schemaVersion (${artifactVerification.schemaVersion}) must equal ${artifactVerificationSchemaVersion}`);
  expect(failures, tag, typeof artifactVerification.verified === 'boolean',
    'artifactVerification verified must be boolean');
  if (artifactVerification.releaseShaMatches != null) {
    expect(failures, tag, typeof artifactVerification.releaseShaMatches === 'boolean',
      'artifactVerification releaseShaMatches must be boolean or null');
  }
  expect(failures, tag, typeof artifactVerification.ciReportVerified === 'boolean',
    'artifactVerification ciReportVerified must be boolean');
  expect(failures, tag, typeof artifactVerification.releaseValidationVerified === 'boolean',
    'artifactVerification releaseValidationVerified must be boolean');
}

function verifyClosedClassificationPromptVersion({ failures, tag, closed, audit }) {
  const expected = Number(audit.prompt_version);
  expect(failures, tag, Number.isInteger(expected) && expected >= 0,
    `audit prompt_version must be a non-negative integer, got ${audit.prompt_version}`);
  if (!Number.isInteger(expected)) return;
  for (const row of closed) {
    expect(failures, tag, Number(row.prompt_version) === expected,
      `closed issue #${row.number} classification prompt_version (${row.prompt_version}) must match audit prompt_version (${expected})`);
  }
}

function verifyProofFreshness({ failures, tag, proofRows, audit }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  for (const row of proofRows) {
    const checkedAt = Date.parse(row.checked_at ?? '');
    expect(failures, tag, Number.isFinite(checkedAt),
      `proof issue #${row.issue_number} checked_at must be a valid timestamp`);
    if (!Number.isFinite(checkedAt)) continue;
    expect(failures, tag, checkedAt <= scoredAt,
      `proof issue #${row.issue_number} checked_at (${row.checked_at}) must not be newer than audit scored_at (${audit.scored_at})`);
    const evidence = parseJson(row.evidence_json, {});
    const closedAt = evidence?.closedAt ? Date.parse(evidence.closedAt) : NaN;
    if (Number.isFinite(closedAt)) {
      expect(failures, tag, checkedAt >= closedAt,
        `proof issue #${row.issue_number} checked_at (${row.checked_at}) must be newer than closure time (${evidence.closedAt})`);
    }
  }
}

function verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence }) {
  for (const pr of prEvidence) {
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(pr.status),
      `proof issue #${row.issue_number} PR #${pr.pr_number} reachability status ${pr.status} must be known`);
    if (pr.release_tag_commit_oid != null) {
      expect(failures, tag, pr.tag_commit_oid === pr.release_tag_commit_oid,
        `proof issue #${row.issue_number} PR #${pr.pr_number} reachability tag commit (${pr.tag_commit_oid}) must match release commit (${pr.release_tag_commit_oid})`);
    }
    if (pr.status === 'unknown') {
      const prReachabilityEvidence = parseJson(pr.evidence_json, {});
      expect(failures, tag, typeof prReachabilityEvidence.evidence === 'string' && prReachabilityEvidence.evidence.length > 0,
        `proof issue #${row.issue_number} PR #${pr.pr_number} unknown reachability must include evidence reason`);
    }
  }
  if (evidence.hasReachableClosingPr === true) {
    expect(failures, tag, prEvidence.some((pr) => pr.merged === 1 && pr.status === 'reachable'),
      `proof issue #${row.issue_number} hasReachableClosingPr must have a merged reachable PR row`);
  }
  if (evidence.hasNotReachableClosingPr === true) {
    expect(failures, tag, prEvidence.some((pr) => pr.merged === 1 && pr.status === 'not_reachable'),
      `proof issue #${row.issue_number} hasNotReachableClosingPr must have a merged not-reachable PR row`);
  }
}

function verifyAllowedKeys({ failures, tag, label, value, allowed }) {
  expect(failures, tag, isObject(value), `${label} must be an object`);
  if (!isObject(value)) return;
  const extra = Object.keys(value).filter((key) => !allowed.has(key)).sort();
  expect(failures, tag, extra.length === 0,
    `${label} must not expose unknown keys: ${extra.join(', ')}`);
}

function verifyNoForbiddenPublicKeys({ failures, tag, value, path = 'public release' }) {
  if (Array.isArray(value)) {
    value.forEach((item, idx) => verifyNoForbiddenPublicKeys({ failures, tag, value: item, path: `${path}[${idx}]` }));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    expect(failures, tag, !forbiddenPublicKeys.has(key),
      `${path} must not expose internal/comparison key ${key}`);
    verifyNoForbiddenPublicKeys({ failures, tag, value: child, path: `${path}.${key}` });
  }
}

function verifyPublicIssueSummaries({ failures, tag, publicRelease }) {
  const issues = Array.isArray(publicRelease.issues) ? publicRelease.issues : [];
  const watchIssues = Array.isArray(publicRelease.watchIssues) ? publicRelease.watchIssues : [];
  for (const [name, rows] of [['issues', issues], ['watchIssues', watchIssues]]) {
    rows.forEach((issue, index) => {
      verifyAllowedKeys({
        failures,
        tag,
        label: `public ${name}[${index}]`,
        value: issue,
        allowed: publicIssueKeys,
      });
      expect(failures, tag, Number.isInteger(issue.number) && issue.number > 0,
        `public ${name}[${index}] must expose a positive issue number`);
      expect(failures, tag, typeof issue.title === 'string' && issue.title.length > 0,
        `public ${name}[${index}] must expose a title`);
      expect(failures, tag, typeof issue.url === 'string' && /^https:\/\/github\.com\//.test(issue.url),
        `public ${name}[${index}] must expose a GitHub URL`);
      expect(failures, tag, typeof issue.affectedUsers === 'string' && publicAffectedUsersRank.has(issue.affectedUsers),
        `public ${name}[${index}] must expose affectedUsers`);
    });
  }
  for (let i = 1; i < issues.length; i++) {
    expect(failures, tag, publicIssueSortKey(issues[i - 1]) <= publicIssueSortKey(issues[i]),
      'public issues must be sorted by effective sentiment/severity/scope');
  }
  expect(failures, tag, issues.length <= 25, 'public issues must stay capped at 25');
  expect(failures, tag, watchIssues.length <= 25, 'public watchIssues must stay capped at 25');
  for (let i = 1; i < watchIssues.length; i++) {
    expect(failures, tag, publicIssueSortKey(watchIssues[i - 1]) <= publicIssueSortKey(watchIssues[i]),
      'public watchIssues must be sorted by effective sentiment/severity/scope');
  }
  for (const issue of watchIssues) {
    expect(failures, tag, issue.state === 'open',
      `public watch issue #${issue.number} must be open`);
    expect(failures, tag, issue.sentiment === 'negative',
      `public watch issue #${issue.number} must be negative`);
    expect(failures, tag, issue.severity === 'critical' || issue.severity === 'high',
      `public watch issue #${issue.number} must be high/critical`);
  }
}

function publicIssueSortKey(issue) {
  return [
    publicSentimentRank.get(issue.sentiment) ?? 9,
    publicSeverityRank.get(issue.severity) ?? 9,
    publicScopeRank.get(issue.scope) ?? 9,
    publicAffectedUsersRank.get(issue.affectedUsers) ?? 9,
  ].join(':');
}

function verifyProofEvidenceShape({ failures, tag, row, evidence }) {
  expect(failures, tag, isObject(evidence),
    `proof issue #${row.issue_number} evidence_json must parse to an object`);
  if (!isObject(evidence)) return;

  if ('stateReasons' in evidence) {
    expect(failures, tag, isStringArray(evidence.stateReasons),
      `proof issue #${row.issue_number} stateReasons must be a string array`);
  }
  if ('closureEventClosedAt' in evidence) {
    expect(failures, tag, isStringArray(evidence.closureEventClosedAt),
      `proof issue #${row.issue_number} closureEventClosedAt must be a string array when present`);
    if (isStringArray(evidence.closureEventClosedAt) && evidence.closedAt) {
      const issueClosedAtMs = Date.parse(evidence.closedAt);
      for (const closedAt of evidence.closureEventClosedAt) {
        const eventClosedAtMs = Date.parse(closedAt);
        const closeDeltaSeconds = Number.isFinite(issueClosedAtMs) && Number.isFinite(eventClosedAtMs)
          ? Math.abs(issueClosedAtMs - eventClosedAtMs) / 1000
          : Infinity;
        expect(failures, tag, closeDeltaSeconds <= 2,
          `proof issue #${row.issue_number} closure event timestamp ${closedAt} must match issue closedAt ${evidence.closedAt}`);
      }
    }
  }
  for (const flag of ['hasReachableFixCommit', 'hasNotReachableFixCommit']) {
    expect(failures, tag, typeof evidence[flag] === 'boolean',
      `proof issue #${row.issue_number} ${flag} must be boolean`);
  }

  const reachableFixCommits = normalizeStringArray(evidence.reachableFixCommits);
  const notReachableFixCommits = normalizeStringArray(evidence.notReachableFixCommits);
  const fixCommitProof = Array.isArray(evidence.fixCommitProof) ? evidence.fixCommitProof : [];
  const canonicalCommitProof = canonicalFixCommitProof(evidence);

  expect(failures, tag, Array.isArray(evidence.reachableFixCommits),
    `proof issue #${row.issue_number} reachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.notReachableFixCommits),
    `proof issue #${row.issue_number} notReachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.fixCommitProof),
    `proof issue #${row.issue_number} fixCommitProof must be an array`);
  if ('canonicalFixCommitProof' in evidence) {
    expect(failures, tag, Array.isArray(evidence.canonicalFixCommitProof),
      `proof issue #${row.issue_number} canonicalFixCommitProof must be an array when present`);
  }

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
    expect(failures, tag, knownCommitProofSources.has(proof.source),
      `proof issue #${row.issue_number} fixCommitProof has unknown source ${proof.source}`);
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
  for (const proof of canonicalCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} canonicalFixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0 && proof.sourceIssueNumber !== row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof sourceIssueNumber must be a different positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} canonicalFixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} canonicalFixCommitProof has unknown status ${proof.status}`);
  }

  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} reachableFixCommits`, reachableFixCommits, uniqueSorted(proofReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} notReachableFixCommits`, notReachableFixCommits, uniqueSorted(proofNotReachable));
  expect(failures, tag, evidence.hasReachableFixCommit === (reachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasReachableFixCommit must match reachableFixCommits`);
  expect(failures, tag, evidence.hasNotReachableFixCommit === (notReachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasNotReachableFixCommit must match notReachableFixCommits`);
}

function canonicalFixCommitProof(evidence) {
  return Array.isArray(evidence?.canonicalFixCommitProof) ? evidence.canonicalFixCommitProof : [];
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

function riskDispositionForStatus(status) {
  return riskDispositionByProofStatus.get(status) ?? 'missing_evidence';
}

function riskDispositionCountsForProofRows(proofRows) {
  const counts = {};
  for (const row of proofRows) {
    const disposition = riskDispositionForStatus(row.status);
    counts[disposition] = (counts[disposition] ?? 0) + 1;
  }
  return counts;
}

function riskSummaryFromCounts(counts, neutralAuditCounts = { highImpact: 0, bugShaped: 0 }) {
  const summary = {
    creditedReleaseFixCount: counts.credited_release_fix ?? 0,
    resolvedByCanonicalReleaseFixCount: counts.resolved_by_canonical_release_fix ?? 0,
    knownNotInReleaseCount: counts.known_not_in_release ?? 0,
    openCanonicalRiskCount: counts.open_canonical_risk ?? 0,
    unsupportedClosureClaimCount: counts.unsupported_closure_claim ?? 0,
    neutralOrNonActionableCount: counts.neutral_or_non_actionable ?? 0,
    neutralHighImpactCount: neutralAuditCounts.highImpact ?? 0,
    neutralBugShapedCount: neutralAuditCounts.bugShaped ?? 0,
    missingEvidenceCount: counts.missing_evidence ?? 0,
  };
  return {
    ...summary,
    unresolvedForReleaseCount: summary.knownNotInReleaseCount +
      summary.openCanonicalRiskCount +
      summary.unsupportedClosureClaimCount +
      summary.missingEvidenceCount,
    unresolvedWeightedRisk: 0,
    weightedRiskByDisposition: {},
  };
}

function riskSummaryForProofRows(proofRows) {
  const counts = riskDispositionCountsForProofRows(proofRows);
  const neutralAuditCounts = neutralAuditSignalCountsForProofRows(proofRows);
  const summary = riskSummaryFromCounts(counts, neutralAuditCounts);
  const byDisposition = {};
  for (const row of proofRows) {
    const disposition = riskDispositionForStatus(row.status);
    const weight = closureRiskWeightForProofRow(row);
    if (weight <= 0) continue;
    byDisposition[disposition] = (byDisposition[disposition] ?? 0) + weight;
  }
  return {
    counts,
    summary: {
      ...summary,
      unresolvedWeightedRisk: roundMetric(Object.values(byDisposition).reduce((sum, value) => sum + Number(value ?? 0), 0)),
      weightedRiskByDisposition: roundRiskMap(byDisposition),
    },
  };
}

function neutralAuditSignalCountsForProofRows(proofRows) {
  let highImpact = 0;
  let bugShaped = 0;
  for (const row of proofRows) {
    if (riskDispositionForStatus(row.status) !== 'neutral_or_non_actionable') continue;
    const classification = effectiveClassificationForProofRow(row);
    if (classification.sentiment !== 'neutral') continue;
    if (classification.severity === 'high' || classification.severity === 'critical') highImpact++;
    if (bugShapedTitleRe.test(row.title ?? '')) bugShaped++;
  }
  return { highImpact, bugShaped };
}

function closureRiskWeightForProofRow(row) {
  const disposition = riskDispositionForStatus(row.status);
  const dispositionWeight = riskDispositionWeights.get(disposition) ?? 0;
  if (dispositionWeight <= 0) return 0;
  const classification = effectiveClassificationForProofRow(row);
  if (classification.sentiment !== 'negative') return 0;
  const severity = severityRiskWeights.get(classification.severity) ?? 0;
  const functionality = functionalityRiskWeights.get(classification.functionality) ?? 0;
  if (severity <= 0 || functionality <= 0) return 0;
  return dispositionWeight *
    severity *
    functionality *
    (scopeRiskWeights.get(classification.scope) ?? 1) *
    (affectedUserRiskWeights.get(classification.affectedUsers ?? 'unknown') ?? affectedUserRiskWeights.get('unknown'));
}

function effectiveClassificationForProofRow(row) {
  const labels = Array.isArray(row.effective_labels)
    ? row.effective_labels.filter((label) => typeof label === 'string')
    : [];
  return applyTitleIssueShapeHint(
    applyLabelOverrides(
      applyTitleFunctionalityHint(rawClassificationForProofRow(row), row.title ?? ''),
      labels,
    ),
    row.title ?? '',
    labels,
  );
}

function rawClassificationForProofRow(row) {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function roundRiskMap(map) {
  const rounded = {};
  for (const [key, value] of Object.entries(map)) {
    const roundedValue = roundMetric(Number(value ?? 0));
    if (roundedValue > 0) rounded[key] = roundedValue;
  }
  return rounded;
}

function roundMetric(value) {
  return Math.round(Number(value ?? 0) * 1000) / 1000;
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
  verifyAllowedKeys({ failures, tag: 'api/public', label: 'public top-level', value: publicPayload, allowed: publicTopLevelKeys });
  expect(failures, 'api/public', publicPayload.schemaVersion === publicPayloadSchemaVersion,
    `public schemaVersion must be ${publicPayloadSchemaVersion}, got ${JSON.stringify(publicPayload.schemaVersion)}`);
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('comparison'), 'public payload must not include comparison data');
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('upstream'), 'public payload must not include upstream data');
  if (status.lastScoredAt) {
    expect(failures, 'api/public', publicPayload.updatedAt === status.lastScoredAt,
      `public updatedAt (${publicPayload.updatedAt}) must equal status lastScoredAt (${status.lastScoredAt})`);
  }

  const releasesPayload = await fetchJson(`${apiBase}/api/releases`);
  const releaseApiByTag = new Map((Array.isArray(releasesPayload) ? releasesPayload : []).map((release) => [release.tag, release]));
  const publicByTag = new Map((publicPayload.releases ?? []).map((release) => [release.tag, release]));
  for (const release of publicPayload.releases ?? []) {
    verifyAllowedKeys({ failures, tag: release.tag ?? 'api/public', label: 'public release', value: release, allowed: publicReleaseKeys });
    verifyNoForbiddenPublicKeys({ failures, tag: release.tag ?? 'api/public', value: release });
  }
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
      expect(failures, release.tag, releaseApi.reason === release.score_reason,
        `releases reason (${releaseApi.reason}) must match DB score_reason (${release.score_reason})`);
      expect(failures, release.tag, releaseApi.negativeIssues === release.negative_issues,
        `releases negativeIssues (${releaseApi.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
      expect(failures, release.tag, releaseApi.positiveIssues === release.positive_issues,
        `releases positiveIssues (${releaseApi.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
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
      expect(failures, release.tag, publicRelease.reason === release.score_reason,
        `public reason (${publicRelease.reason}) must match DB score_reason (${release.score_reason})`);
      expect(failures, release.tag, publicRelease.negativeIssues === Number(release.negative_issues ?? 0),
        `public negativeIssues (${publicRelease.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
      expect(failures, release.tag, publicRelease.positiveIssues === Number(release.positive_issues ?? 0),
        `public positiveIssues (${publicRelease.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
      expect(failures, release.tag, publicRelease.recommended === (release.recommended === 1),
        `public recommended (${publicRelease.recommended}) must match DB recommended (${release.recommended === 1})`);
      expect(failures, release.tag, publicRelease.scoredAt === release.scored_at,
        `public scoredAt (${publicRelease.scoredAt}) must match DB scored_at (${release.scored_at})`);
      verifyScoreAuditSummary({ failures, tag: release.tag, summary: publicRelease.scoreAudit });
      expect(failures, release.tag, publicRelease.totalAttributedIssues === publicRelease.scoreAudit?.rawIssueCount,
        `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match scoreAudit rawIssueCount (${publicRelease.scoreAudit?.rawIssueCount})`);
      const issueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
      if (publicRelease.totalAttributedIssues > 0) {
        expect(failures, release.tag, issueCount > 0,
          'public release with attributed issues must expose capped issue summaries');
      }
      verifyPublicIssueSummaries({ failures, tag: release.tag, publicRelease });
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
    expect(failures, release.tag, review.local?.reason === release.score_reason,
      `review reason (${review.local?.reason}) must match DB score_reason (${release.score_reason})`);
    expect(failures, release.tag, review.local?.negativeIssues === release.negative_issues,
      `review negativeIssues (${review.local?.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
    expect(failures, release.tag, review.local?.positiveIssues === release.positive_issues,
      `review positiveIssues (${review.local?.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
    expect(failures, release.tag, review.local?.recommended === (release.recommended === 1),
      `review recommended (${review.local?.recommended}) must match DB recommended (${release.recommended === 1})`);
    expect(failures, release.tag, review.local?.scoredAt === release.scored_at,
      `review scoredAt (${review.local?.scoredAt}) must match DB scored_at (${release.scored_at})`);
    if (releaseApi) {
      expect(failures, release.tag, releaseApi.band === review.local?.band,
        `releases band (${releaseApi.band}) must match review band (${review.local?.band})`);
    }
    expect(failures, release.tag, review.local?.input?.schemaVersion === scoreInputSchemaVersion,
      `review score input schemaVersion (${review.local?.input?.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
    expect(failures, release.tag, review.local?.components?.schemaVersion === scoreComponentsSchemaVersion,
      `review score components schemaVersion (${review.local?.components?.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
    expect(failures, release.tag, review.local?.gateEvidence?.schemaVersion === gateEvidenceSchemaVersion,
      `review gateEvidence schemaVersion (${review.local?.gateEvidence?.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
    expect(failures, release.tag, review.local?.issueEvidence?.schemaVersion === issueEvidenceSchemaVersion,
      `review issueEvidence schemaVersion (${review.local?.issueEvidence?.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    verifyReleaseChecksGate({
      failures,
      tag: release.tag,
      releaseChecks: review.local?.gateEvidence?.releaseChecks,
    });
    verifyArtifactVerificationGate({
      failures,
      tag: release.tag,
      artifactVerification: review.local?.gateEvidence?.artifactVerification,
    });
    if (publicRelease) {
      expect(failures, release.tag, publicRelease.band === review.local?.band,
        `public band (${publicRelease.band}) must match review band (${review.local?.band})`);
      expect(failures, release.tag, publicRelease.totalAttributedIssues === review.local?.input?.rawIssueCount,
        `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match review rawIssueCount (${review.local?.input?.rawIssueCount})`);
    }
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
      for (const [field, expected] of Object.entries({
        score: review.local?.score,
        band: review.local?.band,
        status: review.local?.status,
        recommended: review.local?.recommended,
        reason: review.local?.reason,
        negativeIssues: review.local?.negativeIssues,
        positiveIssues: review.local?.positiveIssues,
        scoredAt: review.local?.scoredAt,
      })) {
        expect(failures, release.tag, comparison.local[field] === expected,
          `comparison local ${field} (${comparison.local[field]}) must match review (${expected})`);
      }
      expectJsonEqual(failures, release.tag, 'comparison local explanation must match review explanation',
        comparison.local.components?.explanation, review.local?.components?.explanation);
    }

    const proof = review.local?.gateEvidence?.fixProvenance?.closureProof;
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (proof || credit) {
      expect(failures, release.tag, !!proof && !!credit, 'review must expose closureProof and releaseFixCredit together');
      expect(failures, release.tag, proof.schemaVersion === closureProofSchemaVersion,
        `closureProof schemaVersion (${proof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
      expect(failures, release.tag, credit.schemaVersion === releaseFixCreditSchemaVersion,
        `releaseFixCredit schemaVersion (${credit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
      expect(failures, release.tag, credit.countedClosedCount === proof.creditedCount,
        'releaseFixCredit countedClosedCount must match closureProof creditedCount');
      expect(failures, release.tag, credit.notCountedClosedCount === proof.notCreditedCount,
        'releaseFixCredit notCountedClosedCount must match closureProof notCreditedCount');
      expect(failures, release.tag, credit.analyzedClosedCount === proof.creditedCount + proof.notCreditedCount,
        'releaseFixCredit analyzedClosedCount must equal credited + notCredited');
      expect(failures, release.tag, (proof.byStatus?.fixed_in_release ?? 0) === proof.creditedCount,
        'closureProof creditedCount must equal fixed_in_release bucket');
      expect(failures, release.tag, isObject(proof.byRiskDisposition),
        'closureProof must expose byRiskDisposition');
      expect(failures, release.tag, isObject(proof.riskSummary),
        'closureProof must expose riskSummary');
      if (isObject(proof.byRiskDisposition)) {
        for (const [disposition] of Object.entries(proof.byRiskDisposition)) {
          expect(failures, release.tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
      }
      verifyClosureProofExamplesByStatus({
        failures,
        tag: release.tag,
        proof,
        label: 'closureProof',
      });
      for (const example of proof.examples ?? []) {
        expect(failures, release.tag, isObject(example.rawClassification),
          `closure proof example #${example.number} must expose rawClassification`);
        expect(failures, release.tag, isObject(example.classification),
          `closure proof example #${example.number} must expose effective classification`);
        expect(failures, release.tag, isObject(example.classificationDiff),
          `closure proof example #${example.number} must expose classificationDiff`);
        expect(failures, release.tag, typeof example.riskWeight === 'number',
          `closure proof example #${example.number} must expose numeric riskWeight`);
      }
      for (let i = 1; i < (proof.examples ?? []).length; i++) {
        expect(failures, release.tag,
          Number(proof.examples[i - 1].riskWeight ?? 0) >= Number(proof.examples[i].riskWeight ?? 0),
          'closure proof examples must be sorted by descending riskWeight');
      }

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
      expectJsonEqual(failures, release.tag, 'comparison closureProof byRiskDisposition must match review',
        comparisonProof?.byRiskDisposition, proof.byRiskDisposition);
      expectJsonEqual(failures, release.tag, 'comparison closureProof riskSummary must match review',
        comparisonProof?.riskSummary, proof.riskSummary);
      expectJsonEqual(failures, release.tag, 'comparison closureProof examplesByStatus must match review',
        comparisonProof?.examplesByStatus, proof.examplesByStatus);
    }
  }
}

function verifyClosureProofExamplesByStatus({ failures, tag, proof, label }) {
  expect(failures, tag, isObject(proof?.examplesByStatus),
    `${label} must expose examplesByStatus`);
  for (const [status, count] of Object.entries(proof?.byStatus ?? {})) {
    if (status === 'fixed_in_release' || Number(count ?? 0) <= 0) continue;
    const statusExamples = proof?.examplesByStatus?.[status];
    expect(failures, tag, Array.isArray(statusExamples) && statusExamples.length > 0,
      `${label} examplesByStatus must include at least one ${status} example`);
    for (const example of statusExamples ?? []) {
      expect(failures, tag, example.status === status,
        `${label} examplesByStatus ${status} contains example with status ${example.status}`);
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
