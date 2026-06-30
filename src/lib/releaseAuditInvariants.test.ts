import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyReleaseAudit } from '../../scripts/lib/release-audit-invariants.mjs';
import { CLOSURE_PROOF_STATUSES, CLOSURE_RISK_DISPOSITIONS } from './closureProofTaxonomy.ts';
import { RELEASE_ISSUE_EVIDENCE_TIERS } from './releaseIssueEvidence.ts';

const labelTimelineFixture = {
  schemaVersion: 1,
  cutoffAt: null,
  issueCount: 1,
  currentLabelCount: 1,
  timelineLabelCount: 0,
  snapshotLabelCount: 0,
  missingTimelineCount: 0,
  missingTimelineWithCurrentLabelsCount: 0,
  historicalCurrentLabelFallbackAllowed: true,
};
const releaseChecksFixture = {
  schemaVersion: 2,
  state: 'SUCCESS',
  total: 1,
  success: 1,
  failure: 0,
  pending: 0,
  skipped: 0,
  contextCount: 1,
  shownContextCount: 1,
  contextsTruncated: false,
  contexts: [{ name: 'build', conclusion: 'SUCCESS' }],
};
const artifactVerificationFixture = {
  schemaVersion: 1,
  verified: true,
  releaseShaMatches: true,
  ciReportVerified: true,
  releaseValidationVerified: true,
};
const proofCheckedAt = '2026-01-02T00:00:00Z';
const auditScoredAt = '2026-01-02T00:00:01Z';
const tagOid = 'a'.repeat(40);
const mergeOid = 'b'.repeat(40);
const defaultScoreInput = {
  schemaVersion: 1,
  rawIssueCount: 1,
  classifiedIssueCount: 1,
  unresolvedClosureIssueCount: 0,
  unresolvedClosureRiskWeight: 0,
};
const proofDependencyFreshnessFixture = [
  'issue_rows',
  'issue_fetches',
  'issue_comments',
  'classification_rows',
  'label_events',
  'label_snapshots',
  'closure_events',
  'reopen_events',
  'issue_pr_links',
  'issue_commit_references',
  'pull_request_fixes',
  'release_pr_reachability',
].map((source) => ({ source, max_ts: proofCheckedAt }));

function closureProofFixture(overrides: any = {}) {
  const proof = {
    schemaVersion: 1,
    creditedCount: 1,
    notCreditedCount: 0,
    byStatus: { fixed_in_release: 1 },
    byRiskDisposition: { credited_release_fix: 1 },
    riskSummary: {
      creditedReleaseFixCount: 1,
      resolvedByCanonicalReleaseFixCount: 0,
      resolvedByReleaseFixProofCount: 0,
      knownNotInReleaseCount: 0,
      openCanonicalRiskCount: 0,
      unsupportedClosureClaimCount: 0,
      neutralOrNonActionableCount: 0,
      neutralHighImpactCount: 0,
      neutralBugShapedCount: 0,
      missingEvidenceCount: 0,
      unresolvedForReleaseCount: 0,
      unresolvedWeightedRisk: 0,
      weightedRiskByDisposition: {},
    },
    ...overrides,
  };
  proof.examplesByStatus ??= Object.fromEntries(
    Object.keys(proof.byStatus ?? {})
      .filter((status) => status !== 'fixed_in_release')
      .map((status) => [status, [{ number: 1, status }]]),
  );
  return proof;
}

function reader(overrides: Partial<{
  releases: any[];
  rawClosed: any[];
  closed: any[];
  opened: any[];
  verified: any[];
  unverified: any[];
  proofRows: any[];
  prEvidence: any[];
  proofDependencyFreshness: any[];
  issueNumbers: number[];
  audit: any;
}> = {}) {
  const data = {
    releases: [{
      tag: 'v1',
      final_score: 7.5,
      state: 'eligible',
      recommended: 1,
      scored_at: auditScoredAt,
      score_reason: 'test reason',
      negative_issues: 1,
      positive_issues: 0,
    }],
    rawClosed: [{ number: 1 }],
    opened: [],
    closed: [{ number: 1, prompt_version: 6 }],
    verified: [{ number: 1, sentiment: 'negative', prompt_version: 6 }],
    unverified: [],
    proofRows: [{
      release_tag: 'v1',
      issue_number: 1,
      status: 'fixed_in_release',
      checked_at: proofCheckedAt,
      evidence_json: JSON.stringify({
        hasReachableClosingPr: true,
        hasReachableFixCommit: false,
        hasNotReachableFixCommit: false,
        reachableFixCommits: [],
        notReachableFixCommits: [],
        fixCommitProof: [],
        linkedPrs: [{
          number: 1,
          repositoryNameWithOwner: 'openclaw/openclaw',
          source: 'closedByPullRequestsReferences',
          willCloseTarget: 1,
          state: 'MERGED',
          merged: 1,
          mergedAt: '2026-01-01T12:00:00Z',
          reachabilityStatus: 'reachable',
          reachabilityMethod: 'git-merge-base',
          reachabilityEvidence: 'merge_commit_in_release_history',
          mergeCommitOid: mergeOid,
        }],
        stateReasons: ['COMPLETED'],
      }),
    }],
    prEvidence: [{
      issue_number: 1,
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 1,
      merged: 1,
      status: 'reachable',
      tag_commit_oid: tagOid,
      release_tag_commit_oid: tagOid,
      merge_commit_oid: mergeOid,
      evidence_json: JSON.stringify({
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: tagOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        commandStatus: 0,
      }),
    }],
    proofDependencyFreshness: proofDependencyFreshnessFixture,
    issueNumbers: [1],
    audit: {
      prompt_version: 6,
      scored_at: auditScoredAt,
      input_json: JSON.stringify(defaultScoreInput),
      components_json: JSON.stringify({
        schemaVersion: 1,
        components: {},
        evidenceCoverage: 1,
        hotfix: false,
        reason: 'test reason',
        explanation: scoreExplanationFixture(),
      }),
      issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
      gate_evidence_json: JSON.stringify({
        schemaVersion: 1,
        labelTimeline: labelTimelineFixture,
        releaseChecks: releaseChecksFixture,
        artifactVerification: artifactVerificationFixture,
        fixProvenance: {
          verifiedFixedCount: 1,
          unverifiedClosedCount: 0,
          closureProof: closureProofFixture(),
          releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
        },
      }),
    },
    ...overrides,
  };
  if (data.audit && data.audit.issue_evidence_json === undefined) {
    data.audit = { ...data.audit, issue_evidence_json: JSON.stringify({ schemaVersion: 1 }) };
  }
  if (data.audit && data.audit.input_json === undefined) {
    data.audit = { ...data.audit, input_json: JSON.stringify(defaultScoreInput) };
  }
  if (data.audit && data.audit.components_json === undefined) {
    data.audit = {
      ...data.audit,
      components_json: JSON.stringify({
        schemaVersion: 1,
        components: {},
        evidenceCoverage: 1,
        hotfix: false,
        reason: 'test reason',
        explanation: scoreExplanationFixture(),
      }),
    };
  }
  if (data.audit?.gate_evidence_json) {
    const gate = JSON.parse(data.audit.gate_evidence_json);
    gate.schemaVersion ??= 1;
    gate.releaseChecks ??= releaseChecksFixture;
    gate.artifactVerification ??= artifactVerificationFixture;
    data.audit = { ...data.audit, gate_evidence_json: JSON.stringify(gate) };
  }
  return {
    listReleases: () => data.releases,
    rawClosedDuringReign: () => data.rawClosed,
    issueNumbersForVersion: () => data.issueNumbers,
    issuesForVersion: () => data.issueNumbers.map((number: number) => ({
      number,
      state: number === 1 ? 'closed' : 'open',
      title: `issue ${number}`,
      html_url: `https://github.com/x/y/issues/${number}`,
      closed_at: number === 1 ? '2026-01-01T12:00:00Z' : null,
      labels: '[]',
      comments: 0,
      has_workaround: 0,
      reaction_total: 0,
      positive_reactions: 0,
      is_bot: 0,
      author: 'tester',
      author_association: 'MEMBER',
      unique_human_commenters: 0,
      maintainer_commenters: 0,
      contributor_commenters: 0,
      commenter_scan_truncated: 0,
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      workaround_status: 'unknown',
      duplicate_cluster: null,
      affects_version: null,
      confidence: 0.9,
      rationale: '',
    })),
    labelsForIssueAt: (_issueNumber: number, fallbackLabels: string[]) => fallbackLabels,
    openedDuringReign: () => data.opened,
    closedDuringReign: () => data.closed,
    verifiedFixedForRelease: () => data.verified,
    unverifiedClosedForRelease: () => data.unverified,
    proofRowsFor: () => data.proofRows.map((row: any) => ({
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      functionality: 'core',
      affected_users: 'some',
      checked_at: proofCheckedAt,
      ...row,
    })),
    prReachabilityEvidenceForIssue: () => data.prEvidence,
    proofDependencyFreshnessForIssue: () => data.proofDependencyFreshness,
    prReachabilityRowsForRelease: () => data.prEvidence.map((row: any) => ({
      tag: 'v1',
      pr_repository_name_with_owner: row.pr_repository_name_with_owner,
      pr_number: row.pr_number,
      title: `PR ${row.pr_number}`,
      url: `https://github.com/${row.pr_repository_name_with_owner}/pull/${row.pr_number}`,
      state: 'MERGED',
      merged: row.merged,
      merged_at: '2026-01-01T12:00:00Z',
      tag_commit_oid: row.tag_commit_oid ?? null,
      merge_commit_oid: row.merge_commit_oid ?? null,
      pr_merge_commit_oid: row.merge_commit_oid ?? null,
      base_ref_name: row.base_ref_name ?? 'main',
      status: row.status,
      method: row.method ?? 'git-merge-base',
      evidence_json: row.evidence_json ?? JSON.stringify({
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: row.tag_commit_oid ?? tagOid,
        checkedCommitOid: row.merge_commit_oid ?? mergeOid,
        baseRefName: row.base_ref_name ?? 'main',
        commandStatus: 0,
      }),
      checked_at: proofCheckedAt,
    })),
    getReleaseScoreAudit: () => data.audit,
    sourceFreshnessFor: () => [],
  };
}

function scoreExplanationFixture() {
  return {
    schemaVersion: 1,
    title: 'Why not 10?',
    scoreLedger: {
      schemaVersion: 1,
      finalScore: 7.5,
      status: 'eligible',
      band: 'ok',
      subtotalBeforeCaps: 7.5,
      scoreAfterCaps: 7.5,
      rows: [
        { key: 'base', label: 'Base', points: 7.5, kind: 'base' },
        { key: 'verifiedDebt', label: 'Field blocker debt', points: 0, kind: 'neutral' },
        { key: 'carryoverDebt', label: 'Open unconfirmed issue risk', points: 0, kind: 'neutral' },
        { key: 'staleDebt', label: 'Weak or stale evidence', points: 0, kind: 'neutral' },
        { key: 'closureRisk', label: 'Closed-issue proof gap', points: 0, kind: 'neutral' },
        { key: 'coverage', label: 'Classification coverage', points: 0, kind: 'neutral' },
        { key: 'survival', label: 'Stable survival', points: 0, kind: 'neutral' },
        { key: 'shakeout', label: 'Beta shakeout', points: 0, kind: 'neutral' },
        { key: 'regression', label: 'Opened vs fixed balance', points: 0, kind: 'neutral' },
        { key: 'breaking', label: 'Breaking changes', points: 0, kind: 'neutral' },
        { key: 'releaseVerification', label: 'Release checks', points: 0, kind: 'neutral' },
        { key: 'artifactVerification', label: 'Artifact verification', points: 0, kind: 'neutral' },
      ],
      caps: [],
    },
    positives: ['The release is eligible and recommended.'],
    positiveDetails: [{
      code: 'release_recommended',
      label: 'Release recommended',
      text: 'The release is eligible and recommended.',
    }],
    limits: ['One closed issue still needs release proof.'],
    limitDetails: [{
      code: 'closed_issues_not_counted_as_release_fixes',
      label: 'Closed issue release proof',
      text: 'One closed issue still needs release proof.',
      metrics: { notCountedClosedCount: 1 },
      issueRefs: [{ number: 1, title: 'issue 1', url: 'https://github.com/x/y/issues/1' }],
    }],
    verdict: 'This means the release is the current recommended install target under the audit and recommendation gates, but the audit still contains evidence.',
  };
}

function apiFixtureFetchJson(mutator?: (dataFreshness: any, publicRelease: any) => void) {
  const scoreAudit = {
    schemaVersion: 1,
    modelVersion: 'test-model',
    promptVersion: 6,
    evidenceCoverage: 1,
    rawIssueCount: 1,
    classifiedIssueCount: 1,
  };
  const explanation = scoreExplanationFixture();
  const auditLinks = {
    review: '/api/releases/v1/review',
    issues: '/api/releases/v1/review/issues',
    closureProofs: '/api/releases/v1/review/closure-proofs',
    reachability: '/api/releases/v1/review/reachability',
  };
  const dataFreshness = {
    schemaVersion: 1,
    tag: 'v1',
    scoredAt: auditScoredAt,
    issueUpdatedAtMax: '2026-01-01T23:00:00Z',
    issueUpdatedAgeHoursAtScore: 1,
    closureProofCheckedAtMax: proofCheckedAt,
    sourceFetchedAtMax: proofCheckedAt,
    sourceFetchedAgeHoursAtScore: 0,
    sources: [
      { source: 'issue_rows', count: 1, nullCount: 0, maxAt: '2026-01-01T23:00:00Z', ageHoursAtScore: 1 },
      { source: 'classification_rows', count: 1, nullCount: 0, maxAt: '2026-01-01T23:10:00Z', ageHoursAtScore: 0.83 },
      { source: 'closure_proofs', count: 1, nullCount: 0, maxAt: proofCheckedAt, ageHoursAtScore: 0 },
      { source: 'release_metadata', count: 1, nullCount: 0, maxAt: proofCheckedAt, ageHoursAtScore: 0 },
    ],
  };
  const publicRelease = {
    schemaVersion: 4,
    tag: 'v1',
    score: 7.5,
    band: 'ok',
    status: 'eligible',
    recommended: true,
    reason: 'test reason',
    negativeIssues: 1,
    positiveIssues: 0,
    scoredAt: auditScoredAt,
    scoreAudit,
    explanation,
    dataFreshness,
    auditLinks,
    totalAttributedIssues: 1,
    profileEvidence: {
      schemaVersion: 1,
      sourceMode: 'audit_issue_evidence',
      issueEvidenceSchemaVersion: 1,
      issueCount: 1,
      weightedIssueCount: 1,
      surfaceIssueCount: 1,
      surfaceWeight: 2.5,
      surfaces: [{
        label: 'Discord',
        icon: 'discord',
        count: 1,
        weight: 2.5,
        tiers: { verifiedDebt: 1 },
        weightByTier: { verifiedDebt: 2.5 },
      }],
    },
    issues: [{
      number: 1,
      title: 'issue 1',
      url: 'https://github.com/x/y/issues/1',
      affectedUsers: 'some',
    }],
  };
  const sourceProvenance = {
    sourceMode: 'current_db',
    scoreTable: 'release_score_audits',
    scoredAt: auditScoredAt,
    dataFreshnessScoredAt: dataFreshness.scoredAt,
    scoreTimestampAligned: true,
    sources: dataFreshness.sources,
    rawRows: {
      issues: '/api/releases/v1/review/issues',
      closureProofs: '/api/releases/v1/review/closure-proofs',
      reachability: '/api/releases/v1/review/reachability',
    },
  };
  mutator?.(dataFreshness, publicRelease);
  const closurePage = (url: string) => {
    const parsed = new URL(url);
    const statusFilter = scalarSearchParam(parsed, 'status', url, 'invalid status', {
      allowedStatuses: CLOSURE_PROOF_STATUSES,
    });
    const riskDispositionFilter = scalarSearchParam(parsed, 'riskDisposition', url, 'invalid riskDisposition', {
      allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
    });
    const issueFilter = issueNumberSearchParam(parsed, url);
    if (statusFilter && !CLOSURE_PROOF_STATUSES.includes(statusFilter as any)) {
      throwHttpError(url, 400, {
        error: 'invalid status',
        status: statusFilter,
        allowedStatuses: CLOSURE_PROOF_STATUSES,
      });
    }
    if (riskDispositionFilter && !CLOSURE_RISK_DISPOSITIONS.includes(riskDispositionFilter as any)) {
      throwHttpError(url, 400, {
        error: 'invalid riskDisposition',
        riskDisposition: riskDispositionFilter,
        allowedRiskDispositions: CLOSURE_RISK_DISPOSITIONS,
      });
    }
    const row = {
      issueNumber: 1,
      title: 'issue 1',
      url: 'https://github.com/x/y/issues/1',
      closedAt: '2026-01-01T12:00:00Z',
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      riskDisposition: 'credited_release_fix',
      riskDispositionLabel: 'credited release fix',
      riskWeight: 0,
      riskWeightLabel: 'risk 0',
      checkedAt: proofCheckedAt,
      labels: [],
      classification: {},
      classificationDiff: {},
      evidence: {},
    };
    const rows = (issueFilter == null || issueFilter === row.issueNumber) &&
      (!statusFilter || statusFilter === row.status) &&
      (!riskDispositionFilter || riskDispositionFilter === row.riskDisposition)
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 50, 1, 100);
    const pageRows = rows.slice(cursor, cursor + limit);
    const sourceRows = [row];
    const filteredCountsByStatus = rows.reduce((acc: any, item) => {
      acc[item.status] = (acc[item.status] ?? 0) + 1;
      return acc;
    }, {});
    const filteredCountsByRiskDisposition = rows.reduce((acc: any, item) => {
      acc[item.riskDisposition] = (acc[item.riskDisposition] ?? 0) + 1;
      return acc;
    }, {});
    return {
      schemaVersion: 1,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      filters: {
        issue: issueFilter,
        issueNumber: issueFilter,
        status: statusFilter,
        riskDisposition: riskDispositionFilter,
      },
      totals: {
        unfilteredRows: sourceRows.length,
        filteredRows: rows.length,
        unfilteredDistinctIssues: sourceRows.length,
        filteredDistinctIssues: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctIssueCount: rows.length,
      unfilteredCountsByStatus: { fixed_in_release: 1 },
      filteredCountsByStatus,
      unfilteredCountsByRiskDisposition: { credited_release_fix: 1 },
      filteredCountsByRiskDisposition,
      limit,
      cursor,
      nextCursor: cursor + pageRows.length < rows.length ? cursor + pageRows.length : null,
      rows: pageRows,
    };
  };
  const reachabilityPage = (url: string) => {
    const parsed = new URL(url);
    const row = {
      repositoryNameWithOwner: 'openclaw/openclaw',
      number: 1,
      title: 'PR 1',
      url: 'https://github.com/openclaw/openclaw/pull/1',
      state: 'MERGED',
      merged: true,
      mergedAt: '2026-01-01T12:00:00Z',
      status: 'reachable',
      method: 'git-merge-base',
      checkedAt: proofCheckedAt,
      tagCommitOid: tagOid,
      mergeCommitOid: mergeOid,
      prMergeCommitOid: mergeOid,
      baseRefName: 'main',
      evidence: {
        schemaVersion: 1,
        evidence: 'merge_commit_in_release_history',
        method: 'git-merge-base',
        tagCommitOid: tagOid,
        checkedCommitOid: mergeOid,
        baseRefName: 'main',
        commandStatus: 0,
      },
    };
    const statusFilter = scalarSearchParam(parsed, 'status', url, 'invalid status');
    if (statusFilter && !['reachable', 'not_reachable', 'unknown'].includes(statusFilter)) {
      throwHttpError(url, 400, { error: 'invalid status', status: statusFilter });
    }
    const prFilter = scalarSearchParam(parsed, 'pr', url, 'invalid pr filter');
    if (prFilter && !/^(?:[\w.-]+\/[\w.-]+#)?\d+$/.test(prFilter)) {
      throwHttpError(url, 400, { error: 'invalid pr filter', pr: prFilter });
    }
    const rows = (!statusFilter || statusFilter === row.status) &&
      (!prFilter || prFilter === '1' || prFilter === 'openclaw/openclaw#1')
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 100, 1, 250);
    const pageRows = rows.slice(cursor, cursor + limit);
    const sourceRows = [row];
    const filteredCountsByStatus = rows.reduce((acc: any, item) => {
      acc[item.status] = (acc[item.status] ?? 0) + 1;
      return acc;
    }, {});
    return {
      schemaVersion: 1,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      filters: {
        status: statusFilter,
        pr: prFilter ? { repositoryNameWithOwner: prFilter.includes('#') ? prFilter.split('#')[0] : null, number: Number(prFilter.split('#').pop()) } : null,
      },
      totals: {
        unfilteredRows: sourceRows.length,
        filteredRows: rows.length,
        unfilteredPullRequests: sourceRows.length,
        filteredPullRequests: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctPullRequestCount: rows.length,
      countsByStatus: filteredCountsByStatus,
      filteredCountsByStatus,
      unfilteredCountsByStatus: { reachable: 1 },
      limit,
      cursor,
      nextCursor: cursor + pageRows.length < rows.length ? cursor + pageRows.length : null,
      rows: pageRows,
    };
  };
  const issueEvidencePage = (url: string) => {
    const parsed = new URL(url);
    const row = {
      tier: 'verifiedFixed',
      tierLabel: 'Verified release fixes',
      tierDescription: 'Closed issues credited as fixed by code proof reachable from this release tag.',
      installImpactClass: 'state_data',
      weight: 1,
      fieldConfirmed: true,
      issue: {
        number: 1,
        title: 'issue 1',
        url: 'https://github.com/x/y/issues/1',
        state: 'closed',
        labels: [],
        rawClassification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'moderate',
          affectedUsers: 'some',
        },
        classification: {
          sentiment: 'negative',
          severity: 'high',
          functionality: 'core',
          scope: 'moderate',
          affectedUsers: 'some',
        },
        classificationDiff: {},
      },
    };
    const tierFilter = parsed.searchParams.get('tier');
    const tiers = tierFilter ? tierFilter.split(',').map((tier) => tier.trim()).filter(Boolean) : [];
    if (tiers.some((tier) => !(RELEASE_ISSUE_EVIDENCE_TIERS as readonly string[]).includes(tier))) {
      throwHttpError(url, 400, { error: 'invalid tier', tier: tierFilter });
    }
    const impactFilter = parsed.searchParams.get('impact');
    const impacts = impactFilter ? impactFilter.split(',').map((impact) => impact.trim()).filter(Boolean) : [];
    const stateFilter = parsed.searchParams.get('state');
    const states = stateFilter ? stateFilter.split(',').map((state) => state.trim()).filter(Boolean) : [];
    const enumFilter = (key: string) => {
      const raw = parsed.searchParams.get(key);
      return raw ? raw.split(',').map((value) => value.trim()).filter(Boolean) : [];
    };
    const sentiments = enumFilter('sentiment');
    const severities = enumFilter('severity');
    const functionalities = enumFilter('functionality');
    const scopes = enumFilter('scope');
    const affectedUsers = enumFilter('affectedUsers');
    const issueFilter = issueNumberSearchParam(parsed, url);
    const fieldConfirmedFilter = scalarSearchParam(parsed, 'fieldConfirmed', url, 'invalid fieldConfirmed');
    if (fieldConfirmedFilter != null && !['1', 'true', 'yes', '0', 'false', 'no'].includes(fieldConfirmedFilter.toLowerCase())) {
      throwHttpError(url, 400, { error: 'invalid fieldConfirmed', fieldConfirmed: fieldConfirmedFilter });
    }
    const fieldConfirmed = fieldConfirmedFilter == null ? null : ['1', 'true', 'yes'].includes(fieldConfirmedFilter.toLowerCase());
    const minWeightRaw = scalarSearchParam(parsed, 'minWeight', url, 'invalid minWeight');
    const maxWeightRaw = scalarSearchParam(parsed, 'maxWeight', url, 'invalid maxWeight');
    const minWeight = minWeightRaw == null ? null : Number(minWeightRaw);
    const maxWeight = maxWeightRaw == null ? null : Number(maxWeightRaw);
    if (minWeightRaw != null && !Number.isFinite(minWeight)) {
      throwHttpError(url, 400, { error: 'invalid minWeight', minWeight: minWeightRaw });
    }
    if (maxWeightRaw != null && !Number.isFinite(maxWeight)) {
      throwHttpError(url, 400, { error: 'invalid maxWeight', maxWeight: maxWeightRaw });
    }
    if (minWeight != null && maxWeight != null && minWeight > maxWeight) {
      throwHttpError(url, 400, { error: 'invalid weight range', minWeight, maxWeight });
    }
    const sort = scalarSearchParam(parsed, 'sort', url, 'invalid sort') ?? 'rank';
    if (!['rank', 'weight', 'updated', 'created', 'closed', 'number'].includes(sort)) {
      throwHttpError(url, 400, { error: 'invalid sort', sort });
    }
    const direction = scalarSearchParam(parsed, 'direction', url, 'invalid direction') ?? (sort === 'rank' ? 'asc' : 'desc');
    if (!['asc', 'desc'].includes(direction)) {
      throwHttpError(url, 400, { error: 'invalid direction', direction });
    }
    const summaryOnlyRaw = scalarSearchParam(parsed, 'summaryOnly', url, 'invalid summaryOnly');
    if (summaryOnlyRaw != null && !['1', 'true', 'yes', '0', 'false', 'no'].includes(summaryOnlyRaw.toLowerCase())) {
      throwHttpError(url, 400, { error: 'invalid summaryOnly', summaryOnly: summaryOnlyRaw });
    }
    const summaryOnly = ['1', 'true', 'yes'].includes(String(summaryOnlyRaw ?? '').toLowerCase());
    const rows = (!tiers.length || tiers.includes(row.tier)) &&
      (!impacts.length || impacts.includes(row.installImpactClass)) &&
      (!states.length || states.includes(row.issue.state)) &&
      (!sentiments.length || sentiments.includes(row.issue.classification.sentiment)) &&
      (!severities.length || severities.includes(row.issue.classification.severity)) &&
      (!functionalities.length || functionalities.includes(row.issue.classification.functionality)) &&
      (!scopes.length || scopes.includes(row.issue.classification.scope)) &&
      (!affectedUsers.length || affectedUsers.includes(row.issue.classification.affectedUsers)) &&
      (issueFilter == null || row.issue.number === issueFilter) &&
      (fieldConfirmed == null || row.fieldConfirmed === fieldConfirmed) &&
      (minWeight == null || row.weight >= minWeight) &&
      (maxWeight == null || row.weight <= maxWeight)
      ? [row]
      : [];
    const cursor = integerSearchParam(parsed, 'cursor', url, 0, 0, Number.MAX_SAFE_INTEGER);
    const limit = integerSearchParam(parsed, 'limit', url, 50, 1, 250);
    const pageRows = summaryOnly ? [] : rows.slice(cursor, cursor + limit);
    const summaryFor = (count: number) => ({
      count,
      weight: count ? 1 : 0,
      fieldConfirmedCount: count ? 1 : 0,
      openCount: 0,
      closedCount: count,
      otherStateCount: 0,
      missingIssueCount: 0,
      byInstallImpactClass: count ? { state_data: 1 } : {},
      weightByInstallImpactClass: count ? { state_data: 1 } : {},
    });
    const countsByTier = {
      verifiedDebt: 0,
      carryoverDebt: 0,
      staleDebt: 0,
      openedFeltSerious: 0,
      verifiedFixed: 1,
      unverifiedClosed: 0,
      unclassifiedIssues: 0,
    };
    const filteredCountsByTier = { ...countsByTier, verifiedFixed: rows.length };
    const summaryByTier = {
      verifiedDebt: summaryFor(0),
      carryoverDebt: summaryFor(0),
      staleDebt: summaryFor(0),
      openedFeltSerious: summaryFor(0),
      verifiedFixed: summaryFor(1),
      unverifiedClosed: summaryFor(0),
      unclassifiedIssues: summaryFor(0),
    };
    const filteredSummaryByTier = { ...summaryByTier, verifiedFixed: summaryFor(rows.length) };
    return {
      schemaVersion: 1,
      tag: 'v1',
      sourceMode: 'current_db',
      scoredAt: auditScoredAt,
      dataFreshness,
      labelCutoffAt: null,
      filters: {
        tier: tiers.length === 1 ? tiers[0] : null,
        tiers: tiers.length ? tiers : null,
        impact: impacts.length === 1 ? impacts[0] : null,
        impacts: impacts.length ? impacts : null,
        state: states.length === 1 ? states[0] : null,
        states: states.length ? states : null,
        sentiment: sentiments.length === 1 ? sentiments[0] : null,
        sentiments: sentiments.length ? sentiments : null,
        severity: severities.length === 1 ? severities[0] : null,
        severities: severities.length ? severities : null,
        functionality: functionalities.length === 1 ? functionalities[0] : null,
        functionalities: functionalities.length ? functionalities : null,
        scope: scopes.length === 1 ? scopes[0] : null,
        scopes: scopes.length ? scopes : null,
        affectedUsers: affectedUsers.length === 1 ? affectedUsers[0] : null,
        affectedUsersList: affectedUsers.length ? affectedUsers : null,
        issue: issueFilter,
        issueNumber: issueFilter,
        fieldConfirmed,
        minWeight,
        maxWeight,
        sort,
        direction,
        summaryOnly,
      },
      countsByTier,
      summaryByTier,
      unfilteredCountsByTier: countsByTier,
      unfilteredSummaryByTier: summaryByTier,
      filteredCountsByTier,
      filteredSummaryByTier,
      tierInfo: {
        verifiedDebt: {
          label: 'Field blocker debt',
          description: 'Release-local field/community-confirmed blocker evidence that counts as hard open debt.',
        },
        carryoverDebt: {
          label: 'Open unconfirmed issue risk',
          description: 'Open negative issues overlapping this release that are inherited, source-only, or otherwise not proven release-local field blockers.',
        },
        staleDebt: {
          label: 'Stale or weak evidence',
          description: 'Open negative issues with stale, needs-info, low-confidence, low-severity, docs, or otherwise weak evidence.',
        },
        openedFeltSerious: {
          label: 'Opened field-visible reports',
          description: 'Field-visible high/critical reports opened during this release window.',
        },
        verifiedFixed: {
          label: 'Verified release fixes',
          description: 'Closed issues credited as fixed by code proof reachable from this release tag.',
        },
        unverifiedClosed: {
          label: 'Closed issues without release-fix credit',
          description: 'Closed release-window issues that do not receive direct release-fix credit.',
        },
        unclassifiedIssues: {
          label: 'Unclassified attributed issues',
          description: 'Attributed issues missing current classification rows.',
        },
      },
      totals: {
        unfilteredRows: 1,
        filteredRows: rows.length,
        unfilteredDistinctIssues: 1,
        filteredDistinctIssues: rows.length,
      },
      total: rows.length,
      totalRows: rows.length,
      distinctIssueCount: rows.length,
      limit: summaryOnly ? 0 : limit,
      cursor: summaryOnly ? 0 : cursor,
      nextCursor: summaryOnly ? null : cursor + pageRows.length < rows.length ? cursor + pageRows.length : null,
      filteredSummary: { count: rows.length, weight: rows.length ? 1 : 0, fieldConfirmedCount: rows.length ? 1 : 0, openCount: 0, closedCount: rows.length, otherStateCount: 0, missingIssueCount: 0, byInstallImpactClass: rows.length ? { state_data: 1 } : {}, weightByInstallImpactClass: rows.length ? { state_data: 1 } : {} },
      rows: pageRows,
    };
  };
  return async (url: string) => {
    if (url.endsWith('/api/status')) {
      return { schemaVersion: 1, refreshing: false, lastError: null, lastRefreshAt: null, processLastRefreshAt: null, lastScoredAt: auditScoredAt, dataFreshness };
    }
    if (url.endsWith('/api/config')) return { schemaVersion: 1, releases: 10, refreshMinutes: 0 };
    if (url.endsWith('/api/public')) {
      return {
        schemaVersion: 4,
        repo: 'x/y',
        updatedAt: auditScoredAt,
        releases: [publicRelease],
      };
    }
    if (url.endsWith('/api/releases')) {
      return [{
        schemaVersion: 2,
        tag: 'v1',
        finalScore: 7.5,
        band: 'ok',
        status: 'eligible',
        recommended: true,
        reason: 'test reason',
        negativeIssues: 1,
        positiveIssues: 0,
        scoredAt: auditScoredAt,
        scoreAudit,
        explanation,
        dataFreshness,
        auditLinks,
      }];
    }
    if (url.endsWith('/api/releases/history')) {
      return [{
        schemaVersion: 2,
        tag: 'v1',
        publishedAt: '2026-01-01T00:00:00Z',
        finalScore: 7.5,
        status: 'eligible',
        band: 'ok',
        recommended: true,
        scoredAt: auditScoredAt,
        scoreAudit,
        dataFreshness,
        auditLinks,
      }];
    }
    if (url.endsWith('/api/comparison')) {
      return {
        schemaVersion: 1,
        snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
        releases: [{
          tag: 'v1',
          local: {
            schemaVersion: 1,
            score: 7.5,
            band: 'ok',
            status: 'eligible',
            recommended: true,
            reason: 'test reason',
            negativeIssues: 1,
            positiveIssues: 0,
            scoredAt: auditScoredAt,
            dataFreshness,
            components: { explanation },
            gateEvidence: {
              schemaVersion: 1,
              releaseChecks: releaseChecksFixture,
              artifactVerification: artifactVerificationFixture,
              fixProvenance: {
                closureProof: closureProofFixture(),
                releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
              },
            },
          },
          upstream: null,
          delta: { schemaVersion: 1, score: null, negativeIssues: null },
        }],
      };
    }
    if (url.includes('/api/releases/v1/review/closure-proofs')) return closurePage(url);
    if (url.includes('/api/releases/v1/review/reachability')) return reachabilityPage(url);
    if (url.includes('/api/releases/v1/review/issues')) return issueEvidencePage(url);
    if (url.endsWith('/api/releases/v1/review')) {
      return {
        tag: 'v1',
        local: {
          schemaVersion: 1,
          score: 7.5,
          band: 'ok',
          status: 'eligible',
          recommended: true,
          reason: 'test reason',
          negativeIssues: 1,
          positiveIssues: 0,
          scoredAt: auditScoredAt,
          dataFreshness,
          sourceProvenance,
          input: defaultScoreInput,
          issueEvidence: { schemaVersion: 1 },
          gateEvidence: {
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          },
          components: {
            schemaVersion: 1,
            components: {},
            evidenceCoverage: 1,
            hotfix: false,
            reason: 'test reason',
            explanation,
          },
        },
      };
    }
    throw new Error(`unexpected URL ${url}`);
  };
}

function apiFixtureFetchJsonWithMutatedExplanation(mutator: (explanation: any) => void) {
  const fetchJson = apiFixtureFetchJson();
  return async (url: string) => {
    const payload = JSON.parse(JSON.stringify(await fetchJson(url)));
    if (url.endsWith('/api/public')) {
      mutator(payload.releases[0].explanation);
    } else if (url.endsWith('/api/releases')) {
      mutator(payload[0].explanation);
    } else if (url.endsWith('/api/comparison')) {
      mutator(payload.releases[0].local.components.explanation);
    } else if (url.endsWith('/api/releases/v1/review')) {
      mutator(payload.local.components.explanation);
    }
    return payload;
  };
}

function throwHttpError(url: string, status: number, payload: unknown): never {
  const error: any = new Error(`${url} returned ${status}: ${JSON.stringify(payload)}`);
  error.status = status;
  error.body = JSON.stringify(payload);
  error.payload = payload;
  throw error;
}

function scalarSearchParam(parsed: URL, key: string, url: string, error: string, extra: Record<string, unknown> = {}): string | null {
  const values = parsed.searchParams.getAll(key);
  if (values.length === 0) return null;
  if (values.length > 1) throwHttpError(url, 400, { error, [key]: values, ...extra });
  const value = values[0].trim();
  return value ? value : null;
}

function integerSearchParam(parsed: URL, key: string, url: string, fallback: number, min: number, max: number): number {
  const value = scalarSearchParam(parsed, key, url, `invalid ${key}`);
  if (value == null) return fallback;
  if (!/^-?\d+$/.test(value)) throwHttpError(url, 400, { error: `invalid ${key}`, [key]: value });
  const number = Number(value);
  if (!Number.isSafeInteger(number)) throwHttpError(url, 400, { error: `invalid ${key}`, [key]: value });
  return Math.max(min, Math.min(max, number));
}

function issueNumberSearchParam(parsed: URL, url: string): number | null {
  const issue = scalarSearchParam(parsed, 'issue', url, 'invalid issue');
  const number = scalarSearchParam(parsed, 'number', url, 'invalid issue');
  if (issue == null && number == null) return null;
  const values = [issue, number].filter((value): value is string => value != null);
  const parsedValues = values.map((value) => Number(value));
  if (parsedValues.some((value) => !Number.isInteger(value) || value <= 0)) {
    throwHttpError(url, 400, { error: 'invalid issue', issue, number });
  }
  if (parsedValues.some((value) => value !== parsedValues[0])) {
    throwHttpError(url, 400, { error: 'invalid issue', issue, number });
  }
  return parsedValues[0];
}

describe('verifyReleaseAudit', () => {
  it('passes coherent DB and API invariants', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({ reader: reader(), apiBase: 'http://example.test', fetchJson });
    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.rows, [{ tag: 'v1', closed: 1, verified: 1, unverified: 0, proof: 1, counted: 1, notCounted: 0 }]);
  });

  it('allows the internal comparison endpoint to be disabled', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        if (url.endsWith('/api/comparison')) throw new Error(`${url} returned 404`);
        return fetchJson(url);
      },
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when the recommended flag does not match the scoring threshold policy', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{
          tag: 'v1',
          final_score: 7.5,
          state: 'eligible',
          recommended: 0,
          scored_at: auditScoredAt,
          score_reason: 'test reason',
          negative_issues: 1,
          positive_issues: 0,
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /recommended release tags/.test(failure)));
  });

  it('fails when releases API rows expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases')) {
          return [{ ...payload[0], unexpectedDebugField: true }];
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /releases row must not expose unknown keys: unexpectedDebugField/.test(failure)));
  });

  it('fails when persisted score audit payloads expose unexpected top-level keys', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ ...defaultScoreInput, debugInput: true }),
          components_json: JSON.stringify({
            schemaVersion: 1,
            components: {},
            evidenceCoverage: 1,
            hotfix: false,
            reason: 'test reason',
            explanation: scoreExplanationFixture(),
          }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 1, debugIssueEvidence: true }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
            debugGate: true,
          }),
        },
      }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson(),
    });

    assert.ok(result.failures.some((failure) => /score input payload has unexpected top-level key debugInput/.test(failure)));
    assert.ok(result.failures.some((failure) => /issue evidence payload has unexpected top-level key debugIssueEvidence/.test(failure)));
    assert.ok(result.failures.some((failure) => /gate evidence payload has unexpected top-level key debugGate/.test(failure)));
  });

  it('fails when review payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases/v1/review')) {
          return {
            ...payload,
            debugReview: true,
            local: {
              ...payload.local,
              debugLocal: true,
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review payload must not expose unknown keys: debugReview/.test(failure)));
    assert.ok(result.failures.some((failure) => /review local must not expose unknown keys: debugLocal/.test(failure)));
  });

  it('fails when comparison payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/comparison')) {
          return {
            ...payload,
            debugComparison: true,
            snapshot: { ...payload.snapshot, debugSnapshot: true },
            releases: [{
              ...payload.releases[0],
              debugComparisonRow: true,
              local: { ...payload.releases[0].local, debugLocal: true },
              upstream: {
                schemaVersion: 1,
                snapshotId: 1,
                tag: 'v1',
                score: 7.5,
                band: 'ok',
                status: 'eligible',
                recommended: true,
                reason: 'upstream',
                negativeIssues: 1,
                positiveIssues: 0,
                totalAttributedIssues: 1,
                visibleIssues: [],
                rawCardText: 'card',
                debugUpstream: true,
              },
              delta: { ...payload.releases[0].delta, debugDelta: true },
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /comparison payload must not expose unknown keys: debugComparison/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison snapshot must not expose unknown keys: debugSnapshot/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison release row must not expose unknown keys: debugComparisonRow/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison local must not expose unknown keys: debugLocal/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison upstream must not expose unknown keys: debugUpstream/.test(failure)));
    assert.ok(result.failures.some((failure) => /comparison delta must not expose unknown keys: debugDelta/.test(failure)));
  });

  it('fails when score ledger row identity drifts', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        const rows = explanation.scoreLedger.rows;
        rows.splice(rows.findIndex((row: any) => row.key === 'closureRisk'), 1);
        rows.find((row: any) => row.key === 'releaseVerification').label = 'Checks';
        rows.push({ ...rows.find((row: any) => row.key === 'coverage') });
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger component row order/.test(failure)));
    assert.ok(result.failures.some((failure) => /releaseVerification.*label/.test(failure)));
    assert.ok(result.failures.some((failure) => /duplicate keys: coverage/.test(failure)));
  });

  it('fails when score ledger caps use unknown or misordered identities', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        explanation.scoreLedger.caps = [
          { key: 'hotfixCeiling', label: 'Hotfix successor ceiling', ceiling: 8, applied: false, before: 7.5, after: 7.5, reason: 'test' },
          { key: 'closureRiskCeiling', label: 'Wrong closure label', ceiling: 7.9, applied: false, before: 7.5, after: 7.5, reason: 'test' },
          { key: 'mysteryCeiling', label: 'Mystery', ceiling: 7, applied: true, before: 7.5, after: 7, reason: 'test' },
        ];
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger cap order/.test(failure)));
    assert.ok(result.failures.some((failure) => /closureRiskCeiling.*label/.test(failure)));
    assert.ok(result.failures.some((failure) => /unknown cap key/.test(failure)));
  });

  it('fails when score explanation details lack canonical labels or use the wrong code category', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        delete explanation.positiveDetails[0].label;
        explanation.limitDetails[0].code = 'release_recommended';
        explanation.limitDetails[0].label = 'Release recommended';
        explanation.limitDetails[0].debugPayload = true;
      }),
    });

    assert.ok(result.failures.some((failure) => /positiveDetails\[0\] label must be present/.test(failure)));
    assert.ok(result.failures.some((failure) => /limitDetails\[0\] code .* must be known for limitDetails/.test(failure)));
    assert.ok(result.failures.some((failure) => /limitDetails\[0\] must not expose unknown keys: debugPayload/.test(failure)));
  });

  it('fails when score ledger band drifts from the release band', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJsonWithMutatedExplanation((explanation) => {
        explanation.scoreLedger.band = 'solid';
      }),
    });

    assert.ok(result.failures.some((failure) => /scoreLedger band .* must match release band/.test(failure)));
  });

  it('fails when summary release audit links drift from canonical endpoints', async () => {
    const fetchJson = apiFixtureFetchJson((_, publicRelease) => {
      publicRelease.auditLinks = {
        ...publicRelease.auditLinks,
        review: '/wrong/review',
      };
    });
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases')) {
          return [{
            ...payload[0],
            auditLinks: {
              ...payload[0].auditLinks,
              issues: '/wrong/issues',
            },
          }];
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /public release auditLinks must point at release audit endpoints/.test(failure)));
    assert.ok(result.failures.some((failure) => /releases row auditLinks must point at release audit endpoints/.test(failure)));
  });

  it('fails when dynamic audit endpoint payloads expose unexpected keys', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/issues') && !url.includes('not-a-tier')) {
          return { ...payload, debugPayload: true };
        }
        if (url.includes('/api/releases/v1/review/closure-proofs') && payload.rows?.[0]) {
          return { ...payload, rows: [{ ...payload.rows[0], debugRow: true }] };
        }
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return { ...payload, rows: [{ ...payload.rows[0], debugRow: true }] };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /issue evidence audit payload must not expose unknown keys: debugPayload/.test(failure)));
    assert.ok(result.failures.some((failure) => /closure proof audit row must not expose unknown keys: debugRow/.test(failure)));
    assert.ok(result.failures.some((failure) => /PR reachability audit row must not expose unknown keys: debugRow/.test(failure)));
  });

  it('fails when review payload exposes comparison data', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases/v1/review')) {
          return {
            ...payload,
            upstream: { score: 8.7 },
            snapshot: { id: 1 },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review payload must not expose internal\/comparison key upstream/.test(failure)));
    assert.ok(result.failures.some((failure) => /review payload must not expose internal\/comparison key snapshot/.test(failure)));
  });

  it('fails when data freshness sourceFetchedAtMax is not the max source timestamp', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        freshness.sourceFetchedAtMax = '2026-01-01T23:10:00Z';
      }),
    });

    assert.ok(result.failures.some((failure) => /sourceFetchedAtMax/.test(failure)));
  });

  it('fails when data freshness age arithmetic drifts', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        freshness.sources[0].ageHoursAtScore = 99;
      }),
    });

    assert.ok(result.failures.some((failure) => /issue_rows ageHoursAtScore/.test(failure)));
  });

  it('fails when API data freshness reports source evidence newer than the score', async () => {
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((freshness) => {
        const closureProofs = freshness.sources.find((source: any) => source.source === 'closure_proofs');
        closureProofs.maxAt = '2026-01-02T00:01:01Z';
        closureProofs.ageHoursAtScore = -0.02;
        freshness.closureProofCheckedAtMax = closureProofs.maxAt;
        freshness.sourceFetchedAtMax = closureProofs.maxAt;
        freshness.sourceFetchedAgeHoursAtScore = -0.02;
      }),
    });

    assert.ok(result.failures.some((failure) => /closure_proofs changed .* newer than scoredAt/.test(failure)));
  });

  it('fails when proof audit endpoints use stale score timestamps', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/closure-proofs')) {
          return { ...payload, scoredAt: '2025-12-31T00:00:00Z' };
        }
        if (url.includes('/api/releases/v1/review/reachability')) {
          return { ...payload, scoredAt: '2025-12-31T00:00:00Z' };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /closure proof audit scoredAt/.test(failure)));
    assert.ok(result.failures.some((failure) => /PR reachability audit scoredAt/.test(failure)));
  });

  it('fails when reachable PR reachability rows lack auditable commit identity', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return {
            ...payload,
            rows: [{
              ...payload.rows[0],
              tagCommitOid: null,
              mergeCommitOid: null,
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /must include full tagCommitOid/.test(failure)));
    assert.ok(result.failures.some((failure) => /must include full mergeCommitOid/.test(failure)));
  });

  it('fails when PR reachability evidence reason is not known', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.includes('/api/releases/v1/review/reachability') && payload.rows?.[0]) {
          return {
            ...payload,
            rows: [{
              ...payload.rows[0],
              evidence: { ...payload.rows[0].evidence, evidence: 'mystery_reachability_reason' },
            }],
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /evidence reason must be known/.test(failure)));
  });

  it('fails when review source provenance drifts from score freshness', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases/v1/review')) {
          return {
            ...payload,
            local: {
              ...payload.local,
              sourceProvenance: {
                ...payload.local.sourceProvenance,
                scoreTimestampAligned: false,
                rawRows: {
                  ...payload.local.sourceProvenance.rawRows,
                  issues: '/wrong/issues',
                },
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /scoreTimestampAligned/.test(failure)));
    assert.ok(result.failures.some((failure) => /rawRows must point at review row endpoints/.test(failure)));
  });

  it('fails when audit scalar columns drift from the release row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          final_score: 4.2,
          status: 'wait',
          band: 'wait',
          recommended: 0,
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify(defaultScoreInput),
          components_json: JSON.stringify({
            schemaVersion: 1,
            components: {},
            evidenceCoverage: 1,
            hotfix: false,
            reason: 'stale reason',
            explanation: scoreExplanationFixture(),
          }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });

    assert.ok(result.failures.some((failure) => /audit final_score/.test(failure)));
    assert.ok(result.failures.some((failure) => /audit status/.test(failure)));
    assert.ok(result.failures.some((failure) => /audit recommended/.test(failure)));
    assert.ok(result.failures.some((failure) => /score components reason/.test(failure)));
  });

  it('fails when review input masks stale persisted audit input', async () => {
    const fetchJson = apiFixtureFetchJson();
    const result = await verifyReleaseAudit({
      reader: reader(),
      apiBase: 'http://example.test',
      fetchJson: async (url: string) => {
        const payload = await fetchJson(url);
        if (url.endsWith('/api/releases/v1/review')) {
          return {
            ...payload,
            local: {
              ...payload.local,
              input: {
                ...payload.local.input,
                rawIssueCount: 999,
              },
            },
          };
        }
        return payload;
      },
    });

    assert.ok(result.failures.some((failure) => /review input must match persisted audit input/.test(failure)));
  });

  it('fails when review closure proof masks stale persisted audit proof payload', async () => {
    const staleProof = closureProofFixture({
      examples: [{ number: 999, status: 'fixed_in_release', riskWeight: 0 }],
    });
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ schemaVersion: 1, components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: staleProof,
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson(),
    });

    assert.ok(result.failures.some((failure) => /review closureProof must match persisted audit closureProof/.test(failure)));
  });

  it('fails when public issue summaries omit capped release-universe rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({ issueNumbers: [1, 2] }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((_, publicRelease) => {
        publicRelease.totalAttributedIssues = 2;
        publicRelease.scoreAudit.rawIssueCount = 2;
      }),
    });

    assert.ok(result.failures.some((failure) => /public issues length/.test(failure)));
  });

  it('fails when public issue summaries include issues outside the release universe', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({ issueNumbers: [1] }),
      apiBase: 'http://example.test',
      fetchJson: apiFixtureFetchJson((_, publicRelease) => {
        publicRelease.issues = [{
          number: 999,
          title: 'outside issue',
          url: 'https://github.com/x/y/issues/999',
          affectedUsers: 'some',
        }];
      }),
    });

    assert.ok(result.failures.some((failure) => /public issue #999 must belong/.test(failure)));
  });

  it('fails when audit fix counts drift from verified queries', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 2,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.equal(result.failures.length, 1);
    assert.match(result.failures[0], /verifiedFixedCount/);
  });

  it('fails when raw closed issues are missing classifications', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        rawClosed: [{ number: 1 }, { number: 2 }],
        closed: [{ number: 1, prompt_version: 6 }],
      }),
    });
    assert.ok(result.failures.some((failure) => /raw closed release-window issues/.test(failure)));
  });

  it('fails when non-recommended scored releases hide raw closed issues without proof rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        releases: [{ tag: 'v1', final_score: 5.8, state: 'eligible', recommended: 0, scored_at: auditScoredAt }],
        rawClosed: [{ number: 1 }],
        closed: [],
        verified: [],
        unverified: [],
        proofRows: [],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: {
              ...labelTimelineFixture,
              issueCount: 0,
              currentLabelCount: 0,
            },
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 0,
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /raw closed release-window issues/.test(failure)));
    assert.ok(result.failures.some((failure) => /closure proofs .* raw closed release-window issues/.test(failure)));
  });

  it('fails when closed-window classifications are stale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 5 }],
        verified: [{ number: 1, sentiment: 'negative', prompt_version: 5 }],
      }),
    });
    assert.ok(result.failures.some((failure) => /classification prompt_version/.test(failure)));
  });

  it('fails when proof rows are newer than their score audit', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: '2026-01-02T00:00:02Z',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /must not be newer than audit scored_at/.test(failure)));
  });

  it('fails when proof dependency source evidence is newer than the proof row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: [
          ...proofDependencyFreshnessFixture.filter((source) => source.source !== 'issue_pr_links'),
          {
            source: 'issue_pr_links',
            max_ts: '2026-01-02T00:00:00.500Z',
          },
        ],
      }),
    });
    assert.ok(result.failures.some((failure) => /newer than issue_pr_links dependency/.test(failure)));
  });

  it('fails when linked PR metadata is newer than the proof row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: [
          ...proofDependencyFreshnessFixture.filter((source) => source.source !== 'pull_request_fixes'),
          {
            source: 'pull_request_fixes',
            max_ts: '2026-01-02T00:00:00.500Z',
          },
        ],
      }),
    });
    assert.ok(result.failures.some((failure) => /newer than pull_request_fixes dependency/.test(failure)));
  });

  it('fails when proof dependency freshness omits a required source', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofDependencyFreshness: proofDependencyFreshnessFixture
          .filter((source) => source.source !== 'pull_request_fixes'),
      }),
    });
    assert.ok(result.failures.some((failure) => /dependency freshness must include pull_request_fixes/.test(failure)));
  });

  it('fails when source evidence changed after the score audit', async () => {
    const staleReader = reader();
    staleReader.sourceFreshnessFor = () => [{
      source: 'issue_rows',
      max_ts: '2026-01-02T00:00:02Z',
    }];
    const result = await verifyReleaseAudit({ reader: staleReader });
    assert.ok(result.failures.some((failure) => /issue_rows changed/.test(failure)));
  });

  it('allows one-second GitHub closure event timestamp skew', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            closedAt: '2026-01-01T00:00:00Z',
            closureEventClosedAt: ['2026-01-01T00:00:01Z'],
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(!result.failures.some((failure) => /closure event timestamp/.test(failure)));
  });

  it('fails when proof closure event timestamp does not match issue closedAt within tolerance', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            closedAt: '2026-01-01T00:00:00Z',
            closureEventClosedAt: ['2026-01-03T00:00:00Z'],
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /closure event timestamp/.test(failure)));
  });

  it('fails when reachable PR proof lacks backing reachability rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [],
      }),
    });
    assert.ok(result.failures.some((failure) => /merged reachable PR row/.test(failure)));
  });

  it('fails when embedded linked PR proof is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'fixed_in_release',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: true,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            linkedPrs: [{
              number: 1,
              merged: 1,
              reachabilityStatus: 'reachable',
              reachabilityEvidence: 'merge_commit_in_release_history',
            }],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*repositoryNameWithOwner/.test(failure)));
    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*must include source/.test(failure)));
    assert.ok(result.failures.some((failure) => /linkedPrs\[0\].*must include known state/.test(failure)));
  });

  it('fails when related PR context proof is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'related_open_pr_context',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            relatedPrContext: {
              open: [{ number: 44 }],
            },
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /relatedPrContext\.open\[0\].*repositoryNameWithOwner/.test(failure)));
    assert.ok(result.failures.some((failure) => /relatedPrContext\.open\[0\].*must include source/.test(failure)));
  });

  it('fails when canonical open PR evidence is missing identity fields', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          release_tag: 'v1',
          issue_number: 1,
          status: 'superseded_to_open_pr',
          checked_at: proofCheckedAt,
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalOpenPrs: [{ number: 45, repositoryNameWithOwner: 'openclaw/openclaw' }],
            stateReasons: ['COMPLETED'],
          }),
        }],
      }),
    });

    assert.ok(result.failures.some((failure) => /canonicalOpenPrs\[0\].*must include source/.test(failure)));
    assert.ok(result.failures.some((failure) => /canonicalOpenPrs\[0\].*must include known state/.test(failure)));
  });

  it('fails when reachable linked PR proof is backed by a different PR row', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 2,
          merged: 1,
          status: 'reachable',
          tag_commit_oid: tagOid,
          release_tag_commit_oid: tagOid,
          merge_commit_oid: 'c'.repeat(40),
          evidence_json: JSON.stringify({
            schemaVersion: 1,
            evidence: 'merge_commit_in_release_history',
            method: 'git-merge-base',
            tagCommitOid: tagOid,
            checkedCommitOid: 'c'.repeat(40),
            baseRefName: 'main',
            commandStatus: 0,
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /hasReachableClosingPr must have a merged reachable PR row/.test(failure)));
  });

  it('fails when embedded linked PR reachability disagrees with persisted reachability rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 1,
          merged: 1,
          status: 'not_reachable',
          tag_commit_oid: tagOid,
          release_tag_commit_oid: tagOid,
          merge_commit_oid: mergeOid,
          evidence_json: JSON.stringify({
            schemaVersion: 1,
            evidence: 'not_reachable_from_release_tag',
            method: 'git-merge-base',
            tagCommitOid: tagOid,
            checkedCommitOid: mergeOid,
            baseRefName: 'main',
            commandStatus: 1,
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /reachabilityStatus .* must match persisted reachability/.test(failure)));
  });

  it('fails when unknown PR reachability lacks an evidence reason', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'no_code_proof',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        prEvidence: [{
          issue_number: 1,
          pr_repository_name_with_owner: 'openclaw/openclaw',
          pr_number: 1,
          merged: 1,
          status: 'unknown',
          tag_commit_oid: null,
          release_tag_commit_oid: null,
          evidence_json: '{}',
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { no_code_proof: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 2.125,
                  weightedRiskByDisposition: { unsupported_closure_claim: 2.125 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /unknown reachability must include evidence reason/.test(failure)));
  });

  it('fails when persisted closure proof lacks representative examples for non-fixed statuses', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'repro_requested',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        prEvidence: [],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { repro_requested: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 2.125,
                  weightedRiskByDisposition: { unsupported_closure_claim: 2.125 },
                },
                examplesByStatus: {},
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /persisted closureProof examplesByStatus must include at least one repro_requested example/.test(failure)));
  });

  it('fails when score closure-risk input is stale against proof risk summary', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_open_canonical',
          risk_disposition: 'open_canonical_risk',
          risk_weight: 3.188,
          evidence_json: JSON.stringify({
            canonicalIssue: 999,
            canonicalResolution: { terminalIssue: { number: 999, state: 'open' } },
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({
            ...defaultScoreInput,
            unresolvedClosureIssueCount: 0,
            unresolvedClosureRiskWeight: 0,
          }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_open_canonical: 1 },
                byRiskDisposition: { open_canonical_risk: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 1,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.188,
                  weightedRiskByDisposition: { open_canonical_risk: 3.188 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });

    assert.ok(result.failures.some((failure) => /unresolvedClosureIssueCount/.test(failure)));
    assert.ok(result.failures.some((failure) => /unresolvedClosureRiskWeight/.test(failure)));
  });

  it('fails when persisted closure proof schema version is missing', async () => {
    const closureProof = closureProofFixture();
    delete closureProof.schemaVersion;
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof,
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted closureProof schemaVersion/.test(failure)));
  });

  it('fails when persisted release fix credit schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted releaseFixCredit schemaVersion/.test(failure)));
  });

  it('fails when persisted issue evidence schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: '{}',
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted issueEvidence schemaVersion/.test(failure)));
  });

  it('fails when label timeline schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: { ...labelTimelineFixture, schemaVersion: undefined },
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /labelTimeline schemaVersion/.test(failure)));
  });

  it('fails when gate evidence schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 0,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted gateEvidence schemaVersion/.test(failure)));
  });

  it('fails when score input schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ schemaVersion: 1, components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted score input schemaVersion/.test(failure)));
  });

  it('fails when score components schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({ schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 }),
          components_json: JSON.stringify({ components: {}, explanation: { schemaVersion: 1 } }),
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            schemaVersion: 1,
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /persisted score components schemaVersion/.test(failure)));
  });

  it('fails when release checks schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            releaseChecks: { ...releaseChecksFixture, schemaVersion: undefined },
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /releaseChecks schemaVersion/.test(failure)));
  });

  it('fails when artifact verification schema version is missing', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          issue_evidence_json: JSON.stringify({ schemaVersion: 1 }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            releaseChecks: releaseChecksFixture,
            artifactVerification: { ...artifactVerificationFixture, schemaVersion: undefined },
            fixProvenance: {
              verifiedFixedCount: 1,
              unverifiedClosedCount: 0,
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /artifactVerification schemaVersion/.test(failure)));
  });

  it('fails when canonical-open proof does not resolve to open terminal', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_open_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: { terminalIssue: { state: 'closed' } },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_open_canonical: 1 },
                byRiskDisposition: { open_canonical_risk: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 1,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.188,
                  weightedRiskByDisposition: { open_canonical_risk: 3.188 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /open terminal/.test(failure)));
  });

  it('fails when closed canonical proof should use a more specific status', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_closed_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: {
              terminalIssue: { state: 'closed' },
              terminalProof: { status: 'fixed_in_release', summary: 'canonical was fixed in this release' },
            },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_closed_canonical: 1 },
                byRiskDisposition: { unsupported_closure_claim: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 1,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 1,
                  weightedRiskByDisposition: { unsupported_closure_claim: 1 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /more specific canonical status/.test(failure)));
  });

  it('fails when weak not-planned canonical terminal proof is treated as non-actionable', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'duplicate_to_non_actionable_canonical',
          evidence_json: JSON.stringify({
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
            canonicalResolution: {
              terminalIssue: { state: 'closed' },
              terminalProof: { status: 'not_planned', summary: 'canonical was closed not planned' },
            },
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { duplicate_to_non_actionable_canonical: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) => /not_planned terminal proof must include concrete non-actionable rationale/.test(failure)));
  });

  it('fails when negative NOT_PLANNED is neutral without concrete rationale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'not_planned',
          evidence_json: JSON.stringify({
            stateReasons: ['NOT_PLANNED'],
            matchingComments: [],
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { not_planned: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.ok(result.failures.some((failure) =>
      /negative NOT_PLANNED issue #1 cannot be neutral\/non-actionable without concrete close-time rationale/.test(failure)));
  });

  it('allows negative NOT_PLANNED neutralization with concrete outside-repo rationale', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1, prompt_version: 6 }],
        verified: [],
        unverified: [{ number: 1, prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'not_planned',
          evidence_json: JSON.stringify({
            stateReasons: ['NOT_PLANNED'],
            nonActionableRationaleComments: [{
              snippet: 'Close: this lives outside the OpenClaw source repository and is plugin-owned.',
            }],
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { not_planned: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when commit proof uses short hashes or mismatched flags', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: ['cfeaf6897fd8'],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd8',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Fix evidence commit cfeaf6897fd8',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /40-hex SHA/.test(failure)));
    assert.ok(result.failures.some((failure) => /hasReachableFixCommit/.test(failure)));
  });

  it('fails when unknown direct fix commit proof omits unknown commit evidence', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'direct_fix_commit_reachability_unknown',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /must set hasUnknownFixCommit/.test(failure)));
    assert.ok(result.failures.some((failure) => /must include unknownFixCommits/.test(failure)));
    assert.ok(result.failures.some((failure) => /unknownFixCommits must equal/.test(failure)));
  });

  it('fails when admin not-planned proof hides unknown direct fix commit evidence', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'admin_not_planned_unverified',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: true,
            stateReasons: ['NOT_PLANNED'],
            closureContextCommentCount: 1,
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: ['cfeaf6897fd89201b71ff7d5285e48c5a382ac9a'],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /admin_not_planned_unverified issue #1 must not have direct fix proof/.test(failure)));
  });

  it('accepts unknown direct fix commit proof with explicit unknown commit evidence', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        verified: [],
        unverified: [{ number: 1, sentiment: 'negative', prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'direct_fix_commit_reachability_unknown',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: true,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: [commit],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: `Fix evidence commit ${commit}`,
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          input_json: JSON.stringify({
            ...defaultScoreInput,
            unresolvedClosureIssueCount: 1,
            unresolvedClosureRiskWeight: 3.984,
          }),
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { direct_fix_commit_reachability_unknown: 1 },
                byRiskDisposition: { missing_evidence: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 1,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.984,
                  weightedRiskByDisposition: { missing_evidence: 3.984 },
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.deepEqual(result.failures, []);
  });

  it('accepts neutral unknown direct fix commit proof as non-actionable audit evidence', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        verified: [],
        unverified: [{ number: 1, sentiment: 'neutral', prompt_version: 6 }],
        proofRows: [{
          issue_number: 1,
          status: 'non_bug_direct_fix_commit_reachability_unknown',
          title: 'neutral source proof note',
          sentiment: 'neutral',
          severity: 'low',
          functionality: 'docs',
          scope: 'niche',
          affected_users: 'few',
          evidence_json: JSON.stringify({
            closureClassification: {
              classification: {
                sentiment: 'neutral',
                severity: 'low',
                functionality: 'docs',
                scope: 'niche',
                affectedUsers: 'few',
              },
            },
            hasReachableClosingPr: false,
            hasReachableFixCommit: false,
            hasNotReachableFixCommit: false,
            hasUnknownFixCommit: true,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            unknownFixCommits: [commit],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ClosureComment.fixProof',
              status: 'unknown',
              tagCommitOid: null,
              evidence: 'commit_unavailable',
              snippet: `Fix evidence commit ${commit}`,
              trustedSource: true,
              author: 'maintainer',
            }],
          }),
        }],
        audit: {
          prompt_version: 6,
          scored_at: auditScoredAt,
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: closureProofFixture({
                creditedCount: 0,
                notCreditedCount: 1,
                byStatus: { non_bug_direct_fix_commit_reachability_unknown: 1 },
                byRiskDisposition: { neutral_or_non_actionable: 1 },
                riskSummary: {
                  creditedReleaseFixCount: 0,
                  resolvedByCanonicalReleaseFixCount: 0,
                  resolvedByReleaseFixProofCount: 0,
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 0,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 1,
                  neutralHighImpactCount: 0,
                  neutralBugShapedCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 0,
                  unresolvedWeightedRisk: 0,
                  weightedRiskByDisposition: {},
                },
              }),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.deepEqual(result.failures, []);
  });

  it('fails when reachable commit arrays do not match proof entry statuses', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Fix evidence commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /reachableFixCommits must equal/.test(failure)));
  });

  it('accepts referenced event commit proof as a known source', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [commit],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'ReferencedEvent.commit',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'GitHub ReferencedEvent same-repo commit cfeaf6897fd89201b71ff7d5285e48c5a382ac9a: fix(test): prove path',
            }],
          }),
        }],
      }),
    });
    assert.ok(!result.failures.some((failure) => /unknown source|closure-comment commit proof/.test(failure)));
  });

  it('fails when commit proof source is unknown', async () => {
    const commit = 'cfeaf6897fd89201b71ff7d5285e48c5a382ac9a';
    const result = await verifyReleaseAudit({
      reader: reader({
        proofRows: [{
          issue_number: 1,
          status: 'fixed_in_release',
          evidence_json: JSON.stringify({
            hasReachableClosingPr: false,
            hasReachableFixCommit: true,
            hasNotReachableFixCommit: false,
            stateReasons: ['COMPLETED'],
            reachableFixCommits: [commit],
            notReachableFixCommits: [],
            fixCommitProof: [{
              issueNumber: 1,
              sourceIssueNumber: 1,
              commitOid: commit,
              source: 'AdHocCommit',
              status: 'reachable',
              tagCommitOid: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
              evidence: 'fix_commit_in_release_history',
              snippet: 'Ad hoc commit proof',
            }],
          }),
        }],
      }),
    });
    assert.ok(result.failures.some((failure) => /unknown source AdHocCommit/.test(failure)));
  });
});
