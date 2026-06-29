import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyReleaseAudit } from '../../scripts/lib/release-audit-invariants.mjs';

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
  schemaVersion: 1,
  state: 'SUCCESS',
  total: 1,
  success: 1,
  failure: 0,
  pending: 0,
  skipped: 0,
  contexts: [],
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
  verified: any[];
  unverified: any[];
  proofRows: any[];
  prEvidence: any[];
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
        stateReasons: ['COMPLETED'],
      }),
    }],
    prEvidence: [{
      issue_number: 1,
      pr_repository_name_with_owner: 'openclaw/openclaw',
      pr_number: 1,
      merged: 1,
      status: 'reachable',
      tag_commit_oid: 'tag-commit',
      release_tag_commit_oid: 'tag-commit',
    }],
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
    data.audit = { ...data.audit, input_json: JSON.stringify({ schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 }) };
  }
  if (data.audit && data.audit.components_json === undefined) {
    data.audit = { ...data.audit, components_json: JSON.stringify({ schemaVersion: 1, components: {}, explanation: { schemaVersion: 1 } }) };
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
    getReleaseScoreAudit: () => data.audit,
    sourceFreshnessFor: () => [],
  };
}

function apiFixtureFetchJson(mutator?: (dataFreshness: any) => void) {
  const scoreAudit = {
    schemaVersion: 1,
    modelVersion: 'test-model',
    promptVersion: 6,
    evidenceCoverage: 1,
    rawIssueCount: 1,
    classifiedIssueCount: 1,
  };
  const explanation = {
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
        { key: 'carryoverDebt', label: 'Source/carryover risk', points: 0, kind: 'neutral' },
        { key: 'staleDebt', label: 'Stale/low-confidence risk', points: 0, kind: 'neutral' },
        { key: 'closureRisk', label: 'Closed-release risk', points: 0, kind: 'neutral' },
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
      text: 'The release is eligible and recommended.',
    }],
    limits: ['One closed issue still needs release proof.'],
    limitDetails: [{
      code: 'closed_issues_not_counted_as_release_fixes',
      text: 'One closed issue still needs release proof.',
      metrics: { notCountedClosedCount: 1 },
      issueRefs: [{ number: 1, title: 'issue 1', url: 'https://github.com/x/y/issues/1' }],
    }],
    verdict: 'This means the release is the current recommended install candidate under the audit gates, but the audit still contains evidence.',
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
      { source: 'issue_rows', maxAt: '2026-01-01T23:00:00Z', ageHoursAtScore: 1 },
      { source: 'classification_rows', maxAt: '2026-01-01T23:10:00Z', ageHoursAtScore: 0.83 },
      { source: 'closure_proofs', maxAt: proofCheckedAt, ageHoursAtScore: 0 },
      { source: 'release_metadata', maxAt: proofCheckedAt, ageHoursAtScore: 0 },
    ],
  };
  mutator?.(dataFreshness);
  const closurePage = (url: string) => {
    const parsed = new URL(url);
    const row = {
      issueNumber: 1,
      title: 'issue 1',
      url: 'https://github.com/x/y/issues/1',
      closedAt: '2026-01-01T12:00:00Z',
      status: 'fixed_in_release',
      summary: 'Fixed in release.',
      riskDisposition: 'credited_release_fix',
      riskWeight: 0,
      checkedAt: proofCheckedAt,
      labels: [],
      classification: {},
      classificationDiff: {},
      evidence: {},
    };
    const rows = (!parsed.searchParams.get('status') || parsed.searchParams.get('status') === row.status) &&
      (!parsed.searchParams.get('riskDisposition') || parsed.searchParams.get('riskDisposition') === row.riskDisposition)
      ? [row]
      : [];
    const cursor = Number(parsed.searchParams.get('cursor') ?? 0);
    const limit = Number(parsed.searchParams.get('limit') ?? 50);
    const pageRows = rows.slice(cursor, cursor + limit);
    return {
      schemaVersion: 1,
      tag: 'v1',
      filters: {
        status: parsed.searchParams.get('status'),
        riskDisposition: parsed.searchParams.get('riskDisposition'),
      },
      total: rows.length,
      limit,
      cursor,
      nextCursor: cursor + pageRows.length < rows.length ? cursor + pageRows.length : null,
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
        schemaVersion: 1,
        repo: 'x/y',
        updatedAt: auditScoredAt,
        releases: [{
          schemaVersion: 1,
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
          totalAttributedIssues: 1,
          issues: [{
            number: 1,
            title: 'issue 1',
            url: 'https://github.com/x/y/issues/1',
            affectedUsers: 'some',
          }],
        }],
      };
    }
    if (url.endsWith('/api/releases')) {
      return [{
        schemaVersion: 1,
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
      }];
    }
    if (url.endsWith('/api/releases/history')) {
      return [{ schemaVersion: 1, tag: 'v1', publishedAt: '2026-01-01T00:00:00Z', finalScore: 7.5 }];
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
    if (url.endsWith('/api/releases/v1/review')) {
      return {
        snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
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
          input: { schemaVersion: 1, rawIssueCount: 1, classifiedIssueCount: 1 },
          issueEvidence: { schemaVersion: 1 },
          gateEvidence: {
            schemaVersion: 1,
            releaseChecks: releaseChecksFixture,
            artifactVerification: artifactVerificationFixture,
            fixProvenance: {
              closureProof: closureProofFixture(),
              releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          },
          components: { schemaVersion: 1, explanation },
        },
      };
    }
    throw new Error(`unexpected URL ${url}`);
  };
}

describe('verifyReleaseAudit', () => {
  it('passes coherent DB and API invariants', async () => {
    const fetchJson = async (url: string) => {
      const scoreAudit = {
        schemaVersion: 1,
        modelVersion: 'test-model',
        promptVersion: 6,
        evidenceCoverage: 1,
        rawIssueCount: 1,
        classifiedIssueCount: 1,
      };
      const explanation = {
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
            { key: 'carryoverDebt', label: 'Source/carryover risk', points: 0, kind: 'neutral' },
            { key: 'staleDebt', label: 'Stale/low-confidence risk', points: 0, kind: 'neutral' },
            { key: 'closureRisk', label: 'Closed-release risk', points: 0, kind: 'neutral' },
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
          text: 'The release is eligible and recommended.',
        }],
        limits: ['One closed issue still needs release proof.'],
        limitDetails: [{
          code: 'closed_issues_not_counted_as_release_fixes',
          text: 'One closed issue still needs release proof.',
          metrics: { notCountedClosedCount: 1 },
          issueRefs: [{ number: 1, title: 'issue 1', url: 'https://github.com/x/y/issues/1' }],
        }],
        verdict: 'This means the release is the current recommended install candidate under the audit gates, but the audit still contains evidence.',
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
          { source: 'issue_rows', maxAt: '2026-01-01T23:00:00Z', ageHoursAtScore: 1 },
          { source: 'classification_rows', maxAt: '2026-01-01T23:10:00Z', ageHoursAtScore: 0.83 },
          { source: 'closure_proofs', maxAt: proofCheckedAt, ageHoursAtScore: 0 },
          { source: 'release_metadata', maxAt: proofCheckedAt, ageHoursAtScore: 0 },
        ],
      };
      if (url.endsWith('/api/status')) {
        return { schemaVersion: 1, refreshing: false, lastError: null, lastRefreshAt: null, processLastRefreshAt: null, lastScoredAt: auditScoredAt, dataFreshness };
      }
      if (url.endsWith('/api/config')) {
        return { schemaVersion: 1, releases: 10, refreshMinutes: 0 };
      }
      if (url.endsWith('/api/public')) {
        return {
          schemaVersion: 1,
          repo: 'x/y',
          updatedAt: auditScoredAt,
          releases: [{
            schemaVersion: 1,
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
            totalAttributedIssues: 1,
            issues: [{
              number: 1,
              title: 'issue 1',
              url: 'https://github.com/x/y/issues/1',
              affectedUsers: 'some',
            }],
          }],
        };
      }
      if (url.endsWith('/api/releases')) {
        return [{
          schemaVersion: 1,
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
        }];
      }
      if (url.endsWith('/api/releases/history')) {
        return [{
          schemaVersion: 1,
          tag: 'v1',
          publishedAt: '2026-01-01T00:00:00Z',
          finalScore: 7.5,
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
      if (url.includes('/api/releases/v1/review/closure-proofs')) {
        const parsed = new URL(url);
        const row = {
          issueNumber: 1,
          title: 'issue 1',
          url: 'https://github.com/x/y/issues/1',
          closedAt: '2026-01-01T12:00:00Z',
          status: 'fixed_in_release',
          summary: 'Fixed in release.',
          riskDisposition: 'credited_release_fix',
          riskWeight: 0,
          checkedAt: proofCheckedAt,
          labels: [],
          classification: {},
          classificationDiff: {},
          evidence: {},
        };
        const rows = (!parsed.searchParams.get('status') || parsed.searchParams.get('status') === row.status) &&
          (!parsed.searchParams.get('riskDisposition') || parsed.searchParams.get('riskDisposition') === row.riskDisposition)
          ? [row]
          : [];
        const cursor = Number(parsed.searchParams.get('cursor') ?? 0);
        const limit = Number(parsed.searchParams.get('limit') ?? 50);
        const pageRows = rows.slice(cursor, cursor + limit);
        return {
          schemaVersion: 1,
          tag: 'v1',
          filters: {
            status: parsed.searchParams.get('status'),
            riskDisposition: parsed.searchParams.get('riskDisposition'),
          },
          total: rows.length,
          limit,
          cursor,
          nextCursor: cursor + pageRows.length < rows.length ? cursor + pageRows.length : null,
          rows: pageRows,
        };
      }
      if (url.endsWith('/api/releases/v1/review')) {
        return {
          snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
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
            input: {
              schemaVersion: 1,
              rawIssueCount: 1,
              classifiedIssueCount: 1,
            },
            issueEvidence: { schemaVersion: 1 },
            gateEvidence: {
              schemaVersion: 1,
              releaseChecks: releaseChecksFixture,
              artifactVerification: artifactVerificationFixture,
              fixProvenance: {
                closureProof: closureProofFixture(),
                releaseFixCredit: { schemaVersion: 1, countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
              },
            },
            components: { schemaVersion: 1, explanation },
          },
        };
      }
      throw new Error(`unexpected URL ${url}`);
    };
    const result = await verifyReleaseAudit({ reader: reader(), apiBase: 'http://example.test', fetchJson });
    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.rows, [{ tag: 'v1', closed: 1, verified: 1, unverified: 0, proof: 1, counted: 1, notCounted: 0 }]);
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
    assert.equal(result.failures.length, 1);
    assert.match(result.failures[0], /open terminal/);
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
