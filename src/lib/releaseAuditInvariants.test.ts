import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyReleaseAudit } from '../../scripts/lib/release-audit-invariants.mjs';

const labelTimelineFixture = {
  cutoffAt: null,
  issueCount: 1,
  currentLabelCount: 1,
  timelineLabelCount: 0,
  missingTimelineCount: 0,
  missingTimelineWithCurrentLabelsCount: 0,
  historicalCurrentLabelFallbackAllowed: true,
};
const proofCheckedAt = '2026-01-02T00:00:00Z';
const auditScoredAt = '2026-01-02T00:00:01Z';

function closureProofFixture(overrides: any = {}) {
  return {
    creditedCount: 1,
    notCreditedCount: 0,
    byStatus: { fixed_in_release: 1 },
    byRiskDisposition: { credited_release_fix: 1 },
    riskSummary: {
      creditedReleaseFixCount: 1,
      knownNotInReleaseCount: 0,
      openCanonicalRiskCount: 0,
      unsupportedClosureClaimCount: 0,
      neutralOrNonActionableCount: 0,
      missingEvidenceCount: 0,
      unresolvedForReleaseCount: 0,
      unresolvedWeightedRisk: 0,
      weightedRiskByDisposition: {},
    },
    ...overrides,
  };
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
    releases: [{ tag: 'v1', final_score: 7.5, state: 'eligible', recommended: 1, scored_at: auditScoredAt }],
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
      pr_number: 1,
      merged: 1,
      status: 'reachable',
      tag_commit_oid: 'tag-commit',
      release_tag_commit_oid: 'tag-commit',
    }],
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
    ...overrides,
  };
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
  };
}

describe('verifyReleaseAudit', () => {
  it('passes coherent DB and API invariants', async () => {
    const fetchJson = async (url: string) => {
      const scoreAudit = {
        modelVersion: 'test-model',
        promptVersion: 6,
        evidenceCoverage: 1,
        rawIssueCount: 1,
        classifiedIssueCount: 1,
      };
      const explanation = {
        schemaVersion: 1,
        title: 'Why not 10?',
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
      if (url.endsWith('/api/status')) {
        return { refreshing: false, lastError: null, lastRefreshAt: auditScoredAt, lastScoredAt: auditScoredAt };
      }
      if (url.endsWith('/api/public')) {
        return {
          schemaVersion: 1,
          repo: 'x/y',
          updatedAt: auditScoredAt,
          releases: [{
            tag: 'v1',
            score: 7.5,
            status: 'eligible',
            recommended: true,
            scoredAt: auditScoredAt,
            scoreAudit,
            explanation,
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
          tag: 'v1',
          finalScore: 7.5,
          status: 'eligible',
          recommended: true,
          scoredAt: auditScoredAt,
          scoreAudit,
          explanation,
        }];
      }
      if (url.endsWith('/api/comparison')) {
        return {
          snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
          releases: [{
            tag: 'v1',
            local: {
              components: { explanation },
              gateEvidence: {
                fixProvenance: {
                  closureProof: closureProofFixture(),
                  releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
                },
              },
            },
            upstream: null,
            delta: { score: null, negativeIssues: null },
          }],
        };
      }
      if (url.endsWith('/api/releases/v1/review')) {
        return {
          snapshot: { id: 1, sourceUrl: 'http://source.test', capturedAt: 't', pageTitle: 'Snapshot' },
          local: {
            score: 7.5,
            status: 'eligible',
            recommended: true,
            gateEvidence: {
              fixProvenance: {
                closureProof: closureProofFixture(),
                releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
              },
            },
            components: { explanation },
          },
        };
      }
      throw new Error(`unexpected URL ${url}`);
    };
    const result = await verifyReleaseAudit({ reader: reader(), apiBase: 'http://example.test', fetchJson });
    assert.deepEqual(result.failures, []);
    assert.deepEqual(result.rows, [{ tag: 'v1', closed: 1, verified: 1, unverified: 0, proof: 1, counted: 1, notCounted: 0 }]);
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
              releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
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

  it('fails when reachable PR proof lacks backing reachability rows', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        prEvidence: [],
      }),
    });
    assert.ok(result.failures.some((failure) => /merged reachable PR row/.test(failure)));
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
                  knownNotInReleaseCount: 0,
                  openCanonicalRiskCount: 1,
                  unsupportedClosureClaimCount: 0,
                  neutralOrNonActionableCount: 0,
                  missingEvidenceCount: 0,
                  unresolvedForReleaseCount: 1,
                  unresolvedWeightedRisk: 3.188,
                  weightedRiskByDisposition: { open_canonical_risk: 3.188 },
                },
              }),
              releaseFixCredit: { countedClosedCount: 0, notCountedClosedCount: 1, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.equal(result.failures.length, 1);
    assert.match(result.failures[0], /open terminal/);
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
});
