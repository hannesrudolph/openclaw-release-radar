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

function reader(overrides: Partial<{
  releases: any[];
  closed: any[];
  verified: any[];
  unverified: any[];
  proofRows: any[];
  audit: any;
}> = {}) {
  const data = {
    releases: [{ tag: 'v1', final_score: 7.5, state: 'eligible', recommended: 1, scored_at: 't' }],
    closed: [{ number: 1 }],
    verified: [{ number: 1, sentiment: 'negative' }],
    unverified: [],
    proofRows: [{
      release_tag: 'v1',
      issue_number: 1,
      status: 'fixed_in_release',
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
    audit: {
      gate_evidence_json: JSON.stringify({
        labelTimeline: labelTimelineFixture,
        fixProvenance: {
          verifiedFixedCount: 1,
          unverifiedClosedCount: 0,
          closureProof: { creditedCount: 1, notCreditedCount: 0 },
          releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
        },
      }),
    },
    ...overrides,
  };
  return {
    listReleases: () => data.releases,
    closedDuringReign: () => data.closed,
    verifiedFixedForRelease: () => data.verified,
    unverifiedClosedForRelease: () => data.unverified,
    proofRowsFor: () => data.proofRows,
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
        return { refreshing: false, lastError: null, lastRefreshAt: 't', lastScoredAt: 't' };
      }
      if (url.endsWith('/api/public')) {
        return {
          repo: 'x/y',
          updatedAt: 't',
          releases: [{
            tag: 'v1',
            score: 7.5,
            status: 'eligible',
            recommended: true,
            scoredAt: 't',
            scoreAudit,
            explanation,
            totalAttributedIssues: 1,
            issues: [{ number: 1, title: 'issue 1', url: 'https://github.com/x/y/issues/1' }],
          }],
        };
      }
      if (url.endsWith('/api/releases')) {
        return [{
          tag: 'v1',
          finalScore: 7.5,
          status: 'eligible',
          recommended: true,
          scoredAt: 't',
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
                  closureProof: { creditedCount: 1, notCreditedCount: 0 },
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
                closureProof: { creditedCount: 1, notCreditedCount: 0, byStatus: { fixed_in_release: 1 } },
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
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 2,
              unverifiedClosedCount: 0,
              closureProof: { creditedCount: 1, notCreditedCount: 0 },
              releaseFixCredit: { countedClosedCount: 1, notCountedClosedCount: 0, analyzedClosedCount: 1 },
            },
          }),
        },
      }),
    });
    assert.equal(result.failures.length, 1);
    assert.match(result.failures[0], /verifiedFixedCount/);
  });

  it('fails when canonical-open proof does not resolve to open terminal', async () => {
    const result = await verifyReleaseAudit({
      reader: reader({
        closed: [{ number: 1 }],
        verified: [],
        unverified: [{ number: 1 }],
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
          gate_evidence_json: JSON.stringify({
            labelTimeline: labelTimelineFixture,
            fixProvenance: {
              verifiedFixedCount: 0,
              unverifiedClosedCount: 1,
              closureProof: { creditedCount: 0, notCreditedCount: 1 },
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
