import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyReleaseAudit } from '../../scripts/lib/release-audit-invariants.mjs';

function reader(overrides: Partial<{
  releases: any[];
  closed: any[];
  verified: any[];
  unverified: any[];
  proofRows: any[];
  audit: any;
}> = {}) {
  const data = {
    releases: [{ tag: 'v1', final_score: 7.5, state: 'eligible', recommended: 1 }],
    closed: [{ number: 1 }],
    verified: [{ number: 1, sentiment: 'negative' }],
    unverified: [],
    proofRows: [{
      release_tag: 'v1',
      issue_number: 1,
      status: 'fixed_in_release',
      evidence_json: JSON.stringify({
        hasReachableClosingPr: true,
        stateReasons: ['COMPLETED'],
      }),
    }],
    audit: {
      gate_evidence_json: JSON.stringify({
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
      if (url.endsWith('/api/status')) {
        return { refreshing: false, lastError: null, lastRefreshAt: 't', lastScoredAt: 't' };
      }
      if (url.endsWith('/api/public')) return { repo: 'x/y', releases: [] };
      if (url.endsWith('/api/comparison')) {
        return {
          releases: [{
            tag: 'v1',
            local: {
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
          evidence_json: JSON.stringify({ canonicalResolution: { terminalIssue: { state: 'closed' } } }),
        }],
        audit: {
          gate_evidence_json: JSON.stringify({
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
});
