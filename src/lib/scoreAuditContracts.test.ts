import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { verifyScoreAuditPayloadContracts } from '../../scripts/lib/score-audit-contracts.mjs';

const versions = {
  scoreInput: 1,
  scoreComponents: 1,
  issueEvidence: 1,
  gateEvidence: 1,
};

function validPayloads(overrides: Record<string, any> = {}) {
  return {
    tag: 'v-test',
    versions,
    input: {
      schemaVersion: 1,
      publishedAt: '2026-06-01T00:00:00Z',
      isLatest: true,
      hoursToNextStable: null,
      hasHotfixSuccessor: false,
      betaCount: 0,
      breakingCount: 0,
      feltOpenedWeight: 0,
      feltClosedWeight: 0,
      verifiedDebtWeight: 0,
      carryoverDebtWeight: 0,
      staleDebtWeight: 0,
      unresolvedClosureRiskWeight: 0,
      rawIssueCount: 0,
      classifiedIssueCount: 0,
      cveAffected: false,
      cveLoad: 0,
    },
    components: {
      schemaVersion: 1,
      components: {},
      evidenceCoverage: 1,
      hotfix: false,
      reason: 'ok',
      explanation: { schemaVersion: 1 },
    },
    issueEvidence: {
      schemaVersion: 1,
      debtSummary: {},
      verifiedDebt: [],
      carryoverDebt: [],
      staleDebt: [],
      openedFeltSerious: [],
      verifiedFixed: [],
      unverifiedClosed: [],
      unclassifiedIssues: [],
    },
    gateEvidence: {
      schemaVersion: 1,
      cve: {},
      stableTagsNewestFirst: [],
      betaCount: 0,
      breakingCount: 0,
      hoursToNextStable: null,
      hasHotfixSuccessor: false,
      releaseChecks: null,
      artifactVerification: null,
      labelTimeline: {},
      fixProvenance: {},
    },
    ...overrides,
  };
}

describe('score audit payload contracts', () => {
  it('accepts known top-level payload keys and schema versions', () => {
    assert.deepEqual(verifyScoreAuditPayloadContracts(validPayloads()), []);
  });

  it('rejects unexpected top-level keys and stale schema versions', () => {
    const failures = verifyScoreAuditPayloadContracts(validPayloads({
      input: { schemaVersion: 0, rawIssueCount: 1, classifiedIssueCount: 1, unexpected: true },
      components: { schemaVersion: 1, components: {}, evidenceCoverage: 1, hotfix: false, reason: 'ok', explanation: {}, extra: true },
    }));

    assert.ok(failures.some((failure) => /score input schemaVersion/.test(failure)));
    assert.ok(failures.some((failure) => /score input payload has unexpected top-level key unexpected/.test(failure)));
    assert.ok(failures.some((failure) => /score components payload has unexpected top-level key extra/.test(failure)));
  });
});
