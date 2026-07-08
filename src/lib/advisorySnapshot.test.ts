import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  ADVISORY_SNAPSHOT_META_SCHEMA_VERSION,
  COMPOUND_ADVISORY_AUTHORITY_POLICY,
  COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
  advisoryRangeIdentityV2,
  advisorySnapshotCompletenessProblems,
  advisorySnapshotContentHash,
  advisorySnapshotRowProblems,
  advisoryVulnerabilityKey,
  assertCompoundAdvisorySnapshotScoreable,
  buildCompoundAdvisorySnapshot,
  buildCompoundAdvisorySnapshotAuditProjection,
  compoundAdvisoryScoreRows,
  compoundAdvisorySnapshotIntegrityProblems,
  compoundAdvisorySnapshotMetadataDigest,
  compoundAdvisorySnapshotPublicationAuthorizations,
  type AdvisorySnapshotContentRow,
  type AdvisorySnapshotCompletenessMetadata,
  type CompoundAdvisorySnapshotInput,
  type CompoundAdvisorySnapshotMetadata,
} from './advisorySnapshot.ts';
import { repositoryAdvisoryCatalogContentDigest } from './advisoryCatalogDigest.ts';
import type {
  GhAdvisory,
  GhAdvisoryReconciliationInputs,
  GhRepositoryAdvisoryCatalogObservation,
  GhSecurityVulnerabilityCatalogObservation,
  GhSecurityVulnerabilityRangeObservation,
} from './github.ts';

const expected = { ecosystem: 'npm', packageName: 'openclaw' };
const repository = {
  owner: 'openclaw',
  name: 'openclaw',
  url: 'https://github.com/openclaw/openclaw',
};

function sha256(value: unknown): string {
  return createHash('sha256').update(JSON.stringify(value)).digest('hex');
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function row(overrides: Partial<AdvisorySnapshotContentRow> = {}): AdvisorySnapshotContentRow {
  const vulnerableVersionRange = overrides.vulnerable_version_range ?? '< 2.0.0';
  return {
    advisory_key: advisoryVulnerabilityKey(
      overrides.ghsa_id ?? 'GHSA-test',
      overrides.package_ecosystem ?? 'npm',
      overrides.package_name ?? 'openclaw',
      vulnerableVersionRange,
    ),
    ghsa_id: 'GHSA-test',
    cve_id: 'CVE-2026-0001',
    summary: 'Test advisory',
    severity: 'high',
    html_url: 'https://github.com/advisories/GHSA-test',
    published_at: '2026-07-01T00:00:00Z',
    package_ecosystem: 'npm',
    package_name: 'openclaw',
    vulnerable_version_range: vulnerableVersionRange,
    patched_versions: '2.0.0',
    ...overrides,
  };
}

function metadata(rows: AdvisorySnapshotContentRow[]): AdvisorySnapshotCompletenessMetadata {
  return {
    schemaVersion: ADVISORY_SNAPSHOT_META_SCHEMA_VERSION,
    source: 'github-security-vulnerabilities',
    sourceOrder: 'UPDATED_AT_DESC',
    ecosystem: 'npm',
    packageName: 'openclaw',
    capturedAt: '2026-07-04T00:00:00Z',
    exhausted: true,
    stabilized: true,
    totalCount: rows.length,
    nodeCount: rows.length,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    sourceDigest: 'a'.repeat(64),
    advisoryCount: rows.length,
    activeAdvisoryCount: rows.length,
    withdrawnAdvisoryCount: 0,
    rowCount: rows.length,
    contentDigest: advisorySnapshotContentHash(rows),
  };
}

function graphqlRange(
  overrides: Partial<GhSecurityVulnerabilityRangeObservation> = {},
): GhSecurityVulnerabilityRangeObservation {
  const ghsaId = overrides.ghsaId ?? 'GHSA-target';
  const ecosystem = overrides.ecosystem ?? 'npm';
  const packageName = overrides.packageName ?? 'openclaw';
  const vulnerableVersionRange = overrides.vulnerableVersionRange ?? '< 2.0.0';
  return {
    ghsaId,
    cveId: overrides.cveId === undefined ? 'CVE-2026-0001' : overrides.cveId,
    summary: overrides.summary ?? `Summary for ${ghsaId}`,
    severity: overrides.severity ?? 'high',
    htmlUrl: overrides.htmlUrl ?? `https://github.com/advisories/${ghsaId}`,
    publishedAt: overrides.publishedAt ?? '2026-07-01T00:00:00Z',
    withdrawnAt: overrides.withdrawnAt === undefined ? null : overrides.withdrawnAt,
    ecosystem,
    packageName,
    vulnerableVersionRange,
    firstPatchedVersion: overrides.firstPatchedVersion === undefined
      ? '2.0.0'
      : overrides.firstPatchedVersion,
    updatedAt: overrides.updatedAt ?? '2026-07-03T00:00:00Z',
    identity: overrides.identity ?? advisoryRangeIdentityV2(
      ghsaId,
      ecosystem,
      packageName,
      vulnerableVersionRange,
    ),
  };
}

function graphqlObservation(
  ranges: GhSecurityVulnerabilityRangeObservation[],
  overrides: Partial<GhSecurityVulnerabilityCatalogObservation> = {},
): GhSecurityVulnerabilityCatalogObservation {
  const identities = [...new Set(ranges.map((range) => range.identity))].sort(compareBinary);
  const byIdentity = new Map(ranges.map((range) => [range.identity, range]));
  const totalCount = overrides.totalCount ?? ranges.length;
  return {
    source: 'graphql-security-vulnerabilities',
    retrieval: {
      startedAt: '2026-07-03T23:58:00Z',
      completedAt: '2026-07-03T23:59:00Z',
    },
    ecosystem: 'npm',
    packageName: 'openclaw',
    exhausted: true,
    stabilized: true,
    totalCount,
    nodeCount: overrides.nodeCount ?? ranges.length,
    uniqueRangeCount: overrides.uniqueRangeCount ?? identities.length,
    pageCount: overrides.pageCount ?? 1,
    pagesFetched: overrides.pagesFetched ?? 2,
    sweepCount: overrides.sweepCount ?? 2,
    digest: overrides.digest ?? sha256([
      totalCount,
      identities.map((identity) => {
        const range = byIdentity.get(identity)!;
        return [
          identity,
          range.cveId,
          range.summary,
          range.severity,
          range.htmlUrl,
          range.publishedAt,
          range.withdrawnAt,
          range.firstPatchedVersion,
          range.updatedAt,
        ];
      }),
    ]),
    identityDigest: overrides.identityDigest ?? sha256(identities),
    ranges,
    rangeIdentities: overrides.rangeIdentities ?? identities,
    ...overrides,
  };
}

function legacyGraphqlObservation(
  ranges: GhSecurityVulnerabilityRangeObservation[],
): GhSecurityVulnerabilityCatalogObservation {
  const legacyRanges = ranges.map((range) => ({
    ghsaId: range.ghsaId,
    ecosystem: range.ecosystem,
    packageName: range.packageName,
    vulnerableVersionRange: range.vulnerableVersionRange,
    firstPatchedVersion: range.firstPatchedVersion,
    updatedAt: range.updatedAt,
    identity: range.identity,
  }));
  const identities = [...new Set(legacyRanges.map((range) => range.identity))]
    .sort(compareBinary);
  const byIdentity = new Map(legacyRanges.map((range) => [range.identity, range]));
  return {
    source: 'graphql-security-vulnerabilities',
    retrieval: {
      startedAt: '2026-07-03T23:58:00Z',
      completedAt: '2026-07-03T23:59:00Z',
    },
    ecosystem: 'npm',
    packageName: 'openclaw',
    exhausted: true,
    stabilized: true,
    totalCount: legacyRanges.length,
    nodeCount: legacyRanges.length,
    uniqueRangeCount: identities.length,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    digest: sha256([
      legacyRanges.length,
      identities.map((identity) => {
        const range = byIdentity.get(identity)!;
        return [
          identity,
          range.firstPatchedVersion,
          range.updatedAt,
        ];
      }),
    ]),
    identityDigest: sha256(identities),
    ranges: legacyRanges,
    rangeIdentities: identities,
  } as unknown as GhSecurityVulnerabilityCatalogObservation;
}

function advisory(
  overrides: Partial<GhAdvisory> & {
    vulnerabilities?: GhAdvisory['vulnerabilities'];
  } = {},
): GhAdvisory {
  const ghsaId = overrides.ghsa_id ?? 'GHSA-target';
  return {
    ghsa_id: ghsaId,
    cve_id: overrides.cve_id ?? 'CVE-2026-0001',
    summary: overrides.summary ?? `Summary for ${ghsaId}`,
    severity: overrides.severity ?? 'high',
    state: overrides.state ?? 'published',
    published_at: overrides.published_at === undefined
      ? '2026-07-01T00:00:00Z'
      : overrides.published_at,
    withdrawn_at: overrides.withdrawn_at ?? null,
    updated_at: overrides.updated_at === undefined
      ? '2026-07-03T00:00:00Z'
      : overrides.updated_at,
    html_url: overrides.html_url ??
      `https://github.com/openclaw/openclaw/security/advisories/${ghsaId}`,
    vulnerabilities: overrides.vulnerabilities ?? [{
      package: { ecosystem: 'npm', name: 'openclaw' },
      vulnerable_version_range: '< 2.0.0',
      patched_versions: '2.0.0',
    }],
  };
}

function restRangeIdentities(advisories: GhAdvisory[], targetOnly: boolean): string[] {
  return [...new Set(advisories.flatMap((item) =>
    item.vulnerabilities.flatMap((range) => {
      const ecosystem = String(range.package?.ecosystem ?? '').trim().toLowerCase();
      const packageName = String(range.package?.name ?? '').trim().toLowerCase();
      if (targetOnly && (ecosystem !== 'npm' || packageName !== 'openclaw')) return [];
      return [advisoryRangeIdentityV2(
        item.ghsa_id,
        ecosystem,
        packageName,
        range.vulnerable_version_range,
      )];
    })))].sort(compareBinary);
}

function restIdentityDigest(advisories: GhAdvisory[]): string {
  return sha256([
    advisories.length,
    advisories.map((item) => [
      item.ghsa_id,
      item.vulnerabilities.map((range) => advisoryRangeIdentityV2(
        item.ghsa_id,
        range.package?.ecosystem,
        range.package?.name,
        range.vulnerable_version_range,
      )).sort(compareBinary),
    ]).sort((left, right) => compareBinary(String(left[0]), String(right[0]))),
  ]);
}

function repositoryObservation(
  advisories: GhAdvisory[],
  options: { proven?: boolean } = {},
): GhRepositoryAdvisoryCatalogObservation {
  const proven = options.proven ?? false;
  const allRangeIdentities = restRangeIdentities(advisories, false);
  const targetRangeIdentities = restRangeIdentities(advisories, true);
  const mode = proven ? 'link-exhausted' as const : 'single-page-no-link' as const;
  const pageCount = proven
    ? Math.max(2, Math.ceil(advisories.length / 100))
    : 1;
  return {
    source: 'repository-security-advisories-rest',
    retrieval: {
      startedAt: '2026-07-03T23:59:10Z',
      completedAt: '2026-07-03T23:59:20Z',
    },
    stabilized: true,
    exhausted: proven,
    totalCount: proven ? advisories.length : null,
    observedAdvisoryCount: advisories.length,
    observedRangeCount: advisories.reduce(
      (sum, item) => sum + item.vulnerabilities.length,
      0,
    ),
    targetRangeCount: targetRangeIdentities.length,
    pageCount,
    pagesFetched: pageCount * 4,
    sweepCount: 4,
    digest: repositoryAdvisoryCatalogContentDigest(advisories),
    identityDigest: restIdentityDigest(advisories),
    targetIdentityDigest: sha256(targetRangeIdentities),
    allRangeIdentities,
    targetRangeIdentities,
    advisories,
    completeness: {
      terminalPageProven: proven,
      terminalPageEvidence: proven ? 'link-exhausted' : 'unproven-no-link',
      terminalPageLinkHeaderPresent: proven,
      remoteTotalCount: null,
      enumeratedCount: advisories.length,
      crossOrderVerified: true,
      boundaryEvidence: {
        updatedAtDesc: {
          mode,
          linkHeaderPresent: proven,
          pageCount,
          sweepCount: 2,
        },
        updatedAtAsc: {
          mode,
          linkHeaderPresent: proven,
          pageCount,
          sweepCount: 2,
        },
      },
    },
  };
}

function reconciliation(
  graphql: GhSecurityVulnerabilityCatalogObservation,
  rest: GhRepositoryAdvisoryCatalogObservation,
): GhAdvisoryReconciliationInputs {
  return {
    target: { ecosystem: 'npm', packageName: 'openclaw' },
    graphqlSecurityVulnerabilities: {
      totalCount: graphql.totalCount,
      rangeCount: graphql.uniqueRangeCount,
      identityDigest: graphql.identityDigest,
      rangeIdentities: graphql.rangeIdentities,
    },
    repositoryAdvisories: {
      totalCount: rest.totalCount,
      observedAdvisoryCount: rest.observedAdvisoryCount,
      targetRangeCount: rest.targetRangeCount,
      identityDigest: rest.targetIdentityDigest,
      rangeIdentities: rest.targetRangeIdentities,
      completenessProven: rest.completeness.terminalPageProven,
    },
  };
}

function compoundInput(
  graphql: GhSecurityVulnerabilityCatalogObservation,
  rest: GhRepositoryAdvisoryCatalogObservation,
  overrides: Partial<CompoundAdvisorySnapshotInput> = {},
): CompoundAdvisorySnapshotInput {
  return {
    capturedAt: '2026-07-04T00:00:00Z',
    repository,
    observations: {
      securityVulnerabilities: graphql,
      repositoryAdvisories: rest,
    },
    reconciliation: reconciliation(graphql, rest),
    ...overrides,
  };
}

function compoundMetadata(
  snapshotId: number,
  capturedAt: string,
): CompoundAdvisorySnapshotMetadata {
  return {
    schemaVersion: COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION,
    snapshotId,
    capturedAt,
    repository,
    target: expected,
    sourceHash: `${snapshotId}`.repeat(64).slice(0, 64),
    catalogHash: `${snapshotId + 1}`.repeat(64).slice(0, 64),
    scoreHash: `${snapshotId + 2}`.repeat(64).slice(0, 64),
    contentHash: `${snapshotId + 3}`.repeat(64).slice(0, 64),
    previousContentHash: snapshotId === 1
      ? null
      : `${snapshotId + 2}`.repeat(64).slice(0, 64),
    rowCount: 1,
    scoreRowCount: 1,
    scoreReady: true,
    scoreContentDigest: `${snapshotId + 4}`.repeat(64).slice(0, 64),
  };
}

function publicationReceipt(
  metadataValue: CompoundAdvisorySnapshotMetadata,
  overrides: {
    receiptId?: string;
    runId?: string;
    status?: string;
    finishedAt?: string;
    advisoryCatalog?: Record<string, unknown> | null;
  } = {},
) {
  const runId = overrides.runId ?? `run-${metadataValue.snapshotId}`;
  const advisoryCatalog = overrides.advisoryCatalog === undefined
    ? {
        metaKey: 'advisory_snapshot_v2_last_run',
        metadataDigest: compoundAdvisorySnapshotMetadataDigest(metadataValue),
        metadata: metadataValue,
        snapshotId: metadataValue.snapshotId,
        sourceHash: metadataValue.sourceHash,
        catalogHash: metadataValue.catalogHash,
        scoreHash: metadataValue.scoreHash,
        contentHash: metadataValue.contentHash,
        contentDigest: metadataValue.scoreContentDigest,
        advisoryCount: metadataValue.scoreRowCount,
        rowCount: metadataValue.scoreRowCount,
        catalogRowCount: metadataValue.rowCount,
        scoreRowCount: metadataValue.scoreRowCount,
      }
    : overrides.advisoryCatalog;
  return {
    receiptId: overrides.receiptId ?? `receipt-${metadataValue.snapshotId}`,
    runId,
    status: overrides.status ?? 'success',
    finishedAt: overrides.finishedAt ?? '2026-07-05T01:00:00Z',
    durationMs: 3_600_000,
    stageEventCount: 4,
    stageChainHash: 'e'.repeat(64),
    payloadJson: JSON.stringify({
      schemaVersion: 3,
      ...(advisoryCatalog == null ? {} : { advisoryCatalog }),
    }),
  };
}

describe('advisory snapshot v1 validation', () => {
  it('accepts a complete stable snapshot', () => {
    const rows = [row()];
    assert.deepEqual(advisorySnapshotRowProblems(rows, expected), []);
    assert.deepEqual(advisorySnapshotCompletenessProblems(metadata(rows), rows, expected), []);
  });

  it('rejects malformed and contradictory advisory ranges', () => {
    const fixtures = [
      row({ vulnerable_version_range: '>= 2.0.0, < 2.0.0' }),
      row({ vulnerable_version_range: '1.0.0 2.0.0' }),
      row({ vulnerable_version_range: '>= 1.0.0,' }),
    ];
    for (const fixture of fixtures) {
      assert.ok(
        advisorySnapshotRowProblems([fixture], expected)
          .some((problem) => problem.detail.startsWith('malformed_vulnerable_range:')),
      );
    }
  });

  it('rejects patch metadata that is malformed or still vulnerable', () => {
    assert.ok(
      advisorySnapshotRowProblems([row({ patched_versions: '< 2.0.0' })], expected)
        .some((problem) => problem.detail.startsWith('malformed_patch_metadata:')),
    );
    assert.ok(
      advisorySnapshotRowProblems([
        row({ vulnerable_version_range: '<= 2.0.0', patched_versions: '2.0.0' }),
      ], expected).some((problem) => problem.detail.startsWith('patched_version_still_vulnerable:')),
    );
  });

  it('requires an exact normalized severity enum', () => {
    for (const severity of ['HIGH', 'moderate', 'high ', 'unknown']) {
      const problems = advisorySnapshotRowProblems([row({ severity })], expected);
      assert.ok(
        problems.some((problem) =>
          problem.code === 'malformed_row' &&
          problem.detail.startsWith('invalid_severity:')),
        `expected ${JSON.stringify(severity)} to be rejected`,
      );
    }
    for (const severity of ['low', 'medium', 'high', 'critical']) {
      assert.deepEqual(advisorySnapshotRowProblems([row({ severity })], expected), []);
    }
  });

  it('rejects snapshots missing declared active rows', () => {
    const rows = [row()];
    const missingActiveRow = {
      ...metadata(rows),
      totalCount: 2,
      nodeCount: 2,
      advisoryCount: 2,
      activeAdvisoryCount: 2,
    };
    const problems = advisorySnapshotCompletenessProblems(
      missingActiveRow,
      rows,
      expected,
    );
    assert.ok(
      problems.some((problem) =>
        problem.code === 'count_mismatch' &&
        problem.detail.includes('rowCount 1 != activeAdvisoryCount 2')),
    );
  });

  it('rejects incomplete, count-drifted, and digest-drifted metadata', () => {
    const rows = [row()];
    const incomplete = { ...metadata(rows), stabilized: false, sweepCount: 1 };
    assert.ok(
      advisorySnapshotCompletenessProblems(incomplete, rows, expected)
        .some((problem) => problem.code === 'incomplete_sweep'),
    );
    const countDrift = { ...metadata(rows), totalCount: 2 };
    assert.ok(
      advisorySnapshotCompletenessProblems(countDrift, rows, expected)
        .some((problem) => problem.code === 'count_mismatch'),
    );
    const impossibleCardinality = {
      ...metadata(rows),
      advisoryCount: 2,
      activeAdvisoryCount: 1,
      withdrawnAdvisoryCount: 1,
    };
    assert.ok(
      advisorySnapshotCompletenessProblems(impossibleCardinality, rows, expected)
        .some((problem) =>
          problem.code === 'count_mismatch' &&
          problem.detail.includes('advisoryCount 2 is impossible for nodeCount 1')),
    );
    const impossiblePagination = { ...metadata(rows), pagesFetched: 1 };
    assert.ok(
      advisorySnapshotCompletenessProblems(impossiblePagination, rows, expected)
        .some((problem) =>
          problem.code === 'count_mismatch' &&
          problem.detail.includes('pagesFetched 1 < minimum 2')),
    );
    const digestDrift = { ...metadata(rows), contentDigest: 'b'.repeat(64) };
    assert.ok(
      advisorySnapshotCompletenessProblems(digestDrift, rows, expected)
        .some((problem) => problem.code === 'digest_mismatch'),
    );
  });
});

describe('compound advisory snapshot v2', () => {
  it('accepts a counted zero GraphQL proof with an unproven empty REST observation', () => {
    const graphql = graphqlObservation([]);
    const rest = repositoryObservation([]);
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

    assert.equal(snapshot.schemaVersion, COMPOUND_ADVISORY_SNAPSHOT_SCHEMA_VERSION);
    assert.deepEqual(snapshot.authorityPolicy, COMPOUND_ADVISORY_AUTHORITY_POLICY);
    assert.equal(snapshot.sourceObservations.graphql.pagination.completenessProven, true);
    assert.equal(snapshot.sourceObservations.repositoryRest.pagination.completenessProven, false);
    assert.equal(snapshot.reconciliation.status, 'reconciled');
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 0);
    assert.equal(snapshot.blockingProblems.length, 0);
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'unproven_repository_completeness'));
    assertCompoundAdvisorySnapshotScoreable(snapshot);
  });

  it('normalizes and binds immutable source retrieval windows', () => {
    const range = graphqlRange();
    const graphql = graphqlObservation([range], {
      retrieval: {
        startedAt: '2026-07-03T18:58:00-05:00',
        completedAt: '2026-07-03T18:59:00-05:00',
      },
    });
    const rest: GhRepositoryAdvisoryCatalogObservation = {
      ...repositoryObservation([advisory()]),
      retrieval: {
        startedAt: '2026-07-03T19:59:10-04:00',
        completedAt: '2026-07-03T19:59:20-04:00',
      },
    };
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

    assert.deepEqual(snapshot.sourceObservations.graphql.observation.retrieval, {
      startedAt: '2026-07-03T23:58:00.000Z',
      completedAt: '2026-07-03T23:59:00.000Z',
    });
    assert.deepEqual(snapshot.sourceObservations.repositoryRest.observation.retrieval, {
      startedAt: '2026-07-03T23:59:10.000Z',
      completedAt: '2026-07-03T23:59:20.000Z',
    });
    assert.equal(snapshot.score.ready, true);
    assert.deepEqual(compoundAdvisorySnapshotIntegrityProblems(snapshot), []);

    const changed = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([range], {
        retrieval: {
          startedAt: '2026-07-03T23:58:00Z',
          completedAt: '2026-07-03T23:59:30Z',
        },
      }),
      rest,
    ));
    assert.notEqual(changed.sourceHash, snapshot.sourceHash);
    assert.equal(changed.catalogHash, snapshot.catalogHash);
    assert.equal(changed.scoreHash, snapshot.scoreHash);

    const tampered = structuredClone(snapshot);
    tampered.sourceObservations.graphql.observation.retrieval.completedAt =
      '2026-07-03T23:59:30.000Z';
    assert.ok(
      compoundAdvisorySnapshotIntegrityProblems(tampered)
        .some((problem) => problem.includes('source hash')),
    );
  });

  it('blocks a missing source retrieval window', () => {
    const graphql = graphqlObservation([]);
    delete (graphql as { retrieval?: unknown }).retrieval;
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphql,
      repositoryObservation([]),
    ));

    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'graphql-security-vulnerabilities' &&
      problem.detail.includes('retrieval window is missing')));
    assert.equal(snapshot.score.ready, false);
  });

  it('blocks an invalid source retrieval timestamp', () => {
    const rest: GhRepositoryAdvisoryCatalogObservation = {
      ...repositoryObservation([]),
      retrieval: {
        startedAt: 'not-a-timestamp',
        completedAt: '2026-07-03T23:59:20Z',
      },
    };
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      rest,
    ));

    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'repository-security-advisories-rest' &&
      problem.detail.includes('invalid timestamp')));
    assert.equal(snapshot.score.ready, false);
  });

  it('blocks a reversed source retrieval window', () => {
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([], {
        retrieval: {
          startedAt: '2026-07-03T23:59:30Z',
          completedAt: '2026-07-03T23:59:00Z',
        },
      }),
      repositoryObservation([]),
    ));

    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'graphql-security-vulnerabilities' &&
      problem.detail.includes('completedAt predates startedAt')));
    assert.equal(snapshot.score.ready, false);
  });

  it('blocks a compound capturedAt that predates either source completion', () => {
    for (const source of [
      'graphql-security-vulnerabilities',
      'repository-security-advisories-rest',
    ] as const) {
      const graphql = graphqlObservation([]);
      const rest = repositoryObservation([]);
      if (source === 'graphql-security-vulnerabilities') {
        graphql.retrieval = {
          startedAt: '2026-07-03T23:59:50Z',
          completedAt: '2026-07-04T00:00:01Z',
        };
      } else {
        rest.retrieval = {
          startedAt: '2026-07-03T23:59:50Z',
          completedAt: '2026-07-04T00:00:01Z',
        };
      }
      const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

      assert.ok(snapshot.blockingProblems.some((problem) =>
        problem.code === 'invalid_snapshot_input' &&
        problem.source === 'compound-reconciliation' &&
        problem.detail.includes(source)));
      assert.equal(snapshot.score.ready, false);
    }
  });

  it('rejects removed or ambiguous repository terminal proof metadata', () => {
    const rest = repositoryObservation([advisory()], { proven: true });
    (rest.completeness as { terminalPageEvidence: string }).terminalPageEvidence =
      'explicit';
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      rest,
    ));

    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'repository-security-advisories-rest' &&
      problem.detail.includes('pagination metadata')));
    assert.equal(snapshot.score.ready, false);
  });

  it('reconciles a matching unproven single-page REST target observation', () => {
    const range = graphqlRange();
    const graphql = graphqlObservation([range]);
    const rest = repositoryObservation([advisory()]);
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

    assert.equal(snapshot.reconciliation.status, 'reconciled');
    assert.equal(snapshot.reconciliation.reconciledRangeCount, 1);
    assert.equal(snapshot.reconciliation.additionalGraphqlRangeIdentities.length, 0);
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 1);
    assert.equal(snapshot.rows[0].repositoryOwned, true);
    assert.equal(snapshot.rows[0].scoreEligible, true);
    assert.equal(snapshot.rows[0].advisory?.severity, 'high');
    assert.deepEqual(compoundAdvisoryScoreRows(snapshot), [{
      advisory_key: range.identity,
      ghsa_id: range.ghsaId,
      cve_id: range.cveId,
      summary: range.summary,
      severity: range.severity,
      html_url: range.htmlUrl,
      published_at: range.publishedAt,
      package_ecosystem: range.ecosystem,
      package_name: range.packageName,
      vulnerable_version_range: range.vulnerableVersionRange,
      patched_versions: range.firstPatchedVersion,
    }]);
  });

  it('counts one GHSA with two disjoint ranges independently from packages', () => {
    const first = graphqlRange({
      vulnerableVersionRange: '< 1.0.0',
      firstPatchedVersion: '1.0.0',
    });
    const second = graphqlRange({
      vulnerableVersionRange: '>= 2.0.0, < 3.0.0',
      firstPatchedVersion: '3.0.0',
      updatedAt: '2026-07-03T01:00:00Z',
    });
    const graphql = graphqlObservation([first, second]);
    const rest = repositoryObservation([advisory({
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '< 1.0.0',
          patched_versions: '1.0.0',
        },
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '>= 2.0.0, < 3.0.0',
          patched_versions: '3.0.0',
        },
      ],
    })], { proven: true });
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

    assert.deepEqual(snapshot.counts, {
      advisoryCount: 1,
      activeAdvisoryCount: 1,
      withdrawnAdvisoryCount: 0,
      otherStateAdvisoryCount: 0,
      rangeCount: 2,
      activeRangeCount: 2,
      withdrawnRangeCount: 0,
      otherStateRangeCount: 0,
      packageCount: 1,
      targetRangeCount: 2,
      foreignRangeCount: 0,
      sourceObservationCount: 4,
      scoreEligibleRangeCount: 2,
    });
    assert.equal(snapshot.sourceObservations.graphql.counts.advisoryCount, 1);
    assert.equal(snapshot.sourceObservations.graphql.counts.rangeCount, 2);
    assert.equal(snapshot.sourceObservations.repositoryRest.counts.advisoryCount, 1);
    assert.equal(snapshot.sourceObservations.repositoryRest.counts.rangeCount, 2);
  });

  it('blocks conflicting advisory-level metadata across GraphQL rows for one GHSA', () => {
    const fixtures: Array<{
      name: string;
      first?: Partial<GhSecurityVulnerabilityRangeObservation>;
      second: Partial<GhSecurityVulnerabilityRangeObservation>;
      field: string;
    }> = [
      {
        name: 'active and withdrawn state',
        second: { withdrawnAt: '2026-07-03T00:00:00Z' },
        field: 'state',
      },
      {
        name: 'severity',
        second: { severity: 'critical' },
        field: 'severity',
      },
      {
        name: 'CVE',
        second: { cveId: 'CVE-2026-0002' },
        field: 'CVE id',
      },
      {
        name: 'summary',
        second: { summary: 'Conflicting advisory summary' },
        field: 'summary',
      },
      {
        name: 'published timestamp',
        second: { publishedAt: '2026-06-30T00:00:00Z' },
        field: 'publishedAt',
      },
      {
        name: 'withdrawn timestamp',
        first: { withdrawnAt: '2026-07-02T00:00:00Z' },
        second: { withdrawnAt: '2026-07-03T00:00:00Z' },
        field: 'withdrawnAt',
      },
    ];

    for (const [index, fixture] of fixtures.entries()) {
      const ghsaId = `GHSA-metadata-conflict-${index}`;
      const first = graphqlRange({
        ghsaId,
        vulnerableVersionRange: '< 1.0.0',
        firstPatchedVersion: '1.0.0',
        ...fixture.first,
      });
      const second = graphqlRange({
        ghsaId,
        vulnerableVersionRange: '>= 2.0.0, < 3.0.0',
        firstPatchedVersion: '3.0.0',
        updatedAt: '2026-07-03T01:00:00Z',
        ...fixture.second,
      });
      const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
        graphqlObservation([first, second]),
        repositoryObservation([]),
      ));
      const corruptionProblems = snapshot.blockingProblems.filter((problem) =>
        problem.code === 'conflicting_source_advisory_metadata');

      assert.equal(corruptionProblems.length, 2, fixture.name);
      assert.ok(
        corruptionProblems.every((problem) => problem.detail.includes(fixture.field)),
        fixture.name,
      );
      assert.equal(snapshot.reconciliation.status, 'blocked', fixture.name);
      assert.equal(snapshot.score.ready, false, fixture.name);
      assert.equal(snapshot.score.rangeCount, 0, fixture.name);
    }
  });

  it('preserves mixed-package repository rows while scoring only exact GraphQL target rows', () => {
    const graphql = graphqlObservation([graphqlRange()]);
    const rest = repositoryObservation([advisory({
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '< 2.0.0',
          patched_versions: '2.0.0',
        },
        {
          package: { ecosystem: 'npm', name: '@openclaw/feishu' },
          vulnerable_version_range: '<= 1.5.0',
          patched_versions: '2.0.0',
        },
      ],
    })]);
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(graphql, rest));

    assert.equal(snapshot.counts.packageCount, 2);
    assert.equal(snapshot.counts.rangeCount, 2);
    assert.equal(snapshot.counts.foreignRangeCount, 1);
    assert.equal(snapshot.score.rangeCount, 1);
    const foreign = snapshot.rows.find((item) => item.packageName === '@openclaw/feishu');
    assert.ok(foreign);
    assert.equal(foreign.repositoryOwned, true);
    assert.equal(foreign.scoreEligible, false);
    assert.equal(foreign.auditOnly, true);
  });

  it('blocks duplicate and overlapping rows within either source catalog', () => {
    const duplicate = graphqlRange();
    const duplicateGraphql = graphqlObservation([duplicate, { ...duplicate }]);
    const duplicateSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      duplicateGraphql,
      repositoryObservation([]),
    ));
    assert.ok(duplicateSnapshot.blockingProblems.some((problem) =>
      problem.code === 'duplicate_source_range'));
    assert.equal(duplicateSnapshot.score.ready, false);

    const overlapGraphql = graphqlObservation([
      graphqlRange({
        vulnerableVersionRange: '< 2.0.0',
        firstPatchedVersion: '2.0.0',
      }),
      graphqlRange({
        vulnerableVersionRange: '< 3.0.0',
        firstPatchedVersion: '3.0.0',
        updatedAt: '2026-07-03T01:00:00Z',
      }),
    ]);
    const overlapSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      overlapGraphql,
      repositoryObservation([]),
    ));
    assert.ok(overlapSnapshot.blockingProblems.some((problem) =>
      problem.code === 'overlapping_source_ranges'));
    assert.throws(
      () => assertCompoundAdvisorySnapshotScoreable(overlapSnapshot),
      /overlapping_source_ranges/,
    );
  });

  it('blocks missing and conflicting active target reconciliation but accepts GraphQL extras', () => {
    const rest = repositoryObservation([advisory()]);
    const missing = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      rest,
    ));
    assert.equal(missing.reconciliation.status, 'blocked');
    assert.ok(missing.auditProblems.some((problem) =>
      problem.code === 'missing_reconciliation'));
    assert.ok(missing.blockingProblems.some((problem) =>
      problem.code === 'unproven_repository_completeness'));
    assert.equal(missing.score.ready, false);

    const provenRest = repositoryObservation([advisory()], { proven: true });
    const provenFallback = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      provenRest,
    ));
    assert.equal(provenFallback.reconciliation.status, 'divergent');
    assert.equal(provenFallback.blockingProblems.length, 0);
    assert.ok(provenFallback.auditProblems.some((problem) =>
      problem.code === 'missing_reconciliation'));
    assert.equal(provenFallback.score.ready, true);
    assert.equal(provenFallback.score.rangeCount, 1);
    assert.equal(
      provenFallback.score.rows[0].sourceObservations[0].source,
      'repository-security-advisories-rest',
    );
    assert.equal(compoundAdvisoryScoreRows(provenFallback)[0].patched_versions, '2.0.0');

    const conflictingGraphql = graphqlObservation([graphqlRange({
      vulnerableVersionRange: '< 3.0.0',
      firstPatchedVersion: '3.0.0',
    })]);
    const conflicting = buildCompoundAdvisorySnapshot(compoundInput(
      conflictingGraphql,
      rest,
    ));
    assert.equal(conflicting.reconciliation.status, 'divergent');
    assert.equal(conflicting.blockingProblems.length, 0);
    assert.ok(conflicting.auditProblems.some((problem) =>
      problem.code === 'conflicting_reconciliation'));
    assert.equal(conflicting.score.ready, true);
    assert.equal(conflicting.score.rangeCount, 1);
    assert.equal(conflicting.score.rows[0].identity, conflictingGraphql.ranges[0].identity);

    const additional = graphqlRange({
      ghsaId: 'GHSA-package-global',
      vulnerableVersionRange: '< 4.0.0',
      firstPatchedVersion: '4.0.0',
      updatedAt: '2026-07-03T02:00:00Z',
    });
    const withAdditional = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange(), additional]),
      rest,
    ));
    assert.equal(withAdditional.reconciliation.status, 'reconciled');
    assert.deepEqual(
      withAdditional.reconciliation.additionalGraphqlRangeIdentities,
      [additional.identity],
    );
    assert.equal(withAdditional.score.rangeCount, 2);
  });

  it('preserves withdrawn rows as non-score audit evidence', () => {
    const withdrawn = advisory({
      state: 'withdrawn',
      withdrawn_at: '2026-07-03T00:00:00Z',
    });
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      repositoryObservation([withdrawn]),
    ));

    assert.equal(snapshot.reconciliation.status, 'reconciled');
    assert.equal(snapshot.sourceObservations.repositoryRest.counts.withdrawnAdvisoryCount, 1);
    assert.equal(snapshot.counts.withdrawnRangeCount, 1);
    assert.equal(snapshot.rows[0].state, 'withdrawn');
    assert.equal(snapshot.rows[0].scoreEligible, false);
    assert.equal(snapshot.score.ready, true);
  });

  it('blocks repository advisories whose URL belongs to another repository', () => {
    const wrongUrl = advisory({
      html_url: 'https://github.com/other/project/security/advisories/GHSA-target',
    });
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      repositoryObservation([wrongUrl]),
    ));
    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'wrong_repository_url'));
    assert.equal(snapshot.score.ready, false);
  });

  it('requires independently verifiable repository fallback content and metadata', () => {
    const validRest = repositoryObservation([advisory()], { proven: true });
    const digestMismatch = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      {
        ...validRest,
        digest: 'c'.repeat(64),
      },
    ));
    assert.ok(digestMismatch.blockingProblems.some((problem) =>
      problem.code === 'digest_mismatch'));
    assert.equal(digestMismatch.score.ready, false);

    for (const malformed of [
      advisory({ cve_id: 'not-a-cve' }),
      advisory({ published_at: null }),
      advisory({
        state: 'withdrawn',
        withdrawn_at: '2026-06-30T00:00:00Z',
      }),
      advisory({ updated_at: null }),
    ]) {
      const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
        graphqlObservation([]),
        repositoryObservation([malformed], { proven: true }),
      ));
      assert.ok(snapshot.blockingProblems.some((problem) =>
        problem.code === 'invalid_source_observation'));
      assert.equal(snapshot.score.ready, false);
    }
  });

  it('blocks malformed target ranges while retaining malformed foreign rows as audit-only', () => {
    const malformedGraphqlRange = graphqlRange({
      vulnerableVersionRange: '^2.0.0',
      firstPatchedVersion: null,
    });
    const graphqlSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([malformedGraphqlRange]),
      repositoryObservation([]),
    ));
    assert.ok(graphqlSnapshot.blockingProblems.some((problem) =>
      problem.code === 'malformed_target_range'));
    assert.equal(graphqlSnapshot.rows[0].scoreEligible, false);
    assert.equal(graphqlSnapshot.score.ready, false);

    const malformedTarget = advisory({
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'openclaw' },
        vulnerable_version_range: '^2.0.0',
        patched_versions: null,
      }],
    });
    const targetSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      repositoryObservation([malformedTarget]),
    ));
    assert.ok(targetSnapshot.blockingProblems.some((problem) =>
      problem.code === 'malformed_target_range'));
    assert.equal(targetSnapshot.score.ready, false);

    const malformedForeign = advisory({
      ghsa_id: 'GHSA-foreign',
      html_url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-foreign',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '@openclaw/feishu' },
        vulnerable_version_range: '^2.0.0',
        patched_versions: null,
      }],
    });
    const foreignSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      repositoryObservation([malformedForeign]),
    ));
    assert.equal(foreignSnapshot.blockingProblems.length, 0);
    assert.ok(foreignSnapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_foreign_range'));
    assert.equal(foreignSnapshot.rows[0].auditOnly, true);
    assert.equal(foreignSnapshot.score.ready, true);

    const coveredMalformedRepository = advisory({
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'openclaw' },
        vulnerable_version_range: '<= 1.0.0 || = 1.0.1',
        patched_versions: 'None',
      }],
    });
    const coveredSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      repositoryObservation([coveredMalformedRepository], { proven: true }),
    ));
    assert.equal(coveredSnapshot.blockingProblems.length, 0);
    assert.equal(coveredSnapshot.reconciliation.status, 'divergent');
    assert.ok(coveredSnapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_target_range'));
    assert.ok(coveredSnapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_target_patch'));
    assert.equal(coveredSnapshot.score.ready, true);
    assert.equal(coveredSnapshot.score.rangeCount, 1);

    const coveredMalformedPatch = advisory({
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'openclaw' },
        vulnerable_version_range: '< 2.0.0',
        patched_versions: 'None',
      }],
    });
    const patchSnapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      repositoryObservation([coveredMalformedPatch], { proven: true }),
    ));
    assert.equal(patchSnapshot.blockingProblems.length, 0);
    assert.equal(patchSnapshot.reconciliation.status, 'divergent');
    assert.ok(patchSnapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_target_patch'));
    assert.equal(patchSnapshot.score.ready, true);
    assert.equal(patchSnapshot.score.rangeCount, 1);
  });

  it('retains GraphQL-covered package-less rows as divergent audit evidence', () => {
    const targetRange = graphqlRange({
      ghsaId: 'GHSA-77q5-rr5v-x43q',
      vulnerableVersionRange: '< 2026.5.7',
      firstPatchedVersion: '2026.5.7',
    });
    const packageLessRepositoryAdvisory = advisory({
      ghsa_id: targetRange.ghsaId,
      cve_id: null,
      summary: 'Trusted retry endpoint checks could match hostname prefixes',
      severity: 'medium',
      published_at: '2026-05-28T17:39:26Z',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '' },
        vulnerable_version_range: '< 2026.5.7',
        patched_versions: '2026.5.7',
      }],
    });
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([targetRange]),
      repositoryObservation([packageLessRepositoryAdvisory], { proven: true }),
    ));

    assert.equal(snapshot.blockingProblems.length, 0);
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'repository-security-advisories-rest'));
    assert.equal(snapshot.reconciliation.status, 'divergent');
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 1);
    assert.equal(snapshot.score.rows[0].identity, targetRange.identity);
    assert.equal(snapshot.rows.filter((row) => row.auditOnly).length, 1);
  });

  it('blocks an uncovered active package-less advisory in a complete REST catalog', () => {
    const packageLessAdvisory = advisory({
      ghsa_id: 'GHSA-package-less-uncovered',
      html_url:
        'https://github.com/openclaw/openclaw/security/advisories/' +
        'GHSA-package-less-uncovered',
      vulnerabilities: [{
        package: null,
        vulnerable_version_range: '< 2.0.0',
        patched_versions: '2.0.0',
      }],
    });
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([]),
      repositoryObservation([packageLessAdvisory], { proven: true }),
    ));

    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'invalid_source_observation' &&
      problem.source === 'repository-security-advisories-rest' &&
      problem.detail.includes('missing package')));
    assert.equal(snapshot.reconciliation.status, 'blocked');
    assert.equal(snapshot.score.ready, false);
    assert.equal(snapshot.score.rangeCount, 0);
  });

  it('detects a withdrawn REST row that conflicts with an active GraphQL range', () => {
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      repositoryObservation([advisory({
        state: 'withdrawn',
        withdrawn_at: '2026-07-03T00:00:00Z',
      })]),
    ));
    assert.equal(snapshot.blockingProblems.length, 0);
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'withdrawn_state_conflict'));
    assert.equal(snapshot.reconciliation.status, 'divergent');
    assert.equal(snapshot.rows[0].state, 'active');
    assert.equal(snapshot.rows[0].scoreEligible, true);
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 1);
    assert.equal(snapshot.counts.activeAdvisoryCount, 1);
    assert.equal(snapshot.counts.otherStateAdvisoryCount, 0);
  });

  it('reports a covered non-active REST state as divergent under GraphQL authority', () => {
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange()]),
      repositoryObservation([advisory({ state: 'closed' })], { proven: true }),
    ));

    assert.equal(snapshot.blockingProblems.length, 0);
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'conflicting_reconciliation' &&
      problem.detail.includes('"closed"')));
    assert.equal(snapshot.reconciliation.status, 'divergent');
    assert.equal(snapshot.rows[0].state, 'active');
    assert.equal(snapshot.rows[0].scoreEligible, true);
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 1);
  });

  it('retains matching withdrawn GraphQL and REST ranges as audit-only evidence', () => {
    const withdrawnAt = '2026-07-03T00:00:00Z';
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([graphqlRange({ withdrawnAt })]),
      repositoryObservation([advisory({
        state: 'withdrawn',
        withdrawn_at: withdrawnAt,
      })]),
    ));

    assert.equal(snapshot.blockingProblems.length, 0);
    assert.equal(snapshot.reconciliation.status, 'reconciled');
    assert.equal(snapshot.rows[0].state, 'withdrawn');
    assert.equal(snapshot.rows[0].scoreEligible, false);
    assert.equal(snapshot.rows[0].auditOnly, true);
    assert.equal(snapshot.counts.activeAdvisoryCount, 0);
    assert.equal(snapshot.counts.withdrawnAdvisoryCount, 1);
    assert.deepEqual(
      snapshot.rows[0].sourceObservations.map((observation) => observation.state),
      ['withdrawn', 'withdrawn'],
    );
  });

  it('produces deterministic source, catalog, and score hashes', () => {
    const first = graphqlRange({
      ghsaId: 'GHSA-a',
      vulnerableVersionRange: '< 1.0.0',
      firstPatchedVersion: '1.0.0',
    });
    const second = graphqlRange({
      ghsaId: 'GHSA-b',
      vulnerableVersionRange: '>= 2.0.0, < 3.0.0',
      firstPatchedVersion: '3.0.0',
      updatedAt: '2026-07-03T01:00:00Z',
    });
    const targetA = advisory({
      ghsa_id: 'GHSA-a',
      html_url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-a',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: 'openclaw' },
        vulnerable_version_range: '< 1.0.0',
        patched_versions: '1.0.0',
      }],
    });
    const targetB = advisory({
      ghsa_id: 'GHSA-b',
      html_url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-b',
      vulnerabilities: [
        {
          package: { ecosystem: 'npm', name: '@openclaw/feishu' },
          vulnerable_version_range: '< 5.0.0',
          patched_versions: '5.0.0',
        },
        {
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: '>= 2.0.0, < 3.0.0',
          patched_versions: '3.0.0',
        },
      ],
    });
    const foreignC = advisory({
      ghsa_id: 'GHSA-c',
      html_url: 'https://github.com/openclaw/openclaw/security/advisories/GHSA-c',
      vulnerabilities: [{
        package: { ecosystem: 'npm', name: '@openclaw/feishu' },
        vulnerable_version_range: '< 8.0.0',
        patched_versions: '8.0.0',
      }],
    });
    const graphqlOne = graphqlObservation([first, second]);
    const restOne = repositoryObservation([targetA, targetB, foreignC], { proven: true });
    const one = buildCompoundAdvisorySnapshot(compoundInput(graphqlOne, restOne));

    const graphqlTwo = graphqlObservation([second, first]);
    const restTwo = repositoryObservation([
      { ...targetB, vulnerabilities: [...targetB.vulnerabilities].reverse() },
      foreignC,
      targetA,
    ], { proven: true });
    const two = buildCompoundAdvisorySnapshot(compoundInput(graphqlTwo, restTwo));
    assert.deepEqual(one.hashes, two.hashes);

    const changedForeign = repositoryObservation([
      targetA,
      targetB,
      { ...foreignC, summary: 'Changed audit-only repository detail' },
    ], { proven: true });
    const changed = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlOne,
      changedForeign,
    ));
    assert.notEqual(changed.sourceHash, one.sourceHash);
    assert.notEqual(changed.catalogHash, one.catalogHash);
    assert.equal(changed.scoreHash, one.scoreHash);
    for (const hash of Object.values(one.hashes)) {
      assert.match(hash, /^[0-9a-f]{64}$/);
    }
  });

  it('reconstructs unmarked legacy snapshots and rejects authority-policy tampering', () => {
    const range = graphqlRange();
    const rest = repositoryObservation([advisory()], { proven: true });
    const legacy = buildCompoundAdvisorySnapshot(compoundInput(
      legacyGraphqlObservation([range]),
      rest,
      { authorityPolicy: null },
    ));
    assert.equal(Object.hasOwn(legacy, 'authorityPolicy'), false);
    assert.equal(legacy.reconciliation.status, 'reconciled');
    assert.equal(legacy.score.ready, true);
    assert.deepEqual(compoundAdvisorySnapshotIntegrityProblems(legacy), []);

    const current = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([range]),
      rest,
    ));
    assert.deepEqual(current.authorityPolicy, COMPOUND_ADVISORY_AUTHORITY_POLICY);
    assert.notEqual(current.sourceHash, legacy.sourceHash);
    assert.notEqual(current.catalogHash, legacy.catalogHash);
    assert.notEqual(current.scoreHash, legacy.scoreHash);

    const missingMarker = structuredClone(current);
    delete missingMarker.authorityPolicy;
    assert.ok(
      compoundAdvisorySnapshotIntegrityProblems(missingMarker)
        .some((problem) => problem.includes('canonical source reconstruction')),
    );

    const tampered = structuredClone(current) as any;
    tampered.authorityPolicy.name = 'rest_overrides_graphql';
    assert.ok(
      compoundAdvisorySnapshotIntegrityProblems(tampered)
        .some((problem) => problem.includes('Unsupported compound advisory authority policy')),
    );
  });

  it('keeps every valid GraphQL range plus complete repository-only fallbacks scoreable at scale', () => {
    const graphqlRanges = Array.from({ length: 752 }, (_, index) =>
      graphqlRange({
        ghsaId: `GHSA-global-${String(index).padStart(4, '0')}`,
        cveId: `CVE-2026-${String(index + 1000).padStart(4, '0')}`,
        summary: `Global advisory ${index}`,
      }));
    const matchedRepositoryAdvisories = graphqlRanges.slice(0, 611).map(
      (range, index) => advisory({
        ghsa_id: range.ghsaId,
        cve_id: range.cveId,
        summary: index % 2 === 0 ? `Stale repository summary ${index}` : range.summary,
        severity: range.severity,
        published_at: range.publishedAt,
        html_url:
          `https://github.com/openclaw/openclaw/security/advisories/${range.ghsaId}`,
        vulnerabilities: [{
          package: { ecosystem: 'npm', name: 'openclaw' },
          vulnerable_version_range: index % 2 === 0
            ? range.vulnerableVersionRange
            : '< 3.0.0',
          patched_versions: index % 2 === 0
            ? range.firstPatchedVersion
            : '3.0.0',
        }],
      }),
    );
    const fallbackRepositoryAdvisories = Array.from({ length: 46 }, (_, index) =>
      advisory({
        ghsa_id: `GHSA-repository-only-${String(index).padStart(4, '0')}`,
        cve_id: `CVE-2027-${String(index + 1000).padStart(4, '0')}`,
        summary: `Repository-only advisory ${index}`,
        html_url:
          `https://github.com/openclaw/openclaw/security/advisories/` +
          `GHSA-repository-only-${String(index).padStart(4, '0')}`,
      }));
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation(graphqlRanges),
      repositoryObservation([
        ...matchedRepositoryAdvisories,
        ...fallbackRepositoryAdvisories,
      ], { proven: true }),
    ));

    assert.equal(snapshot.blockingProblems.length, 0);
    assert.equal(snapshot.reconciliation.status, 'divergent');
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.sourceObservations.graphql.counts.rangeCount, 752);
    assert.equal(snapshot.sourceObservations.repositoryRest.counts.rangeCount, 657);
    assert.equal(snapshot.score.rangeCount, 798);
    assert.equal(
      new Set(snapshot.score.rangeIdentities).size,
      snapshot.score.rangeCount,
    );
  });

  it('keeps the live advisory shape scoreable when covered REST syntax is only audit evidence', () => {
    const activeGraphqlRangeCount = 592;
    const graphqlRanges = Array.from({ length: 752 }, (_, index) =>
      graphqlRange({
        ghsaId: `GHSA-live-global-${String(index).padStart(4, '0')}`,
        cveId: `CVE-2026-${String(index + 2000).padStart(4, '0')}`,
        summary: `Live global advisory ${index}`,
        withdrawnAt: index < activeGraphqlRangeCount
          ? null
          : '2026-07-02T00:00:00Z',
      }));
    const matchedRepositoryAdvisories = graphqlRanges.slice(0, 611).map(
      (range, index) => {
        const downgradedSyntax = index % 3 === 0;
        return advisory({
          ghsa_id: range.ghsaId,
          cve_id: range.cveId,
          summary: range.summary,
          severity: range.severity,
          published_at: range.publishedAt,
          html_url:
            `https://github.com/openclaw/openclaw/security/advisories/${range.ghsaId}`,
          vulnerabilities: [{
            package: { ecosystem: 'npm', name: 'openclaw' },
            vulnerable_version_range: downgradedSyntax
              ? '<= 1.0.0 || = 1.0.1'
              : range.vulnerableVersionRange,
            patched_versions: downgradedSyntax
              ? 'None'
              : range.firstPatchedVersion,
          }],
        });
      },
    );
    const fallbackRepositoryAdvisories = Array.from({ length: 46 }, (_, index) =>
      advisory({
        ghsa_id: `GHSA-live-fallback-${String(index).padStart(4, '0')}`,
        cve_id: `CVE-2027-${String(index + 2000).padStart(4, '0')}`,
        summary: `Live repository-only advisory ${index}`,
        html_url:
          `https://github.com/openclaw/openclaw/security/advisories/` +
          `GHSA-live-fallback-${String(index).padStart(4, '0')}`,
      }));
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation(graphqlRanges),
      repositoryObservation([
        ...matchedRepositoryAdvisories,
        ...fallbackRepositoryAdvisories,
      ], { proven: true }),
    ));

    assert.equal(snapshot.sourceObservations.graphql.counts.rangeCount, 752);
    assert.equal(snapshot.sourceObservations.repositoryRest.counts.rangeCount, 657);
    assert.equal(snapshot.reconciliation.missingRangeIdentities.length, 46);
    assert.equal(snapshot.blockingProblems.length, 0);
    assert.equal(snapshot.reconciliation.status, 'divergent');
    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rangeCount, 638);
    assert.equal(snapshot.counts.scoreEligibleRangeCount, 638);
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_target_range'));
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'malformed_target_patch'));
    assert.ok(snapshot.auditProblems.some((problem) =>
      problem.code === 'withdrawn_state_conflict'));
    assertCompoundAdvisorySnapshotScoreable(snapshot);
  });

  it('scores GraphQL-only ranges with complete advisory metadata and rejects tampering', () => {
    const range = graphqlRange();
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphqlObservation([range]),
      repositoryObservation([]),
    ));

    assert.equal(snapshot.score.ready, true);
    assert.equal(snapshot.score.rows[0].packageGlobalOnly, true);
    assert.equal(snapshot.score.rows[0].advisory?.severity, 'high');
    assert.equal(compoundAdvisoryScoreRows(snapshot)[0].summary, range.summary);
    assert.deepEqual(compoundAdvisorySnapshotIntegrityProblems(snapshot), []);

    const tampered = structuredClone(snapshot);
    tampered.score.rows[0].advisory!.severity = 'low';
    assert.ok(
      compoundAdvisorySnapshotIntegrityProblems(tampered)
        .some((problem) => problem.includes('score projection')),
    );
    assert.throws(
      () => compoundAdvisoryScoreRows(tampered),
      /integrity failed/,
    );
  });

  it('blocks a conflicting declared reconciliation without changing source rows', () => {
    const graphql = graphqlObservation([graphqlRange()]);
    const rest = repositoryObservation([advisory()]);
    const declared = reconciliation(graphql, rest);
    declared.repositoryAdvisories.rangeIdentities = [];
    const snapshot = buildCompoundAdvisorySnapshot(compoundInput(
      graphql,
      rest,
      { reconciliation: declared },
    ));
    assert.ok(snapshot.blockingProblems.some((problem) =>
      problem.code === 'declared_reconciliation_mismatch'));
    assert.equal(snapshot.reconciliation.declared, true);
    assert.equal(snapshot.reconciliation.status, 'blocked');
    assert.equal(snapshot.score.ready, false);
  });

  it('authorizes exact-bound historical and current snapshots while ignoring staged rows', () => {
    const first = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const second = compoundMetadata(2, '2026-07-04T02:00:00Z');
    const staged = compoundMetadata(3, '2026-07-04T03:00:00Z');
    const report = compoundAdvisorySnapshotPublicationAuthorizations({
      snapshots: [
        { metadata: first },
        { metadata: second },
        { metadata: staged },
      ],
      attempts: [
        { runId: 'run-1', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'run-2', startedAt: '2026-07-04T00:30:00Z' },
      ],
      receipts: [
        publicationReceipt(first),
        publicationReceipt(second),
      ],
    });
    assert.deepEqual(report.problems, []);
    assert.deepEqual(report.authorizedSnapshotIds, [1, 2]);
    assert.deepEqual(report.stagedSnapshotIds, [3]);
    assert.deepEqual(
      report.authorizations.map((authorization) => ({
        snapshotId: authorization.snapshotId,
        runId: authorization.runId,
        metadataDigest: authorization.metadataDigest,
      })),
      [
        {
          snapshotId: 1,
          runId: 'run-1',
          metadataDigest: compoundAdvisorySnapshotMetadataDigest(first),
        },
        {
          snapshotId: 2,
          runId: 'run-2',
          metadataDigest: compoundAdvisorySnapshotMetadataDigest(second),
        },
      ],
    );
  });

  it('does not trust any advisory authorization when the operation ledger is invalid', () => {
    const metadataValue = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const report = compoundAdvisorySnapshotPublicationAuthorizations({
      snapshots: [{ metadata: metadataValue }],
      attempts: [{ runId: 'run-1', startedAt: '2026-07-04T00:00:00Z' }],
      receipts: [publicationReceipt(metadataValue)],
      operationLedgerProblems: ['receipt chain mismatch'],
    });
    assert.deepEqual(report.authorizations, []);
    assert.deepEqual(report.authorizedSnapshotIds, []);
    assert.deepEqual(report.stagedSnapshotIds, [1]);
    assert.deepEqual(report.problems, [
      'operation receipt ledger: receipt chain mismatch',
    ]);
  });

  it('rejects malformed, missing, and duplicate successful receipt bindings', () => {
    const metadataValue = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const malformedCatalog = {
      ...JSON.parse(publicationReceipt(metadataValue).payloadJson).advisoryCatalog,
      scoreHash: '0'.repeat(64),
    };
    const missingSnapshotCatalog = {
      ...JSON.parse(publicationReceipt(metadataValue).payloadJson).advisoryCatalog,
      snapshotId: 99,
      metadata: {
        ...metadataValue,
        snapshotId: 99,
      },
    };
    const report = compoundAdvisorySnapshotPublicationAuthorizations({
      snapshots: [{ metadata: metadataValue }],
      attempts: [
        { runId: 'malformed', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'missing', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'first', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'duplicate', startedAt: '2026-07-04T00:00:00Z' },
      ],
      receipts: [
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-malformed',
          runId: 'malformed',
          advisoryCatalog: malformedCatalog,
        }),
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-missing',
          runId: 'missing',
          advisoryCatalog: missingSnapshotCatalog,
        }),
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-first',
          runId: 'first',
        }),
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-duplicate',
          runId: 'duplicate',
        }),
      ],
    });
    assert.equal(report.authorizations.length, 1);
    assert.equal(report.authorizations[0].receiptId, 'receipt-first');
    assert.ok(report.problems.some((problem) =>
      problem.includes('score hash does not match')));
    assert.ok(report.problems.some((problem) =>
      problem.includes('references missing advisory snapshot v2 99')));
    assert.ok(report.problems.some((problem) =>
      problem.includes('duplicate successful receipt authorization')));
  });

  it('rejects schema-3 success receipts without v2 binding and invalid publication timing', () => {
    const metadataValue = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const report = compoundAdvisorySnapshotPublicationAuthorizations({
      snapshots: [{ metadata: metadataValue }],
      attempts: [
        { runId: 'missing-binding', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'late-start', startedAt: '2026-07-04T02:00:00Z' },
      ],
      receipts: [
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-missing-binding',
          runId: 'missing-binding',
          advisoryCatalog: null,
        }),
        publicationReceipt(metadataValue, {
          receiptId: 'receipt-late-start',
          runId: 'late-start',
        }),
      ],
    });
    assert.deepEqual(report.authorizations, []);
    assert.ok(report.problems.some((problem) =>
      problem.includes('has no advisory v2 binding')));
    assert.ok(report.problems.some((problem) =>
      problem.includes('invalid publication timing')));
  });

  it('projects the active receipt-authorized v2 publication and keeps newer staging separate', () => {
    const first = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const active = compoundMetadata(2, '2026-07-04T02:00:00Z');
    const staged = compoundMetadata(3, '2026-07-04T03:00:00Z');
    const projection = buildCompoundAdvisorySnapshotAuditProjection({
      snapshots: [
        { metadata: first },
        { metadata: active },
        { metadata: staged },
      ],
      activeMetadata: active,
      attempts: [
        { runId: 'run-1', startedAt: '2026-07-04T00:00:00Z' },
        { runId: 'run-2', startedAt: '2026-07-04T00:30:00Z' },
      ],
      receipts: [
        publicationReceipt(first),
        publicationReceipt(active),
      ],
    });

    assert.equal(projection.verified, true);
    assert.equal(projection.failedCount, 0);
    assert.equal(projection.latestSnapshotId, 3);
    assert.equal(projection.activeSnapshotId, 2);
    assert.deepEqual(projection.activeMetadata, active);
    assert.equal(
      projection.activeMetadataDigest,
      compoundAdvisorySnapshotMetadataDigest(active),
    );
    assert.equal(projection.activeContentHash, active.contentHash);
    assert.equal(
      projection.activeScoreContentDigest,
      active.scoreContentDigest,
    );
    assert.equal(projection.activeProjectionVerified, true);
    assert.equal(projection.authorizingReceipt?.receiptId, 'receipt-2');
    assert.deepEqual(projection.authorizedSnapshotIds, [1, 2]);
    assert.deepEqual(projection.stagedSnapshotIds, [3]);
    assert.equal(projection.authorizedSnapshotCount, 2);
    assert.equal(projection.stagedSnapshotCount, 1);
    assert.deepEqual(projection.problems, []);
  });

  it('fails closed for staged-only, unauthorized, and projection-tampered active snapshots', () => {
    const active = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const stagedOnly = buildCompoundAdvisorySnapshotAuditProjection({
      snapshots: [{ metadata: active }],
      activeMetadata: null,
      attempts: [],
      receipts: [],
    });
    assert.equal(stagedOnly.verified, false);
    assert.equal(stagedOnly.activeSnapshotId, null);
    assert.deepEqual(stagedOnly.stagedSnapshotIds, [1]);
    assert.ok(stagedOnly.activeProjectionProblems.some((problem) =>
      problem.includes('metadata is missing')));

    const unauthorized = buildCompoundAdvisorySnapshotAuditProjection({
      snapshots: [{ metadata: active }],
      activeMetadata: active,
      attempts: [],
      receipts: [],
    });
    assert.equal(unauthorized.verified, false);
    assert.equal(unauthorized.activeProjectionVerified, true);
    assert.equal(unauthorized.authorizingReceipt, null);
    assert.ok(unauthorized.authorizationProblems.some((problem) =>
      problem.includes('exactly one successful receipt authorization')));

    const projectionTampered = buildCompoundAdvisorySnapshotAuditProjection({
      snapshots: [{ metadata: active }],
      activeMetadata: active,
      activeProjectionProblems: [
        'active advisory rows do not match the selected v2 score projection',
      ],
      attempts: [
        { runId: 'run-1', startedAt: '2026-07-04T00:00:00Z' },
      ],
      receipts: [publicationReceipt(active)],
    });
    assert.equal(projectionTampered.verified, false);
    assert.equal(projectionTampered.activeProjectionVerified, false);
    assert.ok(projectionTampered.problems.some((problem) =>
      problem.includes('active advisory rows do not match')));
  });

  it('isolates ledger and receipt authorization failures while preserving semantic receipt identity', () => {
    const active = compoundMetadata(1, '2026-07-04T01:00:00Z');
    const receipt = publicationReceipt(active);
    const validInput = {
      snapshots: [{ metadata: active }],
      activeMetadata: active,
      attempts: [
        { runId: 'run-1', startedAt: '2026-07-04T00:00:00Z' },
      ],
    };
    const first = buildCompoundAdvisorySnapshotAuditProjection({
      ...validInput,
      receipts: [{ ...receipt, previousContentHash: null } as typeof receipt],
    });
    const rechained = buildCompoundAdvisorySnapshotAuditProjection({
      ...validInput,
      receipts: [{
        ...receipt,
        previousContentHash: 'f'.repeat(64),
      } as typeof receipt],
    });
    assert.equal(first.verified, true);
    assert.equal(
      rechained.authorizingReceipt?.receiptSemanticIdentity,
      first.authorizingReceipt?.receiptSemanticIdentity,
    );

    const invalidLedger = buildCompoundAdvisorySnapshotAuditProjection({
      ...validInput,
      receipts: [receipt],
      operationLedgerProblems: ['receipt chain mismatch'],
    });
    assert.equal(invalidLedger.verified, false);
    assert.deepEqual(
      invalidLedger.operationLedgerProblems,
      ['receipt chain mismatch'],
    );
    assert.ok(invalidLedger.authorizationProblems.some((problem) =>
      problem.includes('exactly one successful receipt authorization')));
    assert.equal(invalidLedger.authorizingReceipt, null);

    const tamperedCatalog = {
      ...JSON.parse(receipt.payloadJson).advisoryCatalog,
      contentHash: '0'.repeat(64),
    };
    const invalidBinding = buildCompoundAdvisorySnapshotAuditProjection({
      ...validInput,
      receipts: [publicationReceipt(active, {
        advisoryCatalog: tamperedCatalog,
      })],
    });
    assert.equal(invalidBinding.verified, false);
    assert.ok(invalidBinding.authorizationProblems.some((problem) =>
      problem.includes('ledger content hash does not match')));
  });
});
