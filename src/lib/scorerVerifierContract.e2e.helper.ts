import { strict as assert } from 'node:assert';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';

type DatabaseGuardInstallation = {
  assertActive(options: {
    requirePrivateArtifacts: true;
  }): {
    runId: string;
    policyKind: string;
    databasePath: string;
    databaseIdentity: {
      dev: string;
      ino: string;
    } | null;
    dotenvPath: string;
    tempRoot: string;
  };
};

const databaseGuard = require(
  '../../test/database-guard-runtime.cjs',
) as DatabaseGuardInstallation;
const guardAttestation = databaseGuard.assertActive({
  requirePrivateArtifacts: true,
});

const scenario = process.argv[2] ?? '';
const publicationRunId = process.argv[3] ?? '';
const historyRunId = process.argv[4] ?? '';
const historyRunContentHash = process.argv[5] ?? '';
const targetTag = 'v2099.7.5';
const reviewPublicationBindingParams = new Set([
  'publicationSnapshot',
  'auditDigest',
]);

type ReleaseAuditLinks = {
  review: string;
  issues: string;
  closureProofs: string;
  reachability: string;
};

type ReleaseCatalogTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
  prerelease: boolean,
];

type ReleaseArtifactIdentityTuple = [
  tag: string,
  releaseNodeId: string,
  tagCommitOid: string,
];

type PersistedCatalogEvidenceRow = {
  tag: string;
  node_id: string;
  catalog_tag_commit_oid: string;
  prerelease: number;
};

type CatalogCaptureReceiptEvidenceRow = {
  source_kind: string;
  payload_json: string;
};

assert.equal(
  process.env.NODE_TEST_CONTEXT,
  undefined,
  'scorer/verifier helper must not inherit NODE_TEST_CONTEXT',
);
assert.equal(
  guardAttestation.runId,
  process.env.RADAR_TEST_RUN_ID,
  'scorer/verifier helper must use the installed guard run identity',
);
assert.equal(
  guardAttestation.policyKind,
  'authoritative-test-database-guard-policy',
  'scorer/verifier helper must use the authoritative kernel write boundary',
);
assert.equal(
  guardAttestation.databasePath,
  process.env.DB_PATH,
  'scorer/verifier helper must use the guarded private database',
);
assert.equal(
  guardAttestation.dotenvPath,
  process.env.DOTENV_CONFIG_PATH,
  'scorer/verifier helper must use the guarded empty dotenv artifact',
);
assert.ok(
  process.env.RADAR_TEST_RUN_ID,
  'scorer/verifier helper must inherit the guarded test run identity',
);
assert.ok(
  process.env.RADAR_CODE_REVISION,
  'scorer/verifier helper must inherit the guarded code revision',
);
assertScorerVerifierScenario(scenario);
assert.equal(
  process.env.RADAR_DB_BOOTSTRAP_MODE,
  'existing',
  'scorer/verifier helper requires an existing private database',
);
assert.ok(publicationRunId, 'missing refresh publication run id');
assert.equal(
  historyRunId,
  `refresh:${publicationRunId}`,
  'score history run must be bound to the refresh publication run',
);
assert.match(historyRunContentHash, /^[0-9a-f]{64}$/);

const { createE2eDatabaseImportGuard } = require(
  './e2eDatabaseImportGuard',
) as typeof import('./e2eDatabaseImportGuard');
const databaseImportGuard = createE2eDatabaseImportGuard({
  helperName: 'scorer/verifier helper',
  guardAttestation,
  expectedBootstrapMode: 'existing',
});

process.env.REFRESH_ON_STARTUP = 'false';
process.env.REFRESH_MINUTES = '0';
process.env.COMPARISON_API_ENABLED = 'false';

const express = require('express') as typeof import('express');

function assertScorerVerifierScenario(value: string): void {
  if (
    new Set([
      'baseline',
      'score',
      'source-identity',
      'ledger',
      'recommendation',
      'missing-proof',
    ]).has(value)
  ) {
    return;
  }
  throw new Error(`Unknown scorer/verifier contract scenario: ${value}`);
}

async function main() {
  databaseImportGuard.assertReady();
  const dbModule = await import('./db');
  const scoring = await import('./releaseScoring');
  const {
    verifyScoreAuditPayloadContracts,
  } = await import('./scoreAuditContracts');
  let server: Server | null = null;
  let reader: { close(): void } | null = null;

  try {
    const sealedPublication =
      dbModule.getSealedReleaseScoreAuditPublication(targetTag);
    assert.equal(
      sealedPublication.valid,
      true,
      sealedPublication.problems.join('; '),
    );
    const seal = dbModule.getReleaseScoreAuditHistoryRunSeal(historyRunId);
    assert.ok(seal, `missing score history seal ${historyRunId}`);
    assert.equal(seal.content_hash, historyRunContentHash);

    if (scenario !== 'baseline') {
      tamperPublication(dbModule);
    }
    const refreshReceipt =
      dbModule.getRefreshCaptureReceipt(publicationRunId);
    assert.ok(refreshReceipt);
    assert.equal(refreshReceipt.status, 'success');
    const refreshReceiptPayload = JSON.parse(refreshReceipt.payload_json);
    const catalogEvidence = exactReleaseCatalogEvidence(
      dbModule,
      refreshReceiptPayload.releaseArtifacts,
    );

    const audit = dbModule.getReleaseScoreAudit(targetTag);
    assert.ok(audit);
    assert.ok(audit.input_json);
    assert.ok(audit.components_json);
    assert.ok(audit.issue_evidence_json);
    assert.ok(audit.gate_evidence_json);
    const contractFailures = verifyScoreAuditPayloadContracts({
      tag: targetTag,
      scoredAt: audit.scored_at,
      input: JSON.parse(audit.input_json),
      components: JSON.parse(audit.components_json),
      issueEvidence: JSON.parse(audit.issue_evidence_json),
      gateEvidence: JSON.parse(audit.gate_evidence_json),
      versions: {
        scoreInput: scoring.SCORE_INPUT_SCHEMA_VERSION,
        scoreComponents: scoring.SCORE_COMPONENTS_SCHEMA_VERSION,
        issueEvidence: scoring.ISSUE_EVIDENCE_SCHEMA_VERSION,
        gateEvidence: scoring.GATE_EVIDENCE_SCHEMA_VERSION,
      },
    });

    const { api } = await import('../routes/api');
    const app = express();
    app.use('/api', api);
    server = app.listen(0, '127.0.0.1');
    await new Promise<void>((resolve, reject) => {
      server!.once('error', reject);
      server!.once('listening', resolve);
    });
    const address = server.address() as AddressInfo;
    const apiBase = `http://127.0.0.1:${address.port}`;
    const publicResponse = await fetch(`${apiBase}/api/public`);
    const publicResponseText = await publicResponse.text();
    assert.equal(
      publicResponse.status,
      200,
      `public API returned ${publicResponse.status}: ${publicResponseText}`,
    );
    const auditLinksByTag = publishedAuditLinksByTag(
      JSON.parse(publicResponseText),
    );
    const targetAuditLinks = auditLinksByTag.get(targetTag);
    assert.ok(
      targetAuditLinks,
      `public API must include target release ${targetTag}`,
    );

    const apiResponse = await fetch(new URL(targetAuditLinks.review, apiBase));
    const apiResponseText = await apiResponse.text();
    const healthResponseText = apiResponse.ok
      ? null
      : await fetch(`${apiBase}/api/health`).then((response) => response.text());
    assert.equal(
      apiResponse.status,
      200,
      `review API returned ${apiResponse.status}: ${apiResponseText}` +
        (healthResponseText == null ? '' : `; health: ${healthResponseText}`),
    );
    const apiReview = JSON.parse(apiResponseText) as any;

    const readerModulePath = '../../scripts/lib/release-audit-reader.mjs';
    const invariantsModulePath =
      '../../scripts/lib/release-audit-invariants.mjs';
    const { openReleaseAuditReader } = await import(readerModulePath);
    const { verifyReleaseAudit } = await import(invariantsModulePath);
    reader = openReleaseAuditReader(databaseImportGuard.databasePath, {
      allowTestFixtureCatalog: true,
    });
    const verification = await verifyReleaseAudit({
      reader,
      apiBase,
      limit: 1,
      scoredOnly: true,
      fetchJson: (url: string) => fetchJson(
        bindPublishedAuditUrl(url, apiBase, auditLinksByTag),
      ),
    });

    console.log(`CONTRACT_E2E_RESULT=${JSON.stringify({
      scenario,
      score: dbModule.getRelease(targetTag)?.final_score ?? null,
      historyRunId,
      historyRunContentHash,
      apiAuditDigest: apiReview.local?.auditDigest ?? null,
      apiDiagnosticStatus: apiReview.local?.diagnosticStatus ?? null,
      contractFailures,
      verifierFailures: verification.failures,
      ...catalogEvidence,
    })}`);
  } finally {
    reader?.close();
    if (server) {
      await new Promise<void>((resolve, reject) => {
        server!.close((error) => error ? reject(error) : resolve());
      });
    }
    dbModule.db.close();
  }
}

function tamperPublication(
  dbModule: typeof import('./db'),
): void {
  if (scenario === 'score') {
    dbModule.db.prepare(`
      UPDATE releases
      SET final_score=final_score - 1
      WHERE tag=?
    `).run(targetTag);
    return;
  }
  if (scenario === 'source-identity') {
    dbModule.db.prepare(`
      UPDATE release_score_audits
      SET source_identity_json=?
      WHERE release_tag=?
    `).run(
      JSON.stringify({ schemaVersion: 0, digest: '0'.repeat(64) }),
      targetTag,
    );
    return;
  }
  if (scenario === 'ledger' || scenario === 'recommendation') {
    const audit = dbModule.getReleaseScoreAudit(targetTag);
    assert.ok(audit?.components_json);
    const components = JSON.parse(audit.components_json);
    if (scenario === 'ledger') {
      components.explanation.scoreLedger.rows[0].points += 1;
    } else {
      components.recommendationDecision.summary =
        'tampered recommendation summary';
      components.explanation.recommendationDecision.summary =
        'tampered recommendation summary';
    }
    dbModule.db.prepare(`
      UPDATE release_score_audits
      SET components_json=?
      WHERE release_tag=?
    `).run(JSON.stringify(components), targetTag);
    return;
  }
  if (scenario === 'missing-proof') {
    dbModule.db.prepare(`
      DELETE FROM issue_closure_proofs
      WHERE release_tag=?
    `).run(targetTag);
    return;
  }
  throw new Error(`Unknown scorer/verifier contract scenario: ${scenario}`);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function exactReleaseCatalogEvidence(
  dbModule: typeof import('./db'),
  releaseArtifacts: unknown,
): {
  persistedCatalogTuples: ReleaseCatalogTuple[];
  catalogCaptureReceiptTags: string[];
  catalogCaptureReceiptStableCount: number;
  catalogCaptureReceiptPrereleaseCount: number;
  catalogCaptureReceiptLatestStableTuple: ReleaseCatalogTuple | null;
  refreshReceiptArtifactIdentityTuples: ReleaseArtifactIdentityTuple[];
  catalogCaptureReceiptCount: number;
  catalogCaptureReceiptSource: string | null;
} {
  const persistedCatalogRows = dbModule.db.prepare(`
    SELECT tag, node_id, catalog_tag_commit_oid, prerelease
    FROM releases
    WHERE catalog_active=1
    ORDER BY catalog_rank
  `).all() as unknown as PersistedCatalogEvidenceRow[];
  const persistedCatalogTuples = persistedCatalogRows.map(
    (release): ReleaseCatalogTuple => {
      assert.ok(
        release.node_id,
        `persisted catalog release ${release.tag} must have a node ID`,
      );
      assert.ok(
        release.catalog_tag_commit_oid,
        `persisted catalog release ${release.tag} must have a tag commit OID`,
      );
      assert.ok(
        release.prerelease === 0 || release.prerelease === 1,
        `persisted catalog release ${release.tag} must have a prerelease flag`,
      );
      return [
        release.tag,
        release.node_id,
        release.catalog_tag_commit_oid,
        release.prerelease === 1,
      ];
    },
  );
  const catalogCaptureReceipts = dbModule.db.prepare(`
    SELECT source_kind, payload_json
    FROM release_catalog_capture_receipts
    ORDER BY id
  `).all() as unknown as CatalogCaptureReceiptEvidenceRow[];
  assert.ok(catalogCaptureReceipts.length > 0);
  const latestCatalogCaptureReceipt = catalogCaptureReceipts.at(-1)!;
  const catalogCapturePayload = JSON.parse(
    latestCatalogCaptureReceipt.payload_json,
  );
  assert.ok(isRecord(catalogCapturePayload));
  assert.equal(
    catalogCapturePayload.source,
    latestCatalogCaptureReceipt.source_kind,
  );
  const receiptActiveCatalog = catalogCapturePayload.activeCatalog;
  assert.ok(isRecord(receiptActiveCatalog));
  const receiptTags = receiptActiveCatalog.tags;
  const stableCount = receiptActiveCatalog.stableCount;
  const prereleaseCount = receiptActiveCatalog.prereleaseCount;
  assert.ok(Array.isArray(receiptTags));
  const catalogCaptureReceiptTags = receiptTags.map((tag) => {
    assert.ok(typeof tag === 'string');
    return tag;
  });
  assert.ok(
    typeof stableCount === 'number' && Number.isInteger(stableCount),
  );
  assert.ok(
    typeof prereleaseCount === 'number' && Number.isInteger(prereleaseCount),
  );
  const refreshReceiptArtifactIdentityTuples =
    releaseArtifactIdentityTuplesFromReceipt(releaseArtifacts);
  assert.deepEqual(
    refreshReceiptArtifactIdentityTuples
      .map(([tag]) => tag)
      .slice()
      .sort(),
    catalogCaptureReceiptTags.slice().sort(),
    'refresh receipt artifact identities must cover the capture receipt tags',
  );
  const latestStable = receiptActiveCatalog.latestStable;
  let latestStableTuple: ReleaseCatalogTuple | null = null;
  if (latestStable !== null) {
    assert.ok(isRecord(latestStable));
    const tag = latestStable.tag;
    const nodeId = latestStable.nodeId;
    const tagCommitOid = latestStable.tagCommitOid;
    assert.ok(typeof tag === 'string');
    assert.ok(typeof nodeId === 'string');
    assert.ok(typeof tagCommitOid === 'string');
    latestStableTuple = [tag, nodeId, tagCommitOid, false];
  }
  return {
    persistedCatalogTuples,
    catalogCaptureReceiptTags,
    catalogCaptureReceiptStableCount: stableCount,
    catalogCaptureReceiptPrereleaseCount: prereleaseCount,
    catalogCaptureReceiptLatestStableTuple: latestStableTuple,
    refreshReceiptArtifactIdentityTuples,
    catalogCaptureReceiptCount: catalogCaptureReceipts.length,
    catalogCaptureReceiptSource: latestCatalogCaptureReceipt.source_kind,
  };
}

function releaseArtifactIdentityTuplesFromReceipt(
  releaseArtifacts: unknown,
): ReleaseArtifactIdentityTuple[] {
  assert.ok(
    isRecord(releaseArtifacts) && Array.isArray(releaseArtifacts.links),
    'refresh receipt must carry release artifact links',
  );
  return releaseArtifacts.links.map(
    (link, index): ReleaseArtifactIdentityTuple => {
      assert.ok(
        isRecord(link) && isRecord(link.release),
        `refresh receipt artifact link ${index} must carry a release identity`,
      );
      const release = link.release;
      const tag = release.tag;
      const releaseNodeId = release.releaseNodeId;
      const tagCommitOid = release.catalogTagCommitOid;
      assert.ok(typeof tag === 'string');
      assert.ok(typeof releaseNodeId === 'string');
      assert.ok(typeof tagCommitOid === 'string');
      return [tag, releaseNodeId, tagCommitOid];
    },
  );
}

function publishedAuditLinksByTag(
  payload: unknown,
): Map<string, ReleaseAuditLinks> {
  assert.ok(isRecord(payload), 'public API payload must be an object');
  assert.ok(
    Array.isArray(payload.releases),
    'public API payload must expose releases',
  );

  return new Map(payload.releases.map((release, index) => {
    assert.ok(isRecord(release), `public release ${index} must be an object`);
    const tag = release.tag;
    assert.ok(typeof tag === 'string', `public release ${index} must expose tag`);
    const auditLinks = release.auditLinks;
    assert.ok(
      isRecord(auditLinks),
      `public release ${tag} must expose auditLinks`,
    );
    for (const key of [
      'review',
      'issues',
      'closureProofs',
      'reachability',
    ] as const) {
      assert.equal(
        typeof auditLinks[key],
        'string',
        `public release ${tag} auditLinks.${key} must be a string`,
      );
    }
    return [tag, auditLinks as ReleaseAuditLinks] as const;
  }));
}

function bindPublishedAuditUrl(
  requestedUrl: string,
  apiBase: string,
  auditLinksByTag: ReadonlyMap<string, ReleaseAuditLinks>,
): string {
  const requested = new URL(requestedUrl);
  const match = requested.pathname.match(
    /^\/api\/releases\/([^/]+)\/review(?:\/(issues|closure-proofs|reachability))?$/,
  );
  if (!match) return requestedUrl;

  const tag = decodeURIComponent(match[1]);
  const key = ({
    undefined: 'review',
    issues: 'issues',
    'closure-proofs': 'closureProofs',
    reachability: 'reachability',
  } as const)[String(match[2]) as
    'undefined' | 'issues' | 'closure-proofs' | 'reachability'];
  const auditLinks = auditLinksByTag.get(tag);
  assert.ok(auditLinks, `public API payload must expose audit links for ${tag}`);
  const published = new URL(auditLinks[key], apiBase);

  for (const [name, value] of requested.searchParams) {
    if (!reviewPublicationBindingParams.has(name)) {
      published.searchParams.append(name, value);
    }
  }
  return published.toString();
}

async function fetchJson(url: string): Promise<unknown> {
  const response = await fetch(url);
  if (!response.ok) {
    const body = await response.text();
    let payload: unknown = null;
    try {
      payload = body ? JSON.parse(body) : null;
    } catch {
      payload = null;
    }
    throw Object.assign(
      new Error(`${url} returned ${response.status}${body ? `: ${body}` : ''}`),
      { status: response.status, body, payload },
    );
  }
  return response.json();
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
