import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  buildArtifactVerificationEvidence,
  releaseArtifactScoreProjection,
} from './artifactVerification.ts';
import {
  assertReleaseArtifactObservation,
  assertReleaseArtifactReceipt,
  buildReleaseArtifactObservation,
  buildReleaseArtifactReceipt,
  type ReleaseArtifactIdentity,
  type ReleaseArtifactMetadata,
  type ReleaseArtifactReceipt,
} from './releaseArtifactReceipt.ts';
import {
  buildReleaseArtifactPublication,
  releaseArtifactPublicationLink,
} from './releaseArtifactPublication.ts';
import {
  buildReleaseArtifactPublicationScope,
  parseReleaseArtifactPublicationScope,
  releaseArtifactPublicationScopeLinkProblems,
  releaseArtifactPublicationScopeScoreProblems,
} from './releaseArtifactPublicationScope.ts';
import type { EvidenceReportVerification } from './releaseEvidence.ts';

const VERSION = '2026.6.10';
const TAG = `v${VERSION}`;
const RELEASE_SHA = 'a'.repeat(40);
const TARBALL_URL =
  `https://registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`;
const REPORT_URL =
  `https://github.com/openclaw/openclaw/blob/${RELEASE_SHA}/` +
  'release-evidence.json';
const RAW_REPORT_URL =
  `https://raw.githubusercontent.com/openclaw/openclaw/${RELEASE_SHA}/` +
  'release-evidence.json';
const VALIDATION_URL =
  'https://github.com/openclaw/openclaw/actions/runs/123456789';

describe('release artifact receipts', () => {
  it('canonically separates scored releases from predecessor dependencies', () => {
    const scope = buildReleaseArtifactPublicationScope({
      scoredReleaseTags: ['v2026.7.5', 'v2026.7.4'],
      predecessorByReleaseTag: {
        'v2026.7.5': 'v2026.7.4',
        'v2026.7.4': 'v2026.7.3',
      },
    });

    assert.deepEqual(scope.scoredReleaseTags, ['v2026.7.4', 'v2026.7.5']);
    assert.deepEqual(scope.dependencyReleaseTags, ['v2026.7.3']);
    assert.equal(scope.releaseCount, 3);
    assert.deepEqual(parseReleaseArtifactPublicationScope(scope), scope);
    assert.match(scope.contentDigest, /^[0-9a-f]{64}$/);
  });

  it('rejects missing, extra, duplicate, and role-swapped artifact links', () => {
    const expected = {
      scoredReleaseTags: ['v2026.7.5', 'v2026.7.4'],
      predecessorByReleaseTag: {
        'v2026.7.5': 'v2026.7.4',
        'v2026.7.4': 'v2026.7.3',
      },
    };
    const scope = buildReleaseArtifactPublicationScope(expected);
    const publication = (tags: string[]) => ({
      links: tags.map((tag) => ({ release: { tag } })),
    });

    assert.deepEqual(
      releaseArtifactPublicationScopeLinkProblems(
        publication(['v2026.7.5', 'v2026.7.4', 'v2026.7.3']),
        scope,
      ),
      [],
    );
    assert.match(
      releaseArtifactPublicationScopeLinkProblems(
        publication(['v2026.7.5', 'v2026.7.4']),
        scope,
      ).join('\n'),
      /does not match/,
    );
    assert.match(
      releaseArtifactPublicationScopeLinkProblems(
        publication([
          'v2026.7.5',
          'v2026.7.4',
          'v2026.7.3',
          'v2026.7.2',
        ]),
        scope,
      ).join('\n'),
      /does not match/,
    );
    assert.match(
      releaseArtifactPublicationScopeLinkProblems(
        publication(['v2026.7.5', 'v2026.7.4', 'v2026.7.4']),
        scope,
      ).join('\n'),
      /duplicate/,
    );

    const roleSwapped = buildReleaseArtifactPublicationScope({
      scoredReleaseTags: ['v2026.7.5', 'v2026.7.3'],
      predecessorByReleaseTag: {
        'v2026.7.5': 'v2026.7.4',
        'v2026.7.3': null,
      },
    });
    assert.match(
      releaseArtifactPublicationScopeScoreProblems(
        roleSwapped,
        expected,
      ).join('\n'),
      /does not match/,
    );
  });

  it('content-addresses semantic evidence independently from ledger position', () => {
    const first = receipt();
    const chained = receipt({ previousContentHash: 'b'.repeat(64) });

    assert.equal(first.receiptId, chained.receiptId);
    assert.equal(first.evidenceIdentity, chained.evidenceIdentity);
    assert.equal(first.canonicalReceiptJson, chained.canonicalReceiptJson);
    assert.notEqual(first.contentHash, chained.contentHash);
    assertReleaseArtifactReceipt(first);
    assertReleaseArtifactReceipt(chained);
  });

  it('binds publication receipt IDs to their evidence identities', () => {
    const semantic = receipt();
    const observation = buildReleaseArtifactObservation({
      runId: 'refresh-run-publication',
      observedAt: '2026-07-05T00:00:00.000Z',
      release: semantic.release,
      receipt: semantic,
      previousContentHash: null,
    });
    const link = releaseArtifactPublicationLink(observation, semantic);

    assert.throws(
      () => buildReleaseArtifactPublication([{
        ...link,
        evidenceIdentity: 'f'.repeat(64),
      }]),
      /receipt ID does not match its evidence identity/,
    );
  });

  it('keeps observation freshness and run provenance outside semantic identity', () => {
    const semantic = receipt();
    const first = buildReleaseArtifactObservation({
      runId: 'refresh-run-1',
      observedAt: '2026-07-05T00:00:00.000Z',
      release: releaseIdentity(),
      receipt: semantic,
      previousContentHash: null,
    });
    const later = buildReleaseArtifactObservation({
      runId: 'refresh-run-1',
      observedAt: '2026-07-05T00:05:00.000Z',
      release: releaseIdentity(),
      receipt: semantic,
      previousContentHash: null,
    });
    const nextRun = buildReleaseArtifactObservation({
      runId: 'refresh-run-2',
      observedAt: '2026-07-05T00:05:00.000Z',
      release: releaseIdentity(),
      receipt: semantic,
      previousContentHash: first.contentHash,
    });

    assert.equal(first.receiptId, semantic.receiptId);
    assert.equal(later.receiptId, semantic.receiptId);
    assert.equal(nextRun.receiptId, semantic.receiptId);
    assert.equal(first.observationId, later.observationId);
    assert.notEqual(first.contentHash, later.contentHash);
    assert.notEqual(first.observationId, nextRun.observationId);
    assert.equal(nextRun.previousContentHash, first.contentHash);
    assertReleaseArtifactObservation(first);
    assertReleaseArtifactObservation(later);
    assertReleaseArtifactObservation(nextRun);
  });

  it('rejects artifact evidence whose retained facts do not replay its identities', () => {
    const input = receiptInput();
    input.artifact.registryIdentity =
      `artifact-v2:registry:sha256:${'f'.repeat(64)}`;

    assert.throws(
      () => buildReleaseArtifactReceipt(input),
      /does not replay from its retained source facts/,
    );
  });

  it('withholds verification without retained tarball bytes or canonical digests', () => {
    const missingBytes = artifactEvidence({ tarballByteCount: null });
    assert.equal(missingBytes.registryVerified, false);
    assert.equal(missingBytes.verified, false);
    assert.equal(missingBytes.registryState, 'unknown');

    const malformedDigest = artifactEvidence({
      actualDigests: { sha512: 'not-base64' },
    });
    assert.equal(malformedDigest.registryVerified, false);
    assert.equal(malformedDigest.verified, false);
    assert.equal(malformedDigest.registryState, 'mismatch');
    assert.match(malformedDigest.reason ?? '', /digest malformed/);
  });

  it('withholds score verification from an observation bound to another receipt', () => {
    const semantic = receipt();
    const observation = buildReleaseArtifactObservation({
      runId: 'refresh-run-selection',
      observedAt: '2026-07-05T00:00:00.000Z',
      release: semantic.release,
      receipt: semantic,
      previousContentHash: null,
    });
    const projection = releaseArtifactScoreProjection(
      {
        observation: {
          ...observation,
          receiptId: `artifact-receipt-v2:${'f'.repeat(64)}`,
        },
        receipt: semantic,
      },
      RELEASE_SHA,
    );

    assert.equal(projection.input.artifactVerified, false);
    assert.equal(projection.input.ciReportVerified, false);
    assert.equal(projection.gate.verified, false);
    assert.match(
      projection.gate.mismatch ?? '',
      /observation references a different receipt/,
    );
  });

  it('rejects cross-release artifact and report reuse', () => {
    const artifactReplay = receiptInput();
    artifactReplay.release = {
      ...artifactReplay.release,
      tag: 'v2026.6.11',
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(artifactReplay),
      /artifact requestedVersion .* != 2026\.6\.11/,
    );

    const reportReplay = receiptInput();
    reportReplay.evidenceReport = {
      ...reportReplay.evidenceReport,
      expectedReleaseTag: 'v2026.6.9',
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(reportReplay),
      /expected release tag does not match release/,
    );

    const shaReplay = receiptInput();
    shaReplay.evidenceReport = {
      ...shaReplay.evidenceReport,
      expectedReleaseSha: 'c'.repeat(40),
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(shaReplay),
      /expected release SHA does not match release/,
    );
  });

  it('rejects release metadata substitutions and report URL swaps', () => {
    const releaseShaMismatch = receiptInput();
    releaseShaMismatch.releaseMetadata = {
      ...releaseShaMismatch.releaseMetadata,
      releaseSha: 'd'.repeat(40),
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(releaseShaMismatch),
      /expected release SHA does not match release metadata|release metadata SHA .* != catalog/,
    );

    const reportUrlMismatch = receiptInput();
    reportUrlMismatch.evidenceReport = {
      ...reportUrlMismatch.evidenceReport,
      url: 'https://github.com/openclaw/openclaw/blob/main/other.json',
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(reportUrlMismatch),
      /evidence report URL does not match release metadata/,
    );

    const fallbackUrlMismatch = receiptInput({
      evidenceReport: fallbackEvidenceReport(),
    });
    fallbackUrlMismatch.releaseMetadata = {
      ...fallbackUrlMismatch.releaseMetadata,
      fullReleaseValidationUrl:
        'https://github.com/openclaw/openclaw/actions/runs/987654321',
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(fallbackUrlMismatch),
      /fallback URL does not match release metadata/,
    );
  });

  it('requires verified reports to retain their release binding and digest', () => {
    const missingBinding = receiptInput();
    missingBinding.evidenceReport = {
      ...missingBinding.evidenceReport,
      expectedReleaseSha: null,
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(missingBinding),
      /must retain its release tag and SHA binding/,
    );

    const missingDigest = receiptInput();
    missingDigest.evidenceReport = {
      ...missingDigest.evidenceReport,
      contentDigest: null,
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(missingDigest),
      /must retain a content digest/,
    );

    const missingSource = receiptInput();
    missingSource.evidenceReport = {
      ...missingSource.evidenceReport,
      url: null,
      rawUrl: null,
    };
    missingSource.releaseMetadata = {
      ...missingSource.releaseMetadata,
      ciReportUrl: null,
    };
    assert.throws(
      () => buildReleaseArtifactReceipt(missingSource),
      /must retain its source URLs/,
    );
  });

  it('accepts primary success and rejects fallback tuple contamination', () => {
    const valid = primaryEvidenceReport();
    assertReleaseArtifactReceipt(receipt({ evidenceReport: valid }));

    const adversarial: Array<{
      name: string;
      report: EvidenceReportVerification;
      problem: RegExp;
    }> = [
      {
        name: 'kind without URL',
        report: { ...valid, fallbackKind: 'github_actions_run' },
        problem: /fallback kind and URL must both be present or null/,
      },
      {
        name: 'URL without kind',
        report: { ...valid, fallbackUrl: VALIDATION_URL },
        problem: /fallback kind and URL must both be present or null/,
      },
      {
        name: 'artifact count without fallback',
        report: { ...valid, fallbackArtifactCount: 1 },
        problem: /without fallback must have zero artifact count/,
      },
      {
        name: 'artifact digest without fallback',
        report: { ...valid, fallbackArtifactDigest: '8'.repeat(64) },
        problem: /without fallback cannot retain fallback artifact digest/,
      },
      {
        name: 'missing primary digest',
        report: { ...valid, contentDigest: null },
        problem: /Verified primary evidence report must retain a content digest/,
      },
      {
        name: 'success carrying mismatch',
        report: { ...valid, mismatch: 'unexpected primary mismatch' },
        problem: /cannot also carry mismatch detail/,
      },
    ];

    for (const { name, report, problem } of adversarial) {
      assert.throws(
        () => receipt({ evidenceReport: report }),
        problem,
        name,
      );
    }
  });

  it('accepts primary failure and rejects retained success evidence', () => {
    const valid = primaryFailureEvidenceReport();
    assertReleaseArtifactReceipt(receipt({ evidenceReport: valid }));

    const adversarial: Array<{
      name: string;
      report: EvidenceReportVerification;
      problem: RegExp;
    }> = [
      {
        name: 'primary digest retained after failure',
        report: { ...valid, contentDigest: '6'.repeat(64) },
        problem: /Failed primary evidence report cannot retain a success digest/,
      },
      {
        name: 'artifact count retained without fallback',
        report: { ...valid, fallbackArtifactCount: 2 },
        problem: /without fallback must have zero artifact count/,
      },
      {
        name: 'artifact digest retained without fallback',
        report: { ...valid, fallbackArtifactDigest: '8'.repeat(64) },
        problem: /without fallback cannot retain fallback artifact digest/,
      },
      {
        name: 'failure relabeled verified without a digest',
        report: { ...valid, verified: true, mismatch: null },
        problem: /Verified primary evidence report must retain a content digest/,
      },
    ];

    for (const { name, report, problem } of adversarial) {
      assert.throws(
        () => receipt({ evidenceReport: report }),
        problem,
        name,
      );
    }
  });

  it('accepts fallback success and rejects incomplete success tuples', () => {
    const valid = fallbackEvidenceReport();
    assertReleaseArtifactReceipt(receipt({ evidenceReport: valid }));

    const adversarial: Array<{
      name: string;
      report: EvidenceReportVerification;
      problem: RegExp;
    }> = [
      {
        name: 'missing fallback kind',
        report: { ...valid, fallbackKind: null },
        problem: /fallback kind and URL must both be present or null/,
      },
      {
        name: 'missing fallback URL',
        report: { ...valid, fallbackUrl: null },
        problem: /fallback kind and URL must both be present or null/,
      },
      {
        name: 'zero successful artifact count',
        report: { ...valid, fallbackArtifactCount: 0 },
        problem: /must retain a positive artifact count/,
      },
      {
        name: 'missing manifest digest',
        report: { ...valid, contentDigest: null },
        problem: /must retain manifest and artifact digests/,
      },
      {
        name: 'missing artifact digest',
        report: { ...valid, fallbackArtifactDigest: null },
        problem: /must retain manifest and artifact digests/,
      },
      {
        name: 'successful fallback carrying mismatch',
        report: { ...valid, mismatch: 'unexpected fallback mismatch' },
        problem: /cannot also carry mismatch detail/,
      },
    ];

    for (const { name, report, problem } of adversarial) {
      assert.throws(
        () => receipt({ evidenceReport: report }),
        problem,
        name,
      );
    }
  });

  it('accepts fallback failure counts and rejects success residue', () => {
    for (const fallbackArtifactCount of [0, 3]) {
      assertReleaseArtifactReceipt(receipt({
        evidenceReport: fallbackFailureEvidenceReport(fallbackArtifactCount),
      }));
    }

    const valid = fallbackFailureEvidenceReport(2);
    const adversarial: Array<{
      name: string;
      report: EvidenceReportVerification;
      problem: RegExp;
    }> = [
      {
        name: 'failed fallback retaining manifest digest',
        report: { ...valid, contentDigest: '7'.repeat(64) },
        problem: /Failed fallback evidence report cannot retain success digests/,
      },
      {
        name: 'failed fallback retaining artifact digest',
        report: { ...valid, fallbackArtifactDigest: '8'.repeat(64) },
        problem: /Failed fallback evidence report cannot retain success digests/,
      },
      {
        name: 'failed fallback without mismatch detail',
        report: { ...valid, mismatch: null },
        problem: /Failed fallback evidence report must retain mismatch detail/,
      },
      {
        name: 'failed fallback without kind',
        report: { ...valid, fallbackKind: null },
        problem: /fallback kind and URL must both be present or null/,
      },
      {
        name: 'failed fallback without URL',
        report: { ...valid, fallbackUrl: null },
        problem: /fallback kind and URL must both be present or null/,
      },
    ];

    for (const { name, report, problem } of adversarial) {
      assert.throws(
        () => receipt({ evidenceReport: report }),
        problem,
        name,
      );
    }
  });

  it('accepts explicit missing report evidence without inventing verification', () => {
    const missingReport: EvidenceReportVerification = {
      url: REPORT_URL,
      rawUrl: RAW_REPORT_URL,
      fallbackUrl: null,
      fallbackKind: null,
      fallbackArtifactCount: 0,
      contentDigest: null,
      fallbackArtifactDigest: null,
      expectedReleaseTag: TAG,
      expectedReleaseSha: RELEASE_SHA,
      verified: false,
      mismatch: 'release evidence report not found',
    };
    const value = receipt({ evidenceReport: missingReport });

    assert.equal(value.evidenceReport.verified, false);
    assert.equal(value.evidenceReport.mismatch, 'release evidence report not found');
    assertReleaseArtifactReceipt(value);
  });

  it('detects receipt and observation tampering even after fields are reserialized', () => {
    const semantic = receipt();
    for (const tampered of [
      { ...semantic, contentHash: '0'.repeat(64) },
      { ...semantic, evidenceIdentity: '1'.repeat(64) },
      {
        ...semantic,
        evidenceReportIdentity: `release-evidence-v1:sha256:${'2'.repeat(64)}`,
      },
      {
        ...semantic,
        canonicalReceiptJson: semantic.canonicalReceiptJson.replace(
          '"verified":true',
          '"verified":false',
        ),
      },
    ]) {
      assert.throws(
        () => assertReleaseArtifactReceipt(tampered as ReleaseArtifactReceipt),
        /failed verification/,
      );
    }

    const observation = buildReleaseArtifactObservation({
      runId: 'refresh-run-tamper',
      observedAt: '2026-07-05T01:00:00.000Z',
      release: releaseIdentity(),
      receipt: semantic,
      previousContentHash: null,
    });
    for (const tampered of [
      { ...observation, contentHash: '3'.repeat(64) },
      { ...observation, receiptContentHash: '4'.repeat(64) },
      { ...observation, runId: 'refresh-run-substituted' },
      {
        ...observation,
        canonicalObservationJson: observation.canonicalObservationJson.replace(
          'refresh-run-tamper',
          'refresh-run-other',
        ),
      },
    ]) {
      assert.throws(
        () => assertReleaseArtifactObservation(tampered),
        /failed verification/,
      );
    }
  });

  it('rejects noncanonical timestamps and malformed chain anchors', () => {
    assert.throws(
      () => buildReleaseArtifactReceipt({
        ...receiptInput(),
        release: {
          ...releaseIdentity(),
          publishedAt: '2026-06-10T12:00:00Z',
        },
      }),
      /canonical ISO-8601/,
    );
    assert.throws(
      () => receipt({ previousContentHash: 'not-a-digest' }),
      /lowercase SHA-256 digest/,
    );
    assert.throws(
      () => buildReleaseArtifactObservation({
        runId: 'refresh-run-invalid',
        observedAt: '2026-07-05T00:00:00Z',
        release: releaseIdentity(),
        receipt: receipt(),
        previousContentHash: null,
      }),
      /canonical ISO-8601/,
    );
  });
});

function receipt(
  overrides: {
    previousContentHash?: string | null;
    evidenceReport?: EvidenceReportVerification;
  } = {},
): ReleaseArtifactReceipt {
  return buildReleaseArtifactReceipt(receiptInput(overrides));
}

function receiptInput(
  overrides: {
    previousContentHash?: string | null;
    evidenceReport?: EvidenceReportVerification;
  } = {},
) {
  return {
    release: releaseIdentity(),
    releaseMetadata: releaseMetadata(),
    artifact: artifactEvidence(),
    evidenceReport: overrides.evidenceReport ?? primaryEvidenceReport(),
    previousContentHash: overrides.previousContentHash ?? null,
  };
}

function releaseIdentity(): ReleaseArtifactIdentity {
  return {
    repository: 'openclaw/openclaw',
    tag: TAG,
    releaseNodeId: 'RE_kwDOReleaseArtifactReceipt',
    catalogTagCommitOid: RELEASE_SHA,
    publishedAt: '2026-06-10T12:00:00.000Z',
  };
}

function releaseMetadata(): ReleaseArtifactMetadata {
  return {
    npmPackageUrl: `https://www.npmjs.com/package/openclaw/v/${VERSION}`,
    releaseTarballUrl: TARBALL_URL,
    releaseIntegrity: integrity(),
    releaseSha: RELEASE_SHA,
    ciReportUrl: REPORT_URL,
    fullReleaseValidationUrl: VALIDATION_URL,
  };
}

function artifactEvidence(
  overrides: Partial<Parameters<typeof buildArtifactVerificationEvidence>[0]> = {},
) {
  const bytes = Buffer.from('release artifact receipt tarball bytes');
  const digest = createHash('sha512').update(bytes).digest('base64');
  return buildArtifactVerificationEvidence({
    packageName: 'openclaw',
    requestedVersion: VERSION,
    metadataUrl: `https://registry.npmjs.org/openclaw/${VERSION}`,
    metadataContentDigest: '5'.repeat(64),
    registryAvailability: 'available',
    registryPackageName: 'openclaw',
    registryVersion: VERSION,
    registryIntegrity: `sha512-${digest}`,
    registryTarballUrl: TARBALL_URL,
    registryGitHead: RELEASE_SHA,
    actualDigests: { sha512: digest },
    tarballByteCount: bytes.length,
    expectedIntegrity: `sha512-${digest}`,
    expectedTarballUrl: TARBALL_URL,
    expectedReleaseSha: RELEASE_SHA,
    ...overrides,
  });
}

function primaryEvidenceReport(): EvidenceReportVerification {
  return {
    url: REPORT_URL,
    rawUrl: RAW_REPORT_URL,
    fallbackUrl: null,
    fallbackKind: null,
    fallbackArtifactCount: 0,
    contentDigest: '6'.repeat(64),
    fallbackArtifactDigest: null,
    expectedReleaseTag: TAG,
    expectedReleaseSha: RELEASE_SHA,
    verified: true,
    mismatch: null,
  };
}

function fallbackEvidenceReport(): EvidenceReportVerification {
  return {
    url: REPORT_URL,
    rawUrl: RAW_REPORT_URL,
    fallbackUrl: VALIDATION_URL,
    fallbackKind: 'github_actions_run',
    fallbackArtifactCount: 1,
    contentDigest: '7'.repeat(64),
    fallbackArtifactDigest: '8'.repeat(64),
    expectedReleaseTag: TAG,
    expectedReleaseSha: RELEASE_SHA,
    verified: true,
    mismatch: null,
  };
}

function primaryFailureEvidenceReport(): EvidenceReportVerification {
  return {
    ...primaryEvidenceReport(),
    contentDigest: null,
    verified: false,
    mismatch: 'release evidence report rejected',
  };
}

function fallbackFailureEvidenceReport(
  fallbackArtifactCount: number,
): EvidenceReportVerification {
  return {
    ...fallbackEvidenceReport(),
    fallbackArtifactCount,
    contentDigest: null,
    fallbackArtifactDigest: null,
    verified: false,
    mismatch: 'release evidence report not found; fallback verification failed',
  };
}

function integrity(): string {
  const bytes = Buffer.from('release artifact receipt tarball bytes');
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}
