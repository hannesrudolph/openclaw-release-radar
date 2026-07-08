import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  buildArtifactVerificationEvidence,
  releaseArtifactScoreProjection,
} from './artifactVerification.ts';
import {
  buildReleaseArtifactObservation,
  buildReleaseArtifactReceipt,
  type ReleaseArtifactIdentity,
} from './releaseArtifactReceipt.ts';

const VERSION = '2026.6.10';
const TAG = `v${VERSION}`;
const RELEASE_SHA = 'a'.repeat(40);
const TARBALL_URL =
  `https://registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`;
const REPORT_URL =
  `https://github.com/openclaw/openclaw/blob/${RELEASE_SHA}/release-evidence.json`;

describe('release artifact scoring projection', () => {
  it('grants artifact credit only from the immutable selected receipt', () => {
    const receipt = buildReleaseArtifactReceipt({
      release: releaseIdentity(),
      releaseMetadata: {
        npmPackageUrl: `https://www.npmjs.com/package/openclaw/v/${VERSION}`,
        releaseTarballUrl: TARBALL_URL,
        releaseIntegrity: integrity(),
        releaseSha: RELEASE_SHA,
        ciReportUrl: REPORT_URL,
        fullReleaseValidationUrl: null,
      },
      artifact: artifactEvidence(),
      evidenceReport: {
        url: REPORT_URL,
        rawUrl:
          `https://raw.githubusercontent.com/openclaw/openclaw/${RELEASE_SHA}/` +
          'release-evidence.json',
        fallbackUrl: null,
        fallbackKind: null,
        fallbackArtifactCount: 0,
        contentDigest: '6'.repeat(64),
        fallbackArtifactDigest: null,
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
        verified: true,
        mismatch: null,
      },
      previousContentHash: null,
    });
    const observation = buildReleaseArtifactObservation({
      runId: 'artifact-score-run',
      observedAt: '2026-07-05T00:00:00.000Z',
      release: releaseIdentity(),
      receipt,
      previousContentHash: null,
    });

    const missing = releaseArtifactScoreProjection(
      null,
      RELEASE_SHA,
    );
    assert.deepEqual(missing.input, {
      artifactVerified: false,
      artifactMismatch: null,
      ciReportVerified: false,
      ciReportMismatch: null,
      releaseIntegrityPresent: false,
      releaseShaMatches: undefined,
    });
    assert.equal(missing.gate.receiptId, null);
    assert.equal(missing.gate.release, null);
    assert.equal(missing.gate.artifact, null);
    assert.equal(missing.gate.receiptContentHash, null);

    const selected = releaseArtifactScoreProjection(
      { observation, receipt },
      RELEASE_SHA,
    );
    assert.deepEqual(selected.input, {
      artifactVerified: true,
      artifactMismatch: null,
      ciReportVerified: true,
      ciReportMismatch: null,
      releaseIntegrityPresent: true,
      releaseShaMatches: true,
    });
    assert.equal(selected.gate.observationId, observation.observationId);
    assert.equal(selected.gate.receiptId, receipt.receiptId);
    assert.equal(selected.gate.evidenceIdentity, receipt.evidenceIdentity);
    assert.equal(
      selected.gate.evidenceReportIdentity,
      receipt.evidenceReportIdentity,
    );
    assert.equal(selected.gate.schemaVersion, 2);
    assert.equal(selected.gate.runId, observation.runId);
    assert.equal(selected.gate.observedAt, observation.observedAt);
    assert.equal(
      selected.gate.observationContentHash,
      observation.contentHash,
    );
    assert.equal(
      selected.gate.observationPreviousContentHash,
      observation.previousContentHash,
    );
    assert.equal(selected.gate.receiptContentHash, receipt.contentHash);
    assert.equal(
      selected.gate.receiptPreviousContentHash,
      receipt.previousContentHash,
    );
    assert.deepEqual(selected.gate.release, receipt.release);
    assert.deepEqual(selected.gate.releaseMetadata, receipt.releaseMetadata);
    assert.deepEqual(selected.gate.artifact, receipt.artifact);
    assert.deepEqual(selected.gate.evidenceReport, receipt.evidenceReport);

    const wrongCommit = releaseArtifactScoreProjection(
      { observation, receipt },
      'b'.repeat(40),
    );
    assert.equal(wrongCommit.input.releaseShaMatches, false);
    assert.equal(wrongCommit.gate.releaseShaMatches, false);
  });
});

function releaseIdentity(): ReleaseArtifactIdentity {
  return {
    repository: 'openclaw/openclaw',
    tag: TAG,
    releaseNodeId: 'RE_artifact_score_projection',
    catalogTagCommitOid: RELEASE_SHA,
    publishedAt: '2026-06-10T12:00:00.000Z',
  };
}

function artifactEvidence() {
  const bytes = Buffer.from('release artifact scoring bytes');
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
  });
}

function integrity(): string {
  const bytes = Buffer.from('release artifact scoring bytes');
  return `sha512-${createHash('sha512').update(bytes).digest('base64')}`;
}
