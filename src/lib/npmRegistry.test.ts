import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  type ArtifactVerificationFacts,
  buildArtifactVerificationEvidence,
  releaseArtifactScoreProjection,
  replayArtifactVerificationEvidence,
} from './artifactVerification.ts';
import {
  NpmArtifactVerificationError,
  type NpmArtifactVerificationInput,
  npmVersionFromTag,
  verifyNpmArtifact,
} from './npmRegistry.ts';
import {
  buildReleaseArtifactObservation,
  buildReleaseArtifactReceipt,
} from './releaseArtifactReceipt.ts';

const PACKAGE_NAME = 'openclaw';
const VERSION = '2026.6.10';
const RELEASE_SHA = '0123456789abcdef0123456789abcdef01234567';
const OTHER_SHA = '89abcdef0123456789abcdef0123456789abcdef';
const NPM_PACKAGE_URL =
  `https://www.npmjs.com/package/openclaw/v/${VERSION}`;
const TARBALL_URL = `https://registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`;

describe('npm artifact verification', () => {
  it('converts release tags to npm versions', () => {
    assert.equal(npmVersionFromTag(`v${VERSION}`), VERSION);
    assert.equal(npmVersionFromTag(VERSION), VERSION);
  });

  it('downloads the exact registry tarball and verifies a SHA-bound release artifact', async () => {
    const tarball = Buffer.from('exact compressed npm tarball bytes');
    const integrity = sri(tarball);
    const calls: Array<{ url: string; init?: RequestInit }> = [];
    const fetchImpl = mockFetch((url, init) => {
      calls.push({ url, init });
      if (url.endsWith(`/${VERSION}`)) return metadataResponse(integrity);
      if (url === TARBALL_URL) {
        return new Response(tarball, {
          headers: { 'content-length': String(tarball.length) },
        });
      }
      throw new Error(`unexpected fetch ${url}`);
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.schemaVersion, 2);
    assert.equal(result.state, 'release_bound');
    assert.equal(result.registryState, 'registry_verified');
    assert.equal(result.releaseBindingState, 'release_bound');
    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBound, true);
    assert.equal(result.verified, true);
    assert.equal(result.mismatch, null);
    assert.match(result.registryIdentity ?? '', /^artifact-v2:registry:sha256:[0-9a-f]{64}$/);
    assert.match(
      result.releaseBindingIdentity ?? '',
      /^artifact-v2:release-binding:sha256:[0-9a-f]{64}$/,
    );
    assert.deepEqual(calls.map((call) => call.url), [
      `https://registry.npmjs.org/openclaw/${VERSION}`,
      TARBALL_URL,
    ]);
    assert.ok(calls.every((call) => call.init?.redirect === 'manual'));
    assert.ok(calls.every((call) => call.init?.signal instanceof AbortSignal));
  });

  it('requires the canonical release-note npm package URL for release binding', async () => {
    const tarball = Buffer.from('canonical npm package URL binding');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(integrity, tarball);

    const accepted = await verifyNpmArtifact(
      verificationInput(integrity),
      { fetchImpl },
    );
    assert.equal(accepted.releaseBindingState, 'release_bound');
    assert.equal(accepted.verified, true);

    for (const item of [
      {
        name: 'missing',
        value: null,
        state: 'unknown',
        problem: /release npm package URL missing/,
      },
      {
        name: 'malformed',
        value: 'not a URL',
        state: 'mismatch',
        problem: /release npm package URL invalid/,
      },
      {
        name: 'non-canonical',
        value: `${NPM_PACKAGE_URL}/`,
        state: 'mismatch',
        problem: /not the canonical package version URL/,
      },
      {
        name: 'wrong package',
        value: `https://www.npmjs.com/package/not-openclaw/v/${VERSION}`,
        state: 'mismatch',
        problem: /not the canonical package version URL/,
      },
      {
        name: 'wrong version',
        value: 'https://www.npmjs.com/package/openclaw/v/2026.6.9',
        state: 'mismatch',
        problem: /not the canonical package version URL/,
      },
    ] as const) {
      const result = await verifyNpmArtifact(
        verificationInput(integrity, {
          expectedNpmPackageUrl: item.value,
        }),
        { fetchImpl: metadataThenTarball(integrity, tarball) },
      );

      assert.equal(result.registryState, 'registry_verified', item.name);
      assert.equal(result.releaseBindingState, item.state, item.name);
      assert.equal(result.verified, false, item.name);
      assert.match(result.mismatch ?? result.reason ?? '', item.problem, item.name);
      assert.deepEqual(replayArtifactVerificationEvidence(result), result, item.name);
    }
  });

  it('withholds score provenance from an unbound npm package declaration', () => {
    const artifact = buildArtifactVerificationEvidence(artifactVerificationFacts());
    const release = {
      repository: 'openclaw/openclaw',
      tag: `v${VERSION}`,
      releaseNodeId: 'RE_unbound_npm_package_declaration',
      catalogTagCommitOid: RELEASE_SHA,
      publishedAt: '2026-06-10T12:00:00.000Z',
    };
    const receipt = buildReleaseArtifactReceipt({
      release,
      releaseMetadata: {
        npmPackageUrl:
          `https://www.npmjs.com/package/not-openclaw/v/${VERSION}`,
        releaseTarballUrl: TARBALL_URL,
        releaseIntegrity: artifact.expectedIntegrity,
        releaseSha: RELEASE_SHA,
        ciReportUrl: null,
        fullReleaseValidationUrl: null,
      },
      artifact,
      evidenceReport: {
        url: null,
        rawUrl: null,
        fallbackUrl: null,
        fallbackKind: null,
        fallbackArtifactCount: 0,
        contentDigest: null,
        fallbackArtifactDigest: null,
        expectedReleaseTag: release.tag,
        expectedReleaseSha: RELEASE_SHA,
        verified: false,
        mismatch: 'release evidence report not declared',
      },
      previousContentHash: null,
    });
    const observation = buildReleaseArtifactObservation({
      runId: 'unbound-npm-package-score-run',
      observedAt: '2026-07-05T00:00:00.000Z',
      release,
      receipt,
      previousContentHash: null,
    });

    const projection = releaseArtifactScoreProjection(
      { observation, receipt },
      RELEASE_SHA,
    );

    assert.equal(projection.input.artifactVerified, false);
    assert.equal(projection.input.releaseIntegrityPresent, false);
    assert.equal(projection.input.releaseShaMatches, undefined);
    assert.equal(projection.gate.npmPackageUrl, null);
    assert.equal(projection.gate.releaseTarballUrl, null);
    assert.equal(projection.gate.releaseIntegrity, null);
    assert.equal(projection.gate.releaseSha, null);
    assert.equal(projection.gate.verified, false);
    assert.match(
      projection.gate.mismatch ?? '',
      /release npm package URL is not the canonical package version URL/,
    );
  });

  it('keeps registry verification when release integrity identifies different bytes', async () => {
    const tarball = Buffer.from('registry tarball');
    const registryIntegrity = sri(tarball);
    const expectedIntegrity = sri(Buffer.from('different release artifact'));
    const calls: string[] = [];
    const fetchImpl = mockFetch((url) => {
      calls.push(url);
      if (url.endsWith(`/${VERSION}`)) return metadataResponse(registryIntegrity);
      return new Response(tarball);
    });

    const result = await verifyNpmArtifact(
      verificationInput(expectedIntegrity),
      { fetchImpl },
    );

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.equal(result.state, 'mismatch');
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /release integrity does not identify/);
    assert.equal(calls.length, 2);
  });

  it('fails when downloaded bytes do not match registry SRI', async () => {
    const integrity = sri(Buffer.from('declared tarball bytes'));
    const fetchImpl = metadataThenTarball(integrity, Buffer.from('substituted tarball bytes'));

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.registryState, 'mismatch');
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /tarball integrity mismatch/);
  });

  it('verifies each supported SRI algorithm', async () => {
    const tarball = Buffer.from('supported algorithm tarball');
    for (const algorithm of ['sha256', 'sha384', 'sha512'] as const) {
      const integrity = sri(tarball, algorithm);
      const fetchImpl = metadataThenTarball(integrity, tarball);

      const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

      assert.equal(result.state, 'release_bound', algorithm);
      assert.equal(result.verified, true, algorithm);
      assert.equal(result.mismatch, null, algorithm);
    }
  });

  it('uses the strongest supported algorithm in a multi-digest SRI declaration', async () => {
    const tarball = Buffer.from('multi-digest tarball');
    const integrity = `${sri(Buffer.from('wrong sha256 bytes'), 'sha256')} ${
      sri(tarball, 'sha512')
    }`;
    const fetchImpl = metadataThenTarball(integrity, tarball);

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.canonicalIntegrity, sri(tarball, 'sha512'));
    assert.equal(result.verified, true);
    assert.equal(result.mismatch, null);
  });

  it('rejects unsupported and malformed registry SRI declarations before downloading', async () => {
    for (const integrity of [
      sri(Buffer.from('legacy'), 'sha1'),
      'sha512-not-base64!',
      'sha512-Zm9v',
    ]) {
      const calls: string[] = [];
      const fetchImpl = mockFetch((url) => {
        calls.push(url);
        return metadataResponse(integrity);
      });

      const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

      assert.equal(result.registryState, 'mismatch', integrity);
      assert.equal(result.verified, false, integrity);
      assert.match(result.mismatch ?? '', /integrity .*unsupported|integrity .*malformed/, integrity);
      assert.equal(calls.length, 1, integrity);
    }
  });

  it('rejects conflicting registry digests before downloading', async () => {
    const integrity = `${sri(Buffer.from('first'))} ${sri(Buffer.from('second'))}`;
    const calls: string[] = [];
    const fetchImpl = mockFetch((url) => {
      calls.push(url);
      return metadataResponse(integrity);
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.registryState, 'mismatch');
    assert.match(result.mismatch ?? '', /sha512 digests conflict/);
    assert.equal(calls.length, 1);
  });

  it('keeps registry verification but rejects conflicting release digests', async () => {
    const tarball = Buffer.from('registry tarball');
    const registryIntegrity = sri(tarball);
    const releaseIntegrity = `${registryIntegrity} ${sri(Buffer.from('conflict'))}`;

    const result = await verifyNpmArtifact(
      verificationInput(releaseIntegrity),
      { fetchImpl: metadataThenTarball(registryIntegrity, tarball) },
    );

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.match(result.mismatch ?? '', /release integrity sha512 digests conflict/);
  });

  it('keeps registry verification but rejects malformed release integrity', async () => {
    const tarball = Buffer.from('registry tarball');
    const registryIntegrity = sri(tarball);

    const result = await verifyNpmArtifact(
      verificationInput('sha512-not-base64!'),
      { fetchImpl: metadataThenTarball(registryIntegrity, tarball) },
    );

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.match(result.mismatch ?? '', /release integrity malformed/);
  });

  it('rejects registry package and version mismatches before downloading', async () => {
    const integrity = sri(Buffer.from('tarball'));
    for (const metadata of [
      { name: 'other-package' },
      { version: `${VERSION}-other` },
    ]) {
      const calls: string[] = [];
      const fetchImpl = mockFetch((url) => {
        calls.push(url);
        return metadataResponse(integrity, { metadata });
      });

      const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

      assert.equal(result.registryState, 'mismatch');
      assert.match(result.mismatch ?? '', /registry package|registry version/);
      assert.equal(calls.length, 1);
    }
  });

  it('rejects non-canonical, non-HTTPS, credentialed, and foreign-host tarball URLs', async () => {
    const integrity = sri(Buffer.from('tarball'));
    for (const tarballUrl of [
      `http://registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`,
      `https://registry.npmjs.org/other/-/other-${VERSION}.tgz`,
      `https://user@registry.npmjs.org/openclaw/-/openclaw-${VERSION}.tgz`,
      `https://example.test/openclaw/-/openclaw-${VERSION}.tgz`,
      `${TARBALL_URL}?download=1`,
    ]) {
      const calls: string[] = [];
      const fetchImpl = mockFetch((url) => {
        calls.push(url);
        return metadataResponse(integrity, { dist: { tarball: tarballUrl } });
      });

      const result = await verifyNpmArtifact({
        ...verificationInput(integrity),
        expectedTarballUrl: tarballUrl,
      }, { fetchImpl });

      assert.equal(result.registryState, 'mismatch', tarballUrl);
      assert.match(
        result.mismatch ?? '',
        /tarball URL.*(?:canonical|HTTPS|host|credentials|query)/,
        tarballUrl,
      );
      assert.equal(calls.length, 1, tarballUrl);
    }
  });

  it('refuses tarball redirects instead of following them', async () => {
    const tarball = Buffer.from('redirected tarball');
    const integrity = sri(tarball);
    const calls: string[] = [];
    let cancellations = 0;
    const fetchImpl = mockFetch((url) => {
      calls.push(url);
      if (url.endsWith(`/${VERSION}`)) return metadataResponse(integrity);
      return {
        status: 302,
        headers: new Headers({ location: 'https://example.test/substituted.tgz' }),
        body: {
          cancel() {
            cancellations++;
            return Promise.resolve();
          },
        },
      } as unknown as Response;
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.registryState, 'mismatch');
    assert.match(result.mismatch ?? '', /redirect refused/);
    assert.deepEqual(calls, [
      `https://registry.npmjs.org/openclaw/${VERSION}`,
      TARBALL_URL,
    ]);
    assert.equal(cancellations, 1);
  });

  it('fails closed when the streamed tarball exceeds the compressed-byte cap', async () => {
    const tarball = Buffer.from('0123456789');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(
      integrity,
      new ReadableStream<Uint8Array>({
        start(controller) {
          controller.enqueue(tarball.subarray(0, 4));
          controller.enqueue(tarball.subarray(4));
          controller.close();
        },
      }),
    );

    const result = await verifyNpmArtifact(verificationInput(integrity), {
      fetchImpl,
      maxTarballBytes: 5,
    });

    assert.equal(result.registryState, 'mismatch');
    assert.match(result.mismatch ?? '', /compressed-byte cap/);
  });

  it('fails closed when content-length proves the tarball was truncated', async () => {
    const tarball = Buffer.from('short');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(integrity, tarball, {
      'content-length': String(tarball.length + 10),
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.registryState, 'mismatch');
    assert.match(result.mismatch ?? '', /truncated/);
  });

  it('fails before reading a tarball whose declared size exceeds the cap', async () => {
    const tarball = Buffer.from('small');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(integrity, tarball, {
      'content-length': '100',
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), {
      fetchImpl,
      maxTarballBytes: 10,
    });

    assert.equal(result.registryState, 'mismatch');
    assert.match(result.mismatch ?? '', /compressed-byte cap/);
  });

  it('does not grant positive credit when the release SHA is missing', async () => {
    const tarball = Buffer.from('registry verified without release SHA');
    const integrity = sri(tarball);

    const result = await verifyNpmArtifact({
      ...verificationInput(integrity),
      expectedReleaseSha: null,
    }, { fetchImpl: metadataThenTarball(integrity, tarball) });

    assert.equal(result.state, 'registry_verified');
    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'unknown');
    assert.equal(result.verified, false);
    assert.equal(result.mismatch, null);
    assert.match(result.reason ?? '', /release SHA missing/);
  });

  it('does not grant positive credit for SRI-only release evidence', async () => {
    const tarball = Buffer.from('SRI only');
    const integrity = sri(tarball);

    const result = await verifyNpmArtifact({
      tag: `v${VERSION}`,
      expectedNpmPackageUrl: null,
      expectedIntegrity: integrity,
      expectedTarballUrl: null,
      expectedReleaseSha: null,
      expectedCatalogReleaseSha: RELEASE_SHA,
    }, { fetchImpl: metadataThenTarball(integrity, tarball) });

    assert.equal(result.state, 'registry_verified');
    assert.equal(result.releaseBindingState, 'unknown');
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /release tarball URL missing; release SHA missing/);
  });

  it('does not grant positive credit for SHA-only release evidence', async () => {
    const tarball = Buffer.from('SHA only');
    const integrity = sri(tarball);

    const result = await verifyNpmArtifact({
      tag: `v${VERSION}`,
      expectedNpmPackageUrl: null,
      expectedIntegrity: null,
      expectedTarballUrl: null,
      expectedReleaseSha: RELEASE_SHA,
      expectedCatalogReleaseSha: RELEASE_SHA,
    }, { fetchImpl: metadataThenTarball(integrity, tarball) });

    assert.equal(result.state, 'registry_verified');
    assert.equal(result.releaseBindingState, 'unknown');
    assert.equal(result.verified, false);
    assert.match(result.reason ?? '', /release integrity missing; release tarball URL missing/);
  });

  it('does not grant positive credit when all release binding evidence is missing', async () => {
    const tarball = Buffer.from('registry only');
    const integrity = sri(tarball);

    const result = await verifyNpmArtifact({
      tag: `v${VERSION}`,
      expectedNpmPackageUrl: null,
      expectedIntegrity: null,
      expectedTarballUrl: null,
      expectedReleaseSha: null,
      expectedCatalogReleaseSha: RELEASE_SHA,
    }, { fetchImpl: metadataThenTarball(integrity, tarball) });

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBound, false);
    assert.equal(result.verified, false);
    assert.equal(result.releaseBindingIdentity, null);
  });

  it('does not let missing binding fields mask definite mismatches', () => {
    const facts = artifactVerificationFacts();
    const cases: Array<{
      name: string;
      overrides: Partial<ArtifactVerificationFacts>;
      mismatch: RegExp;
    }> = [
      {
        name: 'wrong integrity with missing SHA',
        overrides: {
          expectedIntegrity: sri(Buffer.from('different release bytes')),
          expectedReleaseSha: null,
        },
        mismatch: /release integrity does not identify the registry tarball/,
      },
      {
        name: 'wrong-version tarball URL with missing integrity',
        overrides: {
          expectedIntegrity: null,
          expectedTarballUrl:
            `https://registry.npmjs.org/openclaw/-/openclaw-${VERSION}-wrong.tgz`,
        },
        mismatch: /release tarball URL is not the canonical package tarball/,
      },
      {
        name: 'wrong SHA with missing tarball URL',
        overrides: {
          expectedTarballUrl: null,
          expectedReleaseSha: OTHER_SHA,
        },
        mismatch: /release SHA does not match registry gitHead/,
      },
    ];

    for (const item of cases) {
      const result = buildArtifactVerificationEvidence({
        ...facts,
        ...item.overrides,
      });

      assert.equal(result.registryVerified, true, item.name);
      assert.equal(result.releaseBindingState, 'mismatch', item.name);
      assert.equal(result.state, 'mismatch', item.name);
      assert.equal(result.verified, false, item.name);
      assert.match(result.mismatch ?? '', item.mismatch, item.name);
    }
  });

  it('requires authoritative metadata provenance for positive release binding', () => {
    const facts = artifactVerificationFacts();
    for (const item of [
      {
        name: 'missing metadata URL',
        overrides: { metadataUrl: null },
        reason: /registry metadata URL missing/,
      },
      {
        name: 'missing metadata content digest',
        overrides: { metadataContentDigest: null },
        reason: /registry metadata content digest missing/,
      },
    ]) {
      const result = buildArtifactVerificationEvidence({
        ...facts,
        ...item.overrides,
      });

      assert.equal(result.registryState, 'unknown', item.name);
      assert.equal(result.releaseBindingState, 'unknown', item.name);
      assert.equal(result.state, 'unknown', item.name);
      assert.equal(result.registryIdentity, null, item.name);
      assert.equal(result.releaseBindingIdentity, null, item.name);
      assert.equal(result.registryVerified, false, item.name);
      assert.equal(result.releaseBound, false, item.name);
      assert.equal(result.verified, false, item.name);
      assert.equal(result.mismatch, null, item.name);
      assert.match(result.reason ?? '', item.reason, item.name);
    }
  });

  it('rejects a release SHA that conflicts with npm gitHead', async () => {
    const tarball = Buffer.from('SHA mismatch');
    const integrity = sri(tarball);

    const result = await verifyNpmArtifact({
      ...verificationInput(integrity),
      expectedReleaseSha: OTHER_SHA,
    }, { fetchImpl: metadataThenTarball(integrity, tarball) });

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /release SHA does not match registry gitHead/);
  });

  it('rejects a parsed release SHA that conflicts with the catalog tag OID', async () => {
    const tarball = Buffer.from('catalog SHA mismatch');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(integrity, tarball, {}, {
      metadata: { gitHead: OTHER_SHA },
    });

    const result = await verifyNpmArtifact({
      ...verificationInput(integrity),
      expectedReleaseSha: OTHER_SHA,
      expectedCatalogReleaseSha: RELEASE_SHA,
    }, { fetchImpl });

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'mismatch');
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /release SHA does not match catalog tag OID/);
  });

  it('leaves release binding unknown when npm gitHead is missing', async () => {
    const tarball = Buffer.from('missing registry gitHead');
    const integrity = sri(tarball);
    const fetchImpl = metadataThenTarball(integrity, tarball, {}, {
      metadata: { gitHead: undefined },
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), { fetchImpl });

    assert.equal(result.registryVerified, true);
    assert.equal(result.releaseBindingState, 'unknown');
    assert.equal(result.verified, false);
    assert.equal(result.mismatch, null);
    assert.match(result.reason ?? '', /registry gitHead missing/);
  });

  it('retries transient metadata and tarball failures deterministically', async () => {
    const tarball = Buffer.from('retry success');
    const integrity = sri(tarball);
    let metadataAttempts = 0;
    let tarballAttempts = 0;
    const fetchImpl = mockFetch((url) => {
      if (url.endsWith(`/${VERSION}`)) {
        metadataAttempts++;
        if (metadataAttempts === 1) return new Response('retry', { status: 503 });
        return metadataResponse(integrity);
      }
      tarballAttempts++;
      if (tarballAttempts === 1) throw new TypeError('temporary network failure');
      return new Response(tarball);
    });

    const result = await verifyNpmArtifact(verificationInput(integrity), {
      fetchImpl,
      maxAttempts: 2,
      retryBaseMs: 0,
    });

    assert.equal(result.verified, true);
    assert.equal(metadataAttempts, 2);
    assert.equal(tarballAttempts, 2);
  });

  it('reports exhausted retries as unavailable evidence', async () => {
    let attempts = 0;
    const fetchImpl = mockFetch(() => {
      attempts++;
      throw new TypeError('offline');
    });

    await assert.rejects(
      verifyNpmArtifact(verificationInput(sri(Buffer.from('never fetched'))), {
        fetchImpl,
        maxAttempts: 3,
        retryBaseMs: 0,
      }),
      (error: unknown) => {
        assert.ok(error instanceof NpmArtifactVerificationError);
        assert.equal(error.evidence.state, 'unavailable');
        assert.equal(error.evidence.registryState, 'unavailable');
        assert.equal(error.evidence.releaseBindingState, 'unavailable');
        assert.equal(error.evidence.verified, false);
        assert.equal(error.evidence.mismatch, null);
        assert.match(error.message, /failed after 3 attempt/);
        return true;
      },
    );
    assert.equal(attempts, 3);
  });

  it('aborts a stalled tarball request at the verification deadline', async () => {
    const integrity = sri(Buffer.from('never returned'));
    const fetchImpl = mockFetch((url, init) => {
      if (url.endsWith(`/${VERSION}`)) return metadataResponse(integrity);
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'));
        }, { once: true });
      });
    });

    await assert.rejects(
      verifyNpmArtifact(verificationInput(integrity), {
        fetchImpl,
        maxAttempts: 1,
        timeoutMs: 10,
      }),
      (error: unknown) => {
        assert.ok(error instanceof NpmArtifactVerificationError);
        assert.match(error.message, /timed out after 10ms/);
        assert.equal(error.evidence.state, 'unavailable');
        assert.equal(error.evidence.mismatch, null);
        return true;
      },
    );
  });

  it('times out when fetch ignores abort and cancels its late response', async () => {
    let resolveFetch!: (response: Response) => void;
    let fetchSignal: AbortSignal | null = null;
    let lateCancelReason: unknown;
    const verification = verifyNpmArtifact(
      verificationInput(sri(Buffer.from('ignored timeout'))),
      {
        fetchImpl: ((_input, init) => {
          fetchSignal = init?.signal as AbortSignal;
          return new Promise<Response>((resolve) => {
            resolveFetch = resolve;
          });
        }) as typeof fetch,
        maxAttempts: 1,
        timeoutMs: 10,
      },
    );

    await assert.rejects(verification, (error: unknown) => {
      assert.ok(error instanceof NpmArtifactVerificationError);
      assert.match(error.message, /timed out after 10ms/);
      return true;
    });
    assert.equal(fetchSignal?.aborted, true);
    assert.equal(fetchSignal?.reason?.name, 'TimeoutError');

    resolveFetch({
      body: {
        cancel(reason?: unknown) {
          lateCancelReason = reason;
          return Promise.resolve();
        },
      },
    } as unknown as Response);
    for (let attempt = 0; lateCancelReason === undefined && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.ok(lateCancelReason instanceof Error);
    assert.equal(lateCancelReason.name, 'TimeoutError');
  });

  it('honors caller cancellation without retrying', async () => {
    const controller = new AbortController();
    let attempts = 0;
    const fetchImpl = mockFetch((_url, init) => {
      attempts++;
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => {
          reject(new DOMException('aborted', 'AbortError'));
        }, { once: true });
      });
    });
    const verification = verifyNpmArtifact(
      verificationInput(sri(Buffer.from('cancelled'))),
      {
        fetchImpl,
        maxAttempts: 3,
        retryBaseMs: 0,
        signal: controller.signal,
      },
    );
    await new Promise<void>((resolve) => setImmediate(resolve));
    controller.abort(new DOMException('caller cancelled', 'AbortError'));

    await assert.rejects(verification, (error: unknown) => {
      assert.ok(error instanceof NpmArtifactVerificationError);
      assert.equal(error.message, 'npm artifact verification cancelled');
      assert.equal(error.evidence.state, 'unavailable');
      assert.equal(error.evidence.verified, false);
      return true;
    });
    assert.equal(attempts, 1);
  });

  it('preserves caller cancellation when fetch ignores abort and cancels its late response', async () => {
    const caller = new AbortController();
    const abortReason = new DOMException('caller won abort race', 'AbortError');
    let resolveFetch!: (response: Response) => void;
    let fetchSignal: AbortSignal | null = null;
    let lateCancelReason: unknown;
    const verification = verifyNpmArtifact(
      verificationInput(sri(Buffer.from('ignored caller cancellation'))),
      {
        fetchImpl: ((_input, init) => {
          fetchSignal = init?.signal as AbortSignal;
          return new Promise<Response>((resolve) => {
            resolveFetch = resolve;
          });
        }) as typeof fetch,
        maxAttempts: 3,
        timeoutMs: 5_000,
        signal: caller.signal,
      },
    );

    for (let attempt = 0; fetchSignal === null && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.ok(fetchSignal);
    caller.abort(abortReason);
    await assert.rejects(verification, (error: unknown) => {
      assert.ok(error instanceof NpmArtifactVerificationError);
      assert.equal(error.message, 'npm artifact verification cancelled');
      return true;
    });
    assert.equal(fetchSignal.aborted, true);
    assert.equal(fetchSignal.reason, abortReason);

    resolveFetch({
      body: {
        cancel(reason?: unknown) {
          lateCancelReason = reason;
          return Promise.resolve();
        },
      },
    } as unknown as Response);
    for (let attempt = 0; lateCancelReason === undefined && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(lateCancelReason, abortReason);
  });

  it('does not wait for a stalled stream cancellation after caller abort', async () => {
    const caller = new AbortController();
    let readStarted = false;
    let cancelCalls = 0;
    let releaseLockCalls = 0;
    const response = {
      ok: true,
      status: 200,
      headers: new Headers(),
      body: {
        getReader() {
          return {
            read() {
              readStarted = true;
              return new Promise<never>(() => undefined);
            },
            cancel() {
              cancelCalls++;
              return new Promise<void>(() => undefined);
            },
            releaseLock() {
              releaseLockCalls++;
            },
          };
        },
      },
    } as unknown as Response;
    const verification = verifyNpmArtifact(
      verificationInput(sri(Buffer.from('stalled body cancellation'))),
      {
        fetchImpl: mockFetch(() => response),
        maxAttempts: 1,
        timeoutMs: 5_000,
        signal: caller.signal,
      },
    );

    for (let attempt = 0; !readStarted && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.equal(readStarted, true);
    caller.abort(new DOMException('caller cancelled stalled body', 'AbortError'));
    await Promise.race([
      assert.rejects(verification, (error: unknown) => {
        assert.ok(error instanceof NpmArtifactVerificationError);
        assert.equal(error.message, 'npm artifact verification cancelled');
        return true;
      }),
      new Promise<never>((_resolve, reject) => {
        setTimeout(() => reject(new Error('stalled stream cancellation blocked npm abort')), 100);
      }),
    ]);
    assert.equal(cancelCalls, 1);
    assert.equal(releaseLockCalls, 1);
  });

  it('cancels during retry backoff without starting another request', async () => {
    const controller = new AbortController();
    let attempts = 0;
    let markSleepStarted!: () => void;
    const sleepStarted = new Promise<void>((resolve) => {
      markSleepStarted = resolve;
    });
    const verification = verifyNpmArtifact(
      verificationInput(sri(Buffer.from('cancelled backoff'))),
      {
        fetchImpl: mockFetch(() => {
          attempts++;
          throw new TypeError('temporary failure');
        }),
        maxAttempts: 3,
        retryBaseMs: 1,
        signal: controller.signal,
        sleepImpl: async () => {
          markSleepStarted();
          await new Promise(() => undefined);
        },
      },
    );
    await sleepStarted;
    controller.abort(new DOMException('caller cancelled', 'AbortError'));

    await assert.rejects(verification, (error: unknown) => {
      assert.ok(error instanceof NpmArtifactVerificationError);
      assert.equal(error.message, 'npm artifact verification cancelled');
      assert.equal(error.evidence.state, 'unavailable');
      return true;
    });
    assert.equal(attempts, 1);
  });

  it('returns unavailable rather than mismatch when the version does not exist', async () => {
    const result = await verifyNpmArtifact(
      verificationInput(sri(Buffer.from('missing'))),
      { fetchImpl: mockFetch(() => new Response(null, { status: 404 })) },
    );

    assert.equal(result.state, 'unavailable');
    assert.equal(result.registryState, 'unavailable');
    assert.equal(result.releaseBindingState, 'unavailable');
    assert.equal(result.verified, false);
    assert.equal(result.mismatch, null);
    assert.match(result.reason ?? '', /npm version .* not found/);
  });

  it('produces deterministic canonical fields and source-bound identities', async () => {
    const tarball = Buffer.from('deterministic artifact');
    const sha256 = sri(tarball, 'sha256');
    const sha512 = sri(tarball, 'sha512');
    const firstIntegrity = `${sha256} ${sha512}`;
    const secondIntegrity = `${sha512} ${sha256}`;

    const first = await verifyNpmArtifact(
      verificationInput(firstIntegrity),
      { fetchImpl: metadataThenTarball(firstIntegrity, tarball) },
    );
    const repeated = await verifyNpmArtifact(
      verificationInput(firstIntegrity),
      { fetchImpl: metadataThenTarball(firstIntegrity, tarball) },
    );
    const reordered = await verifyNpmArtifact(
      {
        ...verificationInput(secondIntegrity),
        expectedReleaseSha: RELEASE_SHA.toUpperCase(),
      },
      {
        fetchImpl: metadataThenTarball(secondIntegrity, tarball, {}, {
          metadata: { gitHead: RELEASE_SHA.toUpperCase() },
        }),
      },
    );

    assert.deepEqual(repeated, first);
    assert.equal(first.canonicalIntegrity, sha512);
    assert.equal(reordered.canonicalIntegrity, sha512);
    assert.equal(reordered.canonicalGitHead, RELEASE_SHA);
    assert.notEqual(reordered.metadataContentDigest, first.metadataContentDigest);
    assert.notEqual(reordered.registryIdentity, first.registryIdentity);
    assert.notEqual(reordered.releaseBindingIdentity, first.releaseBindingIdentity);
    assert.equal(reordered.verified, true);
  });
});

function verificationInput(
  integrity: string,
  overrides: Partial<NpmArtifactVerificationInput> = {},
): NpmArtifactVerificationInput {
  return {
    tag: `v${VERSION}`,
    expectedNpmPackageUrl: NPM_PACKAGE_URL,
    expectedIntegrity: integrity,
    expectedTarballUrl: TARBALL_URL,
    expectedReleaseSha: RELEASE_SHA,
    expectedCatalogReleaseSha: RELEASE_SHA,
    ...overrides,
  };
}

function artifactVerificationFacts(): ArtifactVerificationFacts {
  const tarball = Buffer.from('artifact verification facts');
  const digest = createHash('sha512').update(tarball).digest('base64');
  const integrity = `sha512-${digest}`;
  return {
    packageName: PACKAGE_NAME,
    requestedVersion: VERSION,
    metadataUrl: `https://registry.npmjs.org/${PACKAGE_NAME}/${VERSION}`,
    metadataContentDigest: createHash('sha256')
      .update('authoritative metadata')
      .digest('hex'),
    registryAvailability: 'available',
    registryPackageName: PACKAGE_NAME,
    registryVersion: VERSION,
    registryIntegrity: integrity,
    registryTarballUrl: TARBALL_URL,
    registryGitHead: RELEASE_SHA,
    actualDigests: { sha512: digest },
    tarballByteCount: tarball.length,
    expectedIntegrity: integrity,
    expectedTarballUrl: TARBALL_URL,
    expectedReleaseSha: RELEASE_SHA,
  };
}

function metadataResponse(
  integrity: string,
  overrides: {
    metadata?: Partial<{
      name: string | undefined;
      version: string | undefined;
      gitHead: string | undefined;
    }>;
    dist?: Partial<{
      integrity: string | undefined;
      tarball: string | undefined;
    }>;
  } = {},
): Response {
  return Response.json({
    name: PACKAGE_NAME,
    version: VERSION,
    gitHead: RELEASE_SHA,
    ...overrides.metadata,
    dist: {
      integrity,
      tarball: TARBALL_URL,
      ...overrides.dist,
    },
  });
}

function metadataThenTarball(
  integrity: string,
  body: string | Uint8Array | ReadableStream<Uint8Array> | null,
  headers: Record<string, string> = {},
  metadataOverrides: Parameters<typeof metadataResponse>[1] = {},
): typeof fetch {
  return mockFetch((url) => {
    if (url.endsWith(`/${VERSION}`)) return metadataResponse(integrity, metadataOverrides);
    if (url === TARBALL_URL) return new Response(body, { headers });
    throw new Error(`unexpected fetch ${url}`);
  });
}

function mockFetch(
  handler: (
    url: string,
    init?: RequestInit,
  ) => Response | Promise<Response>,
): typeof fetch {
  return (async (input, init) => handler(String(input), init)) as typeof fetch;
}

function sri(
  bytes: Uint8Array,
  algorithm: 'sha1' | 'sha256' | 'sha384' | 'sha512' = 'sha512',
): string {
  return `${algorithm}-${createHash(algorithm).update(bytes).digest('base64')}`;
}
