import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { npmVersionFromTag, verifyNpmArtifact } from './npmRegistry.ts';

describe('npm artifact verification', () => {
  it('converts release tags to npm versions', () => {
    assert.equal(npmVersionFromTag('v2026.6.10'), '2026.6.10');
    assert.equal(npmVersionFromTag('2026.6.10'), '2026.6.10');
  });

  it('verifies registry integrity and tarball metadata', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({
      version: '2026.6.10',
      dist: {
        integrity: 'sha512-good',
        tarball: 'https://registry.npmjs.org/openclaw/-/openclaw-2026.6.10.tgz',
      },
    }))) as typeof fetch;
    try {
      const result = await verifyNpmArtifact({
        tag: 'v2026.6.10',
        expectedIntegrity: 'sha512-good',
        expectedTarballUrl: 'https://registry.npmjs.org/openclaw/-/openclaw-2026.6.10.tgz',
      });
      assert.equal(result.verified, true);
      assert.equal(result.mismatch, null);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  it('reports mismatches without marking the artifact verified', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response(JSON.stringify({
      version: '2026.6.10',
      dist: {
        integrity: 'sha512-bad',
        tarball: 'https://registry.npmjs.org/openclaw/-/openclaw-2026.6.10.tgz',
      },
    }))) as typeof fetch;
    try {
      const result = await verifyNpmArtifact({
        tag: 'v2026.6.10',
        expectedIntegrity: 'sha512-good',
        expectedTarballUrl: 'https://registry.npmjs.org/openclaw/-/openclaw-2026.6.10.tgz',
      });
      assert.equal(result.verified, false);
      assert.match(result.mismatch ?? '', /integrity/);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
