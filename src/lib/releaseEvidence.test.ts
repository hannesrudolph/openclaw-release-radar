import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { rawGitHubUrl, verifyEvidenceReportUrl } from './releaseEvidence.ts';

describe('release evidence report verification', () => {
  it('converts GitHub blob URLs to raw URLs', () => {
    assert.equal(
      rawGitHubUrl('https://github.com/openclaw/releases/blob/main/evidence/2026.6.10/release-evidence.md'),
      'https://raw.githubusercontent.com/openclaw/releases/main/evidence/2026.6.10/release-evidence.md',
    );
  });

  it('marks a non-empty evidence report verified', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response('# release evidence')) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl('https://example.test/report.md');
      assert.equal(result.verified, true);
      assert.equal(result.mismatch, null);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  it('reports missing evidence without throwing', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async () => new Response('not found', { status: 404 })) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl('https://example.test/missing.md');
      assert.equal(result.verified, false);
      assert.match(result.mismatch ?? '', /not found/);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
