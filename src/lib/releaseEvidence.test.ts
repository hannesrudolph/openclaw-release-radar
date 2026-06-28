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
      assert.equal(result.fallbackUrl, null);
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

  it('uses successful GitHub Actions run artifacts as fallback evidence', async () => {
    const previousFetch = globalThis.fetch;
    const calls: string[] = [];
    globalThis.fetch = (async (input) => {
      const url = String(input);
      calls.push(url);
      if (url === 'https://raw.githubusercontent.com/openclaw/releases/main/evidence/2026.6.10/release-evidence.md') {
        return new Response('not found', { status: 404 });
      }
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/28068476120') {
        return Response.json({ status: 'completed', conclusion: 'success' });
      }
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/28068476120/artifacts') {
        return Response.json({ artifacts: [{ expired: false, size_in_bytes: 534 }] });
      }
      throw new Error(`unexpected fetch ${url}`);
    }) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl(
        'https://github.com/openclaw/releases/blob/main/evidence/2026.6.10/release-evidence.md',
        'https://github.com/openclaw/openclaw/actions/runs/28068476120',
      );
      assert.equal(result.verified, true);
      assert.equal(result.mismatch, null);
      assert.equal(result.fallbackKind, 'github_actions_run');
      assert.equal(result.fallbackArtifactCount, 1);
      assert.equal(calls.length, 3);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });

  it('does not verify fallback actions without artifacts', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async (input) => {
      const url = String(input);
      if (url === 'https://example.test/missing.md') return new Response('not found', { status: 404 });
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/1') {
        return Response.json({ status: 'completed', conclusion: 'success' });
      }
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/1/artifacts') {
        return Response.json({ artifacts: [] });
      }
      throw new Error(`unexpected fetch ${url}`);
    }) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl(
        'https://example.test/missing.md',
        'https://github.com/openclaw/openclaw/actions/runs/1',
      );
      assert.equal(result.verified, false);
      assert.match(result.mismatch ?? '', /artifact not found/);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
