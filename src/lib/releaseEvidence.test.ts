import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { rawGitHubUrl, verifyEvidenceReportUrl } from './releaseEvidence.ts';

function storedZip(filename: string, content: string): Uint8Array {
  const name = Buffer.from(filename);
  const data = Buffer.from(content);
  const local = Buffer.alloc(30);
  local.writeUInt32LE(0x04034b50, 0);
  local.writeUInt16LE(20, 4);
  local.writeUInt16LE(0, 6);
  local.writeUInt16LE(0, 8);
  local.writeUInt32LE(0, 10);
  local.writeUInt32LE(0, 14);
  local.writeUInt32LE(data.length, 18);
  local.writeUInt32LE(data.length, 22);
  local.writeUInt16LE(name.length, 26);
  local.writeUInt16LE(0, 28);

  const central = Buffer.alloc(46);
  central.writeUInt32LE(0x02014b50, 0);
  central.writeUInt16LE(20, 4);
  central.writeUInt16LE(20, 6);
  central.writeUInt16LE(0, 8);
  central.writeUInt16LE(0, 10);
  central.writeUInt32LE(0, 12);
  central.writeUInt32LE(0, 16);
  central.writeUInt32LE(data.length, 20);
  central.writeUInt32LE(data.length, 24);
  central.writeUInt16LE(name.length, 28);
  central.writeUInt16LE(0, 30);
  central.writeUInt16LE(0, 32);
  central.writeUInt16LE(0, 34);
  central.writeUInt16LE(0, 36);
  central.writeUInt32LE(0, 38);
  central.writeUInt32LE(0, 42);

  const centralOffset = local.length + name.length + data.length;
  const centralSize = central.length + name.length;
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(1, 8);
  eocd.writeUInt16LE(1, 10);
  eocd.writeUInt32LE(centralSize, 12);
  eocd.writeUInt32LE(centralOffset, 16);
  eocd.writeUInt16LE(0, 20);

  return Buffer.concat([local, name, data, central, name, eocd]);
}

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
        return Response.json({
          artifacts: [{
            expired: false,
            size_in_bytes: 534,
            archive_download_url: 'https://api.github.com/artifact.zip',
          }],
        });
      }
      if (url === 'https://api.github.com/artifact.zip') {
        return new Response(storedZip(
          'full-release-validation-manifest.json',
          JSON.stringify({
            targetRef: 'release/2026.6.10',
            targetSha: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
          }),
        ));
      }
      throw new Error(`unexpected fetch ${url}`);
    }) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl(
        'https://github.com/openclaw/releases/blob/main/evidence/2026.6.10/release-evidence.md',
        'https://github.com/openclaw/openclaw/actions/runs/28068476120',
        {
          expectedReleaseTag: 'v2026.6.10',
          expectedReleaseSha: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
        },
      );
      assert.equal(result.verified, true);
      assert.equal(result.mismatch, null);
      assert.equal(result.fallbackKind, 'github_actions_run');
      assert.equal(result.fallbackArtifactCount, 1);
      assert.equal(calls.length, 4);
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

  it('does not verify fallback artifacts for the wrong release SHA', async () => {
    const previousFetch = globalThis.fetch;
    globalThis.fetch = (async (input) => {
      const url = String(input);
      if (url === 'https://example.test/missing.md') return new Response('not found', { status: 404 });
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/1') {
        return Response.json({ status: 'completed', conclusion: 'success' });
      }
      if (url === 'https://api.github.com/repos/openclaw/openclaw/actions/runs/1/artifacts') {
        return Response.json({
          artifacts: [{
            expired: false,
            size_in_bytes: 100,
            archive_download_url: 'https://api.github.com/bad-artifact.zip',
          }],
        });
      }
      if (url === 'https://api.github.com/bad-artifact.zip') {
        return new Response(storedZip(
          'full-release-validation-manifest.json',
          JSON.stringify({ targetRef: 'release/2026.6.10', targetSha: 'wrong' }),
        ));
      }
      throw new Error(`unexpected fetch ${url}`);
    }) as typeof fetch;
    try {
      const result = await verifyEvidenceReportUrl(
        'https://example.test/missing.md',
        'https://github.com/openclaw/openclaw/actions/runs/1',
        {
          expectedReleaseTag: 'v2026.6.10',
          expectedReleaseSha: 'aa69b12d0086b631b139c1435c9621a5783e3a40',
        },
      );
      assert.equal(result.verified, false);
      assert.match(result.mismatch ?? '', /targetSha wrong/);
    } finally {
      globalThis.fetch = previousFetch;
    }
  });
});
