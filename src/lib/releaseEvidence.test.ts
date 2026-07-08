import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import { deflateRawSync } from 'node:zlib';
import { describe, it } from 'node:test';
import { config } from '../config.ts';
import { rawGitHubUrl, verifyEvidenceReportUrl } from './releaseEvidence.ts';

const TAG = 'v2026.6.10';
const VERSION = '2026.6.10';
const RELEASE_SHA = 'aa69b12d0086b631b139c1435c9621a5783e3a40';
const RUN_HEAD_SHA = '63874fa0d1194675fa6a96a7178ea187d971afa6';
const RUN_ID = '28068476120';
const REPOSITORY_ID = 1_103_012_935;
const ARTIFACT_ID = 7_838_778_217;
const REPORT_URL =
  `https://github.com/openclaw/releases/blob/main/evidence/${VERSION}/release-evidence.md`;
const REPORT_JSON_URL =
  `https://raw.githubusercontent.com/openclaw/releases/main/evidence/${VERSION}/release-evidence.json`;
const ACTION_URL = `https://github.com/openclaw/openclaw/actions/runs/${RUN_ID}`;
const ACTION_API_URL = `https://api.github.com/repos/openclaw/openclaw/actions/runs/${RUN_ID}`;
const ARTIFACTS_API_URL = `${ACTION_API_URL}/artifacts?per_page=100`;
const ARCHIVE_URL =
  `https://api.github.com/repos/openclaw/openclaw/actions/artifacts/${ARTIFACT_ID}/zip`;

interface ZipEntry {
  filename: string;
  content: string | Buffer;
  method?: 0 | 8;
  declaredUncompressedSize?: number;
}

function sha256(content: Uint8Array): string {
  return createHash('sha256').update(content).digest('hex');
}

function githubSha256(content: Uint8Array): string {
  return `sha256:${sha256(content)}`;
}

function zip(entries: ZipEntry[]): Buffer {
  const localParts: Buffer[] = [];
  const centralParts: Buffer[] = [];
  let localOffset = 0;

  for (const entry of entries) {
    const name = Buffer.from(entry.filename);
    const data = Buffer.isBuffer(entry.content) ? entry.content : Buffer.from(entry.content);
    const method = entry.method ?? 0;
    const compressed = method === 8 ? deflateRawSync(data) : data;
    const uncompressedSize = entry.declaredUncompressedSize ?? data.length;

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(0, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(0, 10);
    local.writeUInt32LE(0, 14);
    local.writeUInt32LE(compressed.length, 18);
    local.writeUInt32LE(uncompressedSize, 22);
    local.writeUInt16LE(name.length, 26);
    local.writeUInt16LE(0, 28);
    localParts.push(local, name, compressed);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(0, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(0, 12);
    central.writeUInt32LE(0, 16);
    central.writeUInt32LE(compressed.length, 20);
    central.writeUInt32LE(uncompressedSize, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt16LE(0, 30);
    central.writeUInt16LE(0, 32);
    central.writeUInt16LE(0, 34);
    central.writeUInt16LE(0, 36);
    central.writeUInt32LE(0, 38);
    central.writeUInt32LE(localOffset, 42);
    centralParts.push(central, name);

    localOffset += local.length + name.length + compressed.length;
  }

  const centralDirectory = Buffer.concat(centralParts);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  eocd.writeUInt16LE(0, 4);
  eocd.writeUInt16LE(0, 6);
  eocd.writeUInt16LE(entries.length, 8);
  eocd.writeUInt16LE(entries.length, 10);
  eocd.writeUInt32LE(centralDirectory.length, 12);
  eocd.writeUInt32LE(localOffset, 16);
  eocd.writeUInt16LE(0, 20);
  return Buffer.concat([...localParts, centralDirectory, eocd]);
}

function structuredReport(): Record<string, unknown> {
  return {
    schemaVersion: 1,
    generatedBy: {
      repository: 'openclaw/releases',
      runId: '123',
      workflow: 'OpenClaw Release Evidence',
    },
    release: {
      id: VERSION,
      ref: TAG,
      packageSpec: `openclaw@${VERSION}`,
    },
    sourceRepositories: ['openclaw/openclaw'],
    provenance: {
      releaseRef: {
        input: TAG,
        status: 'resolved',
        kind: 'tag',
        name: TAG,
        ref: `refs/tags/${TAG}`,
        resolvedSha: RELEASE_SHA,
        objectType: 'commit',
        matchingRunLabels: ['full-release-validation', 'normal-ci'],
      },
    },
    summary: {
      blockingPassed: 1,
      blockingFailed: 0,
      blockingSkipped: 0,
      blockingIncomplete: 0,
      advisoryPassed: 1,
      advisoryFailed: 0,
      advisorySkipped: 0,
      advisoryIncomplete: 0,
    },
    runs: [
      {
        label: 'full-release-validation',
        repo: 'openclaw/openclaw',
        runId: 1,
        blocking: false,
        status: 'completed',
        conclusion: 'success',
        workflowName: 'Full Release Validation',
        event: 'workflow_dispatch',
        headBranch: `release/${VERSION}`,
        headSha: RELEASE_SHA,
        path: '.github/workflows/full-release-validation.yml',
      },
      {
        label: 'normal-ci',
        repo: 'openclaw/openclaw',
        runId: 2,
        blocking: true,
        status: 'completed',
        conclusion: 'success',
        workflowName: 'CI',
        event: 'workflow_dispatch',
        headBranch: `release/${VERSION}`,
        headSha: RELEASE_SHA,
        path: '.github/workflows/ci.yml',
      },
    ],
  };
}

function actionRun(): Record<string, unknown> {
  return {
    id: Number(RUN_ID),
    name: 'Full Release Validation',
    event: 'workflow_dispatch',
    status: 'completed',
    conclusion: 'success',
    head_sha: RUN_HEAD_SHA,
    head_branch: 'main',
    path: '.github/workflows/full-release-validation.yml',
    workflow_id: 266_803_721,
    run_attempt: 1,
    url: ACTION_API_URL,
    html_url: ACTION_URL,
    repository: {
      id: REPOSITORY_ID,
      full_name: 'openclaw/openclaw',
    },
    head_repository: {
      id: REPOSITORY_ID,
      full_name: 'openclaw/openclaw',
    },
  };
}

function validationManifest(): Record<string, unknown> {
  return {
    version: 2,
    workflowName: 'Full Release Validation',
    runId: RUN_ID,
    runAttempt: '1',
    workflowRef: 'main',
    targetRef: `release/${VERSION}`,
    targetSha: RELEASE_SHA,
    releaseProfile: 'stable',
    rerunGroup: 'all',
    runReleaseSoak: 'true',
    controls: {
      stableSoakRequired: true,
      performanceBlocking: true,
    },
    childRuns: {
      normalCi: '28068669354',
      pluginPrerelease: '28068669439',
      releaseChecks: '28068671018',
      npmTelegram: '',
      productPerformance: {
        runId: '28068669707',
        conclusion: 'success',
        blocking: true,
      },
    },
  };
}

function artifact(archive: Buffer): Record<string, unknown> {
  return {
    id: ARTIFACT_ID,
    name: `full-release-validation-${RUN_ID}`,
    expired: false,
    size_in_bytes: archive.length,
    archive_download_url: ARCHIVE_URL,
    digest: githubSha256(archive),
    workflow_run: {
      id: Number(RUN_ID),
      repository_id: REPOSITORY_ID,
      head_repository_id: REPOSITORY_ID,
      head_branch: 'main',
      head_sha: RUN_HEAD_SHA,
    },
  };
}

function fallbackFixture(input: {
  run?: Record<string, unknown>;
  artifact?: Record<string, unknown>;
  artifacts?: Array<Record<string, unknown>>;
  archive?: Buffer;
  manifest?: Record<string, unknown>;
} = {}): {
  run: Record<string, unknown>;
  artifacts: Array<Record<string, unknown>>;
  archive: Buffer;
} {
  const archive = input.archive ?? zip([{
    filename: 'full-release-validation-manifest.json',
    content: JSON.stringify(input.manifest ?? validationManifest()),
  }]);
  return {
    run: input.run ?? actionRun(),
    artifacts: input.artifacts ?? [input.artifact ?? artifact(archive)],
    archive,
  };
}

async function withMockFetch<T>(
  handler: (url: string, init?: RequestInit) => Response | Promise<Response>,
  fn: () => Promise<T>,
): Promise<T> {
  const previousFetch = globalThis.fetch;
  globalThis.fetch = (async (input, init) => handler(String(input), init)) as typeof fetch;
  try {
    return await fn();
  } finally {
    globalThis.fetch = previousFetch;
  }
}

async function verifyFallbackWithFixture(
  fixture: ReturnType<typeof fallbackFixture>,
  handler?: (url: string, init?: RequestInit) => Response | Promise<Response> | undefined,
) {
  return withMockFetch(async (url, init) => {
    const override = await handler?.(url, init);
    if (override) return override;
    if (url === REPORT_JSON_URL) return new Response('not found', { status: 404 });
    if (url === ACTION_API_URL) return Response.json(fixture.run);
    if (url === ARTIFACTS_API_URL) {
      return Response.json({
        total_count: fixture.artifacts.length,
        artifacts: fixture.artifacts,
      });
    }
    if (url === ARCHIVE_URL) return new Response(fixture.archive);
    throw new Error(`unexpected fetch ${url}`);
  }, () => verifyEvidenceReportUrl(REPORT_URL, ACTION_URL, {
    expectedReleaseTag: TAG,
    expectedReleaseSha: RELEASE_SHA,
  }));
}

describe('release evidence report verification', () => {
  it('converts GitHub blob URLs to raw URLs', () => {
    assert.equal(
      rawGitHubUrl(REPORT_URL),
      `https://raw.githubusercontent.com/openclaw/releases/main/evidence/${VERSION}/release-evidence.md`,
    );
  });

  it('verifies structured release evidence and returns its immutable digest', async () => {
    const body = Buffer.from(JSON.stringify(structuredReport()));
    const calls: string[] = [];
    const result = await withMockFetch((url, init) => {
      calls.push(url);
      assert.equal(init?.redirect, 'manual');
      assert.ok(init?.signal instanceof AbortSignal);
      return new Response(body);
    }, () => verifyEvidenceReportUrl(REPORT_URL, null, {
      expectedReleaseTag: TAG,
      expectedReleaseSha: RELEASE_SHA,
    }));

    assert.equal(result.verified, true);
    assert.equal(result.mismatch, null);
    assert.equal(result.rawUrl, REPORT_JSON_URL);
    assert.equal(result.contentDigest, sha256(body));
    assert.match(result.contentDigest ?? '', /^[0-9a-f]{64}$/);
    assert.equal(result.fallbackArtifactDigest, null);
    assert.deepEqual(calls, [REPORT_JSON_URL]);
  });

  it('rejects arbitrary non-empty content instead of treating it as evidence', async () => {
    const result = await withMockFetch(
      () => new Response('# release evidence'),
      () => verifyEvidenceReportUrl(REPORT_URL, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }),
    );
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /not valid JSON/);
  });

  it('requires structured expected release tag and SHA validation', async () => {
    let fetchCalls = 0;
    const result = await withMockFetch(() => {
      fetchCalls += 1;
      return Response.json(structuredReport());
    }, () => verifyEvidenceReportUrl(REPORT_URL));
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /expected release tag/);
    assert.equal(fetchCalls, 0);
  });

  it('rejects structured evidence with a substituted release SHA', async () => {
    const report = structuredReport();
    ((report.provenance as Record<string, unknown>).releaseRef as Record<string, unknown>)
      .resolvedSha = 'bb69b12d0086b631b139c1435c9621a5783e3a40';
    const result = await withMockFetch(
      () => Response.json(report),
      () => verifyEvidenceReportUrl(REPORT_URL, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }),
    );
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /tag\/SHA does not match/);
  });

  it('rejects reports with failed or incomplete blocking evidence', async () => {
    const report = structuredReport();
    (report.summary as Record<string, unknown>).blockingFailed = 1;
    const result = await withMockFetch(
      () => Response.json(report),
      () => verifyEvidenceReportUrl(REPORT_URL, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }),
    );
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /blocking checks are not fully successful/);
  });

  it('rejects HTTP, private-address, unapproved-host, and untrusted-repository URLs', async () => {
    const urls = [
      `http://github.com/openclaw/releases/blob/main/evidence/${VERSION}/release-evidence.md`,
      `https://127.0.0.1/evidence/${VERSION}/release-evidence.json`,
      `https://example.test/evidence/${VERSION}/release-evidence.json`,
      `https://raw.githubusercontent.com/attacker/releases/main/evidence/${VERSION}/release-evidence.json`,
    ];
    let fetchCalls = 0;
    for (const url of urls) {
      const result = await withMockFetch(() => {
        fetchCalls += 1;
        return Response.json(structuredReport());
      }, () => verifyEvidenceReportUrl(url, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }));
      assert.equal(result.verified, false, url);
    }
    assert.equal(fetchCalls, 0);
  });

  it('enforces the primary response body budget before parsing', async () => {
    const result = await withMockFetch(
      () => new Response('{}', { headers: { 'content-length': '1048577' } }),
      () => verifyEvidenceReportUrl(REPORT_URL, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }),
    );
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /exceeds 1048576 bytes/);
  });

  it('enforces the body budget when Content-Length is absent', async () => {
    const body = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(700_000));
        controller.enqueue(new Uint8Array(400_000));
        controller.close();
      },
    });
    const result = await withMockFetch(
      () => new Response(body),
      () => verifyEvidenceReportUrl(REPORT_URL, null, {
        expectedReleaseTag: TAG,
        expectedReleaseSha: RELEASE_SHA,
      }),
    );
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /exceeds 1048576 bytes/);
  });

  it('cancels a stalled primary response body when the caller aborts', async () => {
    const caller = new AbortController();
    const abortReason = new Error('release evidence cancelled by caller');
    let markReadStarted!: () => void;
    const readStarted = new Promise<void>((resolve) => {
      markReadStarted = resolve;
    });
    let cancelReason: unknown;
    const reader = {
      read() {
        markReadStarted();
        return new Promise<never>(() => undefined);
      },
      cancel(reason?: unknown) {
        cancelReason = reason;
        return Promise.resolve();
      },
      releaseLock() {
        // The test reader has no external lock state.
      },
    };

    await withMockFetch(
      () => ({
        ok: true,
        status: 200,
        headers: new Headers(),
        body: {
          getReader() {
            return reader;
          },
        },
      }) as unknown as Response,
      async () => {
        const pending = verifyEvidenceReportUrl(REPORT_URL, null, {
          expectedReleaseTag: TAG,
          expectedReleaseSha: RELEASE_SHA,
          signal: caller.signal,
        });
        await readStarted;
        caller.abort(abortReason);
        await assert.rejects(pending, (error: unknown) => {
          assert.ok(error instanceof Error);
          assert.equal(error.name, 'AbortError');
          assert.equal(error.cause, abortReason);
          return true;
        });
      },
    );

    for (let attempt = 0; cancelReason === undefined && attempt < 10; attempt++) {
      await new Promise<void>((resolve) => setImmediate(resolve));
    }
    assert.ok(cancelReason instanceof Error);
    assert.equal(cancelReason.name, 'AbortError');
    assert.equal(cancelReason.cause, abortReason);
  });

  it('keeps the request timeout active through stalled body consumption', async () => {
    let readStarted = false;
    let cancelReason: unknown;
    const reader = {
      read() {
        readStarted = true;
        return new Promise<never>(() => undefined);
      },
      cancel(reason?: unknown) {
        cancelReason = reason;
        return Promise.resolve();
      },
      releaseLock() {
        // The test reader has no external lock state.
      },
    };

    await withMockFetch(
      () => ({
        ok: true,
        status: 200,
        headers: new Headers(),
        body: {
          getReader() {
            return reader;
          },
        },
      }) as unknown as Response,
      async () => {
        await assert.rejects(
          verifyEvidenceReportUrl(REPORT_URL, null, {
            expectedReleaseTag: TAG,
            expectedReleaseSha: RELEASE_SHA,
            requestTimeoutMs: 10,
          }),
          (error: unknown) => {
            assert.ok(error instanceof Error);
            assert.equal(error.name, 'AbortError');
            assert.ok(error.cause instanceof Error);
            assert.equal(error.cause.name, 'TimeoutError');
            return true;
          },
        );
      },
    );

    assert.equal(readStarted, true);
    assert.ok(cancelReason instanceof Error);
    assert.equal(cancelReason.name, 'AbortError');
    assert.ok(cancelReason.cause instanceof Error);
    assert.equal(cancelReason.cause.name, 'TimeoutError');
  });

  it('uses a fully bound GitHub Actions artifact as fallback evidence', async () => {
    const fixture = fallbackFixture();
    const manifestBody = Buffer.from(JSON.stringify(validationManifest()));
    const calls: string[] = [];
    const result = await verifyFallbackWithFixture(fixture, (url) => {
      calls.push(url);
      return undefined;
    });
    assert.equal(result.verified, true);
    assert.equal(result.mismatch, null);
    assert.equal(result.fallbackKind, 'github_actions_run');
    assert.equal(result.fallbackArtifactCount, 1);
    assert.equal(result.contentDigest, sha256(manifestBody));
    assert.equal(result.fallbackArtifactDigest, sha256(fixture.archive));
    assert.match(result.contentDigest ?? '', /^[0-9a-f]{64}$/);
    assert.match(result.fallbackArtifactDigest ?? '', /^[0-9a-f]{64}$/);
    assert.deepEqual(calls, [
      REPORT_JSON_URL,
      ACTION_API_URL,
      ARTIFACTS_API_URL,
      ARCHIVE_URL,
    ]);
  });

  it('binds the fallback URL and API payload to the configured repository', async () => {
    let fetchCalls = 0;
    const badUrlResult = await withMockFetch(() => {
      fetchCalls += 1;
      return Response.json({});
    }, () => verifyEvidenceReportUrl(null, 'https://github.com/attacker/openclaw/actions/runs/1', {
      expectedReleaseTag: TAG,
      expectedReleaseSha: RELEASE_SHA,
    }));
    assert.equal(badUrlResult.verified, false);
    assert.match(badUrlResult.mismatch ?? '', /must identify openclaw\/openclaw/);
    assert.equal(fetchCalls, 0);

    const run = actionRun();
    (run.repository as Record<string, unknown>).full_name = 'attacker/openclaw';
    const payloadResult = await verifyFallbackWithFixture(fallbackFixture({ run }));
    assert.equal(payloadResult.verified, false);
    assert.match(payloadResult.mismatch ?? '', /not bound to openclaw\/openclaw/);
  });

  it('rejects substituted workflow, event, run head SHA, and API identities', async () => {
    const mutations: Array<[string, (run: Record<string, unknown>) => void]> = [
      ['workflow/event', (run) => { run.event = 'push'; }],
      ['head SHA', (run) => { run.head_sha = 'not-a-sha'; }],
      ['API/HTML', (run) => { run.html_url = 'https://github.com/openclaw/openclaw/actions/runs/2'; }],
    ];
    for (const [label, mutate] of mutations) {
      const run = actionRun();
      mutate(run);
      const result = await verifyFallbackWithFixture(fallbackFixture({ run }));
      assert.equal(result.verified, false, label);
      assert.match(result.mismatch ?? '', /identity|head SHA/, label);
    }
  });

  it('requires the exact artifact name, download URL, and workflow-run binding', async () => {
    const baseFixture = fallbackFixture();
    const mutations: Array<[string, (artifactValue: Record<string, unknown>) => void]> = [
      ['name', (value) => { value.name = 'unrelated-json'; }],
      ['URL', (value) => { value.archive_download_url = 'https://api.github.com/artifact.zip'; }],
      ['run head', (value) => {
        (value.workflow_run as Record<string, unknown>).head_sha = RELEASE_SHA;
      }],
    ];
    for (const [label, mutate] of mutations) {
      const artifactValue = artifact(baseFixture.archive);
      mutate(artifactValue);
      const result = await verifyFallbackWithFixture(fallbackFixture({
        archive: baseFixture.archive,
        artifact: artifactValue,
      }));
      assert.equal(result.verified, false, label);
      assert.match(result.mismatch ?? '', /artifact.*(identity|URL|workflow run)/i, label);
    }
  });

  it('verifies the GitHub artifact digest before opening the ZIP', async () => {
    const fixture = fallbackFixture();
    const tamperedArtifact = artifact(fixture.archive);
    tamperedArtifact.digest = `sha256:${'0'.repeat(64)}`;
    const result = await verifyFallbackWithFixture(fallbackFixture({
      archive: fixture.archive,
      artifact: tamperedArtifact,
    }));
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /artifact digest mismatch/);
  });

  it('rejects fallback manifests for a different release tag or SHA', async () => {
    const wrongSha = validationManifest();
    wrongSha.targetSha = 'bb69b12d0086b631b139c1435c9621a5783e3a40';
    const shaResult = await verifyFallbackWithFixture(fallbackFixture({ manifest: wrongSha }));
    assert.equal(shaResult.verified, false);
    assert.match(shaResult.mismatch ?? '', /targetSha/);

    const wrongRef = validationManifest();
    wrongRef.targetRef = 'release/2026.6.9';
    const refResult = await verifyFallbackWithFixture(fallbackFixture({ manifest: wrongRef }));
    assert.equal(refResult.verified, false);
    assert.match(refResult.mismatch ?? '', /targetRef/);
  });

  it('rejects a manifest whose run attempt or workflow ref does not match the run', async () => {
    const manifest = validationManifest();
    manifest.runAttempt = '2';
    const result = await verifyFallbackWithFixture(fallbackFixture({ manifest }));
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /workflow identity/);
  });

  it('rejects ZIPs containing extra entries or arbitrary JSON filenames', async () => {
    const extraEntryArchive = zip([
      {
        filename: 'full-release-validation-manifest.json',
        content: JSON.stringify(validationManifest()),
      },
      {
        filename: 'attacker.json',
        content: JSON.stringify(validationManifest()),
      },
    ]);
    const extraResult = await verifyFallbackWithFixture(fallbackFixture({
      archive: extraEntryArchive,
      artifact: artifact(extraEntryArchive),
    }));
    assert.equal(extraResult.verified, false);
    assert.match(extraResult.mismatch ?? '', /exactly one ZIP entry/);

    const wrongNameArchive = zip([{
      filename: 'attacker.json',
      content: JSON.stringify(validationManifest()),
    }]);
    const wrongNameResult = await verifyFallbackWithFixture(fallbackFixture({
      archive: wrongNameArchive,
      artifact: artifact(wrongNameArchive),
    }));
    assert.equal(wrongNameResult.verified, false);
    assert.match(wrongNameResult.mismatch ?? '', /manifest identity not found/);
  });

  it('rejects compressed ZIP entries that exceed decompression budgets', async () => {
    const bombArchive = zip([{
      filename: 'full-release-validation-manifest.json',
      content: Buffer.alloc(600_000, 0x61),
      method: 8,
    }]);
    const result = await verifyFallbackWithFixture(fallbackFixture({
      archive: bombArchive,
      artifact: artifact(bombArchive),
    }));
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /ZIP entry budget exceeded/);
  });

  it('rejects oversized artifact metadata before downloading the archive', async () => {
    const fixture = fallbackFixture();
    const oversized = artifact(fixture.archive);
    oversized.size_in_bytes = 16_777_217;
    let archiveFetches = 0;
    const result = await verifyFallbackWithFixture(fallbackFixture({
      archive: fixture.archive,
      artifact: oversized,
    }), (url) => {
      if (url === ARCHIVE_URL) archiveFetches += 1;
      return undefined;
    });
    assert.equal(result.verified, false);
    assert.match(result.mismatch ?? '', /artifact exceeds 16777216 bytes/);
    assert.equal(archiveFetches, 0);
  });

  it('rejects private and unapproved artifact redirect destinations without fetching them', async () => {
    for (const location of [
      'https://127.0.0.1/internal',
      'https://attacker.example/artifact.zip',
    ]) {
      const fixture = fallbackFixture();
      let redirectedFetches = 0;
      const result = await verifyFallbackWithFixture(fixture, (url) => {
        if (url === ARCHIVE_URL) {
          return new Response(null, { status: 302, headers: { location } });
        }
        if (url === location) redirectedFetches += 1;
        return undefined;
      });
      assert.equal(result.verified, false, location);
      assert.match(result.mismatch ?? '', /not approved|private or local/, location);
      assert.equal(redirectedFetches, 0, location);
    }
  });

  it('limits artifact redirect chains and strips authorization across origins', async () => {
    const mutableConfig = config.github as unknown as { token: string };
    const previousToken = mutableConfig.token;
    mutableConfig.token = 'test-token';
    const fixture = fallbackFixture();
    const firstRedirect = 'https://productionresultssa0.blob.core.windows.net/container/one';
    const secondRedirect = 'https://objects.githubusercontent.com/container/two';
    const thirdRedirect = 'https://productionresultssa1.blob.core.windows.net/container/three';
    try {
      const result = await verifyFallbackWithFixture(fixture, (url, init) => {
        if (url === ARCHIVE_URL) {
          const headers = new Headers(init?.headers);
          assert.equal(headers.get('authorization'), 'Bearer test-token');
          return new Response(null, { status: 302, headers: { location: firstRedirect } });
        }
        if (url === firstRedirect) {
          const headers = new Headers(init?.headers);
          assert.equal(headers.get('authorization'), null);
          return new Response(null, { status: 302, headers: { location: secondRedirect } });
        }
        if (url === secondRedirect) {
          return new Response(null, { status: 302, headers: { location: thirdRedirect } });
        }
        if (url === thirdRedirect) {
          throw new Error(`redirect budget allowed unexpected fetch ${url}`);
        }
        return undefined;
      });
      assert.equal(result.verified, false);
      assert.match(result.mismatch ?? '', /redirect budget exceeded \(2\)/);
    } finally {
      mutableConfig.token = previousToken;
    }
  });
});
