import { createHash } from 'node:crypto';
import {
  type ArtifactVerificationEvidence,
  type SupportedSriAlgorithm,
  SUPPORTED_SRI_ALGORITHMS,
  buildArtifactVerificationEvidence,
  canonicalizeGitSha,
  canonicalizeNpmPackageVersionUrl,
  canonicalizeNpmTarballUrl,
  canonicalizeSri,
} from './artifactVerification';

const NPM_REGISTRY_ORIGIN = 'https://registry.npmjs.org';
const NPM_PACKAGE_NAME = 'openclaw';
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_MAX_TARBALL_BYTES = 64 * 1024 * 1024;
const DEFAULT_MAX_ATTEMPTS = 3;
const DEFAULT_RETRY_BASE_MS = 100;
const MAX_METADATA_BYTES = 1024 * 1024;
const MAX_ERROR_BODY_BYTES = 64 * 1024;
const REDIRECT_STATUS_CODES = new Set([301, 302, 303, 307, 308]);

export type NpmArtifactEvidence = ArtifactVerificationEvidence;

export interface NpmArtifactVerificationInput {
  tag: string;
  expectedNpmPackageUrl: string | null;
  expectedIntegrity: string | null;
  expectedTarballUrl: string | null;
  expectedReleaseSha?: string | null;
  expectedCatalogReleaseSha: string | null;
}

export interface NpmArtifactVerificationOptions {
  fetchImpl?: typeof fetch;
  timeoutMs?: number;
  maxTarballBytes?: number;
  maxAttempts?: number;
  retryBaseMs?: number;
  signal?: AbortSignal;
  sleepImpl?: (delayMs: number, signal: AbortSignal) => Promise<void>;
}

export class NpmArtifactVerificationError extends Error {
  readonly evidence: NpmArtifactEvidence;

  constructor(message: string, evidence: NpmArtifactEvidence, cause?: unknown) {
    super(message, cause === undefined ? undefined : { cause });
    this.name = 'NpmArtifactVerificationError';
    this.evidence = evidence;
  }
}

interface BoundedBody {
  bytes: Buffer | null;
  problem: string | null;
}

interface TarballDigests {
  digests: Partial<Record<SupportedSriAlgorithm, string>>;
  byteCount: number | null;
  problem: string | null;
}

interface RequestContext {
  fetchImpl: typeof fetch;
  maxAttempts: number;
  retryBaseMs: number;
  signal: AbortSignal;
  sleepImpl: (delayMs: number, signal: AbortSignal) => Promise<void>;
}

export function npmVersionFromTag(tag: string): string {
  return tag.replace(/^v/, '');
}

export async function verifyNpmArtifact(
  input: NpmArtifactVerificationInput,
  options: NpmArtifactVerificationOptions = {},
): Promise<NpmArtifactEvidence> {
  const version = npmVersionFromTag(input.tag);
  const timeoutMs = positiveInteger(options.timeoutMs, DEFAULT_TIMEOUT_MS, 'timeoutMs');
  const maxTarballBytes = positiveInteger(
    options.maxTarballBytes,
    DEFAULT_MAX_TARBALL_BYTES,
    'maxTarballBytes',
  );
  const maxAttempts = positiveInteger(
    options.maxAttempts,
    DEFAULT_MAX_ATTEMPTS,
    'maxAttempts',
  );
  const retryBaseMs = nonNegativeInteger(
    options.retryBaseMs,
    DEFAULT_RETRY_BASE_MS,
    'retryBaseMs',
  );
  const abort = composedAbortController(options.signal, timeoutMs);
  const context: RequestContext = {
    fetchImpl: options.fetchImpl ?? fetch,
    maxAttempts,
    retryBaseMs,
    signal: abort.controller.signal,
    sleepImpl: options.sleepImpl ?? sleepWithSignal,
  };

  try {
    throwIfAborted(context.signal);
    const metadataUrl = `${NPM_REGISTRY_ORIGIN}/${NPM_PACKAGE_NAME}/${encodeURIComponent(version)}`;
    const response = await fetchWithRetry(metadataUrl, {
      headers: {
        accept: 'application/json',
        'user-agent': 'openclaw-release-radar',
      },
      redirect: 'manual',
      signal: context.signal,
    }, 'npm registry metadata', context);

    if (REDIRECT_STATUS_CODES.has(response.status)) {
      cancelResponseBody(response, 'npm registry metadata redirect refused');
      return mismatchEvidence(
        input,
        version,
        `npm registry metadata redirect refused: ${
          response.headers.get('location') ?? 'missing location'
        }`,
      );
    }
    if (response.status === 404) {
      cancelResponseBody(response, 'npm registry metadata version not found');
      return unavailableEvidence(input, version, `npm version ${version} not found`);
    }
    if (!response.ok) {
      const message = `npm registry ${response.status}: ${
        await boundedResponseText(response, context.signal)
      }`;
      throw unavailableError(input, version, message);
    }

    const metadataBody = await readBoundedBody(
      response,
      MAX_METADATA_BYTES,
      'npm registry metadata',
      context.signal,
    );
    if (!metadataBody.bytes) {
      throw unknownError(
        input,
        version,
        metadataBody.problem ?? 'npm registry metadata body missing',
      );
    }
    const metadataContentDigest = createHash('sha256')
      .update(metadataBody.bytes)
      .digest('hex');

    let json: unknown;
    try {
      json = JSON.parse(metadataBody.bytes.toString('utf8'));
    } catch (error) {
      throw unknownError(input, version, 'npm registry metadata is not valid JSON', error);
    }
    const metadata = recordOrNull(json);
    const dist = recordOrNull(metadata?.dist);
    const registryPackageName = stringOrNull(metadata?.name);
    const registryVersion = stringOrNull(metadata?.version);
    const registryIntegrity = stringOrNull(dist?.integrity);
    const registryTarballUrl = stringOrNull(dist?.tarball);
    const registryGitHead = stringOrNull(metadata?.gitHead);
    const registrySri = canonicalizeSri(registryIntegrity, 'registry integrity');
    const registryTarball = canonicalizeNpmTarballUrl(
      registryTarballUrl,
      NPM_PACKAGE_NAME,
      version,
      'registry tarball URL',
    );
    const registryProblems: string[] = [];
    if (registryPackageName !== NPM_PACKAGE_NAME) {
      registryProblems.push(
        `registry package ${registryPackageName ?? 'missing'} != ${NPM_PACKAGE_NAME}`,
      );
    }
    if (registryVersion !== version) {
      registryProblems.push(`registry version ${registryVersion ?? 'missing'} != ${version}`);
    }
    if (registrySri.problem) registryProblems.push(registrySri.problem);
    if (registryTarball.problem) registryProblems.push(registryTarball.problem);

    if (registryProblems.length > 0 || !registrySri.value || !registryTarballUrl) {
      return buildArtifactVerificationEvidence({
        ...evidenceFacts(input, version),
        metadataUrl,
        metadataContentDigest,
        registryAvailability: 'available',
        registryPackageName,
        registryVersion,
        registryIntegrity,
        registryTarballUrl,
        registryGitHead,
        registryProblems,
      });
    }

    const algorithms = new Set<SupportedSriAlgorithm>([registrySri.value.algorithm]);
    const expectedSri = canonicalizeSri(input.expectedIntegrity, 'release integrity');
    if (expectedSri.value) algorithms.add(expectedSri.value.algorithm);
    const tarballResult = await fetchTarballDigests({
      url: registryTarballUrl,
      algorithms,
      maxBytes: maxTarballBytes,
      context,
    });

    return buildArtifactVerificationEvidence({
      ...evidenceFacts(input, version),
      metadataUrl,
      metadataContentDigest,
      registryAvailability: 'available',
      registryPackageName,
      registryVersion,
      registryIntegrity,
      registryTarballUrl,
      registryGitHead,
      registryProblems: tarballResult.problem ? [tarballResult.problem] : [],
      actualDigests: tarballResult.digests,
      tarballByteCount: tarballResult.byteCount,
    });
  } catch (error) {
    if (error instanceof NpmArtifactVerificationError) throw error;
    if (abort.timedOut()) {
      throw unavailableError(
        input,
        version,
        `npm artifact verification timed out after ${timeoutMs}ms`,
        error,
      );
    }
    if (options.signal?.aborted) {
      throw unavailableError(input, version, 'npm artifact verification cancelled', error);
    }
    throw unavailableError(
      input,
      version,
      `npm artifact verification unavailable: ${errorMessage(error)}`,
      error,
    );
  } finally {
    abort.dispose();
  }
}

async function fetchTarballDigests(input: {
  url: string;
  algorithms: ReadonlySet<SupportedSriAlgorithm>;
  maxBytes: number;
  context: RequestContext;
}): Promise<TarballDigests> {
  const response = await fetchWithRetry(input.url, {
    headers: {
      accept: 'application/octet-stream',
      'user-agent': 'openclaw-release-radar',
    },
    redirect: 'manual',
    signal: input.context.signal,
  }, 'npm tarball', input.context);
  if (REDIRECT_STATUS_CODES.has(response.status)) {
    cancelResponseBody(response, 'npm tarball redirect refused');
    return {
      digests: {},
      byteCount: null,
      problem: `npm tarball redirect refused: ${
        response.headers.get('location') ?? 'missing location'
      }`,
    };
  }
  if (response.status === 404) {
    cancelResponseBody(response, 'npm tarball not found');
    return { digests: {}, byteCount: null, problem: 'npm tarball not found' };
  }
  if (!response.ok) {
    const message = `npm tarball ${response.status}: ${
      await boundedResponseText(response, input.context.signal)
    }`;
    throw new Error(message);
  }
  const contentEncoding = response.headers.get('content-encoding');
  if (contentEncoding && contentEncoding.toLowerCase() !== 'identity') {
    cancelResponseBody(response, 'npm tarball content encoding is not byte exact');
    return {
      digests: {},
      byteCount: null,
      problem: `npm tarball content-encoding ${contentEncoding} prevents byte-exact SRI verification`,
    };
  }

  const declaredLength = contentLength(response);
  if (declaredLength.problem) {
    cancelResponseBody(response, declaredLength.problem);
    return { digests: {}, byteCount: null, problem: declaredLength.problem };
  }
  if (declaredLength.value != null && declaredLength.value > input.maxBytes) {
    cancelResponseBody(response, 'npm tarball declared size exceeds compressed-byte cap');
    return {
      digests: {},
      byteCount: null,
      problem: `npm tarball exceeds compressed-byte cap (${
        declaredLength.value
      } > ${input.maxBytes})`,
    };
  }
  if (!response.body) {
    return { digests: {}, byteCount: null, problem: 'npm tarball body missing' };
  }

  const hashes = new Map(
    [...input.algorithms].map((algorithm) => [algorithm, createHash(algorithm)] as const),
  );
  const reader = response.body.getReader();
  let bytesRead = 0;
  try {
    for (;;) {
      const chunk = await abortable(reader.read(), input.context.signal);
      if (chunk.done) break;
      if (!chunk.value) continue;
      bytesRead += chunk.value.byteLength;
      if (bytesRead > input.maxBytes) {
        void reader.cancel('npm tarball compressed-byte cap exceeded').catch(() => undefined);
        return {
          digests: {},
          byteCount: bytesRead,
          problem: `npm tarball exceeds compressed-byte cap (${bytesRead} > ${input.maxBytes})`,
        };
      }
      for (const hash of hashes.values()) hash.update(chunk.value);
    }
  } catch (error) {
    void reader.cancel(error).catch(() => undefined);
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Cancellation can leave an ignored read pending until the stream settles.
    }
  }

  if (bytesRead === 0) {
    return { digests: {}, byteCount: 0, problem: 'npm tarball body empty' };
  }
  if (declaredLength.value != null && bytesRead !== declaredLength.value) {
    return {
      digests: {},
      byteCount: bytesRead,
      problem: bytesRead < declaredLength.value
        ? `npm tarball truncated (${bytesRead} of ${declaredLength.value} bytes)`
        : `npm tarball length mismatch (${bytesRead} != ${declaredLength.value})`,
    };
  }

  const digests: Partial<Record<SupportedSriAlgorithm, string>> = {};
  for (const [algorithm, hash] of hashes) digests[algorithm] = hash.digest('base64');
  return { digests, byteCount: bytesRead, problem: null };
}

async function fetchWithRetry(
  url: string,
  init: RequestInit,
  label: string,
  context: RequestContext,
): Promise<Response> {
  let lastError: unknown = null;
  for (let attempt = 1; attempt <= context.maxAttempts; attempt++) {
    throwIfAborted(context.signal);
    try {
      const response = await fetchWithAbort(
        context.fetchImpl,
        url,
        { ...init, signal: context.signal },
        context.signal,
      );
      if (isRetryableStatus(response.status) && attempt < context.maxAttempts) {
        cancelResponseBody(response, `${label} retry`);
        await retryDelay(attempt, context);
        continue;
      }
      return response;
    } catch (error) {
      if (context.signal.aborted) throw error;
      lastError = error;
      if (attempt >= context.maxAttempts) break;
      await retryDelay(attempt, context);
    }
  }
  throw new Error(
    `${label} request failed after ${context.maxAttempts} attempt(s): ${
      errorMessage(lastError)
    }`,
  );
}

async function retryDelay(attempt: number, context: RequestContext): Promise<void> {
  const delayMs = context.retryBaseMs * 2 ** Math.max(0, attempt - 1);
  await abortable(context.sleepImpl(delayMs, context.signal), context.signal);
}

function evidenceFacts(input: NpmArtifactVerificationInput, version: string) {
  const packageUrl = canonicalizeNpmPackageVersionUrl(
    input.expectedNpmPackageUrl,
    NPM_PACKAGE_NAME,
    version,
    'release npm package URL',
  );
  const releaseSha = canonicalizeGitSha(input.expectedReleaseSha, 'release SHA');
  const catalogSha = canonicalizeGitSha(
    input.expectedCatalogReleaseSha,
    'catalog tag OID',
  );
  const releaseBindingProblems: string[] = [];
  const releaseBindingUnknowns: string[] = [];

  if (packageUrl.problem) {
    if (packageUrl.problem.endsWith('missing')) {
      releaseBindingUnknowns.push(packageUrl.problem);
    } else {
      releaseBindingProblems.push(packageUrl.problem);
    }
  }
  if (catalogSha.problem) {
    if (catalogSha.problem.endsWith('missing')) {
      releaseBindingUnknowns.push(catalogSha.problem);
    } else {
      releaseBindingProblems.push(catalogSha.problem);
    }
  } else if (
    catalogSha.value &&
    releaseSha.value &&
    catalogSha.value !== releaseSha.value
  ) {
    releaseBindingProblems.push('release SHA does not match catalog tag OID');
  }

  return {
    packageName: NPM_PACKAGE_NAME,
    requestedVersion: version,
    releaseBindingProblems,
    releaseBindingUnknowns,
    expectedIntegrity: input.expectedIntegrity,
    expectedTarballUrl: input.expectedTarballUrl,
    expectedReleaseSha: input.expectedReleaseSha ?? null,
  };
}

function mismatchEvidence(
  input: NpmArtifactVerificationInput,
  version: string,
  problem: string,
): NpmArtifactEvidence {
  return buildArtifactVerificationEvidence({
    ...evidenceFacts(input, version),
    registryAvailability: 'available',
    registryProblems: [problem],
  });
}

function unavailableEvidence(
  input: NpmArtifactVerificationInput,
  version: string,
  reason: string,
): NpmArtifactEvidence {
  return buildArtifactVerificationEvidence({
    ...evidenceFacts(input, version),
    registryAvailability: 'unavailable',
    registryAvailabilityReason: reason,
  });
}

function unavailableError(
  input: NpmArtifactVerificationInput,
  version: string,
  message: string,
  cause?: unknown,
): NpmArtifactVerificationError {
  return new NpmArtifactVerificationError(
    message,
    unavailableEvidence(input, version, message),
    cause,
  );
}

function unknownError(
  input: NpmArtifactVerificationInput,
  version: string,
  message: string,
  cause?: unknown,
): NpmArtifactVerificationError {
  return new NpmArtifactVerificationError(
    message,
    buildArtifactVerificationEvidence({
      ...evidenceFacts(input, version),
      registryAvailability: 'unknown',
      registryAvailabilityReason: message,
    }),
    cause,
  );
}

function composedAbortController(callerSignal: AbortSignal | undefined, timeoutMs: number): {
  controller: AbortController;
  timedOut: () => boolean;
  dispose: () => void;
} {
  const controller = new AbortController();
  let abortSource: 'caller' | 'timeout' | null = null;
  const abortFromCaller = () => {
    if (abortSource !== null) return;
    abortSource = 'caller';
    controller.abort(callerSignal?.reason);
  };
  if (callerSignal?.aborted) abortFromCaller();
  else callerSignal?.addEventListener('abort', abortFromCaller, { once: true });
  const timeout = setTimeout(() => {
    if (abortSource !== null) return;
    abortSource = 'timeout';
    controller.abort(new DOMException('timed out', 'TimeoutError'));
  }, timeoutMs);
  return {
    controller,
    timedOut: () => abortSource === 'timeout',
    dispose: () => {
      clearTimeout(timeout);
      callerSignal?.removeEventListener('abort', abortFromCaller);
    },
  };
}

function fetchWithAbort(
  fetchImpl: typeof fetch,
  input: string,
  init: RequestInit,
  signal: AbortSignal,
): Promise<Response> {
  if (signal.aborted) {
    return Promise.reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
  }
  return new Promise<Response>((resolve, reject) => {
    let settled = false;
    const abort = (): void => {
      if (settled) return;
      settled = true;
      signal.removeEventListener('abort', abort);
      reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
    };
    signal.addEventListener('abort', abort, { once: true });
    void fetchImpl(input, init).then(
      (response) => {
        if (settled) {
          void response.body?.cancel(signal.reason).catch(() => undefined);
          return;
        }
        settled = true;
        signal.removeEventListener('abort', abort);
        resolve(response);
      },
      (error) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw signal.reason ?? new DOMException('aborted', 'AbortError');
}

function abortable<T>(promise: Promise<T>, signal: AbortSignal): Promise<T> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise<T>((resolve, reject) => {
    const abort = () => reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
    signal.addEventListener('abort', abort, { once: true });
    promise.then(
      (value) => {
        signal.removeEventListener('abort', abort);
        resolve(value);
      },
      (error) => {
        signal.removeEventListener('abort', abort);
        reject(error);
      },
    );
  });
}

function sleepWithSignal(delayMs: number, signal: AbortSignal): Promise<void> {
  if (delayMs === 0) {
    throwIfAborted(signal);
    return Promise.resolve();
  }
  return new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(done, delayMs);
    const abort = () => {
      clearTimeout(timeout);
      signal.removeEventListener('abort', abort);
      reject(signal.reason ?? new DOMException('aborted', 'AbortError'));
    };
    function done() {
      signal.removeEventListener('abort', abort);
      resolve();
    }
    signal.addEventListener('abort', abort, { once: true });
  });
}

function contentLength(response: Response): {
  value: number | null;
  problem: string | null;
} {
  const raw = response.headers.get('content-length');
  if (raw == null) return { value: null, problem: null };
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) {
    return { value: null, problem: 'npm tarball content-length malformed' };
  }
  const value = Number(raw);
  if (!Number.isSafeInteger(value)) {
    return {
      value: null,
      problem: 'npm tarball content-length exceeds safe integer range',
    };
  }
  return { value, problem: null };
}

async function readBoundedBody(
  response: Response,
  maxBytes: number,
  label: string,
  signal: AbortSignal,
): Promise<BoundedBody> {
  if (!response.body) return { bytes: null, problem: `${label} body missing` };
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    for (;;) {
      const chunk = await abortable(reader.read(), signal);
      if (chunk.done) break;
      if (!chunk.value) continue;
      total += chunk.value.byteLength;
      if (total > maxBytes) {
        void reader.cancel(`${label} byte cap exceeded`).catch(() => undefined);
        return { bytes: null, problem: `${label} exceeds byte cap` };
      }
      chunks.push(Buffer.from(chunk.value));
    }
  } catch (error) {
    void reader.cancel(error).catch(() => undefined);
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // Cancellation can leave an ignored read pending until the stream settles.
    }
  }
  return { bytes: Buffer.concat(chunks, total), problem: null };
}

function cancelResponseBody(response: Response, reason?: unknown): void {
  void response.body?.cancel(reason).catch(() => undefined);
}

async function boundedResponseText(response: Response, signal: AbortSignal): Promise<string> {
  const body = await readBoundedBody(
    response,
    MAX_ERROR_BODY_BYTES,
    'npm error response',
    signal,
  );
  if (!body.bytes) return body.problem ?? 'response body unavailable';
  return body.bytes.toString('utf8');
}

function recordOrNull(value: unknown): Record<string, unknown> | null {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function stringOrNull(value: unknown): string | null {
  return typeof value === 'string' ? value : null;
}

function isRetryableStatus(status: number): boolean {
  return status === 408 || status === 429 || status >= 500;
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function positiveInteger(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return value;
}

function nonNegativeInteger(
  value: number | undefined,
  fallback: number,
  label: string,
): number {
  if (value === undefined) return fallback;
  if (!Number.isInteger(value) || value < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return value;
}
