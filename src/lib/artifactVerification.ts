import { createHash } from 'node:crypto';
import type {
  ReleaseArtifactObservation,
  ReleaseArtifactReceipt,
} from './releaseArtifactReceipt';

export const ARTIFACT_VERIFICATION_SCHEMA_VERSION = 2 as const;

export const SUPPORTED_SRI_ALGORITHMS = [
  { name: 'sha512', digestBytes: 64 },
  { name: 'sha384', digestBytes: 48 },
  { name: 'sha256', digestBytes: 32 },
] as const;

export type SupportedSriAlgorithm = (typeof SUPPORTED_SRI_ALGORITHMS)[number]['name'];

export type ArtifactEvidenceState =
  | 'registry_verified'
  | 'release_bound'
  | 'mismatch'
  | 'unavailable'
  | 'unknown';

export type RegistryArtifactEvidenceState =
  | 'registry_verified'
  | 'mismatch'
  | 'unavailable'
  | 'unknown';

export type ReleaseArtifactBindingState =
  | 'release_bound'
  | 'mismatch'
  | 'unavailable'
  | 'unknown';

export type RegistryArtifactAvailability = 'available' | 'unavailable' | 'unknown';

export interface CanonicalSri {
  algorithm: SupportedSriAlgorithm;
  digestBase64: string;
  digestHex: string;
  integrity: string;
}

export interface CanonicalValue<T> {
  value: T | null;
  problem: string | null;
}

export interface ArtifactVerificationEvidence {
  schemaVersion: typeof ARTIFACT_VERIFICATION_SCHEMA_VERSION;
  packageName: string;
  requestedVersion: string;
  metadataUrl: string | null;
  metadataContentDigest: string | null;
  registryAvailability: RegistryArtifactAvailability;
  registryAvailabilityReason: string | null;
  registryPackageName: string | null;
  registryProblems: string[];
  expectedIntegrity: string | null;
  canonicalExpectedIntegrity: string | null;
  expectedTarballUrl: string | null;
  canonicalExpectedTarballUrl: string | null;
  expectedReleaseSha: string | null;
  canonicalExpectedReleaseSha: string | null;
  state: ArtifactEvidenceState;
  registryState: RegistryArtifactEvidenceState;
  releaseBindingState: ReleaseArtifactBindingState;
  version: string | null;
  integrity: string | null;
  canonicalIntegrity: string | null;
  tarballUrl: string | null;
  canonicalTarballUrl: string | null;
  tarballByteCount: number | null;
  actualDigests: Record<SupportedSriAlgorithm, string | null>;
  gitHead: string | null;
  canonicalGitHead: string | null;
  registryIdentity: string | null;
  releaseBindingIdentity: string | null;
  registryVerified: boolean;
  releaseBound: boolean;
  verified: boolean;
  mismatch: string | null;
  reason: string | null;
}

export interface ArtifactVerificationFacts {
  packageName: string;
  requestedVersion: string;
  metadataUrl?: string | null;
  metadataContentDigest?: string | null;
  registryAvailability: RegistryArtifactAvailability;
  registryAvailabilityReason?: string | null;
  registryPackageName?: string | null;
  registryVersion?: string | null;
  registryIntegrity?: string | null;
  registryTarballUrl?: string | null;
  registryGitHead?: string | null;
  registryProblems?: readonly string[];
  releaseBindingProblems?: readonly string[];
  releaseBindingUnknowns?: readonly string[];
  actualDigests?: Partial<Record<SupportedSriAlgorithm, string>>;
  tarballByteCount?: number | null;
  expectedIntegrity?: string | null;
  expectedTarballUrl?: string | null;
  expectedReleaseSha?: string | null;
}

export interface ReleaseArtifactScoreSelection {
  readonly observation: Readonly<ReleaseArtifactObservation>;
  readonly receipt: Readonly<ReleaseArtifactReceipt>;
}

export interface ReleaseArtifactScoreInput {
  artifactVerified: boolean;
  artifactMismatch: string | null;
  ciReportVerified: boolean;
  ciReportMismatch: string | null;
  releaseIntegrityPresent: boolean;
  releaseShaMatches: boolean | undefined;
}

export interface ReleaseArtifactScoreGate {
  schemaVersion: typeof ARTIFACT_VERIFICATION_SCHEMA_VERSION;
  observationId: string | null;
  receiptId: string | null;
  evidenceIdentity: string | null;
  evidenceReportIdentity: string | null;
  runId: string | null;
  observedAt: string | null;
  observationContentHash: string | null;
  observationPreviousContentHash: string | null;
  receiptContentHash: string | null;
  receiptPreviousContentHash: string | null;
  release: ReleaseArtifactReceipt['release'] | null;
  releaseMetadata: ReleaseArtifactReceipt['releaseMetadata'] | null;
  artifact: ReleaseArtifactReceipt['artifact'] | null;
  evidenceReport: ReleaseArtifactReceipt['evidenceReport'] | null;
  npmPackageUrl: string | null;
  releaseTarballUrl: string | null;
  releaseIntegrity: string | null;
  releaseSha: string | null;
  releaseShaMatches: boolean | null;
  ciReportUrl: string | null;
  ciReportVerified: boolean;
  ciReportMismatch: string | null;
  fullReleaseValidationUrl: string | null;
  releaseValidationVerified: boolean;
  releaseValidationMismatch: string | null;
  registryVersion: string | null;
  registryIntegrity: string | null;
  registryTarballUrl: string | null;
  verified: boolean;
  mismatch: string | null;
}

export interface ReleaseArtifactScoreProjection {
  input: ReleaseArtifactScoreInput;
  gate: ReleaseArtifactScoreGate;
}

export function canonicalizeSri(
  integrity: string | null | undefined,
  label = 'integrity',
): CanonicalValue<CanonicalSri> {
  if (integrity == null || integrity.trim() === '') {
    return { value: null, problem: `${label} missing` };
  }

  const digests = new Map<SupportedSriAlgorithm, Map<string, Buffer>>();
  for (const token of integrity.trim().split(/\s+/)) {
    const match = /^([a-z0-9]+)-([A-Za-z0-9+/]+={0,2})(?:\?[^\s]*)?$/.exec(token);
    if (!match) return { value: null, problem: `${label} malformed` };

    const definition = SUPPORTED_SRI_ALGORITHMS.find(({ name }) => name === match[1]);
    if (!definition) continue;
    const digest = decodeCanonicalBase64(match[2], definition.digestBytes);
    if (!digest) {
      return {
        value: null,
        problem: `${label} ${definition.name} digest malformed`,
      };
    }
    const algorithmDigests = digests.get(definition.name) ?? new Map<string, Buffer>();
    algorithmDigests.set(digest.toString('base64'), digest);
    digests.set(definition.name, algorithmDigests);
  }

  for (const { name } of SUPPORTED_SRI_ALGORITHMS) {
    const algorithmDigests = digests.get(name);
    if (algorithmDigests && algorithmDigests.size > 1) {
      return { value: null, problem: `${label} ${name} digests conflict` };
    }
  }

  for (const { name } of SUPPORTED_SRI_ALGORITHMS) {
    const digest = digests.get(name)?.values().next().value as Buffer | undefined;
    if (!digest) continue;
    const digestBase64 = digest.toString('base64');
    return {
      value: {
        algorithm: name,
        digestBase64,
        digestHex: digest.toString('hex'),
        integrity: `${name}-${digestBase64}`,
      },
      problem: null,
    };
  }

  return { value: null, problem: `${label} algorithm unsupported` };
}

export function canonicalizeGitSha(
  sha: string | null | undefined,
  label = 'release SHA',
): CanonicalValue<string> {
  if (sha == null || sha.trim() === '') {
    return { value: null, problem: `${label} missing` };
  }
  const value = sha.trim().toLowerCase();
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value)) {
    return { value: null, problem: `${label} malformed` };
  }
  return { value, problem: null };
}

export function canonicalizeNpmTarballUrl(
  rawUrl: string | null | undefined,
  packageName: string,
  version: string,
  label = 'tarball URL',
): CanonicalValue<string> {
  if (rawUrl == null || rawUrl.trim() === '') {
    return { value: null, problem: `${label} missing` };
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { value: null, problem: `${label} invalid` };
  }
  if (parsed.protocol !== 'https:') {
    return { value: null, problem: `${label} must use HTTPS` };
  }
  if (parsed.hostname !== 'registry.npmjs.org') {
    return {
      value: null,
      problem: `${label} host ${parsed.hostname || 'missing'} is not allowed`,
    };
  }
  if (parsed.username || parsed.password) {
    return { value: null, problem: `${label} credentials are not allowed` };
  }
  if (parsed.port && parsed.port !== '443') {
    return { value: null, problem: `${label} port is not allowed` };
  }
  if (parsed.search || parsed.hash) {
    return { value: null, problem: `${label} query and fragment are not allowed` };
  }

  const canonical = `https://registry.npmjs.org/${packageName}/-/${packageName}-${
    encodeURIComponent(version)
  }.tgz`;
  if (parsed.href !== canonical) {
    return { value: null, problem: `${label} is not the canonical package tarball` };
  }
  return { value: canonical, problem: null };
}

export function canonicalizeNpmPackageVersionUrl(
  rawUrl: string | null | undefined,
  packageName: string,
  version: string,
  label = 'npm package URL',
): CanonicalValue<string> {
  if (rawUrl == null || rawUrl.trim() === '') {
    return { value: null, problem: `${label} missing` };
  }

  try {
    new URL(rawUrl);
  } catch {
    return { value: null, problem: `${label} invalid` };
  }

  const canonical =
    `https://www.npmjs.com/package/${encodeURIComponent(packageName)}/v/${
      encodeURIComponent(version)
    }`;
  if (rawUrl !== canonical) {
    return {
      value: null,
      problem: `${label} is not the canonical package version URL`,
    };
  }
  return { value: canonical, problem: null };
}

export function buildArtifactVerificationEvidence(
  input: ArtifactVerificationFacts,
): ArtifactVerificationEvidence {
  const registryName = input.registryPackageName ?? null;
  const registryVersion = input.registryVersion ?? null;
  const registryIntegrity = input.registryIntegrity ?? null;
  const registryTarballUrl = input.registryTarballUrl ?? null;
  const registryGitHead = input.registryGitHead ?? null;
  const registrySri = canonicalizeSri(registryIntegrity, 'registry integrity');
  const registryTarball = canonicalizeNpmTarballUrl(
    registryTarballUrl,
    input.packageName,
    input.requestedVersion,
    'registry tarball URL',
  );
  const registrySha = canonicalizeGitSha(registryGitHead, 'registry gitHead');

  let registryState: RegistryArtifactEvidenceState;
  let releaseBindingState: ReleaseArtifactBindingState;
  let state: ArtifactEvidenceState;
  let registryIdentity: string | null = null;
  let releaseBindingIdentity: string | null = null;
  const retainedProblems = retainedArtifactProblems(input);
  const retainedBinding = partitionRetainedArtifactProblems(retainedProblems);
  const registryProblems = [...retainedBinding.registryProblems];
  const bindingProblems = [...retainedBinding.bindingProblems];
  const bindingUnknowns = [...retainedBinding.bindingUnknowns];

  if (input.registryAvailability === 'unavailable') {
    registryState = 'unavailable';
    releaseBindingState = 'unavailable';
    state = 'unavailable';
    const reason = input.registryAvailabilityReason ?? 'npm registry artifact unavailable';
    return evidence({
      input,
      state,
      registryState,
      releaseBindingState,
      registryIdentity,
      releaseBindingIdentity,
      registrySri,
      registryTarball,
      registrySha,
      reason,
      mismatch: null,
    });
  }
  if (input.registryAvailability === 'unknown') {
    registryState = 'unknown';
    releaseBindingState = 'unknown';
    state = 'unknown';
    const reason = input.registryAvailabilityReason ?? 'npm registry artifact state unknown';
    return evidence({
      input,
      state,
      registryState,
      releaseBindingState,
      registryIdentity,
      releaseBindingIdentity,
      registrySri,
      registryTarball,
      registrySha,
      reason,
      mismatch: null,
    });
  }

  if (input.tarballByteCount == null) {
    registryProblems.push('registry tarball byte count unavailable');
  } else if (
    !Number.isSafeInteger(input.tarballByteCount) ||
    input.tarballByteCount <= 0
  ) {
    registryProblems.push('registry tarball byte count invalid');
  }
  registryProblems.push(...actualDigestProblems(input.actualDigests));

  if (registryName !== input.packageName) {
    registryProblems.push(
      `registry package ${registryName ?? 'missing'} != ${input.packageName}`,
    );
  }
  if (registryVersion !== input.requestedVersion) {
    registryProblems.push(
      `registry version ${registryVersion ?? 'missing'} != ${input.requestedVersion}`,
    );
  }
  if (registrySri.problem) registryProblems.push(registrySri.problem);
  if (registryTarball.problem) registryProblems.push(registryTarball.problem);

  if (registryProblems.length === 0 && registrySri.value) {
    const actualDigest = input.actualDigests?.[registrySri.value.algorithm];
    if (!actualDigest) {
      registryProblems.push(
        `registry tarball ${registrySri.value.algorithm} digest unavailable`,
      );
    } else if (actualDigest !== registrySri.value.digestBase64) {
      registryProblems.push('registry tarball integrity mismatch');
    }
  }

  const uniqueRegistryProblems = orderedUnique(registryProblems);
  if (uniqueRegistryProblems.length > 0) {
    registryState = uniqueRegistryProblems.every((problem) => problem.endsWith('unavailable'))
      ? 'unknown'
      : 'mismatch';
    releaseBindingState = registryState === 'unknown' ? 'unknown' : 'mismatch';
    state = registryState;
    const reason = uniqueRegistryProblems.join('; ');
    return evidence({
      input,
      state,
      registryState,
      releaseBindingState,
      registryIdentity,
      releaseBindingIdentity,
      registrySri,
      registryTarball,
      registrySha,
      reason,
      mismatch: state === 'mismatch' ? reason : null,
    });
  }

  const provenanceProblems: string[] = [];
  const provenanceUnknowns: string[] = [];
  const authoritativeMetadataUrl =
    `https://registry.npmjs.org/${input.packageName}/${
      encodeURIComponent(input.requestedVersion)
    }`;
  let canonicalMetadataDigest: string | null = null;
  if (isMissing(input.metadataUrl)) {
    provenanceUnknowns.push('registry metadata URL missing');
  } else if (input.metadataUrl !== authoritativeMetadataUrl) {
    provenanceProblems.push(
      'registry metadata URL is not the authoritative package version endpoint',
    );
  }
  if (isMissing(input.metadataContentDigest)) {
    provenanceUnknowns.push('registry metadata content digest missing');
  } else if (!/^[0-9a-f]{64}$/.test(input.metadataContentDigest!)) {
    provenanceProblems.push('registry metadata content digest malformed');
  } else {
    canonicalMetadataDigest = input.metadataContentDigest!;
  }
  if (provenanceProblems.length > 0) {
    registryState = 'mismatch';
  } else if (provenanceUnknowns.length > 0) {
    registryState = 'unknown';
  } else {
    registryState = 'registry_verified';
    registryIdentity = canonicalIdentity('registry', [
      input.packageName,
      input.requestedVersion,
      registrySri.value!.integrity,
      registryTarball.value!,
      registrySha.value ?? 'git-head-unavailable',
      canonicalMetadataDigest!,
      String(input.tarballByteCount ?? -1),
      JSON.stringify(canonicalActualDigests(input.actualDigests)),
    ]);
  }

  const expectedIntegrityMissing = isMissing(input.expectedIntegrity);
  const expectedTarballMissing = isMissing(input.expectedTarballUrl);
  const expectedShaMissing = isMissing(input.expectedReleaseSha);
  const expectedSri = canonicalizeSri(input.expectedIntegrity, 'release integrity');
  const expectedTarball = canonicalizeNpmTarballUrl(
    input.expectedTarballUrl,
    input.packageName,
    input.requestedVersion,
    'release tarball URL',
  );
  const expectedSha = canonicalizeGitSha(input.expectedReleaseSha, 'release SHA');

  if (expectedIntegrityMissing) {
    bindingUnknowns.push('release integrity missing');
  } else if (expectedSri.problem) {
    bindingProblems.push(expectedSri.problem);
  } else if (expectedSri.value) {
    const actualDigest = input.actualDigests?.[expectedSri.value.algorithm];
    if (!actualDigest) {
      bindingUnknowns.push(
        `release tarball ${expectedSri.value.algorithm} digest unavailable`,
      );
    } else if (actualDigest !== expectedSri.value.digestBase64) {
      bindingProblems.push('release integrity does not identify the registry tarball');
    }
  }

  if (expectedTarballMissing) {
    bindingUnknowns.push('release tarball URL missing');
  } else if (expectedTarball.problem) {
    bindingProblems.push(expectedTarball.problem);
  } else if (expectedTarball.value !== registryTarball.value) {
    bindingProblems.push('release tarball URL does not identify the registry tarball');
  }

  if (expectedShaMissing) {
    bindingUnknowns.push('release SHA missing');
  } else if (expectedSha.problem) {
    bindingProblems.push(expectedSha.problem);
  }
  if (registrySha.problem) {
    if (registrySha.problem.endsWith('missing')) bindingUnknowns.push(registrySha.problem);
    else bindingProblems.push(registrySha.problem);
  }
  if (
    expectedSha.value &&
    registrySha.value &&
    expectedSha.value !== registrySha.value
  ) {
    bindingProblems.push('release SHA does not match registry gitHead');
  }

  const uniqueBindingProblems = orderedUnique([
    ...provenanceProblems,
    ...bindingProblems,
  ]);
  if (uniqueBindingProblems.length > 0) {
    releaseBindingState = 'mismatch';
    state = 'mismatch';
    const reason = uniqueBindingProblems.join('; ');
    return evidence({
      input,
      state,
      registryState,
      releaseBindingState,
      registryIdentity,
      releaseBindingIdentity,
      registrySri,
      registryTarball,
      registrySha,
      reason,
      mismatch: reason,
    });
  }

  const uniqueBindingUnknowns = orderedUnique([
    ...provenanceUnknowns,
    ...bindingUnknowns,
  ]);
  if (uniqueBindingUnknowns.length === 0) {
    releaseBindingState = 'release_bound';
    state = 'release_bound';
    releaseBindingIdentity = canonicalIdentity('release-binding', [
      registryIdentity!,
      expectedSri.value!.integrity,
      expectedTarball.value!,
      expectedSha.value!,
    ]);
    return evidence({
      input,
      state,
      registryState,
      releaseBindingState,
      registryIdentity,
      releaseBindingIdentity,
      registrySri,
      registryTarball,
      registrySha,
      reason: null,
      mismatch: null,
    });
  }

  releaseBindingState = 'unknown';
  state = registryState === 'registry_verified' ? 'registry_verified' : 'unknown';
  const reason = uniqueBindingUnknowns.join('; ');
  return evidence({
    input,
    state,
    registryState,
    releaseBindingState,
    registryIdentity,
    releaseBindingIdentity,
    registrySri,
    registryTarball,
    registrySha,
    reason,
    mismatch: null,
  });
}

export function replayArtifactVerificationEvidence(
  value: ArtifactVerificationEvidence,
): ArtifactVerificationEvidence {
  return buildArtifactVerificationEvidence({
    packageName: value.packageName,
    requestedVersion: value.requestedVersion,
    metadataUrl: value.metadataUrl,
    metadataContentDigest: value.metadataContentDigest,
    registryAvailability: value.registryAvailability,
    registryAvailabilityReason: value.registryAvailabilityReason,
    registryPackageName: value.registryPackageName,
    registryVersion: value.version,
    registryIntegrity: value.integrity,
    registryTarballUrl: value.tarballUrl,
    registryGitHead: value.gitHead,
    registryProblems: value.registryProblems,
    actualDigests: {
      ...(value.actualDigests.sha512 == null
        ? {}
        : { sha512: value.actualDigests.sha512 }),
      ...(value.actualDigests.sha384 == null
        ? {}
        : { sha384: value.actualDigests.sha384 }),
      ...(value.actualDigests.sha256 == null
        ? {}
        : { sha256: value.actualDigests.sha256 }),
    },
    tarballByteCount: value.tarballByteCount,
    expectedIntegrity: value.expectedIntegrity,
    expectedTarballUrl: value.expectedTarballUrl,
    expectedReleaseSha: value.expectedReleaseSha,
  });
}

export function releaseArtifactScoreProjection(
  selection: ReleaseArtifactScoreSelection | null,
  releaseTagCommitOid: string | null,
): ReleaseArtifactScoreProjection {
  const observation = selection?.observation ?? null;
  const receipt = selection?.receipt ?? null;
  const selectionProblem = releaseArtifactScoreSelectionProblem(selection);
  const verifiedBinding = selectionProblem
    ? unverifiedReleaseArtifactBinding(selectionProblem)
    : verifiedReleaseArtifactBinding(receipt);
  const evidenceReportVerified =
    selectionProblem == null && receipt?.evidenceReport.verified === true;
  const evidenceReportMismatch =
    selectionProblem ?? receipt?.evidenceReport.mismatch ?? null;
  const scoredReleaseSha = canonicalizeGitSha(
    releaseTagCommitOid,
    'scored release tag OID',
  );
  const releaseShaMatches =
    verifiedBinding.verified && scoredReleaseSha.value
      ? verifiedBinding.releaseSha === scoredReleaseSha.value
      : null;
  const artifactMismatch =
    selectionProblem ??
    receipt?.artifact.mismatch ??
    (receipt?.artifact.verified === true && !verifiedBinding.verified
      ? verifiedBinding.problem
      : null);
  return {
    input: {
      artifactVerified: verifiedBinding.verified,
      artifactMismatch,
      ciReportVerified: evidenceReportVerified,
      ciReportMismatch: evidenceReportMismatch,
      releaseIntegrityPresent:
        verifiedBinding.verified && verifiedBinding.releaseIntegrity != null,
      releaseShaMatches: releaseShaMatches ?? undefined,
    },
    gate: {
      schemaVersion: ARTIFACT_VERIFICATION_SCHEMA_VERSION,
      observationId: observation?.observationId ?? null,
      receiptId: receipt?.receiptId ?? null,
      evidenceIdentity: receipt?.evidenceIdentity ?? null,
      evidenceReportIdentity: receipt?.evidenceReportIdentity ?? null,
      runId: observation?.runId ?? null,
      observedAt: observation?.observedAt ?? null,
      observationContentHash: observation?.contentHash ?? null,
      observationPreviousContentHash:
        observation?.previousContentHash ?? null,
      receiptContentHash: receipt?.contentHash ?? null,
      receiptPreviousContentHash: receipt?.previousContentHash ?? null,
      release: receipt?.release ?? null,
      releaseMetadata: receipt?.releaseMetadata ?? null,
      artifact: receipt?.artifact ?? null,
      evidenceReport: receipt?.evidenceReport ?? null,
      npmPackageUrl: verifiedBinding.npmPackageUrl,
      releaseTarballUrl: verifiedBinding.releaseTarballUrl,
      releaseIntegrity: verifiedBinding.releaseIntegrity,
      releaseSha: verifiedBinding.releaseSha,
      releaseShaMatches,
      ciReportUrl: receipt?.releaseMetadata.ciReportUrl ?? null,
      ciReportVerified: evidenceReportVerified,
      ciReportMismatch: evidenceReportMismatch,
      fullReleaseValidationUrl:
        receipt?.releaseMetadata.fullReleaseValidationUrl ?? null,
      releaseValidationVerified:
        selectionProblem == null &&
        receipt?.evidenceReport.fallbackKind === 'github_actions_run' &&
        receipt.evidenceReport.verified,
      releaseValidationMismatch:
        receipt?.evidenceReport.fallbackKind === 'github_actions_run'
          ? evidenceReportMismatch
          : null,
      registryVersion: receipt?.artifact.version ?? null,
      registryIntegrity: receipt?.artifact.integrity ?? null,
      registryTarballUrl: receipt?.artifact.tarballUrl ?? null,
      verified: verifiedBinding.verified,
      mismatch: artifactMismatch,
    },
  };
}

function releaseArtifactScoreSelectionProblem(
  selection: ReleaseArtifactScoreSelection | null,
): string | null {
  if (!selection) return null;
  const { observation, receipt } = selection;
  if (observation.receiptId !== receipt.receiptId) {
    return 'artifact observation references a different receipt';
  }
  if (observation.receiptContentHash !== receipt.contentHash) {
    return 'artifact observation receipt hash does not match';
  }
  const observedRelease = observation.release;
  const receiptRelease = receipt.release;
  if (
    observedRelease.repository !== receiptRelease.repository ||
    observedRelease.tag !== receiptRelease.tag ||
    observedRelease.releaseNodeId !== receiptRelease.releaseNodeId ||
    observedRelease.catalogTagCommitOid !== receiptRelease.catalogTagCommitOid ||
    observedRelease.publishedAt !== receiptRelease.publishedAt
  ) {
    return 'artifact observation release identity does not match its receipt';
  }
  return null;
}

function verifiedReleaseArtifactBinding(
  receipt: Readonly<ReleaseArtifactReceipt> | null,
): {
  verified: boolean;
  problem: string | null;
  npmPackageUrl: string | null;
  releaseTarballUrl: string | null;
  releaseIntegrity: string | null;
  releaseSha: string | null;
} {
  if (!receipt) {
    return {
      verified: false,
      problem: null,
      npmPackageUrl: null,
      releaseTarballUrl: null,
      releaseIntegrity: null,
      releaseSha: null,
    };
  }

  const artifact = receipt.artifact;
  const metadata = receipt.releaseMetadata;
  if (
    artifact.verified !== true ||
    artifact.releaseBound !== true ||
    artifact.releaseBindingState !== 'release_bound'
  ) {
    return unverifiedReleaseArtifactBinding(
      artifact.mismatch ?? artifact.reason ?? 'artifact evidence is not release-bound',
    );
  }

  const releaseVersion = receipt.release.tag.replace(/^v/, '');
  if (
    artifact.packageName !== 'openclaw' ||
    artifact.requestedVersion !== releaseVersion ||
    artifact.registryPackageName !== artifact.packageName ||
    artifact.version !== artifact.requestedVersion
  ) {
    return unverifiedReleaseArtifactBinding(
      'artifact package or version does not match the release',
    );
  }

  const npmPackageUrl = canonicalizeNpmPackageVersionUrl(
    metadata.npmPackageUrl,
    artifact.packageName,
    artifact.requestedVersion,
    'release npm package URL',
  );
  if (npmPackageUrl.problem) {
    return unverifiedReleaseArtifactBinding(npmPackageUrl.problem);
  }

  const releaseIntegrity = canonicalizeSri(
    metadata.releaseIntegrity,
    'release integrity',
  );
  if (
    releaseIntegrity.problem ||
    releaseIntegrity.value?.integrity !== artifact.canonicalExpectedIntegrity ||
    artifact.expectedIntegrity !== metadata.releaseIntegrity
  ) {
    return unverifiedReleaseArtifactBinding(
      releaseIntegrity.problem ??
        'release integrity does not match verified artifact evidence',
    );
  }

  const releaseTarballUrl = canonicalizeNpmTarballUrl(
    metadata.releaseTarballUrl,
    artifact.packageName,
    artifact.requestedVersion,
    'release tarball URL',
  );
  if (
    releaseTarballUrl.problem ||
    releaseTarballUrl.value !== artifact.canonicalExpectedTarballUrl ||
    artifact.expectedTarballUrl !== metadata.releaseTarballUrl
  ) {
    return unverifiedReleaseArtifactBinding(
      releaseTarballUrl.problem ??
        'release tarball URL does not match verified artifact evidence',
    );
  }

  const releaseSha = canonicalizeGitSha(metadata.releaseSha, 'release SHA');
  if (
    releaseSha.problem ||
    releaseSha.value !== artifact.canonicalExpectedReleaseSha ||
    artifact.expectedReleaseSha !== metadata.releaseSha ||
    releaseSha.value !== artifact.canonicalGitHead ||
    releaseSha.value !== receipt.release.catalogTagCommitOid
  ) {
    return unverifiedReleaseArtifactBinding(
      releaseSha.problem ??
        'release SHA does not match registry gitHead and catalog tag OID',
    );
  }

  return {
    verified: true,
    problem: null,
    npmPackageUrl: npmPackageUrl.value,
    releaseTarballUrl: metadata.releaseTarballUrl,
    releaseIntegrity: metadata.releaseIntegrity,
    releaseSha: releaseSha.value,
  };
}

function unverifiedReleaseArtifactBinding(problem: string): {
  verified: false;
  problem: string;
  npmPackageUrl: null;
  releaseTarballUrl: null;
  releaseIntegrity: null;
  releaseSha: null;
} {
  return {
    verified: false,
    problem,
    npmPackageUrl: null,
    releaseTarballUrl: null,
    releaseIntegrity: null,
    releaseSha: null,
  };
}

function evidence(args: {
  input: ArtifactVerificationFacts;
  state: ArtifactEvidenceState;
  registryState: RegistryArtifactEvidenceState;
  releaseBindingState: ReleaseArtifactBindingState;
  registryIdentity: string | null;
  releaseBindingIdentity: string | null;
  registrySri: CanonicalValue<CanonicalSri>;
  registryTarball: CanonicalValue<string>;
  registrySha: CanonicalValue<string>;
  reason: string | null;
  mismatch: string | null;
}): ArtifactVerificationEvidence {
  const releaseBound = args.releaseBindingState === 'release_bound';
  const expectedSri = canonicalizeSri(
    args.input.expectedIntegrity,
    'release integrity',
  );
  const expectedTarball = canonicalizeNpmTarballUrl(
    args.input.expectedTarballUrl,
    args.input.packageName,
    args.input.requestedVersion,
    'release tarball URL',
  );
  const expectedSha = canonicalizeGitSha(
    args.input.expectedReleaseSha,
    'release SHA',
  );
  return {
    schemaVersion: ARTIFACT_VERIFICATION_SCHEMA_VERSION,
    packageName: args.input.packageName,
    requestedVersion: args.input.requestedVersion,
    metadataUrl: args.input.metadataUrl ?? null,
    metadataContentDigest: args.input.metadataContentDigest ?? null,
    registryAvailability: args.input.registryAvailability,
    registryAvailabilityReason: args.input.registryAvailabilityReason ?? null,
    registryPackageName: args.input.registryPackageName ?? null,
    registryProblems: retainedArtifactProblems(args.input),
    expectedIntegrity: args.input.expectedIntegrity ?? null,
    canonicalExpectedIntegrity: expectedSri.value?.integrity ?? null,
    expectedTarballUrl: args.input.expectedTarballUrl ?? null,
    canonicalExpectedTarballUrl: expectedTarball.value,
    expectedReleaseSha: args.input.expectedReleaseSha ?? null,
    canonicalExpectedReleaseSha: expectedSha.value,
    state: args.state,
    registryState: args.registryState,
    releaseBindingState: args.releaseBindingState,
    version: args.input.registryVersion ?? null,
    integrity: args.input.registryIntegrity ?? null,
    canonicalIntegrity: args.registrySri.value?.integrity ?? null,
    tarballUrl: args.input.registryTarballUrl ?? null,
    canonicalTarballUrl: args.registryTarball.value,
    tarballByteCount: args.input.tarballByteCount ?? null,
    actualDigests: canonicalActualDigests(args.input.actualDigests),
    gitHead: args.input.registryGitHead ?? null,
    canonicalGitHead: args.registrySha.value,
    registryIdentity: args.registryIdentity,
    releaseBindingIdentity: args.releaseBindingIdentity,
    registryVerified: args.registryState === 'registry_verified',
    releaseBound,
    verified: releaseBound,
    mismatch: args.mismatch,
    reason: args.reason,
  };
}

function canonicalIdentity(kind: 'registry' | 'release-binding', values: string[]): string {
  const payload = JSON.stringify([
    ARTIFACT_VERIFICATION_SCHEMA_VERSION,
    kind,
    ...values,
  ]);
  return `artifact-v2:${kind}:sha256:${
    createHash('sha256').update(payload, 'utf8').digest('hex')
  }`;
}

function canonicalActualDigests(
  value: Partial<Record<SupportedSriAlgorithm, string>> | undefined,
): Record<SupportedSriAlgorithm, string | null> {
  return {
    sha512: value?.sha512 ?? null,
    sha384: value?.sha384 ?? null,
    sha256: value?.sha256 ?? null,
  };
}

function actualDigestProblems(
  value: Partial<Record<SupportedSriAlgorithm, string>> | undefined,
): string[] {
  const problems: string[] = [];
  for (const { name, digestBytes } of SUPPORTED_SRI_ALGORITHMS) {
    const digest = value?.[name];
    if (digest != null && !decodeCanonicalBase64(digest, digestBytes)) {
      problems.push(`registry tarball ${name} digest malformed`);
    }
  }
  return problems;
}

// Evidence v2 has no separate retained binding-diagnostics field. Prefix these
// entries in the existing source-fact array so failed bindings replay exactly.
const RELEASE_BINDING_PROBLEM_PREFIX = '[release-binding-mismatch] ';
const RELEASE_BINDING_UNKNOWN_PREFIX = '[release-binding-unknown] ';

function retainedArtifactProblems(input: ArtifactVerificationFacts): string[] {
  return orderedUnique([
    ...(input.registryProblems ?? []),
    ...(input.releaseBindingProblems ?? []).map(
      (problem) => `${RELEASE_BINDING_PROBLEM_PREFIX}${problem}`,
    ),
    ...(input.releaseBindingUnknowns ?? []).map(
      (problem) => `${RELEASE_BINDING_UNKNOWN_PREFIX}${problem}`,
    ),
  ]);
}

function partitionRetainedArtifactProblems(values: readonly string[]): {
  registryProblems: string[];
  bindingProblems: string[];
  bindingUnknowns: string[];
} {
  const registryProblems: string[] = [];
  const bindingProblems: string[] = [];
  const bindingUnknowns: string[] = [];
  for (const value of values) {
    if (value.startsWith(RELEASE_BINDING_PROBLEM_PREFIX)) {
      bindingProblems.push(value.slice(RELEASE_BINDING_PROBLEM_PREFIX.length));
    } else if (value.startsWith(RELEASE_BINDING_UNKNOWN_PREFIX)) {
      bindingUnknowns.push(value.slice(RELEASE_BINDING_UNKNOWN_PREFIX.length));
    } else {
      registryProblems.push(value);
    }
  }
  return { registryProblems, bindingProblems, bindingUnknowns };
}

function decodeCanonicalBase64(value: string, expectedBytes: number): Buffer | null {
  const decoded = Buffer.from(value, 'base64');
  if (decoded.length !== expectedBytes || decoded.toString('base64') !== value) return null;
  return decoded;
}

function orderedUnique(values: readonly string[]): string[] {
  return [...new Set(values.filter((value) => value.length > 0))];
}

function isMissing(value: string | null | undefined): boolean {
  return value == null || value.trim() === '';
}
