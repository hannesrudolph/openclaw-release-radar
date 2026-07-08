import { createHash } from 'node:crypto';
import { canonicalJson } from './operationReceipts';
import {
  assertReleaseArtifactObservation,
  assertReleaseArtifactReceipt,
  type ReleaseArtifactIdentity,
  type ReleaseArtifactObservation,
  type ReleaseArtifactReceipt,
} from './releaseArtifactReceipt';

export const RELEASE_ARTIFACT_PUBLICATION_SCHEMA_VERSION = 1 as const;

export interface ReleaseArtifactPublicationLink {
  release: ReleaseArtifactIdentity;
  observationId: string;
  observationContentHash: string;
  receiptId: string;
  receiptContentHash: string;
  evidenceIdentity: string;
  evidenceReportIdentity: string;
}

export interface ReleaseArtifactPublication {
  schemaVersion: typeof RELEASE_ARTIFACT_PUBLICATION_SCHEMA_VERSION;
  linkCount: number;
  links: ReleaseArtifactPublicationLink[];
  contentDigest: string;
}

export function releaseArtifactPublicationLink(
  observation: ReleaseArtifactObservation,
  receipt: ReleaseArtifactReceipt,
): ReleaseArtifactPublicationLink {
  assertReleaseArtifactObservation(observation);
  assertReleaseArtifactReceipt(receipt);
  if (observation.receiptId !== receipt.receiptId) {
    throw new Error(
      `Artifact observation ${observation.observationId} references a different receipt`,
    );
  }
  if (observation.receiptContentHash !== receipt.contentHash) {
    throw new Error(
      `Artifact observation ${observation.observationId} receipt hash does not match`,
    );
  }
  if (canonicalJson(observation.release) !== canonicalJson(receipt.release)) {
    throw new Error(
      `Artifact observation ${observation.observationId} release identity does not match`,
    );
  }
  return {
    release: receipt.release,
    observationId: observation.observationId,
    observationContentHash: observation.contentHash,
    receiptId: receipt.receiptId,
    receiptContentHash: receipt.contentHash,
    evidenceIdentity: receipt.evidenceIdentity,
    evidenceReportIdentity: receipt.evidenceReportIdentity,
  };
}

export function buildReleaseArtifactPublication(
  links: readonly ReleaseArtifactPublicationLink[],
): ReleaseArtifactPublication {
  const canonicalLinks = links.map(canonicalPublicationLink)
    .sort(comparePublicationLinks);
  const releaseKeys = new Set<string>();
  const releaseCoordinates = new Set<string>();
  const observationIds = new Set<string>();
  const receiptIds = new Set<string>();
  for (const link of canonicalLinks) {
    const releaseKey = releaseIdentityKey(link.release);
    const releaseCoordinate = canonicalJson([
      link.release.repository,
      link.release.tag,
    ]);
    if (releaseKeys.has(releaseKey)) {
      throw new Error(
        `Artifact publication contains duplicate release ${link.release.tag}`,
      );
    }
    if (releaseCoordinates.has(releaseCoordinate)) {
      throw new Error(
        `Artifact publication contains conflicting identities for release ` +
        `${link.release.repository}@${link.release.tag}`,
      );
    }
    if (observationIds.has(link.observationId)) {
      throw new Error(
        `Artifact publication contains duplicate observation ${link.observationId}`,
      );
    }
    if (receiptIds.has(link.receiptId)) {
      throw new Error(
        `Artifact publication contains duplicate receipt ${link.receiptId}`,
      );
    }
    releaseKeys.add(releaseKey);
    releaseCoordinates.add(releaseCoordinate);
    observationIds.add(link.observationId);
    receiptIds.add(link.receiptId);
  }
  return {
    schemaVersion: RELEASE_ARTIFACT_PUBLICATION_SCHEMA_VERSION,
    linkCount: canonicalLinks.length,
    links: canonicalLinks,
    contentDigest: releaseArtifactPublicationDigest(canonicalLinks),
  };
}

export function parseReleaseArtifactPublication(
  value: unknown,
): ReleaseArtifactPublication {
  const problems = releaseArtifactPublicationProblems(value);
  if (problems.length > 0) {
    throw new Error(`Invalid release artifact publication: ${problems.join('; ')}`);
  }
  const record = value as Record<string, unknown>;
  return buildReleaseArtifactPublication(
    record.links as ReleaseArtifactPublicationLink[],
  );
}

export function releaseArtifactPublicationProblems(value: unknown): string[] {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return ['publication must be an object'];
  }
  const record = value as Record<string, unknown>;
  const problems: string[] = [];
  if (!sameKeys(record, ['schemaVersion', 'linkCount', 'links', 'contentDigest'])) {
    problems.push(
      'publication keys must equal schemaVersion, linkCount, links, contentDigest',
    );
  }
  if (record.schemaVersion !== RELEASE_ARTIFACT_PUBLICATION_SCHEMA_VERSION) {
    problems.push(
      `schemaVersion must equal ${RELEASE_ARTIFACT_PUBLICATION_SCHEMA_VERSION}`,
    );
  }
  if (!Number.isInteger(record.linkCount) || Number(record.linkCount) < 0) {
    problems.push('linkCount must be a non-negative integer');
  }
  if (!Array.isArray(record.links)) {
    problems.push('links must be an array');
    return problems;
  }
  if (record.linkCount !== record.links.length) {
    problems.push('linkCount must equal links length');
  }
  let rebuilt: ReleaseArtifactPublication | null = null;
  try {
    rebuilt = buildReleaseArtifactPublication(
      record.links as ReleaseArtifactPublicationLink[],
    );
  } catch (error) {
    problems.push(error instanceof Error ? error.message : String(error));
  }
  if (
    typeof record.contentDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(record.contentDigest)
  ) {
    problems.push('contentDigest must be a lowercase SHA-256 digest');
  } else if (rebuilt && record.contentDigest !== rebuilt.contentDigest) {
    problems.push('contentDigest does not match the canonical link set');
  }
  if (
    rebuilt &&
    canonicalJson(record.links) !== canonicalJson(rebuilt.links)
  ) {
    problems.push('links must be canonical, unique, and sorted');
  }
  return [...new Set(problems)];
}

export function releaseArtifactPublicationDigest(
  links: readonly ReleaseArtifactPublicationLink[],
): string {
  return createHash('sha256')
    .update('release_artifact_publication_v1\0')
    .update(canonicalJson(links))
    .digest('hex');
}

export function releaseArtifactSemanticProjection(
  receipt: ReleaseArtifactReceipt,
): Record<string, unknown> {
  assertReleaseArtifactReceipt(receipt);
  return {
    release: receipt.release,
    receiptId: receipt.receiptId,
    evidenceIdentity: receipt.evidenceIdentity,
    evidenceReportIdentity: receipt.evidenceReportIdentity,
    canonicalReceiptJson: receipt.canonicalReceiptJson,
  };
}

export function releaseIdentityKey(release: ReleaseArtifactIdentity): string {
  return canonicalJson([
    release.repository,
    release.tag,
    release.releaseNodeId,
    release.catalogTagCommitOid,
    release.publishedAt,
  ]);
}

function canonicalPublicationLink(
  value: ReleaseArtifactPublicationLink,
): ReleaseArtifactPublicationLink {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Artifact publication link must be an object');
  }
  if (
    !sameKeys(value as unknown as Record<string, unknown>, [
      'release',
      'observationId',
      'observationContentHash',
      'receiptId',
      'receiptContentHash',
      'evidenceIdentity',
      'evidenceReportIdentity',
    ])
  ) {
    throw new Error('Artifact publication link contains unsupported fields');
  }
  const release = canonicalReleaseIdentity(value.release);
  if (!/^artifact-observation-v1:[0-9a-f]{64}$/.test(value.observationId)) {
    throw new Error('Artifact publication observation ID is invalid');
  }
  assertSha256(value.observationContentHash, 'observation content hash');
  if (!/^artifact-receipt-v2:[0-9a-f]{64}$/.test(value.receiptId)) {
    throw new Error('Artifact publication receipt ID is invalid');
  }
  assertSha256(value.receiptContentHash, 'receipt content hash');
  assertSha256(value.evidenceIdentity, 'evidence identity');
  if (value.receiptId !== `artifact-receipt-v2:${value.evidenceIdentity}`) {
    throw new Error(
      'Artifact publication receipt ID does not match its evidence identity',
    );
  }
  if (!/^release-evidence-v1:sha256:[0-9a-f]{64}$/.test(
    value.evidenceReportIdentity,
  )) {
    throw new Error('Artifact publication evidence report identity is invalid');
  }
  return {
    release,
    observationId: value.observationId,
    observationContentHash: value.observationContentHash,
    receiptId: value.receiptId,
    receiptContentHash: value.receiptContentHash,
    evidenceIdentity: value.evidenceIdentity,
    evidenceReportIdentity: value.evidenceReportIdentity,
  };
}

function canonicalReleaseIdentity(
  value: ReleaseArtifactIdentity,
): ReleaseArtifactIdentity {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error('Artifact publication release identity must be an object');
  }
  if (
    !sameKeys(value as unknown as Record<string, unknown>, [
      'repository',
      'tag',
      'releaseNodeId',
      'catalogTagCommitOid',
      'publishedAt',
    ])
  ) {
    throw new Error('Artifact publication release identity contains unsupported fields');
  }
  for (const [label, field] of [
    ['repository', value.repository],
    ['tag', value.tag],
    ['release node ID', value.releaseNodeId],
  ] as const) {
    if (!field || field.trim() !== field) {
      throw new Error(`Artifact publication ${label} is invalid`);
    }
  }
  if (!/^[^/\s]+\/[^/\s]+$/.test(value.repository)) {
    throw new Error('Artifact publication repository must be owner/name');
  }
  if (!/^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(value.catalogTagCommitOid)) {
    throw new Error('Artifact publication tag commit OID is invalid');
  }
  if (
    !Number.isFinite(Date.parse(value.publishedAt)) ||
    new Date(value.publishedAt).toISOString() !== value.publishedAt
  ) {
    throw new Error('Artifact publication publishedAt is not canonical ISO-8601');
  }
  return {
    repository: value.repository,
    tag: value.tag,
    releaseNodeId: value.releaseNodeId,
    catalogTagCommitOid: value.catalogTagCommitOid,
    publishedAt: value.publishedAt,
  };
}

function comparePublicationLinks(
  left: ReleaseArtifactPublicationLink,
  right: ReleaseArtifactPublicationLink,
): number {
  return (
    left.release.repository.localeCompare(right.release.repository) ||
    left.release.tag.localeCompare(right.release.tag) ||
    left.release.releaseNodeId.localeCompare(right.release.releaseNodeId) ||
    left.release.catalogTagCommitOid.localeCompare(
      right.release.catalogTagCommitOid,
    ) ||
    left.release.publishedAt.localeCompare(right.release.publishedAt) ||
    left.observationId.localeCompare(right.observationId)
  );
}

function sameKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  return canonicalJson(Object.keys(value).sort()) ===
    canonicalJson([...expected].sort());
}

function assertSha256(value: string, label: string): void {
  if (!/^[0-9a-f]{64}$/.test(value)) {
    throw new Error(`Artifact publication ${label} is invalid`);
  }
}
