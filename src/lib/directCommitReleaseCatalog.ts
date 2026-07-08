import { createHash } from 'node:crypto';

const FULL_COMMIT_OID_RE = /^[0-9a-f]{40}$/;

export interface DirectCommitReleaseCatalogRow {
  node_id: string;
  tag_name: string;
  tag_commit_oid: string;
  published_at: string | null;
  prerelease: boolean;
  draft: boolean;
}

export interface StableReleaseBoundaryRow {
  node_id: string;
  tag: string;
  published_at: string;
  catalog_rank: number;
  catalog_digest: string;
  catalog_receipt_id: string | null;
  catalog_release_count: number;
  catalog_tag_commit_oid: string;
  resolved_tag_commit_oid: string;
}

export function projectDirectCommitStableReleaseBoundaries(
  releases: readonly DirectCommitReleaseCatalogRow[],
): StableReleaseBoundaryRow[] {
  const activeTags = new Set<string>();
  const activeNodeIds = new Set<string>();
  const active = releases.flatMap((release, index) => {
    if (!release || typeof release !== 'object') {
      throw new Error(`Release catalog row ${index} is invalid`);
    }
    if (typeof release.draft !== 'boolean') {
      throw new Error(`Release catalog row ${index} has invalid draft state`);
    }
    if (release.draft) return [];
    if (typeof release.prerelease !== 'boolean') {
      throw new Error(`Release catalog row ${index} has invalid prerelease state`);
    }

    const nodeId = canonicalText(release.node_id);
    const tag = canonicalText(release.tag_name);
    const commitOid = String(release.tag_commit_oid ?? '').toLowerCase();
    const publishedAt = canonicalText(release.published_at);
    if (!nodeId) {
      throw new Error(`Published release catalog row ${index} is missing node_id`);
    }
    if (!tag) {
      throw new Error(`Published release catalog row ${index} is missing tag`);
    }
    if (!FULL_COMMIT_OID_RE.test(commitOid)) {
      throw new Error(`Published release catalog row ${tag} has invalid tag commit OID`);
    }
    if (!publishedAt || !Number.isFinite(Date.parse(publishedAt))) {
      throw new Error(`Published release catalog row ${tag} has invalid published_at`);
    }
    if (activeNodeIds.has(nodeId)) {
      throw new Error(`Published release catalog contains duplicate node_id ${nodeId}`);
    }
    if (activeTags.has(tag)) {
      throw new Error(`Published release catalog contains duplicate tag ${tag}`);
    }
    activeNodeIds.add(nodeId);
    activeTags.add(tag);
    return [{
      nodeId,
      tag,
      commitOid,
      publishedAt,
      prerelease: release.prerelease,
    }];
  });

  active.sort((left, right) =>
    Date.parse(right.publishedAt) - Date.parse(left.publishedAt) ||
    compareBinary(left.tag, right.tag) ||
    compareBinary(left.nodeId, right.nodeId));

  const catalogDigest = createHash('sha256')
    .update(JSON.stringify([
      'direct_commit_release_catalog',
      1,
      active.map((release) => [
        release.nodeId,
        release.tag,
        release.commitOid,
        release.publishedAt,
        release.prerelease,
      ]),
    ]))
    .digest('hex');

  return active.flatMap((release, catalogRank) =>
    release.prerelease
      ? []
      : [{
          node_id: release.nodeId,
          tag: release.tag,
          published_at: release.publishedAt,
          catalog_rank: catalogRank,
          catalog_digest: catalogDigest,
          catalog_receipt_id: null,
          catalog_release_count: active.length,
          catalog_tag_commit_oid: release.commitOid,
          resolved_tag_commit_oid: release.commitOid,
        }]);
}

function canonicalText(value: unknown): string | null {
  return typeof value === 'string' && value.length > 0 && value.trim() === value
    ? value
    : null;
}

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}
