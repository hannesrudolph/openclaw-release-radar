import { createHash } from 'node:crypto';

export const RELEASE_ARTIFACT_PUBLICATION_SCOPE_SCHEMA_VERSION = 1 as const;

export interface ReleaseArtifactPublicationScope {
  schemaVersion: typeof RELEASE_ARTIFACT_PUBLICATION_SCOPE_SCHEMA_VERSION;
  releaseCount: number;
  scoredReleaseTags: string[];
  dependencyReleaseTags: string[];
  predecessorByReleaseTag: Record<string, string | null>;
  contentDigest: string;
}

export function buildReleaseArtifactPublicationScope(input: {
  scoredReleaseTags: readonly string[];
  predecessorByReleaseTag: Readonly<Record<string, string | null>>;
}): ReleaseArtifactPublicationScope {
  const scoredReleaseTags = canonicalTags(
    input.scoredReleaseTags,
    'scored release tags',
  );
  const predecessorByReleaseTag = canonicalPredecessorMap(
    input.predecessorByReleaseTag,
    scoredReleaseTags,
  );
  const scored = new Set(scoredReleaseTags);
  const dependencyReleaseTags = canonicalTags(
    Object.values(predecessorByReleaseTag)
      .filter((tag): tag is string => tag != null && !scored.has(tag)),
    'dependency release tags',
  );
  const core = {
    schemaVersion: RELEASE_ARTIFACT_PUBLICATION_SCOPE_SCHEMA_VERSION,
    releaseCount: scoredReleaseTags.length + dependencyReleaseTags.length,
    scoredReleaseTags,
    dependencyReleaseTags,
    predecessorByReleaseTag,
  };
  return {
    ...core,
    contentDigest: releaseArtifactPublicationScopeDigest(core),
  };
}

export function parseReleaseArtifactPublicationScope(
  value: unknown,
): ReleaseArtifactPublicationScope {
  const problems = releaseArtifactPublicationScopeProblems(value);
  if (problems.length > 0) {
    throw new Error(
      `Invalid release artifact publication scope: ${problems.join('; ')}`,
    );
  }
  const record = value as Record<string, unknown>;
  return buildReleaseArtifactPublicationScope({
    scoredReleaseTags: record.scoredReleaseTags as string[],
    predecessorByReleaseTag:
      record.predecessorByReleaseTag as Record<string, string | null>,
  });
}

export function releaseArtifactPublicationScopeProblems(
  value: unknown,
): string[] {
  if (!isRecord(value)) return ['scope must be an object'];
  const problems: string[] = [];
  if (!sameKeys(value, [
    'schemaVersion',
    'releaseCount',
    'scoredReleaseTags',
    'dependencyReleaseTags',
    'predecessorByReleaseTag',
    'contentDigest',
  ])) {
    problems.push(
      'scope keys must equal schemaVersion, releaseCount, scoredReleaseTags, ' +
      'dependencyReleaseTags, predecessorByReleaseTag, contentDigest',
    );
  }
  if (
    value.schemaVersion !==
      RELEASE_ARTIFACT_PUBLICATION_SCOPE_SCHEMA_VERSION
  ) {
    problems.push(
      `schemaVersion must equal ` +
      `${RELEASE_ARTIFACT_PUBLICATION_SCOPE_SCHEMA_VERSION}`,
    );
  }
  if (!Array.isArray(value.scoredReleaseTags)) {
    problems.push('scoredReleaseTags must be an array');
  }
  if (!Array.isArray(value.dependencyReleaseTags)) {
    problems.push('dependencyReleaseTags must be an array');
  }
  if (!isRecord(value.predecessorByReleaseTag)) {
    problems.push('predecessorByReleaseTag must be an object');
  }
  let rebuilt: ReleaseArtifactPublicationScope | null = null;
  if (
    Array.isArray(value.scoredReleaseTags) &&
    Array.isArray(value.dependencyReleaseTags) &&
    isRecord(value.predecessorByReleaseTag)
  ) {
    try {
      rebuilt = buildReleaseArtifactPublicationScope({
        scoredReleaseTags: value.scoredReleaseTags as string[],
        predecessorByReleaseTag:
          value.predecessorByReleaseTag as Record<string, string | null>,
      });
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (!Number.isInteger(value.releaseCount) || Number(value.releaseCount) < 0) {
    problems.push('releaseCount must be a non-negative integer');
  }
  if (
    typeof value.contentDigest !== 'string' ||
    !/^[0-9a-f]{64}$/.test(value.contentDigest)
  ) {
    problems.push('contentDigest must be a lowercase SHA-256 digest');
  }
  if (rebuilt) {
    if (value.releaseCount !== rebuilt.releaseCount) {
      problems.push('releaseCount does not match the canonical scope');
    }
    if (!sameJson(value.scoredReleaseTags, rebuilt.scoredReleaseTags)) {
      problems.push('scoredReleaseTags must be canonical, unique, and sorted');
    }
    if (!sameJson(
      value.dependencyReleaseTags,
      rebuilt.dependencyReleaseTags,
    )) {
      problems.push(
        'dependencyReleaseTags do not match the canonical predecessor set',
      );
    }
    if (!sameJson(
      sortedRecord(value.predecessorByReleaseTag as Record<string, unknown>),
      rebuilt.predecessorByReleaseTag,
    )) {
      problems.push(
        'predecessorByReleaseTag must exactly cover the scored release tags',
      );
    }
    if (value.contentDigest !== rebuilt.contentDigest) {
      problems.push('contentDigest does not match the canonical scope');
    }
  }
  return [...new Set(problems)];
}

export function releaseArtifactPublicationScopeScoreProblems(
  value: unknown,
  expected: {
    scoredReleaseTags: readonly string[];
    predecessorByReleaseTag: Readonly<Record<string, string | null>>;
  },
): string[] {
  let actual: ReleaseArtifactPublicationScope;
  let canonicalExpected: ReleaseArtifactPublicationScope;
  try {
    actual = parseReleaseArtifactPublicationScope(value);
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
  try {
    canonicalExpected = buildReleaseArtifactPublicationScope(expected);
  } catch (error) {
    return [
      `Expected release artifact scope is invalid: ` +
      `${error instanceof Error ? error.message : String(error)}`,
    ];
  }
  return sameJson(actual, canonicalExpected)
    ? []
    : ['release artifact scope does not match the durable score dependency set'];
}

export function releaseArtifactPublicationScopeLinkProblems(
  publication: unknown,
  scopeValue: unknown,
): string[] {
  let scope: ReleaseArtifactPublicationScope;
  try {
    scope = parseReleaseArtifactPublicationScope(scopeValue);
  } catch (error) {
    return [error instanceof Error ? error.message : String(error)];
  }
  if (!isRecord(publication) || !Array.isArray(publication.links)) {
    return ['release artifact publication links must be an array'];
  }
  const linkTags: string[] = [];
  for (const [index, link] of publication.links.entries()) {
    if (
      !isRecord(link) ||
      !isRecord(link.release) ||
      typeof link.release.tag !== 'string' ||
      !link.release.tag ||
      link.release.tag.trim() !== link.release.tag
    ) {
      return [`release artifact publication link ${index} has no canonical tag`];
    }
    linkTags.push(link.release.tag);
  }
  if (new Set(linkTags).size !== linkTags.length) {
    return ['release artifact publication contains duplicate release tags'];
  }
  const expectedTags = [
    ...scope.scoredReleaseTags,
    ...scope.dependencyReleaseTags,
  ].sort();
  return sameJson(linkTags.slice().sort(), expectedTags)
    ? []
    : ['release artifact publication does not match its scored/dependency scope'];
}

export function releaseArtifactPublicationScopeDigest(
  value: Omit<ReleaseArtifactPublicationScope, 'contentDigest'>,
): string {
  return createHash('sha256')
    .update('release_artifact_publication_scope_v1\0')
    .update(JSON.stringify(value))
    .digest('hex');
}

function canonicalTags(values: readonly string[], label: string): string[] {
  if (!Array.isArray(values)) throw new Error(`${label} must be an array`);
  const tags = values.map((value) => {
    if (typeof value !== 'string' || !value || value.trim() !== value) {
      throw new Error(`${label} must contain canonical non-empty strings`);
    }
    return value;
  });
  if (new Set(tags).size !== tags.length) {
    throw new Error(`${label} must not contain duplicates`);
  }
  return tags.slice().sort();
}

function canonicalPredecessorMap(
  value: Readonly<Record<string, string | null>>,
  scoredReleaseTags: readonly string[],
): Record<string, string | null> {
  if (!isRecord(value)) {
    throw new Error('predecessorByReleaseTag must be an object');
  }
  const keys = Object.keys(value).sort();
  if (!sameJson(keys, [...scoredReleaseTags])) {
    throw new Error(
      'predecessorByReleaseTag must exactly cover the scored release tags',
    );
  }
  const result: Record<string, string | null> = {};
  for (const tag of scoredReleaseTags) {
    const predecessor = value[tag];
    if (
      predecessor !== null &&
      (
        typeof predecessor !== 'string' ||
        !predecessor ||
        predecessor.trim() !== predecessor
      )
    ) {
      throw new Error(
        `predecessorByReleaseTag ${JSON.stringify(tag)} is not canonical`,
      );
    }
    result[tag] = predecessor;
  }
  return result;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value && typeof value === 'object' && !Array.isArray(value));
}

function sameKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
): boolean {
  return sameJson(Object.keys(value).sort(), [...expected].sort());
}

function sameJson(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function sortedRecord(
  value: Record<string, unknown>,
): Record<string, unknown> {
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) =>
      left.localeCompare(right)),
  );
}
