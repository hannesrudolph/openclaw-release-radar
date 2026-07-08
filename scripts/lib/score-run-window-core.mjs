function requireDependency(dependencies, name) {
  const dependency = dependencies?.[name];
  if (typeof dependency !== 'function') {
    throw new TypeError(`score-run-window dependency ${name} must be a function`);
  }
  return dependency;
}

export function createScoreRunWindowHelpers(dependencies) {
  const getMeta = requireDependency(dependencies, 'getMeta');
  const getRelease = requireDependency(dependencies, 'getRelease');
  const listActiveReleaseCatalogDb = requireDependency(
    dependencies,
    'listActiveReleaseCatalogDb',
  );
  const listReleasesDb = requireDependency(dependencies, 'listReleasesDb');

  function scoreRunWindowOptions(releases) {
    const selected = Array.isArray(releases) ? releases : [];
    const activeCatalog = listActiveReleaseCatalogDb();
    const activeTags = new Set(activeCatalog.map((release) => release.tag));
    const missing = selected
      .map((release) => release?.tag)
      .filter((tag) => typeof tag === 'string' && !activeTags.has(tag));
    if (missing.length > 0) {
      throw new Error(
        `Selected score releases are not active catalog members: ${missing.join(', ')}`,
      );
    }
    const allFetchedTags = activeCatalog.map((release) => release.tag);
    const stableTagsNewestFirst = activeCatalog
      .filter((release) => release.prerelease !== 1)
      .map((release) => release.tag);
    const selectedStable = selected.filter((release) => release?.prerelease !== 1);
    const oldestScoredStableTag = selectedStable.at(-1)?.tag ?? null;
    const oldestIndex = oldestScoredStableTag == null
      ? -1
      : stableTagsNewestFirst.indexOf(oldestScoredStableTag);
    const oldestScoredStablePredecessorTag = oldestIndex >= 0
      ? stableTagsNewestFirst[oldestIndex + 1] ?? null
      : null;
    return {
      releases: selected,
      allFetchedTags,
      stableTagsNewestFirst,
      oldestScoredStablePredecessorTag,
    };
  }

  function persistedMonitoredReleaseTags() {
    const raw = getMeta('score_persistence_last_run');
    if (!raw) return [];
    let parsed;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new Error('score_persistence_last_run is malformed JSON');
    }
    if (
      parsed?.schemaVersion !== 2 ||
      !Array.isArray(parsed.releaseTags) ||
      parsed.releaseTags.length === 0
    ) {
      throw new Error(
        'score_persistence_last_run must use schemaVersion 2 with a non-empty releaseTags array',
      );
    }
    const tags = parsed.releaseTags
      .filter((tag) => typeof tag === 'string' && tag.trim())
      .map((tag) => tag.trim());
    if (tags.length !== parsed.releaseTags.length || new Set(tags).size !== tags.length) {
      throw new Error(
        'score_persistence_last_run releaseTags must be unique non-empty strings',
      );
    }
    return tags;
  }

  function monitoredScoreWindowReleases(fallbackLimit = 10) {
    const persistedTags = persistedMonitoredReleaseTags();
    if (persistedTags.length > 0) {
      return persistedTags.map((tag) => {
        const release = getRelease(tag);
        if (!release || release.catalog_active !== 1 || release.prerelease === 1) {
          throw new Error(
            `Persisted monitored score release ${tag} is missing from the active stable catalog`,
          );
        }
        return release;
      });
    }
    const normalizedLimit = Math.max(1, Math.floor(Number(fallbackLimit)));
    return listReleasesDb(normalizedLimit);
  }

  function latestScoreRunWindowOptions(limit = 10) {
    return scoreRunWindowOptions(monitoredScoreWindowReleases(limit));
  }

  return Object.freeze({
    latestScoreRunWindowOptions,
    monitoredScoreWindowReleases,
    scoreRunWindowOptions,
  });
}
