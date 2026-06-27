const DEFAULT_URL = 'https://isitstable.iclaw.digital/api/public';
const ALLOW_FLAG = '--allow-overwrite-local-releases';
const args = process.argv.slice(2);
const allowOverwrite = args.includes(ALLOW_FLAG) || process.env.ALLOW_PUBLIC_SNAPSHOT_IMPORT === 'true';
const sourceUrl = args.find((arg) => !arg.startsWith('--')) ?? process.env.PUBLIC_SNAPSHOT_URL ?? DEFAULT_URL;

if (!allowOverwrite) {
  throw new Error(
    `Refusing to overwrite local release rows from an external public snapshot. ` +
    `Pass ${ALLOW_FLAG} only for intentional legacy recovery imports.`,
  );
}

function assertObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  return value;
}

async function main() {
  const { db, setMeta } = await import('../src/lib/db.ts');
  const res = await fetch(sourceUrl);
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`Fetch failed ${res.status} ${sourceUrl}: ${body.slice(0, 300)}`);
  }

  const payload = assertObject(await res.json(), 'public snapshot');
  if (!Array.isArray(payload.releases)) {
    throw new Error('public snapshot must include a releases array');
  }

  const upsertRelease = db.prepare(`
    INSERT INTO releases (
      tag, name, published_at, html_url, prerelease,
      final_score, negative_issues, positive_issues, scored_at, state,
      recommended, score_reason, broken_surfaces
    )
    VALUES (
      :tag, :name, :published_at, :html_url, 0,
      :final_score, :negative_issues, :positive_issues, :scored_at, :state,
      :recommended, :score_reason, :broken_surfaces
    )
    ON CONFLICT(tag) DO UPDATE SET
      name=excluded.name,
      published_at=excluded.published_at,
      html_url=excluded.html_url,
      prerelease=excluded.prerelease,
      final_score=excluded.final_score,
      negative_issues=excluded.negative_issues,
      positive_issues=excluded.positive_issues,
      scored_at=excluded.scored_at,
      state=excluded.state,
      recommended=excluded.recommended,
      score_reason=excluded.score_reason,
      broken_surfaces=excluded.broken_surfaces
  `);

  const importTime = new Date().toISOString();
  db.exec('BEGIN');
  try {
    for (const release of payload.releases) {
      assertObject(release, 'release');
      if (typeof release.tag !== 'string' || !release.tag) {
        throw new Error('release is missing tag');
      }
      if (typeof release.url !== 'string' || !release.url) {
        throw new Error(`release ${release.tag} is missing url`);
      }

      upsertRelease.run({
        tag: release.tag,
        name: release.tag,
        published_at: release.publishedAt ?? null,
        html_url: release.url,
        final_score: null,
        negative_issues: 0,
        positive_issues: 0,
        scored_at: null,
        state: 'wait',
        recommended: 0,
        score_reason: 'Imported from legacy public snapshot; run a local refresh to score with local evidence.',
        broken_surfaces: '[]',
      });
    }

    setMeta('public_snapshot_source_url', sourceUrl);
    setMeta('public_snapshot_updated_at', payload.updatedAt ?? '');
    setMeta('public_snapshot_imported_at', importTime);
    db.exec('COMMIT');
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }

  const recommended = payload.releases.find((r) => r?.recommended)?.tag ?? null;
  console.log(JSON.stringify({
    importedReleases: payload.releases.length,
    sourceUrl,
    sourceUpdatedAt: payload.updatedAt ?? null,
    sourceRecommended: recommended,
    localScoresImported: false,
    nextStep: 'Run npm run dev or a manual refresh to compute local scores and score audits.',
  }, null, 2));
}

await main();
