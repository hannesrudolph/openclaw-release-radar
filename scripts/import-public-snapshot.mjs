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

function nullableNumber(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function countBrokenSurfaces(release) {
  const counts = new Map();
  const issues = [...(release.issues ?? []), ...(release.watchIssues ?? [])];
  for (const issue of issues) {
    const surface = issue?.surface;
    if (!surface?.label || !surface?.icon) continue;
    if (issue.state !== 'open') continue;
    if (issue.sentiment !== 'negative') continue;
    if (issue.severity !== 'critical' && issue.severity !== 'high') continue;

    const key = `${surface.label}\0${surface.icon}`;
    const prev = counts.get(key) ?? { label: surface.label, icon: surface.icon, count: 0 };
    prev.count++;
    counts.set(key, prev);
  }

  return JSON.stringify(
    [...counts.values()]
      .sort((a, b) => b.count - a.count || a.label.localeCompare(b.label))
      .slice(0, 8),
  );
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
        final_score: nullableNumber(release.score),
        negative_issues: Number.isInteger(release.negativeIssues) ? release.negativeIssues : 0,
        positive_issues: Number.isInteger(release.positiveIssues) ? release.positiveIssues : 0,
        scored_at: release.scoredAt ?? payload.updatedAt ?? importTime,
        state: typeof release.status === 'string' ? release.status : 'eligible',
        recommended: release.recommended ? 1 : 0,
        score_reason: typeof release.reason === 'string' ? release.reason : '',
        broken_surfaces: countBrokenSurfaces(release),
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
    recommended,
  }, null, 2));
}

await main();
