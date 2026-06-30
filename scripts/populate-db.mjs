// Offline DB scoring writer for local inspection when a network refresh is not
// desired. This intentionally delegates all scoring and audit payload generation
// to the shared releaseScoring module used by refresh.ts.
import { DatabaseSync } from 'node:sqlite';
import { listReleasesDb } from '../src/lib/db.ts';
import { computeHoursToNextStable } from '../src/lib/releaseNotes.ts';
import { buildReleaseScoreRun, persistReleaseScoreRun } from '../src/lib/releaseScoring.ts';
import { assertCleanIngestionMetadataBeforeScore } from './lib/score-ingestion-guard.mjs';

const db = new DatabaseSync(process.env.DB_PATH ?? './data/radar.db');
const setStableGap = db.prepare(`UPDATE releases SET hours_to_next_stable=? WHERE tag=?`);
const allReleases = db.prepare(`SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`)
  .all()
  .map((row) => ({
    tag: row.tag,
    published_at: row.published_at,
    prerelease: row.prerelease === 1,
  }));

for (const release of allReleases) {
  if (!release.prerelease) {
    setStableGap.run(computeHoursToNextStable(allReleases, release.tag), release.tag);
  }
}

const monitored = listReleasesDb(10);
assertCleanIngestionMetadataBeforeScore(monitored);
const scoreRun = buildReleaseScoreRun({
  releases: monitored,
});
persistReleaseScoreRun(scoreRun);

console.table(scoreRun.scored.map((result) => ({
  tag: result.rel.tag,
  score: result.conf.score ?? '-',
  status: result.conf.status,
  recommended: result.rel.tag === scoreRun.recommendedTag ? '*' : '',
  reason: result.conf.reason,
})));
console.log(`wrote ${scoreRun.scored.length} releases; recommended = ${scoreRun.recommendedTag}`);
