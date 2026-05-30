// One-off: write the new Install Confidence results into the local DB so the
// API/UI can be inspected without a network refresh. Mirrors refresh.ts's scoring
// block exactly. Production populates these via the real refresh() on the next tick.
import { DatabaseSync } from 'node:sqlite';
import { cveDecayLoad, feltLoad, installConfidence, pickRecommended } from '../src/lib/score.ts';
import { topBrokenSurfaces } from '../src/lib/surfaces.ts';
import {
  listReleasesDb, closedDuringReign, openedDuringReign, issuesForVersion,
  listAdvisories, updateReleaseScore,
} from '../src/lib/db.ts';
import { computeHoursToNextStable, hasHotfixSuccessor } from '../src/lib/releaseNotes.ts';
import { matchesRange, stableDistance } from '../src/lib/versionMatch.ts';
import { applyLabelOverrides, applyTitleFunctionalityHint } from '../src/lib/labelOverrides.ts';

const db = new DatabaseSync('./data/radar.db');
const setStableGap = db.prepare(`UPDATE releases SET hours_to_next_stable=? WHERE tag=?`);
const allRel = db.prepare(`SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`)
  .all().map(r => ({ tag: r.tag, published_at: r.published_at, prerelease: r.prerelease === 1 }));
const allTags = allRel.filter(r => !r.prerelease).map(r => r.tag); // stables only (distance + hotfix-tag)

const advisories = listAdvisories();
const SEV = { critical: 4, high: 3, medium: 2, low: 1 };
const cveFor = (tag) => {
  const matching = advisories.filter(a => matchesRange(tag, a.vulnerable_version_range));
  return {
    affected: matching.some(a => (SEV[a.severity] ?? 0) >= 2),
    load: cveDecayLoad(matching.map(a => ({ severity: a.severity, distance: stableDistance(tag, a.patched_versions, allTags) })).filter(x => x.distance <= 0)),
  };
};
function safeLabels(j){ try{ const v=JSON.parse(j); return Array.isArray(v)?v.filter(x=>typeof x==='string'):[]; }catch{ return []; } }
function rowToCls(r){ const ok=['none','partial','confirmed','unknown']; const ws=ok.includes(r.workaround_status)?r.workaround_status:(r.has_workaround===1?'confirmed':'unknown'); return { sentiment:r.sentiment, severity:r.severity, scope:r.scope, functionality:r.functionality, affectedUsers:r.affected_users, workaroundStatus:ws, duplicateCluster:r.duplicate_cluster, affectsVersion:r.affects_version, confidence:r.confidence, rationale:r.rationale??'' }; }
const classify = (r)=>applyLabelOverrides(applyTitleFunctionalityHint(rowToCls(r), r.title), safeLabels(r.labels));
const isCS = (c)=>c.sentiment==='negative'&&c.functionality==='core'&&(c.severity==='critical'||c.severity==='high');
const countCS = (rows)=>rows.reduce((n,r)=>isCS(classify(r))?n+1:n,0);

const releases = listReleasesDb(10);
const scored = releases.map((rel, idx) => {
  let neg=0,pos=0; for(const r of issuesForVersion(rel.tag)){ const s=classify(r).sentiment; if(s==='negative')neg++; else if(s==='positive')pos++; }
  const oReign = openedDuringReign(rel.tag), cReign = closedDuringReign(rel.tag);
  const opened = countCS(oReign), closed = countCS(cReign);
  const isFelt = c => c.sentiment==='negative' && ['core','integration','provider'].includes(c.functionality) && (c.severity==='critical'||c.severity==='high');
  const brokenSurfaces = JSON.stringify(topBrokenSurfaces(oReign.filter(r => r.state==='open' && isFelt(classify(r))).map(r => r.title)));
  const gap = computeHoursToNextStable(allRel, rel.tag);
  setStableGap.run(gap, rel.tag);
  const cve = cveFor(rel.tag);
  const conf = installConfidence({
    publishedAt: rel.published_at, isLatest: idx === 0, hoursToNextStable: gap,
    hasHotfixSuccessor: hasHotfixSuccessor(allTags, rel.tag), betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight: feltLoad(oReign.map(classify)), feltClosedWeight: feltLoad(cReign.map(classify)),
    cveAffected: cve.affected, cveLoad: cve.load,
  });
  return { rel, conf, neg, pos, opened, closed, brokenSurfaces };
});
const rec = pickRecommended(scored.map(s => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })));
for (const s of scored) {
  updateReleaseScore({
    tag: s.rel.tag, final_score: s.conf.score, negative_issues: s.neg, positive_issues: s.pos,
    state: s.conf.status, recommended: s.rel.tag === rec ? 1 : 0, score_reason: s.conf.reason,
    broken_surfaces: s.brokenSurfaces,
    closed_serious_fixed: s.closed, opened_serious_during_reign: s.opened,
  });
}
console.log(`wrote ${scored.length} releases; recommended = ${rec}`);
