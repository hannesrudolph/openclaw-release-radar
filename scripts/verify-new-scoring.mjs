// Offline validation of the REAL new scoring path against the real DB. Mirrors the
// scoring block in refresh.ts but reads existing classifications (no network/LLM).
// Confirms score.ts + the next-stable reign SQL produce the expected verdicts.
import { DatabaseSync } from 'node:sqlite';
import { cveDecayLoad, feltLoad, installConfidence, pickRecommended } from '../src/lib/score.ts';
import {
  listReleasesDb, closedDuringReign, openedDuringReign, issuesForVersion, listAdvisories,
} from '../src/lib/db.ts';
import { computeHoursToNextStable, hasHotfixSuccessor } from '../src/lib/releaseNotes.ts';
import { matchesRange, stableDistance } from '../src/lib/versionMatch.ts';
import { applyLabelOverrides, applyTitleFunctionalityHint } from '../src/lib/labelOverrides.ts';

const db = new DatabaseSync('./data/radar.db');
const allRel = db.prepare(
  `SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`
).all().map(r => ({ tag: r.tag, published_at: r.published_at, prerelease: r.prerelease === 1 }));
const allTags = allRel.filter(r => !r.prerelease).map(r => r.tag);

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
function rowToCls(r){ const ok=['none','partial','confirmed','unknown']; const ws=ok.includes(r.workaround_status)?r.workaround_status:(r.has_workaround===1?'confirmed':'unknown');
  return { sentiment:r.sentiment, severity:r.severity, scope:r.scope, functionality:r.functionality, affectedUsers:r.affected_users, workaroundStatus:ws, duplicateCluster:r.duplicate_cluster, affectsVersion:r.affects_version, confidence:r.confidence, rationale:r.rationale??'' }; }
const classify = (r)=>applyLabelOverrides(applyTitleFunctionalityHint(rowToCls(r), r.title), safeLabels(r.labels));
const isCoreSerious = (c)=>c.sentiment==='negative'&&c.functionality==='core'&&(c.severity==='critical'||c.severity==='high');
const countCS = (rows)=>rows.reduce((n,r)=>isCoreSerious(classify(r))?n+1:n,0);

const releases = listReleasesDb(10);
const scored = releases.map((rel, idx) => {
  let neg=0,pos=0; for(const r of issuesForVersion(rel.tag)){ const s=classify(r).sentiment; if(s==='negative')neg++; else if(s==='positive')pos++; }
  const conf = installConfidence({
    publishedAt: rel.published_at,
    isLatest: idx === 0,
    hoursToNextStable: computeHoursToNextStable(allRel, rel.tag),
    hasHotfixSuccessor: hasHotfixSuccessor(allTags, rel.tag),
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight: feltLoad(openedDuringReign(rel.tag).map(classify)),
    feltClosedWeight: feltLoad(closedDuringReign(rel.tag).map(classify)),
    cveAffected: cveFor(rel.tag).affected,
    cveLoad: cveFor(rel.tag).load,
  });
  return { rel, conf };
});
const rec = pickRecommended(scored.map(s => ({ tag: s.rel.tag, status: s.conf.status, score: s.conf.score })));

console.table(scored.map(s => ({
  tag: s.rel.tag,
  score: s.conf.score == null ? '—' : s.conf.score,
  band: s.conf.band,
  status: s.conf.status,
  rec: s.rel.tag === rec ? '★' : '',
  reason: s.conf.reason,
})));
console.log(`\nRecommended: ${rec}`);
