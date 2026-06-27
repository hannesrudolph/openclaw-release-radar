// Offline validation of the REAL new scoring path against the real DB. Mirrors the
// scoring block in refresh.ts but reads existing classifications (no network/LLM).
// Confirms score.ts + the next-stable reign SQL produce the expected verdicts.
import { DatabaseSync } from 'node:sqlite';
import { cveDecayLoad, feltLoad, installConfidence, openDebtLoad, pickRecommended } from '../src/lib/score.ts';
import {
  labelsForIssueAt, listReleasesDb, openedDuringReign, issueCountForVersion, issuesForVersion, listAdvisories, verifiedFixedForRelease,
} from '../src/lib/db.ts';
import { computeHoursToNextStable, hasHotfixSuccessor } from '../src/lib/releaseNotes.ts';
import { matchesRange, stableDistance } from '../src/lib/versionMatch.ts';
import { applyLabelOverrides, applyTitleFunctionalityHint, applyTitleIssueShapeHint } from '../src/lib/labelOverrides.ts';

const db = new DatabaseSync('./data/radar.db');
const allRel = db.prepare(
  `SELECT tag, published_at, prerelease FROM releases ORDER BY published_at DESC`
).all().map(r => ({ tag: r.tag, published_at: r.published_at, prerelease: r.prerelease === 1 }));
const commitStmt = db.prepare(`SELECT * FROM release_commits WHERE tag=?`);
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
const classify = (r, labels=safeLabels(r.labels))=>applyTitleIssueShapeHint(applyLabelOverrides(applyTitleFunctionalityHint(rowToCls(r), r.title), labels), r.title, labels);
const isCoreSerious = (c)=>c.sentiment==='negative'&&c.functionality==='core'&&(c.severity==='critical'||c.severity==='high');
const labelCutoff = (rel) => rel.published_at && rel.hours_to_next_release != null
  ? new Date(Date.parse(rel.published_at) + rel.hours_to_next_release * 3_600_000).toISOString()
  : null;

const releases = listReleasesDb(10);
const scored = releases.map((rel, idx) => {
  const attributed = issuesForVersion(rel.tag);
  const relStart = rel.published_at ? Date.parse(rel.published_at) : NaN;
  const fixed = verifiedFixedForRelease(rel.tag);
  const fixedNumbers = new Set(fixed.map(r => r.number));
  const cutoff = labelCutoff(rel);
  const labelsFor = r => labelsForIssueAt(r.number, safeLabels(r.labels), cutoff);
  const classifyAt = r => classify(r, labelsFor(r));
  const countCS = (rows)=>rows.reduce((n,r)=>isCoreSerious(classifyAt(r))?n+1:n,0);
  const scoreState = r => fixedNumbers.has(r.number) ? 'closed' : (r.state === 'open' ? 'open' : 'closed-unverified');
  const scoredIssue = r => ({
    ...classifyAt(r),
    issueNumber: r.number,
    duplicateCluster: r.duplicate_cluster,
    author: r.author,
    authorAssociation: r.author_association,
    isBot: r.is_bot,
    comments: r.comments,
    uniqueHumanCommenterCount: r.unique_human_commenters,
    maintainerCommenterCount: r.maintainer_commenters,
    contributorCommenterCount: r.contributor_commenters,
    commenterScanTruncated: r.commenter_scan_truncated,
    reactionTotal: r.reaction_total,
    positiveReactionCount: r.positive_reactions,
    labels: labelsFor(r),
  });
  const debt = openDebtLoad(attributed.map(r => ({ ...scoredIssue(r), issueNumber: r.number, state: scoreState(r), createdAt: r.created_at, updatedAt: r.updated_at, affectsVersion: r.affects_version, releaseLocal: Number.isFinite(relStart) ? Date.parse(r.created_at) >= relStart : false })));
  const commit = commitStmt.get(rel.tag);
  const conf = installConfidence({
    publishedAt: rel.published_at,
    isLatest: idx === 0,
    hoursToNextStable: computeHoursToNextStable(allRel, rel.tag),
    hasHotfixSuccessor: hasHotfixSuccessor(allTags, rel.tag),
    betaCount: rel.beta_count,
    breakingCount: rel.breaking_count,
    feltOpenedWeight: feltLoad(openedDuringReign(rel.tag).map(scoredIssue)),
    feltClosedWeight: feltLoad(verifiedFixedForRelease(rel.tag).map(scoredIssue)),
    verifiedDebtWeight: debt.verified,
    carryoverDebtWeight: debt.carryover,
    staleDebtWeight: debt.stale,
    rawIssueCount: issueCountForVersion(rel.tag),
    classifiedIssueCount: attributed.length,
    cveAffected: cveFor(rel.tag).affected,
    cveLoad: cveFor(rel.tag).load,
    releaseCheckState: commit?.check_state ?? null,
    releaseCheckTotal: commit?.check_total ?? 0,
    releaseCheckSuccess: commit?.check_success ?? 0,
    releaseCheckFailure: commit?.check_failure ?? 0,
    releaseCheckPending: commit?.check_pending ?? 0,
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
