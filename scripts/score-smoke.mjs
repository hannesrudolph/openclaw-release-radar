// Sanity smoke for the Install Confidence model. Run after `npm run build`:
//   node scripts/score-smoke.mjs
import { installConfidence, pickRecommended } from '../dist/lib/score.js';

const now = Date.now();
const daysAgo = (n) => new Date(now - n * 86400000).toISOString();

function mk(over = {}) {
  return {
    publishedAt: daysAgo(10),
    isLatest: false,
    hoursToNextStable: 24,
    hasHotfixSuccessor: false,
    betaCount: 0,
    breakingCount: 0,
    feltOpenedWeight: 0,
    feltClosedWeight: 0,
    verifiedDebtWeight: 0,
    carryoverDebtWeight: 0,
    staleDebtWeight: 0,
    rawIssueCount: 0,
    classifiedIssueCount: 0,
    cveAffected: false,
    cveLoad: 0,
    ...over,
  };
}

const cases = [
  ['cve (light load)', mk({ cveAffected: true, cveLoad: 3 })],
  ['cve (heavy load)', mk({ cveAffected: true, cveLoad: 40 })],
  ['too-new',          mk({ publishedAt: daysAgo(0.2) })],
  ['hotfixed (-N)',    mk({ hasHotfixSuccessor: true })],
  ['typical ~24h',     mk()],
  ['stood 4d + betas', mk({ hoursToNextStable: 96, betaCount: 10 })],
  ['net-breaking vis', mk({ feltOpenedWeight: 40, feltClosedWeight: 8 })],
  ['latest, 3d',       mk({ isLatest: true, hoursToNextStable: null, publishedAt: daysAgo(3) })],
];

const scored = cases.map(([name, input]) => ({ name, ...installConfidence(input, now) }));
for (const s of scored) {
  console.log(`${s.name.padEnd(18)} score=${String(s.score).padEnd(4)} band=${String(s.band).padEnd(8)} status=${s.status}`);
}
const rec = pickRecommended(scored.map((s) => ({ tag: s.name, status: s.status, score: s.score })));
console.log(`\nrecommended → ${rec}`);
