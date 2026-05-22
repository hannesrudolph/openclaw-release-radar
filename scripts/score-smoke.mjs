// Sanity test for the scoring algorithm. Run after `npm run build`:
//   node scripts/score-smoke.mjs
import { scoreRelease } from '../dist/lib/score.js';

const now = Date.now();
const daysAgo = (n) => new Date(now - n * 86400000).toISOString();

function mkIssue({ number = 0, updatedAt = daysAgo(2), commentCount = 2, classification = {} } = {}) {
  return {
    number,
    updatedAt,
    commentCount,
    classification: {
      sentiment: 'negative',
      severity: 'medium',
      scope: 'moderate',
      functionality: 'integration',
      affectedUsers: 'some',
      hasWorkaround: false,
      duplicateCluster: null,
      affectsVersion: null,
      confidence: 0.8,
      rationale: '',
      ...classification,
    },
  };
}

const cases = [
  ['only-positive', [mkIssue({ classification: { sentiment: 'positive' } })]],
  ['low-doc-bug',   [mkIssue({ classification: {
      severity: 'low', functionality: 'docs', scope: 'niche',
      affectedUsers: 'few', hasWorkaround: true } })]],
  ['two-criticals-same-cluster', [
    mkIssue({ number: 1, commentCount: 12, classification: {
      severity: 'critical', scope: 'broad', functionality: 'core',
      affectedUsers: 'many', confidence: 0.9, duplicateCluster: 'ollama-timeout' } }),
    mkIssue({ number: 2, commentCount: 4, classification: {
      severity: 'critical', scope: 'broad', functionality: 'core',
      affectedUsers: 'many', confidence: 0.9, duplicateCluster: 'ollama-timeout' } }),
  ]],
];

for (const [name, issues] of cases) {
  const r = scoreRelease(issues, now);
  console.log(`${name.padEnd(28)} score=${r.finalScore}  risk=${r.riskIndex}  neg=${r.negativeIssues}  pos=${r.positiveIssues}`);
}
