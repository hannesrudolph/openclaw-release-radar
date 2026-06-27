import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REC_THRESHOLD } from './score.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

describe('static scoring/UI contracts', () => {
  it('does not hardcode a stale recommendation threshold in UI text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.doesNotMatch(html, /newest eligible\s*(?:≥|>=)\s*7/i);
    assert.equal(REC_THRESHOLD, 5.5);
  });

  it('homepage install command only uses server-recommended releases', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function pickRecommendedRelease\(rows\)[\s\S]*?rows\.find\(\(r\) => r\.recommended\) \?\? null;/);
    assert.doesNotMatch(html, /rows\.find\(\(r\) => r\.status === 'eligible' && r\.finalScore != null\)/);
  });

  it('score color helper keeps weak scores below caution threshold', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /if \(n >= 5\.5\) return 'var\(--warn\)'/);
    assert.doesNotMatch(html, /if \(n >= 5\) return 'var\(--warn\)'/);
  });

  it('safe-to-install wording is limited to recommended releases', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /if \(local\?\.recommended\)[\s\S]*release looks safe to install/);
    assert.match(html, /local\?\.status === 'eligible'[\s\S]*passed hard install gates/);
  });

  it('score explanation prefers backend audit text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /local\?\.components\?\.explanation/);
    assert.match(html, /structured\.limits/);
  });

  it('issue title truncation is word-boundary aware in the UI fallback', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function truncateAtWordBoundary/);
    assert.doesNotMatch(html, /slice\(0,\s*85\)/);
  });

  it('legacy public snapshot import requires explicit overwrite flag before loading app DB', () => {
    const script = readFileSync(join(root, 'scripts/import-public-snapshot.mjs'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(script, /--allow-overwrite-local-releases/);
    assert.doesNotMatch(script, /^import \{ db, setMeta \} from '\.\.\/src\/lib\/db\.ts';/m);
    assert.match(script, /await import\('\.\.\/src\/lib\/db\.ts'\)/);
    assert.match(script, /final_score: null/);
    assert.match(script, /recommended: 0/);
    assert.match(script, /localScoresImported: false/);
    assert.doesNotMatch(script, /nullableNumber\(release\.score\)/);
    assert.match(readme, /external scores\/recommendations are not treated as local audit-backed scores/);
  });

  it('score verifier is wired as a hard drift check', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const verifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.equal(pkg.scripts['verify:score'], 'tsx scripts/verify-new-scoring.mjs --check');
    assert.equal(pkg.scripts['verify:ci'], 'npm run typecheck && npm test && npm run build');
    assert.equal(pkg.scripts['verify:local'], 'npm run verify:score && npm run verify:release-audit');
    assert.equal(pkg.scripts['verify:live'], 'npm run verify:score && npm run verify:release-audit -- --api-base http://127.0.0.1:8787 && npm run ui:smoke');
    assert.match(verifier, /buildReleaseScoreRun/);
    assert.doesNotMatch(verifier, /function scoreRelease\(/);
    assert.match(verifier, /scoredAtMillis/);
    assert.match(verifier, /process\.exit\(1\)/);
    assert.match(readme, /npm run verify:ci/);
    assert.match(readme, /npm run verify:local/);
    assert.match(readme, /npm run verify:live/);
  });

  it('deploy workflow runs the CI verification gate', () => {
    const workflow = readFileSync(join(root, '.github/workflows/deploy-radar.yml'), 'utf8');
    assert.match(workflow, /npm run verify:ci/);
    assert.doesNotMatch(workflow, /run: npm run typecheck/);
    assert.doesNotMatch(workflow, /name: Build app[\s\S]*?run: npm run build/);
  });

  it('offline score writers use the shared release scorer', () => {
    const populate = readFileSync(join(root, 'scripts/populate-db.mjs'), 'utf8');
    assert.match(populate, /buildReleaseScoreRun/);
    assert.match(populate, /persistReleaseScoreRun/);
    assert.doesNotMatch(populate, /installConfidence/);
    assert.doesNotMatch(populate, /openDebtLoad/);
    assert.doesNotMatch(populate, /feltLoad/);
  });

  it('docs avoid hardcoded current score snapshots and document explanation details', () => {
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.doesNotMatch(scoringDoc, /Current `v20\d{2}\.\d+\.\d+` Snapshot/);
    assert.doesNotMatch(scoringDoc, /Score:\s*`[0-9.]+`/);
    assert.match(scoringDoc, /components\.explanation/);
    assert.match(scoringDoc, /schemaVersion/);
    assert.match(scoringDoc, /positiveDetails/);
    assert.match(scoringDoc, /limitDetails/);
    assert.match(readme, /structured `explanation` object/);
    assert.match(readme, /Current value: `1`/);
    assert.match(readme, /stable reason `code`/);
  });

  it('explanation reason-code exports remain public', () => {
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    assert.match(scorer, /export const SCORE_EXPLANATION_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const SCORE_EXPLANATION_LIMIT_CODES/);
    assert.match(scorer, /export const SCORE_EXPLANATION_POSITIVE_CODES/);
  });
});
