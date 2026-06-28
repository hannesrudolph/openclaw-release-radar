import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REC_THRESHOLD } from './score.ts';
import { CLOSURE_PROOF_STATUSES, CLOSURE_RISK_DISPOSITIONS } from './closureProofTaxonomy.ts';

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

  it('install wording does not overclaim safety', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.doesNotMatch(html, /release looks safe to install|No safe target|broadly safe/i);
    assert.match(html, /if \(local\?\.recommended\)[\s\S]*recommended install candidate under the audit gates/);
    assert.match(html, /local\?\.status === 'eligible'[\s\S]*passed hard install gates/);
  });

  it('empty watchIssues does not hide capped issue evidence', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /Array\.isArray\(detail\?\.watchIssues\) && detail\.watchIssues\.length/);
    assert.doesNotMatch(html, /if \(Array\.isArray\(detail\?\.watchIssues\)\) return detail\.watchIssues/);
  });

  it('score explanation prefers backend audit text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /local\?\.components\?\.explanation/);
    assert.match(html, /structured\.limits/);
    assert.match(html, /structured\.limitDetails/);
    assert.match(html, /scoreDetailIssueRefsHtml/);
    assert.match(html, /scoreDetailIssueProofHtml/);
    assert.match(html, /scoreDetailMetricsHtml/);
    assert.match(html, /scoreDetailBucketsHtml/);
    assert.match(html, /score-explain__proof/);
    assert.match(html, /Object\.entries\(value\)/);
    assert.match(html, /\.slice\(0,\s*14\)/);
  });

  it('frontend closure proof labels cover backend statuses and risk dispositions', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    CLOSURE_PROOF_STATUSES.forEach((status) =>
      assert.match(html, new RegExp(`${status}:`), `missing frontend closure label for ${status}`));
    CLOSURE_RISK_DISPOSITIONS.forEach((disposition) =>
      assert.match(html, new RegExp(`${disposition}:`), `missing frontend closure risk label for ${disposition}`));
    assert.match(html, /resolvedByCanonicalReleaseFixCount/);
    assert.match(html, /resolvedByReleaseFixProofCount/);
    assert.match(html, /neutralHighImpactCount/);
    assert.match(html, /neutralBugShapedCount/);
    assert.match(html, /closureProofExamplesWithStatusCoverage/);
    assert.match(html, /examplesByStatus/);
    assert.match(html, /Non-actionable rationale:/);
  });

  it('release audit verifier uses shared closure proof taxonomy', () => {
    const verifier = readFileSync(join(root, 'scripts/lib/release-audit-invariants.mjs'), 'utf8');
    assert.match(verifier, /closureProofTaxonomy\.ts/);
    assert.match(verifier, /new Set\(CLOSURE_PROOF_STATUSES\)/);
    assert.match(verifier, /Object\.entries\(CLOSURE_RISK_DISPOSITION_BY_STATUS\)/);
    assert.doesNotMatch(verifier, /'fixed_in_release'[\s\S]*'unknown'[\s\S]*\]\);/);
  });

  it('issue title truncation is word-boundary aware in the UI fallback', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function truncateAtWordBoundary/);
    assert.doesNotMatch(html, /slice\(0,\s*85\)/);
    assert.match(html, /untitled report/);
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
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.equal(pkg.scripts['verify:score'], 'tsx scripts/verify-new-scoring.mjs --check');
    assert.equal(pkg.scripts['verify:scripts'], 'for f in scripts/*.mjs scripts/lib/*.mjs; do node --check "$f"; done');
    assert.equal(pkg.scripts['verify:ci'], 'npm run typecheck && npm test && npm run verify:scripts && npm run build');
    assert.equal(pkg.scripts['verify:local'], 'npm run verify:score -- --all && npm run verify:release-audit -- --all');
    assert.equal(pkg.scripts['verify:live'], 'npm run verify:score -- --all && npm run verify:release-audit -- --all --api-base http://127.0.0.1:8787 && npm run ui:smoke');
    assert.match(verifier, /buildReleaseScoreRun/);
    assert.match(verifier, /RADAR_DB_READ_ONLY = '1'/);
    assert.match(verifier, /verifyScoredReleaseCoverage/);
    assert.match(verifier, /SCORE_MODEL_VERSION/);
    assert.match(verifier, /PROMPT_VERSION/);
    assert.match(verifier, /complete classification coverage/);
    assert.match(verifier, /release scored_at/);
    assert.match(verifier, /audit issue_evidence_json/);
    assert.match(verifier, /audit gate_evidence_json/);
    assert.match(verifier, /--all/);
    assert.doesNotMatch(verifier, /function scoreRelease\(/);
    assert.match(verifier, /scoredAtMillis/);
    assert.match(verifier, /process\.exit\(1\)/);
    assert.match(dbModule, /export const dbReadOnly/);
    assert.match(dbModule, /readOnly: true/);
    assert.match(dbModule, /PRAGMA query_only = ON/);
    assert.match(readme, /npm run verify:ci/);
    assert.match(readme, /npm run verify:scripts/);
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

  it('legacy fix provenance ingestion runs the full proof pipeline', () => {
    const script = readFileSync(join(root, 'scripts/ingest-fix-provenance.mjs'), 'utf8');
    assert.match(script, /releaseTagArg/);
    assert.match(script, /await import\('\.\.\/src\/lib\/closureProofAnalysis\.ts'\)/);
    assert.match(script, /refreshClosureEvidenceForRelease/);
    assert.match(script, /checkReleasePrReachability/);
    assert.match(script, /analyzeClosureProofsForRelease/);
    assert.doesNotMatch(script, /listIssueFixEvidenceBatch/);
    assert.doesNotMatch(script, /upsertIssueClosureEvent/);
  });

  it('single-release proof scripts validate release tags before loading DB writers', () => {
    const helper = readFileSync(join(root, 'scripts/lib/release-tag-arg.mjs'), 'utf8');
    assert.match(helper, /--help/);
    assert.match(helper, /startsWith\('-'\)/);
    for (const file of [
      'scripts/analyze-closure-proofs.mjs',
      'scripts/ingest-fix-provenance.mjs',
      'scripts/check-release-pr-reachability.mjs',
    ]) {
      const script = readFileSync(join(root, file), 'utf8');
      assert.match(script, /releaseTagArg\(process\.argv\.slice\(2\)/, `${file} must validate args first`);
      assert.doesNotMatch(script, /^import \{ .* \} from '\.\.\/src\/lib\//m, `${file} must not statically import DB/network modules`);
      assert.match(script, /await import\('\.\.\/src\/lib\//, `${file} should dynamically import DB/network modules after validation`);
    }
  });

  it('closed-window backfill classifies raw closed gaps and reruns proof pipeline', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const script = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    assert.equal(pkg.scripts['backfill:closed-windows'], 'tsx scripts/backfill-closed-windows.mjs');
    assert.match(script, /listIssuesBatch/);
    assert.match(script, /classifyIssue/);
    assert.match(script, /refreshClosureEvidenceForRelease/);
    assert.match(script, /checkReleasePrReachability/);
    assert.match(script, /analyzeClosureProofsForRelease/);
    assert.match(script, /persistReleaseScoreRun/);
  });

  it('closure proof analysis checks direct commit closers for release reachability', () => {
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    assert.match(analysis, /direct_closer_commits/);
    assert.match(analysis, /e\.closer_type='Commit'/);
    assert.match(analysis, /directClosureCommitMentions/);
    assert.match(analysis, /GitHub ClosedEvent closer commit/);
    assert.match(analysis, /ReferencedEvent\.commit/);
    assert.match(analysis, /commitReferenceMentionsByIssue/);
    assert.match(github, /REFERENCED_EVENT/);
    assert.match(github, /\.\.\. on ReferencedEvent/);
    assert.match(analysis, /allCommitOids\.add\(commitOid\.toLowerCase\(\)\)/);
  });

  it('PR reachability covers related merged PR evidence, not only credited closing links', () => {
    const reachability = readFileSync(join(root, 'src/lib/releaseReachability.ts'), 'utf8');
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    assert.match(reachability, /JOIN issue_pr_links l/);
    assert.match(reachability, /WHERE p\.merged = 1/);
    assert.doesNotMatch(reachability, /creditedFixLinkSql/);
    assert.match(analysis, /refreshClosureCommentPrMentionEvidence/);
    assert.match(analysis, /await checkReleasePrReachability\(releaseTag\);/);
  });

  it('refresh fetches label timelines for all monitored-window issues', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /const monitoredIssueNumbers = page[\s\S]*?issueOverlapsMonitoredWindow\(issue\)[\s\S]*?issue\.number/);
    assert.match(refresh, /listIssueLabelEventsBatch\(monitoredIssueNumbers\)/);
    assert.match(refresh, /listIssueFixEvidenceBatch\(monitoredIssueNumbers\)/);
    assert.match(refresh, /persistIssueStateEvidence\(stateEvidence\)/);
    assert.doesNotMatch(refresh, /issue\.labels\.length/);
  });

  it('docs avoid hardcoded current score snapshots and document explanation details', () => {
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const scoreModel = readFileSync(join(root, 'src/lib/score.ts'), 'utf8')
      .match(/SCORE_MODEL_VERSION = '([^']+)'/)?.[1];
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.doesNotMatch(scoringDoc, /Current `v20\d{2}\.\d+\.\d+` Snapshot/);
    assert.doesNotMatch(scoringDoc, /Score:\s*`[0-9.]+`/);
    assert.ok(scoreModel);
    assert.match(scoringDoc, new RegExp(`Current model: \`${scoreModel}\``));
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
    assert.match(scorer, /export const SCORE_INPUT_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const SCORE_COMPONENTS_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const SCORE_EXPLANATION_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const GATE_EVIDENCE_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const ISSUE_EVIDENCE_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const LABEL_TIMELINE_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const RELEASE_CHECKS_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const ARTIFACT_VERIFICATION_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const SCORE_EXPLANATION_LIMIT_CODES/);
    assert.match(scorer, /export const SCORE_EXPLANATION_POSITIVE_CODES/);
  });

  it('public issue summaries use effective scoring classifications', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    assert.match(api, /PUBLIC_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 1/);
    assert.match(api, /LOCAL_AUDIT_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_UPSTREAM_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_DELTA_SCHEMA_VERSION = 1/);
    assert.match(api, /STATUS_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /CONFIG_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /RELEASE_ROW_SCHEMA_VERSION = 1/);
    assert.match(api, /RELEASE_HISTORY_ROW_SCHEMA_VERSION = 1/);
    assert.match(api, /PUBLIC_RELEASE_SCHEMA_VERSION = 1/);
    assert.match(api, /function publicCacheKey/);
    assert.match(api, /releaseScoreAuditFreshness/);
    assert.match(api, /freshness\.max_scored_at/);
    assert.match(api, /freshness\.count/);
    assert.match(api, /freshness\.digest/);
    assert.match(api, /classifyIssueRowWithLabels/);
    assert.match(api, /labelsForIssueAt/);
    assert.match(api, /releaseLabelCutoff\(r,\s*audit\?\.scored_at/);
    assert.match(api, /useSnapshotWhenNoEvents:\s*labelCutoff != null/);
    assert.match(api, /comparePublicIssueSignal/);
    assert.match(api, /sort\(comparePublicIssueSignal\)/);
    assert.match(api, /classification\.severity/);
    assert.match(api, /affectedUsers:\s+classification\.affectedUsers/);
    assert.doesNotMatch(api, /SEVERITY_RANK\[a\.severity\]/);
  });
});
