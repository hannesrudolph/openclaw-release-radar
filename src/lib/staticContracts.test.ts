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

  it('public payload cache stores under the key used for lookup', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    assert.match(api, /const cacheKey = publicCacheKey\(\);[\s\S]*setCached\(data, cacheKey\);/);
    assert.doesNotMatch(api, /setCached\(data, publicCacheKey\(\)\)/);
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
    assert.doesNotMatch(html, /Each update is now scored for the way you use it/);
    assert.doesNotMatch(html, /My install score is active/);
    assert.match(html, /profile-adjusted estimate beside the audited global score/);
    assert.match(html, /audited global score remains the source of truth/);
    assert.match(html, /capped local estimate layered on the global audited score/);
  });

  it('empty watchIssues does not hide capped issue evidence', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /Array\.isArray\(detail\?\.watchIssues\) && detail\.watchIssues\.length/);
    assert.doesNotMatch(html, /if \(Array\.isArray\(detail\?\.watchIssues\)\) return detail\.watchIssues/);
  });

  it('score explanation prefers backend audit text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(html, /local\?\.components\?\.explanation/);
    assert.match(html, /structured\.limits/);
    assert.match(html, /structured\.limitDetails/);
    assert.match(html, /scoreDetailIssueRefsHtml/);
    assert.match(html, /scoreDetailIssueProofHtml/);
    assert.match(html, /scoreDetailMetricsHtml/);
    assert.match(html, /scoreDetailBucketsHtml/);
    assert.match(html, /issueScoringMetaHtml/);
    assert.match(html, /issueEvidenceRowForIssue/);
    assert.match(html, /Scored as \$\{tier\} risk/);
    assert.match(html, /scoreLedgerHtml/);
    assert.match(html, /scoreDriversHtml/);
    assert.match(html, /Score drivers:/);
    assert.match(html, /score-ledger/);
    assert.match(html, /score-explain__proof/);
    assert.match(html, /issueEvidenceApiLinksHtml/);
    assert.match(html, /\/review\/issues/);
    assert.match(html, /tier=carryoverDebt/);
    assert.match(html, /fieldConfirmed=true/);
    assert.match(html, /severity=critical/);
    assert.match(html, /functionality=core/);
    assert.match(html, /sort=weight/);
    assert.match(html, /tier=staleDebt/);
    assert.match(html, /high-weight stale evidence/);
    assert.match(html, /tier=openedFeltSerious/);
    assert.match(html, /Non-verified/);
    assert.match(html, /Non-verified open risk means open negative issues/);
    const issueEvidence = readFileSync(join(root, 'src/lib/releaseIssueEvidence.ts'), 'utf8');
    assert.match(issueEvidence, /RELEASE_ISSUE_EVIDENCE_TIER_INFO/);
    assert.match(issueEvidence, /summaryByTier/);
    assert.match(issueEvidence, /summarizeIssueEvidenceRows/);
    assert.match(issueEvidence, /Open non-verified risk/);
    assert.match(issueEvidence, /not proven release-local field blockers/);
    assert.match(readme, /\/api\/releases\/:tag\/review\/issues/);
    assert.match(readme, /Paginated current-DB issue-evidence rows/);
    assert.match(readme, /`sourceMode`/);
    assert.match(readme, /`dataFreshness`/);
    assert.match(readme, /comma-separated `tier`/);
    assert.match(readme, /`impact`/);
    assert.match(readme, /`state`/);
    assert.match(readme, /`sentiment`/);
    assert.match(readme, /`severity`/);
    assert.match(readme, /`functionality`/);
    assert.match(readme, /`scope`/);
    assert.match(readme, /`affectedUsers`/);
    assert.match(readme, /`fieldConfirmed`/);
    assert.match(readme, /`minWeight`/);
    assert.match(readme, /`maxWeight`/);
    assert.match(readme, /`sort`/);
    assert.match(readme, /`direction`/);
    assert.match(readme, /`summaryOnly`/);
    assert.match(readme, /summaryByTier/);
    assert.match(readme, /filteredSummary/);
    assert.match(readme, /filteredCountsByTier/);
    assert.match(readme, /filteredSummaryByTier/);
    assert.match(readme, /`totals`/);
    assert.match(html, /Source freshness/);
    assert.match(html, /dataFreshnessText/);
    assert.match(html, /Object\.entries\(value\)/);
    assert.match(html, /\.slice\(0,\s*14\)/);
  });

  it('frontend closure proof labels cover backend statuses and risk dispositions', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const payload = readFileSync(join(root, 'src/lib/closureProofPayload.ts'), 'utf8');
    CLOSURE_PROOF_STATUSES.forEach((status) =>
      assert.match(html, new RegExp(`${status}:`), `missing frontend closure label for ${status}`));
    CLOSURE_RISK_DISPOSITIONS.forEach((disposition) =>
      assert.match(html, new RegExp(`${disposition}:`), `missing frontend closure risk label for ${disposition}`));
    assert.match(payload, /CLOSURE_PROOF_STATUS_RANK/);
    assert.match(payload, /satisfies Record<ClosureProofStatus, number>/);
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
    const routeTest = readFileSync(join(root, 'src/lib/apiRoutes.test.ts'), 'utf8');
    assert.match(verifier, /closureProofTaxonomy\.ts/);
    assert.match(verifier, /releaseScoring\.ts/);
    assert.match(verifier, /releaseRowKeys/);
    assert.match(verifier, /releaseHistoryRowKeys/);
    assert.match(verifier, /issueEvidenceAuditKeys/);
    assert.match(verifier, /closureProofAuditRowKeys/);
    assert.match(verifier, /reachabilityAuditRowKeys/);
    assert.match(verifier, /SCORE_INPUT_SCHEMA_VERSION/);
    assert.match(verifier, /SCORE_COMPONENTS_SCHEMA_VERSION/);
    assert.match(verifier, /GATE_EVIDENCE_SCHEMA_VERSION/);
    assert.match(verifier, /ISSUE_EVIDENCE_SCHEMA_VERSION/);
    assert.match(verifier, /LABEL_TIMELINE_SCHEMA_VERSION/);
    assert.match(verifier, /RELEASE_CHECKS_SCHEMA_VERSION/);
    assert.match(verifier, /ARTIFACT_VERIFICATION_SCHEMA_VERSION/);
    assert.match(verifier, /new Set\(CLOSURE_PROOF_STATUSES\)/);
    assert.match(verifier, /Object\.entries\(CLOSURE_RISK_DISPOSITION_BY_STATUS\)/);
    assert.match(verifier, /expectFetchJsonStatus/);
    assert.match(verifier, /invalid tier/);
    assert.match(verifier, /invalid fieldConfirmed/);
    assert.match(verifier, /invalid weight range/);
    assert.match(verifier, /invalid sort/);
    assert.match(verifier, /invalid direction/);
    assert.match(verifier, /invalid summaryOnly/);
    assert.match(verifier, /invalid status/);
    assert.match(verifier, /invalid riskDisposition/);
    assert.match(routeTest, /applies issue evidence filters/);
    assert.match(routeTest, /summaryOnly=true/);
    assert.match(routeTest, /status=fixed_after_release&riskDisposition=known_not_in_release/);
    assert.match(routeTest, /pr=OpenClaw\/OpenClaw%23123/);
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
    assert.equal(pkg.scripts['verify:local'], 'npm run doctor -- --fail-on-warnings && npm run verify:score -- --all && npm run verify:release-audit -- --all');
    assert.equal(pkg.scripts['verify:live'], 'npm run doctor -- --fail-on-warnings --api-base http://127.0.0.1:8787 && npm run verify:score -- --all && npm run verify:release-audit -- --all --api-base http://127.0.0.1:8787 && npm run ui:smoke');
    assert.equal(pkg.scripts.doctor, 'tsx scripts/doctor.mjs');
    const doctor = readFileSync(join(root, 'scripts/doctor.mjs'), 'utf8');
    const doctorHealth = readFileSync(join(root, 'scripts/lib/doctor-health.mjs'), 'utf8');
    assert.match(doctor, /readOnly: true/);
    assert.match(doctor, /PRAGMA query_only = ON/);
    assert.match(doctor, /closure proof rows/);
    assert.match(doctor, /expected exactly one recommended scored stable release/);
    assert.match(doctor, /no audited stable release found/);
    assert.match(doctorHealth, /classificationFailures/);
    assert.match(doctor, /failOnWarnings/);
    assert.match(doctor, /fail-on-warnings/);
    assert.match(doctor, /api-base/);
    assert.match(doctor, /api public recommended tag/);
    assert.match(doctor, /api status lastScoredAt/);
    assert.match(verifier, /buildReleaseScoreRun/);
    assert.match(verifier, /verifyScoreAuditPayloadContracts/);
    assert.match(verifier, /RADAR_DB_READ_ONLY = '1'/);
    assert.match(verifier, /verifyScoredReleaseCoverage/);
    assert.match(verifier, /SCORE_MODEL_VERSION/);
    assert.match(verifier, /PROMPT_VERSION/);
    assert.match(verifier, /SCORE_INPUT_SCHEMA_VERSION/);
    assert.match(verifier, /SCORE_COMPONENTS_SCHEMA_VERSION/);
    assert.match(verifier, /ISSUE_EVIDENCE_SCHEMA_VERSION/);
    assert.match(verifier, /GATE_EVIDENCE_SCHEMA_VERSION/);
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
    assert.match(readme, /npm run doctor/);
    assert.match(readme, /classification failures/);
    assert.match(readme, /release-metadata\/artifact\/release-check\/advisory\/monitored-release evidence refresh failures/);
    assert.match(readme, /durable `ingestion_evidence_failures` rows/);
    assert.match(readme, /Release metadata, artifact verification, release commit checks, and security advisories are score-affecting evidence/);
    assert.match(readme, /stopReason: "evidence_failure"/);
    assert.match(readme, /recover only when the caller provides an explicit missing-alias reporter/);
    assert.match(readme, /Other callers fail closed/);
    assert.match(readme, /malformed nested evidence connections/);
    assert.match(readme, /hasNextPage` without `endCursor/);
    assert.match(readme, /newest audited stable release/);
    assert.match(readme, /null-score `wait` rows/);
    assert.match(readme, /local\.sourceProvenance/);
    assert.match(readme, /--fail-on-warnings/);
    assert.match(readme, /read-only SQLite health report/);
  });

  it('deploy workflow runs the CI verification gate', () => {
    const workflow = readFileSync(join(root, '.github/workflows/deploy-radar.yml'), 'utf8');
    assert.match(workflow, /npm run verify:ci/);
    assert.doesNotMatch(workflow, /run: npm run typecheck/);
    assert.doesNotMatch(workflow, /name: Build app[\s\S]*?run: npm run build/);
  });

  it('offline score writers use the shared release scorer', () => {
    const populate = readFileSync(join(root, 'scripts/populate-db.mjs'), 'utf8');
    const backfill = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    const verifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const bridgeTest = readFileSync(join(root, 'src/lib/releaseScoringDbBridge.test.ts'), 'utf8');
    assert.match(populate, /buildReleaseScoreRun/);
    assert.match(populate, /const initialMonitored = listReleasesDb\(10\);\s*assertCleanIngestionMetadataBeforeScore\(initialMonitored\);/);
    assert.match(populate, /const setStableGap/);
    assert.ok(
      populate.indexOf('assertCleanIngestionMetadataBeforeScore(initialMonitored)') < populate.indexOf('const setStableGap'),
      'populate-db must validate ingestion metadata before preparing DB mutations',
    );
    assert.match(populate, /persistReleaseScoreRun/);
    assert.doesNotMatch(populate, /new DatabaseSync/);
    assert.match(backfill, /buildReleaseScoreRun/);
    assert.match(backfill, /assertCleanIngestionMetadataBeforeScore\(releases\)/);
    assert.match(backfill, /persistReleaseScoreRun/);
    assert.match(populate, /score-ingestion-guard\.mjs/);
    assert.match(backfill, /score-ingestion-guard\.mjs/);
    assert.doesNotMatch(populate, /installConfidence/);
    assert.doesNotMatch(populate, /openDebtLoad/);
    assert.doesNotMatch(populate, /feltLoad/);
    for (const script of [populate, backfill, verifier]) {
      assert.doesNotMatch(script, /stableTagsNewestFirst\s*=/);
      assert.doesNotMatch(script, /allFetchedTags\s*=/);
    }
    assert.match(bridgeTest, /buildReleaseScoreRun/);
    assert.match(bridgeTest, /verifiedDebtWeight/);
    assert.match(bridgeTest, /unresolvedClosureRiskWeight/);
    assert.match(bridgeTest, /unclassified release issue/);
    assert.match(bridgeTest, /malformed advisory vulnerable_version_range/);
    assert.match(scorer, /assertReleaseScoreRunPersistable/);
    assert.match(scorer, /assertAdvisoryRangesParseable/);
    assert.match(scorer, /isRangeParseable/);
    assert.match(scorer, /complete classification coverage/);
    assert.match(scorer, /runInWriteTransaction/);
    assert.match(bridgeTest, /FOREIGN KEY constraint failed/);
    assert.match(bridgeTest, /getReleaseScoreAudit\('v-tx'\), undefined/);
    assert.match(bridgeTest, /persistReleaseScoreRun/);
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

  it('issue-state backfill fetches evidence before writing rows', () => {
    const script = readFileSync(join(root, 'scripts/backfill-issue-state-events.mjs'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.match(script, /insertIngestionEvidenceFailure/);
    assert.match(script, /recordBackfillEvidenceFailure/);
    assert.match(script, /onMissingIssueAlias/);
    assert.match(script, /const evidenceByIssue = new Map/);
    assert.ok(
      script.indexOf('const evidenceByIssue = new Map') < script.indexOf('snapshotCurrentLabels(issueNumbers, snapshotAt)'),
      'issue-state backfill must fetch all evidence before snapshot writes',
    );
    assert.match(readme, /fetches all GitHub state evidence before writing snapshots\/events/);
    assert.match(scoringDoc, /manual state backfills cannot leave partial evidence/);
  });

  it('closed-window backfill classifies raw closed gaps and reruns proof pipeline', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const script = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    const guard = readFileSync(join(root, 'scripts/lib/score-ingestion-guard.mjs'), 'utf8');
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    assert.equal(pkg.scripts['backfill:closed-windows'], 'tsx scripts/backfill-closed-windows.mjs');
    assert.match(script, /listIssuesBatch/);
    assert.match(script, /classifyIssue/);
    assert.match(script, /refreshClosureEvidenceForRelease/);
    assert.match(script, /checkReleasePrReachability/);
    assert.match(script, /analyzeClosureProofsForRelease/);
    assert.match(script, /assertCleanIngestionMetadataBeforeScore\(releases\)/);
    assert.match(guard, /getMeta\('issue_crawl_last_run'\)/);
    assert.match(guard, /ingestionEvidenceFailuresAfter/);
    assert.match(guard, /listRecentIngestionEvidenceFailures/);
    assert.match(guard, /recorded before first score/);
    assert.match(script, /persistReleaseScoreRun/);
    assert.doesNotMatch(analysis, /FROM issues i\s+JOIN classifications c ON c\.issue_number=i\.number\s+JOIN target/);
    assert.match(analysis, /missingClassificationClosureProof/);
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
    assert.match(analysis, /enrichLinkedPrReachability/);
    assert.match(analysis, /reachabilityStatus/);
    assert.match(analysis, /reachabilityEvidence/);
    assert.match(analysis, /external_repo_unchecked/);
    assert.match(analysis, /external_repository_not_checked_against_openclaw_release_tag/);
    assert.match(analysis, /const item = \{\s*\.\.\.pr,/);
    assert.match(analysis, /state,\s*merged: merged \? 1 : 0/);
  });

  it('GraphQL issue evidence batches recover from missing issue aliases', () => {
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    assert.match(github, /function skipMissingIssueAliases/);
    assert.match(github, /onMissingIssueAlias/);
    assert.match(github, /if \(!onMissingIssueAlias\) return 0/);
    assert.match(github, /listIssueCommentsBatch[\s\S]*skipMissingIssueAliases/);
    assert.match(github, /listIssueLabelEventsBatch[\s\S]*skipMissingIssueAliases/);
    assert.match(github, /listIssueFixEvidenceBatch[\s\S]*skipMissingIssueAliases/);
    assert.match(github, /function requireGraphqlConnection/);
    assert.match(github, /function nextGraphqlPageCursor/);
    assert.match(github, /pageInfo hasNextPage without endCursor/);
    assert.doesNotMatch(github, /connection\?\.nodes \?\? \[\]/);
  });

  it('refresh fetches label timelines for all monitored-window issues', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /const monitoredIssueNumbers = page[\s\S]*?issueOverlapsMonitoredWindow\(issue\)[\s\S]*?issue\.number/);
    assert.match(refresh, /listIssueLabelEventsBatch\(monitoredIssueNumbers,/);
    assert.match(refresh, /listIssueFixEvidenceBatch\(monitoredIssueNumbers,/);
    assert.match(refresh, /persistIssueStateEvidence\(stateEvidence\)/);
    assert.doesNotMatch(refresh, /issue\.labels\.length/);
  });

  it('refresh treats release checks and advisories as score-blocking evidence', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /const evidenceRefreshFailures: string\[\] = \[\]/);
    assert.match(refresh, /insertIngestionEvidenceFailure/);
    assert.match(refresh, /persistEarlyEvidenceFailureCrawlMeta/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('release-metadata', 'listReleases', e/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('artifact-verification', r\.tag_name, e/);
    assert.match(refresh, /issue-comments-missing-alias/);
    assert.match(refresh, /issue-label-events-missing-alias/);
    assert.match(refresh, /issue-fix-evidence-missing-alias/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('release-checks', r\.tag_name, e/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('advisories', advisoryScope, e/);
    assert.match(refresh, /Promise\.allSettled/);
    assert.match(refresh, /issuePaginationStopReason = 'evidence_failure'/);
    assert.match(refresh, /persistIssueCrawlMeta\(buildIssueCrawlMeta\(\)\)/);
    assert.match(refresh, /evidenceRefreshFailures\.push\(message\)/);
    assert.match(refresh, /evidenceRefreshFailures: summarizeFailures\(evidenceRefreshFailures\)/);
    assert.doesNotMatch(refresh, /release-checks[\s\S]{0,120}continuing/);
    assert.doesNotMatch(refresh, /advisories[\s\S]{0,120}continuing/);
    assert.doesNotMatch(refresh, /artifacts[\s\S]{0,120}continuing/);
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
    assert.match(scoringDoc, /Score writers refuse malformed or unsupported `vulnerable_version_range`/);
    assert.match(scoringDoc, /positiveDetails/);
    assert.match(scoringDoc, /limitDetails/);
    assert.match(scoringDoc, /release-metadata\/artifact\/release-check\/advisory\/monitored-release evidence refresh failures/);
    assert.match(scoringDoc, /If release metadata cannot be fetched/);
    assert.match(scoringDoc, /artifact verification, release commit checks, advisories, closure evidence, PR reachability, or closure-proof refresh fails/);
    assert.match(scoringDoc, /stopReason: "evidence_failure"/);
    assert.match(scoringDoc, /ingestion_evidence_failures` is append-only provenance/);
    assert.match(scoringDoc, /GitHub partial responses for missing issue aliases/);
    assert.match(scoringDoc, /Other callers fail closed on the GraphQL error/);
    assert.match(scoringDoc, /Manual score writers share the same clean-ingestion guard/);
    assert.match(scoringDoc, /GraphQL nested evidence connections/);
    assert.match(scoringDoc, /interpreted as empty evidence/);
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
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    assert.match(api, /PUBLIC_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 1/);
    assert.match(api, /LOCAL_AUDIT_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_UPSTREAM_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_DELTA_SCHEMA_VERSION = 1/);
    assert.match(api, /config\.comparison\.apiEnabled/);
    assert.match(api, /comparison api disabled/);
    assert.match(api, /function reviewSourceProvenance/);
    assert.match(api, /sourceMode: 'current_db'/);
    assert.match(api, /rawRows/);
    assert.match(api, /STATUS_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /CONFIG_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /RELEASE_ROW_SCHEMA_VERSION = 1/);
    assert.match(api, /RELEASE_HISTORY_ROW_SCHEMA_VERSION = 1/);
    assert.match(api, /PUBLIC_RELEASE_SCHEMA_VERSION = 1/);
    assert.match(api, /function publicCacheKey/);
    assert.match(api, /releaseScoreAuditFreshness/);
    assert.match(api, /dataFreshnessCacheDigest/);
    assert.match(api, /publicReleaseRowsFreshness\(config\.limits\.releases\)/);
    assert.match(api, /releaseFreshness\.digest/);
    assert.match(api, /freshness\.max_scored_at/);
    assert.match(api, /freshness\.count/);
    assert.match(api, /freshness\.digest/);
    assert.match(api, /dataFreshness:\s+freshnessForRelease/);
    assert.match(db, /fetched_at TEXT/);
    assert.match(db, /'issue_fetches'/);
    assert.match(db, /MAX\(i\.fetched_at\)/);
    assert.match(db, /release_metadata_fetched_at TEXT/);
    assert.match(db, /release_derived_fetched_at TEXT/);
    assert.match(db, /release_artifact_checked_at TEXT/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS ingestion_evidence_failures/);
    assert.match(db, /insertIngestionEvidenceFailure/);
    assert.match(db, /release_metadata_fetched_at AS updated_at/);
    assert.match(db, /'release_rows'/);
    assert.match(api, /publicIssueSummariesForRelease/);
    assert.match(api, /PUBLIC_ISSUES_PER_RELEASE/);
    assert.match(api, /releaseLabelCutoff\(r,\s*audit\?\.scored_at/);
    assert.match(api, /CLOSURE_PROOF_STATUSES/);
    assert.match(api, /allowedStatuses/);
    assert.match(api, /filteredCountsByTier/);
    assert.match(api, /unfilteredCountsByStatus/);
    assert.match(api, /filteredCountsByStatus/);
    assert.match(api, /unfilteredCountsByRiskDisposition/);
    assert.match(api, /filteredCountsByRiskDisposition/);
    assert.match(api, /laterFixProof: compactLaterFixProof/);
    assert.match(api, /unscoredFixProof: compactUnscoredFixProof/);
    const publicIssues = readFileSync(join(root, 'src/lib/publicIssueSummary.ts'), 'utf8');
    assert.match(publicIssues, /classifyIssueRowWithLabels/);
    assert.match(publicIssues, /labelsForIssueAt/);
    assert.match(publicIssues, /useSnapshotWhenNoEvents:\s*labelCutoff != null/);
    assert.match(publicIssues, /comparePublicIssueSignal/);
    assert.match(publicIssues, /sort\(comparePublicIssueSignal\)/);
    assert.match(publicIssues, /classification\.severity/);
    assert.match(publicIssues, /affectedUsers: classification\.affectedUsers/);
    assert.doesNotMatch(api, /SEVERITY_RANK\[a\.severity\]/);
  });
});
