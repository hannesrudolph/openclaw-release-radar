import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  mkdtempSync,
  readFileSync,
  readdirSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { dirname, join, relative } from 'node:path';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { Worker, type WorkerOptions } from 'node:worker_threads';
import { REC_THRESHOLD } from './score.ts';
import { CLOSURE_PROOF_STATUSES, CLOSURE_RISK_DISPOSITIONS } from './closureProofTaxonomy.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

function workerMessage(
  filename: string | URL,
  options: WorkerOptions,
): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const worker = new Worker(filename, options);
    const timeout = setTimeout(() => {
      void worker.terminate();
      reject(new Error('Worker loader regression timed out'));
    }, 5_000);
    worker.once('message', (message) => {
      clearTimeout(timeout);
      resolve(message);
    });
    worker.once('error', (error) => {
      clearTimeout(timeout);
      reject(error);
    });
  });
}

describe('static scoring/UI contracts', () => {
  it('confines incident phantom tags to explicit negative assertions', () => {
    const incidentTags = [
      `v2026.${'7.1'}`,
      `v2026.${'6.30'}`,
    ];
    const allowedFiles = new Set([
      'src/lib/apiRoutes.test.ts',
      'src/lib/composedPublication.e2e.helper.ts',
      'src/lib/composedPublication.e2e.test.ts',
      'src/lib/releaseAuditInvariants.test.ts',
      'src/lib/scorerVerifierContract.e2e.test.ts',
    ]);
    const excludedDirectories = new Set([
      '.cache',
      '.codex-local',
      '.git',
      'coverage',
      'data',
      'dist',
      'node_modules',
    ]);
    const textExtensions = new Set([
      '.cjs',
      '.env',
      '.example',
      '.html',
      '.js',
      '.json',
      '.md',
      '.mjs',
      '.service',
      '.sh',
      '.timer',
      '.ts',
      '.yaml',
      '.yml',
    ]);
    const files: string[] = [];
    const visit = (directory: string) => {
      for (const entry of readdirSync(directory, { withFileTypes: true })) {
        if (entry.isDirectory() && excludedDirectories.has(entry.name)) continue;
        const path = join(directory, entry.name);
        if (entry.isDirectory()) {
          visit(path);
        } else if (
          entry.isFile() &&
          (
            textExtensions.has(entry.name.slice(entry.name.lastIndexOf('.'))) ||
            entry.name === '.env'
          )
        ) {
          files.push(path);
        }
      }
    };
    visit(root);

    const offenders = files.flatMap((path) => {
      const repositoryPath = relative(root, path);
      if (allowedFiles.has(repositoryPath)) return [];
      const contents = readFileSync(path, 'utf8');
      return incidentTags
        .filter((tag) => contents.includes(tag))
        .map((tag) => `${repositoryPath}: ${tag}`);
    });
    assert.deepEqual(offenders, []);
  });

  it('keeps UI smoke outside the database-opening lifecycle allowlist', () => {
    const dbSource = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    assert.doesNotMatch(
      dbSource,
      /\['ui:smoke',\s*'scripts\/ui-smoke\.mjs'\]/,
    );
  });

  it('does not hardcode a stale recommendation threshold in UI text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.doesNotMatch(html, /newest eligible\s*(?:≥|>=)\s*7/i);
    assert.equal(REC_THRESHOLD, 7);
  });

  it('homepage install command only uses server-recommended releases', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function pickRecommendedRelease\(rows\)[\s\S]*?r\.recommended && !isStaleAnalysis\(r\) && finiteScore\(r\.finalScore\) != null/);
    assert.doesNotMatch(html, /rows\.find\(\(r\) => r\.status === 'eligible' && r\.finalScore != null\)/);
  });

  it('keeps exact release tags collision-free in DOM ids and shell-safe in commands', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const smoke = readFileSync(join(root, 'scripts/ui-smoke.mjs'), 'utf8');
    const domIdSource = html.match(
      /function domIdForTag\(tag\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const shellQuoteSource = html.match(
      /function shellQuote\(value\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const npmVersionSource = html.match(
      /function npmVersionFromTag\(tag\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const installCommandSource = html.match(
      /function installCommand\(tag\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const updateCommandBlockSource = html.match(
      /function updateCommandBlockHtml\(tag, opts = \{\}\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';

    assert.notEqual(domIdSource, '');
    assert.notEqual(shellQuoteSource, '');
    assert.notEqual(npmVersionSource, '');
    assert.notEqual(installCommandSource, '');
    assert.notEqual(updateCommandBlockSource, '');
    assert.doesNotMatch(html, /\bcssId\(/);
    assert.match(
      domIdSource,
      /charCodeAt\(i\)\.toString\(16\)\.padStart\(4, '0'\)/,
    );
    assert.match(
      installCommandSource,
      /openclaw update --tag \$\{shellQuote\(npmVersionFromTag\(tag\)\)\}/,
    );
    assert.equal((html.match(/openclaw update --tag/g) ?? []).length, 1);
    assert.match(updateCommandBlockSource, /const cmd = installCommand\(tag\)/);
    assert.match(updateCommandBlockSource, /\$\{esc\(cmd\)\}<\/code>/);
    assert.match(updateCommandBlockSource, /data-cmd="\$\{esc\(cmd\)\}"/);
    assert.match(smoke, /function cssAttributeEquals\(name, value\)/);
    assert.doesNotMatch(smoke, /locator\([^)]*data-tag="\$\{/s);
    assert.doesNotMatch(smoke, /locator\([^)]*data-cmd="\$\{/s);

    const runtime = Function(
      `${domIdSource}\n${npmVersionSource}\n${shellQuoteSource}\n`
        + `${installCommandSource}\n`
        + 'return { domIdForTag, shellQuote, installCommand };',
    )() as {
      domIdForTag(tag: string): string;
      shellQuote(value: string): string;
      installCommand(tag: string): string;
    };
    const tags = [
      '',
      'v2026.7.8',
      'release/a',
      'release+a',
      "v1'$(id);$HOME&`id`",
      '\u03b2/\ud83d\ude80',
      '\ud800',
      '\ufffd',
    ];
    const ids = tags.map(runtime.domIdForTag);
    assert.equal(new Set(ids).size, tags.length);
    assert.ok(ids.every((id) => /^tag-[0-9a-f]*$/.test(id)));
    assert.equal(runtime.domIdForTag('a'), 'tag-0061');
    assert.equal(runtime.domIdForTag('\ud83d\ude80'), 'tag-d83dde80');
    assert.notEqual(
      runtime.domIdForTag('release/a'),
      runtime.domIdForTag('release+a'),
    );

    const hostileTag = "v1'$(id);$HOME&`id`";
    const quotedTag = "'1'\"'\"'$(id);$HOME&`id`'";
    assert.equal(runtime.shellQuote(hostileTag.slice(1)), quotedTag);
    assert.equal(
      runtime.installCommand(hostileTag),
      `openclaw update --tag ${quotedTag}`,
    );
    assert.equal(
      runtime.installCommand('v2026.7.8'),
      "openclaw update --tag '2026.7.8'",
    );
  });

  it('public payload cache and last-known-good data stay epoch-compatible', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const loader = api.slice(
      api.indexOf('async function publicPayloadForCurrentEpoch('),
      api.indexOf("api.get('/public'"),
    );
    assert.match(loader, /const cacheKey = publicCacheKey\(dbEpoch\)/);
    assert.match(loader, /const cached = getCached\(cacheKey\)/);
    assert.match(loader, /lastKnownGoodPublicPayload\?\.dbEpoch === dbEpoch/);
    assert.match(api, /setCached\(payload, publicCacheKey\(dbEpoch\)\)/);
    assert.doesNotMatch(api, /setCached\(payload, publicCacheKey\(\)\)/);
  });

  it('verified fix scoring is proof-row-only', () => {
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const verifiedQuery = db.match(/const verifiedFixedForReleaseStmt = db\.prepare\(`([\s\S]*?)`\);/)?.[1] ?? '';
    const unverifiedQuery = db.match(/const unverifiedClosedForReleaseStmt = db\.prepare\(`([\s\S]*?)`\);/)?.[1] ?? '';
    assert.match(verifiedQuery, /issue_closure_proofs proof[\s\S]*proof\.status = 'fixed_in_release'/);
    assert.doesNotMatch(verifiedQuery, /release_pr_reachability|issue_pr_links|pull_request_fixes|creditedFixLinkSql/);
    assert.match(unverifiedQuery, /issue_closure_proofs proof[\s\S]*proof\.status = 'fixed_in_release'/);
    assert.doesNotMatch(unverifiedQuery, /UNION ALL|release_pr_reachability|issue_pr_links|pull_request_fixes|creditedFixLinkSql/);
  });

  it('score color helper keeps weak scores below caution threshold', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /if \(n >= 5\.5\) return 'var\(--warn\)'/);
    assert.doesNotMatch(html, /if \(n >= 5\) return 'var\(--warn\)'/);
  });

  it('install wording does not overclaim safety', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    assert.doesNotMatch(html, /release looks safe to install|No safe target|broadly safe/i);
    assert.doesNotMatch(html, /\bhard safety gate\b|\bhard install gates\b/i);
    assert.doesNotMatch(scorer, /\bhard safety gate\b|\bhard install gates\b/i);
    assert.match(html, /ordinal 0–10 policy\/stability ranking, not a probability or percentage/);
    assert.match(scoringDoc, /ordinal policy\/stability assessment[\s\S]*not a probability, percentage/);
    assert.doesNotMatch(html, /Install Confidence 0[–-]10/i);
    assert.doesNotMatch(html, /\bperfect\b|model ceiling/i);
    assert.match(html, /if \(local\?\.recommended\)[\s\S]*recommended install target under the audit and recommendation gates/);
    assert.match(html, /local\?\.status === 'eligible'[\s\S]*passed install eligibility checks/);
    assert.doesNotMatch(html, /Each update is now scored for the way you use it/);
    assert.doesNotMatch(html, /My install score is active/);
    assert.match(html, /audited assessment and recommendation stay global/);
    assert.match(html, /never changes the audited assessment or the globally recommended update target/);
    assert.doesNotMatch(html, /function myInstallScore/);
    assert.match(html, /core\/security issues still stay visible/);
    assert.doesNotMatch(html, /ignore the ones that can't/i);
  });

  it('release detail install panel only shows update commands for recommended releases', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const installPanel = html.match(/function installPanelHtml\(r\) \{[\s\S]*?\n\}/)?.[0] ?? '';
    assert.match(html, /function installActionHtml\(r\) \{[\s\S]*if \(isStaleAnalysis\(r\)\) return staleAnalysisStateHtml\(r\);/);
    assert.match(html, /r\?\.recommended && finiteScore\(r\?\.finalScore\) != null[\s\S]*updateCommandBlockHtml\(r\.tag\)/);
    assert.match(html, /install-state--not-recommended/);
    assert.match(html, /install-state--stale/);
    assert.match(installPanel, /installActionHtml\(r\)/);
    assert.doesNotMatch(installPanel, /updateCommandBlockHtml\(r\.tag\)/);
  });

  it('API and UI expose only stale diagnostics for incompatible score audits', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const decisionContract = readFileSync(join(root, 'src/lib/recommendationDecision.ts'), 'utf8');
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const reviewForRender = html.match(
      /function reviewForRender\(tag\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const scoreDrivers = html.match(
      /function scoreDriversHtml\(release\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const scoreReview = html.match(
      /function scoreReviewHtml\(r\) \{[\s\S]*?\n\}/,
    )?.[0] ?? '';
    const loadReview = html.slice(
      html.indexOf('function loadReviewForRelease('),
      html.indexOf('function renderPackageCard('),
    );
    assert.match(api, /function scoreAnalysisCompatibility/);
    assert.match(api, /audit\.score_model_version === SCORE_MODEL_VERSION/);
    assert.match(api, /audit\.prompt_version === PROMPT_VERSION/);
    assert.match(api, /explanation\.schemaVersion === SCORE_EXPLANATION_SCHEMA_VERSION/);
    assert.match(api, /input\.schemaVersion === SCORE_INPUT_SCHEMA_VERSION/);
    assert.match(api, /components\.schemaVersion === SCORE_COMPONENTS_SCHEMA_VERSION/);
    assert.match(api, /issueEvidence\.schemaVersion === ISSUE_EVIDENCE_SCHEMA_VERSION/);
    assert.match(api, /gateEvidence\.schemaVersion === GATE_EVIDENCE_SCHEMA_VERSION/);
    assert.match(api, /verifyScoreAuditPayloadContracts\(\{/);
    assert.match(api, /auditContractFailures\.length === 0/);
    assert.match(api, /scoreSourceIdentityMatches\(sourceIdentity, currentSourceIdentity\)/);
    assert.match(api, /validateRecommendationDecisionCopies\(\{/);
    assert.match(api, /recommendationFailures\.length === 0/);
    assert.match(decisionContract, /for \(const key of RECOMMENDATION_DECISION_KEYS\)/);
    assert.match(decisionContract, /summary must match the canonical recommendation decision summary/);
    assert.doesNotMatch(api, /recommendation\.schemaVersion === 1/);
    assert.match(api, /recommended: compatibility\.usable && release\.recommended === 1/);
    assert.match(api, /const score = compatibility\.usable \? release\.final_score : null/);
    assert.match(api, /compatibility\.usable \? persistedStatus : 'stale'/);
    assert.match(api, /diagnosticStatus: compatibility\.usable \? null : persistedStatus/);
    assert.match(api, /Analysis is stale\./);
    assert.match(api, /staleAudit: compatibility\.staleAudit/);
    assert.match(api, /if \(!audit \|\| !usable\) return null/);
    assert.match(api, /explanation: usable \? explanation : null/);
    assert.match(api, /explanation: context\.presentation\.explanation/);
    assert.match(api, /components: presentation\.auditUsable \? parseJson\(audit\?\.components_json, null\) : null/);
    assert.match(api, /const usableAudit = presentation\.auditUsable \? audit : undefined/);
    assert.match(html, /function isStaleAnalysis/);
    assert.match(html, /if \(isStaleAnalysis\(r\)\) return staleAnalysisStateHtml\(r\)/);
    assert.match(html, /data-review-state="stale"/);
    assert.match(html, /Assessment details unavailable\./);
    assert.match(html, /if \(isStaleAnalysis\(release\)\) \{/);
    assert.match(html, /reviewByTag\.delete\(tag\)/);
    assert.match(html, /isStaleAnalysis\(r\) \|\| isStaleAnalysis\(local\) \|\| local\.staleAudit/);
    assert.match(reviewForRender, /releaseSnapshotActionabilityVerified\(\)/);
    assert.match(reviewForRender, /reviewByTag\.get\(tag\)/);
    assert.match(scoreReview, /const review = reviewForRender\(r\.tag\)/);
    assert.doesNotMatch(scoreReview, /reviewByTag\.get/);
    assert.match(
      scoreReview,
      /!local \|\| isStaleAnalysis\(r\) \|\| isStaleAnalysis\(local\) \|\| local\.staleAudit/,
    );
    assert.match(
      scoreDrivers,
      /const ledger = release\?\.explanation\?\.scoreLedger/,
    );
    assert.match(
      scoreDrivers,
      /if \(!ledger \|\| typeof ledger !== 'object'\) return ''/,
    );
    assert.doesNotMatch(scoreDrivers, /reviewByTag|reviewForRender/);
    assert.match(scoreDrivers, /cap\.applied === true/);
    assert.match(scoreDrivers, /ceiling \$\{metricValue\(cap\.ceiling\)\}/);
    assert.match(scoreDrivers, /const parts = \[\.\.\.capParts, \.\.\.rowParts\]/);
    assert.ok(
      loadReview.indexOf('if (isStaleAnalysis(release))') <
        loadReview.indexOf('if (reviewByTag.has(tag))'),
      'stale releases must be rejected before consulting the retained review cache',
    );
  });

  it('review and comparison expose persisted fix-credit payloads without recomputation', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    assert.doesNotMatch(api, /enrichGateEvidenceWithClosureProof/);
    assert.match(api, /gateEvidence: presentation\.auditUsable \? parseJson\(audit\?\.gate_evidence_json, null\) : null/);
    assert.match(api, /const gateEvidence = parseJson\(usableAudit\?\.gate_evidence_json, null\)/);
  });

  it('gate reasons and every matching advisory stay visible', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const advisoryStatus = api.match(/function advisoryStatusFor\([\s\S]*?\n\}/)?.[0] ?? '';
    assert.match(advisoryStatus, /if \(matchesRange\(tag, a\.vulnerable_version_range\)\) affected\.push\(a\)/);
    assert.doesNotMatch(advisoryStatus, /stableDistance|CVE_BADGE_WINDOW/);
    assert.match(html, /const gateReason = cat\.reason \|\| r\.reason \|\| ''/);
    assert.doesNotMatch(html, /r\.status === 'skip-cve'\s*\?\s*''/);
    assert.match(html, /all matching ranges are retained and not filtered by age or install profile/);
    assert.match(html, /known medium-or-higher CVE exposure\\b\/gi, 'medium-or-higher security advisory exposure'/);
    assert.match(html, /CVE install gate\\b\/gi, 'security advisory install gate'/);
    assert.match(html, /known CVEs\?\\b\/gi, 'medium-or-higher security advisories'/);
    assert.match(html, /a CVE identifier is not, so the UI names the advisory rather than assuming one/);
    assert.match(html, /r\.status === 'skip-hotfix'/);
    assert.match(html, /r\.status === 'wait'/);
  });

  it('release UI renders progressively and binds asynchronous evidence to one snapshot', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const uiSmoke = readFileSync(join(root, 'scripts/ui-smoke.mjs'), 'utf8');
    const loadReleases = html.slice(
      html.indexOf('async function loadReleases('),
      html.indexOf('function releaseSnapshotRow('),
    );
    const publicEnrichment = html.match(/function publicReleaseEnrichment\(row\) \{[\s\S]*?\n\}/)?.[0] ?? '';
    const chartPoint = html.match(/function releaseForChartPoint\(r\) \{[\s\S]*?\n\}/)?.[0] ?? '';
    const historyLoader = html.slice(
      html.indexOf('async function loadHistoryForSnapshot('),
      html.indexOf('function publicReleaseEnrichment('),
    );
    const publicLoader = html.slice(
      html.indexOf('async function loadPublicForSnapshot('),
      html.indexOf('function reviewMatchesReleaseSnapshot('),
    );

    assert.match(
      loadReleases,
      /const response = await api\('\/releases', \{\s*signal: releaseRequestController\.signal,\s*includeMeta: true,\s*\}\)/,
    );
    assert.match(loadReleases, /const releases = response\?\.body/);
    assert.match(loadReleases, /const snapshotId = response\?\.snapshotId/);
    assert.match(loadReleases, /rowsBelongToExplicitSnapshot\(releases, snapshotId\)/);
    assert.match(loadReleases, /renderPackageCard\(\);\s*applyRoute\(\);\s*if \(!allReleases\.length\) return;\s*loadHistoryForSnapshot\(epoch, releaseSnapshot, releaseRequestController\.signal\);\s*loadPublicForSnapshot\(epoch, releaseSnapshot, releaseRequestController\.signal\)/);
    assert.doesNotMatch(loadReleases, /Promise\.all/);
    assert.doesNotMatch(html, /releases\.map\(\(release\) => api\(`\/releases\/\$\{encodeURIComponent\(release\.tag\)\}\/review`/);

    assert.match(html, /let releaseLoadEpoch = 0/);
    assert.match(html, /releaseRequestController\?\.abort\(\)/);
    assert.match(html, /function isExplicitSnapshotId/);
    assert.match(html, /function rowsBelongToExplicitSnapshot/);
    assert.match(html, /function responseBelongsToSnapshot\(epoch, snapshot\)/);
    assert.match(historyLoader, /responseBelongsToSnapshot\(epoch, snapshot\)/);
    assert.match(historyLoader, /response\?\.snapshotId !== snapshot/);
    assert.match(historyLoader, /rowsBelongToExplicitSnapshot\(history, snapshot\)/);
    assert.match(historyLoader, /scheduleAutomaticSnapshotRebase\(epoch, snapshot\)/);
    assert.match(publicLoader, /responseBelongsToSnapshot\(epoch, snapshot\)/);
    assert.match(publicLoader, /response\?\.snapshotId === snapshot/);
    assert.match(publicLoader, /payload\?\.snapshotId === snapshot/);
    assert.match(publicLoader, /snapshotMetadata\?\.id === snapshot/);
    assert.match(publicLoader, /rowsBelongToExplicitSnapshot\(rows, snapshot\)/);
    assert.match(publicLoader, /scheduleAutomaticSnapshotRebase\(epoch, snapshot\)/);

    assert.match(html, /const reviewRequests = new Map\(\)/);
    assert.match(html, /const inflight = reviewRequests\.get\(requestKey\);\s*if \(inflight\) return inflight/);
    assert.match(
      html,
      /!reviewMatchesReleaseSnapshot\(review, currentRelease, snapshot\)/,
    );
    assert.match(html, /function focusReleaseTag\(tag\)[\s\S]*loadReviewForRelease\(tag\)/);
    assert.match(html, /function toggleRelease\(row\)[\s\S]*loadReviewForRelease\(row\.dataset\.tag\)/);
    assert.match(html, /data-review-state="loading"/);
    assert.match(html, /holdDownstreamActionability\(\s*'review_load_failed'/);
    assert.doesNotMatch(html, /invalidateRetainedActionability\(\s*'review_load_failed'/);
    assert.match(
      html,
      /Scores remain visible from the authoritative release snapshot, but install actions remain unavailable/,
    );
    assert.match(html, /data-review-state="stale"/);
    assert.match(html, /data-release-retry/);

    assert.match(html, /id="surfaces-\$\{id\}"/);
    assert.match(html, /id="review-\$\{domIdForTag\(r\.tag\)\}"/);
    assert.match(html, /id="issues-\$\{domIdForTag\(r\.tag\)\}"/);
    assert.match(publicLoader, /patchAllPublicSlots/);
    assert.doesNotMatch(publicLoader, /renderReleases/);
    assert.doesNotMatch(historyLoader, /renderReleases/);
    assert.doesNotMatch(publicEnrichment, /\bscore\s*:|\bstatus\s*:|\brecommended\s*:|\bscoredAt\s*:/);
    assert.doesNotMatch(chartPoint, /publicReleaseDetails|detail\.score/);

    assert.match(
      uiSmoke,
      /#packageLoadState\[data-release-state="hold"\]'\)\.waitFor\(\{\s*state: 'visible'/,
    );
    assert.match(uiSmoke, /Progressive render hid authoritative release rows before public verification/);
    assert.match(uiSmoke, /Initial render fanned out release review requests/);
    assert.match(uiSmoke, /Expected one inflight review/);
    assert.match(uiSmoke, /Chart open requested/);
    assert.match(uiSmoke, /reviewCounts\.get\(chartRelease\.tag\) !== 1/);
    assert.match(uiSmoke, /Async enrichment replaced \/api\/releases score/);
    assert.match(uiSmoke, /Stale review response populated the current release snapshot/);
    assert.match(uiSmoke, /Stale \/api\/public response replaced current enrichment/);
    assert.match(uiSmoke, /Async review\/history\/public completion rerendered the release list/);
    assert.match(uiSmoke, /validateRecommendationDecisionCopies/);
    assert.match(uiSmoke, /UI_SMOKE_FIXTURE_ONLY/);
    assert.match(uiSmoke, /createFixtureSnapshot/);
    assert.match(uiSmoke, /assertFixtureStaticUx/);
    assert.match(uiSmoke, /Fixture-only UI smoke passed/);
  });

  it('hard refresh routing and request states stay exact, bounded, and retryable', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const server = readFileSync(join(root, 'src/index.ts'), 'utf8');
    const uiSmoke = readFileSync(join(root, 'scripts/ui-smoke.mjs'), 'utf8');
    const head = html.slice(0, html.indexOf('</head>'));
    const apiHelper = html.slice(
      html.indexOf('const API_REQUEST_TIMEOUT_MS'),
      html.indexOf('/* ── render releases'),
    );
    const rebaseHelper = html.slice(
      html.indexOf('function scheduleAutomaticSnapshotRebase('),
      html.indexOf('async function loadReleases('),
    );
    const statusLoader = html.slice(
      html.indexOf('async function loadStatus('),
      html.indexOf('/* ── init'),
    );

    assert.match(head, /location\.hash === '#\/openclaw'/);
    assert.match(head, /route-openclaw/);
    assert.match(html, /function isPackageView\(\) \{\s*return location\.hash === '#\/openclaw';\s*\}/);
    assert.doesNotMatch(html, /startsWith\('#\/openclaw'\)/);
    assert.match(html, /html\.route-openclaw #viewPackage\{display:block!important\}/);
    assert.match(html, /id="packageLoadState" data-release-state="loading"/);

    assert.match(html, /data-release-state/);
    assert.match(html, /function scoreAuthorizationAllowsRatings/);
    assert.match(
      html,
      /if \(!available \|\| !status \|\| analysisRefreshInProgress\(status\)\) return true/,
    );
    assert.match(
      html,
      /function releaseSnapshotAuthorityVerified\(\) \{\s*return releaseSnapshotRowsVerified\(\)\s*&& scoreAuthorizationAllowsRatings\(\)/,
    );
    assert.match(
      html,
      /function releaseSnapshotRowsVerified\(\) \{\s*return isExplicitSnapshotId\(releaseSnapshot\)\s*&& rowsBelongToExplicitSnapshot\(allReleases, releaseSnapshot\)/,
    );
    assert.match(
      html,
      /function holdDownstreamActionability[\s\S]*if \(!releaseSnapshotRowsVerified\(\)\) return false/,
    );
    assert.match(
      html,
      /function actionabilityUiStateKey[\s\S]*ratingsVisible:[\s\S]*releaseSnapshotRowsVerified\(\)[\s\S]*scoreAuthorizationAllowsRatings\(status, available\)/,
    );
    assert.match(
      html,
      /function releaseSnapshotIdentityVerified\(\) \{\s*return releaseLoadState\.status === 'ready'\s*&& releaseSnapshotAuthorityVerified\(\)/,
    );
    assert.match(html, /setReleaseLoadState\(releases\.length \? 'ready' : 'empty'\)/);
    assert.match(html, /setReleaseLoadState\('error', message\)/);
    assert.match(html, /setReleaseLoadState\(\s*'stale'/);
    assert.match(html, /Showing retained release data/);
    assert.match(html, /data-release-retry/);
    assert.match(html, /data-public-state="pending"/);
    assert.match(html, /data-public-state="ready"/);
    assert.match(html, /data-public-state="empty"/);
    assert.match(html, /data-public-state="error"/);
    assert.match(html, /data-public-retry/);

    assert.match(apiHelper, /new AbortController\(\)/);
    assert.match(apiHelper, /setTimeout\(\(\) => \{/);
    assert.match(apiHelper, /signal: controller\.signal/);
    assert.match(apiHelper, /boundedUiMessage/);
    assert.match(apiHelper, /new UiRequestError\('http', response\.status\)/);
    assert.doesNotMatch(apiHelper, /response\.text\(|await r\.text\(/);
    assert.match(html, /function clearLoadedReleaseAuthority\(message\)/);
    assert.match(html, /if \(isAuthorityUnavailableError\(error\)\) \{/);
    assert.match(statusLoader, /label\.textContent = 'Latest refresh failed'/);
    assert.doesNotMatch(statusLoader, /humanizeUiText\(s\.lastError\)|label\.textContent\s*=.*s\.lastError/);

    assert.match(rebaseHelper, /automaticSnapshotRebaseUsed/);
    assert.match(rebaseHelper, /scheduledSnapshotRebaseCycle === userLoadCycle/);
    assert.match(rebaseHelper, /loadReleases\(\{ automatic: true, cycle \}\)/);
    assert.match(html, /automaticSnapshotRebaseUsed = false/);

    assert.match(server, /app\.use\(express\.static/);
    assert.doesNotMatch(server, /app\.get\([^)]*\*|sendFile\(/);

    assert.match(uiSmoke, /Delayed release load did not show the package loading state/);
    assert.match(uiSmoke, /Unsafe release error content reached the UI/);
    assert.match(uiSmoke, /Pending public verification hid authoritative release rows/);
    assert.match(uiSmoke, /Automatic snapshot rebase exceeded one request/);
    assert.match(uiSmoke, /Manual snapshot retry did not start exactly one new load cycle/);
    assert.match(uiSmoke, /Release 503 retained untrusted release rows/);
    assert.match(uiSmoke, /Release 503 retained untrusted client state/);
    assert.match(uiSmoke, /Unsafe failed-rebase content reached the UI/);
    assert.match(uiSmoke, /timeout === 17_000 \? 100 : timeout/);
    assert.match(uiSmoke, /Public timeout state did not explain the timeout/);
    assert.match(
      uiSmoke,
      /assertAuthorizedRatingsRemainVisible\(publicPage, releases, 'Public 503'\)/,
    );
    assert.match(
      uiSmoke,
      /assertAuthorizedRatingsRemainVisible\(timeoutPage, releases, 'Public timeout'\)/,
    );
    assert.match(
      uiSmoke,
      /assertAuthorizedRatingsRemainVisible\(page, releases, 'Status unavailable'\)/,
    );
    assert.match(
      uiSmoke,
      /assertAuthorizedRatingsRemainVisible\(page, scenario\.releases, 'Review 503'\)/,
    );
    assert.match(html, /aria-busy="true"/);
    assert.match(html, /state\.setAttribute\('aria-busy', renderedStatus === 'loading' \? 'true' : 'false'\)/);
  });

  it('lazy review guards bind the actual review schema and complete audit identity', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(api, /function scoreAuditIdentityDigest/);
    assert.match(api, /reviewSchemaVersion: LOCAL_AUDIT_SCHEMA_VERSION/);
    assert.match(api, /const publication = sealedScoreAuditPublication\(audit\.release_tag\)/);
    assert.match(api, /auditDigest: publication\.digest/);
    assert.match(html, /local\.schemaVersion !== release\.scoreAudit\.reviewSchemaVersion/);
    assert.match(html, /local\.auditDigest !== release\.scoreAudit\.auditDigest/);
    assert.match(html, /local\.sourceProvenance\?\.auditDigest !== local\.auditDigest/);
    assert.match(
      html,
      /const scoreAuthority = local\.sourceProvenance\?\.scoreAuthority/,
    );
    assert.match(html, /reviewSchemaVersion: local\.schemaVersion \?\? null/);
    assert.match(html, /auditDigest: local\.auditDigest \?\? null/);
    assert.match(
      html,
      /authorityRunId: scoreAuthority\?\.runId \?\? null/,
    );
    assert.match(
      html,
      /authorityRunContentHash: scoreAuthority\?\.contentHash \?\? null/,
    );
    assert.match(
      html,
      /historyV2SealContentHash:\s+scoreAuthority\?\.historyV2SealContentHash \?\? null/,
    );
    assert.doesNotMatch(html, /reviewSchemaVersion: release\.scoreAudit\.reviewSchemaVersion/);
    assert.doesNotMatch(
      html,
      /authorityRunId: release\.scoreAudit\.authorityRunId/,
    );
  });

  it('status distinguishes durable score-persisted refresh success from later crawl failure', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(api, /getMeta\('score_persistence_last_run'\)/);
    assert.match(api, /function durableSuccessfulRefreshAt/);
    assert.match(api, /scorePersistence\.source !== 'refresh'/);
    assert.match(api, /scorePersistedAt !== persistedAt/);
    assert.match(api, /function durableRefreshFailure/);
    assert.match(api, /issueCrawl\.scorePersisted !== true/);
    assert.match(api, /lastError: refreshing \? null : resolvedStatus\.lastError/);
    assert.match(html, /Latest refresh failed/);
  });

  it('empty watchIssues does not hide capped issue evidence', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /\.\.\.\(Array\.isArray\(detail\?\.watchIssues\) \? detail\.watchIssues : \[\]\)/);
    assert.match(html, /\.\.\.\(Array\.isArray\(detail\?\.issues\) \? detail\.issues : \[\]\)/);
    assert.match(html, /const seen = new Set\(\)/);
    assert.doesNotMatch(html, /if \(Array\.isArray\(detail\?\.watchIssues\)\) return detail\.watchIssues/);
    assert.doesNotMatch(html, /function myInstallScore/);
  });

  it('profile evidence preserves explicit zero weights and deduplicates alias groups', () => {
    const evidence = readFileSync(join(root, 'src/lib/releaseIssueEvidence.ts'), 'utf8');
    const weightHelper = evidence.match(/function compactProfileEvidenceWeight\([\s\S]*?\n\}/)?.[0] ?? '';
    const compactBuilder = evidence.slice(
      evidence.indexOf('export function releaseProfileEvidenceRows('),
      evidence.indexOf('function releaseEvidenceComputation('),
    );
    assert.match(weightHelper, /typeof explicitWeight === 'number' && Number\.isFinite\(explicitWeight\)/);
    assert.match(weightHelper, /return Math\.max\(0, explicitWeight\)/);
    assert.doesNotMatch(weightHelper, /explicitWeight > 0/);
    assert.match(compactBuilder, /const byAliasGroup = new Map<string, ReleaseProfileEvidenceCandidate>\(\)/);
    assert.match(compactBuilder, /byAliasGroup\.set\(aliasGroup, candidate\)/);
    assert.match(evidence, /PROFILE_TIER_PRIORITY/);
  });

  it('score explanation prefers backend audit text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(html, /local\?\.components\?\.explanation/);
    assert.match(html, /structured\.limits/);
    assert.match(html, /structured\.limitDetails/);
    assert.match(html, /scoreDetailIssueRefsHtml/);
    assert.match(html, /scoreDetailIssueProofHtml/);
    assert.match(html, /scoreDetailIssueReasonHtml/);
    assert.match(html, /scoreDetailMetricsHtml/);
    assert.match(html, /scoreDetailBucketsHtml/);
    assert.match(html, /issueScoringMetaHtml/);
    assert.match(html, /issueBucketReason/);
    assert.match(html, /issueEvidenceRowForIssue/);
    assert.match(html, /scoreLedgerHtml/);
    assert.match(html, /scoreDriversHtml/);
    assert.match(html, /Assessment drivers:/);
    assert.match(html, /score-ledger/);
    assert.match(html, /score-explain__proof/);
    assert.match(html, /issueEvidenceApiLinksHtml/);
    assert.match(html, /const rawRows = reviewRawRowLinks\(releaseTag\)/);
    assert.match(html, /appendAuditLinkQuery\(rawRows\.issues, \{ issue \}\)/);
    assert.match(html, /function issueAuditLinksHtml/);
    assert.match(html, /appendAuditLinkQuery\(rawRows\.closureProofs, \{ issue \}\)/);
    assert.match(html, /reviewRawRowLinks\(tag\)\.issues/);
    assert.match(html, /issue evidence row/);
    assert.match(html, /closure proof row/);
    assert.match(html, /function issueEvidenceTierLabel/);
    assert.match(html, /const tierLabel = issueEvidenceTierLabel\(tier, issue, evidenceRow\)/);
    assert.match(html, /Evidence bucket: \$\{tierLabel\}/);
    assert.doesNotMatch(html, /Scored as \$\{tier\} risk/);
    assert.doesNotMatch(html, /Scored as carryover risk/);
    assert.match(html, /tier: 'openUnconfirmedRisk'/);
    assert.doesNotMatch(html, /tier: 'carryoverDebt'/);
    assert.match(html, /fieldConfirmed: true/);
    assert.match(html, /severity: 'critical'/);
    assert.match(html, /functionality: 'core'/);
    assert.match(html, /sort: 'weight'/);
    assert.match(html, /tier: 'weakOrStaleEvidence'/);
    assert.doesNotMatch(html, /tier: 'staleDebt'/);
    assert.match(html, /high-weight weak\/stale evidence/);
    assert.match(html, /tier: 'openedFeltSerious'/);
    assert.match(html, /inherited issue context \(zero assessment impact\)/);
    assert.match(html, /field-discussed inherited context/);
    assert.match(html, /critical core inherited context/);
    assert.match(html, /Source-only\/static or otherwise unconfirmed findings are weak\/stale evidence/);
    assert.match(html, /Why this is capped weak\/stale evidence/);
    assert.match(html, /Context that does not lower the assessment/);
    assert.match(html, /function isContextOnlyDetail/);
    assert.match(html, /code === 'open_unconfirmed_issue_risk'/);
    assert.match(html, /code\.includes\('carryover'\)/);
    assert.match(html, /code\.includes\('inherited'\)/);
    assert.match(html, /detail\?\.metrics\?\.scoreAffecting === false/);
    assert.match(html, /const limitDetails = allLimitDetails\.filter\(isScoreLimitingDetail\)/);
    assert.match(html, /const contextDetails = allLimitDetails\.filter\(\(detail\) =>\s*!isScoreLimitingDetail\(detail\)\)/);
    assert.match(html, /No additional assessment-lowering evidence was provided for this assessment/);
    assert.doesNotMatch(html, /open unconfirmed issue risk/i);
    assert.doesNotMatch(html, /Non-verified/);
    assert.doesNotMatch(html, /field-confirmed unconfirmed risk/);
    assert.doesNotMatch(html, /source_carryover_risk/);
    assert.match(html, /componentLabel/);
    assert.match(html, /detail\.label \? `<strong>\$\{esc\(humanizeUiText\(detail\.label\)\)\}:<\/strong> `/);
    assert.match(html, /Assessment-affecting evidence weights/);
    assert.match(html, /Inherited context \(zero assessment impact\)/);
    assert.match(html, /Closed-issue risk/);
    const issueEvidence = readFileSync(join(root, 'src/lib/releaseIssueEvidence.ts'), 'utf8');
    assert.match(issueEvidence, /RELEASE_ISSUE_EVIDENCE_TIER_INFO/);
    assert.match(issueEvidence, /summaryByTier/);
    assert.match(issueEvidence, /summarizeIssueEvidenceRows/);
    assert.match(issueEvidence, /Inherited issue context/);
    assert.match(issueEvidence, /zero score impact and cannot apply a score ceiling/);
    assert.match(issueEvidence, /Source\/static-only or otherwise unconfirmed evidence/);
    assert.match(issueEvidence, /scoreAffecting: false/);
    assert.match(issueEvidence, /Closed issues without release-fix credit/);
    assert.match(readme, /\/api\/releases\/:tag\/review\/issues/);
    assert.match(readme, /supports exact `issue`\/`number`/);
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
    assert.match(readme, /\/api\/releases\/:tag\/review\/closure-proofs.*supports exact `issue`\/`number`/);
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
    const taxonomy = readFileSync(join(root, 'src/lib/closureProofTaxonomy.ts'), 'utf8');
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const verifier = readFileSync(join(root, 'scripts/lib/release-audit-invariants.mjs'), 'utf8');
    CLOSURE_PROOF_STATUSES.forEach((status) =>
      assert.match(html, new RegExp(`${status}:`), `missing frontend closure label for ${status}`));
    CLOSURE_RISK_DISPOSITIONS.forEach((disposition) =>
      assert.match(html, new RegExp(`${disposition}:`), `missing frontend closure risk label for ${disposition}`));
    assert.match(payload, /CLOSURE_PROOF_STATUS_RANK/);
    assert.match(payload, /satisfies Record<ClosureProofStatus, number>/);
    assert.match(taxonomy, /function closureRiskDispositionLabel/);
    assert.match(taxonomy, /function closureRiskWeightLabel/);
    assert.match(api, /riskDispositionLabel: closureRiskDispositionLabel/);
    assert.match(api, /riskWeightLabel: closureRiskWeightLabel/);
    assert.match(verifier, /riskDispositionLabel/);
    assert.match(verifier, /riskWeightLabel/);
    assert.match(html, /Raw unresolved proof categories/);
    assert.match(html, /Raw proof statuses/);
    assert.match(html, /Raw proof audit/);
    assert.match(html, /closureProofExamplesWithStatusCoverage/);
    assert.match(html, /examplesByStatus/);
    assert.match(html, /commentEvidenceHtml\('Non-actionable rationale'/);
  });

  it('renders score explanations with human units and evidence-accurate copy', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const labelAuthority = readFileSync(join(root, 'src/lib/scoringLabelAuthority.ts'), 'utf8');
    assert.match(html, /Recommended at the highest audited score; the newest release wins when scores are equal/);
    assert.match(scorer, /recommended at the highest audited score; the newest release wins when scores are equal/i);
    assert.match(html, /scoredUnresolvedRiskGroupCount: 'scored risk groups'/);
    assert.match(html, /rawUnresolvedRiskGroupCount: 'raw unresolved proof groups'/);
    assert.match(html, /Scored: \$\{esc\(scoredClosureCount\)\} deduplicated groups/);
    assert.match(html, /Raw proof audit: \$\{esc\(closureRisk\.unresolvedForReleaseCount/);
    assert.match(html, /npm tarball bytes match registry SRI/);
    assert.match(html, /const failures = \[\.\.\.new Set/);
    assert.match(html, /function releaseCheckSummaryText/);
    assert.match(html, /of \$\{total\} passed · none failed or pending/);
    assert.match(html, /function scoreLedgerMetricText/);
    assert.match(html, /evidence weight/);
    assert.match(scorer, /opened weight/);
    assert.match(html, /row\?\.key === 'precisionAdjustment'.*Math\.abs\(value\) < 0\.01/s);
    assert.match(html, /return `\$\{value > 0 \? '\+' : '-'\}<0\.01`/);
    assert.match(html, /filter\(isScoreLimitingDetail\)/);
    assert.match(html, /filter\(\(issue\) => !isPlaceholderIssueTitle\(issue\)\)/);
    assert.match(scorer, /filter\(\(issue\) => !isPlaceholderIssueTitle\(issue\)\)/);
    assert.doesNotMatch(scorer, /addLimit\(\s*'audit_only_closed_issue_flags'/);
    assert.match(scorer, /Rounds the three-decimal component subtotal to the one-decimal final score/);
    assert.match(scorer, /downloaded npm tarball bytes match the registry SRI digest/i);
    assert.match(labelAuthority, /HUMAN_PRIORITY_LABELS = new Set\(\['P0', 'P1', 'beta-blocker', 'regression'\]\)/);
    assert.match(labelAuthority, /labelUsesScoreAuthority\(label\)/);
    assert.match(labelAuthority, /scoreAuthorityReferenceProblems\(decision\)\.length === 0/);
    assert.match(scorer, /scoringLabelInfoAtCutoff\(/);
    assert.match(scorer, /latestIssueLabelEventAt\(issueNumber, label, cutoff\)/);
    assert.match(scorer, /labelAuthorizedForScoring\(label, authority\)/);
    assert.match(scorer, /authorityReferenceForEvent\?\.\(event\.event_id\)/);
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
    assert.doesNotMatch(
      verifier,
      /knownProofStatuses\s*=\s*new Set\(\s*\[\s*'fixed_in_release'/,
    );
  });

  it('issue title truncation is word-boundary aware in the UI fallback', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function truncateAtWordBoundary/);
    assert.doesNotMatch(html, /slice\(0,\s*85\)/);
    assert.match(html, /untitled report/);
  });

  it('legacy public snapshot import requires explicit overwrite flag before loading app DB', () => {
    const script = readFileSync(join(root, 'scripts/import-public-snapshot.mjs'), 'utf8');
    assert.match(script, /Public snapshot import is permanently disabled/);
    assert.match(
      script,
      /comparison or snapshot data may never write or replace the .*authoritative GitHub release catalog/s,
    );
    assert.match(script, /in any configured or live database/);
    assert.match(script, /npm run scrape:upstream/);
    assert.doesNotMatch(script, /src\/lib\/db\.ts/);
    assert.doesNotMatch(script, /\bfetch\s*\(/);
    assert.doesNotMatch(
      script,
      /ALLOW_PUBLIC_SNAPSHOT_IMPORT|ALLOW_SCORED_PUBLIC_SNAPSHOT_IMPORT|allow-overwrite/,
    );
    assert.doesNotMatch(script, /\b(?:INSERT|UPDATE|DELETE)\b[\s\S]*\breleases\b/i);
  });

  it('score verifier is wired as a hard drift check', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const verifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const agents = readFileSync(join(root, 'AGENTS.md'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const config = readFileSync(join(root, 'src/config.ts'), 'utf8');
    assert.equal(pkg.scripts['verify:score'], 'tsx scripts/verify-new-scoring.mjs --check');
    assert.equal(pkg.scripts.start, 'NODE_ENV=production node dist/index.js');
    assert.equal(
      pkg.scripts['test:safety'],
      '/usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u npm_lifecycle_event ' +
        'node --no-global-search-paths test/run-database-guard.mjs',
    );
    assert.equal(
      pkg.scripts['verify:scripts'],
      'for f in scripts/*.mjs scripts/lib/*.mjs scripts/validation/*.mjs test/*.mjs test/*.cjs; do node --check "$f" || exit 1; done',
    );
    assert.equal(
      pkg.scripts['verify:authoritative-ci'],
      '/usr/bin/env -u NODE_OPTIONS -u NODE_PATH -u npm_lifecycle_event ' +
        'npm run test:safety && /usr/bin/env -u NODE_OPTIONS -u NODE_PATH ' +
        '-u npm_lifecycle_event npm run test:baseline -- --full --rerun',
    );
    assert.equal(
      pkg.scripts['verify:ci'],
      'npm run typecheck && npm run verify:scripts && npm run build',
    );
    assert.equal(pkg.scripts['verify:local'], 'npm run doctor -- --fail-on-warnings && npm run verify:score -- --all && npm run verify:release-audit -- --all');
    assert.equal(pkg.scripts['verify:live'], 'tsx scripts/verify-live.mjs --api-base http://127.0.0.1:8787 && npm run doctor -- --fail-on-warnings --api-base http://127.0.0.1:8787 && npm run verify:score -- --all && npm run verify:release-audit -- --all --api-base http://127.0.0.1:8787 && npm run ui:smoke');
    assert.equal(pkg.scripts.doctor, 'tsx scripts/doctor.mjs');
    assert.match(config, /const refreshIntervalMinutes = intInRange\('REFRESH_MINUTES', 0, 0, 600\)/);
    assert.match(config, /refresh: \{[\s\S]*?intervalMinutes: refreshIntervalMinutes,/);
    assert.match(config, /if \(production && \(refreshOnStartup \|\| refreshIntervalMinutes !== 0\)\)/);
    assert.match(
      config,
      /function requireProductionDatabaseSafety\(\): void \{[\s\S]*?requireProductionValue\('RADAR_DB_READ_ONLY'\)[\s\S]*?readOnly !== '1' && readOnly !== 'true'[\s\S]*?requireProductionValue\('RADAR_DB_BOOTSTRAP_MODE'\)[\s\S]*?bootstrapMode !== 'existing'/,
    );
    assert.match(
      config,
      /if \(production\) \{\s*requireProductionDatabaseSafety\(\);/,
    );
    assert.equal(pkg.scripts['backfill:issue-comment-snapshots'], 'tsx scripts/backfill-issue-comment-snapshots.mjs');
    const uiSmoke = readFileSync(join(root, 'scripts/ui-smoke.mjs'), 'utf8');
    const liveVerifier = readFileSync(join(root, 'scripts/verify-live.mjs'), 'utf8');
    const doctor = readFileSync(join(root, 'scripts/doctor.mjs'), 'utf8');
    const doctorHealth = readFileSync(join(root, 'scripts/lib/doctor-health.mjs'), 'utf8');
    const commentSnapshotBackfill = readFileSync(join(root, 'scripts/backfill-issue-comment-snapshots.mjs'), 'utf8');
    assert.match(commentSnapshotBackfill, /listIssueCommentSnapshotsBatch/);
    assert.match(commentSnapshotBackfill, /reconcileIssueCommentSnapshots/);
    assert.match(commentSnapshotBackfill, /canonicalManualScope/);
    assert.match(commentSnapshotBackfill, /supersedeExactIngestionEvidenceFailures/);
    assert.match(commentSnapshotBackfill, /snapshotCommitted/);
    assert.match(commentSnapshotBackfill, /scored_at IS NOT NULL/);
    assert.match(commentSnapshotBackfill, /release_score_audits/);
    assert.doesNotMatch(commentSnapshotBackfill, /supersedeIngestionEvidenceFailures\(/);
    assert.match(readme, /backfill:issue-comment-snapshots/);
    assert.match(doctor, /readOnly: true/);
    assert.match(doctor, /PRAGMA query_only = ON/);
    assert.match(doctor, /closure proof rows/);
    assert.match(doctor, /expected exactly one recommended scored stable release/);
    assert.match(doctor, /no audited stable release found/);
    assert.match(doctorHealth, /classificationFailures/);
    assert.match(doctorHealth, /scoredAt is not a valid timestamp/);
    assert.match(doctorHealth, /sourceFetchedAtMax is not a valid timestamp/);
    assert.match(doctorHealth, /issueUpdatedAtMax is not a valid timestamp/);
    assert.match(doctorHealth, /freshness maxAt is not a valid timestamp/);
    assert.match(doctor, /failOnWarnings/);
    assert.match(doctor, /fail-on-warnings/);
    assert.match(doctor, /api-base/);
    assert.match(doctor, /api public recommended tag/);
    assert.match(doctor, /api status lastScoredAt/);
    assert.match(verifier, /buildReleaseScoreRun/);
    assert.match(verifier, /currentScoreCompletenessDiagnostic/);
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
    assert.match(verifier, /process\.exitCode = 1/);
    assert.doesNotMatch(verifier, /process\.exit\(1\)/);
    assert.match(dbModule, /export const dbReadOnly/);
    assert.match(dbModule, /readOnly: true/);
    assert.match(dbModule, /PRAGMA query_only = ON/);
    const normalIterationContract = 'Normal iteration is `npm run test:preflight` only when the installer changed, `npm run test:focus -- <manifest-test-file> [--name <pattern>]`, optional `npm run test:focus -- --authoritative <manifest-test-file> [--name <pattern>]`, then `npm run verify:ci`.';
    const fullGateContract = 'Run the full gate once, after implementation stabilizes and before push or deploy: choose either `npm test -- --full` or `npm run test:baseline -- --full`, not both.';
    const baselineAcceptanceContract = 'Baseline acceptance is separate: review the generated candidate, then run `npm run test:baseline:accept`.';
    const fullArgumentContract = 'Full test runs require the explicit `--full` flag, and each entrypoint rejects unsupported forwarded arguments.';
    for (const [label, document] of [
      ['README.md', readme],
      ['AGENTS.md', agents],
      ['docs/scoring-model.md', scoringDoc],
    ] as const) {
      assert.ok(
        document.includes(normalIterationContract),
        `${label} must document the exact normal iteration workflow`,
      );
      assert.ok(
        document.includes(fullGateContract),
        `${label} must document the exact single full-gate workflow`,
      );
      assert.ok(
        document.includes(baselineAcceptanceContract),
        `${label} must keep baseline acceptance separate`,
      );
      assert.ok(
        document.includes(fullArgumentContract),
        `${label} must require the explicit full-suite flag`,
      );
      assert.doesNotMatch(
        document,
        /^npm test\s*$/m,
        `${label} must not document a bare full-suite command`,
      );
      assert.doesNotMatch(
        document,
        /^npm test -- --full\s*\n\s*npm run test:baseline -- --full$/m,
        `${label} must not run both full gates back-to-back`,
      );
    }
    assert.match(readme, /npm run verify:ci/);
    assert.match(readme, /npm run verify:scripts/);
    assert.match(readme, /npm run test:safety/);
    assert.match(readme, /Raw VM\s+disk operations are not part of this repository workflow/);
    assert.match(
      readme,
      /supported app\s+runtimes are `npm run dev` \(`tsx watch src\/index\.ts`\) for local development and\s+`npm start` \(`NODE_ENV=production node dist\/index\.js`\) for an installer-authorized\s+production release/,
    );
    assert.match(readme, /eval, print, stdin, or custom import script/);
    assert.match(agents, /Raw VM disk operations are not part of this repository workflow/);
    assert.match(agents, /exact app runtimes declared in `package\.json`/);
    assert.match(scoringDoc, /workflow runs `verify:authoritative-ci` on macOS[\s\S]*npm run test:baseline -- --full --rerun/);
    assert.match(
      scoringDoc,
      /Raw VM\s+disk operations are outside this repository\s+workflow/,
    );
    assert.match(
      scoringDoc,
      /Eval,\s+print, stdin, and custom import\s+scripts must use an\s+explicit\s+fresh\s+private\s+`DB_PATH`/,
    );
    assert.match(readme, /npm run verify:local/);
    assert.match(readme, /npm run verify:live/);
    assert.match(readme, /desktop\/mobile browser layout smoke checks/);
    assert.match(uiSmoke, /viewport: \{ width: 1440, height: 1000 \}/);
    assert.match(uiSmoke, /viewport: \{ width: 390, height: 844 \}/);
    assert.match(uiSmoke, /assertNoHorizontalOverflow/);
    assert.match(uiSmoke, /page\.screenshot/);
    assert.match(uiSmoke, /uniqueByteCount/);
    assert.match(uiSmoke, /mobile score review/);
    assert.match(uiSmoke, /UI smoke coverage:/);
    assert.match(uiSmoke, /eligible nonrecommended/);
    assert.match(uiSmoke, /fix-credit link examples/);
    assert.match(uiSmoke, /assertReleaseRowsDoNotOverlap/);
    assert.match(liveVerifier, /\/api\/live returned HTTP/);
    assert.match(liveVerifier, /\/api\/health returned HTTP/);
    assert.match(liveVerifier, /status must equal live/);
    assert.match(liveVerifier, /status must equal ready/);
    assert.match(liveVerifier, /checks are not all ok/);
    assert.ok(
      liveVerifier.indexOf('`${base}/api/live`') <
        liveVerifier.indexOf('`${base}/api/health`'),
      'live verification must check process liveness before semantic readiness',
    );
    assert.match(readme, /npm run doctor/);
    assert.match(readme, /classification failures/);
    assert.match(readme, /release-metadata\/artifact\/release-check\/advisory\/monitored-release evidence refresh failures/);
    assert.match(readme, /durable `ingestion_evidence_failures` rows/);
    assert.match(readme, /Release metadata, release-window context, artifact verification, release commit checks, and security advisories are score-affecting evidence/);
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

  it('deploy workflow ships a production-only runtime and polls semantic readiness', () => {
    const workflow = readFileSync(join(root, '.github/workflows/deploy-radar.yml'), 'utf8');
    const installer = readFileSync(
      join(root, 'ops/viralo/openclaw-release-radar-install-release.sh'),
      'utf8',
    );
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const bootUnit = readFileSync(
      join(root, 'ops/viralo/openclaw-release-radar-reconcile-boot.service'),
      'utf8',
    );
    const applicationService = readFileSync(
      join(root, 'ops/viralo/openclaw-release-radar.service'),
      'utf8',
    );
    const serviceDropIn = readFileSync(
      join(
        root,
        'ops/viralo/openclaw-release-radar.service.d/10-deploy-reconcile.conf',
      ),
      'utf8',
    );
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const index = readFileSync(join(root, 'src/index.ts'), 'utf8');
    const startupAuthorization = readFileSync(
      join(root, 'src/lib/startupAuthorization.ts'),
      'utf8',
    );
    const runtimeVerifier = readFileSync(join(root, 'src/lib/scoreAuditContracts.ts'), 'utf8');
    const scoreVerifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
    const auditVerifier = readFileSync(join(root, 'scripts/lib/release-audit-invariants.mjs'), 'utf8');
    assert.match(workflow, /verify-authoritative:/);
    assert.match(workflow, /runs-on: macos-latest/);
    assert.match(workflow, /npm run verify:authoritative-ci/);
    assert.match(workflow, /needs: verify-authoritative/);
    assert.match(workflow, /npm run verify:ci/);
    assert.doesNotMatch(workflow, /run: npm run typecheck/);
    assert.doesNotMatch(workflow, /name: Build app[\s\S]*?run: npm run build/);
    assert.match(workflow, /npm ci --omit=dev --prefix "\$release_root"/);
    assert.match(workflow, /dist\/lib\/releaseValidationOpportunityStatus\.js/);
    assert.match(workflow, /test ! -e "\$release_root\/node_modules\/tsx"/);
    assert.match(workflow, /install -d -m 700 "\$smoke_root"/);
    assert.match(
      workflow,
      /cat > "\$release_root\/\.env" <<EOF\s+PORT=8787\s+DB_PATH=\$smoke_root\/radar\.db\s+RADAR_DB_READ_ONLY=1\s+RADAR_DB_BOOTSTRAP_MODE=existing\s+REFRESH_ON_STARTUP=false\s+REFRESH_MINUTES=0\s+RADAR_CODE_REVISION=\$GITHUB_SHA\s+EOF\s+chmod 600 "\$release_root\/\.env"/,
    );
    assert.match(
      workflow,
      /DB_PATH=\/tmp\/inherited-db-must-be-ignored \\\s+REFRESH_ON_STARTUP=true \\\s+REFRESH_MINUTES=99 \\\s+RADAR_CODE_REVISION=f{40} \\\s+DOTENV_CONFIG_PATH=\/tmp\/inherited-dotenv-must-be-ignored \\\s+node "\$release_root\/dist\/index\.js" --print-effective-config/,
    );
    assert.match(workflow, /payload\.source\?\.kind !== 'release-runtime-env'/);
    assert.match(
      workflow,
      /payload\.source\?\.path !== path\.join\(process\.env\.RELEASE_ROOT, '\.env'\)/,
    );
    assert.match(
      workflow,
      /payload\.source\?\.realPath !== fs\.realpathSync\(path\.join\(process\.env\.RELEASE_ROOT, '\.env'\)\)/,
    );
    assert.match(
      workflow,
      /payload\.database\?\.path !== fs\.realpathSync\(process\.env\.SMOKE_DB\)/,
    );
    assert.match(workflow, /payload\.refresh\?\.onStartup !== false/);
    assert.match(workflow, /payload\.refresh\?\.intervalMinutes !== 0/);
    assert.match(workflow, /payload\.release\?\.revision !== process\.env\.GIT_SHA/);
    assert.match(
      installer,
      /RADAR_CODE_REVISION=%s\\nRADAR_DB_READ_ONLY=1\\nRADAR_DB_BOOTSTRAP_MODE=existing\\n/,
    );
    assert.match(
      installer,
      /production shared \.env must not define \$\{key\}; the installer binds it per release/,
    );
    assert.match(
      installer,
      /release runtime env does not bind RADAR_DB_READ_ONLY=1/,
    );
    assert.match(
      installer,
      /release runtime env does not bind RADAR_DB_BOOTSTRAP_MODE=existing/,
    );
    assert.match(
      installer,
      /quality-db-promotion-authorization-v1\\0/,
    );
    assert.match(
      installer,
      /promotion authorization has no exact independent GitHub catalog proof/,
    );
    assert.match(
      installer,
      /promotionAuthorizationContentHash/,
    );
    assert.match(
      installer,
      /promotionAuthorization\?\.installedDatabase/,
    );
    assert.match(
      installer,
      /installed database physical digest does not match promotion authorization/,
    );
    assert.match(installer, /write_pending_startup_authorization/);
    assert.match(installer, /write_committed_startup_authorization_at/);
    assert.match(installer, /restore_previous_startup_authorization_at/);
    assert.match(workflow, /tar -C "\$release_root" -czf "\$GITHUB_WORKSPACE\/\$RELEASE_TARBALL" \./);
    assert.match(workflow, /schemaVersion: 4/);
    assert.match(workflow, /applicationService: \{/);
    assert.match(workflow, /controlPlane: \{/);
    assert.match(workflow, /reconcileBootService:/);
    assert.match(workflow, /serviceDropIn:/);
    assert.match(
      workflow,
      /remote_upload="\/tmp\/\$RELEASE_NAME-\$DEPLOY_TRANSACTION_ID\.tar\.gz"/,
    );
    assert.match(workflow, /payload\.status !== "ready"/);
    assert.match(
      workflow,
      /requiredChecks\.some\(\(name\) => checks\[name\]\?\.ok !== true\)/,
    );
    assert.match(workflow, /npx playwright install --with-deps chromium/);
    assert.match(workflow, /sudo systemctl cat openclaw-release-radar\.service/);
    assert.match(
      workflow,
      /publish_root_file \\\s+"\$source_root\/openclaw-release-radar\.service" \\\s+\/etc\/systemd\/system\/openclaw-release-radar\.service \\\s+644 \\\s+"\$application_service_sha"/,
    );
    assert.match(workflow, /command -v lsof/);
    assert.match(workflow, /command -v getfacl/);
    assert.match(workflow, /command -v getfattr/);
    assert.match(workflow, /DEPLOY_VERIFIER_HMAC_KEY must contain at least 32 safe bytes/);
    assert.match(workflow, /const requiredChecks = \[/);
    assert.match(workflow, /payload\.schemaVersion !== 1/);
    assert.match(workflow, /API_BASE="\$public_base" npm run ui:smoke/);
    assert.ok(
      workflow.indexOf('name: Verify public health endpoint') <
        workflow.indexOf('name: Verify deployed public UI'),
      'deployed UI smoke must run after semantic readiness',
    );
    assert.match(installer, /dist\/lib\/releaseValidationOpportunityStatus\.js/);
    assert.match(installer, /release artifact unexpectedly contains dev-only tsx/);
    assert.match(
      installer,
      /code-only activation is restricted to explicit installer test mode/,
    );
    assert.doesNotMatch(installer, /npm ci|npx tsx|npm run doctor/);
    assert.match(installer, /invalid release name: expected one safe basename/);
    assert.match(
      installer,
      /staging_dir="\$releases\/\.\$\{release_name\}\.staging-\$\{transaction_id\}"/,
    );
    assert.match(installer, /validate_runtime "\$staging_dir"/);
    assert.match(installer, /release_digest "\$staging_dir"/);
    assert.match(installer, /release already exists with different contents/);
    assert.match(installer, /fs\.renameSync\(process\.argv\[2\], process\.argv\[3\]\)/);
    assert.match(
      installer,
      /read_current_target\(\) \{[\s\S]*if \[ -L "\$current" \]; then[\s\S]*readlink "\$current"/,
    );
    assert.match(
      installer,
      /if previous_current_target="\$\(read_current_target\)"; then/,
    );
    assert.match(installer, /restore_previous_release/);
    assert.match(installer, /artifact_root="\$shared\/deploy-artifacts"/);
    assert.match(installer, /installer-pending-promotion-v2/);
    assert.match(installer, /recover_verified_authorization_at/);
    assert.match(installer, /append_phase_transition_at "\$state_root" verified/);
    assert.match(installer, /release control-plane digest mismatch/);
    assert.match(serviceDropIn, /Requires=openclaw-release-radar-reconcile-boot\.service/);
    assert.doesNotMatch(serviceDropIn, /Wants=/);
    assert.match(
      applicationService,
      /ExecStartPre=.*--verify-startup-authorization/,
    );
    assert.match(
      index,
      /const startupAuthorization = requireProductionStartupAuthorization\(\);[\s\S]*?require\('\.\/routes\/api'\)/,
    );
    assert.ok(
      index.indexOf('requireProductionStartupAuthorization()') <
        index.indexOf("require('./routes/api')"),
      'startup authorization must run before the first DB-capable API import',
    );
    assert.match(
      index,
      /const revalidated = requireProductionStartupAuthorization\(\);[\s\S]*?app\.listen/,
    );
    assert.ok(
      index.indexOf('const revalidated = requireProductionStartupAuthorization();') <
        index.indexOf('app.listen('),
      'startup authorization must be revalidated after DB-capable imports and before listening',
    );
    assert.match(
      startupAuthorization,
      /lifecycle: 'pending-activation' \| 'committed-completion'/,
    );
    assert.match(
      startupAuthorization,
      /installed database physical digest does not match authorization/,
    );
    assert.match(
      startupAuthorization,
      /validateCommittedFinalization/,
    );
    assert.doesNotMatch(bootUnit, /ConditionPathExists=/);
    assert.match(installer, /previous release restored/);
    assert.match(installer, /semantic_ready/);
    assert.match(installer, /payload\.status !== "ready"/);
    assert.match(readme, /`\/api\/live` does not read SQLite/);
    assert.match(readme, /performs no server-side dependency installation or network package fetch/);
    assert.match(readme, /verified `promotion-runtime` bundled in the release artifact/);
    assert.match(readme, /immutable deployment completion receipts/);
    assert.match(readme, /shared\/deploy-completions\//);
    assert.match(readme, /fresh staging directory/);
    assert.match(readme, /atomically replaces the `current` symlink/);
    assert.match(readme, /restores and restarts the prior release/);
    assert.match(api, /api\.get\('\/live'/);
    assert.match(api, /api\.get\('\/health'/);
    assert.match(api, /releaseClosureProofIntegrity/);
    assert.match(api, /listActiveIngestionEvidenceFailures/);
    assert.match(api, /currentRecommendationRun/);
    assert.match(api, /const candidateContexts = listReleasesDb\(config\.limits\.releases\)/);
    assert.match(api, /releaseClosureProofIntegrity\(release\.tag, 3\)/);
    assert.match(api, /staleReleaseTags: staleClosureProofCandidates/);
    assert.match(api, /res\.status\(payload\.ok \? 200 : 503\)/);
    assert.match(api, /from '\.\.\/lib\/scoreAuditContracts'/);
    assert.doesNotMatch(api, /scripts\/lib\/score-audit-contracts|scoreAuditContractsReady|nativeImport/);
    assert.match(runtimeVerifier, /export function verifyScoreAuditPayloadContracts/);
    assert.match(scoreVerifier, /from '\.\.\/src\/lib\/scoreAuditContracts\.ts'/);
    assert.match(auditVerifier, /from '\.\.\/\.\.\/src\/lib\/scoreAuditContracts\.ts'/);
    assert.match(
      readFileSync(join(root, 'scripts/lib/release-audit-reader.mjs'), 'utf8'),
      /currentScoreReceiptProblems/,
    );
  });

  it('promotion preserves operation receipts and revalidates source and activity boundaries', () => {
    const promotion = readFileSync(join(root, 'scripts/promote-quality-db.mjs'), 'utf8');
    const promotionTests = readFileSync(join(root, 'src/lib/promoteQualityDb.test.ts'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    assert.match(promotion, /mergeDestinationOperationReceipts/);
    assert.match(promotion, /destinationChainPreservedAsPrefix: true/);
    assert.match(promotion, /verifyOperationReceiptLedgerRows/);
    assert.match(promotion, /phase: 'source-after-staging'/);
    assert.match(promotion, /phase: 'source-immediately-before-swap'/);
    assert.match(promotion, /phase: 'before-success'/);
    assert.match(promotion, /phase: 'before-rollback'/);
    assert.match(promotion, /phase: 'after-rollback'/);
    assert.match(promotionTests, /preserves the destination receipt chain/);
    assert.match(promotionTests, /source contents drift after staging/);
    assert.match(promotionTests, /source inode is replaced at the final swap boundary/);
    assert.match(promotionTests, /active leases before reporting success/);
    assert.match(promotionTests, /refresh lease appears at the rollback boundary/);
    assert.match(
      promotionTests,
      /rejects a real-default promotion before validation when no canonical evaluation receipt exists/,
    );
    assert.match(promotionTests, /rejects an internally consistent obsolete model with the real score verifier/);
    assert.match(promotionTests, /rejects internally consistent but mathematically wrong scores with the real score verifier/);
    assert.match(readme, /destination capture-receipt chain remains the exact prefix/);
    assert.match(readme, /full source family, holder, lease, and logical-identity revalidation/);
    assert.match(readme, /holders across both complete SQLite families and active refresh leases before final success and around rollback/);
  });

  it('refresh orchestration is executable through durable success and failure receipts', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    const qualityRefresh = readFileSync(
      join(root, 'scripts/refresh-quality-db.mjs'),
      'utf8',
    );
    const qualityRefreshCli = readFileSync(
      join(root, 'scripts/lib/quality-refresh-cli.mjs'),
      'utf8',
    );
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const receipts = readFileSync(join(root, 'src/lib/operationReceipts.ts'), 'utf8');
    const refreshTests = readFileSync(join(root, 'src/lib/refresh.test.ts'), 'utf8');
    const receiptTests = readFileSync(join(root, 'src/lib/operationReceipts.test.ts'), 'utf8');
    const provenanceTests = readFileSync(join(root, 'src/lib/db.provenance.test.ts'), 'utf8');
    assert.match(refresh, /function createRefreshOrchestration/);
    assert.match(refresh, /orchestration\.publishScore\(\{/);
    assert.match(refresh, /terminalReceiptId = orchestration\?\.fail\(e\)/);
    assert.match(qualityRefresh, /process\.env\.RADAR_DB_READ_ONLY = '0'/);
    assert.match(
      qualityRefreshCli,
      /argv\.length === 3[\s\S]*?argv\[2\] === '--resume-existing'/,
    );
    assert.doesNotMatch(qualityRefreshCli, /process\.env/);
    assert.match(
      qualityRefreshCli,
      /const SQLITE_FAMILY_SUFFIXES = \['', '-wal', '-shm', '-journal'\]/,
    );
    assert.match(
      qualityRefreshCli,
      /member\.lstat\.isSymbolicLink\(\) \|\| !member\.lstat\.isFile\(\)/,
    );
    assert.match(
      qualityRefreshCli,
      /left\.stat\.dev === right\.stat\.dev[\s\S]*?left\.stat\.ino === right\.stat\.ino/,
    );
    const forceFreshIndex = qualityRefresh.indexOf(
      "process.env.RADAR_DB_BOOTSTRAP_MODE = 'fresh'",
    );
    const writerLockIndex = qualityRefresh.indexOf(
      'const writerLock = acquireRepositoryDatabaseWriterLock',
    );
    const familyValidationIndex = qualityRefresh.indexOf(
      'validateQualityRefreshDatabase({',
    );
    const resumeBootstrapIndex = qualityRefresh.indexOf(
      "process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing'",
    );
    const databaseImportIndex = qualityRefresh.indexOf(
      "await import('../src/lib/db.ts')",
    );
    assert.ok(
      forceFreshIndex >= 0 &&
        forceFreshIndex < writerLockIndex &&
        writerLockIndex < familyValidationIndex &&
        familyValidationIndex < resumeBootstrapIndex &&
        resumeBootstrapIndex < databaseImportIndex,
      'quality refresh must force fresh mode, lock, validate, select resume mode, then import',
    );
    assert.match(qualityRefresh, /databaseModule\?\.db\.close\(\)/);
    assert.match(qualityRefresh, /writerLock\.release\(\)/);
    assert.match(dbModule, /assertActiveRefreshLeaseFence\(\{/);
    assert.match(dbModule, /without an active started stage/);
    assert.match(dbModule, /function recoverUnsuccessfulRefreshScoreTip/);
    assert.match(dbModule, /restoreLatestActionableRefreshScorePublication/);
    assert.match(
      dbModule,
      /authority_run_id:\s*historyRow\.authority_run_id/,
    );
    assert.match(dbModule, /function displacedRefreshPublicationBindingsAfter/);
    assert.match(dbModule, /score-publication-recovery-bindings-v1/);
    assert.match(dbModule, /displacedPublicationDigest/);
    assert.match(dbModule, /displacedPublications:\s*displacedPublications\.bindings/);
    assert.match(dbModule, /restoredAuthorityRunContentHash/);
    assert.match(dbModule, /displacedHistoryV2SealContentHash/);
    assert.match(receipts, /successful refresh requires score\.persist then forecast\.capture/);
    assert.match(receipts, /not backed by its active matching lease/);
    assert.match(
      refreshTests,
      /orchestrates attempt, injected evidence stages, score, not-eligible forecast, and success receipt/,
    );
    assert.match(
      refreshTests,
      /records failed score orchestration with a terminal failure receipt and no forecast stage/,
    );
    assert.match(receiptTests, /rejects stale holders for both stage and receipt appends/);
    assert.match(receiptTests, /rejects zero-stage successful score-publishing refresh receipts/);
    assert.match(receiptTests, /rejects inactive stage completion before inserting a ledger row/);
    assert.match(receiptTests, /accepts unterminated attempts only while their matching lease is active/);
    assert.match(provenanceTests, /clears a receiptless sealed score tip when no prior actionable publication exists/);
    assert.match(provenanceTests, /restores the prior actionable publication after receiptless, failed, or abandoned tips/);
    assert.match(provenanceTests, /restores across an ordered suffix of multiple unsuccessful publications/);
    assert.match(provenanceTests, /history and authority restoration metadata is invalid/);
  });

  it('offline score writers use the shared release scorer', () => {
    const populate = readFileSync(join(root, 'scripts/populate-db.mjs'), 'utf8');
    const backfill = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    const verifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const doctor = readFileSync(join(root, 'scripts/doctor.mjs'), 'utf8');
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const bridgeTest = readFileSync(join(root, 'src/lib/releaseScoringDbBridge.test.ts'), 'utf8');
    const timelineGuardTest = readFileSync(join(root, 'src/lib/releaseScoringTimelineGuard.test.ts'), 'utf8');
    const provenanceTest = readFileSync(join(root, 'src/lib/db.provenance.test.ts'), 'utf8');
    assert.match(populate, /buildReleaseScoreRun/);
    assert.match(populate, /const initialMonitored = listReleasesDb\(10\);\s*assertCleanIngestionMetadataBeforeScore\(initialMonitored\);/);
    assert.match(populate, /const setStableGap/);
    assert.ok(
      populate.indexOf('assertCleanIngestionMetadataBeforeScore(initialMonitored)') < populate.indexOf('const setStableGap'),
      'populate-db must validate ingestion metadata before preparing DB mutations',
    );
    assert.match(populate, /persistReleaseScoreRun/);
    assert.match(populate, /source: 'populate-db'/);
    assert.doesNotMatch(populate, /new DatabaseSync/);
    assert.match(backfill, /buildReleaseScoreRun/);
    assert.match(backfill, /assertCleanIngestionMetadataBeforeScore\(monitoredReleases/);
    assert.match(backfill, /buildReleaseScoreRun\(scoreRunWindowOptions\(monitoredReleases\)\)/);
    assert.match(backfill, /monitoredScoreWindowReleases/);
    assert.match(backfill, /selectedCoversMonitoredWindow/);
    assert.match(backfill, /status: 'staged-only'/);
    assert.match(backfill, /persistReleaseScoreRun/);
    assert.match(backfill, /source: 'backfill-closed-windows'/);
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /persistReleaseScoreRun\(scoreRun, \{/);
    assert.match(refresh, /source: 'refresh'/);
    assert.match(refresh, /issueCrawl: issueCrawlMeta/);
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
    assert.match(scorer, /stableReleaseWindowIntegrity/);
    assert.match(scorer, /formatStableReleaseWindowIntegrityFailure/);
    assert.match(scorer, /releaseIssueTimelineIntegrity/);
    assert.match(scorer, /formatReleaseIssueTimelineIntegrityFailure/);
    assert.match(scorer, /runInWriteTransaction/);
    assert.match(scorer, /releaseClosureProofIntegrity/);
    assert.match(scorer, /formatReleaseClosureProofIntegrityFailure/);
    assert.match(scorer, /releasePrReachabilityIntegrity/);
    assert.match(scorer, /formatReleasePrReachabilityIntegrityFailure/);
    assert.match(dbModule, /stableReleaseWindowIntegrity/);
    assert.match(dbModule, /formatStableReleaseWindowIntegrityFailure/);
    assert.match(dbModule, /releaseIssueTimelineIntegrity/);
    assert.match(dbModule, /formatReleaseIssueTimelineIntegrityFailure/);
    assert.match(timelineGuardTest, /issue open-interval evidence is ambiguous/);
    assert.match(provenanceTest, /ambiguous-reopen-interval/);
    assert.match(provenanceTest, /stable-window-integrity/);
    assert.match(scorer, /score_persistence_last_run/);
    assert.match(scorer, /clearReleaseScoresOutsideTags\(run\.scored\.map/);
    assert.match(doctor, /auditedStableTags/);
    assert.match(doctor, /scoredStableTags/);
    assert.match(doctor, /missingAuditTags/);
    assert.match(doctor, /orphanAuditTags/);
    assert.match(doctor, /releaseAuditMismatches/);
    assert.match(doctor, /auditModelVersions/);
    assert.match(doctor, /auditPromptVersions/);
    assert.match(doctor, /score persistence releaseTags do not match scored stable release rows/);
    assert.match(doctor, /score persistence missing release_score_audits rows for scored stable releases/);
    assert.match(doctor, /score persistence has audit rows without scored stable release rows/);
    assert.match(doctor, /score persistence release\/audit field mismatch/);
    assert.match(doctor, /score persistence releaseTags do not match audited stable rows/);
    assert.match(doctor, /score persistence scoreModelVersion does not match audited stable rows/);
    assert.match(doctor, /score persistence promptVersion does not match audited stable rows/);
    assert.match(scorer, /last_scored_at/);
    assert.match(dbModule, /writeTransactionDepth/);
    assert.match(dbModule, /SAVEPOINT/);
    assert.match(dbModule, /ROLLBACK TO SAVEPOINT/);
    assert.match(bridgeTest, /getReleaseScoreAudit\('v-tx'\), undefined/);
    assert.match(bridgeTest, /score_persistence_last_run/);
    assert.match(bridgeTest, /persistReleaseScoreRun/);
  });

  it('legacy fix provenance ingestion runs the full proof pipeline', () => {
    const script = readFileSync(join(root, 'scripts/ingest-fix-provenance.mjs'), 'utf8');
    assert.match(script, /releaseTagArg/);
    assert.match(script, /assertValidIssueCrawlMetadataBeforeMutation/);
    assert.match(script, /insertIngestionEvidenceFailure/);
    assert.match(script, /await import\('\.\.\/src\/lib\/closureProofAnalysis\.ts'\)/);
    assert.match(script, /refreshClosureEvidenceForRelease/);
    assert.match(script, /checkReleasePrReachability/);
    assert.match(script, /analyzeClosureProofsForRelease/);
    assert.match(script, /persistScoreAuditPayload: false/);
    assert.match(script, /status: 'staged-only'/);
    assert.match(script, /supersedeExactIngestionEvidenceFailures/);
    assert.doesNotMatch(script, /buildReleaseScoreRun|persistReleaseScoreRun/);
    assert.doesNotMatch(script, /listIssueFixEvidenceBatch/);
    assert.doesNotMatch(script, /upsertIssueClosureEvent/);
  });

  it('single-release proof scripts validate release tags before loading DB writers', () => {
    const helper = readFileSync(join(root, 'scripts/lib/release-tag-arg.mjs'), 'utf8');
    assert.match(helper, /--help/);
    assert.match(helper, /startsWith\('-'\)/);
    assert.match(helper, /Expected exactly one release tag/);
    assert.doesNotMatch(helper, /defaultTag|v2026\.6\.10/);
    for (const file of [
      'scripts/analyze-closure-proofs.mjs',
      'scripts/ingest-fix-provenance.mjs',
      'scripts/check-release-pr-reachability.mjs',
    ]) {
      const script = readFileSync(join(root, file), 'utf8');
      if (file === 'scripts/check-release-pr-reachability.mjs') {
        assert.match(
          script,
          /parseReleaseReachabilityArgs\(process\.argv\.slice\(2\)/,
          `${file} must validate args first`,
        );
      } else {
        assert.match(
          script,
          /releaseTagArg\(process\.argv\.slice\(2\)/,
          `${file} must validate args first`,
        );
      }
      assert.doesNotMatch(script, /^import \{ .* \} from '\.\.\/src\/lib\//m, `${file} must not statically import DB/network modules`);
      assert.match(script, /await import\('\.\.\/src\/lib\//, `${file} should dynamically import DB/network modules after validation`);
      assert.match(script, /getRelease/);
      assert.match(script, /currentAuthorizedReleaseCatalog/);
      assert.match(script, /catalog_active !== 1/);
      assert.match(script, /prerelease !== 0/);
      assert.match(script, /authorizedCatalog\.tags\.includes/);
    }
    for (const file of [
      'scripts/analyze-closure-proofs.mjs',
      'scripts/ingest-fix-provenance.mjs',
    ]) {
      const script = readFileSync(join(root, file), 'utf8');
      assert.match(script, /assertValidIssueCrawlMetadataBeforeMutation\(\)/, `${file} must validate crawl schema and baseline before mutation`);
      assert.match(script, /insertIngestionEvidenceFailure/, `${file} must record durable failure provenance`);
      assert.match(script, /persistScoreAuditPayload: false/, `${file} must keep proof writes side-table-only before final scoring`);
      assert.match(script, /createClosureProofRunContext/, `${file} must share one accepted comment snapshot context`);
      assert.match(script, /acquireRenewableRefreshLease/, `${file} must hold one renewable write lease`);
      assert.match(script, /refreshClosureEvidenceForRelease\(releaseTag, closureRunContext\)/, `${file} must reuse comment snapshots for raw evidence`);
      assert.match(script, /runContext: closureRunContext/, `${file} must reuse comment snapshots for proof analysis`);
      assert.match(script, /reconcileClosureSnapshotDrift/, `${file} must reconcile detected metadata drift`);
      assert.match(script, /maxAnalysisAttempts = 4/, `${file} must bound proof reconciliation retries`);
      assert.match(script, /supersedeExactIngestionEvidenceFailures/, `${file} must recover only its exact failure tuple`);
      assert.match(script, /status: 'staged-only'/, `${file} must leave score replacement to a full-window command`);
      assert.doesNotMatch(script, /persistReleaseScoreRun/, `${file} must not replace scores after a one-tag repair`);
    }
  });

  it('issue-state backfill fetches evidence before writing rows', () => {
    const script = readFileSync(join(root, 'scripts/backfill-issue-state-events.mjs'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.match(script, /insertIngestionEvidenceFailure/);
    assert.match(script, /runInWriteTransaction/);
    assert.match(script, /recordBackfillEvidenceFailure/);
    assert.match(script, /backfill-issue-state-events-write/);
    assert.match(script, /onMissingIssueAlias/);
    assert.match(script, /const evidenceByIssue = new Map/);
    assert.match(script, /acquireRenewableRefreshLease/);
    assert.match(script, /assertIssueEvidenceRevisions/);
    assert.match(script, /lease\.assertHeld\('issue state evidence persistence'\)/);
    assert.match(script, /supersedeExactIngestionEvidenceFailures/);
    assert.match(script, /stateEvidenceCommitted/);
    assert.match(script, /replaceVerifiedIssueStateEventSnapshot\(evidence\)/);
    assert.match(readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8'), /deleteIssueCommitReferencesForIssues/);
    assert.ok(
      script.indexOf('const evidenceByIssue = new Map') < script.indexOf('runInWriteTransaction(() => {'),
      'issue-state backfill must fetch all evidence before snapshot writes',
    );
    assert.ok(
      script.indexOf('runInWriteTransaction(() => {') < script.indexOf('snapshotCurrentLabels(issueNumbers, snapshotAt)'),
      'issue-state backfill must write snapshots/events inside one transaction',
    );
    assert.match(readme, /fetches all GitHub state evidence before writing/);
    assert.match(readme, /writes snapshots, closure\/reopen events, PR links, and PR rows in one transaction/);
    assert.match(scoringDoc, /writes the full snapshot\/event\/PR batch in one DB transaction/);
    assert.match(scoringDoc, /post-commit lease\/recovery failure reports that the evidence was committed/);
  });

  it('closed-window backfill classifies raw closed gaps and reruns proof pipeline', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const script = readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8');
    const guard = readFileSync(join(root, 'scripts/lib/score-ingestion-guard.mjs'), 'utf8');
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const provenance = readFileSync(join(root, 'src/lib/fixProvenance.ts'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.equal(pkg.scripts['backfill:closed-windows'], 'tsx scripts/backfill-closed-windows.mjs');
    assert.match(script, /reconcileIssueCommentSnapshots/);
    assert.match(script, /classificationConcurrency/);
    assert.match(script, /backfill-closed-windows-classification/);
    assert.match(script, /backfill-closed-windows-closure-evidence/);
    assert.match(script, /backfill-closed-windows-reachability/);
    assert.match(script, /backfill-closed-windows-closure-proof/);
    assert.match(script, /backfill-closed-windows-closure-proof-stabilization/);
    assert.match(script, /analyzeClosureProofsForRelease\(tag, \{ persistScoreAuditPayload: false \}\)/);
    assert.match(script, /const maxStabilizationPasses = 3/);
    assert.match(script, /releaseClosureProofIntegrity\(tag, 1\)/);
    assert.match(script, /refreshCommentPrMentionEvidence: false/);
    assert.match(script, /refreshPrReachability: false/);
    assert.match(script, /Closure proof dependencies did not stabilize/);
    assert.match(script, /release_tag: typeof context\.releaseTag === 'string' \? context\.releaseTag : null/);
    assert.match(script, /insertIngestionEvidenceFailure/);
    assert.match(script, /issueNumbers/);
    assert.match(script, /refreshClosureEvidenceForRelease/);
    assert.match(script, /checkReleasePrReachability/);
    assert.match(script, /analyzeClosureProofsForRelease/);
    assert.match(script, /assertValidIssueCrawlMetadataBeforeMutation\(\)/);
    assert.ok(
      script.indexOf('assertValidIssueCrawlMetadataBeforeMutation()') <
        script.indexOf("acquireRenewableRefreshLease('backfill-closed-windows')"),
      'closed-window backfill must validate crawl schema and baseline before its first write',
    );
    assert.match(script, /assertCleanIngestionMetadataBeforeScore\(monitoredReleases/);
    assert.match(script, /getReleaseScoreAudit/);
    assert.match(script, /release\.scored_at != null/);
    assert.match(script, /monitoredScoreWindowReleases/);
    assert.match(script, /selectedCoversMonitoredWindow/);
    assert.match(script, /status: 'staged-only'/);
    assert.match(script, /exactIngestionFailureMatches/);
    assert.match(script, /supersedeExactIngestionEvidenceFailures/);
    assert.doesNotMatch(script, /supersedeIngestionEvidenceFailures\(/);
    assert.match(guard, /getMeta\('issue_crawl_last_run'\)/);
    assert.match(guard, /assertValidIssueCrawlMetadataBeforeMutation/);
    assert.match(guard, /ingestionEvidenceFailuresAfter/);
    assert.match(guard, /listRecentIngestionEvidenceFailures/);
    assert.match(guard, /recorded before first score/);
    assert.match(script, /persistReleaseScoreRun/);
    assert.match(script, /args\.all === true/);
    assert.match(script, /1_000_000/);
    assert.match(script, /scoreRunCommittedByThisCommand/);
    assert.match(script, /the complete monitored score window was committed before the post-commit failure/);
    assert.doesNotMatch(analysis, /FROM issues i\s+JOIN classifications c ON c\.issue_number=i\.number\s+JOIN target/);
    assert.match(analysis, /missingClassificationClosureProof/);
    assert.match(readme, /stages all classification results before writing them in one transaction/);
    assert.match(readme, /bounded fixed point/);
    assert.match(readme, /skipped proof, reachability, and score stages never clear their failures/);
    assert.match(readme, /failed evidence pass cannot attach fresh proof payloads to stale scores/);
    assert.match(scoringDoc, /writes the staged classification set in one DB transaction/);
    assert.match(scoringDoc, /Stage recovery is exact/);
    assert.match(scoringDoc, /writes the staged classification set in one DB transaction/);
    assert.match(scoringDoc, /leave every score\/audit row untouched/);
  });

  it('prospective score validation uses immutable database ledgers', () => {
    const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const snapshot = readFileSync(join(root, 'scripts/validation/snapshot-forecast.mjs'), 'utf8');
    const opportunities = readFileSync(join(root, 'scripts/validation/forecast-opportunity-status.mjs'), 'utf8');
    const observe = readFileSync(join(root, 'scripts/validation/observe-outcomes.mjs'), 'utf8');
    const evaluate = readFileSync(join(root, 'scripts/validation/evaluate-score-quality.mjs'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.equal(pkg.scripts['validation:snapshot'], 'tsx scripts/validation/snapshot-forecast.mjs');
    assert.equal(pkg.scripts['validation:opportunities'], 'tsx scripts/validation/forecast-opportunity-status.mjs');
    assert.equal(pkg.scripts['validation:observe'], 'tsx scripts/validation/observe-outcomes.mjs');
    assert.equal(pkg.scripts['validation:evaluate'], 'tsx scripts/validation/evaluate-score-quality.mjs');
    assert.match(dbModule, /CREATE TABLE IF NOT EXISTS release_validation_forecasts/);
    assert.match(dbModule, /release_validation_forecasts is append-only/);
    assert.match(dbModule, /CREATE TABLE IF NOT EXISTS release_validation_outcome_observations/);
    assert.match(dbModule, /release_validation_outcome_observations is append-only/);
    assert.match(dbModule, /CREATE TABLE IF NOT EXISTS release_validation_observation_batches/);
    assert.match(dbModule, /release_validation_observation_batches is append-only/);
    assert.match(dbModule, /commitReleaseValidationObservationBatch/);
    assert.match(dbModule, /CREATE TABLE IF NOT EXISTS advisory_snapshot_history/);
    assert.match(scorer, /recorded_at: recordedAt/);
    assert.match(scorer, /RELEASE_VALIDATION_OPPORTUNITIES/);
    assert.match(scorer, /releaseValidationForecastTiming/);
    assert.match(scorer, /schemaVersion: 4/);
    assert.match(scorer, /scoreCommit: args\.scorePersistence\.commitTiming/);
    assert.match(scorer, /catalogAttestation: attestation/);
    assert.match(snapshot, /RADAR_DB_READ_ONLY = '1'/);
    assert.match(snapshot, /listReleaseValidationForecasts/);
    assert.doesNotMatch(snapshot, /appendFileSync|predictedAt/);
    assert.match(opportunities, /RADAR_DB_READ_ONLY = '1'/);
    assert.match(opportunities, /REFRESH_ON_STARTUP = 'false'/);
    assert.match(opportunities, /REFRESH_MINUTES = '0'/);
    assert.match(opportunities, /runInReadTransaction/);
    assert.doesNotMatch(opportunities, /refresh\.ts|index\.ts|persistReleaseScoreRun/);
    assert.match(observe, /stageReleaseValidationOutcomeRows/);
    assert.match(observe, /stageReleaseValidationObservationBatchReceipt/);
    assert.match(observe, /commitReleaseValidationObservationBatch/);
    assert.match(observe, /verifyReleaseValidationObservationBatchLedger/);
    assert.match(observe, /listAuthorizedReleaseValidationAdvisorySnapshots/);
    assert.doesNotMatch(observe, /listAdvisorySnapshotRows|advisory_snapshot_history/);
    assert.match(evaluate, /listReleaseValidationOutcomeObservations/);
    assert.match(evaluate, /listAuthorizedReleaseValidationAdvisorySnapshots/);
    assert.doesNotMatch(evaluate, /listAdvisorySnapshotRows|advisory_snapshot_history/);
    assert.match(dbModule, /compoundAdvisorySnapshotPublicationAuthorizations/);
    assert.match(dbModule, /buildCompoundAdvisorySnapshotValidationEvidence/);
    assert.match(scoringDoc, /Validation is prospective only/);
    assert.match(scoringDoc, /`validated` exits `0`/);
    assert.match(scoringDoc, /`insufficient` exits `2`/);
    assert.match(scoringDoc, /`measurable_but_failed` exits `1`/);
  });

  it('publishes one receipt-authorized advisory-v2 audit contract through API and verifier', () => {
    const advisory = readFileSync(
      join(root, 'src/lib/advisorySnapshot.ts'),
      'utf8',
    );
    const dbModule = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const reader = readFileSync(
      join(root, 'scripts/lib/release-audit-reader.mjs'),
      'utf8',
    );
    const invariants = readFileSync(
      join(root, 'scripts/lib/release-audit-invariants.mjs'),
      'utf8',
    );
    const scoringDoc = readFileSync(
      join(root, 'docs/scoring-model.md'),
      'utf8',
    );
    assert.match(
      advisory,
      /buildCompoundAdvisorySnapshotAuditProjection/,
    );
    assert.match(
      advisory,
      /receipt_authorized_compound_advisory_v2/,
    );
    assert.match(
      dbModule,
      /currentCompoundAdvisorySnapshotAuditProjection/,
    );
    assert.match(
      api,
      /advisorySnapshot: currentCompoundAdvisorySnapshotAuditProjection\(\)/,
    );
    assert.match(
      reader,
      /advisorySnapshotAuditProjection\(\s*v2Summary = null,\s*\{ observedAt = new Date\(\)\.toISOString\(\) \} = \{\}/,
    );
    assert.match(
      invariants,
      /advisorySnapshot must match the independently reconstructed v2 publication audit/,
    );
    assert.match(
      scoringDoc,
      /Legacy snapshot metadata and history are reported separately/,
    );
  });

  it('closure evidence refresh fetches PR mention evidence before replacing links', () => {
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    const rawMentionFetch = analysis.indexOf('const mentionedPrs = await pullRequestsForLookups');
    const rawReplacement = analysis.indexOf('replaceVerifiedIssueStateEventSnapshot(item)');
    const commentMentionFetch = analysis.lastIndexOf('const mentionedPrs = await pullRequestsForLookups');
    const commentDelete = analysis.lastIndexOf('deleteCommentIssuePrLinksForIssues(issueNumbers)');
    assert.ok(rawMentionFetch !== -1 && rawReplacement !== -1 && rawMentionFetch < rawReplacement,
      'raw closure evidence must fetch comment PR details before replacing verified issue reference evidence');
    assert.ok(commentMentionFetch !== -1 && commentDelete !== -1 && commentMentionFetch < commentDelete,
      'comment-derived PR refresh must fetch replacement PR details before deleting old comment links');
    assert.match(github, /missing pull request .* while resolving closure-comment PR evidence/);
    assert.doesNotMatch(github, /chunk\.length === 1 && isMissingPullRequestError\(e\)\) continue/);
    assert.match(analysis, /runInWriteTransaction\(\(\) => \{[\s\S]*replaceVerifiedIssueStateEventSnapshot\(item\)/);
    assert.match(
      analysis,
      /runInWriteTransaction\(\(\) => \{[\s\S]*?closure comment PR mention persistence transaction[\s\S]*?deleteCommentIssuePrLinksForIssues\(issueNumbers\);/,
    );
  });

  it('closure proof analysis checks direct commit closers for release reachability', () => {
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const payload = readFileSync(join(root, 'src/lib/closureProofPayload.ts'), 'utf8');
    const reachability = readFileSync(join(root, 'src/lib/releaseReachability.ts'), 'utf8');
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    assert.ok(
      analysis.indexOf('const proofRows = preparedRows') < analysis.indexOf('deleteIssueClosureProofsForRelease(releaseTag)'),
      'closure proof rows must be staged before deleting persisted proof rows',
    );
    assert.match(analysis, /legacyPersistScoreAuditPayload/);
    assert.match(analysis, /persistScoreAuditPayload=true is disabled/);
    assert.doesNotMatch(analysis, /persistClosureProofInScoreAudit/);
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /checkReleasePrReachabilityForReleases/);
    assert.match(refresh, /preparedDependencies/);
    assert.match(refresh, /refreshPrReachability: false/);
    assert.match(readFileSync(join(root, 'scripts/backfill-closed-windows.mjs'), 'utf8'), /analyzeClosureProofsForRelease\(tag, \{ persistScoreAuditPayload: false \}\)/);
    assert.match(readFileSync(join(root, 'docs/scoring-model.md'), 'utf8'), /refresh does not patch existing `release_score_audits`/);
    assert.match(readFileSync(join(root, 'docs/scoring-model.md'), 'utf8'), /bare not-planned terminal proof remains unresolved closed-canonical risk/);
    assert.match(payload, /Direct closure-proof patching is disabled/);
    assert.doesNotMatch(payload, /updateReleaseScoreAuditClosureProofGateEvidence/);
    assert.doesNotMatch(payload, /updateReleaseScoreAuditGateEvidence/);
    assert.match(db, /function updateReleaseScoreAuditClosureProofGateEvidence/);
    assert.match(db, /validateClosureProofGateEvidence/);
    assert.match(db, /releaseFixCredit counts must match closureProof counts/);
    assert.doesNotMatch(db, /function updateReleaseScoreAuditGateEvidence/);
    assert.match(payload, /emptyClosureProofPayload/);
    assert.doesNotMatch(payload, /if \(!summaryRows\.length\) return null/);
    assert.match(reachability, /refusing to check direct commit reachability/);
    assert.match(reachability, /throw new Error\(gitFailureMessage\('release_commit_fetch_failed'/);
    assert.match(reachability, /throw new Error\(gitFailureMessage\('commit_fetch_failed'/);
    assert.match(reachability, /isCommitUnavailableFetch/);
    assert.match(reachability, /throw new Error\(gitFailureMessage\('merge_base_error'/);
    assert.match(analysis, /direct_closer_commits/);
    assert.match(analysis, /terminalProofCanResolveAsNonActionable/);
    assert.match(analysis, /concreteNonActionableRationale/);
    assert.match(analysis, /p\.evidence_json/);
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
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const script = readFileSync(join(root, 'scripts/check-release-pr-reachability.mjs'), 'utf8');
    const reachabilityCandidateSql = db.match(
      /const reachabilityCandidateSql = `([\s\S]*?)`;/,
    )?.[1] ?? '';
    const reachabilityReplacement = db.slice(
      db.indexOf('export function replaceReleasePrReachabilityForRelease('),
      db.indexOf('type PreparedReleasePrReachability'),
    );
    assert.match(reachability, /readAuthorizedReleaseReachabilityData/);
    assert.match(reachability, /authorized\.pullRequestCandidates/);
    assert.match(reachabilityCandidateSql, /FROM pull_request_fixes p[\s\S]*JOIN issue_pr_links l[\s\S]*WHERE p\.merged=1/);
    assert.doesNotMatch(reachability, /creditedFixLinkSql/);
    assert.doesNotMatch(reachabilityCandidateSql, /creditedFixLinkSql/);
    assert.match(reachability, /replaceReleasePrReachabilityForRelease\(tag, rows\)/);
    assert.doesNotMatch(reachability, /deleteReleasePrReachabilityForRelease/);
    assert.match(db, /replaceReleasePrReachabilityForRelease/);
    assert.match(db, /releasePrReachabilityIntegrity/);
    assert.match(db, /formatReleasePrReachabilityIntegrityFailure/);
    assert.match(reachabilityReplacement, /runInWriteTransaction\(\(\) => \{/);
    assert.match(reachabilityReplacement, /readAuthorizedReleaseReachabilityData/);
    assert.match(reachabilityReplacement, /deleteReleasePrReachabilityForReleaseStmt\.run\(tag\)/);
    assert.ok(
      reachabilityReplacement.indexOf('readAuthorizedReleaseReachabilityData') <
        reachabilityReplacement.indexOf('deleteReleasePrReachabilityForReleaseStmt.run(tag)'),
    );
    assert.match(script, /getRelease/);
    assert.match(script, /insertIngestionEvidenceFailure/);
    assert.match(script, /release_pr_reachability/);
    assert.match(script, /acquireRenewableRefreshLease/);
    assert.match(script, /lease\.assertHeld\('standalone reachability post-commit recovery'\)/);
    assert.match(script, /supersedeExactIngestionEvidenceFailures/);
    assert.match(script, /reachabilityCommitted/);
    assert.match(analysis, /refreshClosureCommentPrMentionEvidence/);
    assert.match(
      analysis,
      /checkReleasePrReachability\(releaseTag, \{[\s\S]*?context: reachabilityContext,[\s\S]*?signal: options\.runContext!\.signal,[\s\S]*?assertCanWrite: options\.runContext!\.assertCanWrite/,
    );
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(refresh, /closure-dependencies/);
    assert.match(refresh, /closure-proof-initial/);
    assert.match(refresh, /refreshCommentPrMentionEvidence: false/);
    assert.ok(
      refresh.indexOf('[closure-proof-initial]') < refresh.indexOf('analyzed after candidate stabilization'),
      'refresh must discover all proof candidates before the final stabilized proof pass',
    );
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
    assert.match(github, /stateEvents: timelineItems[\s\S]*CLOSED_EVENT, REOPENED_EVENT/);
    assert.match(github, /referenceEvents: timelineItems[\s\S]*CROSS_REFERENCED_EVENT, REFERENCED_EVENT/);
    assert.match(github, /function requireGraphqlConnection/);
    assert.match(github, /returned null node at index/);
    assert.match(github, /function nextGraphqlPageCursor/);
    assert.match(github, /pageInfo hasNextPage without endCursor/);
    assert.doesNotMatch(github, /connection\?\.nodes \?\? \[\]/);
  });

  it('refresh fetches label timelines for all monitored-window issues', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.match(refresh, /const initialMonitoredIssueNumbers = page[\s\S]*?issueOverlapsMonitoredWindow\(issue\)[\s\S]*?issue\.number/);
    assert.match(
      refresh,
      /listIssueLabelEvidenceSnapshotsBatch\(\s*initialMonitoredIssueNumbers,/,
    );
    assert.match(refresh, /listIssueFixEvidenceBatch\(initialMonitoredIssueNumbers,/);
    assert.match(refresh, /replaceVerifiedIssueStateEventSnapshot\(evidence\)/);
    assert.match(readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8'), /deleteIssueCommitReferencesForIssues/);
    assert.match(refresh, /issueCommentSnapshot\(snapshot\)/);
    assert.match(refresh, /upsertIssueCommentSnapshot/);
    assert.match(refresh, /runInWriteTransaction\(\(\) => \{[\s\S]*persistIssueStateEvidence\(stateEvidence\)/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('issue-page-write', pageEvidenceScope, error, pageEvidenceContext\)/);
    assert.match(refresh, /const stagedClassifications/);
    assert.match(refresh, /stagedClassifications\.push\(\{/);
    assert.match(refresh, /runInWriteTransaction\(\(\) => \{[\s\S]*upsertClassificationForSnapshot/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('issue-classification-write', pageEvidenceScope, error, pageEvidenceContext\)/);
    assert.match(
      refresh,
      /function runIssuePageEvidenceFetchGroup[\s\S]*?return runCooperativeGroup\(tasks, \{ signal \}\)/,
    );
    const pageEvidenceFetch = refresh.indexOf('] = await runIssuePageEvidenceFetchGroup([');
    const pageEvidenceWrite = refresh.indexOf(
      'assertRefreshWriteAllowed(`issue page ${pagesFetched} evidence persistence`)',
      pageEvidenceFetch,
    );
    assert.ok(
      pageEvidenceFetch >= 0 && pageEvidenceWrite > pageEvidenceFetch,
      'refresh must fetch issue page evidence before transactionally writing page rows',
    );
    const pageEvidenceTransaction = refresh.indexOf(
      'runInWriteTransaction(() => {',
      pageEvidenceWrite,
    );
    const pageClassification = refresh.indexOf(
      'await mapWithConcurrency(',
      pageEvidenceTransaction,
    );
    assert.ok(
      pageEvidenceTransaction >= 0 && pageClassification > pageEvidenceTransaction,
      'refresh must finish page evidence write transaction before classification',
    );
    const stagedClassificationAt = refresh.indexOf('stagedClassifications.push({');
    const stagedClassificationPersistenceAt = refresh.indexOf(
      'for (const row of stagedClassifications)',
      stagedClassificationAt,
    );
    assert.ok(
      stagedClassificationAt >= 0 &&
        stagedClassificationPersistenceAt > stagedClassificationAt,
      'refresh must stage classifications before transactional classification writes',
    );
    assert.doesNotMatch(refresh, /issue\.labels\.length/);
    assert.match(scoringDoc, /issue-page write failures are recorded as `issue-page-write`, rolled back, and score-blocking/);
    assert.match(scoringDoc, /classifications are also staged in memory and written in one transaction/);
    assert.match(
      refresh,
      /function runLeaseFencedWrite[\s\S]*?assertCanWrite\(`\$\{stage\} transaction`\)[\s\S]*?assertCanWrite\(`\$\{stage\} commit`\)/,
    );
    assert.match(
      refresh,
      /runRefreshWrite\(`evidence failure \$\{source\}`[\s\S]*?insertIngestionEvidenceFailure/,
    );
    assert.match(
      refresh,
      /runRefreshWrite\(\s*'stale classification deletion',\s*\(\) => deleteStaleClassifications/,
    );
  });

  it('verified issue state snapshots use a dedicated counted connection and shared atomic writer', () => {
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const backfill = readFileSync(join(root, 'scripts/backfill-issue-state-events.mjs'), 'utf8');
    const frozenCollector = github.match(
      /class FrozenAppendOnlyConnectionCollector[\s\S]*?(?=\nexport async function listIssueCommentSnapshotsBatch)/,
    )?.[0] ?? '';
    assert.match(github, /stateEvents: timelineItems\(first: \$stateFirst\$\{idx\}, itemTypes: \[CLOSED_EVENT, REOPENED_EVENT\]\)/);
    assert.match(github, /stateEvents:[\s\S]*totalCount/);
    assert.match(github, /referenceEvents: timelineItems\(first: \$referenceFirst\$\{idx\}, itemTypes: \[CROSS_REFERENCED_EVENT, REFERENCED_EVENT\]\)/);
    assert.match(github, /class FrozenAppendOnlyConnectionCollector/);
    assert.match(
      frozenCollector,
      /if \(connection\.totalCount > this\.boundaryTotalCount\) \{[\s\S]*?throw new IssueFixEvidenceInstabilityError\([\s\S]*?restart from cursor null/,
    );
    assert.match(frozenCollector, /this\.observedTotalCount = connection\.totalCount/);
    assert.match(
      frozenCollector,
      /if \(this\.observedTotalCount !== this\.boundaryTotalCount\) \{[\s\S]*?cannot publish an incomplete stable observation/,
    );
    assert.match(frozenCollector, /postBoundaryGrowthCount: 0/);
    assert.doesNotMatch(
      frozenCollector,
      /postBoundaryGrowthCount: this\.observedTotalCount - this\.boundaryTotalCount/,
    );
    assert.match(github, /totalCount decreased below frozen boundary/);
    assert.match(github, /terminal first-N identity changed across frozen sweeps/);
    assert.match(github, /finalizeIssueStateSnapshot/);
    assert.match(github, /state event snapshot[\s\S]*metadata drifted during pagination/);
    assert.match(github, /state event count mismatch/);
    assert.match(refresh, /issueStateMetadataMatchesSnapshot/);
    assert.match(analysis, /replaceIssueStateEventSnapshot\(\{/);
    assert.match(analysis, /validateIssueStateEventSnapshot/);
    assert.match(analysis, /replaceVerifiedIssueStateEventSnapshot\(item\)/);
    assert.match(backfill, /replaceVerifiedIssueStateEventSnapshot\(evidence\)/);
  });

  it('refresh activates the exhaustive catalog before production scoring', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    assert.match(
      refresh,
      /const activeCatalogRows =\s*activeCatalogInputs\(releaseSelection\.ordered\)/,
    );
    assert.match(
      refresh,
      /authorizeGithubReleaseCatalogPublication\(\s*releaseCatalog,\s*activeCatalogRows/,
    );
    assert.match(
      refresh,
      /replaceActiveReleaseCatalog\(\s*activeCatalogRows,\s*\{\s*capture: \{\s*source: 'github_graphql'/,
    );
    assert.match(
      refresh,
      /buildReleaseScoreRunForStagedAdvisory\([\s\S]*?releases: allReleases,[\s\S]*?artifactObservationRunId: runId/,
    );
    assert.match(
      refresh,
      /\[finalIssueCatalog, finalReleaseCatalog\] = await runCooperativeGroup\(\[[\s\S]*?'release\.final-attest'/,
    );
    assert.match(
      refresh,
      /verifyIssueCatalogBoundary\(\s*completedCatalog\.snapshotBoundary,/,
    );
    assert.doesNotMatch(refresh, /previousContentDigest/);
    assert.match(refresh, /finalReleaseCatalogAttestation\(\{/);
    assert.match(refresh, /catalogAttestation,/);
    assert.doesNotMatch(refresh, /allFetchedTags: releaseSelection|stableTagsNewestFirst: releaseSelection/);
  });

  it('refresh treats release checks and advisories as score-blocking evidence', () => {
    const refresh = readFileSync(join(root, 'src/lib/refresh.ts'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    assert.match(refresh, /const evidenceRefreshFailures: string\[\] = \[\]/);
    assert.match(refresh, /insertIngestionEvidenceFailure/);
    assert.match(refresh, /persistEarlyEvidenceFailureCrawlMeta/);
    assert.match(
      refresh,
      /releaseCatalog = await timed\(\s*'release\.fetch',\s*\(\) => fetchReleaseCatalog\(\{\s*signal,\s*operationBinding: releaseCatalogOperationBinding,\s*\}\),?\s*\)/,
    );
    assert.match(refresh, /releaseCatalogMetadata = releaseCatalog\.metadata/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('release-metadata', 'fetchReleaseCatalog', e/);
    assert.match(refresh, /releaseWindowCompleteness\(releaseCatalog, monitoredReleaseCount\)/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('release-window', 'fetchReleaseCatalog', error/);
    assert.match(
      refresh,
      /new ReleaseRefreshStageError\(\s*'artifact-verification',\s*r\.tag_name,\s*error/,
    );
    assert.match(
      refresh,
      /const source = stageError\?\.stage \?\? 'release-evidence'[\s\S]*?recordEvidenceRefreshFailure\(\s*source,\s*scope,\s*stageError\?\.stageCause \?\? releaseEvidenceFailure/,
    );
    assert.match(refresh, /issue-comments-missing-alias/);
    assert.match(refresh, /issue-label-events-missing-alias/);
    assert.match(refresh, /issue-fix-evidence-missing-alias/);
    assert.match(refresh, /shouldRefuseScoreAfterTruncatedCommentScans\(commenterScanTruncatedCount\)/);
    assert.match(refresh, /recordEvidenceRefreshFailure\('issue-comments-truncated', null, error/);
    assert.match(refresh, /refusing score persistence until issue comments are fully scanned/);
    assert.match(
      refresh,
      /new ReleaseRefreshStageError\(\s*'release-checks',\s*r\.tag_name,\s*error/,
    );
    assert.match(refresh, /buildCompoundAdvisorySnapshot\(\{/);
    assert.match(refresh, /stageCompoundAdvisorySnapshot\(compoundSnapshot/);
    assert.match(
      refresh,
      /activatePublication: \(\) => \{\s*activateCompoundAdvisorySnapshot\(advisoryProvenance\.snapshotId/,
    );
    assert.match(refresh, /function flattenAdvisoryVulnerabilityRows/);
    assert.match(refresh, /advisoryVulnerabilityKey/);
    assert.match(refresh, /function recordAdvisoryIngestionFailure/);
    assert.match(refresh, /args\.recordFailure\('advisories', args\.scope, args\.error/);
    assert.match(
      refresh,
      /await runCooperativeGroup\(\[[\s\S]*?issue-comments-missing-alias[\s\S]*?issue-label-events-missing-alias[\s\S]*?issue-fix-evidence-missing-alias/,
    );
    assert.doesNotMatch(
      refresh.slice(
        refresh.indexOf('const pageEvidenceScope = `page ${pagesFetched}`'),
        refresh.indexOf('const metadataMismatchNumbers = page'),
      ),
      /Promise\.allSettled/,
    );
    assert.match(refresh, /issuePaginationStopReason = 'evidence_failure'/);
    assert.match(refresh, /persistIssueCrawlMeta\(buildIssueCrawlMeta\(\)\)/);
    assert.match(refresh, /evidenceRefreshFailures\.push\(message\)/);
    assert.match(refresh, /evidenceRefreshFailures: summarizeFailures\(evidenceRefreshFailures\)/);
    assert.match(scoringDoc, /Truncated comment scans are treated as score-blocking incomplete evidence/);
    assert.doesNotMatch(refresh, /release-checks[\s\S]{0,120}continuing/);
    assert.doesNotMatch(refresh, /advisories[\s\S]{0,120}continuing/);
    assert.doesNotMatch(refresh, /artifacts[\s\S]{0,120}continuing/);
  });

  it('docs avoid hardcoded current score snapshots and document explanation details', () => {
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const doctor = readFileSync(join(root, 'scripts/doctor.mjs'), 'utf8');
    const verifier = readFileSync(join(root, 'scripts/verify-new-scoring.mjs'), 'utf8');
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
    assert.match(scoringDoc, /A single GHSA can contain multiple vulnerable package ranges/);
    assert.match(scoringDoc, /each vulnerability range as its own advisory row/);
    assert.match(scoringDoc, /positiveDetails/);
    assert.match(scoringDoc, /limitDetails/);
    assert.match(scoringDoc, /release-metadata\/artifact\/release-check\/advisory\/monitored-release evidence refresh failures/);
    assert.match(scoringDoc, /fetched release window lacks enough stable releases/);
    assert.match(scoringDoc, /If release metadata cannot be fetched/);
    assert.match(scoringDoc, /artifact verification, release commit checks, advisories, closure evidence, PR reachability, or closure-proof refresh fails/);
    assert.match(scoringDoc, /stopReason: "evidence_failure"/);
    assert.match(scoringDoc, /ingestion_evidence_failures` is append-only provenance/);
    assert.match(scoringDoc, /GitHub partial responses for missing issue aliases/);
    assert.match(scoringDoc, /Missing `nodes`, null nodes, missing `pageInfo`/);
    assert.match(scoringDoc, /Other callers fail closed on the GraphQL error/);
    assert.match(scoringDoc, /Manual score writers share the same clean-ingestion guard/);
    assert.match(scoringDoc, /score_persistence_last_run/);
    assert.match(scoringDoc, /exact release-tag set, model version, prompt version, or source identity/);
    assert.match(scoringDoc, /GraphQL nested evidence connections/);
    assert.match(scoringDoc, /interpreted as empty evidence/);
    assert.match(scoringDoc, /PR reachability evidence must cover the current merged linked-PR candidate set/);
    assert.match(scoringDoc, /Closure proof evidence must cover every raw closed issue in the release window/);
    assert.match(doctor, /reachabilityIntegritySummary/);
    assert.match(doctor, /PR reachability evidence is stale or incomplete/);
    assert.match(doctor, /closureProofIntegritySummary/);
    assert.match(doctor, /closure proof evidence is stale or incomplete/);
    assert.match(verifier, /releaseClosureProofIntegrity/);
    assert.match(verifier, /releasePrReachabilityIntegrity/);
    assert.match(readme, /structured `explanation` object/);
    assert.match(readme, /public payload contract version\. Current value: `4`/);
    assert.match(readme, /mandatory canonical `label`/);
    assert.match(scoringDoc, /ledger row keys, labels, order, cap keys, and cap order/);
    assert.match(scoringDoc, /mandatory canonical `label`/);
    assert.match(readme, /score_persistence_last_run/);
    assert.match(readme, /Current value: `1`/);
    assert.match(readme, /`scoreAudit` summaries expose `schemaVersion`\. Current value: `2`/);
    assert.match(readme, /releaseChecks` object exposes `schemaVersion`\. Current value: `2`/);
    assert.match(readme, /\/api\/public` payload and `\/api\/public` release rows expose `schemaVersion`\. Current value: `4`/);
    assert.match(readme, /profileEvidence\.schemaVersion` current value: `2`/);
    assert.match(readme, /`sealed_score_replay`/);
    assert.match(readme, /`current_diagnostic_evidence`/);
    assert.match(readme, /stable reason `code`/);
  });

  it('explanation reason-code exports remain public', () => {
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    assert.match(scorer, /export const SCORE_INPUT_SCHEMA_VERSION = 2/);
    assert.match(scorer, /export function currentScoreCompletenessDiagnostic/);
    assert.match(scorer, /export const SCORE_COMPONENTS_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const SCORE_EXPLANATION_SCHEMA_VERSION = 5/);
    assert.match(scorer, /export const GATE_EVIDENCE_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const ISSUE_EVIDENCE_SCHEMA_VERSION = 2/);
    assert.match(scorer, /export const LABEL_TIMELINE_SCHEMA_VERSION = 1/);
    assert.match(scorer, /export const RELEASE_CHECKS_SCHEMA_VERSION = 2/);
    assert.match(
      scorer,
      /export const ARTIFACT_VERIFICATION_SCHEMA_VERSION =\s+ARTIFACT_EVIDENCE_SCHEMA_VERSION/,
    );
    assert.match(scorer, /export const SCORE_EXPLANATION_LIMIT_CODES/);
    assert.match(scorer, /export const SCORE_EXPLANATION_POSITIVE_CODES/);
    assert.match(scorer, /export const SCORE_EXPLANATION_DETAIL_LABELS/);
  });

  it('public issue summaries use effective scoring classifications', () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const apiTests = readFileSync(join(root, 'src/lib/apiRoutes.test.ts'), 'utf8');
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const readme = readFileSync(join(root, 'README.md'), 'utf8');
    const scoringDoc = readFileSync(join(root, 'docs/scoring-model.md'), 'utf8');
    const scorer = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const verifier = readFileSync(join(root, 'scripts/lib/release-audit-invariants.mjs'), 'utf8');
    const buildPublicPayloadStart = api.indexOf('function buildPublicPayload(');
    const buildPublicPayloadEnd = api.indexOf(
      'function createManagedPublicPayloadBuild(',
      buildPublicPayloadStart,
    );
    assert.ok(buildPublicPayloadStart >= 0);
    assert.ok(buildPublicPayloadEnd > buildPublicPayloadStart);
    const buildPublicPayload = api.slice(
      buildPublicPayloadStart,
      buildPublicPayloadEnd,
    );
    assert.match(api, /PUBLIC_PAYLOAD_SCHEMA_VERSION = 4/);
    assert.match(api, /SCORE_AUDIT_SUMMARY_SCHEMA_VERSION = 2/);
    assert.match(verifier, /scoreAuditSummarySchemaVersion = 2/);
    assert.match(api, /LOCAL_AUDIT_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_UPSTREAM_SCHEMA_VERSION = 1/);
    assert.match(api, /COMPARISON_DELTA_SCHEMA_VERSION = 1/);
    assert.match(api, /config\.comparison\.apiEnabled/);
    assert.match(api, /comparison api disabled/);
    assert.doesNotMatch(api, /includeComparison/);
    assert.doesNotMatch(api, /payload\.upstream/);
    assert.doesNotMatch(api, /payload\.(?:upstream|comparison|delta)/);
    assert.match(api, /snapshot:\s*\{\s*\.\.\.releaseApi\.snapshot/);
    assert.match(api, /res\.set\(RELEASE_SNAPSHOT_HEADER, payload\.snapshot\.id\)/);
    assert.match(db, /function validateComparisonSnapshotInput/);
    assert.match(db, /comparison snapshot releases must be a non-empty array/);
    assert.match(db, /comparison release tag .* appears more than once/);
    assert.match(db, /runInWriteTransaction\(\(\) => \{[\s\S]*insertComparisonSnapshotStmt\.run/);
    assert.match(readme, /stored separately from local model data after validating the rendered release rows/);
    assert.match(readme, /Review endpoints do not expose upstream comparison fields/);
    assert.match(scoringDoc, /Comparison snapshots are internal calibration artifacts/);
    assert.match(api, /function reviewSourceProvenance/);
    assert.match(api, /sourceMode: 'current_db'/);
    assert.match(api, /rawRows/);
    assert.match(api, /STATUS_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /CONFIG_PAYLOAD_SCHEMA_VERSION = 1/);
    assert.match(api, /RELEASE_ROW_SCHEMA_VERSION = 2/);
    assert.match(api, /RELEASE_HISTORY_ROW_SCHEMA_VERSION = 2/);
    assert.match(api, /PUBLIC_RELEASE_SCHEMA_VERSION = 4/);
    assert.match(api, /PROFILE_EVIDENCE_SCHEMA_VERSION = 2/);
    assert.match(api, /PROFILE_EVIDENCE_PUBLICATION_BINDING_SCHEMA_VERSION = 1/);
    assert.match(api, /release-profile-evidence-binding-v1/);
    const profileEvidenceStart = buildPublicPayload.indexOf(
      'profileEvidence: profileEvidenceForRelease(',
    );
    const profileEvidenceEnd = buildPublicPayload.indexOf(
      'issues:',
      profileEvidenceStart,
    );
    assert.ok(profileEvidenceStart >= 0);
    assert.ok(profileEvidenceEnd > profileEvidenceStart);
    const profileEvidenceCall = buildPublicPayload.slice(
      profileEvidenceStart,
      profileEvidenceEnd,
    );
    assert.match(
      buildPublicPayload,
      /const scoreAudit = actionable \? base\.scoreAudit : null/,
    );
    assert.match(profileEvidenceCall, /attributed: all/);
    assert.match(profileEvidenceCall, /opened/);
    assert.match(profileEvidenceCall, /commentEvidenceCache/);
    assert.match(
      profileEvidenceCall,
      /closureAuthority: scoreAudit\?\.authorityRunId/,
    );
    assert.match(
      profileEvidenceCall,
      /createReleaseClosureAuthorityEvaluationForRun/,
    );
    assert.match(profileEvidenceCall, /\}, scoreAudit\),/);
    assert.match(verifier, /verifyPublicProfileEvidence/);
    assert.match(api, /function releaseAuditLinks/);
    assert.match(api, /auditLinks:\s+releaseAuditLinks/);
    assert.match(api, /api\.get\('\/releases\/history'/);
    assert.match(api, /const scoreAudit = scoreAuditSummary\(audit, presentation\.auditUsable\)/);
    assert.match(api, /dataFreshness:\s+freshnessForRelease\(r, audit\)/);
    assert.match(readme, /\/api\/releases\/history.*`scoredAt`, `scoreAudit`, `dataFreshness`, and `auditLinks`/);
    assert.match(scoringDoc, /\/api\/releases\/history` rows expose `schemaVersion`\. Current value: `2`/);
    assert.match(verifier, /'pull_request_fixes'/);
    assert.match(readFileSync(join(root, 'scripts/lib/release-audit-reader.mjs'), 'utf8'), /SELECT 'pull_request_fixes', MAX\(p\.fetched_at\)/);
    assert.match(api, /function publicCacheKey/);
    assert.match(api, /publicCacheKey\(dbEpoch = scoreApiSourceEpoch\(\)\)/);
    assert.equal(api.match(/new Worker\(filename/g)?.length, 3);
    assert.doesNotMatch(api, /RADAR_DB_READ_ONLY/);
    assert.equal(
      api.match(/databaseContext: API_READ_WORKER_DATABASE_CONTEXT/g)?.length,
      3,
    );
    const databaseWorkerContext = readFileSync(
      join(root, 'src/lib/databaseWorkerContext.ts'),
      'utf8',
    );
    assert.match(
      db,
      /const trustedApiReadWorkerDatabaseIdentity =\s+apiReadWorkerExpectedDatabaseIdentity\(\)/,
    );
    assert.match(
      databaseWorkerContext,
      /databaseIdentity\?: \{\s+dev\?: unknown;\s+ino\?: unknown;/,
    );
    assert.match(
      databaseWorkerContext,
      /return \{ dev: Number\(dev\), ino: Number\(ino\) \}/,
    );
    assert.equal(
      api.match(/databaseIdentity: openedDatabaseFileIdentity\(\)/g)?.length,
      3,
    );
    assert.match(
      db,
      /export const dbReadOnly =[\s\S]*trustedApiReadWorker/,
    );
    assert.match(db, /context: 'api-read-worker', mode: 'existing'/);
    assert.match(api, /let activePublicPayloadBuild: ManagedPublicPayloadBuild \| null = null/);
    assert.match(api, /serializePublicPayloadBuildTransition/);
    assert.match(api, /await activePublicPayloadBuild\.cancel\(\)/);
    assert.match(api, /await terminate\(\)/);
    assert.match(api, /publicPayloadWorkerLifecycleSnapshot/);
    assert.doesNotMatch(api, /inflightPublicPayloads|ISSUE_EVIDENCE_CACHE_MAX_BYTES/);
    assert.match(api, /async function publicPayloadForCurrentEpoch/);
    assert.match(api, /const payload = await publicPayloadForCurrentEpoch\(\)/);
    assert.match(api, /res\.json\(payload\)/);
    assert.match(api, /releaseProfileEvidenceRows\(tag, sourceRows\)/);
    assert.match(api, /releaseIssueEvidencePage\(tag/);
    assert.match(api, /function closureProofPage/);
    assert.match(api, /function reachabilityPage/);
    assert.match(api, /LIMIT \? OFFSET \?/);
    assert.match(api, /stableApiRead/);
    assert.doesNotMatch(api, /closureProofAuditRows\(tag\)|releasePrReachabilityRows\(tag\)/);
    const issueEvidence = readFileSync(join(root, 'src/lib/releaseIssueEvidence.ts'), 'utf8');
    assert.match(issueEvidence, /function batchIssueLabelInfo/);
    assert.match(issueEvidence, /FROM json_each\(\?\)/);
    assert.match(issueEvidence, /function\* releaseIssueEvidenceRowIterator/);
    assert.doesNotMatch(issueEvidence, /issueLabelEventCount\(|labelsForIssueAt\(/);
    assert.doesNotMatch(
      api.match(/function profileEvidenceForRelease\([\s\S]*?\n\}/)?.[0] ?? '',
      /cachedReleaseIssueEvidence/,
    );
    assert.match(apiTests, /keeps liveness responsive during a cold bounded public payload build/);
    assert.match(apiTests, /HEAVY_RATIONALE_MARKER/);
    assert.match(apiTests, /payloadBytes < 128 \* 1024/);
    assert.match(apiTests, /publicSettled, false/);
    assert.match(apiTests, /serves only bounded stale non-actionable retained public data while a rebuild runs/);
    assert.match(apiTests, /cancels superseded public workers across refresh-epoch churn without RSS growth/);
    assert.match(apiTests, /keeps bounded pagination equivalent to one-shot issue, closure, and reachability reads/);
    assert.match(apiTests, /lifecycle\.terminated, lifecycle\.spawned/);
    assert.match(apiTests, /memoryAfter\.rss - memoryBefore\.rss < 160 \* 1024 \* 1024/);
    assert.match(api, /currentApiDbEpoch/);
    assert.match(db, /PRAGMA data_version/);
    assert.match(db, /SELECT total_changes\(\) AS changes/);
    assert.match(api, /dataFreshness:\s+freshnessForRelease/);
    assert.match(db, /fetched_at TEXT/);
    assert.match(db, /'issue_fetches'/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS issue_comment_snapshots/);
    assert.match(db, /upsertIssueCommentSnapshot/);
    assert.match(db, /'issue_comments'/);
    assert.match(verifier, /'issue_comments'/);
    assert.match(db, /MAX\(i\.fetched_at\)/);
    assert.match(db, /release_metadata_fetched_at TEXT/);
    assert.match(db, /release_derived_fetched_at TEXT/);
    assert.match(db, /release_artifact_checked_at TEXT/);
    assert.match(db, /CREATE TABLE IF NOT EXISTS ingestion_evidence_failures/);
    assert.match(db, /insertIngestionEvidenceFailure/);
    assert.match(db, /release_metadata_fetched_at AS updated_at/);
    assert.match(db, /'release_rows'/);
    assert.match(
      buildPublicPayload,
      /publicIssueSummariesForRelease\(\{[\s\S]*issues: all,[\s\S]*openedIssues: opened,[\s\S]*labelCutoff,[\s\S]*publicLabelInfo\.get\(issueNumber\)\?\.labels/,
    );
    assert.match(api, /PUBLIC_ISSUES_PER_RELEASE/);
    const closureProofPayload = readFileSync(
      join(root, 'src/lib/closureProofPayload.ts'),
      'utf8',
    );
    const scoringLabelAuthority = readFileSync(
      join(root, 'src/lib/scoringLabelAuthority.ts'),
      'utf8',
    );
    assert.match(scoringLabelAuthority, /export function scoringLabelInfoAtCutoff/);
    assert.match(closureProofPayload, /export function effectiveClosureClassification/);
    assert.match(closureProofPayload, /scoringLabelInfoAtCutoff/);
    assert.match(api, /effectiveClosureClassification/);
    assert.doesNotMatch(api, /function effectiveClosureClassification/);
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
    assert.match(scorer, /contextCount: releaseCheckContextCount/);
    assert.match(scorer, /shownContextCount: releaseCheckContexts\.length/);
    assert.match(scorer, /contextsTruncated: releaseCheckContexts\.length < releaseCheckContextCount/);
    assert.match(verifier, /releaseChecks contextsTruncated must be boolean/);
    assert.match(scoringDoc, /contextsTruncated/);
    const publicIssues = readFileSync(join(root, 'src/lib/publicIssueSummary.ts'), 'utf8');
    const classifyPublicIssueStart = publicIssues.indexOf(
      'function classifyPublicIssue(',
    );
    const classifyPublicIssueEnd = publicIssues.indexOf(
      'function comparePublicIssueSignal(',
      classifyPublicIssueStart,
    );
    assert.ok(classifyPublicIssueStart >= 0);
    assert.ok(classifyPublicIssueEnd > classifyPublicIssueStart);
    const classifyPublicIssue = publicIssues.slice(
      classifyPublicIssueStart,
      classifyPublicIssueEnd,
    );
    assert.match(
      classifyPublicIssue,
      /const labelInfo = scoringLabelInfoAtCutoff\(\s*issue\.number,\s*labelsAtCutoff,\s*labelCutoff,\s*\)/,
    );
    assert.match(
      classifyPublicIssue,
      /classification: classifyIssueRowWithLabels\(issue, labelInfo\.labels, labelInfo\)/,
    );
    assert.match(classifyPublicIssue, /labels: labelInfo\.labels/);
    assert.doesNotMatch(publicIssues, /confidence: classification\.confidence/);
    assert.doesNotMatch(publicIssues, /rationale: classification\.rationale/);
    assert.match(publicIssues, /labelsForIssueAt/);
    assert.match(publicIssues, /useSnapshotWhenNoEvents:\s*labelCutoff != null/);
    assert.match(publicIssues, /comparePublicIssueSignal/);
    assert.match(publicIssues, /sort\(comparePublicIssueSignal\)/);
    assert.match(publicIssues, /classification\.severity/);
    assert.match(publicIssues, /affectedUsers: classification\.affectedUsers/);
    assert.doesNotMatch(api, /SEVERITY_RANK\[a\.severity\]/);
  });

  it('launches TypeScript API workers through a tsx ESM bootstrap without test args', async () => {
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    assert.match(api, /function apiWorkerLaunch/);
    assert.match(api, /if \(!filename\.endsWith\('\.ts'\)\) \{\s*return \{ filename, execArgv: \[\] \};/);
    assert.match(api, /void import\('tsx'\)/);
    assert.match(api, /\.then\(\(\) => require\(/);
    assert.doesNotMatch(api, /tsx\/cjs/);
    assert.equal(api.match(/apiWorkerLaunch\(\)/g)?.length, 3);

    const dir = mkdtempSync(join(tmpdir(), 'radar-api-worker-loader-'));
    try {
      writeFileSync(join(dir, 'config.ts'), 'export const value: number = 42;\n');
      writeFileSync(
        join(dir, 'worker.ts'),
        [
          "import { parentPort } from 'node:worker_threads';",
          "import { value } from './config';",
          'parentPort?.postMessage({',
          '  value,',
          '  execArgv: process.execArgv,',
          '  nodeOptions: process.env.NODE_OPTIONS ?? null,',
          '  marker: process.env.RADAR_WORKER_LOADER_MARKER ?? null,',
          '});',
          'parentPort?.close();',
        ].join('\n'),
      );
      writeFileSync(
        join(dir, 'worker.js'),
        [
          "const { parentPort } = require('node:worker_threads');",
          'parentPort.postMessage({',
          '  value: 7,',
          '  execArgv: process.execArgv,',
          '  marker: process.env.RADAR_WORKER_LOADER_MARKER ?? null,',
          '});',
          'parentPort.close();',
        ].join('\n'),
      );

      const modulePath = join(dir, 'worker.ts');
      const bootstrap = [
        "void import('tsx')",
        `.then(() => require(${JSON.stringify(modulePath)}))`,
        '.catch((error) => { setImmediate(() => { throw error; }); });',
      ].join('');
      const env = {
        ...process.env,
        RADAR_WORKER_LOADER_MARKER: 'preserved',
      };
      const tsResult = await workerMessage(bootstrap, {
        eval: true,
        execArgv: [],
        env,
      }) as {
        value: number;
        execArgv: string[];
        nodeOptions: string | null;
        marker: string | null;
      };
      const jsResult = await workerMessage(join(dir, 'worker.js'), {
        execArgv: [],
        env,
      }) as {
        value: number;
        execArgv: string[];
        marker: string | null;
      };

      assert.equal(tsResult.value, 42);
      assert.equal(jsResult.value, 7);
      assert.equal(tsResult.marker, 'preserved');
      assert.equal(jsResult.marker, 'preserved');
      assert.equal(tsResult.nodeOptions, process.env.NODE_OPTIONS ?? null);
      assert.equal(tsResult.execArgv.includes('--test'), false);
      assert.equal(jsResult.execArgv.includes('--test'), false);
      assert.equal(tsResult.execArgv.some((arg) => arg.includes('tsx/cjs')), false);
      assert.equal(jsResult.execArgv.some((arg) => arg.includes('tsx')), false);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('score source identity excludes comparison and score-output state', () => {
    const identity = readFileSync(join(root, 'src/lib/scoreSourceIdentity.ts'), 'utf8');
    const scoring = readFileSync(join(root, 'src/lib/releaseScoring.ts'), 'utf8');
    const doctor = readFileSync(join(root, 'scripts/doctor.mjs'), 'utf8');
    assert.match(identity, /SCORE_SOURCE_IDENTITY_SCHEMA_VERSION = 17/);
    assert.match(identity, /scoreSourceRuntimeIdentity/);
    assert.match(identity, /effectiveScoringConfigDigest/);
    assert.match(identity, /source: 'advisory_snapshot'/);
    assert.match(identity, /'issue_closure_proofs'/);
    assert.match(identity, /'issue_state_event_snapshots'/);
    assert.match(identity, /'release_pr_reachability'/);
    assert.match(identity, /'release_closure_dependency_snapshots'/);
    assert.doesNotMatch(identity, /comparison_snapshots|comparison_releases/);
    assert.doesNotMatch(identity, /release_score_audits/);
    assert.doesNotMatch(identity, /release_score_audit_history/);
    assert.match(identity, /RELEASE_SCORE_OUTPUT_COLUMNS/);
    assert.match(readFileSync(join(root, 'src/lib/db.ts'), 'utf8'), /export function runInReadTransaction/);
    assert.match(scoring, /return runInReadTransaction\(\(\) => buildReleaseScoreRunSnapshot\(options\)\)/);
    assert.match(scoring, /sourceIdentityBefore = scoreSourceIdentity\(sourceIdentityOptions\)/);
    assert.match(scoring, /source rows changed while scores were being built/);
    assert.match(scoring, /source rows changed after scores were built and before persistence/);
    assert.match(doctor, /score source identity drift/);
  });

  it('closure proof evidence keeps exact GitHub links', () => {
    const github = readFileSync(join(root, 'src/lib/github.ts'), 'utf8');
    const db = readFileSync(join(root, 'src/lib/db.ts'), 'utf8');
    const analysis = readFileSync(join(root, 'src/lib/closureProofAnalysis.ts'), 'utf8');
    const provenance = readFileSync(join(root, 'src/lib/fixProvenance.ts'), 'utf8');
    const api = readFileSync(join(root, 'src/routes/api.ts'), 'utf8');
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(github, /databaseId\s+url\s+author/);
    assert.match(github, /sourceCommentDatabaseId/);
    assert.match(github, /onMissingPullRequest/);
    assert.match(provenance, /source != '\$\{CLOSURE_COMMENT_FIX_PROOF_SOURCE\}'.*\$\{prAlias\}\.pr_number IS NOT NULL/);
    assert.match(db, /source_comment_database_id INTEGER/);
    assert.match(db, /source_comment_url TEXT/);
    assert.match(analysis, /metadataMissing/);
    assert.match(analysis, /creditedFixLinkSql\('l', 'p'\)/);
    assert.match(analysis, /onMissingPullRequest: \(\{ repositoryNameWithOwner, prNumber \}:/);
    assert.match(analysis, /source_comment_database_id: mention\.sourceCommentDatabaseId/);
    assert.match(api, /sourceCommentUrl/);
    assert.match(api, /commitUrl/);
    assert.match(api, /referencedCommitContext: arrayOf/);
    assert.match(html, /function safeEvidenceUrl/);
    assert.match(html, /function closureCommitEvidenceHtml/);
    assert.match(html, /function commentEvidenceHtml/);
    assert.match(html, /function canonicalPathHtml/);
  });
});
