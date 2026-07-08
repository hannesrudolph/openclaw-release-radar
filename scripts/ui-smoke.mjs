import { chromium } from 'playwright';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { extname, resolve } from 'node:path';
import { canonicalJson } from '../src/lib/operationReceipts.ts';
import {
  validateRecommendationDecisionCopies,
  validateRecommendationDecisionRun,
} from '../src/lib/recommendationDecision.ts';
import {
  REC_THRESHOLD,
  RECOMMENDATION_RECENCY_TOLERANCE,
} from '../src/lib/score.ts';

const fixtureOnly = process.env.UI_SMOKE_FIXTURE_ONLY === '1';
const base = (
  fixtureOnly
    ? 'http://ui-smoke.fixture'
    : process.env.API_BASE || process.argv[2] || 'http://127.0.0.1:8787'
).replace(/\/$/, '');
const coverage = createCoverageReport();
const INCIDENT_PHANTOM_TAGS = [
  `v2026.${'7.1'}`,
  `v2026.${'6.30'}`,
];
let fixtureResponses = null;
let fixtureIndexHtmlPromise = null;

function cssAttributeEquals(name, value) {
  if (!/^[A-Za-z_][A-Za-z0-9_-]*$/.test(name)) {
    throw new Error(`Invalid CSS attribute name ${name}`);
  }
  return `[${name}=${JSON.stringify(String(value))}]`;
}

function releaseSelector(tag) {
  return `.release${cssAttributeEquals('data-tag', tag)}`;
}

if (fixtureOnly) {
  await runFixtureOnlySmoke();
  process.exit(0);
}
await assertStaticAssetsRemainCacheable();
const releases = await json('/api/releases');
const historyPayload = await json('/api/releases/history');
const publicPayload = await json('/api/public');
assertSharedSnapshotIdentity(releases, historyPayload, publicPayload);
if (process.env.UI_SMOKE_HARD_REFRESH_ONLY === '1') {
  const hardRefreshBrowser = await chromium.launch({ headless: true });
  try {
    await assertHardRefreshUx(hardRefreshBrowser, {
      releases,
      historyPayload,
      publicPayload,
    });
    console.log('Hard-refresh UI smoke passed');
  } finally {
    await hardRefreshBrowser.close();
  }
  process.exit(0);
}
const releasesByTag = new Map(releases.map((release) => [release.tag, release]));
const publicByTag = new Map((publicPayload.releases ?? []).map((release) => [release.tag, release]));
const recommendedReleases = releases.filter((release) => release.recommended);
if (recommendedReleases.length > 1) {
  throw new Error(`Expected zero or one recommended release, got ${recommendedReleases.length}`);
}
const eligibleNonRecommended = releases.find((r) => r.status === 'eligible' && !r.recommended);
if (!eligibleNonRecommended) {
  skipCoverage(
    coverage.optional,
    'eligible nonrecommended',
    'no eligible non-recommended release is present in the deployed dataset',
  );
}
const securityGatedRelease = releases.find((r) => r.status === 'skip-cve');
if (!securityGatedRelease) {
  skipCoverage(
    coverage.optional,
    'advisory-gated',
    'no security-advisory-gated release is present in the deployed dataset',
  );
}

let fixCreditTag = null;
let fixCreditText = null;
let closureRiskText = null;
let explanationText = null;
let explanationIssueRef = null;
let explanationMetricText = null;
let explanationProofText = null;
let expectedCheckLinkText = null;
let expectedArtifactLinkText = null;
let expectedReleaseCheckText = null;
let expectedProofPrUrl = null;
let expectedSourceCommentUrl = null;
let expectedCommitUrl = null;
const reviewByTag = new Map();
for (const release of releases) {
  const review = await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
  assertNoComparisonPayload(review, `/api/releases/${release.tag}/review`);
  assertReviewAuditIdentity(release, review);
  const decisionFailures = validateRecommendationDecisionCopies({
    tag: release.tag,
    componentsDecision: review.local?.components?.recommendationDecision,
    explanationDecision: review.local?.components?.explanation?.recommendationDecision,
    expectedStatus: review.local?.status ?? null,
    expectedScore: review.local?.score ?? null,
    expectedSelected: review.local?.recommended === true,
    expectedThreshold: REC_THRESHOLD,
    expectedRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
  });
  if (decisionFailures.length) {
    throw new Error(`Invalid recommendation decision for ${release.tag}: ${decisionFailures.join('; ')}`);
  }
  reviewByTag.set(release.tag, review);
  const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
  const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
  if (credit) {
    fixCreditTag = release.tag;
    fixCreditText = `${credit.countedClosedCount} direct fixes credited · ${credit.notCountedClosedCount} raw proof issues without direct credit · ${credit.analyzedClosedCount} raw closed issues analyzed`;
    const scoredGroups = Number(review.local?.input?.unresolvedClosureIssueCount ?? 0);
    const scoredWeight = Number(review.local?.input?.unresolvedClosureRiskWeight ?? 0);
    closureRiskText = risk
      ? `Scored: ${scoredGroups} deduplicated groups · weight ${humanWeightValue(scoredWeight)} · Raw proof audit: ${risk.unresolvedForReleaseCount ?? 0} unresolved groups`
      : null;
    explanationText = (review.local?.components?.explanation?.limits ?? [])
      .find((line) => /deduplicated closed-issue risk groups contribute to this score/i.test(line))
      ?? review.local?.components?.explanation?.limits?.[0]
      ?? null;
    const closureDetail = (review.local?.components?.explanation?.limitDetails ?? [])
      .find((detail) => detail.code === 'closed_issues_not_counted_as_release_fixes');
    explanationIssueRef = closureDetail?.issueRefs?.[0] ?? null;
    const metric = closureDetail?.metrics?.scoredUnresolvedRiskGroupCount;
    explanationMetricText = Number.isFinite(metric) ? `scored risk groups: ${metric}` : null;
    explanationProofText = explanationIssueRef?.proof?.riskDispositionLabel ?? explanationIssueRef?.proof?.statusLabel ?? null;
    const checkContext = (review.local?.gateEvidence?.releaseChecks?.contexts ?? [])
      .find((context) => context?.url && context?.name);
    expectedCheckLinkText = checkContext?.name ?? null;
    expectedReleaseCheckText = releaseCheckSummaryText(review.local?.gateEvidence?.releaseChecks);
    const artifact = review.local?.gateEvidence?.artifactVerification;
    expectedArtifactLinkText = artifact?.npmPackageUrl ? 'npm package' : artifact?.ciReportUrl ? 'evidence report' : null;
    const proofRefs = [
      ...(explanationIssueRef?.proof?.openPrs ?? []),
      ...(explanationIssueRef?.proof?.reachablePrs ?? []),
      ...(explanationIssueRef?.proof?.notReachablePrs ?? []),
      ...(explanationIssueRef?.proof?.unknownReachabilityPrs ?? []),
      ...(explanationIssueRef?.proof?.closedUnmergedPrs ?? []),
      ...(explanationIssueRef?.proof?.externalClosingPrs ?? []),
    ];
    expectedProofPrUrl = proofRefs.find((ref) => ref?.url)?.url ?? null;
    expectedSourceCommentUrl = proofRefs.find((ref) => ref?.sourceCommentUrl)?.sourceCommentUrl ?? null;
    const closureExamples = review.local?.gateEvidence?.fixProvenance?.closureProof?.examples ?? [];
    expectedCommitUrl = closureExamples
      .flatMap((example) => [
        ...(example?.evidence?.fixCommitProof ?? []),
        ...(example?.evidence?.canonicalFixCommitProof ?? []),
      ])
      .find((commit) => commit?.commitOid)?.commitOid;
    if (expectedCommitUrl) expectedCommitUrl = `https://github.com/openclaw/openclaw/commit/${expectedCommitUrl}`;
  }
}
const recommendationRunFailures = validateRecommendationDecisionRun({
  rows: releases.map((release) => {
    const review = reviewByTag.get(release.tag);
    return {
      tag: release.tag,
      status: review?.local?.status ?? null,
      score: review?.local?.score ?? null,
      recommended: review?.local?.recommended === true,
      componentsDecision: review?.local?.components?.recommendationDecision,
      explanationDecision: review?.local?.components?.explanation?.recommendationDecision,
    };
  }),
  expectedSelectedTag: recommendedReleases[0]?.tag ?? null,
  expectedThreshold: REC_THRESHOLD,
  expectedRecencyTolerance: RECOMMENDATION_RECENCY_TOLERANCE,
});
if (recommendationRunFailures.length > 0) {
  throw new Error(`Invalid recommendation run: ${recommendationRunFailures.join('; ')}`);
}
const publicDetail = fixCreditTag ? publicByTag.get(fixCreditTag) : null;
const watchIssues = Array.isArray(publicDetail?.watchIssues) ? publicDetail.watchIssues : [];
const topIssues = Array.isArray(publicDetail?.issues) ? publicDetail.issues : [];
const combinedRelatedIssues = [...watchIssues, ...topIssues].filter((issue, index, rows) =>
  issue?.number && rows.findIndex((candidate) => candidate?.number === issue.number) === index);
const relatedIssue = combinedRelatedIssues[0];
const topRelatedIssue = combinedRelatedIssues[1];
const combinedRelatedIssueCount = combinedRelatedIssues.length;
const fixCreditMissing = [
  [fixCreditTag, 'releaseFixCredit'],
  [explanationText, 'score explanation'],
  [closureRiskText, 'closure risk summary'],
  [explanationIssueRef?.number && explanationIssueRef?.url, 'explanation issue reference'],
  [explanationMetricText, 'explanation metric'],
  [explanationProofText, 'explanation proof context'],
  [expectedCheckLinkText, 'release check link'],
  [expectedReleaseCheckText, 'release check summary'],
  [expectedArtifactLinkText, 'artifact link'],
  [expectedProofPrUrl, 'linked proof PR'],
  [expectedSourceCommentUrl, 'linked source comment'],
  [expectedCommitUrl, 'linked commit proof'],
  [relatedIssue?.number && relatedIssue?.url, 'first related issue'],
  [topRelatedIssue?.number && topRelatedIssue?.url, 'second related issue'],
].filter(([value]) => !value).map(([, label]) => label);
const hasFixCreditLinkScenario = fixCreditMissing.length === 0;
if (!hasFixCreditLinkScenario) {
  skipCoverage(
    coverage.optional,
    'fix-credit link examples',
    `dataset is missing ${fixCreditMissing.join(', ')}`,
  );
}

const browser = await chromium.launch({ headless: true });
await assertHardRefreshUx(browser, {
  releases,
  historyPayload,
  publicPayload,
});
passCoverage(coverage.core, 'stale');
await assertProgressiveFirstRender(browser, {
  releases,
  historyPayload,
  publicPayload,
  releasesByTag,
});
const page = await newSmokePage(browser, { viewport: { width: 1440, height: 1000 } });
const badRequests = [];
page.on('request', (req) => {
  if (new URL(req.url()).pathname === '/api/comparison') badRequests.push(req.url());
});

try {
  await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
  await page.waitForSelector('#releases .release');
  const prEvidenceLabels = await page.evaluate(() => ({
    ambient: closurePrEvidenceHtml([{
      number: 98507,
      repositoryNameWithOwner: 'openclaw/openclaw',
      source: 'CrossReferencedEvent',
      willCloseTarget: false,
      state: 'OPEN',
      merged: false,
      url: 'https://github.com/openclaw/openclaw/pull/98507',
    }]),
    trusted: closurePrEvidenceHtml([{
      number: 98507,
      repositoryNameWithOwner: 'openclaw/openclaw',
      source: 'ClosureComment.prMention',
      willCloseTarget: null,
      state: 'OPEN',
      merged: false,
      url: 'https://github.com/openclaw/openclaw/pull/98507',
    }]),
  }));
  if (!prEvidenceLabels.ambient.startsWith('Ambient cross-reference:') || prEvidenceLabels.ambient.includes('PR evidence:')) {
    throw new Error(`Non-closing CrossReferencedEvent was not labeled as ambient provenance: ${prEvidenceLabels.ambient}`);
  }
  if (!prEvidenceLabels.trusted.startsWith('PR evidence:') || prEvidenceLabels.trusted.includes('Ambient cross-reference:')) {
    throw new Error(`Trusted PR context lost its proof label: ${prEvidenceLabels.trusted}`);
  }

  if (badRequests.length) throw new Error(`UI requested /api/comparison: ${badRequests.join(', ')}`);
  const bodyText = await page.locator('body').innerText();
  const assessmentHelpText = await page.locator('#scoreHelp .score-explain').textContent();
  if (!/ordinal 0[–-]10 policy\/stability ranking, not a probability or percentage/i.test(assessmentHelpText ?? '')) {
    throw new Error(`Score help did not define the ordinal non-probability semantics: ${assessmentHelpText}`);
  }
  if (/\bperfect\b|model ceiling/i.test(await page.locator('body').textContent())) {
    throw new Error('Public UI described 10 as perfect or claimed a generic model ceiling');
  }
  if (/\b(upstream|comparison)\b/i.test(bodyText)) {
    throw new Error('Visible UI leaked upstream/comparison wording');
  }
  const renderedRows = page.locator('#releases .release');
  const renderedCount = await renderedRows.count();
  if (renderedCount !== releases.length) {
    throw new Error(`Rendered release row count ${renderedCount} did not match /api/releases ${releases.length}`);
  }
  for (const release of releases) {
    const row = page.locator(releaseSelector(release.tag));
    if (await row.count() !== 1) throw new Error(`Expected one DOM row for ${release.tag}`);
  }
  const recommendedRows = page.locator('#releases .release--recommended');
  const recommendedRowCount = await recommendedRows.count();
  if (recommendedRowCount !== recommendedReleases.length) {
    throw new Error(
      `Recommended DOM row count ${recommendedRowCount} did not match /api/releases ${recommendedReleases.length}`,
    );
  }
  const recommendedTag = recommendedReleases[0]?.tag ?? null;
  const expectedRecommendedCmd = recommendedTag
    ? installCommand(recommendedTag)
    : null;
  const recommendedDecisionCopy = recommendedReleases[0]
    ? expectedRecommendationDecisionCopy(recommendedReleases[0])
    : null;
  if (recommendedTag) {
    const renderedRecommendedTag = await recommendedRows.first().getAttribute('data-tag');
    if (renderedRecommendedTag !== recommendedTag) {
      throw new Error(`Recommended DOM row ${renderedRecommendedTag} did not match /api/releases ${recommendedTag}`);
    }
    const recommendedDriverText = await recommendedRows.first().locator('.release__drivers').innerText();
    if (!/^Assessment drivers:/i.test(recommendedDriverText)) {
      throw new Error(`recommended row missing assessment drivers: ${recommendedDriverText}`);
    }
    if (!/\brisk\b/i.test(recommendedDriverText)) {
      throw new Error(`recommended row score drivers did not include a risk label: ${recommendedDriverText}`);
    }
    if (/raw\/classified|attributed issues/i.test(recommendedDriverText)) {
      throw new Error(`recommended row score drivers looked issue-volume based: ${recommendedDriverText}`);
    }
  }
  await assertReleaseRowInteractionSemantics(page, releases[0].tag);
  const recommendationPanel = await openScoreBreakdown(page, recommendedTag ?? releases[0].tag);
  const recommendationPanelText = await recommendationPanel.innerText();
  if (recommendedTag && expectedRecommendedCmd && recommendedDecisionCopy) {
    await recommendationPanel.locator('.update-cmd__code').filter({ hasText: expectedRecommendedCmd }).waitFor();
    await recommendationPanel
      .locator(`.update-cmd__copy${cssAttributeEquals('data-cmd', expectedRecommendedCmd)}`)
      .waitFor();
    if (!recommendationPanelText.includes(recommendedDecisionCopy)) {
      throw new Error(`Recommended panel missing human decision copy: ${recommendedDecisionCopy}`);
    }
  } else {
    if (await recommendationPanel.locator('.update-cmd__code, .update-cmd__copy').count()) {
      throw new Error('Zero-recommendation run rendered an update command');
    }
    const fallbackDecisionCopy = expectedRecommendationDecisionCopy(releases[0]);
    if (!recommendationPanelText.includes(fallbackDecisionCopy)) {
      throw new Error(`Zero-recommendation panel missing human decision copy: ${fallbackDecisionCopy}`);
    }
  }
  assertNoMachineDecisionCopy(recommendationPanelText, 'recommendation panel');
  passCoverage(
    coverage.core,
    'recommendation',
    recommendedTag ?? 'no qualifying release',
  );

  if (hasFixCreditLinkScenario) {
  const fixPanel = await openScoreBreakdown(page, fixCreditTag);
  await fixPanel.getByText('Model', { exact: true }).waitFor();
  await fixPanel.getByText('Evidence coverage', { exact: true }).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Release fix credit' }).first().waitFor();
  await fixPanel.getByText(fixCreditText).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Closed-issue risk' }).first().waitFor();
  await fixPanel.getByText(closureRiskText).waitFor();
  await fixPanel.locator('.score-review__item').filter({ hasText: 'Release checks' }).getByText(expectedReleaseCheckText).waitFor();
  await fixPanel.locator('a.score-explain__ref').filter({ hasText: expectedCheckLinkText }).first().waitFor();
  await fixPanel.locator('a.score-explain__ref').filter({ hasText: expectedArtifactLinkText }).first().waitFor();
  await fixPanel.locator(`a[href="${expectedProofPrUrl}"]`).first().waitFor();
  await fixPanel.locator(`a[href="${expectedSourceCommentUrl}"]`).first().waitFor();
  await fixPanel.locator(`a[href="${expectedCommitUrl}"]`).first().waitFor();
  const fixPanelText = await fixPanel.innerText();
  if (!fixPanelText.includes(explanationText)) {
    throw new Error(`Score explanation text not rendered for ${fixCreditTag}: ${explanationText}`);
  }
  await fixPanel.locator('.score-ledger').filter({ hasText: 'Assessment calculation' }).first().waitFor();
  await fixPanel.locator('.score-ledger__row').filter({ hasText: 'Unresolved closed-issue evidence' }).first().waitFor();
  await fixPanel.locator('.score-explain__metric').filter({ hasText: explanationMetricText }).first().waitFor();
  await fixPanel.locator('.score-explain__ref').filter({ hasText: `#${explanationIssueRef.number}` }).first().waitFor();
  await fixPanel.locator('.score-explain__ref').filter({ hasText: /\sx[0-9.]+/ }).first().waitFor();
  await fixPanel.locator('.score-explain__proof').filter({ hasText: `#${explanationIssueRef.number}` }).first().waitFor();
  await fixPanel.locator('.score-explain__proof').filter({ hasText: explanationProofText }).first().waitFor();
  await assertAuditLinkJson(
    fixPanel.locator(`a.score-explain__ref[href*="issue=${explanationIssueRef.number}"]`, { hasText: 'issue evidence row' }).first(),
    explanationIssueRef.number,
    'issue evidence row',
  );
  await assertAuditLinkJson(
    fixPanel.locator(`a.score-explain__ref[href*="issue=${explanationIssueRef.number}"]`, { hasText: 'closure proof row' }).first(),
    explanationIssueRef.number,
    'closure proof row',
  );
  await fixPanel
    .getByText('A closed issue only reduces release risk when its merged linked PR or named fix/source commit is reachable from this release tag.')
    .waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open review JSON' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open issue evidence rows' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'inherited issue context (zero assessment impact)' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'field-discussed inherited context' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'critical core inherited context' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'weak or stale issue evidence' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'high-weight weak/stale evidence' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'opened reports' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open closure proof rows' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open PR reachability rows' }).first().waitFor();
  if (fixPanelText.includes('Audit-only closed issue flags')) {
    throw new Error('Zero-penalty audit-only flags were shown as score limits');
  }
  if (/open unconfirmed issue risk/i.test(fixPanelText)) {
    throw new Error('Legacy open-unconfirmed wording reached the public score review');
  }
  const fixInput = reviewByTag.get(fixCreditTag)?.local?.input ?? {};
  if (Number(fixInput.carryoverDebtWeight ?? 0) > 0) {
    await fixPanel.getByText('Context that does not lower the assessment:', { exact: true }).waitFor();
    const limitingListText = await scoreExplanationSectionListText(
      fixPanel,
      'What lowers or limits this assessment:',
    );
    if (/inherited issue|0 score points|cannot apply a score ceiling/i.test(limitingListText)) {
      throw new Error(`Zero-impact carryover appeared under score limits: ${limitingListText}`);
    }
  }
  if (/\[Bug\]:?(?:\s*;|\s*$)/m.test(fixPanelText)) {
    throw new Error(`Placeholder issue title leaked into score explanation: ${fixPanelText}`);
  }
  const artifact = reviewByTag.get(fixCreditTag)?.local?.gateEvidence?.artifactVerification;
  const duplicateArtifactFailure = artifact?.ciReportMismatch &&
    artifact.ciReportMismatch === artifact.releaseValidationMismatch
    ? artifact.ciReportMismatch
    : null;
  if (duplicateArtifactFailure) {
    const artifactText = await fixPanel
      .locator('.score-review__item')
      .filter({ hasText: 'Artifact evidence' })
      .innerText();
    if (artifactText.split(duplicateArtifactFailure).length - 1 !== 1) {
      throw new Error(`Artifact failure text was not deduplicated: ${artifactText}`);
    }
  }
  const precisionRow = reviewByTag.get(fixCreditTag)?.local?.components?.explanation?.scoreLedger?.rows
    ?.find((row) => row.key === 'precisionAdjustment' && Math.abs(Number(row.points)) < 0.01 && Number(row.points) !== 0);
  if (precisionRow) {
    await fixPanel.locator('.score-ledger__row')
      .filter({ hasText: 'Final score rounding' })
      .filter({ hasText: '<0.01' })
      .waitFor();
  }
  await fixPanel.locator('summary.evidence-toggle__summary', { hasText: 'Show related issues' }).click();
  if (combinedRelatedIssueCount > 8) {
    await fixPanel.locator('.evidence__more')
      .filter({ hasText: `Show all ${combinedRelatedIssueCount} related issues` })
      .waitFor();
  }
  const relatedIssueRow = fixPanel.locator('li.evidence__item').filter({ hasText: `#${relatedIssue.number}` }).first();
  await relatedIssueRow.waitFor();
  await relatedIssueRow.getByText(/Evidence bucket: /).waitFor();
  await relatedIssueRow.getByText(new RegExp(`${relatedIssue.severity}.*${relatedIssue.affectedUsers} users`, 'i')).waitFor();
  await assertAuditLinkJson(
    relatedIssueRow.locator('a.score-explain__ref', { hasText: 'issue evidence row' }).first(),
    relatedIssue.number,
    'related issue evidence row',
  );
  const topRelatedIssueRow = fixPanel.locator('li.evidence__item').filter({ hasText: `#${topRelatedIssue.number}` }).first();
  await topRelatedIssueRow.waitFor();
  if (await topRelatedIssueRow.isHidden()) {
    await fixPanel.locator('.evidence__more')
      .filter({ hasText: `Show all ${combinedRelatedIssueCount} related issues` })
      .click();
    await topRelatedIssueRow.waitFor({ state: 'visible' });
  }
  passCoverage(coverage.optional, 'fix-credit link examples', fixCreditTag);
  }

  if (eligibleNonRecommended) {
  const normalRow = page.locator(releaseSelector(eligibleNonRecommended.tag));
  await normalRow.evaluate((el) => {
    if (!el.classList.contains('release--normal')) throw new Error('eligible non-recommended row is not normal category');
    if (el.querySelector('.rec-pill')) throw new Error('eligible non-recommended row shows Recommended pill');
    if (el.querySelector('.release__reason')?.textContent?.trim()) throw new Error('eligible non-recommended row has verbose reason text');
    const drivers = el.querySelector('.release__drivers')?.textContent?.trim() ?? '';
    if (!drivers.startsWith('Assessment drivers:')) throw new Error('eligible non-recommended row is missing assessment drivers');
  });
  const normalPanel = await openScoreBreakdown(page, eligibleNonRecommended.tag);
  await normalPanel.locator('.install-state--not-recommended').waitFor();
  await normalPanel.locator('.install-state__meta').filter({ hasText: 'Passed install eligibility checks' }).waitFor();
  const normalText = await normalPanel.innerText();
  if (await normalPanel.locator('.update-cmd__copy').count()) {
    throw new Error('eligible non-recommended panel showed a copy button');
  }
  if (await normalPanel.locator('.update-cmd__code').count()) {
    throw new Error('eligible non-recommended panel showed command code');
  }
  if (normalText.includes(installCommand(eligibleNonRecommended.tag))) {
    throw new Error('eligible non-recommended panel showed install command text');
  }
  if (normalText.includes('The release is eligible and recommended.')) {
    throw new Error('eligible non-recommended breakdown used recommended wording');
  }
  if (normalText.includes('release looks safe to install')) {
    throw new Error('eligible non-recommended breakdown used safe-to-install wording');
  }
  if (/hard (install|safety) gate/i.test(normalText)) {
    throw new Error('eligible non-recommended breakdown used hard gate wording');
  }
  const expectedNormalDecisionCopy = expectedRecommendationDecisionCopy(releasesByTag.get(eligibleNonRecommended.tag));
  if (!normalText.includes(expectedNormalDecisionCopy)) {
    throw new Error(`eligible non-recommended panel missing human decision copy: ${expectedNormalDecisionCopy}`);
  }
  assertNoMachineDecisionCopy(normalText, 'eligible non-recommended panel');
  passCoverage(coverage.optional, 'eligible nonrecommended', eligibleNonRecommended.tag);
  }

  if (securityGatedRelease) {
  const securityRow = page.locator(releaseSelector(securityGatedRelease.tag));
  const securityRowText = await securityRow.innerText();
  if (!/medium-or-higher security advisor(y|ies)/i.test(securityRowText)) {
    throw new Error(`security-gated row did not use advisory wording: ${securityRowText}`);
  }
  assertNoUnsupportedCveCopy(securityRowText, 'security-gated row');
  const securityPanel = await openScoreBreakdown(page, securityGatedRelease.tag);
  const securityPanelText = await securityPanel.innerText();
  if (!/security advisory install gate/i.test(securityPanelText)) {
    throw new Error(`security-gated panel did not translate the advisory gate: ${securityPanelText}`);
  }
  assertNoUnsupportedCveCopy(securityPanelText, 'security-gated panel');
  assertNoMachineDecisionCopy(securityPanelText, 'security-gated panel');
  passCoverage(coverage.optional, 'advisory-gated', securityGatedRelease.tag);
  }

  for (const release of releases) {
    const review = reviewByTag.get(release.tag) ?? await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
    const panel = await openScoreBreakdown(page, release.tag);
    const input = review.local?.input ?? {};
    const expectedRawClassified = `${input.classifiedIssueCount ?? '—'} / ${input.rawIssueCount ?? '—'}`;
    await panel.locator('.score-review__item').filter({ hasText: 'Raw/classified' }).getByText(expectedRawClassified).waitFor();
    const expectedCoverage = `${Math.round((review.local?.components?.evidenceCoverage ?? 0) * 100)}%`;
    await panel.locator('.score-review__item').filter({ hasText: 'Evidence coverage' }).getByText(expectedCoverage).waitFor();
    const freshness = review.local?.dataFreshness;
    if (!freshness?.issueUpdatedAtMax || !freshness?.scoredAt) throw new Error(`Missing data freshness for ${release.tag}`);
    await panel.locator('.score-review__item').filter({ hasText: 'Source freshness' }).getByText('issue lag').waitFor();
    const expectedRiskWeights = `Policy-qualified blocker ${humanWeightValue(input.verifiedDebtWeight ?? 0)} · Weak/stale ${humanWeightValue(input.staleDebtWeight ?? 0)} · Closed-issue risk ${humanWeightValue(input.unresolvedClosureRiskWeight ?? 0)}`;
    await panel.locator('.score-review__item').filter({ hasText: 'Assessment-affecting evidence weights' }).getByText(expectedRiskWeights).waitFor();
    const expectedContextWeight = `${humanWeightValue(input.carryoverDebtWeight ?? 0)} audit weight · does not lower or limit the assessment`;
    await panel.locator('.score-review__item').filter({ hasText: 'Inherited context (zero assessment impact)' }).getByText(expectedContextWeight).waitFor();
    const panelText = await panel.innerText();
    if (/\bperfect\b|model ceiling|open unconfirmed issue risk/i.test(panelText)) {
      throw new Error(`${release.tag} exposed obsolete public scoring semantics: ${panelText}`);
    }
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (credit) {
      const expectedCredit = `${credit.countedClosedCount} direct fixes credited · ${credit.notCountedClosedCount} raw proof issues without direct credit · ${credit.analyzedClosedCount} raw closed issues analyzed`;
      await panel.locator('.score-review__item').filter({ hasText: 'Release fix credit' }).getByText(expectedCredit).waitFor();
      const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
      if (!risk) throw new Error(`Missing closure risk summary for ${release.tag}`);
      const expectedRisk = `Scored: ${Number(input.unresolvedClosureIssueCount ?? 0)} deduplicated groups · weight ${humanWeightValue(input.unresolvedClosureRiskWeight ?? 0)} · Raw proof audit: ${risk.unresolvedForReleaseCount ?? 0} unresolved groups`;
      await panel.locator('.score-review__item').filter({ hasText: 'Closed-issue risk' }).getByText(expectedRisk).waitFor();
    }
    const displayedPointValues = await panel
      .locator('.score-ledger__points, .score-review__components .score-review__value')
      .allInnerTexts();
    const rawPointValue = displayedPointValues.find((value) => /[+-]?\d+\.\d{3,}/.test(value.trim()));
    if (rawPointValue) throw new Error(`${release.tag} displayed an unrounded point value: ${rawPointValue}`);
  }
  await assertVisualSmoke(page, 'desktop');
  await assertHelpAndDisclosureTargetSizes(page, 'desktop');
  passCoverage(coverage.core, 'desktop');

  const profilePage = await newSmokePage(browser, { viewport: { width: 1024, height: 900 } });
  await profilePage.addInitScript(() => {
    localStorage.setItem(
      'openclaw-release-radar.installProfile.v1',
      JSON.stringify(['macOS', 'Discord', 'OpenAI']),
    );
  });
  try {
    await profilePage.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await profilePage.waitForSelector('#releases .release');
    for (const release of releases) {
      const scoreText = await profilePage
        .locator(`${releaseSelector(release.tag)} .score-num`)
        .innerText();
      const expectedScore = release.finalScore == null ? '—' : Number(release.finalScore).toFixed(1);
      if (scoreText !== expectedScore) {
        throw new Error(`Profile changed ${release.tag} score from audited ${expectedScore} to ${scoreText}`);
      }
      if (await profilePage.locator(`${releaseSelector(release.tag)} .score-sub`).count()) {
        throw new Error(`Profile rendered a secondary mutated score for ${release.tag}`);
      }
    }
    const profileText = await profilePage.locator('body').innerText();
    if (/My install score|profile-adjusted estimate/i.test(profileText)) {
      throw new Error('Profile UI still claims to mutate the audited score');
    }
    await profilePage.getByText('Global assessment history', { exact: true }).waitFor();
    await profilePage
      .getByText('Related evidence is filtered for your setup; the audited assessment and recommendation stay global.', { exact: true })
      .waitFor();
    const profileRecommendationPanel = await openScoreBreakdown(
      profilePage,
      recommendedTag ?? releases[0].tag,
    );
    const profileDecisionText = await profileRecommendationPanel.innerText();
    if (recommendedTag && expectedRecommendedCmd && recommendedDecisionCopy) {
      await profileRecommendationPanel.locator('.update-cmd__code')
        .filter({ hasText: expectedRecommendedCmd })
        .waitFor();
      if (!profileDecisionText.includes(recommendedDecisionCopy)) {
        throw new Error('Profile changed or obscured the global recommendation explanation');
      }
    } else if (await profileRecommendationPanel.locator('.update-cmd__code, .update-cmd__copy').count()) {
      throw new Error('Profile rendered an update command for a zero-recommendation run');
    }
    await assertVisualSmoke(profilePage, 'profile desktop');
  } finally {
    await profilePage.close();
  }

  const mobilePage = await newSmokePage(browser, { viewport: { width: 390, height: 844 } });
  mobilePage.on('request', (req) => {
    if (new URL(req.url()).pathname === '/api/comparison') badRequests.push(req.url());
  });
  try {
    await mobilePage.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await mobilePage.waitForSelector('#releases .release');
    if (badRequests.length) throw new Error(`UI requested /api/comparison: ${badRequests.join(', ')}`);
    const mobileText = await mobilePage.locator('body').innerText();
    if (/\b(upstream|comparison)\b/i.test(mobileText)) {
      throw new Error('Visible mobile UI leaked upstream/comparison wording');
    }
    const mobileRenderedCount = await mobilePage.locator('#releases .release').count();
    if (mobileRenderedCount !== releases.length) {
      throw new Error(`Mobile rendered release row count ${mobileRenderedCount} did not match /api/releases ${releases.length}`);
    }

    const mobileRecommendationPanel = await openScoreBreakdown(
      mobilePage,
      recommendedTag ?? releases[0].tag,
    );
    if (recommendedTag && expectedRecommendedCmd) {
      await mobileRecommendationPanel.locator('.update-cmd__code')
        .filter({ hasText: expectedRecommendedCmd })
        .waitFor();
      await mobileRecommendationPanel
        .locator(`.update-cmd__copy${cssAttributeEquals('data-cmd', expectedRecommendedCmd)}`)
        .waitFor();
      await assertElementInViewport(mobilePage, mobileRecommendationPanel.locator('.update-cmd__code').first(), 'mobile update command');
      await assertElementInViewport(mobilePage, mobileRecommendationPanel.locator('.update-cmd__copy').first(), 'mobile copy button');
    } else if (await mobileRecommendationPanel.locator('.update-cmd__code, .update-cmd__copy').count()) {
      throw new Error('Mobile rendered an update command for a zero-recommendation run');
    }
    const mobileReviewPanel = hasFixCreditLinkScenario
      ? await openScoreBreakdown(mobilePage, fixCreditTag)
      : mobileRecommendationPanel;
    await mobileReviewPanel.locator('.score-review').waitFor();
    if (recommendedTag) {
      await mobilePage.locator(`${releaseSelector(recommendedTag)} .release__drivers`).first().waitFor();
    }

    await assertVisualSmoke(mobilePage, 'mobile');
    await assertHelpAndDisclosureTargetSizes(mobilePage, 'mobile');
    await assertElementInViewport(mobilePage, mobilePage.locator('.topbar__nav').first(), 'mobile topbar nav');
    await assertElementInViewport(mobilePage, mobileReviewPanel.locator('.score-review').first(), 'mobile score review');
    if (recommendedTag) {
      await assertElementInViewport(mobilePage, mobilePage.locator(`${releaseSelector(recommendedTag)} .release__drivers`).first(), 'mobile score drivers');
    }
    passCoverage(coverage.core, 'mobile');
  } finally {
    await mobilePage.close();
  }

  const narrowPage = await newSmokePage(browser, { viewport: { width: 320, height: 700 } });
  await narrowPage.route('**/api/status', async (route) => {
    await fulfillStatus(route, releases, {
      lastScoredAt: '2026-01-01T00:00:00.000Z',
      dataFreshness: { issueUpdatedAgeHoursAtScore: 1234.567 },
    });
  });
  try {
    await narrowPage.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await narrowPage.waitForSelector('#releases .release');
    const warning = narrowPage.locator('#topbarUpdated');
    await warning.waitFor({ state: 'visible' });
    await warning.getByText(/Source data may be stale/).waitFor();
    await assertWarningContrast(narrowPage, 'warning');
    await assertNoHorizontalOverflow(narrowPage, 'narrow warning');
    await assertElementInViewport(narrowPage, warning, 'narrow topbar warning');
    await narrowPage.locator('.install-summary .help-popover summary').click();
    const setupPopover = narrowPage.locator('.install-summary .help-popover .score-explain');
    await setupPopover.waitFor({ state: 'visible' });
    await assertNoHorizontalOverflow(narrowPage, 'narrow setup popover');
    await assertElementInViewport(narrowPage, setupPopover, 'narrow setup popover');
  } finally {
    await narrowPage.close();
  }

  passCoverage(coverage.core, 'no-overlap');
  reportCoverage(coverage);
  console.log(`UI smoke passed for ${base}`);
} finally {
  await browser.close();
}

async function assertHardRefreshUx(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const coherent = coherentSnapshotVariant(releases, publicPayload);
  const baseline = coherent.releases.some((release) =>
    release.recommended && release.finalScore != null && release.status !== 'stale')
    ? coherent
    : actionableSnapshotVariant(coherent);
  await assertActiveRefreshLifecycle(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertAuthorizationTransitions(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertCoherentPhantomAuthorizationGate(browser, {
    releases: baseline.releases,
    publicPayload: baseline.publicPayload,
  });
  await assertStaleCauseMappings(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertDelayedReleaseAndPublicStates(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertPublicReleaseSetAuthorization(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertHistoryReleaseSetAuthorization(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertRetainedPublicSnapshotIsDiagnostic(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertStatusFreshnessBlocksInstallActions(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertFocusAndMobileBrand(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertProfileSummaryOmission(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertAllStaleResponsiveState(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertStaleAuditHardRefreshIsolation(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertSafeReleaseAndPublicErrors(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertReviewFailureInvalidatesSnapshot(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertReviewSnapshotMismatchRecovery(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertSnapshotRebaseBudget(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
  await assertFailedSnapshotRebaseDropsRows(browser, {
    releases: baseline.releases,
    historyPayload: baseline.history,
    publicPayload: baseline.publicPayload,
  });
}

function actionableSnapshotVariant(snapshot) {
  const variant = snapshotVariant(
    snapshot.releases,
    snapshot.history,
    snapshot.publicPayload,
    250,
    0,
  );
  const target = variant.releases.find((release) => release.tag === variant.targetTag);
  if (!target) throw new Error('Hard-refresh smoke could not synthesize an actionable release');
  target.finalScore = target.finalScore ?? 8;
  target.band = 'solid';
  target.status = 'eligible';
  target.diagnosticStatus = null;
  target.recommended = true;
  target.reason = 'Synthetic actionable hard-refresh snapshot.';
  target.staleAudit = null;
  variant.releases.forEach((release) => {
    if (release.tag !== target.tag) release.recommended = false;
  });
  const historyRow = variant.history.find((release) => release.tag === target.tag);
  if (historyRow) {
    historyRow.finalScore = target.finalScore;
    historyRow.band = target.band;
    historyRow.status = target.status;
    historyRow.diagnosticStatus = null;
    historyRow.recommended = true;
    historyRow.staleAudit = null;
  }
  variant.history.forEach((release) => {
    if (release.tag !== target.tag) release.recommended = false;
  });
  const publicRow = variant.publicPayload.releases?.find((release) => release.tag === target.tag);
  if (publicRow) {
    publicRow.score = target.finalScore;
    publicRow.band = target.band;
    publicRow.status = target.status;
    publicRow.diagnosticStatus = null;
    publicRow.recommended = true;
    publicRow.reason = target.reason;
    publicRow.staleAudit = null;
  }
  variant.publicPayload.releases?.forEach((release) => {
    if (release.tag !== target.tag) release.recommended = false;
  });
  return variant;
}

async function assertActiveRefreshLifecycle(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const initial = coherentSnapshotVariant(releases, publicPayload);
  const recommended = initial.releases.find((release) =>
    release.recommended && release.finalScore != null
  );
  if (!recommended) throw new Error('Active-refresh smoke needs an actionable release');
  const stale = staleSnapshotVariant(
    initial.releases,
    initial.history,
    initial.publicPayload,
  );
  const completed = snapshotVariant(
    initial.releases,
    initial.history,
    initial.publicPayload,
    41,
    0.1,
  );
  const completedTarget = completed.releases.find((release) => release.tag === completed.targetTag);
  if (!completedTarget) throw new Error('Active-refresh smoke could not build a completed snapshot');
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let phase = 'initial';
  let releaseCalls = 0;
  let historyCalls = 0;
  let publicCalls = 0;
  let statusCalls = 0;
  let pendingCompletedPublicRoute = null;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      if (phase === 'active') {
        await new Promise((resolve) => setTimeout(resolve, 25));
      }
      const body = phase === 'active'
        ? stale.releases
        : phase === 'complete'
          ? completed.releases
          : initial.releases;
      return fulfillJson(route, body);
    }
    if (path === '/api/releases/history') {
      historyCalls += 1;
      const body = phase === 'active'
        ? stale.history
        : phase === 'complete'
          ? completed.history
          : initial.history;
      return fulfillJson(route, body);
    }
    if (path === '/api/public') {
      publicCalls += 1;
      if (phase === 'complete') {
        if (pendingCompletedPublicRoute) {
          throw new Error('Active-refresh smoke issued duplicate completed public requests');
        }
        pendingCompletedPublicRoute = route;
        return;
      }
      return fulfillJson(
        route,
        phase === 'active' ? stale.publicPayload : initial.publicPayload,
      );
    }
    if (path === '/api/status') {
      statusCalls += 1;
      return fulfillStatus(
        route,
        phase === 'complete' ? completed.releases : initial.releases,
        phase === 'active'
        ? {
            refreshing: true,
            activeRunId: null,
            currentScoreAuthorizationStatus: 'unavailable',
            lastError: 'synthetic previous failure that must not win during an active refresh',
            lastScoredAt: new Date().toISOString(),
            dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
          }
        : {
            refreshing: false,
            activeRunId: null,
            currentScoreAuthorizationStatus: 'authorized',
            lastError: null,
            lastScoredAt: completedTarget?.scoredAt ?? new Date().toISOString(),
            dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
          },
      );
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return fulfillJson(route, { error: 'review not expected in active-refresh smoke' }, 500);
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.locator('.release--recommended').waitFor();
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Active-refresh smoke did not start from actionable UI');
    }
    if (releaseCalls !== 1 || publicCalls !== 1 || historyCalls !== 1) {
      throw new Error(
        `Initial active-refresh snapshot used unexpected request counts: ` +
        `releases=${releaseCalls}, public=${publicCalls}, history=${historyCalls}`,
      );
    }

    phase = 'active';
    await page.evaluate(() => loadStatus());
    await page
      .locator('#updatedLabel')
      .getByText('Analysis refresh in progress', { exact: true })
      .waitFor();
    if (await page.getByText('Latest refresh failed', { exact: true }).count()) {
      throw new Error('Active refresh rendered a false latest-refresh-failed status');
    }
    await page
      .locator('#packageLoadState[data-release-state="hold"]')
      .getByText(/Analysis refresh in progress/)
      .waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Active refresh status transition');
    await assertAuthorizedRatingsRemainVisible(
      page,
      initial.releases,
      'Active refresh status transition',
    );
    if (releaseCalls !== 1) {
      throw new Error(`Active status transition unexpectedly loaded releases ${releaseCalls} times`);
    }

    await page.evaluate(() => {
      location.hash = '#/';
    });
    await page.locator('#viewHome').waitFor({ state: 'visible' });
    await page
      .locator('#packageCards')
      .getByText(/Analysis refresh in progress/)
      .waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Active refresh home card');
    await assertAuthorizedPackageRatingRemainsVisible(
      page,
      initial.releases[0],
      'Active refresh home card',
    );

    await page.evaluate(() => {
      location.hash = '#/openclaw';
    });
    await page.locator('#viewPackage').waitFor({ state: 'visible' });
    await page.reload({ waitUntil: 'networkidle' });
    await page
      .locator('#packageLoadState[data-release-state="hold"]')
      .getByText(/Analysis refresh in progress/)
      .waitFor();
    await assertNoActionableRetainedUi(page, 'Active refresh hard reload');
    if (releaseCalls !== 2) {
      throw new Error(`Active hard reload used ${releaseCalls} release requests instead of 2 total`);
    }

    phase = 'complete';
    await page.evaluate(() => loadStatus());
    await waitForCondition(
      () => releaseCalls === 3 && pendingCompletedPublicRoute,
      'post-refresh release load and public verification request',
    );
    await page.waitForFunction(
      ({ tag, scoredAt }) =>
        allReleases.find((release) => release.tag === tag)?.scoredAt === scoredAt,
      { tag: completed.targetTag, scoredAt: completedTarget?.scoredAt },
    );
    await assertNoRecommendationOrInstallUi(
      page,
      'Completed release snapshot pending public verification',
    );
    await fulfillJson(pendingCompletedPublicRoute, completed.publicPayload);
    pendingCompletedPublicRoute = null;
    await page.locator('.release--recommended').waitFor();
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Completed coherent snapshot did not restore install actions');
    }
    await page.waitForTimeout(100);
    if (releaseCalls !== 3 || publicCalls !== 2 || historyCalls !== 2) {
      throw new Error(
        `Refresh completion exceeded bounded request counts: ` +
        `releases=${releaseCalls}, public=${publicCalls}, history=${historyCalls}`,
      );
    }

    await page.evaluate(() => loadStatus());
    await page.waitForTimeout(100);
    if (releaseCalls !== 3) {
      throw new Error(`Repeated inactive status triggered ${releaseCalls - 3} extra release loads`);
    }
    if (statusCalls < 4) {
      throw new Error(`Active-refresh smoke did not exercise all status transitions: ${statusCalls}`);
    }
  } finally {
    await page.close();
  }
}

async function assertAuthorizationTransitions(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let authorization = 'authorized';
  let releaseCalls = 0;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      return fulfillJson(route, releases);
    }
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') return fulfillJson(route, publicPayload);
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        currentScoreAuthorizationStatus: authorization,
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) return;
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.locator('.release--recommended').waitFor();
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Authorized score publication did not expose install actions');
    }

    for (const scenario of [
      ['unauthorized', 'Analysis authorization failed'],
      ['missing', 'Analysis authorization is missing'],
      ['unavailable', 'Analysis authorization unavailable'],
      [undefined, 'Analysis authorization unavailable'],
    ]) {
      authorization = scenario[0];
      await page.evaluate(() => loadStatus());
      await page
        .locator('#packageLoadState[data-release-state="hold"]')
        .getByText(scenario[1], { exact: true })
        .waitFor();
      await assertNoRecommendationOrInstallUi(
        page,
        `Authorization ${String(scenario[0] ?? 'missing-field')}`,
      );
      if (await page.locator('#releases .release').count()) {
        throw new Error(
          `Authorization ${String(scenario[0] ?? 'missing-field')} exposed unauthorized ratings`,
        );
      }
    }

    authorization = 'not_required';
    await page.evaluate(() => loadStatus());
    await page.locator('.release--recommended').waitFor();
    await page.locator('#packageLoadState[data-release-state="ready"]').waitFor({
      state: 'hidden',
    });
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Narrow not_required authorization did not restore install actions');
    }
    if (releaseCalls !== 1) {
      throw new Error(`Authorization transitions unexpectedly reloaded releases ${releaseCalls} times`);
    }
  } finally {
    await page.close();
  }
}

async function assertCoherentPhantomAuthorizationGate(browser, {
  releases,
  publicPayload,
}) {
  if (!releases.length) {
    throw new Error('Phantom authorization smoke needs at least one release');
  }
  const snapshotId = snapshotIdForPayload(releases);
  if (!isFixtureSnapshotId(snapshotId)) {
    throw new Error('Phantom authorization smoke needs an explicit snapshot');
  }
  const phantomTags = INCIDENT_PHANTOM_TAGS;
  const parsedBaselineScoredAt = Date.parse(
    releases[0].scoredAt ?? new Date().toISOString(),
  );
  const baselineScoredAt = Number.isFinite(parsedBaselineScoredAt)
    ? parsedBaselineScoredAt
    : Date.now();
  const contaminatedRows = [
    ...structuredClone(releases),
    ...phantomTags.map((tag, index) => ({
      ...structuredClone(releases[0]),
      tag,
      name: tag,
      htmlUrl: `https://github.com/openclaw/openclaw/releases/tag/${tag}`,
      recommended: false,
      auditLinks: fixtureAuditLinks(
        tag,
        snapshotId,
        releases[0].scoreAudit?.auditDigest ?? null,
      ),
      scoredAt: new Date(baselineScoredAt + (index + 1) * 1000).toISOString(),
    })),
  ];
  const contaminated = coherentSnapshotVariant(
    contaminatedRows,
    publicPayload,
  );
  const page = await newSmokePage(browser, {
    viewport: { width: 1000, height: 800 },
  });

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      return fulfillJson(route, contaminated.releases);
    }
    if (path === '/api/releases/history') {
      return fulfillJson(route, contaminated.history);
    }
    if (path === '/api/public') {
      return fulfillJson(route, contaminated.publicPayload);
    }
    if (path === '/api/status') {
      return fulfillStatus(route, contaminated.releases, {
        currentScoreAuthorizationStatus: 'unauthorized',
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) return;
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page
      .locator('#packageLoadState[data-release-state="hold"]')
      .getByText(/Analysis authorization failed/)
      .waitFor();
    if (await page.locator('#releases .release').count()) {
      throw new Error(
        'Unauthorized coherent phantom payload rendered release rows',
      );
    }
    const bodyText = await page.locator('body').innerText();
    for (const tag of phantomTags) {
      if (bodyText.includes(tag)) {
        throw new Error(`Unauthorized phantom release ${tag} reached the DOM`);
      }
    }
    await assertNoRecommendationOrInstallUi(
      page,
      'Unauthorized coherent phantom payload',
    );
  } finally {
    await page.close();
  }
}

async function assertStaleCauseMappings(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const stale = staleSnapshotVariant(releases, historyPayload, publicPayload);
  const target = stale.releases[0];
  if (!target) throw new Error('Stale-cause smoke needs a release row');
  target.staleAudit = {
    ...(target.staleAudit ?? {}),
    schemaVersion: 1,
    state: 'stale',
    message: 'Analysis is stale. Previous audited status: skip-cve. Refresh before installing.',
    previousStatus: 'skip-cve',
    auditedAt: target.staleAudit?.auditedAt ?? null,
    causes: [
      'audit_missing',
      'audit_publication_invalid',
      'score_model_changed',
      'prompt_changed',
      'release_score_record_mismatch',
      'audit_payload_incompatible',
      'recommendation_policy_incompatible',
      'score_ledger_incompatible',
      'evidence_source_changed',
      'audit_incompatible',
      'closure_proof_integrity_stale',
      'score_blocking_ingestion_failure',
      'refresh_in_progress',
      'current_score_missing',
    ],
  };
  target.reason = target.staleAudit.message;

  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, stale.releases);
    if (path === '/api/releases/history') return fulfillJson(route, stale.history);
    if (path === '/api/public') return fulfillJson(route, stale.publicPayload);
    if (path === '/api/status') return fulfillStatus(route, stale.releases);
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return fulfillJson(route, { error: 'stale rows must not request reviews' }, 500);
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await releaseToggle(page, target.tag).click();
    const diagnostic = page.locator(`#review-${domIdForTag(target.tag)} [data-review-state="stale"]`);
    await diagnostic.waitFor();
    const text = await diagnostic.innerText();
    for (const expected of [
      'closed-issue proof integrity must be refreshed',
      'a required evidence ingestion step failed',
      'no current score publication exists',
      'Previous audited status: blocked by security advisory',
    ]) {
      if (!text.includes(expected)) {
        throw new Error(`Stale diagnostic did not humanize ${expected}: ${text}`);
      }
    }
    if (/closure_proof_integrity_stale|score_blocking_ingestion_failure|skip-cve/.test(text)) {
      throw new Error(`Stale diagnostic exposed raw machine status: ${text}`);
    }
  } finally {
    await page.close();
  }
}

async function assertStaleAuditHardRefreshIsolation(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const currentRelease = releases.find((release) =>
    release.finalScore != null && release.scoreAudit?.auditDigest
  ) ?? releases[0];
  if (!currentRelease) throw new Error('Stale-audit hard-refresh smoke needs a release row');
  const previousStatus = currentRelease.diagnosticStatus ?? currentRelease.status ?? 'eligible';
  const staleAudit = {
    schemaVersion: 1,
    state: 'stale',
    message: `Analysis is stale. Previous audited status: ${previousStatus}. Refresh before installing.`,
    previousStatus,
    auditedAt: currentRelease.staleAudit?.auditedAt ?? currentRelease.scoredAt ?? null,
    causes: ['evidence_source_changed'],
  };
  const staleRelease = {
    ...structuredClone(currentRelease),
    finalScore: null,
    band: 'wait',
    status: 'stale',
    diagnosticStatus: previousStatus,
    recommended: false,
    reason: staleAudit.message,
    brokenSurfaces: [],
    negativeIssues: null,
    positiveIssues: null,
    closedSeriousFixed: null,
    openedSeriousDuringReign: null,
    scoredAt: null,
    scoreAudit: null,
    staleAudit,
    explanation: null,
  };
  const staleReleases = structuredClone(releases).map((release) =>
    release.tag === staleRelease.tag ? staleRelease : release
  );
  const staleSnapshotId = staleReleases[0]?.snapshotId ?? 'a'.repeat(64);
  staleReleases.forEach((release) => { release.snapshotId = staleSnapshotId; });
  const obsoleteSnapshotId = 'b'.repeat(64);
  const obsoleteHistory = structuredClone(historyPayload).map((release) =>
    release.tag === staleRelease.tag
      ? {
          ...release,
          finalScore: 9.9,
          band: 'solid',
          status: previousStatus,
          diagnosticStatus: null,
          recommended: true,
          scoredAt: staleAudit.auditedAt,
          scoreAudit: currentRelease.scoreAudit ?? {
            schemaVersion: 2,
            reviewSchemaVersion: 1,
            auditDigest: 'e'.repeat(64),
            authorityRunId: `ui-smoke-obsolete-authority:${release.tag}`,
            authorityRunContentHash: createHash('sha256')
              .update(`ui-smoke-obsolete-authority-content:${release.tag}`)
              .digest('hex'),
            historyV2SealContentHash: createHash('sha256')
              .update(`ui-smoke-obsolete-history-v2-seal:${release.tag}`)
              .digest('hex'),
            modelVersion: 'ui-smoke-obsolete',
            promptVersion: 1,
            evidenceCoverage: 1,
            rawIssueCount: 0,
            classifiedIssueCount: 0,
          },
          staleAudit: null,
          dataFreshness: staleRelease.dataFreshness,
        }
      : release
  );
  obsoleteHistory.forEach((release) => { release.snapshotId = obsoleteSnapshotId; });
  const stalePublic = structuredClone(publicPayload);
  stalePublic.snapshotId = staleSnapshotId;
  stalePublic.snapshot = {
    ...(stalePublic.snapshot ?? {}),
    id: staleSnapshotId,
    source: 'current',
    retained: false,
    stale: false,
    actionable: true,
    ageMs: 0,
    maxAgeMs: null,
  };
  stalePublic.releases?.forEach((release) => { release.snapshotId = staleSnapshotId; });
  const stalePublicRow = stalePublic.releases?.find((release) => release.tag === staleRelease.tag);
  if (!stalePublicRow) throw new Error(`Stale-audit hard-refresh smoke missing ${staleRelease.tag}`);
  Object.assign(stalePublicRow, {
    score: null,
    band: 'wait',
    status: 'stale',
    diagnosticStatus: previousStatus,
    recommended: false,
    reason: staleAudit.message,
    negativeIssues: null,
    positiveIssues: null,
    scoredAt: null,
    scoreAudit: null,
    staleAudit,
    explanation: null,
    watchIssues: [{
      number: 990003,
      title: 'CURRENT EVIDENCE MARKER',
      url: 'https://github.com/openclaw/openclaw/issues/990003',
      state: 'open',
      severity: 'low',
      affectedUsers: 'few',
      surface: { label: 'Core', icon: 'core' },
    }],
    issues: [],
  });
  const obsoleteReview = {
    tag: staleRelease.tag,
    local: {
      schemaVersion: 1,
      score: 9.9,
      band: 'solid',
      status: 'eligible',
      diagnosticStatus: null,
      recommended: true,
      reason: 'OBSOLETE SCORE COMPONENT MARKER',
      staleAudit: null,
      scoredAt: staleAudit.auditedAt,
      auditDigest: 'f'.repeat(64),
      sourceProvenance: { auditDigest: 'f'.repeat(64) },
      input: { rawIssueCount: 99, classifiedIssueCount: 99 },
      issueEvidence: {},
      gateEvidence: {},
      components: {
        evidenceCoverage: 1,
        components: { obsoletePenalty: -9.9 },
        explanation: {
          title: 'OBSOLETE SCORE COMPONENT MARKER',
        },
      },
    },
  };

  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let reviewCalls = 0;
  let historyCalls = 0;
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, staleReleases);
    if (path === '/api/releases/history') {
      historyCalls += 1;
      return fulfillJson(route, obsoleteHistory);
    }
    if (path === '/api/public') return fulfillJson(route, stalePublic);
    if (path === '/api/status') {
      return fulfillStatus(route, staleReleases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (path === `/api/releases/${encodeURIComponent(staleRelease.tag)}/review`) {
      reviewCalls += 1;
      return fulfillJson(route, obsoleteReview);
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page
      .locator('#recTarget')
      .getByText(/stored analysis was produced by older scoring code or evidence/i)
      .waitFor();
    const row = page.locator(releaseSelector(staleRelease.tag));
    await row.waitFor();
    await row.locator('[data-release-toggle]').click();
    const panel = page.locator(`#det-${domIdForTag(staleRelease.tag)}`);
    const diagnostic = panel.locator('[data-review-state="stale"]');
    await diagnostic.getByText('Assessment details unavailable.', { exact: false }).waitFor();
    await diagnostic.getByText(/evidence source changed after scoring/i).waitFor();
    await panel.locator('summary.evidence-toggle__summary', { hasText: 'Show related issues' }).click();
    await panel.getByText('CURRENT EVIDENCE MARKER', { exact: false }).waitFor();
    if (reviewCalls !== 0) {
      throw new Error(`Stale hard reload requested ${reviewCalls} obsolete score review(s)`);
    }
    if (await panel.locator('.score-review, .score-ledger, .score-review__components').count()) {
      throw new Error('Stale hard reload rendered obsolete score components');
    }
    const panelText = await panel.innerText();
    if (/OBSOLETE SCORE COMPONENT MARKER|obsoletePenalty|-9\.9/.test(panelText)) {
      throw new Error(`Stale hard reload mixed obsolete score details with current evidence: ${panelText}`);
    }
    if (await page.locator(`.score-history__dot${cssAttributeEquals('data-tag', staleRelease.tag)}`).count()) {
      throw new Error('Obsolete history score reappeared for an authoritative stale release');
    }
    if (historyCalls < 2) {
      throw new Error('Stale history override did not exercise the automatic snapshot rebase');
    }
  } finally {
    await page.close();
  }
}

async function assertDelayedReleaseAndPublicStates(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  const release = releases[0];
  const emptyPublic = structuredClone(publicPayload);
  const emptyPublicRow = emptyPublic.releases?.find((row) => row.tag === release.tag);
  if (!emptyPublicRow) throw new Error(`Missing public row for ${release.tag}`);
  emptyPublicRow.watchIssues = [];
  emptyPublicRow.issues = [];
  let pendingReleaseRoute = null;
  let pendingPublicRoute = null;

  await page.addInitScript(() => {
    requestAnimationFrame(() => {
      const packageView = document.getElementById('viewPackage');
      const homeView = document.getElementById('viewHome');
      window.__hardRefreshFirstPaint = {
        exactRoute: location.hash === '#/openclaw',
        routeClass: document.documentElement.classList.contains('route-openclaw'),
        packageVisible: packageView ? getComputedStyle(packageView).display !== 'none' : false,
        homeHidden: homeView ? getComputedStyle(homeView).display === 'none' : false,
      };
    });
  });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      pendingReleaseRoute = route;
      return;
    }
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') {
      pendingPublicRoute = route;
      return;
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return;
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    await waitForCondition(() => pendingReleaseRoute, 'delayed release request');
    const loading = page.locator('#packageLoadState[data-release-state="loading"]');
    if (!await loading.isVisible()) {
      throw new Error('Delayed release load did not show the package loading state');
    }
    await page.waitForFunction(() => window.__hardRefreshFirstPaint != null);
    const firstPaint = await page.evaluate(() => window.__hardRefreshFirstPaint);
    if (!firstPaint.exactRoute || !firstPaint.routeClass || !firstPaint.packageVisible || !firstPaint.homeHidden) {
      throw new Error(`Exact package route was not established before first paint: ${JSON.stringify(firstPaint)}`);
    }

    await fulfillJson(pendingReleaseRoute, releases);
    pendingReleaseRoute = null;
    await waitForCondition(() => pendingPublicRoute, 'delayed public request');
    await page.locator('#packageLoadState[data-release-state="hold"]').waitFor({
      state: 'visible',
    });
    if (await page.locator('#releases .release').count() !== releases.length) {
      throw new Error('Pending public verification hid authoritative release rows');
    }
    await assertNoRecommendationOrInstallUi(page, 'Pending public verification');
    await assertAuthorizedRatingsRemainVisible(page, releases, 'Pending public verification');

    await fulfillJson(pendingPublicRoute, emptyPublic);
    pendingPublicRoute = null;
    await page.waitForSelector('#releases .release');
    await assertReleaseRowInteractionSemantics(page, release.tag);
    const row = page.locator(releaseSelector(release.tag));
    await row.locator('[data-release-toggle]').click();
    const issueSlot = page.locator(`#issues-${domIdForTag(release.tag)}`);
    await issueSlot.locator('[data-public-state="empty"]').waitFor({ state: 'visible' });
    await page.locator('.release--recommended').waitFor();

    await page.evaluate(() => {
      location.hash = '#/openclaw/extra';
    });
    await page.locator('#viewHome').waitFor({ state: 'visible' });
    if (await page.locator('#viewPackage').isVisible()) {
      throw new Error('A non-exact openclaw hash activated the package route');
    }
  } finally {
    await page.close();
  }
}

async function assertPublicReleaseSetAuthorization(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const publicRows = publicPayload.releases ?? [];
  if (!releases.length || publicRows.length !== releases.length) {
    throw new Error('Public release-set authorization smoke needs a complete baseline');
  }
  const missingRelease = structuredClone(publicPayload);
  missingRelease.releases = missingRelease.releases.slice(0, -1);
  const duplicateRelease = structuredClone(publicPayload);
  duplicateRelease.releases = [
    ...duplicateRelease.releases,
    structuredClone(duplicateRelease.releases[0]),
  ];
  const substituteRelease = (tag) => {
    const payload = structuredClone(publicPayload);
    payload.releases[0] = {
      ...payload.releases[0],
      tag,
      url: `https://github.com/openclaw/openclaw/releases/tag/${tag}`,
    };
    return payload;
  };

  for (const scenario of [
    { label: 'missing release', payload: missingRelease, phantomTag: null },
    { label: 'duplicate release', payload: duplicateRelease, phantomTag: null },
    {
      label: `same-size ${INCIDENT_PHANTOM_TAGS[0]} substitution`,
      payload: substituteRelease(INCIDENT_PHANTOM_TAGS[0]),
      phantomTag: INCIDENT_PHANTOM_TAGS[0],
    },
    {
      label: `same-size ${INCIDENT_PHANTOM_TAGS[1]} substitution`,
      payload: substituteRelease(INCIDENT_PHANTOM_TAGS[1]),
      phantomTag: INCIDENT_PHANTOM_TAGS[1],
    },
  ]) {
    const {
      label,
      payload: mismatchedPublic,
      phantomTag,
    } = scenario;
    const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
    let releaseCalls = 0;
    let publicCalls = 0;

    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/releases') {
        releaseCalls += 1;
        return fulfillJson(route, releases);
      }
      if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
      if (path === '/api/public') {
        publicCalls += 1;
        return fulfillJson(route, mismatchedPublic);
      }
      if (path === '/api/status') {
        return fulfillStatus(route, releases, {
          lastError: null,
          lastScoredAt: new Date().toISOString(),
          dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
        });
      }
      if (/^\/api\/releases\/[^/]+\/review$/.test(path)) return;
      return route.continue();
    });

    try {
      await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
      await waitForCondition(
        () => releaseCalls === 2 && publicCalls === 2,
        `public ${label} automatic snapshot rebase`,
      );
      await page.locator('#packageLoadState[data-release-state="hold"]').waitFor({
        state: 'visible',
      });
      await assertNoRecommendationOrInstallUi(page, `Public ${label}`);
      await assertAuthorizedRatingsRemainVisible(page, releases, `Public ${label}`);
      const state = await page.evaluate(() => ({
        releaseState: releaseLoadState.status,
        publicState: publicLoadState.status,
        releaseSnapshot,
        publicDetailCount: publicReleaseDetails.size,
      }));
      if (
        state.releaseState !== 'ready'
        || state.publicState !== 'error'
        || !/^[0-9a-f]{64}$/.test(state.releaseSnapshot)
        || state.publicDetailCount !== 0
      ) {
        throw new Error(`Public ${label} did not fail closed: ${JSON.stringify(state)}`);
      }
      if (
        phantomTag &&
        (await page.locator('body').innerText()).includes(phantomTag)
      ) {
        throw new Error(`Public ${label} rendered phantom tag ${phantomTag}`);
      }
      await page.waitForTimeout(100);
      if (releaseCalls !== 2 || publicCalls !== 2) {
        throw new Error(
          `Public ${label} exceeded the rebase budget: releases=${releaseCalls}, public=${publicCalls}`,
        );
      }
    } finally {
      await page.close();
    }
  }
}

async function assertHistoryReleaseSetAuthorization(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  if (!releases.length || !historyPayload.length) {
    throw new Error('History release-set authorization smoke needs scored history');
  }

  for (const phantomTag of INCIDENT_PHANTOM_TAGS) {
    const mismatchedHistory = structuredClone(historyPayload);
    mismatchedHistory[0] = {
      ...mismatchedHistory[0],
      tag: phantomTag,
    };
    const page = await newSmokePage(browser, {
      viewport: { width: 1000, height: 800 },
    });
    let releaseCalls = 0;
    let historyCalls = 0;

    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/releases') {
        releaseCalls += 1;
        return fulfillJson(route, releases);
      }
      if (path === '/api/releases/history') {
        historyCalls += 1;
        return fulfillJson(route, mismatchedHistory);
      }
      if (path === '/api/public') return fulfillJson(route, publicPayload);
      if (path === '/api/status') return fulfillStatus(route, releases);
      if (/^\/api\/releases\/[^/]+\/review$/.test(path)) return;
      return route.continue();
    });

    try {
      await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
      await page.waitForSelector('#releases .release');
      await waitForCondition(
        () => releaseCalls === 2 && historyCalls === 2,
        `history ${phantomTag} automatic snapshot rebase`,
      );
      await page.locator('.release--recommended').waitFor();
      if (await page.locator(`.score-history__dot${cssAttributeEquals('data-tag', phantomTag)}`).count()) {
        throw new Error(`History rendered phantom rating ${phantomTag}`);
      }
      if ((await page.locator('body').innerText()).includes(phantomTag)) {
        throw new Error(`History rendered phantom tag ${phantomTag}`);
      }
      await page.waitForTimeout(100);
      if (releaseCalls !== 2 || historyCalls !== 2) {
        throw new Error(
          `History ${phantomTag} exceeded the rebase budget: ` +
          `releases=${releaseCalls}, history=${historyCalls}`,
        );
      }
    } finally {
      await page.close();
    }
  }
}

async function assertRetainedPublicSnapshotIsDiagnostic(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const retained = structuredClone(publicPayload);
  retained.snapshot = {
    ...retained.snapshot,
    source: 'retained',
    retained: true,
    stale: true,
    actionable: false,
    ageMs: 250,
    maxAgeMs: 30_000,
  };
  retained.releases = retained.releases.map((release) => ({
    ...release,
    score: null,
    band: 'wait',
    status: 'stale',
    recommended: false,
    scoredAt: null,
    scoreAudit: null,
    explanation: null,
    staleAudit: {
      schemaVersion: 1,
      state: 'stale',
      message: 'Analysis is stale. Retained public evidence is diagnostic only.',
      previousStatus: release.status,
      auditedAt: release.scoredAt,
      causes: ['public_payload_retained'],
    },
  }));
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') return fulfillJson(route, retained);
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastError: null,
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.locator('#packageLoadState[data-release-state="hold"]').waitFor({
      state: 'visible',
    });
    await page
      .locator('#packageLoadState')
      .getByText(/retained or stale diagnostic data/i)
      .waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Retained public snapshot');
    await assertAuthorizedRatingsRemainVisible(page, releases, 'Retained public snapshot');
    await exposeReleaseDetailsWithoutReview(page, releases[0].tag);
    await page
      .locator(`#issues-${domIdForTag(releases[0].tag)} [data-public-retry]`)
      .waitFor({ state: 'visible' });
    await assertRetryTargetSizes(page, 'Retained public snapshot');
  } finally {
    await page.close();
  }
}

async function assertStatusFreshnessBlocksInstallActions(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let statusMode = 'fresh';

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') return fulfillJson(route, publicPayload);
    if (path === '/api/status') {
      if (statusMode === 'unavailable') {
        return route.fulfill({
          status: 503,
          contentType: 'application/json',
          body: JSON.stringify({ error: 'RAW_STATUS_503_DO_NOT_RENDER' }),
        });
      }
      if (statusMode === 'failed') {
        return fulfillStatus(route, releases, {
          lastError: 'synthetic refresh failure',
          lastScoredAt: new Date().toISOString(),
          dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
        });
      }
      if (statusMode === 'stale') {
        return fulfillStatus(route, releases, {
          lastError: null,
          lastScoredAt: new Date().toISOString(),
          dataFreshness: { issueUpdatedAgeHoursAtScore: 24 },
        });
      }
      return fulfillStatus(route, releases, {
        lastError: null,
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.locator('.release--recommended').waitFor();
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Fresh status did not expose the verified install action');
    }

    statusMode = 'failed';
    await page.evaluate(() => loadStatus());
    await page.locator('#updatedLabel').getByText('Latest refresh failed', { exact: true }).waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Failed refresh status');
    await assertAuthorizedRatingsRemainVisible(page, releases, 'Failed refresh status');
    await page.locator('#recTarget').waitFor({ state: 'visible' });

    statusMode = 'stale';
    await page.evaluate(() => loadStatus());
    await page.locator('#updatedLabel').getByText(/Source data may be stale/).waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Stale source status');
    await assertAuthorizedRatingsRemainVisible(page, releases, 'Stale source status');
    await page.locator('#recTarget').waitFor({ state: 'visible' });

    statusMode = 'unavailable';
    await page.evaluate(() => loadStatus());
    await page.locator('#updatedLabel').getByText('Status unavailable', { exact: true }).waitFor();
    await assertNoRecommendationOrInstallUi(page, 'Status unavailable');
    await assertAuthorizedRatingsRemainVisible(page, releases, 'Status unavailable');
    await page.locator('#recTarget').waitFor({ state: 'visible' });

    statusMode = 'fresh';
    await page.evaluate(() => loadStatus());
    await page.locator('.release--recommended').waitFor();
    if (!await page.locator('.update-cmd__code').count()) {
      throw new Error('Fresh status did not restore install actions');
    }
  } finally {
    await page.close();
  }
}

async function assertFocusAndMobileBrand(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const page = await newSmokePage(browser, { viewport: { width: 390, height: 844 } });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') return fulfillJson(route, publicPayload);
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastError: null,
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.waitForSelector('#releases .release');
    await page.getByRole('link', { name: 'Release Radar', exact: true }).waitFor();

    await page.locator('#profileFilter [data-action="open"]').click();
    await page.locator('#profileFilter [data-action="close"]').waitFor();
    if (!await page.locator('#profileFilter').evaluate((filter) => filter.contains(document.activeElement))) {
      throw new Error('Opening the setup wizard moved focus outside the visible wizard');
    }

    const firstOption = page.locator('#profileFilter [data-action="toggle"]').first();
    const firstLabel = await firstOption.getAttribute('data-label');
    await firstOption.click();
    const focusedLabel = await page.evaluate(() => document.activeElement?.dataset?.label ?? null);
    if (focusedLabel !== firstLabel) {
      throw new Error(`Wizard option rerender lost focus: expected ${firstLabel}, got ${focusedLabel}`);
    }

    await page.evaluate(() => renderProfileFilter(allReleases));
    if (!await page.locator('#profileFilter').evaluate((filter) => filter.contains(document.activeElement))) {
      throw new Error('Profile rerender moved focus outside the visible wizard');
    }

    await page.locator('#profileFilter [data-action="close"]').click();
    const summaryOpen = page.locator('#profileFilter [data-action="open"]');
    await summaryOpen.waitFor();
    if (!await summaryOpen.evaluate((element) => element === document.activeElement)) {
      throw new Error('Closing the setup wizard did not return focus to its visible launcher');
    }

    const back = page.locator('.detail-back');
    await back.focus();
    await back.click();
    await page.locator('#viewHome').waitFor({ state: 'visible' });
    if (!await page.locator('#viewHome').evaluate((view) => view.contains(document.activeElement))) {
      throw new Error('Route rerender left focus in the hidden package view');
    }
  } finally {
    await page.close();
  }
}

async function assertProfileSummaryOmission(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const target = releases[0];
  if (!target) throw new Error('Profile-summary omission smoke needs a release row');
  const selectedSurface = { label: 'Discord', icon: 'discord' };
  const omittedPublic = structuredClone(publicPayload);
  const publicRow = omittedPublic.releases?.find((row) => row.tag === target.tag);
  if (!publicRow) throw new Error(`Profile-summary omission smoke missing ${target.tag}`);
  publicRow.profileEvidence = fixtureProfileEvidence({
    tag: publicRow.tag,
    scoreAudit: publicRow.scoreAudit,
    sourceIdentityDigest:
      publicRow.profileEvidence?.publicationBinding?.sourceIdentityDigest ??
      createHash('sha256')
        .update(`ui-smoke-source-identity:${publicRow.tag}`)
        .digest('hex'),
    issueEvidenceSchemaVersion:
      publicRow.profileEvidence?.issueEvidenceSchemaVersion ?? 2,
    profileRowCount: 3,
    issueCount: 3,
    weightedIssueCount: 3,
    surfaceIssueCount: 3,
    surfaceWeight: 3,
    surfaces: [{
      ...selectedSurface,
      count: 3,
      weight: 3,
      tiers: { verifiedDebt: 3 },
      weightByTier: { verifiedDebt: 3 },
    }],
  });
  publicRow.watchIssues = Array.from({ length: 25 }, (_, index) => ({
    number: 991000 + index,
    title: `Telegram summary issue ${index + 1}`,
    url: `https://github.com/openclaw/openclaw/issues/${991000 + index}`,
    state: 'open',
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    affectedUsers: 'some',
    hasWorkaround: false,
    surface: { label: 'Telegram', icon: 'telegram' },
  }));
  publicRow.issues = [];

  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let releaseCalls = 0;
  let historyCalls = 0;
  let publicCalls = 0;
  let reviewCalls = 0;
  await page.addInitScript((surfaceLabel) => {
    localStorage.setItem(
      'openclaw-release-radar.installProfile.v1',
      JSON.stringify([surfaceLabel]),
    );
  }, selectedSurface.label);
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      return fulfillJson(route, releases);
    }
    if (path === '/api/releases/history') {
      historyCalls += 1;
      return fulfillJson(route, historyPayload);
    }
    if (path === '/api/public') {
      publicCalls += 1;
      return fulfillJson(route, omittedPublic);
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      reviewCalls += 1;
      return;
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.waitForSelector('#releases .release');
    await releaseToggle(page, target.tag).click();
    const panel = page.locator(`#det-${domIdForTag(target.tag)}`);
    await panel.locator('summary.evidence-toggle__summary', { hasText: 'Show related issues' }).click();
    await panel
      .getByText(
        'The full analysis contains 3 matching watch-area issues, but this 25-item public summary does not include their details.',
        { exact: true },
      )
      .waitFor();
    const panelText = await panel.innerText();
    if (/No watch-area (?:issues|reports) found/i.test(panelText)) {
      throw new Error(`Profile summary falsely claimed no matching issues: ${panelText}`);
    }
    await assertHelpAndDisclosureTargetSizes(page, 'profile summary omission');
    if (releaseCalls !== 1 || historyCalls !== 1 || publicCalls !== 1 || reviewCalls !== 1) {
      throw new Error(
        `Profile-summary omission used unexpected requests: ` +
        `releases=${releaseCalls}, history=${historyCalls}, public=${publicCalls}, review=${reviewCalls}`,
      );
    }
  } finally {
    await page.close();
  }
}

async function assertAllStaleResponsiveState(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const stale = staleSnapshotVariant(releases, historyPayload, publicPayload);
  const target = stale.releases[0];
  if (!target) throw new Error('All-stale responsive smoke needs a release row');
  const targetPublic = stale.publicPayload.releases?.find((row) => row.tag === target.tag);
  if (targetPublic && !(targetPublic.watchIssues?.length || targetPublic.issues?.length)) {
    targetPublic.watchIssues = [{
      number: 991100,
      title: 'Synthetic stale-state evidence',
      url: 'https://github.com/openclaw/openclaw/issues/991100',
      state: 'open',
      sentiment: 'negative',
      severity: 'high',
      scope: 'moderate',
      affectedUsers: 'some',
      hasWorkaround: false,
      surface: { label: 'Core', icon: 'core' },
    }];
  }

  for (const scenario of [
    { label: 'all-stale desktop', viewport: { width: 1200, height: 900 } },
    { label: 'all-stale mobile', viewport: { width: 390, height: 844 } },
  ]) {
    const page = await newSmokePage(browser, { viewport: scenario.viewport });
    let releaseCalls = 0;
    let historyCalls = 0;
    let publicCalls = 0;
    let reviewCalls = 0;
    await page.route('**/api/**', async (route) => {
      const path = new URL(route.request().url()).pathname;
      if (path === '/api/releases') {
        releaseCalls += 1;
        return fulfillJson(route, stale.releases);
      }
      if (path === '/api/releases/history') {
        historyCalls += 1;
        return fulfillJson(route, stale.history);
      }
      if (path === '/api/public') {
        publicCalls += 1;
        return fulfillJson(route, stale.publicPayload);
      }
      if (path === '/api/status') {
        return fulfillStatus(route, stale.releases, {
          refreshing: false,
          activeRunId: null,
          lastError: null,
          lastScoredAt: new Date().toISOString(),
          dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
        });
      }
      if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
        reviewCalls += 1;
        return fulfillJson(route, { error: 'stale rows must not request score reviews' }, 500);
      }
      return route.continue();
    });

    try {
      await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
      await page.waitForSelector('#releases .release');
      if (scenario.label === 'all-stale desktop') {
        await assertWarningContrast(page, scenario.label);
      }
      await page
        .locator('#recTarget')
        .getByText(/stored analysis was produced by older scoring code or evidence/i)
        .waitFor();
      const staleRows = page.locator('#releases .release--stale');
      if (await staleRows.count() !== stale.releases.length) {
        throw new Error(`${scenario.label} did not render every release as stale`);
      }
      await assertNoActionableRetainedUi(page, scenario.label);
      await releaseToggle(page, target.tag).click();
      await page.locator(`#det-${domIdForTag(target.tag)}`).waitFor({ state: 'visible' });
      await assertNoActionableRetainedUi(page, `${scenario.label} expanded`);
      await assertVisualSmoke(page, scenario.label);
      await assertHelpAndDisclosureTargetSizes(page, scenario.label);
      await page.waitForTimeout(50);
      if (releaseCalls !== 1 || historyCalls !== 1 || publicCalls !== 1 || reviewCalls !== 0) {
        throw new Error(
          `${scenario.label} exceeded bounded requests: ` +
          `releases=${releaseCalls}, history=${historyCalls}, public=${publicCalls}, review=${reviewCalls}`,
        );
      }
    } finally {
      await page.close();
    }
  }
}

async function assertSafeReleaseAndPublicErrors(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const rawReleaseMarker = 'RAW_RELEASE_RESPONSE_BODY_DO_NOT_RENDER';
  const releasePage = await newSmokePage(browser, { viewport: { width: 900, height: 700 } });
  let releaseCalls = 0;
  await releasePage.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      if (releaseCalls === 1) {
        return route.fulfill({
          status: 502,
          contentType: 'text/plain',
          body: `${rawReleaseMarker}\nupstream status 599`,
        });
      }
      return fulfillJson(route, [], 200, releases[0]?.snapshotId);
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastError: 'RAW_STATUS_ERROR_DO_NOT_RENDER',
        lastScoredAt: new Date().toISOString(),
      });
    }
    return route.continue();
  });
  try {
    await releasePage.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    const errorState = releasePage.locator('#packageLoadState[data-release-state="error"]');
    await errorState.waitFor({ state: 'visible' });
    const bodyText = await releasePage.locator('body').innerText();
    if (bodyText.includes(rawReleaseMarker) || bodyText.includes('RAW_STATUS_ERROR_DO_NOT_RENDER') ||
        /\b(502|599)\b/.test(bodyText)) {
      throw new Error(`Unsafe release error content reached the UI: ${bodyText}`);
    }
    await releasePage.locator('#updatedLabel').getByText('Latest refresh failed', { exact: true }).waitFor();
    await errorState.locator('[data-release-retry]').click();
    await releasePage.locator('#packageLoadState[data-release-state="empty"]').waitFor({ state: 'visible' });
    if (releaseCalls !== 2) {
      throw new Error(`Release error retry issued ${releaseCalls} release requests instead of 2`);
    }
  } finally {
    await releasePage.close();
  }

  const rawPublicMarker = 'RAW_PUBLIC_RESPONSE_BODY_DO_NOT_RENDER';
  const publicPage = await newSmokePage(browser, { viewport: { width: 900, height: 700 } });
  await publicPage.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') {
      return route.fulfill({
        status: 503,
        contentType: 'application/json',
        body: JSON.stringify({ error: rawPublicMarker, status: 598 }),
      });
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return;
    }
    return route.continue();
  });
  try {
    await publicPage.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    const publicHold = publicPage.locator('#packageLoadState[data-release-state="hold"]');
    await publicHold.waitFor({
      state: 'visible',
    });
    const bodyText = await publicPage.locator('body').innerText();
    if (bodyText.includes(rawPublicMarker) || /\b(503|598)\b/.test(bodyText)) {
      throw new Error(`Unsafe public error content reached the UI: ${bodyText}`);
    }
    await publicPage.locator('[data-public-retry]').first().waitFor({ state: 'attached' });
    await assertNoRecommendationOrInstallUi(publicPage, 'Public 503');
    await assertAuthorizedRatingsRemainVisible(publicPage, releases, 'Public 503');
  } finally {
    await publicPage.close();
  }

  const timeoutPage = await newSmokePage(browser, { viewport: { width: 900, height: 700 } });
  await timeoutPage.addInitScript(() => {
    const nativeSetTimeout = window.setTimeout.bind(window);
    window.setTimeout = (handler, timeout = 0, ...args) =>
      nativeSetTimeout(handler, timeout === 17_000 ? 100 : timeout, ...args);
  });
  await timeoutPage.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') {
      await new Promise((resolve) => setTimeout(resolve, 400));
      return fulfillJson(route, publicPayload);
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return;
    }
    return route.continue();
  });
  try {
    await timeoutPage.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    const timeoutState = timeoutPage.locator('#packageLoadState[data-release-state="hold"]');
    await timeoutState.waitFor({
      state: 'visible',
    });
    await timeoutState.getByText(/timed out/i).waitFor();
    const timeoutText = await timeoutState.innerText();
    if (!/timed out/i.test(timeoutText)) {
      throw new Error(`Public timeout state did not explain the timeout: ${timeoutText}`);
    }
    await timeoutPage.locator('[data-public-retry]').first().waitFor({ state: 'attached' });
    await assertNoRecommendationOrInstallUi(timeoutPage, 'Public timeout');
    await assertAuthorizedRatingsRemainVisible(timeoutPage, releases, 'Public timeout');
  } finally {
    await timeoutPage.close();
  }
}

async function assertReviewFailureInvalidatesSnapshot(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const scenario = releases.some((row) => row.finalScore != null)
    ? {
        releases: structuredClone(releases),
        history: structuredClone(historyPayload),
        publicPayload: structuredClone(publicPayload),
      }
    : snapshotVariant(releases, historyPayload, publicPayload, 21, 0.1);
  let release = scenario.releases.find((row) => row.recommended && row.finalScore != null)
    ?? scenario.releases.find((row) => row.finalScore != null);
  if (!release) throw new Error('Review failure smoke needs a scored release');
  if (!release.recommended) {
    release.recommended = true;
    const historyRow = scenario.history.find((row) => row.tag === release.tag);
    if (historyRow) historyRow.recommended = true;
    const publicRow = scenario.publicPayload.releases?.find((row) => row.tag === release.tag);
    if (publicRow) publicRow.recommended = true;
  }
  const rawReviewMarker = 'RAW_REVIEW_503_BODY_DO_NOT_RENDER';
  const validReview = smokeReviewForRelease(release);
  const page = await newSmokePage(browser, { viewport: { width: 900, height: 700 } });
  let reviewCalls = 0;
  let releaseCalls = 0;
  let failReview = true;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      return fulfillJson(route, scenario.releases);
    }
    if (path === '/api/releases/history') return fulfillJson(route, scenario.history);
    if (path === '/api/public') return fulfillJson(route, scenario.publicPayload);
    if (path === '/api/status') {
      return fulfillStatus(route, scenario.releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (path === `/api/releases/${encodeURIComponent(release.tag)}/review`) {
      reviewCalls += 1;
      return failReview
        ? fulfillJson(route, { error: rawReviewMarker }, 503)
        : fulfillJson(route, validReview);
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await releaseToggle(page, release.tag).click();
    await page.locator('#packageLoadState[data-release-state="hold"]').waitFor({
      state: 'visible',
    });
    if (reviewCalls !== 1) {
      throw new Error(`Review 503 smoke issued ${reviewCalls} review requests`);
    }
    const bodyText = await page.locator('body').innerText();
    if (bodyText.includes(rawReviewMarker) || /\b503\b/.test(bodyText)) {
      throw new Error(`Unsafe review error content reached the UI: ${bodyText}`);
    }
    await assertNoRecommendationOrInstallUi(page, 'Review 503');
    await assertAuthorizedRatingsRemainVisible(page, scenario.releases, 'Review 503');
    const retry = page.locator(
      `#review-${domIdForTag(release.tag)} [data-review-state="error"] [data-release-retry]`,
    );
    await retry.waitFor();
    await assertRetryTargetSizes(page, 'Review failure');
    failReview = false;
    await retry.click();
    await waitForCondition(() => releaseCalls === 2, 'review failure global retry');
    await page.locator('#packageLoadState[data-release-state="ready"]').waitFor({
      state: 'attached',
    });
    await page.locator('.release--recommended').waitFor();

    const panel = await openScoreBreakdown(page, release.tag);
    await panel.locator('.update-cmd__code').waitFor();
    await panel
      .locator('summary.evidence-toggle__summary')
      .filter({ hasText: /Assessment details for/ })
      .waitFor();
    if (reviewCalls !== 2) {
      throw new Error(`Review failure recovery issued ${reviewCalls} review requests instead of 2`);
    }
  } finally {
    await page.close();
  }
}

async function assertReviewSnapshotMismatchRecovery(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const scenario = {
    releases: structuredClone(releases),
    history: structuredClone(historyPayload),
    publicPayload: structuredClone(publicPayload),
  };
  const release = scenario.releases.find((row) => row.recommended && row.finalScore != null)
    ?? scenario.releases.find((row) => row.finalScore != null);
  if (!release) throw new Error('Review snapshot mismatch smoke needs a scored release');
  if (!release.recommended) {
    release.recommended = true;
    scenario.releases.forEach((row) => {
      if (row.tag !== release.tag) row.recommended = false;
    });
    scenario.history.forEach((row) => {
      row.recommended = row.tag === release.tag;
    });
    scenario.publicPayload.releases?.forEach((row) => {
      row.recommended = row.tag === release.tag;
    });
  }
  const validReview = smokeReviewForRelease(release);
  const mismatchMarker = 'MISMATCHED_REVIEW_BODY_MUST_NOT_RENDER';
  const mismatchedReview = structuredClone(validReview);
  mismatchedReview.snapshotId = 'b'.repeat(64);
  mismatchedReview.local.reason = mismatchMarker;

  const page = await newSmokePage(browser, { viewport: { width: 900, height: 700 } });
  let releaseCalls = 0;
  let reviewCalls = 0;
  let pendingRecoveryReleaseRoute = null;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      if (releaseCalls === 2) {
        pendingRecoveryReleaseRoute = route;
        return;
      }
      return fulfillJson(route, scenario.releases);
    }
    if (path === '/api/releases/history') return fulfillJson(route, scenario.history);
    if (path === '/api/public') return fulfillJson(route, scenario.publicPayload);
    if (path === '/api/status') return fulfillStatus(route, scenario.releases);
    if (path === `/api/releases/${encodeURIComponent(release.tag)}/review`) {
      reviewCalls += 1;
      return reviewCalls === 1
        ? fulfillJson(route, mismatchedReview, 200, release.snapshotId)
        : fulfillJson(route, validReview);
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await releaseToggle(page, release.tag).click();
    await waitForCondition(
      () => releaseCalls === 2 && pendingRecoveryReleaseRoute,
      'review snapshot mismatch rebase',
    );
    const bodyText = await page.locator('body').innerText();
    if (bodyText.includes(mismatchMarker)) {
      throw new Error('Mismatched review body rendered before snapshot identity was verified');
    }
    await assertNoRecommendationOrInstallUi(page, 'Review snapshot mismatch');
    await assertAuthorizedRatingsRemainVisible(
      page,
      scenario.releases,
      'Review snapshot mismatch',
    );

    await fulfillJson(pendingRecoveryReleaseRoute, scenario.releases);
    pendingRecoveryReleaseRoute = null;
    await page.locator('#packageLoadState[data-release-state="ready"]').waitFor({
      state: 'attached',
    });
    await page.locator('.release--recommended').waitFor();

    const panel = await openScoreBreakdown(page, release.tag);
    await panel.locator('.update-cmd__code').waitFor();
    await panel
      .locator('summary.evidence-toggle__summary')
      .filter({ hasText: /Assessment details for/ })
      .waitFor();
    if (reviewCalls !== 2) {
      throw new Error(`Review mismatch recovery issued ${reviewCalls} review requests instead of 2`);
    }
  } finally {
    if (pendingRecoveryReleaseRoute) {
      await pendingRecoveryReleaseRoute.abort().catch(() => undefined);
    }
    await page.close();
  }
}

function smokeReviewForRelease(release) {
  if (!release?.scoreAudit) {
    throw new Error(`Smoke review requires score audit identity for ${release?.tag ?? 'unknown'}`);
  }
  return {
    snapshotId: release.snapshotId,
    tag: release.tag,
    local: {
      schemaVersion: release.scoreAudit.reviewSchemaVersion,
      auditDigest: release.scoreAudit.auditDigest,
      sourceProvenance: {
        auditDigest: release.scoreAudit.auditDigest,
        scoreAuthority: {
          runId: release.scoreAudit.authorityRunId ?? null,
          contentHash: release.scoreAudit.authorityRunContentHash ?? null,
          historyV2SealContentHash:
            release.scoreAudit.historyV2SealContentHash ?? null,
        },
      },
      modelVersion: release.scoreAudit.modelVersion,
      promptVersion: release.scoreAudit.promptVersion,
      score: release.finalScore,
      status: release.status,
      recommended: release.recommended === true,
      reason: release.reason,
      scoredAt: release.scoredAt,
      dataFreshness: structuredClone(release.dataFreshness),
      staleAudit: null,
      input: {
        rawIssueCount: release.scoreAudit.rawIssueCount,
        classifiedIssueCount: release.scoreAudit.classifiedIssueCount,
        verifiedDebtWeight: 0,
        staleDebtWeight: 0,
        carryoverDebtWeight: 0,
        unresolvedClosureRiskWeight: 0,
        unresolvedClosureIssueCount: 0,
      },
      issueEvidence: {
        verifiedDebt: [],
        staleDebt: [],
        carryoverDebt: [],
        openedFeltSerious: [],
        verifiedFixed: [],
        unverifiedClosed: [],
      },
      gateEvidence: {},
      components: {
        schemaVersion: 1,
        evidenceCoverage: release.scoreAudit.evidenceCoverage,
        components: {},
        explanation: {
          schemaVersion: 4,
          title: 'Smoke recovery assessment',
          scoreLedger: release.explanation?.scoreLedger ?? null,
          positives: [],
          positiveDetails: [],
          limits: [],
          limitDetails: [],
          verdict: release.reason,
        },
      },
    },
  };
}

async function assertSnapshotRebaseBudget(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const first = snapshotVariant(releases, historyPayload, publicPayload, 1, 0.1);
  const second = snapshotVariant(releases, historyPayload, publicPayload, 2, 0.2);
  const third = snapshotVariant(releases, historyPayload, publicPayload, 3, 0.3);
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let releaseCalls = 0;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      const body = releaseCalls === 1
        ? first.releases
        : releaseCalls === 2
          ? second.releases
          : third.releases;
      return fulfillJson(route, body);
    }
    if (path === '/api/releases/history') {
      const body = releaseCalls === 1
        ? second.history
        : releaseCalls === 2
          ? second.history
          : third.history;
      return fulfillJson(route, body);
    }
    if (path === '/api/public') {
      const body = releaseCalls === 1
        ? second.publicPayload
        : releaseCalls === 2
          ? third.publicPayload
          : third.publicPayload;
      return fulfillJson(route, body);
    }
    if (path === '/api/status') {
      const statusReleases = releaseCalls <= 1
        ? first.releases
        : releaseCalls === 2
          ? second.releases
          : third.releases;
      return fulfillStatus(route, statusReleases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (/^\/api\/releases\/[^/]+\/review$/.test(path)) {
      return;
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    await waitForCondition(() => releaseCalls === 2, 'automatic snapshot rebase');
    const publicHold = page.locator('#packageLoadState[data-release-state="hold"]');
    await publicHold.waitFor({ state: 'visible' });
    await page.waitForFunction(() =>
      actionabilityHold?.cause === 'snapshot_mismatch'
        && releaseSnapshotAuthorityVerified());
    const renderedTags = await page
      .locator('#releases .release')
      .evaluateAll((rows) => rows.map((row) => row.dataset.tag));
    if (renderedTags.length !== second.releases.length) {
      throw new Error(
        `Snapshot rebase budget hid authoritative release rows: ` +
        `${JSON.stringify({ renderedTags, expected: second.releases.map((row) => row.tag) })}`,
      );
    }
    await assertNoRecommendationOrInstallUi(page, 'Snapshot rebase budget exhausted');
    await assertAuthorizedRatingsRemainVisible(
      page,
      second.releases,
      'Snapshot rebase budget exhausted',
    );
    await page.waitForTimeout(150);
    if (releaseCalls !== 2) {
      throw new Error(`Automatic snapshot rebase exceeded one request: ${releaseCalls} release loads`);
    }

    await exposeReleaseDetailsWithoutReview(page, second.targetTag);
    const publicRetry = page.locator(
      `#issues-${domIdForTag(second.targetTag)} [data-public-retry]`,
    );
    await publicRetry.waitFor({ state: 'visible' });
    await publicRetry.click();
    await waitForCondition(() => releaseCalls === 3, 'manual snapshot retry');
    const targetTag = third.targetTag;
    await page.waitForSelector('#releases .release');
    await page
      .locator(`#issues-${domIdForTag(targetTag)} [data-public-state="ready"], #issues-${domIdForTag(targetTag)} [data-public-state="empty"]`)
      .waitFor({ state: 'attached' });
    await page.waitForTimeout(150);
    if (releaseCalls !== 3) {
      throw new Error(`Manual snapshot retry did not start exactly one new load cycle: ${releaseCalls} loads`);
    }
  } finally {
    await page.close();
  }
}

async function assertFailedSnapshotRebaseDropsRows(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const first = snapshotVariant(releases, historyPayload, publicPayload, 11, 0.1);
  const second = snapshotVariant(releases, historyPayload, publicPayload, 12, 0.2);
  const rawFailureMarker = 'RAW_FAILED_REBASE_BODY_DO_NOT_RENDER';
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  let releaseCalls = 0;
  let publicCalls = 0;
  let pendingFirstHistoryRoute = null;
  let pendingReviewRoute = null;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      if (releaseCalls === 1) return fulfillJson(route, first.releases);
      if (releaseCalls === 2) {
        return route.fulfill({
          status: 503,
          contentType: 'text/plain',
          body: rawFailureMarker,
        });
      }
      return fulfillJson(route, second.releases);
    }
    if (path === '/api/releases/history') {
      if (releaseCalls === 1) {
        pendingFirstHistoryRoute = route;
        return;
      }
      return fulfillJson(route, releaseCalls >= 3 ? second.history : first.history);
    }
    if (path === '/api/public') {
      publicCalls += 1;
      return fulfillJson(
        route,
        releaseCalls >= 3 ? second.publicPayload : first.publicPayload,
      );
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releaseCalls >= 3 ? second.releases : first.releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (path === `/api/releases/${encodeURIComponent(first.targetTag)}/review`) {
      pendingReviewRoute = route;
      return;
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#releases .release');
    await waitForCondition(() => pendingFirstHistoryRoute, 'first failed-rebase history request');
    const row = page.locator(releaseSelector(first.targetTag));
    await row.locator('[data-release-toggle]').click();
    await page
      .locator(`#review-${domIdForTag(first.targetTag)} [data-review-state="loading"]`)
      .waitFor({ state: 'visible' });
    await waitForCondition(() => pendingReviewRoute, 'first failed-rebase review request');

    await fulfillJson(pendingFirstHistoryRoute, second.history);
    pendingFirstHistoryRoute = null;
    await waitForCondition(() => releaseCalls === 2, 'failed automatic snapshot rebase');

    const unavailable = page.locator('#packageLoadState[data-release-state="error"]');
    await unavailable.waitFor({ state: 'visible' });
    await unavailable.locator('[data-release-retry]').waitFor();
    if (await page.locator('#releases .release').count() !== 0) {
      throw new Error('Release 503 retained untrusted release rows');
    }
    const clientState = await page.evaluate(() => ({
      releaseCount: allReleases.length,
      publicCount: publicReleaseDetails.size,
      reviewCount: reviewByTag.size,
      reviewLoadCount: reviewLoadStateByTag.size,
    }));
    if (
      clientState.releaseCount !== 0
      || clientState.publicCount !== 0
      || clientState.reviewCount !== 0
      || clientState.reviewLoadCount !== 0
    ) {
      throw new Error(
        `Release 503 retained untrusted client state: ${JSON.stringify(clientState)}`,
      );
    }
    const bodyText = await page.locator('body').innerText();
    if (bodyText.includes(rawFailureMarker) || /\b503\b/.test(bodyText)) {
      throw new Error(`Unsafe failed-rebase content reached the UI: ${bodyText}`);
    }
    await assertNoActionableRetainedUi(page, 'Release 503 after snapshot rebase');

    await unavailable.locator('[data-release-retry]').click();
    await waitForCondition(() => releaseCalls === 3, 'failed-rebase manual retry');
    await page.locator('#packageLoadState[data-release-state="ready"]').waitFor({ state: 'attached' });
    await page
      .locator(`#issues-${domIdForTag(second.targetTag)} [data-public-state="ready"], #issues-${domIdForTag(second.targetTag)} [data-public-state="empty"]`)
      .waitFor({ state: 'attached' });
    if (publicCalls !== 2) {
      throw new Error(`Failed-rebase retry issued ${publicCalls} public requests instead of 2`);
    }
  } finally {
    await page.close();
  }
}

function snapshotVariant(releases, historyPayload, publicPayload, tick, scoreDelta) {
  const snapshotId = Number(tick).toString(16).padStart(64, '0');
  const releaseRows = structuredClone(releases);
  releaseRows.forEach((row) => { row.snapshotId = snapshotId; });
  const target = releaseRows.find((row) => row.scoredAt) ?? releaseRows[0];
  if (!target) throw new Error('Snapshot rebase smoke needs a release row');
  const baselineAt = target.scoredAt ?? target.staleAudit?.auditedAt ?? new Date().toISOString();
  if (target.finalScore == null) {
    target.finalScore = 7.5;
    target.band = 'ok';
    target.status = 'eligible';
    target.diagnosticStatus = null;
    target.recommended = false;
    target.reason = 'Synthetic current snapshot for UI smoke.';
    const syntheticAuditIdentity = String(tick).padStart(2, '0');
    target.scoreAudit = {
      schemaVersion: 2,
      reviewSchemaVersion: 1,
      auditDigest: syntheticAuditIdentity.repeat(32).slice(0, 64),
      authorityRunId: `ui-smoke-snapshot-authority:${snapshotId}`,
      authorityRunContentHash: createHash('sha256')
        .update(`ui-smoke-snapshot-authority-content:${snapshotId}`)
        .digest('hex'),
      historyV2SealContentHash: createHash('sha256')
        .update(`ui-smoke-snapshot-history-v2-seal:${snapshotId}`)
        .digest('hex'),
      modelVersion: 'ui-smoke',
      promptVersion: 1,
      evidenceCoverage: 1,
      rawIssueCount: 0,
      classifiedIssueCount: 0,
    };
    target.staleAudit = null;
    target.explanation = null;
  }
  if (target.finalScore != null && Number.isFinite(Number(target.finalScore))) {
    const baseScore = Number(target.finalScore);
    target.finalScore = Math.max(0, Math.min(10, baseScore + scoreDelta));
  }
  target.scoredAt = new Date(Date.parse(baselineAt) + tick * 1000).toISOString();
  releaseRows.forEach((row) => {
    row.auditLinks = fixtureAuditLinks(
      row.tag,
      snapshotId,
      row.scoreAudit?.auditDigest ?? null,
    );
  });

  const history = structuredClone(historyPayload);
  history.forEach((row) => {
    row.snapshotId = snapshotId;
    row.auditLinks = fixtureAuditLinks(
      row.tag,
      snapshotId,
      row.scoreAudit?.auditDigest ?? null,
    );
  });
  const historyRow = history.find((row) => row.tag === target.tag);
  if (historyRow) {
    historyRow.finalScore = target.finalScore;
    historyRow.band = target.band;
    historyRow.status = target.status;
    historyRow.diagnosticStatus = target.diagnosticStatus;
    historyRow.recommended = target.recommended;
    historyRow.scoredAt = target.scoredAt;
    historyRow.scoreAudit = target.scoreAudit;
    historyRow.staleAudit = target.staleAudit;
  }

  const publicCopy = structuredClone(publicPayload);
  publicCopy.snapshotId = snapshotId;
  publicCopy.snapshot = {
    ...(publicCopy.snapshot ?? {}),
    id: snapshotId,
    source: 'current',
    retained: false,
    stale: false,
    actionable: true,
    ageMs: 0,
    maxAgeMs: null,
  };
  publicCopy.releases?.forEach((row) => {
    row.snapshotId = snapshotId;
    row.auditLinks = fixtureAuditLinks(
      row.tag,
      snapshotId,
      row.scoreAudit?.auditDigest ?? null,
    );
  });
  const publicRow = publicCopy.releases?.find((row) => row.tag === target.tag);
  if (!publicRow) throw new Error(`Snapshot rebase smoke missing public row for ${target.tag}`);
  publicRow.score = target.finalScore;
  publicRow.band = target.band;
  publicRow.status = target.status;
  publicRow.diagnosticStatus = target.diagnosticStatus;
  publicRow.recommended = target.recommended;
  publicRow.reason = target.reason;
  publicRow.scoredAt = target.scoredAt;
  publicRow.scoreAudit = target.scoreAudit;
  publicRow.staleAudit = target.staleAudit;
  publicRow.explanation = target.explanation;
  return {
    releases: releaseRows,
    history,
    publicPayload: publicCopy,
    targetTag: target.tag,
  };
}

function coherentSnapshotVariant(releases, publicPayload) {
  const releaseRows = structuredClone(releases);
  const snapshotId = releaseRows[0]?.snapshotId
    ?? publicPayload?.snapshot?.id
    ?? '0'.repeat(64);
  releaseRows.forEach((row) => { row.snapshotId = snapshotId; });
  const publicByTag = new Map(
    structuredClone(publicPayload).releases?.map((row) => [row.tag, row]) ?? [],
  );
  const publicCopy = structuredClone(publicPayload);
  publicCopy.snapshotId = snapshotId;
  publicCopy.snapshot = {
    ...(publicCopy.snapshot ?? {}),
    id: snapshotId,
    source: 'current',
    retained: false,
    stale: false,
    actionable: true,
    ageMs: 0,
    maxAgeMs: null,
  };
  publicCopy.releases = releaseRows.map((release) => ({
    ...(publicByTag.get(release.tag) ?? {}),
    snapshotId,
    tag: release.tag,
    score: release.finalScore,
    band: release.band,
    status: release.status,
    diagnosticStatus: release.diagnosticStatus ?? null,
    recommended: release.recommended === true,
    reason: release.reason,
    scoredAt: release.scoredAt,
    scoreAudit: release.scoreAudit ?? null,
    staleAudit: release.staleAudit ?? null,
    dataFreshness: release.dataFreshness ?? null,
    explanation: release.explanation ?? null,
  }));
  return {
    releases: releaseRows,
    history: structuredClone(releaseRows),
    publicPayload: publicCopy,
  };
}

function staleSnapshotVariant(releases, historyPayload, publicPayload) {
  const snapshotId = releases[0]?.snapshotId
    ?? publicPayload?.snapshot?.id
    ?? '0'.repeat(64);
  const releaseRows = structuredClone(releases).map((release) => {
    const previousStatus = release.diagnosticStatus
      ?? release.staleAudit?.previousStatus
      ?? (release.status === 'stale' ? null : release.status)
      ?? null;
    const auditedAt = release.staleAudit?.auditedAt ?? release.scoredAt ?? null;
    const message =
      'Analysis is stale. The stored analysis must be recomputed before installing.';
    return {
      ...release,
      snapshotId,
      finalScore: null,
      band: 'wait',
      status: 'stale',
      diagnosticStatus: previousStatus,
      recommended: false,
      reason: message,
      brokenSurfaces: [],
      negativeIssues: null,
      positiveIssues: null,
      closedSeriousFixed: null,
      openedSeriousDuringReign: null,
      scoredAt: null,
      scoreAudit: null,
      explanation: null,
      staleAudit: {
        schemaVersion: 1,
        state: 'stale',
        message,
        previousStatus,
        auditedAt,
        causes: ['score_model_changed'],
      },
    };
  });
  const historyByTag = new Map(structuredClone(historyPayload).map((row) => [row.tag, row]));
  const history = releaseRows.map((release) => ({
    ...(historyByTag.get(release.tag) ?? {}),
    ...release,
    snapshotId,
  }));
  const publicByTag = new Map(
    structuredClone(publicPayload).releases?.map((row) => [row.tag, row]) ?? [],
  );
  const publicCopy = structuredClone(publicPayload);
  publicCopy.snapshotId = snapshotId;
  publicCopy.snapshot = {
    ...(publicCopy.snapshot ?? {}),
    id: snapshotId,
    source: 'current',
    retained: false,
    stale: false,
    actionable: true,
    ageMs: 0,
    maxAgeMs: null,
  };
  publicCopy.releases = releaseRows.map((release) => ({
    ...(publicByTag.get(release.tag) ?? {}),
    snapshotId,
    tag: release.tag,
    score: null,
    band: release.band,
    status: release.status,
    diagnosticStatus: release.diagnosticStatus,
    recommended: false,
    reason: release.reason,
    scoredAt: null,
    scoreAudit: null,
    staleAudit: release.staleAudit,
    dataFreshness: release.dataFreshness,
    explanation: null,
  }));
  return {
    releases: releaseRows,
    history,
    publicPayload: publicCopy,
  };
}

async function assertProgressiveFirstRender(browser, {
  releases,
  historyPayload,
  publicPayload,
}) {
  const historyTags = new Set(historyPayload.map((release) => release.tag));
  const rowRelease = releases.find((release) =>
    release.finalScore != null && historyTags.has(release.tag)
  );
  const chartRelease = releases.find((release) =>
    release.tag !== rowRelease?.tag && release.finalScore != null && historyTags.has(release.tag)
  );
  if (!rowRelease || !chartRelease) {
    throw new Error('Progressive UI smoke needs two scored releases present in history');
  }
  const rowReview = await json(`/api/releases/${encodeURIComponent(rowRelease.tag)}/review`);
  const chartReview = await json(`/api/releases/${encodeURIComponent(chartRelease.tag)}/review`);

  const page = await newSmokePage(browser, { viewport: { width: 1100, height: 850 } });
  const reviewCounts = new Map();
  let pendingHistoryRoute = null;
  let pendingPublicRoute = null;
  let pendingRowReviewRoute = null;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') {
      pendingHistoryRoute = route;
      return;
    }
    if (path === '/api/public') {
      pendingPublicRoute = route;
      return;
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releases, {
        lastError: null,
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    const match = path.match(/^\/api\/releases\/([^/]+)\/review$/);
    if (!match) return route.continue();
    const tag = decodeURIComponent(match[1]);
    reviewCounts.set(tag, (reviewCounts.get(tag) ?? 0) + 1);
    if (tag === rowRelease.tag) {
      pendingRowReviewRoute = route;
      return;
    }
    if (tag === chartRelease.tag) {
      return fulfillJson(route, chartReview);
    }
    return fulfillJson(route, { error: 'unexpected review request', tag }, 500);
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    await waitForCondition(() => pendingHistoryRoute && pendingPublicRoute, 'background history/public requests');
    await page.locator('#packageLoadState[data-release-state="hold"]').waitFor({
      state: 'visible',
    });
    if (await page.locator('#releases .release').count() !== releases.length) {
      throw new Error('Progressive render hid authoritative release rows before public verification');
    }
    await assertNoRecommendationOrInstallUi(page, 'Progressive public verification');
    await assertAuthorizedRatingsRemainVisible(
      page,
      releases,
      'Progressive public verification',
    );
    if ([...reviewCounts.values()].reduce((sum, count) => sum + count, 0) !== 0) {
      throw new Error('Initial render fanned out release review requests');
    }
    if (await page.locator('#scoreHistory').isVisible()) {
      throw new Error('History rendered before the delayed /api/releases/history response');
    }
    await page.evaluate(() => {
      window.__progressiveFirstRow = document.querySelector('#releases .release');
    });
    const row = page.locator(releaseSelector(rowRelease.tag));
    const toggle = row.locator('[data-release-toggle]');
    const panel = page.locator(`#det-${domIdForTag(rowRelease.tag)}`);
    const firstScoreBeforeAsyncCompletion = await row.locator('.score-num').innerText();

    await fulfillJson(pendingPublicRoute, publicPayload);
    pendingPublicRoute = null;
    await page
      .locator(`#issues-${domIdForTag(rowRelease.tag)} [data-public-state="ready"], #issues-${domIdForTag(rowRelease.tag)} [data-public-state="empty"]`)
      .waitFor({ state: 'attached' });
    await toggle.click();
    await panel.locator('[data-review-state="loading"]').waitFor();
    await toggle.click();
    await toggle.click();
    await waitForCondition(() => pendingRowReviewRoute, `${rowRelease.tag} review request`);
    if (reviewCounts.get(rowRelease.tag) !== 1) {
      throw new Error(`Expected one inflight review for ${rowRelease.tag}, got ${reviewCounts.get(rowRelease.tag)}`);
    }
    await fulfillJson(pendingRowReviewRoute, rowReview);
    pendingRowReviewRoute = null;
    await panel.locator('summary.evidence-toggle__summary', {
      hasText: /^(Assessment details for .+\/10|Show assessment details)$/,
    }).waitFor({ state: 'attached' });
    if (reviewCounts.get(rowRelease.tag) !== 1) {
      throw new Error(`Reopening ${rowRelease.tag} bypassed review request dedupe`);
    }

    await fulfillJson(pendingHistoryRoute, historyPayload);
    pendingHistoryRoute = null;
    await page.locator('#scoreHistory').waitFor({ state: 'visible' });
    await page.locator(`.score-history__dot${cssAttributeEquals('data-tag', chartRelease.tag)}`).click();
    const chartPanel = page.locator(`#det-${domIdForTag(chartRelease.tag)}`);
    await waitForCondition(
      () => reviewCounts.get(chartRelease.tag) === 1,
      `${chartRelease.tag} chart review request`,
    );
    await chartPanel.locator('summary.evidence-toggle__summary', {
      hasText: /^(Assessment details for .+\/10|Show assessment details)$/,
    }).waitFor({ state: 'attached' });
    if (reviewCounts.get(chartRelease.tag) !== 1) {
      throw new Error(`Chart open requested ${chartRelease.tag} review ${reviewCounts.get(chartRelease.tag)} times`);
    }

    const firstScoreAfterAsyncCompletion = await page
      .locator(`${releaseSelector(rowRelease.tag)} .score-num`)
      .innerText();
    if (firstScoreAfterAsyncCompletion !== firstScoreBeforeAsyncCompletion) {
      throw new Error(`Async enrichment replaced /api/releases score for ${rowRelease.tag}`);
    }
    const firstRowStayedStable = await page.evaluate(() =>
      window.__progressiveFirstRow === document.querySelector('#releases .release')
    );
    if (!firstRowStayedStable) {
      throw new Error('Async review/history/public completion rerendered the release list');
    }
  } finally {
    await page.close();
  }

  await assertStaleResponseIsolation(browser, {
    releases,
    historyPayload,
    publicPayload,
    release: rowRelease,
    review: rowReview,
  });
}

async function assertStaleResponseIsolation(browser, {
  releases,
  historyPayload,
  publicPayload,
  release,
  review,
}) {
  const page = await newSmokePage(browser, { viewport: { width: 1000, height: 800 } });
  const changedScore = Number(release.finalScore) >= 9.5
    ? Number(release.finalScore) - 0.5
    : Number(release.finalScore) + 0.5;
  const changedScoredAt = new Date(Date.parse(release.scoredAt) + 1000).toISOString();
  const changedReleases = structuredClone(releases);
  const changedRelease = changedReleases.find((row) => row.tag === release.tag);
  changedRelease.finalScore = changedScore;
  changedRelease.scoredAt = changedScoredAt;
  const changedHistory = structuredClone(historyPayload);
  const changedHistoryRow = changedHistory.find((row) => row.tag === release.tag);
  changedHistoryRow.finalScore = changedScore;
  changedHistoryRow.scoredAt = changedScoredAt;
  const stalePublic = publicPayloadWithMarker(publicPayload, release.tag, 'STALE PUBLIC MARKER');
  const changedPublic = publicPayloadWithMarker(publicPayload, release.tag, 'FRESH PUBLIC MARKER');
  const changedPublicRow = changedPublic.releases.find((row) => row.tag === release.tag);
  changedPublicRow.score = changedScore;
  changedPublicRow.scoredAt = changedScoredAt;

  let releaseCalls = 0;
  let historyCalls = 0;
  let publicCalls = 0;
  let pendingOldHistoryRoute = null;
  let pendingOldPublicRoute = null;
  let pendingOldReviewRoute = null;

  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') {
      releaseCalls += 1;
      return fulfillJson(route, releaseCalls === 1 ? releases : changedReleases);
    }
    if (path === '/api/releases/history') {
      historyCalls += 1;
      if (historyCalls === 2) {
        pendingOldHistoryRoute = route;
        return;
      }
      return fulfillJson(route, historyCalls === 1 ? historyPayload : changedHistory);
    }
    if (path === '/api/public') {
      publicCalls += 1;
      if (publicCalls === 2) {
        pendingOldPublicRoute = route;
        return;
      }
      return fulfillJson(route, publicCalls === 1 ? publicPayload : changedPublic);
    }
    if (path === '/api/status') {
      return fulfillStatus(route, releaseCalls >= 2 ? changedReleases : releases, {
        lastScoredAt: new Date().toISOString(),
        dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
      });
    }
    if (path === `/api/releases/${encodeURIComponent(release.tag)}/review`) {
      pendingOldReviewRoute = route;
      return;
    }
    return route.continue();
  });

  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'domcontentloaded' });
    await page.waitForSelector('#releases .release');
    const row = page.locator(releaseSelector(release.tag));
    await row.locator('[data-release-toggle]').click();
    await page.locator(`#review-${domIdForTag(release.tag)} [data-review-state="loading"]`).waitFor();
    await waitForCondition(() => pendingOldReviewRoute, 'first snapshot review request');
    await page.evaluate(() => {
      loadHistoryForSnapshot(releaseLoadEpoch, releaseSnapshot);
      loadPublicForSnapshot(releaseLoadEpoch, releaseSnapshot);
    });
    await waitForCondition(
      () => pendingOldHistoryRoute && pendingOldPublicRoute,
      'extra first snapshot background requests',
    );

    await page.evaluate(() => loadReleases());
    const expectedScore = Number(changedScore).toFixed(1);
    await page
      .locator(`${releaseSelector(release.tag)} .score-num`)
      .filter({ hasText: expectedScore })
      .waitFor();
    await page.waitForFunction(
      ({ id }) => document.getElementById(id)?.textContent?.includes('FRESH PUBLIC MARKER'),
      { id: `issues-${domIdForTag(release.tag)}` },
    );
    await page.evaluate((tag) => {
      window.__freshSnapshotRow = document.querySelector(`.release[data-tag="${CSS.escape(tag)}"]`);
    }, release.tag);

    await fulfillJson(pendingOldReviewRoute, review).catch(() => undefined);
    pendingOldReviewRoute = null;
    await fulfillJson(pendingOldHistoryRoute, historyPayload);
    pendingOldHistoryRoute = null;
    await fulfillJson(pendingOldPublicRoute, stalePublic);
    pendingOldPublicRoute = null;
    await page.waitForTimeout(50);

    const reviewSlot = page.locator(`#review-${domIdForTag(release.tag)}`);
    if (await reviewSlot.locator('.score-review').count()) {
      throw new Error('Stale review response populated the current release snapshot');
    }
    await reviewSlot.locator('[data-review-state="idle"]').waitFor({ state: 'attached' });
    const issueText = await page.locator(`#issues-${domIdForTag(release.tag)}`).textContent();
    if (!issueText.includes('FRESH PUBLIC MARKER') || issueText.includes('STALE PUBLIC MARKER')) {
      throw new Error('Stale /api/public response replaced current enrichment');
    }
    const currentScore = await page.locator(`${releaseSelector(release.tag)} .score-num`).innerText();
    if (currentScore !== expectedScore) {
      throw new Error(`Stale response changed current /api/releases score ${expectedScore} to ${currentScore}`);
    }
    const freshRowStayedStable = await page.evaluate((tag) =>
      window.__freshSnapshotRow === document.querySelector(`.release[data-tag="${CSS.escape(tag)}"]`)
    , release.tag);
    if (!freshRowStayedStable) {
      throw new Error('Stale response rerendered the current release list');
    }
  } finally {
    await page.close();
  }
}

function publicPayloadWithMarker(payload, tag, title) {
  const copy = structuredClone(payload);
  const row = copy.releases?.find((release) => release.tag === tag);
  if (!row) throw new Error(`Missing public row for ${tag}`);
  row.watchIssues = [{
    number: title === 'STALE PUBLIC MARKER' ? 990001 : 990002,
    title,
    url: `https://github.com/openclaw/openclaw/issues/${title === 'STALE PUBLIC MARKER' ? 990001 : 990002}`,
    state: 'open',
    severity: 'low',
    affectedUsers: 'few',
    surface: { label: 'Core', icon: 'core' },
  }];
  row.issues = [];
  return copy;
}

async function fulfillJson(route, body, status = 200, explicitSnapshotId = null) {
  const path = new URL(route.request().url()).pathname;
  const payload = body;
  if (path === '/api/status') {
    const snapshotId = payload?.snapshotId;
    if (
      !isFixtureSnapshotId(snapshotId)
      || payload?.publicationSnapshotId !== snapshotId
      || payload?.currentScoreAuthorizationSnapshotId !== snapshotId
    ) {
      throw new Error('Status fixture is not bound to one explicit publication snapshot');
    }
  }
  const snapshotId = explicitSnapshotId ?? snapshotIdForPayload(payload);
  await route.fulfill({
    status,
    contentType: 'application/json',
    headers: snapshotId ? { 'X-Radar-Snapshot-Id': snapshotId } : undefined,
    body: JSON.stringify(payload),
  });
}

async function fulfillStatus(route, snapshotSource, overrides = {}) {
  const payload = statusForSnapshot(snapshotSource, overrides);
  return fulfillJson(route, payload, 200, payload.snapshotId);
}

function statusForSnapshot(snapshotSource, overrides = {}) {
  const snapshotId = typeof snapshotSource === 'string'
    ? snapshotSource
    : snapshotIdForPayload(snapshotSource);
  if (!isFixtureSnapshotId(snapshotId)) {
    throw new Error(`Status fixture needs an explicit snapshot identity: ${snapshotId}`);
  }
  return {
    snapshotId,
    publicationSnapshotId: snapshotId,
    currentScoreAuthorizationSnapshotId: snapshotId,
    refreshing: false,
    activeRunId: null,
    lastError: null,
    currentScoreAuthorizationStatus: 'authorized',
    lastScoredAt: new Date().toISOString(),
    dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
    ...overrides,
  };
}

function isFixtureSnapshotId(value) {
  return /^[0-9a-f]{64}$/.test(String(value ?? ''));
}

function snapshotIdForPayload(payload) {
  if (Array.isArray(payload)) return payload[0]?.snapshotId ?? null;
  return payload?.snapshot?.id ?? payload?.snapshotId ?? null;
}

function releaseTagSetsMatch(authoritativeRows, candidateRows) {
  if (
    !Array.isArray(authoritativeRows)
    || !Array.isArray(candidateRows)
    || authoritativeRows.length !== candidateRows.length
  ) {
    return false;
  }
  const authoritativeTags = new Set();
  const candidateTags = new Set();
  for (const row of authoritativeRows) {
    const tag = row?.tag;
    if (typeof tag !== 'string' || !tag || authoritativeTags.has(tag)) return false;
    authoritativeTags.add(tag);
  }
  for (const row of candidateRows) {
    const tag = row?.tag;
    if (typeof tag !== 'string' || !tag || candidateTags.has(tag)) return false;
    candidateTags.add(tag);
  }
  return authoritativeTags.size === candidateTags.size
    && [...authoritativeTags].every((tag) => candidateTags.has(tag));
}

function assertSharedSnapshotIdentity(releases, history, publicPayload) {
  const snapshotId = releases[0]?.snapshotId ?? publicPayload?.snapshot?.id;
  if (!/^[0-9a-f]{64}$/.test(String(snapshotId ?? ''))) {
    throw new Error(`Release endpoints did not expose an explicit snapshot identity: ${snapshotId}`);
  }
  if (
    publicPayload?.snapshotId !== snapshotId
    || publicPayload?.snapshot?.id !== snapshotId
    || publicPayload?.snapshot?.stale !== false
    || publicPayload?.snapshot?.actionable !== true
    || releases.some((row) => row.snapshotId !== snapshotId)
    || history.some((row) => row.snapshotId !== snapshotId)
    || (publicPayload?.releases ?? []).some((row) => row.snapshotId !== snapshotId)
    || !releaseTagSetsMatch(releases, publicPayload?.releases)
  ) {
    throw new Error(
      'Release, history, and public payloads do not share one complete actionable snapshot identity',
    );
  }
}

async function assertNoActionableRetainedUi(page, label) {
  const forbiddenSelectors = [
    '.update-cmd__copy',
    '.update-cmd__code',
    '.rec-pill',
    '.release--recommended',
    '.score-review',
    '.score-ledger',
    '.score-review__components',
    '.pkg-card__alt',
  ];
  for (const selector of forbiddenSelectors) {
    if (await page.locator(selector).count()) {
      throw new Error(`${label} retained actionable UI at ${selector}`);
    }
  }
  const bodyText = await page.locator('body').innerText();
  if (/openclaw update --tag/i.test(bodyText)) {
    throw new Error(`${label} retained an update command`);
  }
  const scores = await page.locator('#releases .score-num').allInnerTexts();
  if (scores.some((score) => score.trim() !== '—')) {
    throw new Error(`${label} retained numeric scores: ${scores.join(', ')}`);
  }
  const state = await page.evaluate(() => ({
    releases: allReleases.map((release) => ({
      finalScore: release.finalScore,
      recommended: release.recommended,
      stale: isStaleAnalysis(release),
    })),
    reviewCount: reviewByTag.size,
  }));
  if (
    state.reviewCount !== 0 ||
    state.releases.some((release) =>
      release.finalScore != null || release.recommended || !release.stale)
  ) {
    throw new Error(`${label} retained actionable client state: ${JSON.stringify(state)}`);
  }
}

async function assertNoRecommendationOrInstallUi(page, label) {
  const forbiddenSelectors = [
    '.update-cmd__copy',
    '.update-cmd__code',
    '.rec-pill',
    '.release--recommended',
    '.score-review',
    '.pkg-card__alt',
  ];
  for (const selector of forbiddenSelectors) {
    if (await page.locator(selector).count()) {
      throw new Error(`${label} exposed actionability at ${selector}`);
    }
  }
  const bodyText = await page.locator('body').innerText();
  if (/openclaw update --tag/i.test(bodyText)) {
    throw new Error(`${label} exposed an install command`);
  }
}

async function assertAuthorizedRatingsRemainVisible(page, expectedReleases, label) {
  if (!Array.isArray(expectedReleases) || !expectedReleases.length) {
    throw new Error(`${label} has no authoritative releases to compare`);
  }
  const rows = page.locator('#releases .release');
  await rows.first().waitFor();
  const rendered = await rows.evaluateAll((elements) => elements.map((element) => ({
    tag: element.dataset.tag ?? '',
    score: element.querySelector('.score-num')?.textContent?.trim() ?? '',
  })));
  const expected = expectedReleases.map((release) => ({
    tag: release.tag,
    score: renderedScore(release.finalScore),
  }));
  if (JSON.stringify(rendered) !== JSON.stringify(expected)) {
    throw new Error(
      `${label} did not preserve exact authorized ratings: ` +
      `${JSON.stringify({ rendered, expected })}`,
    );
  }
  if (!expected.some((release) => release.score !== '—')) {
    throw new Error(`${label} fixture has no authorized numeric rating`);
  }
  await assertAuthorizedPackageRatingRemainsVisible(
    page,
    expectedReleases[0],
    label,
  );
}

async function assertAuthorizedPackageRatingRemainsVisible(
  page,
  expectedRelease,
  label,
) {
  if (!expectedRelease) throw new Error(`${label} has no package release to compare`);
  const packageScore = (await page
    .locator('#packageCards .pkg-card__score-big')
    .first()
    .textContent() ?? '').replace(/\s+/g, '');
  const expected = `${renderedScore(expectedRelease.finalScore)}/10`;
  if (packageScore !== expected) {
    throw new Error(
      `${label} did not preserve the exact package rating: ` +
      `${JSON.stringify({ packageScore, expected })}`,
    );
  }
}

function renderedScore(value) {
  return typeof value === 'number' && Number.isFinite(value)
    ? value.toFixed(1)
    : '—';
}

async function waitForCondition(check, label, timeoutMs = 5000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  throw new Error(`Timed out waiting for ${label}`);
}

function expectedRecommendationDecisionCopy(release) {
  const decision = release?.explanation?.recommendationDecision;
  if (!decision) throw new Error(`Missing recommendation decision for ${release?.tag ?? 'unknown release'}`);
  const selectedTag = decision.selectedTag || 'the recommended release';
  const score = Number.isFinite(Number(decision.releaseScore)) ? Number(decision.releaseScore).toFixed(1) : null;
  const threshold = Number.isFinite(Number(decision.threshold)) ? Number(decision.threshold).toFixed(1) : 'required';
  const tolerance = Number.isFinite(Number(decision.recencyTolerance))
    ? Number(decision.recencyTolerance).toFixed(1)
    : 'the allowed margin';
  switch (decision.decisionCode) {
    case 'highest_confidence':
      return 'Recommended at the highest audited score; the newest release wins when scores are equal.';
    case 'newest_within_confidence_tolerance':
      return `Recommended as the newest qualifying release within ${tolerance} points of the highest audited score.`;
    case 'higher_confidence_release_selected':
      return `Not selected: ${selectedTag} has a higher audited policy/stability assessment.`;
    case 'newer_release_within_tolerance_selected':
      return `Not selected: ${selectedTag} is newer and remains within ${tolerance} points of this score.`;
    case 'below_recommendation_threshold':
      return `Not selected: ${score ? `score ${score} is` : 'the score is'} below the ${threshold} recommendation threshold.`;
    case 'install_gate_active':
      return release.status === 'skip-cve'
        ? 'Not selected: a medium-or-higher security advisory blocks this version.'
        : 'Not selected: an install gate is active.';
    default:
      return decision.selected
        ? 'Recommended under the current audited release policy.'
        : 'Not selected under the current audited release policy.';
  }
}

function humanWeightValue(value) {
  const number = Number(value);
  if (!Number.isFinite(number)) return '—';
  if (Math.abs(number) >= 100) return String(Math.round(number));
  return String(Math.round(number * 100) / 100);
}

async function runFixtureOnlySmoke() {
  const fixtures = createFixtureSnapshot();
  assertSharedSnapshotIdentity(
    fixtures.releases,
    fixtures.historyPayload,
    fixtures.publicPayload,
  );
  assertFixtureScoreArithmetic(fixtures);
  fixtureResponses = new Map([
    ['/api/releases', fixtures.releases],
    ['/api/releases/history', fixtures.historyPayload],
    ['/api/public', fixtures.publicPayload],
    ...Object.entries(fixtures.reviewsByTag).map(([tag, review]) => [
      `/api/releases/${encodeURIComponent(tag)}/review`,
      review,
    ]),
  ]);
  const browser = await chromium.launch({ headless: true });
  try {
    await assertHardRefreshUx(browser, fixtures);
    await assertProgressiveFirstRender(browser, fixtures);
    await assertFixtureStaticUx(browser, fixtures);
    console.log('Fixture-only UI smoke passed');
  } finally {
    fixtureResponses = null;
    await browser.close();
  }
}

function fixtureProfileEvidence({
  tag,
  scoreAudit,
  sourceIdentityDigest,
  issueEvidenceSchemaVersion = 2,
  profileRowCount,
  issueCount,
  weightedIssueCount,
  surfaceIssueCount,
  surfaceWeight,
  surfaces,
}) {
  const profileRowsDigest = createHash('sha256')
    .update('ui-smoke-profile-evidence-v1\0')
    .update(canonicalJson({
      tag,
      issueEvidenceSchemaVersion,
      profileRowCount,
      surfaces,
    }))
    .digest('hex');
  let publicationBinding = null;
  let sourceMode = 'current_diagnostic_evidence';
  if (scoreAudit) {
    if (
      typeof scoreAudit.auditDigest !== 'string' ||
      typeof scoreAudit.authorityRunId !== 'string' ||
      typeof scoreAudit.authorityRunContentHash !== 'string' ||
      typeof scoreAudit.historyV2SealContentHash !== 'string' ||
      typeof scoreAudit.modelVersion !== 'string' ||
      !Number.isInteger(scoreAudit.promptVersion) ||
      !/^[0-9a-f]{64}$/.test(sourceIdentityDigest ?? '')
    ) {
      throw new Error(`UI smoke profile evidence for ${tag} lacks sealed score identity`);
    }
    const content = {
      schemaVersion: 1,
      auditDigest: scoreAudit.auditDigest,
      authorityRunId: scoreAudit.authorityRunId,
      authorityRunContentHash: scoreAudit.authorityRunContentHash,
      historyV2SealContentHash: scoreAudit.historyV2SealContentHash,
      sourceIdentityDigest,
      scoreModelVersion: scoreAudit.modelVersion,
      promptVersion: scoreAudit.promptVersion,
      profileRowsDigest,
    };
    publicationBinding = {
      ...content,
      contentHash: createHash('sha256')
        .update('release-profile-evidence-binding-v1\0')
        .update(canonicalJson(content))
        .digest('hex'),
    };
    sourceMode = 'sealed_score_replay';
  }
  return {
    schemaVersion: 2,
    sourceMode,
    issueEvidenceSchemaVersion,
    profileRowCount,
    profileRowsDigest,
    publicationBinding,
    issueCount,
    weightedIssueCount,
    surfaceIssueCount,
    surfaceWeight,
    surfaces,
  };
}

function createFixtureSnapshot() {
  const snapshotId = 'a'.repeat(64);
  const scoredAt = new Date().toISOString();
  const published = [
    '2026-07-03T12:00:00.000Z',
    '2026-07-02T12:00:00.000Z',
    '2026-07-01T12:00:00.000Z',
  ];
  const definitions = [
    {
      tag: 'v2026.7.3',
      score: 8.2,
      status: 'eligible',
      recommended: true,
      surface: 'Discord',
      fixCredit: 1,
    },
    {
      tag: 'v2026.7.2',
      score: 7.7,
      status: 'eligible',
      recommended: false,
      surface: 'macOS',
      fixCredit: 0,
    },
    {
      tag: 'v2099.7.1',
      score: 6.5,
      status: 'skip-cve',
      recommended: false,
      surface: 'Linux',
      fixCredit: 0,
    },
  ];
  const releases = definitions.map((definition, index) => {
    const auditDigest = String(index + 1).repeat(64);
    const authorityRunId = `ui-smoke-authority:${definition.tag}`;
    const authorityRunContentHash = createHash('sha256')
      .update(`ui-smoke-authority-content:${definition.tag}`)
      .digest('hex');
    const historyV2SealContentHash = createHash('sha256')
      .update(`ui-smoke-history-v2-seal:${definition.tag}`)
      .digest('hex');
    const dataFreshness = {
      issueUpdatedAtMax: '2026-07-04T11:30:00.000Z',
      scoredAt,
      labelCutoffAt: scoredAt,
      issueUpdatedAgeHoursAtScore: 0.5,
    };
    const scoreLedger = fixtureScoreLedger(definition.score, {
      advisoryGated: definition.status === 'skip-cve',
    });
    const advisory = definition.status === 'skip-cve'
      ? {
          ghsaId: 'GHSA-fixture-gate',
          cveId: null,
          severity: 'high',
          summary: 'Fixture advisory blocks this release.',
          url: 'https://github.com/advisories/GHSA-fixture-gate',
          patchedVersion: '2026.7.2',
        }
      : null;
    return {
      schemaVersion: 2,
      snapshotId,
      tag: definition.tag,
      name: definition.tag,
      publishedAt: published[index],
      finalScore: definition.score,
      band: definition.status === 'skip-cve'
        ? 'skip'
        : definition.score >= 8 ? 'solid' : 'ok',
      status: definition.status,
      diagnosticStatus: null,
      recommended: definition.recommended,
      reason: definition.status === 'skip-cve'
        ? 'A medium-or-higher security advisory blocks this version.'
        : definition.recommended
          ? 'Recommended at the highest audited assessment.'
          : 'Eligible, but another release has a stronger audited assessment.',
      scoredAt,
      scoreAudit: {
        schemaVersion: 2,
        reviewSchemaVersion: 1,
        auditDigest,
        authorityRunId,
        authorityRunContentHash,
        historyV2SealContentHash,
        modelVersion: 'ui-smoke-fixture',
        promptVersion: 1,
        evidenceCoverage: 1,
        rawIssueCount: 2,
        classifiedIssueCount: 2,
      },
      auditLinks: fixtureAuditLinks(definition.tag, snapshotId, auditDigest),
      staleAudit: null,
      dataFreshness,
      explanation: {
        schemaVersion: 4,
        scoreLedger,
      },
      advisories: {
        affected: advisory
          ? { total: 1, bySeverity: { high: 1 }, items: [advisory] }
          : { total: 0, bySeverity: {}, items: [] },
        patched: { total: 0, bySeverity: {}, items: [] },
      },
      brokenSurfaces: [{ label: definition.surface, icon: definition.surface.toLowerCase(), count: 1 }],
      negativeIssues: 1,
      positiveIssues: 1,
      closedSeriousFixed: 1,
      openedSeriousDuringReign: 1,
    };
  });
  const historyPayload = structuredClone(releases);
  const publicPayload = {
    schemaVersion: 4,
    snapshotId,
    snapshot: {
      id: snapshotId,
      source: 'current',
      retained: false,
      stale: false,
      actionable: true,
      ageMs: 0,
      maxAgeMs: null,
    },
    repo: 'openclaw/openclaw',
    updatedAt: scoredAt,
    releases: releases.map((release, index) => ({
      schemaVersion: 4,
      snapshotId,
      tag: release.tag,
      score: release.finalScore,
      band: release.band,
      status: release.status,
      diagnosticStatus: null,
      recommended: release.recommended,
      reason: release.reason,
      scoredAt,
      scoreAudit: structuredClone(release.scoreAudit),
      auditLinks: structuredClone(release.auditLinks),
      staleAudit: null,
      dataFreshness: structuredClone(release.dataFreshness),
      explanation: structuredClone(release.explanation),
      profileEvidence: fixtureProfileEvidence({
        tag: release.tag,
        scoreAudit: release.scoreAudit,
        sourceIdentityDigest: createHash('sha256')
          .update(`ui-smoke-source-identity:${release.tag}`)
          .digest('hex'),
        issueEvidenceSchemaVersion: 2,
        profileRowCount: 1,
        issueCount: 1,
        weightedIssueCount: 1,
        surfaceIssueCount: 1,
        surfaceWeight: 1,
        surfaces: [{
          label: definitions[index].surface,
          icon: definitions[index].surface.toLowerCase(),
          count: 1,
          weight: 1,
          tiers: { staleDebt: 1 },
          weightByTier: { staleDebt: 1 },
        }],
      }),
      issues: [{
        number: 88000 + index,
        title: `Fixture source-only report for ${release.tag}`,
        url: `https://github.com/openclaw/openclaw/issues/${88000 + index}`,
        state: 'open',
        sentiment: 'negative',
        severity: 'medium',
        functionality: 'integration',
        scope: 'moderate',
        affectedUsers: 'some',
        hasWorkaround: false,
        surface: {
          label: definitions[index].surface,
          icon: definitions[index].surface.toLowerCase(),
        },
      }],
      watchIssues: [],
    })),
  };
  const reviewsByTag = Object.fromEntries(releases.map((release, index) => [
    release.tag,
    fixtureReview(release, index),
  ]));
  return { releases, historyPayload, publicPayload, reviewsByTag };
}

function fixtureAuditLinks(tag, snapshotId, auditDigest = null) {
  if (!isFixtureSnapshotId(snapshotId)) {
    throw new Error(`Fixture audit links need an explicit snapshot identity: ${snapshotId}`);
  }
  const binding = new URLSearchParams({
    publicationSnapshot: snapshotId,
    auditDigest: auditDigest ?? 'unavailable',
  }).toString();
  const root = `/api/releases/${encodeURIComponent(tag)}/review`;
  return {
    review: `${root}?${binding}`,
    issues: `${root}/issues?${binding}`,
    closureProofs: `${root}/closure-proofs?${binding}`,
    reachability: `${root}/reachability?${binding}`,
  };
}

function fixtureScoreLedger(finalScore, { advisoryGated = false } = {}) {
  const gatePenalty = advisoryGated ? -1.5 : 0;
  const rows = [
    {
      key: 'base',
      label: 'Base assessment',
      kind: 'bonus',
      metric: null,
      points: roundFixtureScore(finalScore + 0.3 - gatePenalty),
    },
    { key: 'staleDebt', label: 'Weak or stale evidence', kind: 'penalty', metric: 1, points: -0.3 },
    ...(advisoryGated
      ? [{
          key: 'cveGate',
          label: 'CVE install gate',
          kind: 'penalty',
          metric: 1,
          points: gatePenalty,
        }]
      : []),
    { key: 'carryoverDebt', label: 'Inherited issue context', kind: 'neutral', metric: 1, points: 0 },
  ];
  const subtotalBeforeCaps = roundFixtureScore(
    rows.reduce((sum, row) => sum + row.points, 0),
  );
  return {
    schemaVersion: 2,
    rows,
    caps: [],
    subtotalBeforeCaps,
    scoreAfterCaps: subtotalBeforeCaps,
    finalScore: subtotalBeforeCaps,
  };
}

function fixtureScoreComponents(ledger) {
  const components = {};
  for (const row of ledger.rows) {
    if (Object.hasOwn(components, row.key)) {
      throw new Error(`Fixture score ledger contains duplicate row ${row.key}`);
    }
    components[row.key] = row.points;
  }
  return components;
}

function roundFixtureScore(value) {
  return Math.round(Number(value) * 1000) / 1000;
}

function assertFixtureScoreNumber(actual, expected, label) {
  if (
    typeof actual !== 'number'
    || typeof expected !== 'number'
    || !Number.isFinite(actual)
    || !Number.isFinite(expected)
    || Math.abs(actual - expected) > 1e-9
  ) {
    throw new Error(`${label}: expected ${expected}, got ${actual}`);
  }
}

function assertFixtureLedgerArithmetic(ledger, expectedFinalScore, label) {
  if (!ledger || !Array.isArray(ledger.rows) || !Array.isArray(ledger.caps)) {
    throw new Error(`${label} is missing score ledger rows or caps`);
  }
  const rowKeys = new Set();
  for (const row of ledger.rows) {
    if (!row?.key || rowKeys.has(row.key) || !Number.isFinite(Number(row.points))) {
      throw new Error(`${label} has an invalid or duplicate row ${String(row?.key)}`);
    }
    rowKeys.add(row.key);
  }
  const subtotal = roundFixtureScore(
    ledger.rows.reduce((sum, row) => sum + Number(row.points), 0),
  );
  assertFixtureScoreNumber(
    ledger.subtotalBeforeCaps,
    subtotal,
    `${label} subtotalBeforeCaps`,
  );

  let scoreAfterCaps = subtotal;
  for (const cap of ledger.caps) {
    assertFixtureScoreNumber(cap.before, scoreAfterCaps, `${label} ${cap.key} before`);
    const expectedAfter = roundFixtureScore(
      cap.applied ? Math.min(scoreAfterCaps, Number(cap.ceiling)) : scoreAfterCaps,
    );
    assertFixtureScoreNumber(cap.after, expectedAfter, `${label} ${cap.key} after`);
    scoreAfterCaps = expectedAfter;
  }
  assertFixtureScoreNumber(ledger.scoreAfterCaps, scoreAfterCaps, `${label} scoreAfterCaps`);
  assertFixtureScoreNumber(ledger.finalScore, scoreAfterCaps, `${label} finalScore`);
  assertFixtureScoreNumber(ledger.finalScore, expectedFinalScore, `${label} expected finalScore`);
  return new Map(ledger.rows.map((row) => [row.key, Number(row.points)]));
}

function assertFixtureScoreArithmetic({ releases, reviewsByTag }) {
  for (const release of releases) {
    const review = reviewsByTag[release.tag];
    const releaseLedger = release.explanation?.scoreLedger;
    const reviewLedger = review?.local?.components?.explanation?.scoreLedger;
    const releaseRows = assertFixtureLedgerArithmetic(
      releaseLedger,
      release.finalScore,
      `${release.tag} release ledger`,
    );
    const reviewRows = assertFixtureLedgerArithmetic(
      reviewLedger,
      review?.local?.score,
      `${release.tag} review ledger`,
    );
    assertFixtureScoreNumber(
      review?.local?.score,
      release.finalScore,
      `${release.tag} review/release score`,
    );
    if (JSON.stringify(reviewLedger) !== JSON.stringify(releaseLedger)) {
      throw new Error(`${release.tag} review ledger does not match the release ledger`);
    }
    const components = review?.local?.components?.components;
    if (!components || typeof components !== 'object') {
      throw new Error(`${release.tag} review is missing score components`);
    }
    if (
      Object.keys(components).length !== reviewRows.size
      || [...reviewRows].some(([key, points]) => !Object.hasOwn(components, key)
        || typeof components[key] !== 'number'
        || Math.abs(components[key] - points) > 1e-9)
      || [...releaseRows].some(([key, points]) => !Object.hasOwn(components, key)
        || typeof components[key] !== 'number'
        || Math.abs(components[key] - points) > 1e-9)
    ) {
      throw new Error(`${release.tag} score components do not reconcile with the ledger rows`);
    }
  }
}

function fixtureReview(release, index) {
  const sourceOnlyIssue = {
    number: 88000 + index,
    title: `Fixture source-only report for ${release.tag}`,
    url: `https://github.com/openclaw/openclaw/issues/${88000 + index}`,
    state: 'open',
  };
  const inheritedIssue = {
    number: 88100 + index,
    title: `Fixture inherited context for ${release.tag}`,
    url: `https://github.com/openclaw/openclaw/issues/${88100 + index}`,
    state: 'open',
  };
  const countedFixes = index === 0 ? 1 : 0;
  const scoreLedger = structuredClone(release.explanation.scoreLedger);
  const fixProvenance = countedFixes > 0
    ? {
        releaseFixCredit: {
          countedClosedCount: countedFixes,
          notCountedClosedCount: 0,
          analyzedClosedCount: countedFixes,
        },
        closureProof: {
          creditedCount: countedFixes,
          notCreditedCount: 0,
          byStatus: { fixed_in_release: countedFixes },
          riskSummary: {
            unresolvedForReleaseCount: 0,
            unresolvedRiskWeight: 0,
          },
          examples: [],
          examplesByStatus: {},
        },
      }
    : null;
  return {
    snapshotId: release.snapshotId,
    tag: release.tag,
    local: {
      schemaVersion: 1,
      auditDigest: release.scoreAudit.auditDigest,
      sourceProvenance: {
        auditDigest: release.scoreAudit.auditDigest,
        scoreAuthority: {
          runId: release.scoreAudit.authorityRunId ?? null,
          contentHash: release.scoreAudit.authorityRunContentHash ?? null,
          historyV2SealContentHash:
            release.scoreAudit.historyV2SealContentHash ?? null,
        },
      },
      modelVersion: release.scoreAudit.modelVersion,
      promptVersion: release.scoreAudit.promptVersion,
      score: release.finalScore,
      status: release.status,
      recommended: release.recommended,
      reason: release.reason,
      scoredAt: release.scoredAt,
      dataFreshness: structuredClone(release.dataFreshness),
      staleAudit: null,
      input: {
        rawIssueCount: 2,
        classifiedIssueCount: 2,
        verifiedDebtWeight: 0,
        staleDebtWeight: 1,
        carryoverDebtWeight: 1,
        unresolvedClosureRiskWeight: 0,
        unresolvedClosureIssueCount: 0,
      },
      issueEvidence: {
        verifiedDebt: [],
        staleDebt: [{
          tier: 'stale',
          weight: 1,
          fieldConfirmed: false,
          humanReporterCount: 1,
          humanCommenterCount: 1,
          issue: { ...sourceOnlyIssue, labels: ['clawsweeper:source-repro'] },
        }],
        carryoverDebt: [{
          tier: 'carryover',
          weight: 1,
          fieldConfirmed: false,
          clusterReleaseLocal: false,
          issue: { ...inheritedIssue, labels: ['clawsweeper:source-repro'] },
        }],
        openedFeltSerious: [],
        verifiedFixed: [],
        unverifiedClosed: [],
      },
      gateEvidence: {
        ...(fixProvenance ? { fixProvenance } : {}),
      },
      components: {
        schemaVersion: 1,
        evidenceCoverage: 1,
        components: fixtureScoreComponents(scoreLedger),
        explanation: {
          schemaVersion: 4,
          title: 'Fixture assessment',
          scoreLedger,
          positives: ['Release checks and package evidence are current.'],
          positiveDetails: [{
            code: 'fixture_positive',
            label: 'Current release evidence',
            text: 'Release checks and package evidence are current.',
          }],
          limits: [
            'Source-only evidence remains weak until installed-release impact is confirmed.',
            'Inherited source-only context remains visible for audit with zero assessment impact.',
          ],
          limitDetails: [
            {
              code: 'weak_source_evidence',
              label: 'Weak/stale evidence',
              text: 'Source-only evidence remains weak until installed-release impact is confirmed.',
              metrics: { scoreAffecting: true, scoredPenalty: 0.3 },
              issueRefs: [sourceOnlyIssue],
            },
            {
              code: 'open_unconfirmed_issue_risk',
              label: 'Inherited issue context',
              text: 'Inherited source-only context remains visible for audit with zero assessment impact.',
              metrics: { scoreAffecting: false, scoredPenalty: 0 },
              issueRefs: [inheritedIssue],
            },
          ],
          verdict: release.reason,
        },
      },
    },
  };
}

async function assertFixtureStaticUx(browser, {
  releases,
  historyPayload,
  publicPayload,
  reviewsByTag,
}) {
  const recommended = releases.find((release) => release.recommended);
  const eligibleNonRecommended = releases.find((release) =>
    release.status === 'eligible' && !release.recommended);
  const advisoryGated = releases.find((release) => release.status === 'skip-cve');
  const fixCreditRelease = releases.find((release) =>
    reviewsByTag[release.tag]?.local?.gateEvidence?.fixProvenance
      ?.releaseFixCredit?.countedClosedCount > 0);
  if (!recommended || !eligibleNonRecommended || !advisoryGated || !fixCreditRelease) {
    throw new Error(
      'Fixture snapshot must include recommended, eligible nonrecommended, advisory-gated, and nonzero fix-credit releases',
    );
  }
  for (const release of releases) {
    const review = reviewsByTag[release.tag];
    if (review?.snapshotId !== release.snapshotId) {
      throw new Error(`Fixture review snapshot mismatch for ${release.tag}`);
    }
  }

  const page = await newSmokePage(browser, { viewport: { width: 390, height: 844 } });
  let reviewCalls = 0;
  let pendingReviewRoute = null;
  let delayFirstReview = true;
  const stableStatus = statusForSnapshot(releases, {
    refreshing: false,
    activeRunId: null,
    lastError: null,
    lastScoredAt: releases[0]?.scoredAt,
    dataFreshness: { issueUpdatedAgeHoursAtScore: 0 },
  });
  await page.route('**/api/**', async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path === '/api/releases') return fulfillJson(route, releases);
    if (path === '/api/releases/history') return fulfillJson(route, historyPayload);
    if (path === '/api/public') return fulfillJson(route, publicPayload);
    if (path === '/api/status') {
      return fulfillJson(route, stableStatus, 200, stableStatus.snapshotId);
    }
    const match = path.match(/^\/api\/releases\/([^/]+)\/review$/);
    if (match) {
      reviewCalls += 1;
      const tag = decodeURIComponent(match[1]);
      if (delayFirstReview) {
        delayFirstReview = false;
        pendingReviewRoute = route;
        return;
      }
      return fulfillJson(route, reviewsByTag[tag]);
    }
    return route.continue();
  });
  try {
    await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
    await page.waitForSelector('#releases .release');
    if (reviewCalls !== 0) throw new Error('Fixture first render eagerly requested score reviews');
    if (await page.locator('#packageLoadState').getAttribute('aria-busy') !== 'false') {
      throw new Error('Fixture release loading state did not clear aria-busy');
    }
    const bodyText = await page.locator('body').innerText();
    if (/\b(upstream|comparison)\b/i.test(bodyText)) {
      throw new Error('Fixture product UI leaked upstream/comparison wording');
    }
    if (/Score history|Score drivers:|Score math|Score breakdown unavailable/i.test(bodyText)) {
      throw new Error('Fixture product UI exposed internal score-oriented labels');
    }
    if (/community-confirmed|field-confirmed reproduction/i.test(bodyText)) {
      throw new Error('Fixture product UI mislabeled policy evidence as independent reproduction');
    }
    await page.getByText('Global assessment history', { exact: true }).waitFor();
    await assertReleaseRowInteractionSemantics(page, releases[0].tag);
    await releaseToggle(page, releases[0].tag).click();
    const panel = page.locator(`#det-${domIdForTag(releases[0].tag)}`);
    const loading = panel.locator('[data-review-state="loading"]');
    await loading.waitFor();
    if (await loading.getAttribute('aria-busy') !== 'true') {
      throw new Error('Fixture assessment loading state did not expose aria-busy');
    }
    await fulfillJson(pendingReviewRoute, reviewsByTag[releases[0].tag]);
    pendingReviewRoute = null;
    const summary = panel.locator('summary.evidence-toggle__summary', {
      hasText: /^Assessment details for .+\/10$/,
    });
    await summary.waitFor();
    await summary.click();
    const limiting = await scoreExplanationSectionListText(
      panel,
      'What lowers or limits this assessment:',
    );
    const context = await scoreExplanationSectionListText(
      panel,
      'Context that does not lower the assessment:',
    );
    if (!/Source-only evidence remains weak/i.test(limiting)) {
      throw new Error(`Fixture source-only evidence was not assessment-lowering: ${limiting}`);
    }
    if (/Inherited source-only context/i.test(limiting)) {
      throw new Error(`Fixture inherited context appeared under assessment limits: ${limiting}`);
    }
    if (!/Inherited source-only context/i.test(context)) {
      throw new Error(`Fixture inherited context was not rendered separately: ${context}`);
    }
    const firstPanelText = await panel.innerText();
    if (
      !firstPanelText.includes('Policy and discussion signals')
      || !firstPanelText.includes('Those signals are not independent reproduction')
    ) {
      throw new Error(`Fixture policy evidence copy was not explicit: ${firstPanelText}`);
    }
    await assertUnchangedStatusPollPreservesInteractiveDom(page, releases[0].tag);

    const fixPanel = await openScoreBreakdown(page, fixCreditRelease.tag);
    await fixPanel
      .locator('.score-review__item')
      .filter({ hasText: 'Release fix credit' })
      .getByText('1 direct fixes credited')
      .waitFor();

    const nonRecommendedPanel = await openScoreBreakdown(page, eligibleNonRecommended.tag);
    await nonRecommendedPanel.locator('.install-state--not-recommended').waitFor();
    if (await nonRecommendedPanel.locator('.update-cmd__code').count()) {
      throw new Error('Fixture eligible nonrecommended release exposed an install command');
    }

    const advisoryRowText = await page
      .locator(releaseSelector(advisoryGated.tag))
      .innerText();
    if (!/medium-or-higher security advisor(y|ies)/i.test(advisoryRowText)) {
      throw new Error(`Fixture advisory-gated row did not use advisory wording: ${advisoryRowText}`);
    }
    const advisoryPanel = await openScoreBreakdown(page, advisoryGated.tag);
    const advisoryPanelText = await advisoryPanel.innerText();
    if (!/security advisory install gate/i.test(advisoryPanelText)) {
      throw new Error(`Fixture advisory gate was not humanized: ${advisoryPanelText}`);
    }
    assertNoUnsupportedCveCopy(advisoryPanelText, 'fixture advisory-gated panel');
    await assertNoHorizontalOverflow(page, 'fixture mobile');
    await assertHelpAndDisclosureTargetSizes(page, 'fixture mobile');
  } finally {
    if (pendingReviewRoute) {
      await pendingReviewRoute.abort().catch(() => undefined);
    }
    await page.close();
  }
}

async function assertUnchangedStatusPollPreservesInteractiveDom(page, tag) {
  const id = domIdForTag(tag);
  const actionSelector = `#install-action-${id}`;
  const reviewSelector = `#review-${id}`;
  const panelSelector = `#det-${id}`;
  const actionFocus = page.locator(`${actionSelector} .update-cmd__copy`);
  await actionFocus.waitFor();
  await actionFocus.focus();
  await page.evaluate(({ actionSelector }) => {
    const actionSlot = document.querySelector(actionSelector);
    if (!actionSlot?.firstElementChild || !document.activeElement) {
      throw new Error('Could not capture the fixture action DOM before an unchanged status poll');
    }
    window.__uiSmokeStableStatusNodes = {
      actionRoot: actionSlot.firstElementChild,
      focused: document.activeElement,
    };
  }, { actionSelector });
  await page.evaluate(() => loadStatus());
  const actionState = await page.evaluate(({ actionSelector }) => {
    const saved = window.__uiSmokeStableStatusNodes;
    const actionSlot = document.querySelector(actionSelector);
    return {
      sameActionRoot: actionSlot?.firstElementChild === saved?.actionRoot,
      sameFocus: document.activeElement === saved?.focused,
    };
  }, { actionSelector });
  if (!actionState.sameActionRoot || !actionState.sameFocus) {
    throw new Error(`Unchanged status poll rewrote action DOM or dropped focus: ${JSON.stringify(actionState)}`);
  }

  const summary = page.locator(
    `${reviewSelector} summary.evidence-toggle__summary`,
    { hasText: /^Assessment details for .+\/10$/ },
  );
  if (!await summary.evaluate((element) => element.parentElement?.open === true)) {
    await summary.click();
  }
  await summary.focus();
  await page.evaluate(({ actionSelector, reviewSelector }) => {
    const actionSlot = document.querySelector(actionSelector);
    const reviewSlot = document.querySelector(reviewSelector);
    const assessment = reviewSlot?.querySelector('details.evidence-toggle');
    if (!actionSlot?.firstElementChild || !reviewSlot?.firstElementChild || !assessment) {
      throw new Error('Could not capture the fixture review DOM before an unchanged status poll');
    }
    window.__uiSmokeStableStatusNodes = {
      actionRoot: actionSlot.firstElementChild,
      reviewRoot: reviewSlot.firstElementChild,
      assessment,
      focused: document.activeElement,
    };
  }, { actionSelector, reviewSelector });
  await page.evaluate(() => loadStatus());
  const reviewState = await page.evaluate(({
    actionSelector,
    reviewSelector,
    panelSelector,
  }) => {
    const saved = window.__uiSmokeStableStatusNodes;
    const actionSlot = document.querySelector(actionSelector);
    const reviewSlot = document.querySelector(reviewSelector);
    const panel = document.querySelector(panelSelector);
    const row = panel?.previousElementSibling;
    delete window.__uiSmokeStableStatusNodes;
    return {
      sameActionRoot: actionSlot?.firstElementChild === saved?.actionRoot,
      sameReviewRoot: reviewSlot?.firstElementChild === saved?.reviewRoot,
      sameAssessment: reviewSlot?.querySelector('details.evidence-toggle') === saved?.assessment,
      assessmentOpen: saved?.assessment?.open === true,
      releaseOpen: row?.classList.contains('open') === true && panel?.hidden === false,
      sameFocus: document.activeElement === saved?.focused,
    };
  }, { actionSelector, reviewSelector, panelSelector });
  if (Object.values(reviewState).some((value) => value !== true)) {
    throw new Error(
      `Unchanged status poll rewrote review DOM, collapsed details, or dropped focus: ${JSON.stringify(reviewState)}`,
    );
  }
}

async function newSmokePage(browser, options) {
  const page = await browser.newPage(options);
  if (!fixtureOnly) return page;
  fixtureIndexHtmlPromise ??= readFile(resolve('public/index.html'));
  await page.route(`${base}/**`, async (route) => {
    const url = new URL(route.request().url());
    if (url.pathname.startsWith('/api/')) return route.continue();
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return route.fulfill({
        status: 200,
        contentType: 'text/html',
        headers: { 'Cache-Control': 'public, max-age=60' },
        body: await fixtureIndexHtmlPromise,
      });
    }
    const relative = decodeURIComponent(url.pathname).replace(/^\/+/, '');
    if (!relative || relative.split('/').includes('..')) {
      return route.fulfill({ status: 404, body: '' });
    }
    try {
      const body = await readFile(resolve('public', relative));
      const contentType = ({
        '.ico': 'image/x-icon',
        '.png': 'image/png',
        '.svg': 'image/svg+xml',
      })[extname(relative).toLowerCase()] ?? 'application/octet-stream';
      return route.fulfill({
        status: 200,
        contentType,
        headers: { 'Cache-Control': 'public, max-age=60' },
        body,
      });
    } catch {
      return route.fulfill({ status: 404, body: '' });
    }
  });
  return page;
}

function releaseCheckSummaryText(checks) {
  if (!checks) return null;
  const total = Number(checks.total ?? 0);
  const passed = Number(checks.success ?? 0);
  const failed = Number(checks.failure ?? 0);
  const pending = Number(checks.pending ?? 0);
  const skipped = Number(checks.skipped ?? Math.max(0, total - passed - failed - pending));
  if (failed === 0 && pending === 0 && passed > 0) {
    return `${passed} of ${total} passed · none failed or pending${skipped > 0 ? ` · ${skipped} skipped` : ''}`;
  }
  return `${passed} of ${total} passed · ${failed} failed · ${pending} pending${skipped > 0 ? ` · ${skipped} skipped` : ''}`;
}

function assertNoMachineDecisionCopy(text, label) {
  if (/Decision [a-z_]+:|highest_confidence|confidence_tolerance|recommendation_threshold|install_gate_active/i.test(text)) {
    throw new Error(`${label} exposed machine recommendation copy`);
  }
}

function assertNoUnsupportedCveCopy(text, label) {
  if (/known CVEs?\b|CVE install gate|known medium-or-higher CVE exposure/i.test(text)) {
    throw new Error(`${label} claimed a CVE where only an advisory is guaranteed`);
  }
}

async function scoreExplanationSectionListText(panel, heading) {
  return panel.evaluate((root, { heading }) => {
    const paragraphs = [...root.querySelectorAll('.score-explain > p')];
    const paragraph = paragraphs.find((candidate) => candidate.textContent?.trim() === heading);
    const list = paragraph?.nextElementSibling;
    return list?.tagName === 'UL' ? list.textContent?.trim() ?? '' : '';
  }, { heading });
}

function assertNoComparisonPayload(value, path) {
  const forbidden = new Set(['snapshot', 'upstream', 'delta', 'rawCardText', 'sourceUrl', 'pageText']);
  if (Array.isArray(value)) {
    value.forEach((item, idx) => assertNoComparisonPayload(item, `${path}[${idx}]`));
    return;
  }
  if (!value || typeof value !== 'object') return;
  for (const [key, child] of Object.entries(value)) {
    if (forbidden.has(key)) {
      throw new Error(`${path} leaked comparison field ${key}`);
    }
    assertNoComparisonPayload(child, `${path}.${key}`);
  }
}

function assertReviewAuditIdentity(release, review) {
  const local = review?.local;
  if (!release?.scoreAudit || !local) {
    throw new Error(`Missing score audit identity for ${release?.tag ?? 'unknown release'}`);
  }
  if (local.schemaVersion !== release.scoreAudit.reviewSchemaVersion) {
    throw new Error(
      `${release.tag} review schema ${local.schemaVersion} did not match ${release.scoreAudit.reviewSchemaVersion}`,
    );
  }
  if (!/^[0-9a-f]{64}$/.test(String(release.scoreAudit.auditDigest ?? ''))) {
    throw new Error(`${release.tag} release row did not expose a stable audit digest`);
  }
  if (review.snapshotId !== release.snapshotId) {
    throw new Error(`${release.tag} review snapshot did not match the release snapshot`);
  }
  if (local.auditDigest !== release.scoreAudit.auditDigest ||
      local.sourceProvenance?.auditDigest !== release.scoreAudit.auditDigest) {
    throw new Error(`${release.tag} review audit identity did not match the release snapshot`);
  }
}

async function json(path) {
  if (fixtureResponses?.has(path)) {
    return structuredClone(fixtureResponses.get(path));
  }
  const res = await fetch(base + path);
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  if (path.startsWith('/api/') && res.headers.get('cache-control') !== 'no-store') {
    throw new Error(`${path} did not return Cache-Control: no-store`);
  }
  return res.json();
}

async function assertStaticAssetsRemainCacheable() {
  const response = await fetch(`${base}/favicon.ico`);
  if (!response.ok) throw new Error(`/favicon.ico returned ${response.status}`);
  const cacheControl = response.headers.get('cache-control') ?? '';
  if (!cacheControl || /\bno-store\b/i.test(cacheControl)) {
    throw new Error(`Static asset cache policy is not cacheable: ${cacheControl || 'missing'}`);
  }
}

async function assertAuditLinkJson(locator, expectedIssueNumber, label) {
  await locator.waitFor();
  const href = await locator.getAttribute('href');
  if (!href) throw new Error(`${label} link is missing href`);
  const url = new URL(href, base);
  const payload = await json(`${url.pathname}${url.search}`);
  if (payload.filters?.issue !== expectedIssueNumber || payload.filters?.issueNumber !== expectedIssueNumber) {
    throw new Error(`${label} link did not echo issue filter ${expectedIssueNumber}: ${JSON.stringify(payload.filters)}`);
  }
  if (!Array.isArray(payload.rows) || payload.rows.length < 1) {
    throw new Error(`${label} link returned no rows`);
  }
  const ok = payload.rows.every((row) => {
    const number = row.issue?.number ?? row.issueNumber;
    return number === expectedIssueNumber;
  });
  if (!ok) throw new Error(`${label} link returned rows for another issue`);
}

async function assertReleaseRowInteractionSemantics(page, tag) {
  const row = page.locator(releaseSelector(tag));
  const toggle = row.locator('[data-release-toggle]');
  const semantics = await row.evaluate((element) => ({
    role: element.getAttribute('role'),
    tabIndex: element.getAttribute('tabindex'),
  }));
  if (semantics.role != null || semantics.tabIndex != null) {
    throw new Error(`Release row retained button semantics: ${JSON.stringify(semantics)}`);
  }
  if (await toggle.evaluate((element) => element.tagName) !== 'BUTTON') {
    throw new Error('Release disclosure control is not a native button');
  }
  const nestedInteractive = await toggle
    .locator('a, button, input, select, textarea, summary, [role="button"], [tabindex]')
    .count();
  if (nestedInteractive !== 0) {
    throw new Error(`Release toggle contains ${nestedInteractive} nested interactive element(s)`);
  }

  const panel = page.locator(`#det-${domIdForTag(tag)}`);
  await toggle.press('Enter');
  await panel.waitFor({ state: 'visible' });
  if (await toggle.getAttribute('aria-expanded') !== 'true') {
    throw new Error('Enter did not update release toggle aria-expanded');
  }
  await toggle.press('Space');
  await panel.waitFor({ state: 'hidden' });
  if (await toggle.getAttribute('aria-expanded') !== 'false') {
    throw new Error('Space did not close the release disclosure');
  }
}

async function assertHelpAndDisclosureTargetSizes(page, label) {
  const groups = [
    { selector: '.help-button:visible', name: 'help control' },
    {
      selector: 'summary.evidence-toggle__summary:visible, summary.surf-more:visible, .evidence__more:visible',
      name: 'disclosure control',
    },
  ];
  for (const group of groups) {
    const locator = page.locator(group.selector);
    const count = await locator.count();
    if (!count) throw new Error(`${label} has no visible ${group.name} to size-check`);
    const boxes = await locator.evaluateAll((elements) => elements.map((element) => {
      const box = element.getBoundingClientRect();
      return {
        text: element.textContent?.trim() ?? '',
        width: box.width,
        height: box.height,
      };
    }));
    const undersized = boxes.find((box) => box.width < 23.99 || box.height < 23.99);
    if (undersized) {
      throw new Error(`${label} ${group.name} is below 24px: ${JSON.stringify(undersized)}`);
    }
  }
}

async function assertRetryTargetSizes(page, label) {
  const locator = page.locator(
    '[data-release-retry], [data-public-retry], [data-review-retry]',
  );
  const boxes = await locator.evaluateAll((elements) => elements
    .map((element) => {
      const box = element.getBoundingClientRect();
      return {
        text: element.textContent?.trim() ?? '',
        width: box.width,
        height: box.height,
      };
    })
    .filter((box) => box.width > 0 && box.height > 0));
  if (!boxes.length) throw new Error(`${label} has no visible retry target to size-check`);
  const undersized = boxes.find((box) => box.width < 23.99 || box.height < 23.99);
  if (undersized) {
    throw new Error(`${label} retry target is below 24px: ${JSON.stringify(undersized)}`);
  }
}

async function assertWarningContrast(page, label) {
  for (const colorScheme of ['light', 'dark']) {
    await page.emulateMedia({ colorScheme });
    const contrast = await page.evaluate(() => {
      const rootStyle = getComputedStyle(document.documentElement);
      const resolveRgb = (value) => {
        const probe = document.createElement('span');
        probe.style.color = value;
        document.body.appendChild(probe);
        const channels = getComputedStyle(probe).color.match(/[\d.]+/g)?.slice(0, 3).map(Number);
        probe.remove();
        return channels;
      };
      const luminance = (rgb) => {
        const channels = rgb.map((channel) => {
          const normalized = channel / 255;
          return normalized <= 0.04045
            ? normalized / 12.92
            : ((normalized + 0.055) / 1.055) ** 2.4;
        });
        return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
      };
      const ratio = (foreground, background) => {
        const light = Math.max(luminance(foreground), luminance(background));
        const dark = Math.min(luminance(foreground), luminance(background));
        return (light + 0.05) / (dark + 0.05);
      };
      const warn = resolveRgb(rootStyle.getPropertyValue('--warn'));
      const bg = resolveRgb(rootStyle.getPropertyValue('--bg'));
      const surface = resolveRgb(rootStyle.getPropertyValue('--surface'));
      return {
        background: ratio(warn, bg),
        surface: ratio(warn, surface),
      };
    });
    const minimum = Math.min(contrast.background, contrast.surface);
    if (minimum < 4.5) {
      throw new Error(
        `${label} ${colorScheme} contrast is ${minimum.toFixed(2)}:1: ${JSON.stringify(contrast)}`,
      );
    }
  }
  await page.emulateMedia({ colorScheme: 'light' });
}

async function assertVisualSmoke(page, label) {
  await assertNoHorizontalOverflow(page, label);
  await assertReleaseRowsDoNotOverlap(page, label);
  const bodyText = await page.locator('body').innerText();
  if (bodyText.trim().length < 100) throw new Error(`${label} page rendered too little text`);
  const screenshot = await page.screenshot({ fullPage: false });
  const uniqueByteCount = new Set(screenshot).size;
  if (screenshot.length < 1500 || uniqueByteCount < 32) {
    throw new Error(`${label} screenshot looked blank or invalid: ${screenshot.length} bytes, ${uniqueByteCount} unique bytes`);
  }
  await assertElementInViewport(page, page.locator('.topbar__nav').first(), `${label} topbar nav`);
  await assertElementInViewport(page, page.locator('#releases .release').first(), `${label} release row`);
}

async function assertReleaseRowsDoNotOverlap(page, label) {
  const boxes = await page.locator('#releases .release:visible').evaluateAll((rows) =>
    rows.map((row) => {
      const box = row.getBoundingClientRect();
      return {
        tag: row.getAttribute('data-tag'),
        top: box.top,
        bottom: box.bottom,
      };
    }),
  );
  for (let index = 1; index < boxes.length; index++) {
    const previous = boxes[index - 1];
    const current = boxes[index];
    if (current.top < previous.bottom - 1) {
      throw new Error(
        `${label} release rows overlap: ${previous.tag} ends at ${previous.bottom}, ` +
        `${current.tag} starts at ${current.top}`,
      );
    }
  }
}

async function assertNoHorizontalOverflow(page, label) {
  const metrics = await page.evaluate(() => ({
    htmlScrollWidth: document.documentElement.scrollWidth,
    bodyScrollWidth: document.body.scrollWidth,
    innerWidth: window.innerWidth,
  }));
  const overflow = Math.max(metrics.htmlScrollWidth, metrics.bodyScrollWidth) - metrics.innerWidth;
  if (overflow > 1) {
    throw new Error(`${label} page has horizontal overflow ${overflow}px (${JSON.stringify(metrics)})`);
  }
}

async function assertElementInViewport(page, locator, label) {
  await locator.scrollIntoViewIfNeeded();
  const box = await locator.boundingBox();
  const viewport = page.viewportSize();
  if (!box || !viewport || box.width <= 0 || box.height <= 0) {
    throw new Error(`${label} is not visibly rendered`);
  }
  if (box.x < -1 || box.x + box.width > viewport.width + 1) {
    throw new Error(`${label} is horizontally clipped: ${JSON.stringify({ box, viewport })}`);
  }
  if (box.y > viewport.height + 1 || box.y + box.height < -1) {
    throw new Error(`${label} is outside the viewport: ${JSON.stringify({ box, viewport })}`);
  }
}

async function openScoreBreakdown(page, tag) {
  const row = page.locator(releaseSelector(tag));
  const panel = page.locator(`#det-${domIdForTag(tag)}`);
  if (!(await panel.isVisible())) {
    await row.locator('[data-release-toggle]').click();
    await panel.waitFor({ state: 'visible' });
  }
  const summary = panel.locator('summary.evidence-toggle__summary', { hasText: /^(Assessment details for .+\/10|Show assessment details)$/ });
  await summary.waitFor();
  const isOpen = await summary.evaluate((el) => el.parentElement?.hasAttribute('open') === true);
  if (!isOpen) await summary.click();
  return panel;
}

function releaseToggle(page, tag) {
  return page.locator(`${releaseSelector(tag)} [data-release-toggle]`);
}

async function exposeReleaseDetailsWithoutReview(page, tag) {
  await page.evaluate((releaseTag) => {
    const row = document.querySelector(
      `.release[data-tag="${CSS.escape(releaseTag)}"]`,
    );
    const details = row?.nextElementSibling;
    if (!row || !details?.classList.contains('details')) {
      throw new Error(`Release details are unavailable for ${releaseTag}`);
    }
    row.classList.add('open');
    row.querySelector('[data-release-toggle]')?.setAttribute('aria-expanded', 'true');
    details.hidden = false;
  }, tag);
}

function domIdForTag(tag) {
  const value = String(tag);
  let encoded = 'tag-';
  for (let index = 0; index < value.length; index += 1) {
    encoded += value.charCodeAt(index).toString(16).padStart(4, '0');
  }
  return encoded;
}

function shellQuote(value) {
  return "'" + String(value).replace(/'/g, "'\"'\"'") + "'";
}

function installCommand(tag) {
  return `openclaw update --tag ${shellQuote(String(tag ?? '').replace(/^v/i, ''))}`;
}

function createCoverageReport() {
  return {
    core: new Map([
      ['recommendation', { status: 'required', detail: null }],
      ['stale', { status: 'required', detail: null }],
      ['no-overlap', { status: 'required', detail: null }],
      ['mobile', { status: 'required', detail: null }],
      ['desktop', { status: 'required', detail: null }],
    ]),
    optional: new Map([
      ['advisory-gated', { status: 'available', detail: null }],
      ['eligible nonrecommended', { status: 'available', detail: null }],
      ['fix-credit link examples', { status: 'available', detail: null }],
    ]),
  };
}

function passCoverage(group, name, detail = null) {
  group.set(name, { status: 'passed', detail });
}

function skipCoverage(group, name, detail) {
  group.set(name, { status: 'skipped', detail });
}

function reportCoverage(report) {
  const incompleteCore = [...report.core]
    .filter(([, result]) => result.status !== 'passed')
    .map(([name]) => name);
  if (incompleteCore.length > 0) {
    throw new Error(`UI smoke did not complete core coverage: ${incompleteCore.join(', ')}`);
  }
  console.log('UI smoke coverage:');
  for (const [name, result] of [...report.core, ...report.optional]) {
    console.log(`- ${name}: ${result.status}${result.detail ? ` (${result.detail})` : ''}`);
  }
}
