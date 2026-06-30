import { chromium } from 'playwright';

const base = (process.env.API_BASE || process.argv[2] || 'http://127.0.0.1:8787').replace(/\/$/, '');

const releases = await json('/api/releases');
const publicPayload = await json('/api/public');
const publicByTag = new Map((publicPayload.releases ?? []).map((release) => [release.tag, release]));
const publicRecommended = (publicPayload.releases ?? []).filter((release) => release.recommended);
if (publicRecommended.length !== 1) throw new Error(`Expected exactly one public recommended release, got ${publicRecommended.length}`);
const eligibleNonRecommended = releases.find((r) => r.status === 'eligible' && !r.recommended);
if (!eligibleNonRecommended) throw new Error('No eligible non-recommended release available for UI smoke');

let fixCreditTag = null;
let fixCreditText = null;
let closureRiskText = null;
let explanationText = null;
let explanationIssueRef = null;
let explanationMetricText = null;
let explanationProofText = null;
let expectedCheckLinkText = null;
let expectedArtifactLinkText = null;
const reviewByTag = new Map();
for (const release of releases) {
  const review = await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
  assertNoComparisonPayload(review, `/api/releases/${release.tag}/review`);
  reviewByTag.set(release.tag, review);
  const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
  const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
  if (credit) {
    fixCreditTag = release.tag;
    fixCreditText = `${credit.countedClosedCount} counted · ${credit.notCountedClosedCount} not counted · ${credit.analyzedClosedCount} analyzed`;
    closureRiskText = risk
      ? `${risk.unresolvedForReleaseCount ?? 0} unresolved · ${risk.knownNotInReleaseCount ?? 0} known not in tag · ${risk.neutralOrNonActionableCount ?? 0} not scored`
      : null;
    explanationText = (review.local?.components?.explanation?.limits ?? [])
      .find((line) => /closed issues .* not counted as release fixes/i.test(line))
      ?? review.local?.components?.explanation?.limits?.[0]
      ?? null;
    const closureDetail = (review.local?.components?.explanation?.limitDetails ?? [])
      .find((detail) => detail.code === 'closed_issues_not_counted_as_release_fixes');
    explanationIssueRef = closureDetail?.issueRefs?.[0] ?? null;
    const metric = closureDetail?.metrics?.unresolvedForReleaseCount;
    explanationMetricText = Number.isFinite(metric) ? `unresolved: ${metric}` : null;
    explanationProofText = explanationIssueRef?.proof?.riskDispositionLabel ?? explanationIssueRef?.proof?.statusLabel ?? null;
    const checkContext = (review.local?.gateEvidence?.releaseChecks?.contexts ?? [])
      .find((context) => context?.url && context?.name);
    expectedCheckLinkText = checkContext?.name ?? null;
    const artifact = review.local?.gateEvidence?.artifactVerification;
    expectedArtifactLinkText = artifact?.npmPackageUrl ? 'npm package' : artifact?.ciReportUrl ? 'evidence report' : null;
    break;
  }
}
if (!fixCreditTag) throw new Error('No release exposes releaseFixCredit for UI smoke');
if (!explanationText) throw new Error(`No score explanation text available for ${fixCreditTag}`);
if (!closureRiskText) throw new Error(`No closure risk summary available for ${fixCreditTag}`);
if (!explanationIssueRef?.number || !explanationIssueRef?.url) throw new Error(`No explanation issue ref available for ${fixCreditTag}`);
if (!explanationMetricText) throw new Error(`No explanation metric available for ${fixCreditTag}`);
if (!explanationProofText) throw new Error(`No explanation proof context available for ${fixCreditTag}`);
if (!expectedCheckLinkText) throw new Error(`No release check link available for ${fixCreditTag}`);
if (!expectedArtifactLinkText) throw new Error(`No artifact link available for ${fixCreditTag}`);
const publicDetail = publicByTag.get(fixCreditTag);
const relatedIssue = (publicDetail?.watchIssues?.length ? publicDetail.watchIssues : publicDetail?.issues ?? [])[0];
if (!relatedIssue?.number || !relatedIssue?.url) {
  throw new Error(`No public related issue details available for ${fixCreditTag}`);
}

const browser = await chromium.launch({ headless: true });
const page = await browser.newPage({ viewport: { width: 1440, height: 1000 } });
const badRequests = [];
page.on('request', (req) => {
  if (new URL(req.url()).pathname === '/api/comparison') badRequests.push(req.url());
});

try {
  await page.goto(`${base}/#/openclaw`, { waitUntil: 'networkidle' });
  await page.waitForSelector('#releases .release');

  if (badRequests.length) throw new Error(`UI requested /api/comparison: ${badRequests.join(', ')}`);
  const bodyText = await page.locator('body').innerText();
  if (/\b(upstream|comparison)\b/i.test(bodyText)) {
    throw new Error('Visible UI leaked upstream/comparison wording');
  }
  const renderedRows = page.locator('#releases .release');
  const renderedCount = await renderedRows.count();
  if (renderedCount !== publicPayload.releases.length) {
    throw new Error(`Rendered release row count ${renderedCount} did not match public releases ${publicPayload.releases.length}`);
  }
  for (const release of publicPayload.releases) {
    const row = page.locator(`.release[data-tag="${release.tag}"]`);
    if (await row.count() !== 1) throw new Error(`Expected one DOM row for ${release.tag}`);
  }
  const recommendedRows = page.locator('#releases .release--recommended');
  if (await recommendedRows.count() !== 1) throw new Error(`Expected exactly one recommended DOM row`);
  const recommendedTag = await recommendedRows.first().getAttribute('data-tag');
  if (recommendedTag !== publicRecommended[0].tag) {
    throw new Error(`Recommended DOM row ${recommendedTag} did not match public API ${publicRecommended[0].tag}`);
  }
  const recommendedDriverText = await recommendedRows.first().locator('.release__drivers').innerText();
  if (!/^Score drivers:/i.test(recommendedDriverText)) {
    throw new Error(`recommended row missing score drivers: ${recommendedDriverText}`);
  }
  if (!/\brisk\b/i.test(recommendedDriverText)) {
    throw new Error(`recommended row score drivers did not include a risk label: ${recommendedDriverText}`);
  }
  if (/raw\/classified|attributed issues/i.test(recommendedDriverText)) {
    throw new Error(`recommended row score drivers looked issue-volume based: ${recommendedDriverText}`);
  }
  const recommendedPanel = await openScoreBreakdown(page, recommendedTag);
  const expectedRecommendedCmd = `openclaw update --tag ${recommendedTag.replace(/^v/i, '')}`;
  await recommendedPanel.locator('.update-cmd__code').filter({ hasText: expectedRecommendedCmd }).waitFor();
  await recommendedPanel.locator(`.update-cmd__copy[data-cmd="${expectedRecommendedCmd}"]`).waitFor();

  const fixPanel = await openScoreBreakdown(page, fixCreditTag);
  await fixPanel.getByText('Model', { exact: true }).waitFor();
  await fixPanel.getByText('Evidence coverage', { exact: true }).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Release fix credit' }).first().waitFor();
  await fixPanel.getByText(fixCreditText).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Closed issue proof' }).first().waitFor();
  await fixPanel.getByText(closureRiskText).waitFor();
  await fixPanel.locator('a.score-explain__ref').filter({ hasText: expectedCheckLinkText }).first().waitFor();
  await fixPanel.locator('a.score-explain__ref').filter({ hasText: expectedArtifactLinkText }).first().waitFor();
  const fixPanelText = await fixPanel.innerText();
  if (!fixPanelText.includes(explanationText)) {
    throw new Error(`Score explanation text not rendered for ${fixCreditTag}: ${explanationText}`);
  }
  await fixPanel.locator('.score-ledger').filter({ hasText: 'Score math' }).first().waitFor();
  await fixPanel.locator('.score-ledger__row').filter({ hasText: 'Closed-issue proof gap' }).first().waitFor();
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
  await fixPanel.locator('a').filter({ hasText: 'open unconfirmed issue risk' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'field-discussed open risk' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'critical core contextual risk' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'weak or stale issue evidence' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'high-weight weak/stale evidence' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'opened reports' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open closure proof rows' }).first().waitFor();
  await fixPanel.locator('a').filter({ hasText: 'Open PR reachability rows' }).first().waitFor();
  await fixPanel.locator('summary.evidence-toggle__summary', { hasText: 'Show related issues' }).click();
  const relatedIssueRow = fixPanel.locator('li.evidence__item').filter({ hasText: `#${relatedIssue.number}` }).first();
  await relatedIssueRow.waitFor();
  await relatedIssueRow.getByText(/Evidence bucket: /).waitFor();
  await relatedIssueRow.getByText(new RegExp(`${relatedIssue.severity}.*${relatedIssue.affectedUsers} users`, 'i')).waitFor();
  await assertAuditLinkJson(
    relatedIssueRow.locator('a.score-explain__ref', { hasText: 'issue evidence row' }).first(),
    relatedIssue.number,
    'related issue evidence row',
  );

  const normalRow = page.locator(`.release[data-tag="${eligibleNonRecommended.tag}"]`);
  await normalRow.evaluate((el) => {
    if (!el.classList.contains('release--normal')) throw new Error('eligible non-recommended row is not normal category');
    if (el.querySelector('.rec-pill')) throw new Error('eligible non-recommended row shows Recommended pill');
    if (el.querySelector('.release__reason')?.textContent?.trim()) throw new Error('eligible non-recommended row has verbose reason text');
    const drivers = el.querySelector('.release__drivers')?.textContent?.trim() ?? '';
    if (!drivers.startsWith('Score drivers:')) throw new Error('eligible non-recommended row is missing score drivers');
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
  if (normalText.includes(`openclaw update --tag ${eligibleNonRecommended.tag.replace(/^v/i, '')}`)) {
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

  for (const release of publicPayload.releases) {
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
    const expectedRiskWeights = `Field ${Math.round(input.verifiedDebtWeight ?? 0)} · Open unconfirmed ${Math.round(input.carryoverDebtWeight ?? 0)} · Weak/stale ${Math.round(input.staleDebtWeight ?? 0)} · Closed proof gap ${Math.round(input.unresolvedClosureRiskWeight ?? 0)}`;
    await panel.locator('.score-review__item').filter({ hasText: 'Audit weights' }).getByText(expectedRiskWeights).waitFor();
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (credit) {
      const expectedCredit = `${credit.countedClosedCount} counted · ${credit.notCountedClosedCount} not counted · ${credit.analyzedClosedCount} analyzed`;
      await panel.locator('.score-review__item').filter({ hasText: 'Release fix credit' }).getByText(expectedCredit).waitFor();
      const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
      if (!risk) throw new Error(`Missing closure risk summary for ${release.tag}`);
      const expectedRisk = `${risk.unresolvedForReleaseCount ?? 0} unresolved · ${risk.knownNotInReleaseCount ?? 0} known not in tag · ${risk.neutralOrNonActionableCount ?? 0} not scored`;
      await panel.locator('.score-review__item').filter({ hasText: 'Closed issue proof' }).getByText(expectedRisk).waitFor();
    }
  }
  await assertVisualSmoke(page, 'desktop');

  const mobilePage = await browser.newPage({ viewport: { width: 390, height: 844 } });
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
    if (mobileRenderedCount !== publicPayload.releases.length) {
      throw new Error(`Mobile rendered release row count ${mobileRenderedCount} did not match public releases ${publicPayload.releases.length}`);
    }

    const mobileRecommendedPanel = await openScoreBreakdown(mobilePage, recommendedTag);
    await mobileRecommendedPanel.locator('.update-cmd__code').filter({ hasText: expectedRecommendedCmd }).waitFor();
    await mobileRecommendedPanel.locator(`.update-cmd__copy[data-cmd="${expectedRecommendedCmd}"]`).waitFor();
    const mobileFixPanel = await openScoreBreakdown(mobilePage, fixCreditTag);
    await mobileFixPanel.locator('.score-review').waitFor();
    await mobilePage.locator(`.release[data-tag="${recommendedTag}"] .release__drivers`).first().waitFor();

    await assertVisualSmoke(mobilePage, 'mobile');
    await assertElementInViewport(mobilePage, mobilePage.locator('.topbar__nav').first(), 'mobile topbar nav');
    await assertElementInViewport(mobilePage, mobileRecommendedPanel.locator('.update-cmd__code').first(), 'mobile update command');
    await assertElementInViewport(mobilePage, mobileRecommendedPanel.locator('.update-cmd__copy').first(), 'mobile copy button');
    await assertElementInViewport(mobilePage, mobileFixPanel.locator('.score-review').first(), 'mobile score review');
    await assertElementInViewport(mobilePage, mobilePage.locator(`.release[data-tag="${recommendedTag}"] .release__drivers`).first(), 'mobile score drivers');
  } finally {
    await mobilePage.close();
  }

  console.log(`UI smoke passed: fix credit ${fixCreditTag}; eligible non-recommended ${eligibleNonRecommended.tag}`);
} finally {
  await browser.close();
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

async function json(path) {
  const res = await fetch(base + path);
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
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

async function assertVisualSmoke(page, label) {
  await assertNoHorizontalOverflow(page, label);
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
  const row = page.locator(`.release[data-tag="${tag}"]`);
  const panel = page.locator(`#det-${cssId(tag)}`);
  if (!(await panel.isVisible())) {
    await row.click();
    await panel.waitFor({ state: 'visible' });
  }
  const summary = panel.locator('summary.evidence-toggle__summary', { hasText: /^(Why .+\/10\?|Show score breakdown)$/ });
  const isOpen = await summary.evaluate((el) => el.parentElement?.hasAttribute('open') === true);
  if (!isOpen) await summary.click();
  return panel;
}

function cssId(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}
