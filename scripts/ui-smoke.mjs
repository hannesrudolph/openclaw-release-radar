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
const reviewByTag = new Map();
for (const release of releases) {
  const review = await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
  reviewByTag.set(release.tag, review);
  const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
  const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
  if (credit) {
    fixCreditTag = release.tag;
    fixCreditText = `${credit.countedClosedCount} counted · ${credit.notCountedClosedCount} not counted · ${credit.analyzedClosedCount} analyzed`;
    closureRiskText = risk
      ? `${risk.unresolvedForReleaseCount ?? 0} unresolved · ${risk.knownNotInReleaseCount ?? 0} known not in tag · ${risk.neutralOrNonActionableCount ?? 0} neutral`
      : null;
    explanationText = (review.local?.components?.explanation?.limits ?? [])
      .find((line) => /closed issues .* not counted as release fixes/i.test(line))
      ?? review.local?.components?.explanation?.limits?.[0]
      ?? null;
    break;
  }
}
if (!fixCreditTag) throw new Error('No release exposes releaseFixCredit for UI smoke');
if (!explanationText) throw new Error(`No score explanation text available for ${fixCreditTag}`);
if (!closureRiskText) throw new Error(`No closure risk summary available for ${fixCreditTag}`);
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

  const fixPanel = await openScoreBreakdown(page, fixCreditTag);
  await fixPanel.getByText('Model', { exact: true }).waitFor();
  await fixPanel.getByText('Evidence coverage', { exact: true }).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Release fix credit' }).first().waitFor();
  await fixPanel.getByText(fixCreditText).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Closure risk' }).first().waitFor();
  await fixPanel.getByText(closureRiskText).waitFor();
  const fixPanelText = await fixPanel.innerText();
  if (!fixPanelText.includes(explanationText)) {
    throw new Error(`Score explanation text not rendered for ${fixCreditTag}: ${explanationText}`);
  }
  await fixPanel
    .getByText('A closed issue only reduces release risk when its merged linked PR or named fix/source commit is reachable from this release tag.')
    .waitFor();
  await fixPanel.locator('summary.evidence-toggle__summary', { hasText: 'Show related issues' }).click();
  await fixPanel.locator('a').filter({ hasText: `#${relatedIssue.number}` }).first().waitFor();
  await fixPanel.getByText(/Scored as .* risk /).first().waitFor();

  const normalRow = page.locator(`.release[data-tag="${eligibleNonRecommended.tag}"]`);
  await normalRow.evaluate((el) => {
    if (!el.classList.contains('release--normal')) throw new Error('eligible non-recommended row is not normal category');
    if (el.querySelector('.rec-pill')) throw new Error('eligible non-recommended row shows Recommended pill');
    if (el.querySelector('.release__reason')?.textContent?.trim()) throw new Error('eligible non-recommended row has verbose reason text');
  });
  const normalPanel = await openScoreBreakdown(page, eligibleNonRecommended.tag);
  await normalPanel.getByText('The release passed hard install gates.').waitFor();
  const normalText = await normalPanel.innerText();
  if (normalText.includes('The release is eligible and recommended.')) {
    throw new Error('eligible non-recommended breakdown used recommended wording');
  }
  if (normalText.includes('release looks safe to install')) {
    throw new Error('eligible non-recommended breakdown used safe-to-install wording');
  }

  for (const release of publicPayload.releases) {
    const review = reviewByTag.get(release.tag) ?? await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
    const panel = await openScoreBreakdown(page, release.tag);
    const input = review.local?.input ?? {};
    const expectedRawClassified = `${input.classifiedIssueCount ?? '—'} / ${input.rawIssueCount ?? '—'}`;
    await panel.locator('.score-review__item').filter({ hasText: 'Raw/classified' }).getByText(expectedRawClassified).waitFor();
    const expectedCoverage = `${Math.round((review.local?.components?.evidenceCoverage ?? 0) * 100)}%`;
    await panel.locator('.score-review__item').filter({ hasText: 'Evidence coverage' }).getByText(expectedCoverage).waitFor();
    const expectedRiskWeights = `Field ${Math.round(input.verifiedDebtWeight ?? 0)} · Source ${Math.round(input.carryoverDebtWeight ?? 0)} · Stale ${Math.round(input.staleDebtWeight ?? 0)} · Closure ${Math.round(input.unresolvedClosureRiskWeight ?? 0)}`;
    await panel.locator('.score-review__item').filter({ hasText: 'Risk weights' }).getByText(expectedRiskWeights).waitFor();
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (credit) {
      const expectedCredit = `${credit.countedClosedCount} counted · ${credit.notCountedClosedCount} not counted · ${credit.analyzedClosedCount} analyzed`;
      await panel.locator('.score-review__item').filter({ hasText: 'Release fix credit' }).getByText(expectedCredit).waitFor();
      const risk = review.local?.gateEvidence?.fixProvenance?.closureProof?.riskSummary;
      if (!risk) throw new Error(`Missing closure risk summary for ${release.tag}`);
      const expectedRisk = `${risk.unresolvedForReleaseCount ?? 0} unresolved · ${risk.knownNotInReleaseCount ?? 0} known not in tag · ${risk.neutralOrNonActionableCount ?? 0} neutral`;
      await panel.locator('.score-review__item').filter({ hasText: 'Closure risk' }).getByText(expectedRisk).waitFor();
    }
  }

  console.log(`UI smoke passed: fix credit ${fixCreditTag}; eligible non-recommended ${eligibleNonRecommended.tag}`);
} finally {
  await browser.close();
}

async function json(path) {
  const res = await fetch(base + path);
  if (!res.ok) throw new Error(`${path} returned ${res.status}`);
  return res.json();
}

async function openScoreBreakdown(page, tag) {
  const row = page.locator(`.release[data-tag="${tag}"]`);
  const panel = page.locator(`#det-${cssId(tag)}`);
  if (!(await panel.isVisible())) {
    await row.click();
    await panel.waitFor({ state: 'visible' });
  }
  const summary = panel.locator('summary.evidence-toggle__summary', { hasText: 'Show score breakdown' });
  const isOpen = await summary.evaluate((el) => el.parentElement?.hasAttribute('open') === true);
  if (!isOpen) await summary.click();
  return panel;
}

function cssId(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}
