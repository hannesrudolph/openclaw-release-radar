import { chromium } from 'playwright';

const base = (process.env.API_BASE || process.argv[2] || 'http://127.0.0.1:8787').replace(/\/$/, '');

const releases = await json('/api/releases');
const eligibleNonRecommended = releases.find((r) => r.status === 'eligible' && !r.recommended);
if (!eligibleNonRecommended) throw new Error('No eligible non-recommended release available for UI smoke');

let fixCreditTag = null;
let fixCreditText = null;
for (const release of releases) {
  const review = await json(`/api/releases/${encodeURIComponent(release.tag)}/review`);
  const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
  if (credit) {
    fixCreditTag = release.tag;
    fixCreditText = `${credit.countedClosedCount} counted · ${credit.notCountedClosedCount} not counted · ${credit.analyzedClosedCount} analyzed`;
    break;
  }
}
if (!fixCreditTag) throw new Error('No release exposes releaseFixCredit for UI smoke');

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

  const fixPanel = await openScoreBreakdown(page, fixCreditTag);
  await fixPanel.getByText('Model', { exact: true }).waitFor();
  await fixPanel.getByText('Evidence coverage', { exact: true }).waitFor();
  await fixPanel.locator('.score-review__label').filter({ hasText: 'Release fix credit' }).first().waitFor();
  await fixPanel.getByText(fixCreditText).waitFor();
  await fixPanel
    .getByText('A closed issue only reduces release risk when its merged linked PR is reachable from this release tag.')
    .waitFor();

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
  await row.click();
  const panel = page.locator(`#det-${cssId(tag)}`);
  await panel.waitFor({ state: 'visible' });
  const summary = panel.locator('summary.evidence-toggle__summary', { hasText: 'Show score breakdown' });
  await summary.click();
  return panel;
}

function cssId(value) {
  return String(value).replace(/[^a-zA-Z0-9_-]/g, '_');
}
