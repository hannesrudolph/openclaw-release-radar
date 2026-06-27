import { chromium } from 'playwright';
import { saveComparisonSnapshot } from '../src/lib/db.ts';

const sourceUrl = process.argv[2] ?? 'https://isitstable.iclaw.digital/#/openclaw';

function numberOrNull(value) {
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function stringOrNull(value) {
  return typeof value === 'string' && value.length > 0 ? value : null;
}

async function main() {
  const browser = await chromium.launch({ headless: true });
  try {
    const page = await browser.newPage({ viewport: { width: 1440, height: 1200 } });
    await page.goto(sourceUrl, { waitUntil: 'networkidle' });
    await page.waitForSelector('#releases .release');
    await page.waitForTimeout(500);

    const rendered = await page.evaluate(() => {
      const numberOrNull = (value) =>
        typeof value === 'number' && Number.isFinite(value) ? value : null;
      const stringOrNull = (value) =>
        typeof value === 'string' && value.length > 0 ? value : null;
      const releases = typeof allReleases === 'object' && Array.isArray(allReleases)
        ? allReleases
        : [];
      const details = typeof publicReleaseDetails === 'object'
        ? publicReleaseDetails
        : new Map();
      const cardNodes = [...document.querySelectorAll('#releases .release')];
      const cardTextByTag = new Map(
        cardNodes.map((node) => [node.dataset.tag, node.innerText.trim()]),
      );

      return {
        pageTitle: document.title,
        pageText: document.body.innerText,
        releases: releases.map((release) => {
          const detail = details.get(release.tag);
          return {
            tag: release.tag,
            name: release.name ?? null,
            publishedAt: release.publishedAt ?? null,
            htmlUrl: release.htmlUrl,
            displayedDate: cardNodes
              .find((node) => node.dataset.tag === release.tag)
              ?.querySelector('.release__date')?.textContent?.trim() ?? null,
            score: numberOrNull(release.finalScore),
            band: stringOrNull(release.band),
            status: stringOrNull(release.status),
            recommended: release.recommended === true,
            reason: stringOrNull(release.reason),
            negativeIssues: numberOrNull(release.negativeIssues),
            positiveIssues: numberOrNull(release.positiveIssues),
            totalAttributedIssues: numberOrNull(detail?.totalAttributedIssues),
            visibleIssues: [
              ...(detail?.issues ?? []),
              ...(detail?.watchIssues ?? []),
            ],
            rawCardText: cardTextByTag.get(release.tag) ?? '',
          };
        }),
      };
    });

    const snapshotId = saveComparisonSnapshot({
      source_url: page.url(),
      captured_at: new Date().toISOString(),
      page_title: rendered.pageTitle,
      page_text: rendered.pageText,
      raw_html: await page.content(),
      releases: rendered.releases.map((release) => ({
        tag: release.tag,
        name: release.name,
        published_at: release.publishedAt,
        html_url: release.htmlUrl,
        displayed_date: release.displayedDate,
        score: release.score,
        band: release.band,
        status: release.status,
        recommended: release.recommended,
        reason: release.reason,
        negative_issues: release.negativeIssues,
        positive_issues: release.positiveIssues,
        total_attributed_issues: release.totalAttributedIssues,
        visible_issues: release.visibleIssues,
        raw_card_text: release.rawCardText,
      })),
    });

    console.log(JSON.stringify({
      snapshotId,
      sourceUrl: page.url(),
      pageTitle: rendered.pageTitle,
      releaseCount: rendered.releases.length,
      latest: rendered.releases[0] ?? null,
    }, null, 2));
  } finally {
    await browser.close();
  }
}

await main();
