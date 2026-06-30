export function assessIssueCrawlHealth(issueCrawl, latest) {
  const warnings = [];
  const failures = [];
  if (!issueCrawl) return { warnings, failures };

  if (issueCrawl.schemaVersion !== 1) {
    failures.push(`issue crawl metadata schemaVersion (${issueCrawl.schemaVersion}) must equal 1`);
  }

  const stopReason = issueCrawl.stopReason ?? 'unknown';
  const latestScoredAt = latest?.scoredAt ?? null;
  const startedAt = issueCrawl.startedAt ?? null;
  const finishedAt = issueCrawl.finishedAt ?? null;
  const scorePersisted = issueCrawl.scorePersisted === true;
  const crawlStartedAfterLatestScore = isAfter(startedAt, latestScoredAt);
  const crawlFinishedAfterLatestScore = isAfter(finishedAt, latestScoredAt);

  if (stopReason === 'page_cap') {
    const message = `latest issue crawl hit page cap after ${Number(issueCrawl.pagesFetched ?? 0)} page(s); score persistence is unsafe until a complete crawl runs`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that incomplete crawl`);
    }
  }

  if (issueCrawl.backfillCompleteAfterRun === false) {
    warnings.push('latest issue crawl did not mark issue backfill complete');
  }

  if (!scorePersisted && stopReason !== 'page_cap' && crawlFinishedAfterLatestScore) {
    warnings.push('latest issue crawl finished after the latest score without persisting a new score');
  }

  return { warnings, failures };
}

function isAfter(left, right) {
  if (!left || !right) return false;
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs > rightMs;
}
