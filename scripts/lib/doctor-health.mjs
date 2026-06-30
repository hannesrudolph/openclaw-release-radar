export function assessIssueCrawlHealth(issueCrawl, latest) {
  const warnings = [];
  const failures = [];
  if (!issueCrawl) {
    if (latest?.scoredAt) {
      const tag = latest?.tag ? `${latest.tag}: ` : '';
      warnings.push(`${tag}latest scored release has no issue crawl metadata; run a clean refresh before trusting current score freshness`);
    }
    return { warnings, failures };
  }

  if (issueCrawl.schemaVersion !== 1) {
    failures.push(`issue crawl metadata schemaVersion (${issueCrawl.schemaVersion}) must equal 1`);
  }

  const stopReason = issueCrawl.stopReason ?? 'unknown';
  const latestScoredAt = latest?.scoredAt ?? null;
  const startedAt = issueCrawl.startedAt ?? null;
  const finishedAt = issueCrawl.finishedAt ?? null;
  const scorePersisted = issueCrawl.scorePersisted === true;
  const evidenceRefreshFailures = issueCrawl.evidenceRefreshFailures;
  const crawlStartedAfterLatestScore = isAfter(startedAt, latestScoredAt);
  const crawlFinishedAfterLatestScore = isAfter(finishedAt, latestScoredAt);

  if (evidenceRefreshFailures != null && !Array.isArray(evidenceRefreshFailures)) {
    failures.push('issue crawl metadata evidenceRefreshFailures must be an array when present');
  }

  if (stopReason === 'page_cap') {
    const message = `latest issue crawl hit page cap after ${Number(issueCrawl.pagesFetched ?? 0)} page(s); score persistence is unsafe until a complete crawl runs`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that incomplete crawl`);
    }
  }

  if (Array.isArray(evidenceRefreshFailures) && evidenceRefreshFailures.length > 0) {
    const message = `latest issue crawl recorded ${evidenceRefreshFailures.length} monitored-release evidence refresh failure(s); score persistence is unsafe until closure evidence, PR reachability, and closure proof all refresh cleanly`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that failed evidence refresh`);
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
