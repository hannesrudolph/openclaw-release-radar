export function assessDataFreshnessHealth(freshness, latest, {
  maxIssueLagHours = 48,
} = {}) {
  const warnings = [];
  const failures = [];
  if (!freshness) return { warnings, failures };

  const tag = latest?.tag ?? freshness.tag ?? 'latest scored release';
  const scoredAt = freshness.scoredAt ?? latest?.scoredAt ?? null;
  const sourceFetchedAtMax = freshness.sourceFetchedAtMax ?? null;
  const issueUpdatedAtMax = freshness.issueUpdatedAtMax ?? null;

  if (isAfter(sourceFetchedAtMax, scoredAt)) {
    const newerSources = Array.isArray(freshness.sources)
      ? freshness.sources
        .filter((source) => isAfter(source?.maxAt, scoredAt))
        .map((source) => source.source)
        .filter(Boolean)
      : [];
    const suffix = newerSources.length ? ` (${newerSources.join(', ')})` : '';
    failures.push(`${tag}: source evidence changed after latest score${suffix}; rerun scoring after refresh completes`);
  }

  const requiredTimestampSources = new Set(['issue_fetches', 'release_rows']);
  if (Array.isArray(freshness.sources)) {
    for (const source of freshness.sources) {
      if (Number(source?.nullCount ?? 0) > 0) {
        failures.push(`${tag}: ${source.source} freshness has ${Number(source.nullCount)} row(s) without timestamp; rerun a complete refresh before trusting current score`);
      }
      if (!requiredTimestampSources.has(source?.source)) continue;
      if (Number(source.count ?? 0) > 0 && source.maxAt == null) {
        failures.push(`${tag}: ${source.source} freshness has ${Number(source.count ?? 0)} row(s) but no timestamp; run a freshness backfill or refresh before trusting current score`);
      }
    }
  }

  if (isAfter(issueUpdatedAtMax, scoredAt)) {
    failures.push(`${tag}: issue data includes updates after latest score; rerun scoring after refresh completes`);
  }

  if (Number(freshness.issueUpdatedAgeHoursAtScore ?? 0) > maxIssueLagHours) {
    warnings.push(`${tag}: issue data was ${freshness.issueUpdatedAgeHoursAtScore}h old at scoring time`);
  }
  if (Number(freshness.issueUpdatedAgeHoursNow ?? 0) > maxIssueLagHours) {
    warnings.push(`${tag}: latest issue data is ${freshness.issueUpdatedAgeHoursNow}h old now`);
  }

  return { warnings, failures };
}

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
  const classificationFailures = issueCrawl.classificationFailures;
  const crawlStartedAfterLatestScore = isAfter(startedAt, latestScoredAt);
  const crawlFinishedAfterLatestScore = isAfter(finishedAt, latestScoredAt);

  if (evidenceRefreshFailures != null && !Array.isArray(evidenceRefreshFailures)) {
    failures.push('issue crawl metadata evidenceRefreshFailures must be an array when present');
  }
  if (classificationFailures != null && !Array.isArray(classificationFailures)) {
    failures.push('issue crawl metadata classificationFailures must be an array when present');
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
    const message = `latest issue crawl recorded ${evidenceRefreshFailures.length} score-affecting evidence refresh failure(s); score persistence is unsafe until release checks, advisories, closure evidence, PR reachability, and closure proof all refresh cleanly`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that failed evidence refresh`);
    }
  }

  if (stopReason === 'evidence_failure' && !(Array.isArray(evidenceRefreshFailures) && evidenceRefreshFailures.length > 0)) {
    const message = 'latest issue crawl stopped during score-affecting evidence refresh; score persistence is unsafe until evidence refresh completes cleanly';
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that failed evidence refresh`);
    }
  }

  if (Array.isArray(classificationFailures) && classificationFailures.length > 0) {
    const message = `latest issue crawl recorded ${classificationFailures.length} issue classification failure(s); score persistence is unsafe until all score-attributed issues classify cleanly`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that failed classification pass`);
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

export function assessDurableIngestionEvidenceFailureHealth(durableFailures, latest) {
  const warnings = [];
  const failures = [];
  if (!durableFailures?.present) return { warnings, failures };
  const count = Number(durableFailures.blockingAfterLatestScoreCount ?? 0);
  if (count <= 0) return { warnings, failures };
  const tag = latest?.tag ?? 'latest scored release';
  const sources = durableFailures.bySource && typeof durableFailures.bySource === 'object'
    ? Object.entries(durableFailures.bySource)
      .map(([source, value]) => `${source}:${Number(value?.count ?? value ?? 0)}`)
      .join(', ')
    : '';
  const suffix = sources ? ` (${sources})` : '';
  warnings.push(`${tag}: ${count} durable score-affecting ingestion evidence failure(s) recorded after latest score${suffix}; rerun a clean refresh before trusting current ingestion health`);
  return { warnings, failures };
}

function isAfter(left, right) {
  if (!left || !right) return false;
  const leftMs = Date.parse(left);
  const rightMs = Date.parse(right);
  return Number.isFinite(leftMs) && Number.isFinite(rightMs) && leftMs > rightMs;
}
