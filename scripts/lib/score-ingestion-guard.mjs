import {
  getMeta,
  ingestionEvidenceFailuresAfter,
} from '../../src/lib/db.ts';

export function assertCleanIngestionMetadataBeforeScore(releases) {
  const failures = [];
  const rawIssueCrawl = getMeta('issue_crawl_last_run');
  if (!rawIssueCrawl) {
    failures.push('issue crawl metadata is missing');
  }
  const issueCrawl = rawIssueCrawl ? parseJson(rawIssueCrawl, null) : null;
  if (rawIssueCrawl && !issueCrawl) {
    failures.push('issue crawl metadata is malformed JSON');
  }
  if (issueCrawl) {
    if (issueCrawl.schemaVersion !== 1) failures.push(`issue crawl metadata schemaVersion is ${issueCrawl.schemaVersion}`);
    if (issueCrawl.stopReason === 'page_cap') failures.push('latest issue crawl hit MAX_ISSUE_PAGES');
    if (issueCrawl.stopReason === 'evidence_failure') failures.push('latest issue crawl stopped during evidence refresh');
    if (issueCrawl.evidenceRefreshFailures != null && !Array.isArray(issueCrawl.evidenceRefreshFailures)) {
      failures.push('issue crawl metadata evidenceRefreshFailures is not an array');
    } else if (Array.isArray(issueCrawl.evidenceRefreshFailures) && issueCrawl.evidenceRefreshFailures.length > 0) {
      failures.push(`latest issue crawl has ${issueCrawl.evidenceRefreshFailures.length} evidence refresh failure(s)`);
    }
    if (issueCrawl.classificationFailures != null && !Array.isArray(issueCrawl.classificationFailures)) {
      failures.push('issue crawl metadata classificationFailures is not an array');
    } else if (Array.isArray(issueCrawl.classificationFailures) && issueCrawl.classificationFailures.length > 0) {
      failures.push(`latest issue crawl has ${issueCrawl.classificationFailures.length} classification failure(s)`);
    }
  }
  const latestScoredAt = releases
    .map((release) => release.scored_at)
    .filter((scoredAt) => typeof scoredAt === 'string' && Number.isFinite(Date.parse(scoredAt)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0];
  if (latestScoredAt) {
    const durableFailures = ingestionEvidenceFailuresAfter(latestScoredAt, 5);
    if (durableFailures.length > 0) {
      failures.push(`${durableFailures.length} durable ingestion evidence failure(s) recorded after latest score`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`Refusing to persist scores until ingestion metadata is clean: ${failures.join('; ')}`);
  }
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
