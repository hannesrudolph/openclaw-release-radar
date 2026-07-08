import {
  getMeta,
  ingestionEvidenceFailuresAfter,
  listActiveIngestionEvidenceFailures as listRecentIngestionEvidenceFailures,
} from '../../src/lib/db.ts';
import { issueCrawlCompletenessProblems } from './doctor-health.mjs';

export function assertValidIssueCrawlMetadataBeforeMutation() {
  const failures = issueCrawlMetadataFailures();
  if (failures.length > 0) {
    throw new Error(
      `Refusing to mutate score evidence until issue crawl metadata is valid: ${failures.join('; ')}`,
    );
  }
}

export function assertCleanIngestionMetadataBeforeScore(releases, options = {}) {
  const failures = issueCrawlMetadataFailures();
  const issueCrawl = parsedIssueCrawlMetadata();
  if (issueCrawl) {
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
    const durableFailures = ingestionEvidenceFailuresAfter(latestScoredAt, 25)
      .filter((failure) => !options.ignoreFailure?.(failure));
    if (durableFailures.length > 0) {
      failures.push(`${durableFailures.length} durable ingestion evidence failure(s) recorded after latest score`);
    }
  } else {
    const durableFailures = listRecentIngestionEvidenceFailures(25)
      .filter((failure) => !options.ignoreFailure?.(failure));
    if (durableFailures.length > 0) {
      failures.push(`${durableFailures.length} durable ingestion evidence failure(s) recorded before first score`);
    }
  }
  if (failures.length > 0) {
    throw new Error(`Refusing to persist scores until ingestion metadata is clean: ${failures.join('; ')}`);
  }
}

function issueCrawlMetadataFailures() {
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
    const rawBaseline = getMeta('issue_crawl_exhaustive_baseline');
    const baseline = rawBaseline ? parseJson(rawBaseline, rawBaseline) : null;
    for (const problem of issueCrawlCompletenessProblems(issueCrawl, { baseline })) {
      failures.push(`issue crawl completeness metadata is invalid: ${problem}`);
    }
  }
  return failures;
}

function parsedIssueCrawlMetadata() {
  const raw = getMeta('issue_crawl_last_run');
  return raw ? parseJson(raw, null) : null;
}

function parseJson(value, fallback) {
  try {
    return JSON.parse(value);
  } catch {
    return fallback;
  }
}
