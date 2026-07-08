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

  if (scoredAt != null && !isTimestamp(scoredAt)) {
    failures.push(`${tag}: score freshness scoredAt is not a valid timestamp: ${scoredAt}`);
  }
  if (sourceFetchedAtMax != null && !isTimestamp(sourceFetchedAtMax)) {
    failures.push(`${tag}: sourceFetchedAtMax is not a valid timestamp: ${sourceFetchedAtMax}`);
  }
  if (issueUpdatedAtMax != null && !isTimestamp(issueUpdatedAtMax)) {
    failures.push(`${tag}: issueUpdatedAtMax is not a valid timestamp: ${issueUpdatedAtMax}`);
  }

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
      if (Number(source?.count ?? 0) > 0 && source.maxAt != null && !isTimestamp(source.maxAt)) {
        failures.push(`${tag}: ${source.source} freshness maxAt is not a valid timestamp: ${source.maxAt}`);
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

export function issueCrawlBaselineProblems(baseline, {
  repository = null,
} = {}) {
  const problems = [];
  if (!baseline || typeof baseline !== 'object' || Array.isArray(baseline)) {
    return ['baseline must be an object'];
  }
  if (baseline.schemaVersion !== 2) problems.push('baseline schemaVersion must equal 2');
  if (baseline.source !== 'github.repository.issues') {
    problems.push('baseline source must equal github.repository.issues');
  }
  if (typeof baseline.repository !== 'string' || baseline.repository.length === 0) {
    problems.push('baseline repository must be a non-empty string');
  } else if (repository != null && baseline.repository !== repository) {
    problems.push(`baseline repository must equal ${repository}`);
  }
  if (baseline.sourceOrder !== 'CREATED_AT_ASC') {
    problems.push('baseline sourceOrder must equal CREATED_AT_ASC');
  }
  if (!isTimestamp(baseline.establishedAt)) {
    problems.push('baseline establishedAt must be a valid timestamp');
  }
  if (!isTimestamp(baseline.crawlStartedAt)) {
    problems.push('baseline crawlStartedAt must be a valid timestamp');
  }
  for (const field of [
    'boundaryTotalCount',
    'observedTotalCount',
    'postBoundaryGrowthCount',
    'fetchedCount',
    'uniqueCount',
    'pageCount',
    'pagesFetched',
    'sweepCount',
  ]) {
    if (!Number.isInteger(baseline[field]) || baseline[field] < 0) {
      problems.push(`baseline ${field} must be a non-negative integer`);
    }
  }
  if (
    Number.isInteger(baseline.boundaryTotalCount) &&
    (
      baseline.fetchedCount !== baseline.boundaryTotalCount ||
      baseline.uniqueCount !== baseline.boundaryTotalCount
    )
  ) {
    problems.push('baseline fetchedCount and uniqueCount must equal boundaryTotalCount');
  }
  if (
    Number.isInteger(baseline.boundaryTotalCount) &&
    Number.isInteger(baseline.observedTotalCount) &&
    baseline.observedTotalCount < baseline.boundaryTotalCount
  ) {
    problems.push('baseline observedTotalCount cannot be less than boundaryTotalCount');
  }
  if (
    Number.isInteger(baseline.boundaryTotalCount) &&
    Number.isInteger(baseline.observedTotalCount) &&
    Number.isInteger(baseline.postBoundaryGrowthCount) &&
    baseline.postBoundaryGrowthCount !==
      baseline.observedTotalCount - baseline.boundaryTotalCount
  ) {
    problems.push(
      'baseline postBoundaryGrowthCount must equal observedTotalCount minus boundaryTotalCount',
    );
  }
  if (!Number.isInteger(baseline.sweepCount) || baseline.sweepCount < 2) {
    problems.push('baseline sweepCount must be at least 2');
  }
  if (!isSha256(baseline.digest)) {
    problems.push('baseline digest must be a lowercase SHA-256 hex string');
  }
  if (!isSha256(baseline.membershipDigest)) {
    problems.push('baseline membershipDigest must be a lowercase SHA-256 hex string');
  }
  if (!isSha256(baseline.contentDigest)) {
    problems.push('baseline contentDigest must be a lowercase SHA-256 hex string');
  }
  if (
    isSha256(baseline.digest) &&
    isSha256(baseline.membershipDigest) &&
    baseline.digest !== baseline.membershipDigest
  ) {
    problems.push('baseline digest must equal membershipDigest');
  }
  const boundary = baseline.asOfBoundary;
  if (!boundary || typeof boundary !== 'object' || Array.isArray(boundary)) {
    problems.push('baseline asOfBoundary must be an object');
  } else {
    if (!Number.isInteger(boundary.totalCount) || boundary.totalCount < 0) {
      problems.push('baseline asOfBoundary.totalCount must be a non-negative integer');
    }
    if (boundary.totalCount !== baseline.boundaryTotalCount) {
      problems.push('baseline asOfBoundary.totalCount must equal boundaryTotalCount');
    }
    if (!isSha256(boundary.membershipDigest)) {
      problems.push(
        'baseline asOfBoundary.membershipDigest must be a lowercase SHA-256 hex string',
      );
    } else if (boundary.membershipDigest !== baseline.membershipDigest) {
      problems.push('baseline asOfBoundary.membershipDigest must equal membershipDigest');
    }
    if (boundary.totalCount === 0 && boundary.terminalIssue !== null) {
      problems.push('baseline asOfBoundary.terminalIssue must be null for an empty boundary');
    }
    if (boundary.totalCount > 0) {
      const terminal = boundary.terminalIssue;
      if (!terminal || typeof terminal !== 'object' || Array.isArray(terminal)) {
        problems.push('baseline asOfBoundary.terminalIssue must identify the terminal issue');
      } else {
        if (typeof terminal.nodeId !== 'string' || terminal.nodeId.length === 0) {
          problems.push(
            'baseline asOfBoundary.terminalIssue.nodeId must be a non-empty string',
          );
        }
        if (!Number.isInteger(terminal.issueNumber) || terminal.issueNumber <= 0) {
          problems.push(
            'baseline asOfBoundary.terminalIssue.issueNumber must be a positive integer',
          );
        }
        if (!isTimestamp(terminal.createdAt)) {
          problems.push(
            'baseline asOfBoundary.terminalIssue.createdAt must be a valid timestamp',
          );
        }
      }
    }
  }
  if (!isSha256(baseline.identity)) {
    problems.push('baseline identity must be a lowercase SHA-256 hex string');
  } else if (
    typeof baseline.repository === 'string' &&
    typeof baseline.sourceOrder === 'string' &&
    boundary &&
    typeof boundary === 'object' &&
    !Array.isArray(boundary)
  ) {
    const expectedIdentity = createHash('sha256')
      .update(JSON.stringify([
        baseline.repository,
        baseline.sourceOrder,
        boundary.totalCount,
        boundary.terminalIssue?.nodeId ?? null,
        boundary.terminalIssue?.issueNumber ?? null,
        boundary.terminalIssue?.createdAt ?? null,
        boundary.membershipDigest,
      ]))
      .digest('hex');
    if (baseline.identity !== expectedIdentity) {
      problems.push(
        'baseline identity does not match repository, source order, and immutable as-of boundary',
      );
    }
  }
  return problems;
}

export function issueCrawlCompletenessProblems(issueCrawl, {
  baseline: storedBaseline = null,
  repository = null,
} = {}) {
  const problems = [];
  if (!issueCrawl || typeof issueCrawl !== 'object' || Array.isArray(issueCrawl)) {
    return ['issue crawl metadata must be an object'];
  }
  if (issueCrawl.schemaVersion !== 4) {
    problems.push('issue crawl schemaVersion must equal 4');
  }
  const expectedRepository =
    repository ?? storedBaseline?.repository ?? issueCrawl.baseline?.repository ?? null;
  if (
    typeof issueCrawl.repository !== 'string' ||
    issueCrawl.repository.length === 0
  ) {
    problems.push('issue crawl repository must be a non-empty string');
  } else if (
    expectedRepository != null &&
    issueCrawl.repository !== expectedRepository
  ) {
    problems.push(`issue crawl repository must equal ${expectedRepository}`);
  }
  const stopReason = issueCrawl.stopReason ?? 'unknown';
  if (!['exhausted', 'early_stop', 'page_cap', 'evidence_failure'].includes(stopReason)) {
    problems.push(`unsupported stopReason ${String(stopReason)}`);
  }
  const pagination = issueCrawl.pagination;
  if (pagination == null) {
    if (stopReason === 'exhausted' || stopReason === 'early_stop') {
      problems.push(`${stopReason} crawl must include pagination metadata`);
    }
    return problems;
  }
  if (typeof pagination !== 'object' || Array.isArray(pagination)) {
    problems.push('pagination must be an object');
    return problems;
  }
  if (pagination.schemaVersion !== 2) problems.push('pagination schemaVersion must equal 2');
  if (pagination.source !== 'github.repository.issues') {
    problems.push('pagination source must equal github.repository.issues');
  }
  if (typeof pagination.repository !== 'string' || pagination.repository.length === 0) {
    problems.push('pagination repository must be a non-empty string');
  } else if (
    expectedRepository != null &&
    pagination.repository !== expectedRepository
  ) {
    problems.push(`pagination repository must equal ${expectedRepository}`);
  }
  for (const field of ['fetchedCount', 'uniqueCount', 'pageCount', 'pagesFetched', 'sweepCount']) {
    if (!Number.isInteger(pagination[field]) || pagination[field] < 0) {
      problems.push(`pagination ${field} must be a non-negative integer`);
    }
  }
  if (
    Number.isInteger(pagination.fetchedCount) &&
    Number.isInteger(pagination.uniqueCount) &&
    pagination.fetchedCount !== pagination.uniqueCount
  ) {
    problems.push('pagination fetchedCount must equal uniqueCount');
  }
  if (
    Number.isInteger(pagination.pageCount) &&
    Number.isInteger(pagination.pagesFetched) &&
    pagination.pagesFetched < pagination.pageCount
  ) {
    problems.push('pagination pagesFetched cannot be less than pageCount');
  }

  const embeddedBaseline = issueCrawl.baseline;
  const embeddedBaselineProblems = issueCrawlBaselineProblems(embeddedBaseline, {
    repository: expectedRepository,
  });
  const storedBaselineProblems = issueCrawlBaselineProblems(storedBaseline, {
    repository: expectedRepository,
  });
  const baselineRequired = stopReason === 'exhausted' || stopReason === 'early_stop';
  if (baselineRequired) {
    problems.push(...embeddedBaselineProblems.map((problem) => `embedded ${problem}`));
    problems.push(...storedBaselineProblems.map((problem) => `stored ${problem}`));
    if (
      embeddedBaselineProblems.length === 0 &&
      storedBaselineProblems.length === 0 &&
      (
        embeddedBaseline.identity !== storedBaseline.identity ||
        embeddedBaseline.repository !== storedBaseline.repository ||
        JSON.stringify(embeddedBaseline.asOfBoundary) !==
          JSON.stringify(storedBaseline.asOfBoundary)
      )
    ) {
      problems.push('embedded baseline does not match stored exhaustive baseline');
    }
  }

  if (
    embeddedBaselineProblems.length === 0 &&
    pagination.repository !== embeddedBaseline.repository
  ) {
    problems.push('pagination repository must match exhaustive baseline repository');
  }
  if (embeddedBaselineProblems.length === 0) {
    if (pagination.boundaryTotalCount !== embeddedBaseline.boundaryTotalCount) {
      problems.push('pagination boundaryTotalCount must match exhaustive baseline');
    }
    if (
      JSON.stringify(pagination.asOfBoundary) !==
      JSON.stringify(embeddedBaseline.asOfBoundary)
    ) {
      problems.push('pagination asOfBoundary must match exhaustive baseline');
    }
    if (
      !Number.isInteger(pagination.observedTotalCount) ||
      pagination.observedTotalCount < embeddedBaseline.boundaryTotalCount
    ) {
      problems.push('pagination observedTotalCount cannot be below exhaustive boundary');
    } else if (
      pagination.postBoundaryGrowthCount !==
      pagination.observedTotalCount - embeddedBaseline.boundaryTotalCount
    ) {
      problems.push(
        'pagination postBoundaryGrowthCount must equal observedTotalCount minus boundaryTotalCount',
      );
    }
  }

  if (stopReason === 'exhausted' && issueCrawl.crawlMode === 'exhaustive') {
    if (pagination.completeness !== 'exhaustive_stable') {
      problems.push('exhaustive pagination completeness must equal exhaustive_stable');
    }
    if (pagination.sourceOrder !== 'CREATED_AT_ASC') {
      problems.push('exhaustive pagination sourceOrder must equal CREATED_AT_ASC');
    }
    if (pagination.exhausted !== true) problems.push('exhausted pagination must set exhausted=true');
    if (pagination.stabilized !== true) problems.push('exhausted pagination must set stabilized=true');
    if (pagination.hasNextPage !== false) problems.push('exhausted pagination must set hasNextPage=false');
    if (pagination.nextCursor !== null) problems.push('exhausted pagination nextCursor must be null');
    if (
      !isSha256(pagination.membershipDigest) ||
      pagination.digest !== pagination.membershipDigest
    ) {
      problems.push('exhaustive pagination digest must equal membershipDigest');
    }
    if (!isSha256(pagination.contentDigest)) {
      problems.push(
        'exhaustive pagination contentDigest must be a lowercase SHA-256 hex string',
      );
    }
    if (!Number.isInteger(pagination.sweepCount) || pagination.sweepCount < 2) {
      problems.push('exhausted pagination sweepCount must be at least 2');
    }
    if (
      embeddedBaselineProblems.length === 0 &&
      pagination.fetchedCount !== embeddedBaseline.boundaryTotalCount
    ) {
      problems.push('exhaustive pagination fetchedCount must equal boundaryTotalCount');
    }
    if (
      embeddedBaselineProblems.length === 0 &&
      (
        embeddedBaseline.membershipDigest !== pagination.membershipDigest ||
        embeddedBaseline.contentDigest !== pagination.contentDigest
      )
    ) {
      problems.push('exhausted pagination does not match its established baseline');
    }
  } else if (stopReason === 'exhausted' && issueCrawl.crawlMode === 'incremental') {
    if (pagination.completeness !== 'incremental_exhaustive') {
      problems.push(
        'naturally exhausted incremental pagination completeness must equal incremental_exhaustive',
      );
    }
    if (pagination.sourceOrder !== 'UPDATED_AT_DESC') {
      problems.push(
        'naturally exhausted incremental pagination sourceOrder must equal UPDATED_AT_DESC',
      );
    }
    if (pagination.exhausted !== true) {
      problems.push('naturally exhausted incremental pagination must set exhausted=true');
    }
    if (pagination.stabilized !== false) {
      problems.push('naturally exhausted incremental pagination must set stabilized=false');
    }
    if (pagination.hasNextPage !== false || pagination.nextCursor !== null) {
      problems.push('naturally exhausted incremental pagination must have no next cursor');
    }
    if (pagination.fetchedCount !== pagination.observedTotalCount) {
      problems.push(
        'naturally exhausted incremental fetchedCount must equal observedTotalCount',
      );
    }
    if (
      !isSha256(pagination.membershipDigest) ||
      pagination.digest !== pagination.membershipDigest
    ) {
      problems.push(
        'naturally exhausted incremental pagination digest must equal membershipDigest',
      );
    }
    if (!isSha256(pagination.contentDigest)) {
      problems.push(
        'naturally exhausted incremental contentDigest must be a lowercase SHA-256 hex string',
      );
    }
    if (pagination.sweepCount !== 1) {
      problems.push('naturally exhausted incremental pagination sweepCount must equal 1');
    }
  } else if (stopReason === 'exhausted') {
    problems.push(`exhausted crawlMode must be exhaustive or incremental`);
  }

  if (stopReason === 'early_stop') {
    if (issueCrawl.crawlMode !== 'incremental') problems.push('early_stop crawlMode must equal incremental');
    if (issueCrawl.fullIssueBackfill === true) problems.push('full issue backfill cannot stop early');
    if (pagination.completeness !== 'incremental_partial') {
      problems.push('early_stop pagination completeness must equal incremental_partial');
    }
    if (pagination.sourceOrder !== 'UPDATED_AT_DESC') {
      problems.push('early_stop pagination sourceOrder must equal UPDATED_AT_DESC');
    }
    if (pagination.exhausted !== false) problems.push('early_stop pagination must set exhausted=false');
    if (pagination.stabilized !== false) problems.push('early_stop pagination must set stabilized=false');
    if (pagination.hasNextPage !== true) problems.push('early_stop pagination must set hasNextPage=true');
    if (typeof pagination.nextCursor !== 'string' || pagination.nextCursor.length === 0) {
      problems.push('early_stop pagination nextCursor must be a non-empty string');
    }
    if (
      pagination.digest !== null ||
      pagination.membershipDigest !== null ||
      pagination.contentDigest !== null
    ) {
      problems.push('early_stop pagination digests must be null');
    }
    if (pagination.sweepCount !== 1) problems.push('early_stop pagination sweepCount must equal 1');
    if (
      Number.isInteger(pagination.observedTotalCount) &&
      Number.isInteger(pagination.fetchedCount) &&
      pagination.fetchedCount >= pagination.observedTotalCount
    ) {
      problems.push('early_stop pagination fetchedCount must be less than observedTotalCount');
    }
  }

  if (
    (stopReason === 'exhausted' || stopReason === 'early_stop') &&
    issueCrawl.backfillCompleteAfterRun !== true
  ) {
    problems.push(`${stopReason} crawl must retain a proven exhaustive baseline`);
  }
  if (
    issueCrawl.scorePersisted === true &&
    stopReason !== 'exhausted' &&
    stopReason !== 'early_stop'
  ) {
    problems.push(`scorePersisted cannot be true for stopReason ${stopReason}`);
  }
  if (issueCrawl.scorePersisted === true) {
    if (!(stopReason === 'exhausted' && issueCrawl.crawlMode === 'exhaustive')) {
      problems.push('score persistence requires an exhaustive stabilized issue crawl');
    }
    if (pagination.postBoundaryGrowthCount !== 0) {
      problems.push('score persistence requires zero issue-catalog post-boundary growth');
    }
    if (
      Array.isArray(issueCrawl.evidenceRefreshFailures) &&
      issueCrawl.evidenceRefreshFailures.length > 0
    ) {
      problems.push('evidenceRefreshFailures must be empty before score persistence');
    }
    if (
      Array.isArray(issueCrawl.classificationFailures) &&
      issueCrawl.classificationFailures.length > 0
    ) {
      problems.push('classificationFailures must be empty before score persistence');
    }

    const snapshot = issueCrawl.catalogSnapshot;
    if (!snapshot || typeof snapshot !== 'object' || Array.isArray(snapshot)) {
      problems.push('catalogSnapshot must be an object before score persistence');
    } else {
      if (snapshot.schemaVersion !== 1) {
        problems.push('catalogSnapshot schemaVersion must equal 1');
      }
      if (!isSha256(snapshot.snapshotId) || snapshot.snapshotId !== snapshot.contentHash) {
        problems.push('catalogSnapshot snapshotId/contentHash must be the same SHA-256');
      }
      if (!isTimestamp(snapshot.capturedAt)) {
        problems.push('catalogSnapshot capturedAt must be a valid timestamp');
      }
      if (typeof snapshot.resumed !== 'boolean') {
        problems.push('catalogSnapshot resumed must be boolean');
      }
      if (
        !['missing', 'invalid', 'stale', 'consumed', 'resumable'].includes(
          snapshot.priorStatus,
        )
      ) {
        problems.push('catalogSnapshot priorStatus is invalid');
      }
      if (snapshot.resumed !== (snapshot.priorStatus === 'resumable')) {
        problems.push('catalogSnapshot resumed must match priorStatus resumable');
      }
      if (!Number.isInteger(snapshot.maxAgeHours) || snapshot.maxAgeHours <= 0) {
        problems.push('catalogSnapshot maxAgeHours must be a positive integer');
      }
      if (!isTimestamp(snapshot.consumedAt)) {
        problems.push('catalogSnapshot consumedAt must be a valid timestamp');
      }
      if (
        typeof snapshot.consumedByRunId !== 'string' ||
        snapshot.consumedByRunId.length === 0
      ) {
        problems.push('catalogSnapshot consumedByRunId must be non-empty');
      }
      if (!isSha256(snapshot.consumptionContentHash)) {
        problems.push('catalogSnapshot consumptionContentHash must be SHA-256');
      }
    }

    const attestation = issueCrawl.catalogAttestation;
    if (!attestation || typeof attestation !== 'object' || Array.isArray(attestation)) {
      problems.push('catalogAttestation must be an object before score persistence');
    } else {
      if (attestation.schemaVersion !== 1) {
        problems.push('catalogAttestation schemaVersion must equal 1');
      }
      if (
        !snapshot ||
        attestation.snapshotId !== snapshot.snapshotId ||
        attestation.snapshotContentHash !== snapshot.contentHash
      ) {
        problems.push('catalogAttestation must bind the consumed catalog snapshot');
      }
      if (!isTimestamp(attestation.observedAt)) {
        problems.push('catalogAttestation observedAt must be a valid timestamp');
      } else if (
        snapshot &&
        isTimestamp(snapshot.consumedAt) &&
        Date.parse(attestation.observedAt) < Date.parse(snapshot.consumedAt)
      ) {
        problems.push('catalogAttestation cannot predate snapshot consumption');
      }
      if (attestation.totalCount !== pagination.boundaryTotalCount) {
        problems.push('catalogAttestation totalCount must match exhaustive pagination');
      }
      if (attestation.membershipDigest !== pagination.membershipDigest) {
        problems.push('catalogAttestation membershipDigest must match exhaustive pagination');
      }
      if (attestation.contentDigest !== pagination.contentDigest) {
        problems.push('catalogAttestation contentDigest must match exhaustive pagination');
      }
      if (
        !Number.isInteger(attestation.finalSweepCount) ||
        attestation.finalSweepCount < 2
      ) {
        problems.push('catalogAttestation finalSweepCount must be at least 2');
      }
      if (
        !Number.isInteger(attestation.finalPagesFetched) ||
        attestation.finalPagesFetched < attestation.finalSweepCount
      ) {
        problems.push('catalogAttestation finalPagesFetched must cover every final sweep');
      }
    }
  }
  return problems;
}

export function assessIssueCrawlHealth(issueCrawl, latest, {
  baseline = null,
  repository = null,
} = {}) {
  const warnings = [];
  const failures = [];
  if (!issueCrawl) {
    if (latest?.scoredAt) {
      const tag = latest?.tag ? `${latest.tag}: ` : '';
      warnings.push(`${tag}latest scored release has no issue crawl metadata; run a clean refresh before trusting current score freshness`);
    }
    return { warnings, failures };
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
  const completenessProblems = issueCrawlCompletenessProblems(issueCrawl, {
    baseline,
    repository,
  });
  for (const problem of completenessProblems) {
    const message = `issue crawl completeness metadata is invalid: ${problem}`;
    if (scorePersisted || !crawlStartedAfterLatestScore) {
      failures.push(message);
    } else {
      warnings.push(`${message}; current score predates that crawl`);
    }
  }

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
    const message = `latest issue crawl recorded ${evidenceRefreshFailures.length} score-affecting evidence refresh failure(s); score persistence is unsafe until release metadata, artifact verification, release checks, advisories, closure evidence, PR reachability, and closure proof all refresh cleanly`;
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

function isTimestamp(value) {
  return typeof value === 'string' && Number.isFinite(Date.parse(value));
}

function isSha256(value) {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
}
import { createHash } from 'node:crypto';
