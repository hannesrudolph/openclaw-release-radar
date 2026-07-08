import { createHash } from 'node:crypto';

export function canonicalManualScope({
  releaseTags = [],
  issueNumbers = [],
} = {}) {
  const payload = {
    schemaVersion: 1,
    releaseTags: [...new Set(releaseTags)]
      .filter((tag) => typeof tag === 'string' && tag.trim())
      .map((tag) => tag.trim())
      .sort(),
    issueNumbers: [...new Set(issueNumbers)]
      .filter((issueNumber) => Number.isInteger(issueNumber) && issueNumber > 0)
      .sort((left, right) => left - right),
  };
  const digest = createHash('sha256').update(JSON.stringify(payload)).digest('hex');
  return `manual-scope-v1:${digest}`;
}

export function manualScorePlan({
  selectedReleaseTags = [],
  monitoredReleaseTags = [],
  skipProof = false,
  skipScore = false,
} = {}) {
  if (skipScore) {
    return { status: 'staged-only', reason: 'score persistence was explicitly skipped' };
  }
  if (skipProof) {
    return { status: 'staged-only', reason: 'proof and reachability refresh was skipped' };
  }
  const selected = new Set(selectedReleaseTags);
  if (!monitoredReleaseTags.every((tag) => selected.has(tag))) {
    return {
      status: 'staged-only',
      reason: 'selected releases do not cover the complete monitored score window',
    };
  }
  return { status: 'full-window-commit', reason: null };
}

export function exactIngestionFailureMatches(failure, coordinate) {
  return failure?.source === coordinate.source &&
    nullable(failure?.scope) === nullable(coordinate.scope) &&
    nullable(failure?.release_tag) === nullable(coordinate.releaseTag) &&
    nullableInteger(failure?.issue_number) === nullableInteger(coordinate.issueNumber) &&
    nullable(failure?.pr_repository_name_with_owner) ===
      nullable(coordinate.prRepositoryNameWithOwner) &&
    nullableInteger(failure?.pr_number) === nullableInteger(coordinate.prNumber);
}

export function supersedeExactIngestionEvidenceFailures(database, {
  successfulRunId,
  supersededAt = new Date().toISOString(),
  source,
  scope = null,
  releaseTag = null,
  issueNumber = null,
  prRepositoryNameWithOwner = null,
  prNumber = null,
}) {
  if (!successfulRunId?.trim()) throw new Error('Successful ingestion run ID is required');
  if (!source?.trim()) throw new Error('Successful ingestion source is required');
  if (!Number.isFinite(Date.parse(supersededAt))) {
    throw new Error(`Invalid ingestion failure supersession timestamp ${supersededAt}`);
  }
  const result = database.prepare(`
    UPDATE ingestion_evidence_failures
    SET superseded_at=?,
        superseded_by_run_id=?
    WHERE scoring_blocking=1
      AND superseded_by_run_id IS NULL
      AND run_id != ?
      AND occurred_at <= ?
      AND source=?
      AND scope IS ?
      AND release_tag IS ?
      AND issue_number IS ?
      AND pr_repository_name_with_owner IS ?
      AND pr_number IS ?
  `).run(
    supersededAt,
    successfulRunId,
    successfulRunId,
    supersededAt,
    source,
    scope,
    releaseTag,
    issueNumber,
    prRepositoryNameWithOwner,
    prNumber,
  );
  return Number(result.changes ?? 0);
}

function nullable(value) {
  return value == null ? null : String(value);
}

function nullableInteger(value) {
  return Number.isInteger(value) ? Number(value) : null;
}
