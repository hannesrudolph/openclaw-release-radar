export const SCORE_AUDIT_TOP_LEVEL_KEYS = {
  input: [
    'artifactMismatch',
    'artifactVerified',
    'betaCount',
    'breakingCount',
    'carryoverDebtIssueCount',
    'carryoverDebtWeight',
    'ciReportMismatch',
    'ciReportVerified',
    'classifiedIssueCount',
    'cveAffected',
    'cveLoad',
    'feltClosedWeight',
    'feltOpenedWeight',
    'hasHotfixSuccessor',
    'hoursToNextStable',
    'isLatest',
    'publishedAt',
    'rawIssueCount',
    'releaseCheckFailure',
    'releaseCheckPending',
    'releaseCheckState',
    'releaseCheckSuccess',
    'releaseCheckTotal',
    'releaseIntegrityPresent',
    'releaseShaMatches',
    'schemaVersion',
    'staleDebtIssueCount',
    'staleDebtWeight',
    'unresolvedClosureIssueCount',
    'unresolvedClosureRiskWeight',
    'verifiedDebtIssueCount',
    'verifiedDebtWeight',
  ],
  components: ['schemaVersion', 'components', 'evidenceCoverage', 'hotfix', 'reason', 'explanation'],
  issueEvidence: [
    'schemaVersion',
    'debtSummary',
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'openedFeltSerious',
    'verifiedFixed',
    'unverifiedClosed',
    'unclassifiedIssues',
  ],
  gateEvidence: [
    'schemaVersion',
    'cve',
    'stableTagsNewestFirst',
    'betaCount',
    'breakingCount',
    'hoursToNextStable',
    'hasHotfixSuccessor',
    'releaseChecks',
    'artifactVerification',
    'labelTimeline',
    'fixProvenance',
  ],
};

export function verifyScoreAuditPayloadContracts({
  tag,
  input,
  components,
  issueEvidence,
  gateEvidence,
  versions,
}) {
  const failures = [];
  verifyPayload({
    failures,
    tag,
    label: 'score input',
    payload: input,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.input,
    expectedSchemaVersion: versions.scoreInput,
  });
  verifyPayload({
    failures,
    tag,
    label: 'score components',
    payload: components,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.components,
    expectedSchemaVersion: versions.scoreComponents,
  });
  verifyPayload({
    failures,
    tag,
    label: 'issue evidence',
    payload: issueEvidence,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.issueEvidence,
    expectedSchemaVersion: versions.issueEvidence,
  });
  verifyPayload({
    failures,
    tag,
    label: 'gate evidence',
    payload: gateEvidence,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.gateEvidence,
    expectedSchemaVersion: versions.gateEvidence,
  });
  return failures;
}

function verifyPayload({
  failures,
  tag,
  label,
  payload,
  allowedKeys,
  expectedSchemaVersion,
}) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
    failures.push(`${tag}: ${label} payload must be an object`);
    return;
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(payload).sort()) {
    if (!allowed.has(key)) failures.push(`${tag}: ${label} payload has unexpected top-level key ${key}`);
  }
  if (payload.schemaVersion !== expectedSchemaVersion) {
    failures.push(`${tag}: ${label} schemaVersion (${payload.schemaVersion}) must equal ${expectedSchemaVersion}`);
  }
}
