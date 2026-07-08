// @ts-nocheck

import {
  installConfidence,
  SCORE_LEDGER_SCHEMA_VERSION,
  SCORE_LEDGER_TYPE,
  scoreExplanationAuditProblems,
  scoreLedgerV2Problems,
} from './score.ts';
import { canonicalJson } from './operationReceipts.ts';
import {
  buildReleaseArtifactObservation,
  buildReleaseArtifactReceipt,
} from './releaseArtifactReceipt.ts';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION as ARTIFACT_EVIDENCE_SCHEMA_VERSION,
} from './artifactVerification.ts';

export const SCORE_AUDIT_TOP_LEVEL_KEYS = {
  input: [
    'affirmativeClosureRiskCeilingWeight',
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
  components: ['schemaVersion', 'components', 'evidenceCoverage', 'hotfix', 'reason', 'explanation', 'recommendationDecision'],
  issueEvidence: [
    'schemaVersion',
    'evidenceCounts',
    'targetEvidenceAttribution',
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

export const RECOMMENDATION_DECISION_KEYS = [
  'schemaVersion',
  'policyCode',
  'threshold',
  'recencyTolerance',
  'selectedTag',
  'selectedScore',
  'highestScoringTag',
  'highestScore',
  'releaseTag',
  'releaseScore',
  'qualifies',
  'selected',
  'recencyRank',
  'scoreRank',
  'scoreDeltaToHighest',
  'decisionCode',
  'summary',
];

export const SCORE_AUDIT_REQUIRED_KEYS = {
  input: [
    'affirmativeClosureRiskCeilingWeight',
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
    'schemaVersion',
    'staleDebtIssueCount',
    'staleDebtWeight',
    'unresolvedClosureIssueCount',
    'unresolvedClosureRiskWeight',
    'verifiedDebtIssueCount',
    'verifiedDebtWeight',
  ],
  components: [
    'schemaVersion',
    'components',
    'evidenceCoverage',
    'hotfix',
    'reason',
    'explanation',
    'recommendationDecision',
  ],
  installComponents: [
    'base',
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'closureRisk',
    'closureRiskCeiling',
    'coverage',
    'survival',
    'shakeout',
    'regression',
    'breaking',
    'releaseVerification',
    'artifactVerification',
  ],
  issueEvidence: [
    'schemaVersion',
    'evidenceCounts',
    'targetEvidenceAttribution',
    'debtSummary',
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'openedFeltSerious',
    'verifiedFixed',
    'unverifiedClosed',
    'unclassifiedIssues',
  ],
  issueEvidenceCounts: [
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'openedFeltSerious',
    'verifiedFixed',
    'unverifiedClosed',
    'unclassifiedIssues',
    'targetEvidenceAttribution',
  ],
  debtSummary: ['verified', 'carryover', 'stale'],
  debtTierSummary: ['count', 'weight', 'storedWeight', 'byInstallImpactClass'],
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
  cve: ['affected', 'load'],
  releaseChecks: [
    'schemaVersion',
    'state',
    'total',
    'success',
    'failure',
    'pending',
    'skipped',
    'contextCount',
    'shownContextCount',
    'contextsTruncated',
    'contexts',
  ],
  artifactVerification: [
    'schemaVersion',
    'observationId',
    'receiptId',
    'evidenceIdentity',
    'evidenceReportIdentity',
    'runId',
    'observedAt',
    'observationContentHash',
    'observationPreviousContentHash',
    'receiptContentHash',
    'receiptPreviousContentHash',
    'release',
    'releaseMetadata',
    'artifact',
    'evidenceReport',
    'npmPackageUrl',
    'releaseTarballUrl',
    'releaseIntegrity',
    'releaseSha',
    'releaseShaMatches',
    'ciReportUrl',
    'ciReportVerified',
    'ciReportMismatch',
    'fullReleaseValidationUrl',
    'releaseValidationVerified',
    'releaseValidationMismatch',
    'registryVersion',
    'registryIntegrity',
    'registryTarballUrl',
    'verified',
    'mismatch',
  ],
  artifactRelease: [
    'repository',
    'tag',
    'releaseNodeId',
    'catalogTagCommitOid',
    'publishedAt',
  ],
  artifactReleaseMetadata: [
    'npmPackageUrl',
    'releaseTarballUrl',
    'releaseIntegrity',
    'releaseSha',
    'ciReportUrl',
    'fullReleaseValidationUrl',
  ],
  artifactEvidence: [
    'schemaVersion',
    'packageName',
    'requestedVersion',
    'metadataUrl',
    'metadataContentDigest',
    'registryAvailability',
    'registryAvailabilityReason',
    'registryPackageName',
    'registryProblems',
    'expectedIntegrity',
    'canonicalExpectedIntegrity',
    'expectedTarballUrl',
    'canonicalExpectedTarballUrl',
    'expectedReleaseSha',
    'canonicalExpectedReleaseSha',
    'state',
    'registryState',
    'releaseBindingState',
    'version',
    'integrity',
    'canonicalIntegrity',
    'tarballUrl',
    'canonicalTarballUrl',
    'tarballByteCount',
    'actualDigests',
    'gitHead',
    'canonicalGitHead',
    'registryIdentity',
    'releaseBindingIdentity',
    'registryVerified',
    'releaseBound',
    'verified',
    'mismatch',
    'reason',
  ],
  artifactActualDigests: ['sha512', 'sha384', 'sha256'],
  artifactEvidenceReport: [
    'url',
    'rawUrl',
    'fallbackUrl',
    'fallbackKind',
    'fallbackArtifactCount',
    'contentDigest',
    'fallbackArtifactDigest',
    'expectedReleaseTag',
    'expectedReleaseSha',
    'verified',
    'mismatch',
  ],
  labelTimeline: [
    'schemaVersion',
    'cutoffAt',
    'issueCount',
    'currentLabelCount',
    'timelineLabelCount',
    'snapshotLabelCount',
    'missingTimelineCount',
    'missingTimelineWithCurrentLabelsCount',
    'historicalCurrentLabelFallbackAllowed',
  ],
  explanation: [
    'schemaVersion',
    'title',
    'scoreLedger',
    'positives',
    'positiveDetails',
    'limits',
    'limitDetails',
    'verdict',
    'recommendationDecision',
    'authorityReferences',
  ],
  scoreLedger: [
    'schemaVersion',
    'ledgerType',
    'immutable',
    'formulaCode',
    'evaluatedAt',
    'finalScore',
    'status',
    'band',
    'thresholds',
    'operations',
    'evidence',
    'aliasElection',
    'cveGate',
    'gapToTen',
    'digest',
    'subtotalBeforeCaps',
    'scoreAfterCaps',
    'rows',
    'caps',
    'explanationAudit',
  ],
  scoreLedgerRow: ['key', 'label', 'points', 'kind'],
  scoreLedgerCap: ['key', 'label', 'ceiling', 'applied', 'before', 'after', 'reason'],
  scoreLedgerExplanationAudit: [
    'schemaVersion',
    'baseLedgerDigest',
    'title',
    'verdict',
    'listsDigest',
    'recommendationDecisionDigest',
    'details',
    'digest',
  ],
  scoreLedgerExplanationAuditDetail: [
    'section',
    'index',
    'code',
    'label',
    'text',
    'metricsDigest',
    'bucketsDigest',
    'riskBucketsDigest',
    'issueRefsDigest',
    'operations',
  ],
  scoreLedgerExplanationOperationReceipt: [
    'sequence',
    'code',
    'formulaCode',
    'evidenceDigest',
  ],
  explanationDetail: ['code', 'label', 'text'],
  explanationIssueRef: ['number', 'title', 'url'],
  confirmationReason: [
    'code',
    'source',
    'author',
    'occurredAt',
    'authorityReference',
  ],
  explanationIssueProof: [
    'status',
    'statusLabel',
    'riskDisposition',
    'riskDispositionLabel',
    'summary',
    'riskWeight',
  ],
  explanationLinkedRef: ['number'],
  releaseLocalEvidence: ['kind', 'source', 'version', 'snippet'],
  scoreAuthorityReference: [
    'subjectKind',
    'subjectIdentity',
    'resolutionHash',
    'evidenceDigest',
    'authorizedForScoring',
  ],
  recommendationDecision: RECOMMENDATION_DECISION_KEYS,
  fixProvenance: [
    'verifiedFixedCount',
    'creditedFixedCount',
    'unverifiedClosedCount',
    'predecessorBoundary',
    'closureProof',
    'releaseFixCredit',
  ],
  predecessorBoundary: [
    'schemaVersion',
    'oldestScoredStableTag',
    'oldestScoredStablePredecessorTag',
    'targetTag',
    'predecessorTag',
  ],
  closureProof: [
    'schemaVersion',
    'creditedCount',
    'notCreditedCount',
    'analyzedClosedCount',
    'containedFixedCount',
    'containedNotCreditedCount',
    'targetTag',
    'predecessorTag',
    'fixCreditDecisionCounts',
    'fixCreditDecisions',
    'byStatus',
    'byRiskDisposition',
    'riskSummary',
    'neutralAuditExamples',
    'examplesByStatus',
    'examples',
  ],
  closureProofRiskSummary: [
    'creditedReleaseFixCount',
    'containedReleaseFixCount',
    'containedWithoutFirstCreditCount',
    'resolvedByCanonicalReleaseFixCount',
    'resolvedByReleaseFixProofCount',
    'knownNotInReleaseCount',
    'openCanonicalRiskCount',
    'unsupportedClosureClaimCount',
    'neutralOrNonActionableCount',
    'neutralHighImpactCount',
    'neutralBugShapedCount',
    'missingEvidenceCount',
    'unresolvedForReleaseCount',
    'unresolvedWeightedRisk',
    'weightedRiskByDisposition',
  ],
  fixCreditDecisionCounts: ['credited', 'withheld', 'invalid'],
  releaseFixCredit: [
    'schemaVersion',
    'targetTag',
    'predecessorTag',
    'countedClosedCount',
    'notCountedClosedCount',
    'analyzedClosedCount',
    'containedFixedCount',
    'containedNotCreditedCount',
    'decisionCounts',
    'decisions',
  ],
  fixCreditDecision: [
    'schemaVersion',
    'issueNumber',
    'status',
    'reasonCode',
    'targetTag',
    'predecessorTag',
    'proofIdentities',
  ],
  trustedPullRequestProof: [
    'kind',
    'repositoryNameWithOwner',
    'prNumber',
    'sources',
    'merged',
    'mergeCommitOid',
    'baseRefName',
    'target',
    'predecessor',
  ],
  directCommitProof: [
    'kind',
    'schemaVersion',
    'repositoryNameWithOwner',
    'commitOid',
    'targetTag',
    'predecessorTag',
    'status',
    'reasonCode',
    'creditEligible',
    'target',
    'predecessor',
    'releaseAncestry',
    'strictValid',
    'validationReasonCode',
  ],
  directCommitReachabilityProof: [
    'tag',
    'status',
    'tagCommitOid',
    'checkedCommitOid',
    'method',
    'evidence',
    'strictValid',
    'validationReasonCode',
  ],
  reachabilityProof: [
    'tag',
    'status',
    'tagCommitOid',
    'checkedCommitOid',
    'baseRefName',
    'method',
    'checkedAt',
    'evidenceReason',
    'strictValid',
    'validationReasonCode',
  ],
};

const SCORE_AUDIT_ALLOWED_NESTED_KEYS = {
  ...SCORE_AUDIT_REQUIRED_KEYS,
  scoreLedger: [
    ...SCORE_AUDIT_REQUIRED_KEYS.scoreLedger,
  ],
  scoreLedgerRow: [...SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerRow, 'metric', 'note'],
  explanationDetail: [
    ...SCORE_AUDIT_REQUIRED_KEYS.explanationDetail,
    'metrics',
    'buckets',
    'riskBuckets',
    'issueRefs',
  ],
  explanationIssueRef: [
    ...SCORE_AUDIT_REQUIRED_KEYS.explanationIssueRef,
    'state',
    'status',
    'tier',
    'weight',
    'fieldConfirmed',
    'confirmationReasons',
    'releaseLocal',
    'releaseLocalEvidence',
    'releaseScopedState',
    'scoringReason',
    'installImpactClass',
    'installImpactMultiplier',
    'proof',
  ],
  confirmationReason: [
    ...SCORE_AUDIT_REQUIRED_KEYS.confirmationReason,
    'association',
    'updatedAt',
    'commentId',
    'commentUrl',
    'issueNodeId',
    'issueAuthorNodeId',
    'issueAuthorType',
    'commentNodeId',
    'commentNodeType',
    'actorNodeId',
    'actorType',
    'commentBodyDigest',
    'label',
    'eventId',
    'snippet',
    'authorityReference',
  ],
  releaseLocalEvidence: [
    ...SCORE_AUDIT_REQUIRED_KEYS.releaseLocalEvidence,
    'commentId',
    'commentUrl',
    'commentNodeId',
    'author',
    'actorNodeId',
    'actorType',
    'association',
    'occurredAt',
    'updatedAt',
    'commentBodyDigest',
    'authorityReference',
  ],
  explanationIssueProof: [
    ...SCORE_AUDIT_REQUIRED_KEYS.explanationIssueProof,
    'canonicalIssue',
    'canonicalPath',
    'openPrs',
    'reachablePrs',
    'notReachablePrs',
    'unknownReachabilityPrs',
    'closedUnmergedPrs',
    'externalClosingPrs',
  ],
  explanationLinkedRef: [
    ...SCORE_AUDIT_REQUIRED_KEYS.explanationLinkedRef,
    'title',
    'url',
    'state',
    'status',
    'repositoryNameWithOwner',
    'source',
    'merged',
    'mergedAt',
    'referencedAt',
    'willCloseTarget',
    'reachabilityMethod',
    'mergeCommitOid',
    'sourceCommentUrl',
  ],
};

const recommendationDecisionCodes = new Set([
  'highest_confidence',
  'newest_within_confidence_tolerance',
  'higher_confidence_release_selected',
  'newer_release_within_tolerance_selected',
  'below_recommendation_threshold',
  'install_gate_active',
]);
const confirmationReasonCodes = new Set([
  'independent_human_reproduction',
  'human_applied_p0',
  'human_applied_p1',
  'human_applied_regression',
]);
const confirmationReasonSources = new Set(['comment', 'label_event']);
const confirmationReasonLabels = new Set(['P0', 'P1', 'regression']);
const confirmationReasonCodeByLabel = new Map([
  ['P0', 'human_applied_p0'],
  ['P1', 'human_applied_p1'],
  ['regression', 'human_applied_regression'],
]);
const releaseLocalEvidenceSources = new Set(['title', 'body', 'comment']);
const releaseCheckAggregateStates = new Set([
  'ERROR',
  'EXPECTED',
  'FAILURE',
  'PENDING',
  'SUCCESS',
]);
const releaseCheckFailureStates = new Set([
  'ACTION_REQUIRED',
  'CANCELLED',
  'ERROR',
  'FAILURE',
  'STALE',
  'STARTUP_FAILURE',
  'TIMED_OUT',
]);
const releaseCheckPendingStates = new Set([
  'EXPECTED',
  'IN_PROGRESS',
  'PENDING',
  'PENDING_REQUESTED',
  'QUEUED',
  'REQUESTED',
  'WAITING',
]);
const releaseCheckSuccessStates = new Set(['SUCCESS']);
const releaseCheckSkippedStates = new Set(['NEUTRAL', 'SKIPPED']);
const releaseCheckContextKeys = new Set([
  'type',
  'name',
  'workflowName',
  'appSlug',
  'status',
  'conclusion',
  'url',
]);

export function verifyScoreAuditPayloadContracts({
  tag,
  input,
  components,
  issueEvidence,
  gateEvidence,
  versions,
  scoredAt,
}) {
  const failures = [];
  const inputValid = verifyPayload({
    failures,
    tag,
    label: 'score input',
    payload: input,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.input,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.input,
    expectedSchemaVersion: versions.scoreInput,
  });
  const componentsValid = verifyPayload({
    failures,
    tag,
    label: 'score components',
    payload: components,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.components,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.components,
    expectedSchemaVersion: versions.scoreComponents,
  });
  const issueEvidenceValid = verifyPayload({
    failures,
    tag,
    label: 'issue evidence',
    payload: issueEvidence,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.issueEvidence,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.issueEvidence,
    expectedSchemaVersion: versions.issueEvidence,
  });
  const gateEvidenceValid = verifyPayload({
    failures,
    tag,
    label: 'gate evidence',
    payload: gateEvidence,
    allowedKeys: SCORE_AUDIT_TOP_LEVEL_KEYS.gateEvidence,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.gateEvidence,
    expectedSchemaVersion: versions.gateEvidence,
  });
  if (componentsValid) verifyScoreComponentsContract({ failures, tag, components });
  if (inputValid) {
    for (const field of [
      'feltOpenedWeight',
      'feltClosedWeight',
      'verifiedDebtWeight',
      'carryoverDebtWeight',
      'staleDebtWeight',
      'unresolvedClosureRiskWeight',
      'cveLoad',
    ]) {
      expect(
        failures,
        tag,
        isFiniteNumber(input[field]),
        `score input ${field} must be a finite number`,
      );
    }
    expect(
      failures,
      tag,
      isFiniteNumber(input.affirmativeClosureRiskCeilingWeight) &&
        input.affirmativeClosureRiskCeilingWeight >= 0,
      'score input affirmativeClosureRiskCeilingWeight must be a non-negative finite number',
    );
  }
  if (issueEvidenceValid) verifyIssueEvidenceContract({ failures, tag, issueEvidence });
  if (gateEvidenceValid) {
    verifyGateEvidenceContract({
      failures,
      tag,
      gateEvidence,
      input: inputValid ? input : null,
    });
  }

  const explanation = isObject(components?.explanation) ? components.explanation : null;
  const ledger = isObject(explanation?.scoreLedger) ? explanation.scoreLedger : null;
  const authoritativeScoredAt =
    typeof scoredAt === 'string' ? scoredAt : '';
  const scoreLedgerExpectations = {
    ...(inputValid ? { input } : {}),
    scoredAt: authoritativeScoredAt,
  };
  for (const problem of scoreLedgerV2Problems(ledger, scoreLedgerExpectations)) {
    failures.push(`${tag}: ${problem}`);
  }
  for (const problem of scoreExplanationAuditProblems(explanation, ledger)) {
    failures.push(`${tag}: ${problem}`);
  }
  if (
    inputValid &&
    componentsValid &&
    ledger &&
    Number.isFinite(Date.parse(authoritativeScoredAt))
  ) {
    try {
      const replayAt = Date.parse(authoritativeScoredAt);
      const recomputed = installConfidence(input, replayAt);
      if (!sameJsonValue(components.components, recomputed.components)) {
        failures.push(`${tag}: score components.components must match ScoreLedgerV2 semantic replay`);
      }
      if (components.hotfix !== recomputed.hotfix) {
        failures.push(`${tag}: score components.hotfix must match ScoreLedgerV2 semantic replay`);
      }
      if (components.evidenceCoverage !== recomputed.evidenceCoverage) {
        failures.push(`${tag}: score components.evidenceCoverage must match ScoreLedgerV2 semantic replay`);
      }
      if (ledger.finalScore !== recomputed.score || ledger.status !== recomputed.status || ledger.band !== recomputed.band) {
        failures.push(`${tag}: ScoreLedgerV2 final tuple must match recomputed install confidence`);
      }
    } catch (error) {
      failures.push(
        `${tag}: score input cannot be replayed: ${error instanceof Error ? error.message : String(error)}`,
      );
    }
  }
  const decisionContext = {
    tag,
    expectedStatus: ledger?.status,
    expectedScore: ledger?.finalScore,
  };
  failures.push(...verifyRecommendationDecisionContract({
    ...decisionContext,
    label: 'score components.recommendationDecision',
    decision: components?.recommendationDecision,
  }));
  failures.push(...verifyRecommendationDecisionContract({
    ...decisionContext,
    label: 'score components.explanation.recommendationDecision',
    decision: explanation?.recommendationDecision,
  }));
  if (isObject(components?.recommendationDecision) && isObject(explanation?.recommendationDecision)) {
    for (const key of RECOMMENDATION_DECISION_KEYS) {
      if (!sameJsonValue(components.recommendationDecision[key], explanation.recommendationDecision[key])) {
        failures.push(`${tag}: score components and explanation recommendationDecision field ${key} must match`);
      }
    }
  }
  return failures;
}

export function verifyRecommendationDecisionContract({
  tag,
  label = 'recommendationDecision',
  decision,
  expectedStatus,
  expectedScore,
  expectedSelected,
}) {
  const failures = [];
  if (!isObject(decision)) {
    failures.push(`${tag}: ${label} must be an object`);
    return failures;
  }

  const allowed = new Set(RECOMMENDATION_DECISION_KEYS);
  for (const key of Object.keys(decision).sort()) {
    if (!allowed.has(key)) failures.push(`${tag}: ${label} has unexpected key ${key}`);
  }
  for (const key of RECOMMENDATION_DECISION_KEYS) {
    if (!Object.hasOwn(decision, key)) failures.push(`${tag}: ${label} is missing required field ${key}`);
  }

  expect(failures, tag, decision.schemaVersion === 1, `${label} schemaVersion must be 1`);
  expect(
    failures,
    tag,
    decision.policyCode === 'highest_confidence_with_recency_tolerance',
    `${label} policyCode must be highest_confidence_with_recency_tolerance`,
  );
  expect(failures, tag, isFiniteNumber(decision.threshold) && decision.threshold > 0,
    `${label} threshold must be a positive finite number`);
  expect(failures, tag, isFiniteNumber(decision.recencyTolerance) && decision.recencyTolerance >= 0,
    `${label} recencyTolerance must be a non-negative finite number`);
  expect(failures, tag, isNullableTag(decision.selectedTag), `${label} selectedTag must be a non-empty string or null`);
  expect(failures, tag, isNullableFiniteNumber(decision.selectedScore), `${label} selectedScore must be a finite number or null`);
  expect(failures, tag, isNullableTag(decision.highestScoringTag), `${label} highestScoringTag must be a non-empty string or null`);
  expect(failures, tag, isNullableFiniteNumber(decision.highestScore), `${label} highestScore must be a finite number or null`);
  expect(failures, tag, typeof decision.releaseTag === 'string' && decision.releaseTag.length > 0,
    `${label} releaseTag must be a non-empty string`);
  expect(failures, tag, isNullableFiniteNumber(decision.releaseScore), `${label} releaseScore must be a finite number or null`);
  expect(failures, tag, typeof decision.qualifies === 'boolean', `${label} qualifies must be boolean`);
  expect(failures, tag, typeof decision.selected === 'boolean', `${label} selected must be boolean`);
  expect(failures, tag, Number.isInteger(decision.recencyRank) && decision.recencyRank > 0,
    `${label} recencyRank must be a positive integer`);
  expect(failures, tag, decision.scoreRank == null || Number.isInteger(decision.scoreRank) && decision.scoreRank > 0,
    `${label} scoreRank must be a positive integer or null`);
  expect(failures, tag, decision.scoreDeltaToHighest == null ||
    isFiniteNumber(decision.scoreDeltaToHighest) && decision.scoreDeltaToHighest >= 0,
    `${label} scoreDeltaToHighest must be a non-negative finite number or null`);
  expect(failures, tag, recommendationDecisionCodes.has(decision.decisionCode),
    `${label} decisionCode must be known`);
  expect(failures, tag, typeof decision.summary === 'string' && decision.summary.length > 0,
    `${label} summary must be present`);

  const selectedPairPresent = decision.selectedTag != null && decision.selectedScore != null;
  const selectedPairAbsent = decision.selectedTag == null && decision.selectedScore == null;
  expect(failures, tag, selectedPairPresent || selectedPairAbsent,
    `${label} selectedTag and selectedScore must both be present or both be null`);
  const highestPairPresent = decision.highestScoringTag != null && decision.highestScore != null;
  const highestPairAbsent = decision.highestScoringTag == null && decision.highestScore == null;
  expect(failures, tag, highestPairPresent || highestPairAbsent,
    `${label} highestScoringTag and highestScore must both be present or both be null`);
  expect(failures, tag, selectedPairPresent === highestPairPresent,
    `${label} selected and highest-scoring release fields must become present together`);

  if (typeof decision.releaseTag === 'string') {
    expect(failures, tag, decision.releaseTag === tag,
      `${label} releaseTag (${decision.releaseTag}) must match ${tag}`);
  }
  if (expectedScore !== undefined) {
    expect(failures, tag, sameJsonValue(decision.releaseScore, expectedScore),
      `${label} releaseScore (${decision.releaseScore}) must match score ledger finalScore (${expectedScore})`);
  }
  if (typeof expectedSelected === 'boolean') {
    expect(failures, tag, decision.selected === expectedSelected,
      `${label} selected (${decision.selected}) must match expected recommended (${expectedSelected})`);
  }

  if (selectedPairPresent && highestPairPresent) {
    expect(failures, tag, decision.highestScore >= decision.selectedScore,
      `${label} highestScore must be greater than or equal to selectedScore`);
    expect(failures, tag, decision.selectedScore >= decision.highestScore - decision.recencyTolerance,
      `${label} selectedScore must be within recencyTolerance of highestScore`);
    if (decision.selectedTag === decision.highestScoringTag) {
      expect(failures, tag, decision.selectedScore === decision.highestScore,
        `${label} selectedScore and highestScore must match when their tags match`);
    }
  }

  if (decision.selected === true) {
    expect(failures, tag, decision.qualifies === true, `${label} selected release must qualify`);
    expect(failures, tag, decision.selectedTag === decision.releaseTag,
      `${label} selectedTag must match releaseTag for the selected release`);
    expect(failures, tag, decision.selectedScore === decision.releaseScore,
      `${label} selectedScore must match releaseScore for the selected release`);
  } else if (decision.selectedTag != null) {
    expect(failures, tag, decision.selectedTag !== decision.releaseTag,
      `${label} unselected release must not name itself as selectedTag`);
  }

  if (isFiniteNumber(decision.releaseScore) && isFiniteNumber(decision.highestScore)) {
    const expectedDelta = roundMetric(decision.highestScore - decision.releaseScore);
    expect(failures, tag, decision.scoreDeltaToHighest === expectedDelta,
      `${label} scoreDeltaToHighest (${decision.scoreDeltaToHighest}) must equal ${expectedDelta}`);
  } else {
    expect(failures, tag, decision.scoreDeltaToHighest == null,
      `${label} scoreDeltaToHighest must be null without both releaseScore and highestScore`);
  }

  if (typeof expectedStatus === 'string' && isFiniteNumber(decision.threshold)) {
    const expectedQualifies =
      expectedStatus === 'eligible' &&
      isFiniteNumber(decision.releaseScore) &&
      decision.releaseScore >= decision.threshold;
    expect(failures, tag, decision.qualifies === expectedQualifies,
      `${label} qualifies (${decision.qualifies}) must match status, score, and threshold`);
    expect(failures, tag, expectedStatus === 'eligible' ? decision.scoreRank != null : decision.scoreRank == null,
      `${label} scoreRank presence must match eligible status`);
    const expectedCode = expectedRecommendationDecisionCode(decision, expectedStatus, expectedQualifies);
    expect(failures, tag, decision.decisionCode === expectedCode,
      `${label} decisionCode (${decision.decisionCode}) must equal ${expectedCode}`);
  }

  return failures;
}

function verifyPayload({
  failures,
  tag,
  label,
  payload,
  allowedKeys,
  requiredKeys,
  expectedSchemaVersion,
}) {
  if (!isObject(payload)) {
    failures.push(`${tag}: ${label} payload must be an object`);
    return false;
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(payload).sort()) {
    if (!allowed.has(key)) failures.push(`${tag}: ${label} payload has unexpected top-level key ${key}`);
  }
  verifyRequiredKeys({ failures, tag, path: label, value: payload, requiredKeys });
  if (payload.schemaVersion !== expectedSchemaVersion) {
    failures.push(`${tag}: ${label} schemaVersion (${payload.schemaVersion}) must equal ${expectedSchemaVersion}`);
  }
  return true;
}

function verifyScoreComponentsContract({ failures, tag, components }) {
  verifyObjectContract({
    failures,
    tag,
    path: 'score components.components',
    value: components.components,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.installComponents,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.installComponents,
    nullable: true,
  });
  verifyExplanationContract({
    failures,
    tag,
    path: 'score components.explanation',
    explanation: components.explanation,
  });
}

function verifyIssueEvidenceContract({ failures, tag, issueEvidence }) {
  verifyObjectContract({
    failures,
    tag,
    path: 'issue evidence.evidenceCounts',
    value: issueEvidence.evidenceCounts,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.issueEvidenceCounts,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.issueEvidenceCounts,
  });
  if (verifyObjectContract({
    failures,
    tag,
    path: 'issue evidence.debtSummary',
    value: issueEvidence.debtSummary,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.debtSummary,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.debtSummary,
  })) {
    for (const tier of SCORE_AUDIT_REQUIRED_KEYS.debtSummary) {
      verifyObjectContract({
        failures,
        tag,
        path: `issue evidence.debtSummary.${tier}`,
        value: issueEvidence.debtSummary[tier],
        allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.debtTierSummary,
        requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.debtTierSummary,
      });
    }
  }
  for (const key of [
    'targetEvidenceAttribution',
    'verifiedDebt',
    'carryoverDebt',
    'staleDebt',
    'openedFeltSerious',
    'verifiedFixed',
    'unverifiedClosed',
    'unclassifiedIssues',
  ]) {
    verifyArrayContract({
      failures,
      tag,
      path: `issue evidence.${key}`,
      value: issueEvidence[key],
    });
  }
  if (Array.isArray(issueEvidence.verifiedFixed)) {
    for (const [index, row] of issueEvidence.verifiedFixed.entries()) {
      if (!isObject(row) || !Object.hasOwn(row, 'fixCreditDecision') || row.fixCreditDecision == null) continue;
      verifyFixCreditDecisionContract({
        failures,
        tag,
        path: `issue evidence.verifiedFixed[${index}].fixCreditDecision`,
        decision: row.fixCreditDecision,
      });
    }
  }
}

function verifyGateEvidenceContract({ failures, tag, gateEvidence, input }) {
  verifyObjectContract({
    failures,
    tag,
    path: 'gate evidence.cve',
    value: gateEvidence.cve,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.cve,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.cve,
  });
  verifyArrayContract({
    failures,
    tag,
    path: 'gate evidence.stableTagsNewestFirst',
    value: gateEvidence.stableTagsNewestFirst,
  });
  verifyObjectContract({
    failures,
    tag,
    path: 'gate evidence.releaseChecks',
    value: gateEvidence.releaseChecks,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.releaseChecks,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.releaseChecks,
    expectedSchemaVersion: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
    nullable: true,
  });
  verifyReleaseChecksContract({
    failures,
    tag,
    input,
    releaseChecks: gateEvidence.releaseChecks,
  });
  const artifactVerificationValid = verifyObjectContract({
    failures,
    tag,
    path: 'gate evidence.artifactVerification',
    value: gateEvidence.artifactVerification,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactVerification,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactVerification,
    expectedSchemaVersion: 2,
  });
  if (artifactVerificationValid) {
    verifyArtifactVerificationContract({
      failures,
      tag,
      artifactVerification: gateEvidence.artifactVerification,
      input,
    });
  }
  verifyObjectContract({
    failures,
    tag,
    path: 'gate evidence.labelTimeline',
    value: gateEvidence.labelTimeline,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.labelTimeline,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.labelTimeline,
    expectedSchemaVersion: 1,
  });
  verifyFixProvenanceContract({
    failures,
    tag,
    path: 'gate evidence.fixProvenance',
    fixProvenance: gateEvidence.fixProvenance,
  });
}

function verifyArtifactVerificationContract({
  failures,
  tag,
  artifactVerification,
  input,
}) {
  const path = 'gate evidence.artifactVerification';
  const proofFields = [
    'observationId',
    'receiptId',
    'evidenceIdentity',
    'evidenceReportIdentity',
    'runId',
    'observedAt',
    'observationContentHash',
    'receiptContentHash',
    'release',
    'releaseMetadata',
    'artifact',
    'evidenceReport',
  ];
  const proofCount = proofFields
    .map((field) => artifactVerification[field])
    .filter((value) => value != null)
    .length;
  const proofPresent = proofCount === proofFields.length;
  const proofAbsent = proofCount === 0;

  expect(
    failures,
    tag,
    proofAbsent || proofPresent,
    `${path} immutable proof fields must be all null or all present`,
  );
  expect(
    failures,
    tag,
    artifactVerification.observationId == null ||
      /^artifact-observation-v1:[0-9a-f]{64}$/.test(
        artifactVerification.observationId,
      ),
    `${path}.observationId must be a canonical artifact observation ID or null`,
  );
  expect(
    failures,
    tag,
    artifactVerification.receiptId == null ||
      /^artifact-receipt-v2:[0-9a-f]{64}$/.test(
        artifactVerification.receiptId,
      ),
    `${path}.receiptId must be a canonical artifact receipt ID or null`,
  );
  expect(
    failures,
    tag,
    artifactVerification.evidenceIdentity == null ||
      /^[0-9a-f]{64}$/.test(artifactVerification.evidenceIdentity),
    `${path}.evidenceIdentity must be SHA-256 or null`,
  );
  expect(
    failures,
    tag,
    artifactVerification.evidenceReportIdentity == null ||
      /^release-evidence-v1:sha256:[0-9a-f]{64}$/.test(
        artifactVerification.evidenceReportIdentity,
      ),
    `${path}.evidenceReportIdentity must be a canonical release-evidence identity or null`,
  );
  if (
    typeof artifactVerification.receiptId === 'string' &&
    typeof artifactVerification.evidenceIdentity === 'string'
  ) {
    expect(
      failures,
      tag,
      artifactVerification.receiptId ===
        `artifact-receipt-v2:${artifactVerification.evidenceIdentity}`,
      `${path}.receiptId must bind evidenceIdentity`,
    );
  }
  for (const field of [
    'observationContentHash',
    'receiptContentHash',
  ]) {
    expect(
      failures,
      tag,
      artifactVerification[field] == null ||
        /^[0-9a-f]{64}$/.test(artifactVerification[field]),
      `${path}.${field} must be SHA-256 or null`,
    );
  }
  for (const field of [
    'observationPreviousContentHash',
    'receiptPreviousContentHash',
  ]) {
    expect(
      failures,
      tag,
      artifactVerification[field] == null ||
        /^[0-9a-f]{64}$/.test(artifactVerification[field]),
      `${path}.${field} must be SHA-256 or null`,
    );
  }
  expect(
    failures,
    tag,
    artifactVerification.runId == null ||
      isNonEmptyString(artifactVerification.runId),
    `${path}.runId must be a non-empty string or null`,
  );
  expect(
    failures,
    tag,
    artifactVerification.observedAt == null ||
      (
        isValidTimestamp(artifactVerification.observedAt) &&
        new Date(artifactVerification.observedAt).toISOString() ===
          artifactVerification.observedAt
      ),
    `${path}.observedAt must be a canonical ISO-8601 timestamp or null`,
  );

  for (const field of [
    'ciReportVerified',
    'releaseValidationVerified',
    'verified',
  ]) {
    expect(
      failures,
      tag,
      typeof artifactVerification[field] === 'boolean',
      `${path}.${field} must be a boolean`,
    );
  }
  expect(
    failures,
    tag,
    artifactVerification.releaseShaMatches == null ||
      typeof artifactVerification.releaseShaMatches === 'boolean',
    `${path}.releaseShaMatches must be a boolean or null`,
  );
  for (const field of [
    'npmPackageUrl',
    'releaseTarballUrl',
    'releaseIntegrity',
    'releaseSha',
    'ciReportUrl',
    'ciReportMismatch',
    'fullReleaseValidationUrl',
    'releaseValidationMismatch',
    'registryVersion',
    'registryIntegrity',
    'registryTarballUrl',
    'mismatch',
  ]) {
    expect(
      failures,
      tag,
      artifactVerification[field] == null ||
        isNonEmptyString(artifactVerification[field]),
      `${path}.${field} must be a non-empty string or null`,
    );
  }
  expect(
    failures,
    tag,
    artifactVerification.releaseSha == null ||
      /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/.test(
      artifactVerification.releaseSha,
      ),
    `${path}.releaseSha must be a canonical Git OID or null`,
  );

  if (proofAbsent) {
    for (const field of [
      'observationPreviousContentHash',
      'receiptPreviousContentHash',
    ]) {
      expect(
        failures,
        tag,
        artifactVerification[field] == null,
        `${path}.${field} must be null without immutable artifact proof`,
      );
    }
    for (const field of [
      'npmPackageUrl',
      'releaseTarballUrl',
      'releaseIntegrity',
      'releaseSha',
      'releaseShaMatches',
      'ciReportUrl',
      'ciReportMismatch',
      'fullReleaseValidationUrl',
      'releaseValidationMismatch',
      'registryVersion',
      'registryIntegrity',
      'registryTarballUrl',
      'mismatch',
    ]) {
      expect(
        failures,
        tag,
        artifactVerification[field] == null,
        `${path}.${field} must be null without immutable artifact identities`,
      );
    }
    for (const field of [
      'ciReportVerified',
      'releaseValidationVerified',
      'verified',
    ]) {
      expect(
        failures,
        tag,
        artifactVerification[field] === false,
        `${path}.${field} must be false without immutable artifact identities`,
      );
    }
  }

  if (proofPresent) {
    const releaseValid = verifyObjectContract({
      failures,
      tag,
      path: `${path}.release`,
      value: artifactVerification.release,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactRelease,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactRelease,
    });
    const releaseMetadataValid = verifyObjectContract({
      failures,
      tag,
      path: `${path}.releaseMetadata`,
      value: artifactVerification.releaseMetadata,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactReleaseMetadata,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactReleaseMetadata,
    });
    const artifactValid = verifyObjectContract({
      failures,
      tag,
      path: `${path}.artifact`,
      value: artifactVerification.artifact,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactEvidence,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactEvidence,
      expectedSchemaVersion: ARTIFACT_EVIDENCE_SCHEMA_VERSION,
    });
    const evidenceReportValid = verifyObjectContract({
      failures,
      tag,
      path: `${path}.evidenceReport`,
      value: artifactVerification.evidenceReport,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactEvidenceReport,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactEvidenceReport,
    });
    if (artifactValid) {
      verifyArrayContract({
        failures,
        tag,
        path: `${path}.artifact.registryProblems`,
        value: artifactVerification.artifact.registryProblems,
      });
      verifyObjectContract({
        failures,
        tag,
        path: `${path}.artifact.actualDigests`,
        value: artifactVerification.artifact.actualDigests,
        allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.artifactActualDigests,
        requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.artifactActualDigests,
      });
    }
    if (
      releaseValid &&
      releaseMetadataValid &&
      artifactValid &&
      evidenceReportValid
    ) {
      let rebuiltReceipt = null;
      try {
        rebuiltReceipt = buildReleaseArtifactReceipt({
          release: artifactVerification.release,
          releaseMetadata: artifactVerification.releaseMetadata,
          artifact: artifactVerification.artifact,
          evidenceReport: artifactVerification.evidenceReport,
          previousContentHash:
            artifactVerification.receiptPreviousContentHash,
        });
      } catch (error) {
        failures.push(
          `${tag}: ${path} receipt replay failed: ${
            error instanceof Error ? error.message : String(error)
          }`,
        );
      }
      if (rebuiltReceipt) {
        const receiptBindings = [
          ['receiptId', rebuiltReceipt.receiptId],
          ['evidenceIdentity', rebuiltReceipt.evidenceIdentity],
          ['evidenceReportIdentity', rebuiltReceipt.evidenceReportIdentity],
          ['receiptContentHash', rebuiltReceipt.contentHash],
          ['receiptPreviousContentHash', rebuiltReceipt.previousContentHash],
        ];
        for (const [field, expected] of receiptBindings) {
          expect(
            failures,
            tag,
            artifactVerification[field] === expected,
            `${path}.${field} must match semantic receipt replay`,
          );
        }
        for (const field of [
          'release',
          'releaseMetadata',
          'artifact',
          'evidenceReport',
        ]) {
          expect(
            failures,
            tag,
            canonicalJson(rebuiltReceipt[field]) ===
              canonicalJson(artifactVerification[field]),
            `${path}.${field} must be canonical`,
          );
        }
        try {
          const rebuiltObservation = buildReleaseArtifactObservation({
            runId: artifactVerification.runId,
            observedAt: artifactVerification.observedAt,
            release: artifactVerification.release,
            receipt: {
              receiptId: rebuiltReceipt.receiptId,
              contentHash: rebuiltReceipt.contentHash,
            },
            previousContentHash:
              artifactVerification.observationPreviousContentHash,
          });
          const observationBindings = [
            ['observationId', rebuiltObservation.observationId],
            ['observationContentHash', rebuiltObservation.contentHash],
            [
              'observationPreviousContentHash',
              rebuiltObservation.previousContentHash,
            ],
          ];
          for (const [field, expected] of observationBindings) {
            expect(
              failures,
              tag,
              artifactVerification[field] === expected,
              `${path}.${field} must match semantic observation replay`,
            );
          }
        } catch (error) {
          failures.push(
            `${tag}: ${path} observation replay failed: ${
              error instanceof Error ? error.message : String(error)
            }`,
          );
        }
        expect(
          failures,
          tag,
          rebuiltReceipt.release.tag === tag,
          `${path}.release.tag must match the scored release tag`,
        );
        const expectedFlatFields = {
          npmPackageUrl: rebuiltReceipt.releaseMetadata.npmPackageUrl,
          releaseTarballUrl:
            rebuiltReceipt.releaseMetadata.releaseTarballUrl,
          releaseIntegrity: rebuiltReceipt.releaseMetadata.releaseIntegrity,
          releaseSha: rebuiltReceipt.releaseMetadata.releaseSha,
          releaseShaMatches: true,
          ciReportUrl: rebuiltReceipt.releaseMetadata.ciReportUrl,
          ciReportVerified: rebuiltReceipt.evidenceReport.verified,
          ciReportMismatch: rebuiltReceipt.evidenceReport.mismatch,
          fullReleaseValidationUrl:
            rebuiltReceipt.releaseMetadata.fullReleaseValidationUrl,
          releaseValidationVerified:
            rebuiltReceipt.evidenceReport.fallbackKind ===
              'github_actions_run' &&
            rebuiltReceipt.evidenceReport.verified,
          releaseValidationMismatch:
            rebuiltReceipt.evidenceReport.fallbackKind ===
              'github_actions_run'
              ? rebuiltReceipt.evidenceReport.mismatch
              : null,
          registryVersion: rebuiltReceipt.artifact.version,
          registryIntegrity: rebuiltReceipt.artifact.integrity,
          registryTarballUrl: rebuiltReceipt.artifact.tarballUrl,
          verified: rebuiltReceipt.artifact.verified,
          mismatch: rebuiltReceipt.artifact.mismatch,
        };
        for (const [field, expected] of Object.entries(expectedFlatFields)) {
          expect(
            failures,
            tag,
            sameJsonValue(artifactVerification[field], expected),
            `${path}.${field} must match nested immutable proof`,
          );
        }
      }
    }
  }

  if (!input) return;
  const inputBindings = [
    ['artifactVerified', 'verified'],
    ['artifactMismatch', 'mismatch'],
    ['ciReportVerified', 'ciReportVerified'],
    ['ciReportMismatch', 'ciReportMismatch'],
  ];
  for (const [inputField, artifactField] of inputBindings) {
    expect(
      failures,
      tag,
      sameJsonValue(input[inputField], artifactVerification[artifactField]),
      `score input ${inputField} must match ${path}.${artifactField}`,
    );
  }
  expect(
    failures,
    tag,
    input.releaseIntegrityPresent ===
      (artifactVerification.releaseIntegrity != null),
    `score input releaseIntegrityPresent must match ${path}.releaseIntegrity`,
  );
  if (artifactVerification.releaseShaMatches == null) {
    expect(
      failures,
      tag,
      !Object.hasOwn(input, 'releaseShaMatches') ||
        input.releaseShaMatches == null,
      `score input releaseShaMatches must be absent or null when ${path}.releaseShaMatches is null`,
    );
  } else {
    expect(
      failures,
      tag,
      input.releaseShaMatches === artifactVerification.releaseShaMatches,
      `score input releaseShaMatches must match ${path}.releaseShaMatches`,
    );
  }
}

function verifyReleaseChecksContract({ failures, tag, input, releaseChecks }) {
  const inputFields = {
    state: input?.releaseCheckState,
    total: input?.releaseCheckTotal,
    success: input?.releaseCheckSuccess,
    failure: input?.releaseCheckFailure,
    pending: input?.releaseCheckPending,
  };
  if (releaseChecks == null) {
    if (
      input &&
      (
        inputFields.state != null ||
        inputFields.total !== 0 ||
        inputFields.success !== 0 ||
        inputFields.failure !== 0 ||
        inputFields.pending !== 0
      )
    ) {
      failures.push(
        `${tag}: score input release-check fields must be empty when ` +
        `gate evidence.releaseChecks is null`,
      );
    }
    return;
  }
  if (!isObject(releaseChecks)) return;

  const counts = {};
  for (const field of ['total', 'success', 'failure', 'pending', 'skipped']) {
    const value = releaseChecks[field];
    expect(
      failures,
      tag,
      Number.isInteger(value) && value >= 0,
      `gate evidence.releaseChecks ${field} must be a non-negative integer`,
    );
    counts[field] = Number.isInteger(value) && value >= 0 ? value : null;
  }
  const state = releaseChecks.state;
  expect(
    failures,
    tag,
    state == null ||
      typeof state === 'string' &&
      state === normalizeReleaseCheckState(state) &&
      releaseCheckAggregateStates.has(state),
    'gate evidence.releaseChecks state must be a canonical aggregate state or null',
  );

  if (Object.values(counts).every((value) => value != null)) {
    expect(
      failures,
      tag,
      counts.success + counts.failure + counts.pending + counts.skipped === counts.total,
      'gate evidence.releaseChecks category counts must sum to total',
    );
    if (counts.total === 0) {
      expect(
        failures,
        tag,
        state == null,
        'gate evidence.releaseChecks state must be null when total is zero',
      );
    } else if (counts.failure > 0) {
      expect(
        failures,
        tag,
        state === 'FAILURE' || state === 'ERROR',
        'gate evidence.releaseChecks failure counts require a failure aggregate state',
      );
    } else if (counts.pending > 0) {
      expect(
        failures,
        tag,
        state === 'PENDING' || state === 'EXPECTED',
        'gate evidence.releaseChecks pending counts require a pending aggregate state',
      );
    } else {
      expect(
        failures,
        tag,
        state === 'SUCCESS',
        'gate evidence.releaseChecks completed counts require SUCCESS aggregate state',
      );
    }
  }

  const contextCount = releaseChecks.contextCount;
  const shownContextCount = releaseChecks.shownContextCount;
  const contextsTruncated = releaseChecks.contextsTruncated;
  const contexts = releaseChecks.contexts;
  expect(
    failures,
    tag,
    Number.isInteger(contextCount) && contextCount >= 0,
    'gate evidence.releaseChecks contextCount must be a non-negative integer',
  );
  expect(
    failures,
    tag,
    Number.isInteger(shownContextCount) && shownContextCount >= 0,
    'gate evidence.releaseChecks shownContextCount must be a non-negative integer',
  );
  expect(
    failures,
    tag,
    typeof contextsTruncated === 'boolean',
    'gate evidence.releaseChecks contextsTruncated must be boolean',
  );
  expect(
    failures,
    tag,
    Array.isArray(contexts),
    'gate evidence.releaseChecks contexts must be an array',
  );
  if (
    Number.isInteger(contextCount) &&
    Number.isInteger(shownContextCount) &&
    typeof contextsTruncated === 'boolean' &&
    Array.isArray(contexts)
  ) {
    expect(
      failures,
      tag,
      contextCount === releaseChecks.total,
      'gate evidence.releaseChecks contextCount must equal total',
    );
    expect(
      failures,
      tag,
      shownContextCount === contexts.length,
      'gate evidence.releaseChecks shownContextCount must equal contexts length',
    );
    expect(
      failures,
      tag,
      shownContextCount <= contextCount,
      'gate evidence.releaseChecks shownContextCount cannot exceed contextCount',
    );
    expect(
      failures,
      tag,
      contextsTruncated === (shownContextCount < contextCount),
      'gate evidence.releaseChecks contextsTruncated must match omitted context count',
    );

    const shownCounts = {
      success: 0,
      failure: 0,
      pending: 0,
      skipped: 0,
      ambiguous: 0,
    };
    const seenContextIdentities = new Set();
    for (const [index, context] of contexts.entries()) {
      const path = `gate evidence.releaseChecks.contexts[${index}]`;
      if (!isObject(context)) {
        failures.push(`${tag}: ${path} must be an object`);
        shownCounts.ambiguous++;
        continue;
      }
      for (const key of Object.keys(context).sort()) {
        if (!releaseCheckContextKeys.has(key)) {
          failures.push(`${tag}: ${path} has unexpected key ${key}`);
        }
      }
      expect(
        failures,
        tag,
        isNonEmptyString(context.name) && context.name.trim() === context.name,
        `${path}.name must be a canonical non-empty string`,
      );
      if (context.type != null) {
        expect(
          failures,
          tag,
          context.type === 'CheckRun' || context.type === 'StatusContext',
          `${path}.type must be CheckRun or StatusContext`,
        );
      }
      for (const key of ['workflowName', 'appSlug', 'url']) {
        expect(
          failures,
          tag,
          context[key] == null ||
            typeof context[key] === 'string' &&
            context[key].trim() === context[key],
          `${path}.${key} must be a canonical string or null`,
        );
      }
      const identity = JSON.stringify([
        context.type ?? null,
        context.name ?? null,
        context.workflowName ?? null,
        context.appSlug ?? null,
        context.url ?? null,
      ]);
      if (seenContextIdentities.has(identity)) {
        failures.push(`${tag}: ${path} duplicates or conflicts with another check context`);
      }
      seenContextIdentities.add(identity);

      const disposition = releaseCheckContextDisposition(context);
      if (disposition === 'ambiguous') {
        failures.push(`${tag}: ${path} has missing, unknown, or conflicting check state`);
      }
      shownCounts[disposition]++;
    }

    if (contextCount > 0) {
      expect(
        failures,
        tag,
        shownContextCount > 0,
        'gate evidence.releaseChecks must retain evidence for a non-empty check set',
      );
    }
    if (contextsTruncated === false && Object.values(counts).every((value) => value != null)) {
      for (const field of ['success', 'failure', 'pending', 'skipped']) {
        expect(
          failures,
          tag,
          shownCounts[field] === counts[field],
          `gate evidence.releaseChecks shown ${field} contexts must match aggregate count`,
        );
      }
      expect(
        failures,
        tag,
        shownCounts.ambiguous === 0,
        'gate evidence.releaseChecks complete contexts cannot be ambiguous',
      );
    } else if (Object.values(counts).every((value) => value != null)) {
      for (const field of ['success', 'failure', 'pending', 'skipped']) {
        expect(
          failures,
          tag,
          shownCounts[field] <= counts[field],
          `gate evidence.releaseChecks shown ${field} contexts cannot exceed aggregate count`,
        );
      }
      if (counts.failure > 0) {
        expect(
          failures,
          tag,
          shownCounts.failure > 0,
          'gate evidence.releaseChecks truncated failure aggregate must retain failure evidence',
        );
      } else if (counts.pending > 0) {
        expect(
          failures,
          tag,
          shownCounts.pending > 0,
          'gate evidence.releaseChecks truncated pending aggregate must retain pending evidence',
        );
      }
    }
  }

  if (input) {
    const comparisons = [
      ['state', 'releaseCheckState'],
      ['total', 'releaseCheckTotal'],
      ['success', 'releaseCheckSuccess'],
      ['failure', 'releaseCheckFailure'],
      ['pending', 'releaseCheckPending'],
    ];
    const mismatches = comparisons.filter(([field, inputField]) =>
      !sameJsonValue(releaseChecks[field], input[inputField]));
    const omitsOnlyPositiveEvidence =
      input.releaseCheckState == null &&
      input.releaseCheckTotal === 0 &&
      input.releaseCheckSuccess === 0 &&
      input.releaseCheckFailure === 0 &&
      input.releaseCheckPending === 0 &&
      releaseChecks.state === 'SUCCESS' &&
      releaseChecks.failure === 0 &&
      releaseChecks.pending === 0;
    if (!omitsOnlyPositiveEvidence) {
      for (const [field, inputField] of mismatches) {
        failures.push(
          `${tag}: gate evidence.releaseChecks ${field} must match score input ${inputField}`,
        );
      }
    }
  }
}

function releaseCheckContextDisposition(context) {
  const conclusion = releaseCheckContextState(context.conclusion);
  const status = releaseCheckContextState(context.status);
  const conclusionDisposition = releaseCheckStateDisposition(conclusion);
  const statusDisposition = status === 'COMPLETED'
    ? null
    : releaseCheckStateDisposition(status);
  if (
    conclusionDisposition &&
    statusDisposition &&
    conclusionDisposition !== statusDisposition
  ) {
    return 'ambiguous';
  }
  return conclusionDisposition ?? statusDisposition ?? 'ambiguous';
}

function releaseCheckStateDisposition(state) {
  if (!state) return null;
  if (releaseCheckFailureStates.has(state)) return 'failure';
  if (releaseCheckPendingStates.has(state)) return 'pending';
  if (releaseCheckSuccessStates.has(state)) return 'success';
  if (releaseCheckSkippedStates.has(state)) return 'skipped';
  return null;
}

function releaseCheckContextState(value) {
  if (value == null) return '';
  if (typeof value !== 'string') return '__INVALID__';
  const normalized = normalizeReleaseCheckState(value);
  return normalized === value ? normalized : '__INVALID__';
}

function normalizeReleaseCheckState(value) {
  return String(value).trim().toUpperCase().replace(/[\s-]+/g, '_');
}

function verifyExplanationContract({ failures, tag, path, explanation }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: explanation,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.explanation,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.explanation,
    expectedSchemaVersion: 5,
  })) return;

  verifyScoreLedgerContract({
    failures,
    tag,
    path: `${path}.scoreLedger`,
    ledger: explanation.scoreLedger,
  });
  for (const key of ['positives', 'limits']) {
    verifyArrayContract({
      failures,
      tag,
      path: `${path}.${key}`,
      value: explanation[key],
    });
  }
  for (const key of ['positiveDetails', 'limitDetails']) {
    verifyExplanationDetailsContract({
      failures,
      tag,
      path: `${path}.${key}`,
      details: explanation[key],
    });
  }
  if (verifyArrayContract({
    failures,
    tag,
    path: `${path}.authorityReferences`,
    value: explanation.authorityReferences,
  })) {
    const identities = new Set();
    for (const [index, reference] of explanation.authorityReferences.entries()) {
      verifyScoreAuthorityReferenceContract({
        failures,
        tag,
        path: `${path}.authorityReferences[${index}]`,
        reference,
      });
      const identity = `${reference?.subjectKind}\0${reference?.subjectIdentity}`;
      expect(failures, tag, !identities.has(identity),
        `${path}.authorityReferences contains duplicate ${identity}`);
      identities.add(identity);
    }
  }
}

function verifyScoreLedgerContract({ failures, tag, path, ledger }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: ledger,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedger,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedger,
    expectedSchemaVersion: SCORE_LEDGER_SCHEMA_VERSION,
  })) return;
  expect(failures, tag, ledger.ledgerType === SCORE_LEDGER_TYPE,
    `${path}.ledgerType must be ${SCORE_LEDGER_TYPE}`);
  expect(failures, tag, ledger.immutable === true,
    `${path}.immutable must be true`);
  verifyArrayContract({ failures, tag, path: `${path}.operations`, value: ledger.operations });

  if (verifyArrayContract({ failures, tag, path: `${path}.rows`, value: ledger.rows })) {
    for (const [index, row] of ledger.rows.entries()) {
      verifyObjectContract({
        failures,
        tag,
        path: `${path}.rows[${index}]`,
        value: row,
        allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedgerRow,
        requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerRow,
      });
    }
  }
  if (verifyArrayContract({ failures, tag, path: `${path}.caps`, value: ledger.caps })) {
    for (const [index, cap] of ledger.caps.entries()) {
      verifyObjectContract({
        failures,
        tag,
        path: `${path}.caps[${index}]`,
        value: cap,
        allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedgerCap,
        requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerCap,
      });
    }
  }
  verifyScoreLedgerExplanationAuditContract({
    failures,
    tag,
    path: `${path}.explanationAudit`,
    audit: ledger.explanationAudit,
  });
}

function verifyScoreLedgerExplanationAuditContract({ failures, tag, path, audit }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: audit,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedgerExplanationAudit,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationAudit,
    expectedSchemaVersion: 1,
  })) return;
  for (const key of [
    'baseLedgerDigest',
    'title',
    'verdict',
    'listsDigest',
    'recommendationDecisionDigest',
    'digest',
  ]) {
    expect(failures, tag, isNonEmptyString(audit[key]),
      `${path}.${key} must be a non-empty string`);
  }
  if (!verifyArrayContract({
    failures,
    tag,
    path: `${path}.details`,
    value: audit.details,
  })) return;
  for (const [detailIndex, detail] of audit.details.entries()) {
    const detailPath = `${path}.details[${detailIndex}]`;
    if (!verifyObjectContract({
      failures,
      tag,
      path: detailPath,
      value: detail,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedgerExplanationAuditDetail,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationAuditDetail,
    })) continue;
    expect(failures, tag, detail.section === 'limit' || detail.section === 'positive',
      `${detailPath}.section must be limit or positive`);
    expect(failures, tag, Number.isInteger(detail.index) && detail.index >= 0,
      `${detailPath}.index must be a non-negative integer`);
    for (const key of [
      'code',
      'label',
      'text',
      'metricsDigest',
      'bucketsDigest',
      'riskBucketsDigest',
      'issueRefsDigest',
    ]) {
      expect(failures, tag, isNonEmptyString(detail[key]),
        `${detailPath}.${key} must be a non-empty string`);
    }
    if (!verifyArrayContract({
      failures,
      tag,
      path: `${detailPath}.operations`,
      value: detail.operations,
    })) continue;
    for (const [receiptIndex, receipt] of detail.operations.entries()) {
      const receiptPath = `${detailPath}.operations[${receiptIndex}]`;
      if (!verifyObjectContract({
        failures,
        tag,
        path: receiptPath,
        value: receipt,
        allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreLedgerExplanationOperationReceipt,
        requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationOperationReceipt,
      })) continue;
      expect(failures, tag, Number.isInteger(receipt.sequence) && receipt.sequence >= 0,
        `${receiptPath}.sequence must be a non-negative integer`);
      for (const key of ['code', 'formulaCode', 'evidenceDigest']) {
        expect(failures, tag, isNonEmptyString(receipt[key]),
          `${receiptPath}.${key} must be a non-empty string`);
      }
    }
  }
}

function verifyExplanationDetailsContract({ failures, tag, path, details }) {
  if (!verifyArrayContract({ failures, tag, path, value: details })) return;
  for (const [detailIndex, detail] of details.entries()) {
    const detailPath = `${path}[${detailIndex}]`;
    if (!verifyObjectContract({
      failures,
      tag,
      path: detailPath,
      value: detail,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.explanationDetail,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.explanationDetail,
    })) continue;
    if (!Object.hasOwn(detail, 'issueRefs')) continue;
    if (!verifyArrayContract({
      failures,
      tag,
      path: `${detailPath}.issueRefs`,
      value: detail.issueRefs,
    })) continue;
    for (const [issueIndex, issueRef] of detail.issueRefs.entries()) {
      verifyExplanationIssueRefContract({
        failures,
        tag,
        path: `${detailPath}.issueRefs[${issueIndex}]`,
        issueRef,
      });
    }
  }
}

function verifyExplanationIssueRefContract({ failures, tag, path, issueRef }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: issueRef,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.explanationIssueRef,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.explanationIssueRef,
  })) return;
  if (Object.hasOwn(issueRef, 'confirmationReasons')) {
    if (verifyArrayContract({
      failures,
      tag,
      path: `${path}.confirmationReasons`,
      value: issueRef.confirmationReasons,
    })) {
      for (const [index, reason] of issueRef.confirmationReasons.entries()) {
        verifyConfirmationReasonContract({
          failures,
          tag,
          path: `${path}.confirmationReasons[${index}]`,
          reason,
        });
      }
    }
  }
  if (Object.hasOwn(issueRef, 'releaseLocalEvidence') && issueRef.releaseLocalEvidence != null) {
    verifyReleaseLocalEvidenceContract({
      failures,
      tag,
      path: `${path}.releaseLocalEvidence`,
      evidence: issueRef.releaseLocalEvidence,
    });
  }
  if (Object.hasOwn(issueRef, 'proof') && issueRef.proof != null) {
    verifyExplanationIssueProofContract({
      failures,
      tag,
      path: `${path}.proof`,
      proof: issueRef.proof,
    });
  }
}

function verifyConfirmationReasonContract({ failures, tag, path, reason }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: reason,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.confirmationReason,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.confirmationReason,
  })) return;

  expect(failures, tag, confirmationReasonCodes.has(reason.code),
    `${path}.code (${reason.code}) must be a known confirmation reason code`);
  expect(failures, tag, confirmationReasonSources.has(reason.source),
    `${path}.source (${reason.source}) must be comment or label_event`);
  expect(failures, tag, isNonEmptyString(reason.author),
    `${path}.author must be a non-empty string`);
  expect(failures, tag, isValidTimestamp(reason.occurredAt),
    `${path}.occurredAt must be a valid timestamp string`);
  verifyScoreAuthorityReferenceContract({
    failures,
    tag,
    path: `${path}.authorityReference`,
    reference: reason.authorityReference,
  });
  if (Object.hasOwn(reason, 'association')) {
    expect(failures, tag, reason.association == null || isNonEmptyString(reason.association),
      `${path}.association must be a non-empty string or null`);
  }
  if (Object.hasOwn(reason, 'commentId')) {
    expect(failures, tag, Number.isInteger(reason.commentId) && reason.commentId > 0,
      `${path}.commentId must be a positive integer`);
  }
  for (const key of ['commentUrl', 'eventId', 'snippet']) {
    if (Object.hasOwn(reason, key)) {
      expect(failures, tag, isNonEmptyString(reason[key]),
        `${path}.${key} must be a non-empty string`);
    }
  }
  if (Object.hasOwn(reason, 'label')) {
    expect(failures, tag, confirmationReasonLabels.has(reason.label),
      `${path}.label (${reason.label}) must be P0, P1, or regression`);
  }

  if (reason.source === 'comment') {
    verifyRequiredKeys({
      failures,
      tag,
      path,
      value: reason,
      requiredKeys: [
        'updatedAt',
        'commentId',
        'commentUrl',
        'issueNodeId',
        'issueAuthorNodeId',
        'issueAuthorType',
        'commentNodeId',
        'commentNodeType',
        'actorNodeId',
        'actorType',
        'commentBodyDigest',
        'snippet',
        'authorityReference',
      ],
    });
    expect(failures, tag, reason.code === 'independent_human_reproduction',
      `${path}.code must be independent_human_reproduction for comment evidence`);
    expect(failures, tag, isValidTimestamp(reason.updatedAt),
      `${path}.updatedAt must be a valid timestamp string`);
    expect(failures, tag,
      isValidTimestamp(reason.updatedAt) &&
        Date.parse(reason.updatedAt) >= Date.parse(reason.occurredAt),
      `${path}.updatedAt cannot precede occurredAt`);
    for (const key of [
      'issueNodeId',
      'issueAuthorNodeId',
      'issueAuthorType',
      'commentNodeId',
      'actorNodeId',
    ]) {
      expect(failures, tag, isNonEmptyString(reason[key]),
        `${path}.${key} must be a non-empty string`);
    }
    expect(failures, tag, reason.commentNodeType === 'IssueComment',
      `${path}.commentNodeType must be IssueComment`);
    expect(failures, tag, reason.actorType === 'User',
      `${path}.actorType must be User`);
    expect(failures, tag,
      typeof reason.commentBodyDigest === 'string' &&
        /^[0-9a-f]{64}$/.test(reason.commentBodyDigest),
      `${path}.commentBodyDigest must be SHA-256`);
    expect(failures, tag,
      reason.actorNodeId !== reason.issueAuthorNodeId ||
        reason.actorType !== reason.issueAuthorType,
      `${path} actor must be independent from the issue author`);
    expect(failures, tag,
      reason.authorityReference?.subjectKind === 'comment' &&
        reason.authorityReference?.subjectIdentity === reason.commentNodeId,
      `${path}.authorityReference must bind the exact comment`);
    for (const key of ['label', 'eventId']) {
      expect(failures, tag, !Object.hasOwn(reason, key),
        `${path}.${key} is not allowed for comment evidence`);
    }
  } else if (reason.source === 'label_event') {
    verifyRequiredKeys({
      failures,
      tag,
      path,
      value: reason,
      requiredKeys: ['label', 'eventId'],
    });
    expect(failures, tag,
      reason.authorityReference?.subjectKind === 'label_event' &&
        reason.authorityReference?.subjectIdentity === reason.eventId,
      `${path}.authorityReference must bind the exact label event`);
    if (confirmationReasonLabels.has(reason.label)) {
      expect(failures, tag, reason.code === confirmationReasonCodeByLabel.get(reason.label),
        `${path}.code must match label ${reason.label}`);
    }
    for (const key of [
      'association',
      'updatedAt',
      'commentId',
      'commentUrl',
      'issueNodeId',
      'issueAuthorNodeId',
      'issueAuthorType',
      'commentNodeId',
      'commentNodeType',
      'actorNodeId',
      'actorType',
      'commentBodyDigest',
      'snippet',
    ]) {
      expect(failures, tag, !Object.hasOwn(reason, key),
        `${path}.${key} is not allowed for label_event evidence`);
    }
  }
}

function verifyScoreAuthorityReferenceContract({
  failures,
  tag,
  path,
  reference,
}) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: reference,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.scoreAuthorityReference,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.scoreAuthorityReference,
  })) return;
  expect(failures, tag,
    ['closure_claim', 'comment', 'label_event'].includes(reference.subjectKind),
    `${path}.subjectKind must be closure_claim, comment, or label_event`);
  expect(failures, tag, isNonEmptyString(reference.subjectIdentity),
    `${path}.subjectIdentity must be a non-empty string`);
  for (const key of ['resolutionHash', 'evidenceDigest']) {
    expect(failures, tag,
      typeof reference[key] === 'string' && /^[0-9a-f]{64}$/.test(reference[key]),
      `${path}.${key} must be SHA-256`);
  }
  expect(failures, tag, reference.authorizedForScoring === true,
    `${path}.authorizedForScoring must be exactly true`);
}

function verifyReleaseLocalEvidenceContract({ failures, tag, path, evidence }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: evidence,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.releaseLocalEvidence,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.releaseLocalEvidence,
  })) return;

  expect(failures, tag, evidence.kind === 'exact-version',
    `${path}.kind must be exact-version`);
  expect(failures, tag, releaseLocalEvidenceSources.has(evidence.source),
    `${path}.source (${evidence.source}) must be title, body, or comment`);
  expect(failures, tag, isNonEmptyString(evidence.version),
    `${path}.version must be a non-empty string`);
  expect(failures, tag, isNonEmptyString(evidence.snippet),
    `${path}.snippet must be a non-empty string`);
  if (Object.hasOwn(evidence, 'commentId')) {
    expect(failures, tag, Number.isInteger(evidence.commentId) && evidence.commentId > 0,
      `${path}.commentId must be a positive integer`);
  }
  for (const key of [
    'commentUrl',
    'commentNodeId',
    'author',
    'actorNodeId',
  ]) {
    if (Object.hasOwn(evidence, key)) {
      expect(failures, tag, isNonEmptyString(evidence[key]),
        `${path}.${key} must be a non-empty string`);
    }
  }

  if (evidence.source === 'comment') {
    verifyRequiredKeys({
      failures,
      tag,
      path,
      value: evidence,
      requiredKeys: [
        'commentId',
        'commentUrl',
        'commentNodeId',
        'author',
        'actorNodeId',
        'actorType',
        'association',
        'occurredAt',
        'updatedAt',
        'commentBodyDigest',
        'authorityReference',
      ],
    });
    verifyScoreAuthorityReferenceContract({
      failures,
      tag,
      path: `${path}.authorityReference`,
      reference: evidence.authorityReference,
    });
    expect(failures, tag,
      evidence.authorityReference?.subjectKind === 'comment' &&
        evidence.authorityReference?.subjectIdentity === evidence.commentNodeId,
      `${path}.authorityReference must bind the exact comment`);
    expect(failures, tag, evidence.actorType === 'User',
      `${path}.actorType must be User`);
    expect(failures, tag,
      evidence.association == null || isNonEmptyString(evidence.association),
      `${path}.association must be a non-empty string or null`);
    expect(failures, tag, isValidTimestamp(evidence.occurredAt),
      `${path}.occurredAt must be a valid timestamp string`);
    expect(failures, tag, isValidTimestamp(evidence.updatedAt),
      `${path}.updatedAt must be a valid timestamp string`);
    expect(failures, tag,
      isValidTimestamp(evidence.occurredAt) &&
        isValidTimestamp(evidence.updatedAt) &&
        Date.parse(evidence.updatedAt) >= Date.parse(evidence.occurredAt),
      `${path}.updatedAt cannot precede occurredAt`);
    expect(failures, tag,
      typeof evidence.commentBodyDigest === 'string' &&
        /^[0-9a-f]{64}$/.test(evidence.commentBodyDigest),
      `${path}.commentBodyDigest must be SHA-256`);
  } else if (releaseLocalEvidenceSources.has(evidence.source)) {
    for (const key of [
      'commentId',
      'commentUrl',
      'commentNodeId',
      'author',
      'actorNodeId',
      'actorType',
      'association',
      'occurredAt',
      'updatedAt',
      'commentBodyDigest',
      'authorityReference',
    ]) {
      expect(failures, tag, !Object.hasOwn(evidence, key),
        `${path}.${key} is not allowed for ${evidence.source} evidence`);
    }
  }
}

function verifyExplanationIssueProofContract({ failures, tag, path, proof }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: proof,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.explanationIssueProof,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.explanationIssueProof,
  })) return;
  if (Object.hasOwn(proof, 'canonicalIssue') && proof.canonicalIssue != null) {
    verifyExplanationLinkedRefContract({
      failures,
      tag,
      path: `${path}.canonicalIssue`,
      ref: proof.canonicalIssue,
    });
  }
  for (const key of [
    'openPrs',
    'reachablePrs',
    'notReachablePrs',
    'unknownReachabilityPrs',
    'closedUnmergedPrs',
    'externalClosingPrs',
  ]) {
    if (!Object.hasOwn(proof, key) || proof[key] == null) continue;
    if (!verifyArrayContract({ failures, tag, path: `${path}.${key}`, value: proof[key] })) continue;
    for (const [index, ref] of proof[key].entries()) {
      verifyExplanationLinkedRefContract({
        failures,
        tag,
        path: `${path}.${key}[${index}]`,
        ref,
      });
    }
  }
}

function verifyExplanationLinkedRefContract({ failures, tag, path, ref }) {
  verifyObjectContract({
    failures,
    tag,
    path,
    value: ref,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.explanationLinkedRef,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.explanationLinkedRef,
  });
}

function verifyFixProvenanceContract({ failures, tag, path, fixProvenance }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: fixProvenance,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.fixProvenance,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.fixProvenance,
  })) return;
  verifyObjectContract({
    failures,
    tag,
    path: `${path}.predecessorBoundary`,
    value: fixProvenance.predecessorBoundary,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.predecessorBoundary,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.predecessorBoundary,
    expectedSchemaVersion: 1,
  });
  verifyClosureProofContract({
    failures,
    tag,
    path: `${path}.closureProof`,
    closureProof: fixProvenance.closureProof,
  });
  verifyReleaseFixCreditContract({
    failures,
    tag,
    path: `${path}.releaseFixCredit`,
    releaseFixCredit: fixProvenance.releaseFixCredit,
  });
}

function verifyClosureProofContract({ failures, tag, path, closureProof }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: closureProof,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.closureProof,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.closureProof,
    expectedSchemaVersion: 1,
  })) return;
  verifyObjectContract({
    failures,
    tag,
    path: `${path}.fixCreditDecisionCounts`,
    value: closureProof.fixCreditDecisionCounts,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.fixCreditDecisionCounts,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecisionCounts,
  });
  verifyObjectContract({
    failures,
    tag,
    path: `${path}.riskSummary`,
    value: closureProof.riskSummary,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.closureProofRiskSummary,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.closureProofRiskSummary,
  });
  if (verifyArrayContract({
    failures,
    tag,
    path: `${path}.fixCreditDecisions`,
    value: closureProof.fixCreditDecisions,
  })) {
    for (const [index, decision] of closureProof.fixCreditDecisions.entries()) {
      verifyFixCreditDecisionContract({
        failures,
        tag,
        path: `${path}.fixCreditDecisions[${index}]`,
        decision,
      });
    }
  }
  for (const key of ['neutralAuditExamples', 'examples']) {
    verifyArrayContract({
      failures,
      tag,
      path: `${path}.${key}`,
      value: closureProof[key],
    });
  }
}

function verifyReleaseFixCreditContract({ failures, tag, path, releaseFixCredit }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: releaseFixCredit,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.releaseFixCredit,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.releaseFixCredit,
    expectedSchemaVersion: 1,
  })) return;
  verifyObjectContract({
    failures,
    tag,
    path: `${path}.decisionCounts`,
    value: releaseFixCredit.decisionCounts,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.fixCreditDecisionCounts,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecisionCounts,
  });
  if (!verifyArrayContract({
    failures,
    tag,
    path: `${path}.decisions`,
    value: releaseFixCredit.decisions,
  })) return;
  for (const [index, decision] of releaseFixCredit.decisions.entries()) {
    verifyFixCreditDecisionContract({
      failures,
      tag,
      path: `${path}.decisions[${index}]`,
      decision,
    });
  }
}

function verifyFixCreditDecisionContract({ failures, tag, path, decision }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: decision,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.fixCreditDecision,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecision,
    expectedSchemaVersion: 1,
  })) return;
  if (!verifyArrayContract({
    failures,
    tag,
    path: `${path}.proofIdentities`,
    value: decision.proofIdentities,
  })) return;
  for (const [index, proofIdentity] of decision.proofIdentities.entries()) {
    verifyFixCreditProofIdentityContract({
      failures,
      tag,
      path: `${path}.proofIdentities[${index}]`,
      proofIdentity,
    });
  }
}

function verifyFixCreditProofIdentityContract({ failures, tag, path, proofIdentity }) {
  if (!isObject(proofIdentity)) {
    failures.push(`${tag}: ${path} must be an object`);
    return;
  }
  if (!Object.hasOwn(proofIdentity, 'kind')) {
    failures.push(`${tag}: ${path} is missing required field kind`);
    return;
  }
  if (proofIdentity.kind === 'trusted_pull_request') {
    if (!verifyObjectContract({
      failures,
      tag,
      path,
      value: proofIdentity,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.trustedPullRequestProof,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.trustedPullRequestProof,
    })) return;
    verifyReachabilityProofContract({
      failures,
      tag,
      path: `${path}.target`,
      proof: proofIdentity.target,
    });
    verifyReachabilityProofContract({
      failures,
      tag,
      path: `${path}.predecessor`,
      proof: proofIdentity.predecessor,
    });
    return;
  }
  if (proofIdentity.kind === 'direct_commit') {
    if (!verifyObjectContract({
      failures,
      tag,
      path,
      value: proofIdentity,
      allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.directCommitProof,
      requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.directCommitProof,
    })) return;
    for (const field of ['target', 'predecessor', 'releaseAncestry']) {
      verifyDirectCommitReachabilityProofContract({
        failures,
        tag,
        path: `${path}.${field}`,
        proof: proofIdentity[field],
      });
    }
    return;
  }
  failures.push(`${tag}: ${path}.kind (${proofIdentity.kind}) must be a known proof identity kind`);
}

function verifyDirectCommitReachabilityProofContract({ failures, tag, path, proof }) {
  if (!verifyObjectContract({
    failures,
    tag,
    path,
    value: proof,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.directCommitReachabilityProof,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.directCommitReachabilityProof,
    nullable: true,
  })) return;
  if (!isObject(proof.evidence)) {
    failures.push(`${tag}: ${path}.evidence must be an object`);
  }
}

function verifyReachabilityProofContract({ failures, tag, path, proof }) {
  verifyObjectContract({
    failures,
    tag,
    path,
    value: proof,
    allowedKeys: SCORE_AUDIT_ALLOWED_NESTED_KEYS.reachabilityProof,
    requiredKeys: SCORE_AUDIT_REQUIRED_KEYS.reachabilityProof,
    nullable: true,
  });
}

function verifyObjectContract({
  failures,
  tag,
  path,
  value,
  allowedKeys,
  requiredKeys,
  expectedSchemaVersion,
  nullable = false,
}) {
  if (value == null && nullable) return false;
  if (!isObject(value)) {
    failures.push(`${tag}: ${path} must be an object${nullable ? ' or null' : ''}`);
    return false;
  }
  const allowed = new Set(allowedKeys);
  for (const key of Object.keys(value).sort()) {
    if (!allowed.has(key)) failures.push(`${tag}: ${path} has unexpected key ${key}`);
  }
  verifyRequiredKeys({ failures, tag, path, value, requiredKeys });
  if (expectedSchemaVersion !== undefined && value.schemaVersion !== expectedSchemaVersion) {
    failures.push(
      `${tag}: ${path} schemaVersion (${value.schemaVersion}) must equal ${expectedSchemaVersion}`,
    );
  }
  return true;
}

function verifyRequiredKeys({ failures, tag, path, value, requiredKeys }) {
  for (const key of requiredKeys) {
    if (!Object.hasOwn(value, key)) {
      failures.push(`${tag}: ${path} is missing required field ${key}`);
    }
  }
}

function verifyArrayContract({ failures, tag, path, value, nullable = false }) {
  if (value == null && nullable) return false;
  if (!Array.isArray(value)) {
    failures.push(`${tag}: ${path} must be an array${nullable ? ' or null' : ''}`);
    return false;
  }
  return true;
}

function expectedRecommendationDecisionCode(decision, status, qualifies) {
  if (status !== 'eligible') return 'install_gate_active';
  if (!qualifies) return 'below_recommendation_threshold';
  if (decision.selected && decision.releaseTag === decision.highestScoringTag) return 'highest_confidence';
  if (decision.selected) return 'newest_within_confidence_tolerance';
  if (isFiniteNumber(decision.selectedScore) &&
      isFiniteNumber(decision.releaseScore) &&
      decision.releaseScore >= decision.selectedScore) {
    return 'newer_release_within_tolerance_selected';
  }
  return 'higher_confidence_release_selected';
}

function isObject(value) {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function isNonEmptyString(value) {
  return typeof value === 'string' && value.length > 0;
}

function isValidTimestamp(value) {
  return isNonEmptyString(value) && Number.isFinite(Date.parse(value));
}

function isNullableFiniteNumber(value) {
  return value == null || isFiniteNumber(value);
}

function isNullableTag(value) {
  return value == null || typeof value === 'string' && value.length > 0;
}

function sameJsonValue(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function roundMetric(value) {
  return Math.round(value * 1000) / 1000;
}

function expect(failures, tag, condition, message) {
  if (!condition) failures.push(`${tag}: ${message}`);
}
