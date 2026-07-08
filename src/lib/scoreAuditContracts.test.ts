import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { createHash } from 'node:crypto';
import {
  SCORE_AUDIT_REQUIRED_KEYS,
  verifyScoreAuditPayloadContracts,
} from './scoreAuditContracts.ts';
import {
  bindScoreExplanationAudit,
  buildScoreLedgerV2,
  installConfidence,
} from './score.ts';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  repositoryPermissionObservationRowHash,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';
import {
  buildScoreAuthorityReference,
  buildScoreAuthorityResolution,
  buildScoreCommentAuthorityResolution,
  type ScoreAuthorityReference,
} from './scoreAuthorityResolution.ts';
import { buildArtifactVerificationEvidence } from './artifactVerification.ts';
import {
  buildReleaseArtifactObservation,
  buildReleaseArtifactReceipt,
} from './releaseArtifactReceipt.ts';

const versions = {
  scoreInput: 2,
  scoreComponents: 1,
  issueEvidence: 2,
  gateEvidence: 1,
};
const tagOid = 'a'.repeat(40);
const mergeOid = 'b'.repeat(40);
const predecessorOid = 'c'.repeat(40);
const directCommitOid = 'd'.repeat(40);
const artifactVersion = '-test';
const artifactTarballUrl =
  `https://registry.npmjs.org/openclaw/-/openclaw-${artifactVersion}.tgz`;
const artifactReportUrl =
  `https://github.com/openclaw/openclaw/blob/${tagOid}/release-evidence.json`;

function noArtifactVerificationGate() {
  return {
    schemaVersion: 2,
    observationId: null,
    receiptId: null,
    evidenceIdentity: null,
    evidenceReportIdentity: null,
    runId: null,
    observedAt: null,
    observationContentHash: null,
    observationPreviousContentHash: null,
    receiptContentHash: null,
    receiptPreviousContentHash: null,
    release: null,
    releaseMetadata: null,
    artifact: null,
    evidenceReport: null,
    npmPackageUrl: null,
    releaseTarballUrl: null,
    releaseIntegrity: null,
    releaseSha: null,
    releaseShaMatches: null,
    ciReportUrl: null,
    ciReportVerified: false,
    ciReportMismatch: null,
    fullReleaseValidationUrl: null,
    releaseValidationVerified: false,
    releaseValidationMismatch: null,
    registryVersion: null,
    registryIntegrity: null,
    registryTarballUrl: null,
    verified: false,
    mismatch: null,
  };
}

function canonicalArtifactVerificationGate() {
  const bytes = Buffer.from('score audit contract artifact bytes');
  const digest = createHash('sha512').update(bytes).digest('base64');
  const integrity = `sha512-${digest}`;
  const release = {
    repository: 'openclaw/openclaw',
    tag: 'v-test',
    releaseNodeId: 'RE_score_audit_contract',
    catalogTagCommitOid: tagOid,
    publishedAt: '2026-06-01T00:00:00.000Z',
  };
  const releaseMetadata = {
    npmPackageUrl:
      `https://www.npmjs.com/package/openclaw/v/${artifactVersion}`,
    releaseTarballUrl: artifactTarballUrl,
    releaseIntegrity: integrity,
    releaseSha: tagOid,
    ciReportUrl: artifactReportUrl,
    fullReleaseValidationUrl: null,
  };
  const artifact = buildArtifactVerificationEvidence({
    packageName: 'openclaw',
    requestedVersion: artifactVersion,
    metadataUrl:
      `https://registry.npmjs.org/openclaw/${artifactVersion}`,
    metadataContentDigest: '5'.repeat(64),
    registryAvailability: 'available',
    registryPackageName: 'openclaw',
    registryVersion: artifactVersion,
    registryIntegrity: integrity,
    registryTarballUrl: artifactTarballUrl,
    registryGitHead: tagOid,
    actualDigests: { sha512: digest },
    tarballByteCount: bytes.length,
    expectedIntegrity: integrity,
    expectedTarballUrl: artifactTarballUrl,
    expectedReleaseSha: tagOid,
  });
  const evidenceReport = {
    url: artifactReportUrl,
    rawUrl:
      `https://raw.githubusercontent.com/openclaw/openclaw/${tagOid}/` +
      'release-evidence.json',
    fallbackUrl: null,
    fallbackKind: null,
    fallbackArtifactCount: 0,
    contentDigest: '6'.repeat(64),
    fallbackArtifactDigest: null,
    expectedReleaseTag: 'v-test',
    expectedReleaseSha: tagOid,
    verified: true,
    mismatch: null,
  };
  const receipt = buildReleaseArtifactReceipt({
    release,
    releaseMetadata,
    artifact,
    evidenceReport,
    previousContentHash: '7'.repeat(64),
  });
  const observation = buildReleaseArtifactObservation({
    runId: 'score-audit-artifact-run',
    observedAt: '2026-06-02T00:00:00.000Z',
    release,
    receipt,
    previousContentHash: '8'.repeat(64),
  });
  return {
    schemaVersion: 2,
    observationId: observation.observationId,
    receiptId: receipt.receiptId,
    evidenceIdentity: receipt.evidenceIdentity,
    evidenceReportIdentity: receipt.evidenceReportIdentity,
    runId: observation.runId,
    observedAt: observation.observedAt,
    observationContentHash: observation.contentHash,
    observationPreviousContentHash: observation.previousContentHash,
    receiptContentHash: receipt.contentHash,
    receiptPreviousContentHash: receipt.previousContentHash,
    release: receipt.release,
    releaseMetadata: receipt.releaseMetadata,
    artifact: receipt.artifact,
    evidenceReport: receipt.evidenceReport,
    npmPackageUrl: receipt.releaseMetadata.npmPackageUrl,
    releaseTarballUrl: receipt.releaseMetadata.releaseTarballUrl,
    releaseIntegrity: receipt.releaseMetadata.releaseIntegrity,
    releaseSha: receipt.releaseMetadata.releaseSha,
    releaseShaMatches: true,
    ciReportUrl: receipt.releaseMetadata.ciReportUrl,
    ciReportVerified: receipt.evidenceReport.verified,
    ciReportMismatch: receipt.evidenceReport.mismatch,
    fullReleaseValidationUrl:
      receipt.releaseMetadata.fullReleaseValidationUrl,
    releaseValidationVerified: false,
    releaseValidationMismatch: null,
    registryVersion: receipt.artifact.version,
    registryIntegrity: receipt.artifact.integrity,
    registryTarballUrl: receipt.artifact.tarballUrl,
    verified: receipt.artifact.verified,
    mismatch: receipt.artifact.mismatch,
  };
}

function scoreLabelAuthorityReference(input: {
  eventId: string;
  label: string;
  issueNumber: number;
  eventTime: string;
}) {
  const actorNodeId = 'U_human-maintainer';
  const repositoryNodeId = 'R_score-audit-contracts-test';
  const permissionBase: RepositoryPermissionObservation = {
    kind: 'repository_permission_observation',
    evidenceId: `permission-${input.eventId}`,
    sourceIdentity: `permission:${input.eventId}`,
    repositoryNodeId,
    repository: 'openclaw/openclaw',
    actorNodeId,
    actorLogin: 'maintainer',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    permission: 'maintain',
    observedAt: new Date(
      Date.parse(input.eventTime) - 3_600_000,
    ).toISOString(),
    runHash: 'a'.repeat(64),
  };
  const permission = {
    ...permissionBase,
    rowHash: repositoryPermissionObservationRowHash(permissionBase),
  };
  const resolution = buildScoreAuthorityResolution({
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: `label-event:${input.eventId}`,
      repositoryNodeId,
      repository: 'openclaw/openclaw',
      issueNumber: input.issueNumber,
      eventId: input.eventId,
      action: 'labeled',
      label: input.label,
      eventTime: input.eventTime,
      actor: {
        nodeId: actorNodeId,
        login: 'maintainer',
        type: 'User',
        association: 'MEMBER',
      },
    },
    permissionObservations: [permission],
    approvedRosterEntries: [],
  });
  return buildScoreAuthorityReference(
    'label_event',
    input.eventId,
    resolution,
  );
}

function scoreCommentAuthorityReference(input: {
  issueNumber: number;
  issueNodeId: string;
  issueAuthorNodeId: string;
  issueAuthorType: string;
  commentNodeId: string;
  commentId: number;
  commentUrl: string;
  actorNodeId: string;
  commentCreatedAt: string;
  commentUpdatedAt: string;
  commentBodyDigest: string;
  claimSnippet: string;
}) {
  const resolution = buildScoreCommentAuthorityResolution({
    ...input,
    actorType: 'User',
  });
  return buildScoreAuthorityReference(
    'comment',
    input.commentNodeId,
    resolution,
  );
}

function sortedAuthorityReferences(
  references: readonly ScoreAuthorityReference[],
): ScoreAuthorityReference[] {
  return [...references].sort(
    (left, right) =>
      left.subjectKind.localeCompare(right.subjectKind) ||
      left.subjectIdentity.localeCompare(right.subjectIdentity),
  );
}

function validRecommendationDecision(overrides: Record<string, any> = {}) {
  return {
    schemaVersion: 1,
    policyCode: 'highest_confidence_with_recency_tolerance',
    threshold: 7,
    recencyTolerance: 0.5,
    selectedTag: 'v-test',
    selectedScore: 7.5,
    highestScoringTag: 'v-test',
    highestScore: 7.5,
    releaseTag: 'v-test',
    releaseScore: 7.5,
    qualifies: true,
    selected: true,
    recencyRank: 1,
    scoreRank: 1,
    scoreDeltaToHighest: 0,
    decisionCode: 'highest_confidence',
    summary: 'canonical summary',
    ...overrides,
  };
}

function validReachabilityProof(
  tag: string,
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
) {
  return {
    tag,
    status,
    tagCommitOid,
    checkedCommitOid: mergeOid,
    baseRefName: 'main',
    method: 'git-merge-base',
    checkedAt: '2026-06-01T01:00:00Z',
    evidenceReason: status === 'reachable'
      ? 'merge_commit_in_release_history'
      : 'not_reachable_from_release_tag',
    strictValid: true,
    validationReasonCode: null,
  };
}

function validDirectReachabilityProof(
  tag: string,
  status: 'reachable' | 'not_reachable',
  tagCommitOid: string,
  checkedCommitOid: string,
  evidenceReason:
    | 'fix_commit_in_release_history'
    | 'predecessor_release_in_target_history'
    | 'not_reachable_from_release_tag',
) {
  return {
    tag,
    status,
    tagCommitOid,
    checkedCommitOid,
    method: 'git-merge-base',
    evidence: {
      schemaVersion: 1,
      evidence: evidenceReason,
      method: 'git-merge-base',
      repositoryNameWithOwner: 'openclaw/openclaw',
      tagCommitOid,
      checkedCommitOid,
      baseRefName: null,
      commandStatus: status === 'reachable' ? 0 : 1,
      stdout: null,
      stderr: null,
      signal: null,
      timedOut: false,
      outputLimitExceeded: false,
      aborted: false,
    },
    strictValid: true,
    validationReasonCode: null,
  };
}

function validDirectCommitProof() {
  return {
    kind: 'direct_commit',
    schemaVersion: 1,
    repositoryNameWithOwner: 'openclaw/openclaw',
    commitOid: directCommitOid,
    targetTag: 'v-test',
    predecessorTag: 'v-previous',
    status: 'credited',
    reasonCode: 'first_containing_direct_commit',
    creditEligible: true,
    target: validDirectReachabilityProof(
      'v-test',
      'reachable',
      tagOid,
      directCommitOid,
      'fix_commit_in_release_history',
    ),
    predecessor: validDirectReachabilityProof(
      'v-previous',
      'not_reachable',
      predecessorOid,
      directCommitOid,
      'not_reachable_from_release_tag',
    ),
    releaseAncestry: validDirectReachabilityProof(
      'v-test',
      'reachable',
      tagOid,
      predecessorOid,
      'predecessor_release_in_target_history',
    ),
    strictValid: true,
    validationReasonCode: null,
  };
}

function validFixCreditDecision(overrides: Record<string, any> = {}) {
  return {
    schemaVersion: 1,
    issueNumber: 101,
    status: 'credited',
    reasonCode: 'first_containing_direct_commit',
    targetTag: 'v-test',
    predecessorTag: 'v-previous',
    proofIdentities: [{
      kind: 'trusted_pull_request',
      repositoryNameWithOwner: 'openclaw/openclaw',
      prNumber: 501,
      sources: ['closedByPullRequestsReferences'],
      merged: true,
      mergeCommitOid: mergeOid,
      baseRefName: 'main',
      target: validReachabilityProof('v-test', 'reachable', tagOid),
      predecessor: validReachabilityProof('v-previous', 'not_reachable', predecessorOid),
    }, validDirectCommitProof()],
    ...overrides,
  };
}

function debtTierSummary() {
  return {
    count: 0,
    weight: 0,
    storedWeight: 0,
    byInstallImpactClass: {},
  };
}

function closureRiskSummary() {
  return {
    creditedReleaseFixCount: 1,
    containedReleaseFixCount: 1,
    containedWithoutFirstCreditCount: 0,
    resolvedByCanonicalReleaseFixCount: 0,
    resolvedByReleaseFixProofCount: 0,
    knownNotInReleaseCount: 0,
    openCanonicalRiskCount: 0,
    unsupportedClosureClaimCount: 0,
    neutralOrNonActionableCount: 0,
    neutralHighImpactCount: 0,
    neutralBugShapedCount: 0,
    missingEvidenceCount: 0,
    unresolvedForReleaseCount: 0,
    unresolvedWeightedRisk: 0,
    weightedRiskByDisposition: {},
  };
}

function validPayloads(overrides: Record<string, any> = {}): any {
  const recommendationDecision = validRecommendationDecision();
  const fixCreditDecision = validFixCreditDecision();
  const commentAuthorityReference = scoreCommentAuthorityReference({
    issueNumber: 101,
    issueNodeId: 'I_101',
    issueAuthorNodeId: 'U_original-reporter',
    issueAuthorType: 'User',
    commentNodeId: 'IC_7001',
    commentId: 7001,
    commentUrl:
      'https://github.com/openclaw/openclaw/issues/101#issuecomment-7001',
    actorNodeId: 'U_community-reporter',
    commentCreatedAt: '2026-06-01T00:30:00Z',
    commentUpdatedAt: '2026-06-01T00:30:00Z',
    commentBodyDigest: 'a'.repeat(64),
    claimSnippet: 'Can confirm, I reproduced the same issue.',
  });
  const labelAuthorityReference = scoreLabelAuthorityReference({
    eventId: 'label-event-101-p0',
    label: 'P0',
    issueNumber: 101,
    eventTime: '2026-06-01T00:45:00Z',
  });
  const authorityReferences = sortedAuthorityReferences([
    commentAuthorityReference,
    labelAuthorityReference,
  ]);
  const explanationIssueRef = {
    number: 101,
    title: 'Release issue',
    url: null,
    confirmationReasons: [{
      code: 'independent_human_reproduction',
      source: 'comment',
      author: 'community-reporter',
      association: 'CONTRIBUTOR',
      occurredAt: '2026-06-01T00:30:00Z',
      updatedAt: '2026-06-01T00:30:00Z',
      commentId: 7001,
      commentUrl: 'https://github.com/openclaw/openclaw/issues/101#issuecomment-7001',
      issueNodeId: 'I_101',
      issueAuthorNodeId: 'U_original-reporter',
      issueAuthorType: 'User',
      commentNodeId: 'IC_7001',
      commentNodeType: 'IssueComment',
      actorNodeId: 'U_community-reporter',
      actorType: 'User',
      commentBodyDigest: 'a'.repeat(64),
      snippet: 'Can confirm, I reproduced the same issue.',
      authorityReference: commentAuthorityReference,
    }, {
      code: 'human_applied_p0',
      source: 'label_event',
      author: 'maintainer',
      occurredAt: '2026-06-01T00:45:00Z',
      label: 'P0',
      eventId: 'label-event-101-p0',
      authorityReference: labelAuthorityReference,
    }],
    releaseLocalEvidence: {
      kind: 'exact-version',
      source: 'comment',
      version: 'v-test',
      snippet: 'Can confirm this affects v-test.',
      commentId: 7001,
      commentUrl: 'https://github.com/openclaw/openclaw/issues/101#issuecomment-7001',
      commentNodeId: 'IC_7001',
      author: 'community-reporter',
      actorNodeId: 'U_community-reporter',
      actorType: 'User',
      association: 'CONTRIBUTOR',
      occurredAt: '2026-06-01T00:30:00Z',
      updatedAt: '2026-06-01T00:30:00Z',
      commentBodyDigest: 'a'.repeat(64),
      authorityReference: commentAuthorityReference,
    },
    proof: {
      status: 'fixed_in_release',
      statusLabel: 'Fixed in release',
      riskDisposition: 'credited_release_fix',
      riskDispositionLabel: 'Credited release fix',
      summary: null,
      riskWeight: 0,
      canonicalIssue: null,
      canonicalPath: null,
      openPrs: [{ number: 501 }],
      reachablePrs: [],
      notReachablePrs: [],
      unknownReachabilityPrs: [],
      closedUnmergedPrs: [],
      externalClosingPrs: [],
    },
  };
  const scoreInput = {
    schemaVersion: 2,
    affirmativeClosureRiskCeilingWeight: 40,
    publishedAt: '2026-06-01T00:00:00Z',
    isLatest: true,
    hoursToNextStable: null,
    hasHotfixSuccessor: false,
    betaCount: 0,
    breakingCount: 0,
    feltOpenedWeight: 0,
    feltClosedWeight: 0,
    verifiedDebtWeight: 0,
    carryoverDebtWeight: 0,
    staleDebtWeight: 0,
    verifiedDebtIssueCount: 0,
    carryoverDebtIssueCount: 0,
    staleDebtIssueCount: 0,
    unresolvedClosureRiskWeight: 0,
    unresolvedClosureIssueCount: 0,
    rawIssueCount: 0,
    classifiedIssueCount: 0,
    cveAffected: false,
    cveLoad: 0,
    releaseCheckState: null,
    releaseCheckTotal: 0,
    releaseCheckSuccess: 0,
    releaseCheckFailure: 0,
    releaseCheckPending: 0,
    artifactVerified: false,
    artifactMismatch: null,
    ciReportVerified: false,
    ciReportMismatch: null,
    releaseIntegrityPresent: false,
  };
  const scoreNow = Date.parse('2026-06-02T00:00:00Z');
  const scoreConfidence = installConfidence(scoreInput, scoreNow);
  const scoreLedger = structuredClone(buildScoreLedgerV2({
    input: scoreInput,
    confidence: scoreConfidence,
    now: scoreNow,
  }));
  const payloads = {
    tag: 'v-test',
    versions,
    scoredAt: new Date(scoreNow).toISOString(),
    input: scoreInput,
    components: {
      schemaVersion: 1,
      components: scoreConfidence.components,
      evidenceCoverage: scoreConfidence.evidenceCoverage,
      hotfix: scoreConfidence.hotfix,
      reason: 'ok',
      recommendationDecision,
      explanation: {
        schemaVersion: 5,
        title: 'Why not 10?',
        scoreLedger,
        positives: ['Hard gates passed.'],
        positiveDetails: [{
          code: 'hard_gates_passed',
          label: 'Install eligibility passed',
          text: 'Hard gates passed.',
          issueRefs: [explanationIssueRef],
        }],
        limits: ['No remaining score gap.'],
        limitDetails: [{
          code: 'no_remaining_score_gap',
          label: 'No remaining score gap',
          text: 'No remaining score gap.',
        }],
        verdict: 'Eligible for installation.',
        recommendationDecision: { ...recommendationDecision },
        authorityReferences,
      },
    },
    issueEvidence: {
      schemaVersion: 2,
      evidenceCounts: {
        verifiedDebt: 0,
        carryoverDebt: 0,
        staleDebt: 0,
        openedFeltSerious: 0,
        verifiedFixed: 0,
        unverifiedClosed: 0,
        unclassifiedIssues: 0,
        targetEvidenceAttribution: 0,
      },
      targetEvidenceAttribution: [],
      debtSummary: {
        verified: debtTierSummary(),
        carryover: debtTierSummary(),
        stale: debtTierSummary(),
      },
      verifiedDebt: [],
      carryoverDebt: [],
      staleDebt: [],
      openedFeltSerious: [],
      verifiedFixed: [],
      unverifiedClosed: [],
      unclassifiedIssues: [],
    },
    gateEvidence: {
      schemaVersion: 1,
      cve: { affected: false, load: 0 },
      stableTagsNewestFirst: ['v-test', 'v-previous'],
      betaCount: 0,
      breakingCount: 0,
      hoursToNextStable: null,
      hasHotfixSuccessor: false,
      releaseChecks: {
        schemaVersion: 2,
        state: null,
        total: 0,
        success: 0,
        failure: 0,
        pending: 0,
        skipped: 0,
        contextCount: 0,
        shownContextCount: 0,
        contextsTruncated: false,
        contexts: [],
      },
      artifactVerification: noArtifactVerificationGate(),
      labelTimeline: {
        schemaVersion: 1,
        cutoffAt: null,
        issueCount: 0,
        currentLabelCount: 0,
        timelineLabelCount: 0,
        snapshotLabelCount: 0,
        missingTimelineCount: 0,
        missingTimelineWithCurrentLabelsCount: 0,
        historicalCurrentLabelFallbackAllowed: true,
      },
      fixProvenance: {
        verifiedFixedCount: 1,
        creditedFixedCount: 1,
        unverifiedClosedCount: 0,
        predecessorBoundary: {
          schemaVersion: 1,
          oldestScoredStableTag: 'v-test',
          oldestScoredStablePredecessorTag: 'v-previous',
          targetTag: 'v-test',
          predecessorTag: 'v-previous',
        },
        closureProof: {
          schemaVersion: 2,
          creditedCount: 1,
          notCreditedCount: 0,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 0,
          targetTag: 'v-test',
          predecessorTag: 'v-previous',
          fixCreditDecisionCounts: { credited: 1, withheld: 0, invalid: 0 },
          fixCreditDecisions: [structuredClone(fixCreditDecision)],
          byStatus: { fixed_in_release: 1 },
          byRiskDisposition: { credited_release_fix: 1 },
          riskSummary: closureRiskSummary(),
          neutralAuditExamples: [],
          examplesByStatus: {},
          examples: [],
        },
        releaseFixCredit: {
          schemaVersion: 1,
          targetTag: 'v-test',
          predecessorTag: 'v-previous',
          countedClosedCount: 1,
          notCountedClosedCount: 0,
          analyzedClosedCount: 1,
          containedFixedCount: 1,
          containedNotCreditedCount: 0,
          decisionCounts: { credited: 1, withheld: 0, invalid: 0 },
          decisions: [structuredClone(fixCreditDecision)],
        },
      },
    },
  };
  payloads.components.explanation.scoreLedger = structuredClone(
    bindScoreExplanationAudit(scoreLedger, payloads.components.explanation),
  );
  return { ...payloads, ...overrides };
}

function bindCanonicalArtifactProof(payloads: any) {
  const artifactVerification = canonicalArtifactVerificationGate();
  payloads.gateEvidence.artifactVerification = artifactVerification;
  Object.assign(payloads.input, {
    artifactVerified: artifactVerification.verified,
    artifactMismatch: artifactVerification.mismatch,
    ciReportVerified: artifactVerification.ciReportVerified,
    ciReportMismatch: artifactVerification.ciReportMismatch,
    releaseIntegrityPresent: artifactVerification.releaseIntegrity != null,
    releaseShaMatches: artifactVerification.releaseShaMatches,
  });
  const evaluatedAt = Date.parse(
    payloads.components.explanation.scoreLedger.evaluatedAt,
  );
  const confidence = installConfidence(payloads.input, evaluatedAt);
  payloads.components.components = confidence.components;
  payloads.components.evidenceCoverage = confidence.evidenceCoverage;
  payloads.components.hotfix = confidence.hotfix;
  for (const decision of [
    payloads.components.recommendationDecision,
    payloads.components.explanation.recommendationDecision,
  ]) {
    decision.selectedScore = confidence.score;
    decision.highestScore = confidence.score;
    decision.releaseScore = confidence.score;
    decision.qualifies =
      confidence.status === 'eligible' &&
      confidence.score != null &&
      confidence.score >= decision.threshold;
  }
  const ledger = buildScoreLedgerV2({
    input: payloads.input,
    confidence,
    now: evaluatedAt,
  });
  payloads.components.explanation.scoreLedger = structuredClone(
    bindScoreExplanationAudit(ledger, payloads.components.explanation),
  );
}

function assertMissingField(
  path: string,
  requiredKeys: readonly string[],
  locate: (payloads: any) => Record<string, any>,
) {
  for (const field of requiredKeys) {
    const payloads = validPayloads();
    delete locate(payloads)[field];
    const failures = verifyScoreAuditPayloadContracts(payloads);
    assert.ok(
      failures.includes(`v-test: ${path} is missing required field ${field}`),
      `expected exact missing-field failure for ${path}.${field}; got ${failures.join('; ')}`,
    );
  }
}

describe('score audit payload contracts', () => {
  it('accepts a coherent current persisted payload', () => {
    assert.deepEqual(verifyScoreAuditPayloadContracts(validPayloads()), []);
  });

  it('exact-binds replay to persisted scoredAt across the 24h settle boundary', () => {
    const boundary = '2026-06-02T00:00:00.000Z';
    assert.deepEqual(
      verifyScoreAuditPayloadContracts(validPayloads({ scoredAt: boundary })),
      [],
    );

    for (const scoredAt of [
      '2026-06-01T23:59:59.999Z',
      '2026-06-02T00:00:00.001Z',
    ]) {
      const failures = verifyScoreAuditPayloadContracts(
        validPayloads({ scoredAt }),
      );
      assert.ok(failures.some((failure) =>
        failure.includes(
          'scoreLedger evaluatedAt must exactly match persisted scoredAt',
        )));
      assert.ok(failures.some((failure) =>
        failure.includes('scoreLedger semantic replay does not match')));
      if (scoredAt < boundary) {
        assert.ok(failures.some((failure) =>
          failure.includes(
            'ScoreLedgerV2 final tuple must match recomputed install confidence',
        )));
      }
    }

    const missing = validPayloads();
    delete missing.scoredAt;
    for (const payloads of [
      missing,
      validPayloads({ scoredAt: 'not-a-timestamp' }),
    ]) {
      const failures = verifyScoreAuditPayloadContracts(payloads);
      assert.ok(failures.some((failure) =>
        failure.includes('persisted scoredAt must be a valid timestamp')));
    }

    const equivalentInstant = verifyScoreAuditPayloadContracts(
      validPayloads({ scoredAt: '2026-06-02T00:00:00Z' }),
    );
    assert.ok(equivalentInstant.some((failure) =>
      failure.includes(
        'scoreLedger evaluatedAt must exactly match persisted scoredAt',
      )));
  });

  it('accepts the canonical no-artifact-observation projection', () => {
    const payloads = validPayloads();
    Object.assign(payloads.gateEvidence.artifactVerification, {
      observationId: null,
      receiptId: null,
      evidenceIdentity: null,
      evidenceReportIdentity: null,
    });
    assert.deepEqual(verifyScoreAuditPayloadContracts(payloads), []);
  });

  it('rejects malformed, partial, or input-divergent artifact proof bindings', () => {
    const cases: Array<[string, (payloads: any) => void, string]> = [
      [
        'partial proof',
        (payloads) => {
          bindCanonicalArtifactProof(payloads);
          payloads.gateEvidence.artifactVerification.observationId = null;
        },
        'immutable proof fields must be all null or all present',
      ],
      [
        'malformed receipt identity',
        (payloads) => {
          bindCanonicalArtifactProof(payloads);
          payloads.gateEvidence.artifactVerification.receiptId =
            'artifact-receipt-v2:not-a-hash';
        },
        'receiptId must be a canonical artifact receipt ID or null',
      ],
      [
        'receipt/evidence mismatch',
        (payloads) => {
          bindCanonicalArtifactProof(payloads);
          payloads.gateEvidence.artifactVerification.evidenceIdentity =
            '2'.repeat(64);
        },
        'receiptId must bind evidenceIdentity',
      ],
      [
        'score input divergence',
        (payloads) => {
          bindCanonicalArtifactProof(payloads);
          payloads.input.artifactVerified = false;
        },
        'score input artifactVerified must match',
      ],
      [
        'unbound retained evidence',
        (payloads) => {
          Object.assign(payloads.gateEvidence.artifactVerification, {
            observationId: null,
            receiptId: null,
            evidenceIdentity: null,
            evidenceReportIdentity: null,
            npmPackageUrl:
              'https://www.npmjs.com/package/openclaw/v/2026.6.10',
          });
        },
        'npmPackageUrl must be null without immutable artifact identities',
      ],
    ];

    for (const [label, mutate, expected] of cases) {
      const payloads = validPayloads();
      mutate(payloads);
      const failures = verifyScoreAuditPayloadContracts(payloads);
      assert.ok(
        failures.some((failure) => failure.includes(expected)),
        `${label} was not rejected: ${failures.join('; ')}`,
      );
    }
  });

  it('accepts replayable artifact proof and rejects nested or ledger drift', () => {
    const valid = validPayloads();
    bindCanonicalArtifactProof(valid);
    assert.deepEqual(verifyScoreAuditPayloadContracts(valid), []);

    const cases: Array<[string, (payloads: any) => void, string]> = [
      [
        'receipt ledger hash',
        (payloads) => {
          payloads.gateEvidence.artifactVerification.receiptContentHash =
            '9'.repeat(64);
        },
        'receiptContentHash must match semantic receipt replay',
      ],
      [
        'observation ledger hash',
        (payloads) => {
          payloads.gateEvidence.artifactVerification.observationContentHash =
            '9'.repeat(64);
        },
        'observationContentHash must match semantic observation replay',
      ],
      [
        'artifact digest facts',
        (payloads) => {
          payloads.gateEvidence.artifactVerification.artifact.actualDigests.sha512 =
            createHash('sha512').update('different bytes').digest('base64');
        },
        'receipt replay failed',
      ],
      [
        'release binding',
        (payloads) => {
          payloads.gateEvidence.artifactVerification.release.catalogTagCommitOid =
            '9'.repeat(40);
        },
        'receipt replay failed',
      ],
      [
        'flat projection',
        (payloads) => {
          payloads.gateEvidence.artifactVerification.registryVersion =
            'different-version';
        },
        'registryVersion must match nested immutable proof',
      ],
    ];
    for (const [label, mutate, expected] of cases) {
      const payloads = validPayloads();
      bindCanonicalArtifactProof(payloads);
      mutate(payloads);
      const failures = verifyScoreAuditPayloadContracts(payloads);
      assert.ok(
        failures.some((failure) => failure.includes(expected)),
        `${label} drift was not rejected: ${failures.join('; ')}`,
      );
    }
  });

  it('requires every field in the nested replayable artifact proof', () => {
    const cases: Array<[
      string,
      readonly string[],
      (payloads: any) => Record<string, any>,
    ]> = [
      [
        'gate evidence.artifactVerification.release',
        SCORE_AUDIT_REQUIRED_KEYS.artifactRelease,
        (payloads) => payloads.gateEvidence.artifactVerification.release,
      ],
      [
        'gate evidence.artifactVerification.releaseMetadata',
        SCORE_AUDIT_REQUIRED_KEYS.artifactReleaseMetadata,
        (payloads) =>
          payloads.gateEvidence.artifactVerification.releaseMetadata,
      ],
      [
        'gate evidence.artifactVerification.artifact',
        SCORE_AUDIT_REQUIRED_KEYS.artifactEvidence,
        (payloads) => payloads.gateEvidence.artifactVerification.artifact,
      ],
      [
        'gate evidence.artifactVerification.artifact.actualDigests',
        SCORE_AUDIT_REQUIRED_KEYS.artifactActualDigests,
        (payloads) =>
          payloads.gateEvidence.artifactVerification.artifact.actualDigests,
      ],
      [
        'gate evidence.artifactVerification.evidenceReport',
        SCORE_AUDIT_REQUIRED_KEYS.artifactEvidenceReport,
        (payloads) =>
          payloads.gateEvidence.artifactVerification.evidenceReport,
      ],
    ];
    for (const [path, requiredKeys, locate] of cases) {
      for (const field of requiredKeys) {
        const payloads = validPayloads();
        bindCanonicalArtifactProof(payloads);
        delete locate(payloads)[field];
        const failures = verifyScoreAuditPayloadContracts(payloads);
        assert.ok(
          failures.includes(
            `v-test: ${path} is missing required field ${field}`,
          ),
          `expected ${path}.${field} to be required; got ${failures.join('; ')}`,
        );
      }
    }
  });

  it('rejects shape-valid explanation prose, metric, issue, and ledger-receipt tampering', () => {
    const cases: Array<[string, (payloads: any) => void]> = [
      ['prose', (payloads) => {
        payloads.components.explanation.positives[0] = 'Hard gates definitely passed.';
        payloads.components.explanation.positiveDetails[0].text =
          'Hard gates definitely passed.';
      }],
      ['metric', (payloads) => {
        payloads.components.explanation.positiveDetails[0].metrics = {
          hardGateCount: 999,
        };
      }],
      ['issue reference', (payloads) => {
        payloads.components.explanation.positiveDetails[0].issueRefs[0].title =
          'Tampered issue title';
      }],
      ['ordered ledger receipt', (payloads) => {
        const receipt =
          payloads.components.explanation.scoreLedger.explanationAudit.details[0]
            .operations[0];
        receipt.formulaCode = `${receipt.formulaCode}.tampered`;
      }],
    ];

    for (const [label, mutate] of cases) {
      const payloads = validPayloads();
      mutate(payloads);
      const failures = verifyScoreAuditPayloadContracts(payloads);
      assert.ok(
        failures.some((failure) =>
          failure.includes('canonical replay') ||
          failure.includes('operation receipt does not match the ordered ledger') ||
          failure.includes('explanationAudit digest does not match')),
        `${label} tamper was not rejected: ${failures.join('; ')}`,
      );
    }
  });

  it('rejects explanations without the canonical replay receipt', () => {
    const payloads = validPayloads();
    delete payloads.components.explanation.scoreLedger.explanationAudit;
    const failures = verifyScoreAuditPayloadContracts(payloads);
    assert.ok(failures.includes(
      'v-test: score components.explanation.scoreLedger is missing required field explanationAudit',
    ));
    assert.ok(failures.some((failure) =>
      failure.includes('missing the required canonical explanation replay receipt')));
  });

  it('rejects schema-only payloads with precise missing paths', () => {
    const failures = verifyScoreAuditPayloadContracts(validPayloads({
      input: { schemaVersion: 2 },
      components: { schemaVersion: 1 },
      issueEvidence: { schemaVersion: 2 },
      gateEvidence: { schemaVersion: 1 },
    }));

    assert.ok(failures.includes('v-test: score input is missing required field publishedAt'));
    assert.ok(failures.includes('v-test: score components is missing required field components'));
    assert.ok(failures.includes('v-test: issue evidence is missing required field evidenceCounts'));
    assert.ok(failures.includes('v-test: gate evidence is missing required field cve'));
  });

  it('rejects every one-missing-field adversarial payload at its exact path', () => {
    const cases: Array<[
      string,
      readonly string[],
      (payloads: any) => Record<string, any>,
    ]> = [
      ['score input', SCORE_AUDIT_REQUIRED_KEYS.input, (p) => p.input],
      ['score components', SCORE_AUDIT_REQUIRED_KEYS.components, (p) => p.components],
      ['score components.components', SCORE_AUDIT_REQUIRED_KEYS.installComponents, (p) => p.components.components],
      ['score components.explanation', SCORE_AUDIT_REQUIRED_KEYS.explanation, (p) => p.components.explanation],
      ['score components.explanation.scoreLedger', SCORE_AUDIT_REQUIRED_KEYS.scoreLedger, (p) => p.components.explanation.scoreLedger],
      ['score components.explanation.scoreLedger.rows[0]', SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerRow, (p) => p.components.explanation.scoreLedger.rows[0]],
      ['score components.explanation.scoreLedger.caps[0]', SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerCap, (p) => p.components.explanation.scoreLedger.caps[0]],
      ['score components.explanation.scoreLedger.explanationAudit', SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationAudit, (p) => p.components.explanation.scoreLedger.explanationAudit],
      ['score components.explanation.scoreLedger.explanationAudit.details[0]', SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationAuditDetail, (p) => p.components.explanation.scoreLedger.explanationAudit.details[0]],
      ['score components.explanation.scoreLedger.explanationAudit.details[0].operations[0]', SCORE_AUDIT_REQUIRED_KEYS.scoreLedgerExplanationOperationReceipt, (p) => p.components.explanation.scoreLedger.explanationAudit.details[0].operations[0]],
      ['score components.explanation.positiveDetails[0]', SCORE_AUDIT_REQUIRED_KEYS.explanationDetail, (p) => p.components.explanation.positiveDetails[0]],
      ['score components.explanation.positiveDetails[0].issueRefs[0]', SCORE_AUDIT_REQUIRED_KEYS.explanationIssueRef, (p) => p.components.explanation.positiveDetails[0].issueRefs[0]],
      ['score components.explanation.positiveDetails[0].issueRefs[0].confirmationReasons[0]', SCORE_AUDIT_REQUIRED_KEYS.confirmationReason, (p) => p.components.explanation.positiveDetails[0].issueRefs[0].confirmationReasons[0]],
      ['score components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence', SCORE_AUDIT_REQUIRED_KEYS.releaseLocalEvidence, (p) => p.components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence],
      ['score components.explanation.positiveDetails[0].issueRefs[0].proof', SCORE_AUDIT_REQUIRED_KEYS.explanationIssueProof, (p) => p.components.explanation.positiveDetails[0].issueRefs[0].proof],
      ['score components.explanation.positiveDetails[0].issueRefs[0].proof.openPrs[0]', SCORE_AUDIT_REQUIRED_KEYS.explanationLinkedRef, (p) => p.components.explanation.positiveDetails[0].issueRefs[0].proof.openPrs[0]],
      ['issue evidence', SCORE_AUDIT_REQUIRED_KEYS.issueEvidence, (p) => p.issueEvidence],
      ['issue evidence.evidenceCounts', SCORE_AUDIT_REQUIRED_KEYS.issueEvidenceCounts, (p) => p.issueEvidence.evidenceCounts],
      ['issue evidence.debtSummary', SCORE_AUDIT_REQUIRED_KEYS.debtSummary, (p) => p.issueEvidence.debtSummary],
      ['issue evidence.debtSummary.verified', SCORE_AUDIT_REQUIRED_KEYS.debtTierSummary, (p) => p.issueEvidence.debtSummary.verified],
      ['gate evidence', SCORE_AUDIT_REQUIRED_KEYS.gateEvidence, (p) => p.gateEvidence],
      ['gate evidence.cve', SCORE_AUDIT_REQUIRED_KEYS.cve, (p) => p.gateEvidence.cve],
      ['gate evidence.releaseChecks', SCORE_AUDIT_REQUIRED_KEYS.releaseChecks, (p) => p.gateEvidence.releaseChecks],
      ['gate evidence.artifactVerification', SCORE_AUDIT_REQUIRED_KEYS.artifactVerification, (p) => p.gateEvidence.artifactVerification],
      ['gate evidence.labelTimeline', SCORE_AUDIT_REQUIRED_KEYS.labelTimeline, (p) => p.gateEvidence.labelTimeline],
      ['gate evidence.fixProvenance', SCORE_AUDIT_REQUIRED_KEYS.fixProvenance, (p) => p.gateEvidence.fixProvenance],
      ['gate evidence.fixProvenance.predecessorBoundary', SCORE_AUDIT_REQUIRED_KEYS.predecessorBoundary, (p) => p.gateEvidence.fixProvenance.predecessorBoundary],
      ['gate evidence.fixProvenance.closureProof', SCORE_AUDIT_REQUIRED_KEYS.closureProof, (p) => p.gateEvidence.fixProvenance.closureProof],
      ['gate evidence.fixProvenance.closureProof.fixCreditDecisionCounts', SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecisionCounts, (p) => p.gateEvidence.fixProvenance.closureProof.fixCreditDecisionCounts],
      ['gate evidence.fixProvenance.closureProof.riskSummary', SCORE_AUDIT_REQUIRED_KEYS.closureProofRiskSummary, (p) => p.gateEvidence.fixProvenance.closureProof.riskSummary],
      ['gate evidence.fixProvenance.releaseFixCredit', SCORE_AUDIT_REQUIRED_KEYS.releaseFixCredit, (p) => p.gateEvidence.fixProvenance.releaseFixCredit],
      ['gate evidence.fixProvenance.releaseFixCredit.decisionCounts', SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecisionCounts, (p) => p.gateEvidence.fixProvenance.releaseFixCredit.decisionCounts],
      ['gate evidence.fixProvenance.releaseFixCredit.decisions[0]', SCORE_AUDIT_REQUIRED_KEYS.fixCreditDecision, (p) => p.gateEvidence.fixProvenance.releaseFixCredit.decisions[0]],
      ['gate evidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[0]', SCORE_AUDIT_REQUIRED_KEYS.trustedPullRequestProof, (p) => p.gateEvidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[0]],
      ['gate evidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[0].target', SCORE_AUDIT_REQUIRED_KEYS.reachabilityProof, (p) => p.gateEvidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[0].target],
      ['gate evidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[1]', SCORE_AUDIT_REQUIRED_KEYS.directCommitProof, (p) => p.gateEvidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[1]],
    ];
    for (const [path, requiredKeys, locate] of cases) {
      assertMissingField(path, requiredKeys, locate);
    }

    assertMissingField(
      'score components.recommendationDecision',
      SCORE_AUDIT_REQUIRED_KEYS.recommendationDecision,
      (p) => p.components.recommendationDecision,
    );
    assertMissingField(
      'score components.explanation.recommendationDecision',
      SCORE_AUDIT_REQUIRED_KEYS.recommendationDecision,
      (p) => p.components.explanation.recommendationDecision,
    );
  });

  it('preserves optional and required-nullable fields', () => {
    const payloads = validPayloads();
    payloads.gateEvidence.releaseChecks = null;
    for (const decision of [
      payloads.gateEvidence.fixProvenance.closureProof.fixCreditDecisions[0],
      payloads.gateEvidence.fixProvenance.releaseFixCredit.decisions[0],
    ]) {
      decision.status = 'withheld';
      decision.reasonCode = 'target_reachability_missing';
      decision.proofIdentities[0].target = null;
      decision.proofIdentities[0].predecessor = null;
    }
    delete payloads.input.releaseShaMatches;
    payloads.gateEvidence.artifactVerification.releaseShaMatches = null;
    assert.equal(Object.hasOwn(payloads.input, 'releaseShaMatches'), false);
    assert.deepEqual(verifyScoreAuditPayloadContracts(payloads), []);
  });

  it('rejects the legacy direct-commit placeholder without replayable proof evidence', () => {
    const payloads = validPayloads();
    payloads.gateEvidence.fixProvenance.releaseFixCredit.decisions[0].proofIdentities[1] = {
      kind: 'direct_commit',
      commitOid: directCommitOid,
      targetTag: 'v-test',
      predecessorTag: 'v-previous',
    };

    const failures = verifyScoreAuditPayloadContracts(payloads);
    assert.ok(failures.some((failure) =>
      failure.includes('proofIdentities[1] is missing required field schemaVersion')));
  });

  it('rejects missing, ambiguous, conflicting, and score-input-mismatched release checks', () => {
    const missing = validPayloads();
    missing.gateEvidence.releaseChecks = null;
    Object.assign(missing.input, {
      releaseCheckState: 'SUCCESS',
      releaseCheckTotal: 1,
      releaseCheckSuccess: 1,
    });
    assert.ok(
      verifyScoreAuditPayloadContracts(missing).some((failure) =>
        failure.includes('release-check fields must be empty')),
    );

    const aggregateConflict = validPayloads();
    aggregateConflict.gateEvidence.releaseChecks = {
      schemaVersion: 2,
      state: 'SUCCESS',
      total: 1,
      success: 0,
      failure: 1,
      pending: 0,
      skipped: 0,
      contextCount: 1,
      shownContextCount: 1,
      contextsTruncated: false,
      contexts: [{ name: 'build', conclusion: 'FAILURE' }],
    };
    assert.ok(
      verifyScoreAuditPayloadContracts(aggregateConflict).some((failure) =>
        failure.includes('failure counts require a failure aggregate state')),
    );

    const countGap = validPayloads();
    countGap.gateEvidence.releaseChecks = {
      schemaVersion: 2,
      state: 'SUCCESS',
      total: 2,
      success: 1,
      failure: 0,
      pending: 0,
      skipped: 0,
      contextCount: 2,
      shownContextCount: 1,
      contextsTruncated: true,
      contexts: [{ name: 'build', conclusion: 'SUCCESS' }],
    };
    assert.ok(
      verifyScoreAuditPayloadContracts(countGap).some((failure) =>
        failure.includes('category counts must sum to total')),
    );

    const ambiguousContext = validPayloads();
    ambiguousContext.gateEvidence.releaseChecks = {
      schemaVersion: 2,
      state: 'SUCCESS',
      total: 1,
      success: 1,
      failure: 0,
      pending: 0,
      skipped: 0,
      contextCount: 1,
      shownContextCount: 1,
      contextsTruncated: false,
      contexts: [{
        type: 'CheckRun',
        name: 'build',
        status: 'COMPLETED',
        conclusion: null,
      }],
    };
    assert.ok(
      verifyScoreAuditPayloadContracts(ambiguousContext).some((failure) =>
        failure.includes('missing, unknown, or conflicting check state')),
    );

    const duplicateConflict = validPayloads();
    duplicateConflict.gateEvidence.releaseChecks = {
      schemaVersion: 2,
      state: 'FAILURE',
      total: 2,
      success: 1,
      failure: 1,
      pending: 0,
      skipped: 0,
      contextCount: 2,
      shownContextCount: 2,
      contextsTruncated: false,
      contexts: [
        {
          type: 'CheckRun',
          name: 'build',
          workflowName: 'CI',
          appSlug: 'github-actions',
          status: 'COMPLETED',
          conclusion: 'SUCCESS',
          url: 'https://example.test/checks/build',
        },
        {
          type: 'CheckRun',
          name: 'build',
          workflowName: 'CI',
          appSlug: 'github-actions',
          status: 'COMPLETED',
          conclusion: 'FAILURE',
          url: 'https://example.test/checks/build',
        },
      ],
    };
    assert.ok(
      verifyScoreAuditPayloadContracts(duplicateConflict).some((failure) =>
        failure.includes('duplicates or conflicts with another check context')),
    );

    const inputMismatch = validPayloads();
    inputMismatch.gateEvidence.releaseChecks = {
      schemaVersion: 2,
      state: 'FAILURE',
      total: 1,
      success: 0,
      failure: 1,
      pending: 0,
      skipped: 0,
      contextCount: 1,
      shownContextCount: 1,
      contextsTruncated: false,
      contexts: [{ name: 'build', conclusion: 'FAILURE' }],
    };
    assert.ok(
      verifyScoreAuditPayloadContracts(inputMismatch).some((failure) =>
        failure.includes('failure must match score input releaseCheckFailure')),
    );
  });

  it('rejects a null ScoreLedgerV2 for every status', () => {
    const payloads = validPayloads();
    payloads.components.explanation.scoreLedger = null;
    const failures = verifyScoreAuditPayloadContracts(payloads);
    assert.ok(failures.some((failure) => /scoreLedger must be an object/.test(failure)));
    assert.ok(failures.some((failure) => /scoreLedger must be a non-null object/.test(failure)));
  });

  it('accepts strict title, body, and comment locality plus both confirmation reason variants', () => {
    for (const releaseLocalEvidence of [
      {
        kind: 'exact-version',
        source: 'title',
        version: 'v-test',
        snippet: 'Failure in v-test.',
      },
      {
        kind: 'exact-version',
        source: 'body',
        version: 'v-test',
        snippet: 'Observed on v-test after upgrade.',
      },
      {
        kind: 'exact-version',
        source: 'comment',
        version: 'v-test',
        snippet: 'Same issue on v-test.',
        commentId: 7002,
        commentUrl: 'https://github.com/openclaw/openclaw/issues/101#issuecomment-7002',
        commentNodeId: 'IC_7002',
        author: 'second-reporter',
        actorNodeId: 'U_second-reporter',
        actorType: 'User',
        association: 'NONE',
        occurredAt: '2026-06-01T01:00:00Z',
        updatedAt: '2026-06-01T01:00:00Z',
        commentBodyDigest: 'b'.repeat(64),
        authorityReference: scoreCommentAuthorityReference({
          issueNumber: 101,
          issueNodeId: 'I_101',
          issueAuthorNodeId: 'U_original-reporter',
          issueAuthorType: 'User',
          commentNodeId: 'IC_7002',
          commentId: 7002,
          commentUrl:
            'https://github.com/openclaw/openclaw/issues/101#issuecomment-7002',
          actorNodeId: 'U_second-reporter',
          commentCreatedAt: '2026-06-01T01:00:00Z',
          commentUpdatedAt: '2026-06-01T01:00:00Z',
          commentBodyDigest: 'b'.repeat(64),
          claimSnippet: 'Same issue on v-test.',
        }),
      },
    ] as any[]) {
      const payloads = validPayloads();
      payloads.components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence =
        releaseLocalEvidence;
      if (releaseLocalEvidence.authorityReference) {
        payloads.components.explanation.authorityReferences =
          sortedAuthorityReferences([
            ...payloads.components.explanation.authorityReferences,
            releaseLocalEvidence.authorityReference,
          ]);
      }
      payloads.components.explanation.scoreLedger = structuredClone(
        bindScoreExplanationAudit(
          payloads.components.explanation.scoreLedger,
          payloads.components.explanation,
        ),
      );
      assert.deepEqual(verifyScoreAuditPayloadContracts(payloads), []);
    }
  });

  it('rejects malformed and unexpected confirmation reason fields', () => {
    const payloads = validPayloads();
    const issueRef = payloads.components.explanation.positiveDetails[0].issueRefs[0];
    Object.assign(issueRef.confirmationReasons[0], {
      occurredAt: 'not-a-timestamp',
      association: 42,
      commentId: '7001',
      label: 'P0',
      unexpected: true,
    });
    delete issueRef.confirmationReasons[0].commentUrl;
    Object.assign(issueRef.confirmationReasons[1], {
      code: 'human_applied_p1',
      commentUrl: 'https://example.test/not-allowed',
    });
    delete issueRef.confirmationReasons[1].eventId;
    const failures = verifyScoreAuditPayloadContracts(payloads);

    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\] has unexpected key unexpected/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\]\.occurredAt must be a valid timestamp/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\]\.association must be a non-empty string or null/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\]\.commentId must be a positive integer/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\] is missing required field commentUrl/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[0\]\.label is not allowed for comment evidence/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[1\] is missing required field eventId/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[1\]\.code must match label P0/.test(failure)));
    assert.ok(failures.some((failure) =>
      /confirmationReasons\[1\]\.commentUrl is not allowed for label_event evidence/.test(failure)));
  });

  it('rejects malformed and unexpected release-local evidence fields', () => {
    const payloads = validPayloads();
    const evidence =
      payloads.components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence;
    Object.assign(evidence, {
      kind: 'guessed-version',
      version: '',
      snippet: '',
      commentId: 0,
      commentUrl: 42,
      author: '',
      association: 42,
      occurredAt: 'not-a-timestamp',
      updatedAt: 'not-a-timestamp',
      commentBodyDigest: 'not-a-digest',
      unexpected: true,
    });
    const failures = verifyScoreAuditPayloadContracts(payloads);

    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence has unexpected key unexpected/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.kind must be exact-version/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.version must be a non-empty string/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.snippet must be a non-empty string/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.commentId must be a positive integer/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.commentUrl must be a non-empty string/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.author must be a non-empty string/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.association must be a non-empty string or null/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.occurredAt must be a valid timestamp/.test(failure)));
    assert.ok(failures.some((failure) =>
      /releaseLocalEvidence\.commentBodyDigest must be SHA-256/.test(failure)));
  });

  it('requires source-specific nested fields and rejects cross-source locality fields', () => {
    const commentPayloads = validPayloads();
    const commentEvidence =
      commentPayloads.components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence;
    delete commentEvidence.commentId;
    delete commentEvidence.author;
    delete commentEvidence.actorNodeId;
    delete commentEvidence.occurredAt;
    const commentFailures = verifyScoreAuditPayloadContracts(commentPayloads);
    assert.ok(commentFailures.some((failure) =>
      /releaseLocalEvidence is missing required field commentId/.test(failure)));
    assert.ok(commentFailures.some((failure) =>
      /releaseLocalEvidence is missing required field author/.test(failure)));
    assert.ok(commentFailures.some((failure) =>
      /releaseLocalEvidence is missing required field actorNodeId/.test(failure)));
    assert.ok(commentFailures.some((failure) =>
      /releaseLocalEvidence is missing required field occurredAt/.test(failure)));

    const titlePayloads = validPayloads();
    const titleEvidence =
      titlePayloads.components.explanation.positiveDetails[0].issueRefs[0].releaseLocalEvidence;
    titleEvidence.source = 'title';
    const titleFailures = verifyScoreAuditPayloadContracts(titlePayloads);
    assert.ok(titleFailures.some((failure) =>
      /releaseLocalEvidence\.commentId is not allowed for title evidence/.test(failure)));
    assert.ok(titleFailures.some((failure) =>
      /releaseLocalEvidence\.commentUrl is not allowed for title evidence/.test(failure)));
    assert.ok(titleFailures.some((failure) =>
      /releaseLocalEvidence\.author is not allowed for title evidence/.test(failure)));
    assert.ok(titleFailures.some((failure) =>
      /releaseLocalEvidence\.actorNodeId is not allowed for title evidence/.test(failure)));
    assert.ok(titleFailures.some((failure) =>
      /releaseLocalEvidence\.commentBodyDigest is not allowed for title evidence/.test(failure)));
  });

  it('rejects unexpected keys, stale schemas, and recommendation drift', () => {
    const payloads = validPayloads();
    payloads.input.schemaVersion = 0;
    payloads.input.unexpected = true;
    payloads.components.extra = true;
    payloads.components.explanation.recommendationDecision.summary = 'drifted summary';
    payloads.components.explanation.recommendationDecision.selectedScore = 7.4;
    const failures = verifyScoreAuditPayloadContracts(payloads);

    assert.ok(failures.some((failure) => /score input schemaVersion/.test(failure)));
    assert.ok(failures.some((failure) => /score input payload has unexpected top-level key unexpected/.test(failure)));
    assert.ok(failures.some((failure) => /score components payload has unexpected top-level key extra/.test(failure)));
    assert.ok(failures.some((failure) =>
      /components and explanation recommendationDecision field summary must match/.test(failure)));
    assert.ok(failures.some((failure) =>
      /components and explanation recommendationDecision field selectedScore must match/.test(failure)));
  });

  it('requires a non-negative finite affirmative closure ceiling weight', () => {
    const payloads = validPayloads();
    payloads.input.affirmativeClosureRiskCeilingWeight = -1;
    const failures = verifyScoreAuditPayloadContracts(payloads);
    assert.ok(failures.includes(
      'v-test: score input affirmativeClosureRiskCeilingWeight must be a non-negative finite number',
    ));
  });

  it('reports every non-finite scoring weight without throwing during semantic replay', () => {
    for (const field of [
      'feltOpenedWeight',
      'feltClosedWeight',
      'verifiedDebtWeight',
      'carryoverDebtWeight',
      'staleDebtWeight',
      'unresolvedClosureRiskWeight',
      'cveLoad',
    ]) {
      const payloads = validPayloads();
      payloads.input[field] = Number.NaN;
      const failures = verifyScoreAuditPayloadContracts(payloads);
      assert.ok(failures.includes(`v-test: score input ${field} must be a finite number`));
      assert.ok(failures.some((failure) =>
        failure.includes(`InstallInput.${field} must be a finite number`)));
    }
  });

  it('retains semantic recommendation-decision validation', () => {
    const payloads = validPayloads();
    Object.assign(payloads.components.recommendationDecision, {
      selectedTag: 'v-other',
      selectedScore: 6.5,
      highestScoringTag: 'v-high',
      highestScore: 8,
      qualifies: false,
      selected: true,
      recencyRank: 0,
      scoreRank: null,
      scoreDeltaToHighest: 0,
      decisionCode: 'install_gate_active',
      summary: '',
      unexpected: true,
    });
    payloads.components.explanation.recommendationDecision = {
      ...payloads.components.recommendationDecision,
    };
    const failures = verifyScoreAuditPayloadContracts(payloads);

    assert.ok(failures.some((failure) => /unexpected key unexpected/.test(failure)));
    assert.ok(failures.some((failure) => /recencyRank must be a positive integer/.test(failure)));
    assert.ok(failures.some((failure) => /selected release must qualify/.test(failure)));
    assert.ok(failures.some((failure) => /selectedTag must match releaseTag/.test(failure)));
    assert.ok(failures.some((failure) => /scoreDeltaToHighest .* must equal 0.5/.test(failure)));
    assert.ok(failures.some((failure) => /qualifies .* must match status, score, and threshold/.test(failure)));
    assert.ok(failures.some((failure) =>
      /decisionCode .* must equal newest_within_confidence_tolerance/.test(failure)));
    assert.ok(failures.some((failure) => /summary must be present/.test(failure)));
  });
});
