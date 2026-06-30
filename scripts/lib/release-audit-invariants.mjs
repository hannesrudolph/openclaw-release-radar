import {
  applyClosureRiskSentimentHint,
  applyLabelOverrides,
  applyTitleFunctionalityHint,
  applyTitleIssueShapeHint,
} from '../../src/lib/labelOverrides.ts';
import { REC_THRESHOLD } from '../../src/lib/score.ts';
import { publicIssueSummariesForRelease } from '../../src/lib/publicIssueSummary.ts';
import {
  RELEASE_ISSUE_EVIDENCE_TIERS,
  RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION,
  RELEASE_ISSUE_EVIDENCE_TIER_INFO,
} from '../../src/lib/releaseIssueEvidence.ts';
import {
  CLOSURE_PROOF_STATUSES,
  CLOSURE_RISK_DISPOSITIONS,
  CLOSURE_RISK_DISPOSITION_BY_STATUS,
  CLOSURE_RISK_DISPOSITION_WEIGHT,
} from '../../src/lib/closureProofTaxonomy.ts';
import {
  ARTIFACT_VERIFICATION_SCHEMA_VERSION,
  GATE_EVIDENCE_SCHEMA_VERSION,
  ISSUE_EVIDENCE_SCHEMA_VERSION,
  LABEL_TIMELINE_SCHEMA_VERSION,
  RELEASE_CHECKS_SCHEMA_VERSION,
  SCORE_COMPONENTS_SCHEMA_VERSION,
  SCORE_EXPLANATION_DETAIL_LABELS,
  SCORE_EXPLANATION_LIMIT_CODES,
  SCORE_EXPLANATION_POSITIVE_CODES,
  SCORE_INPUT_SCHEMA_VERSION,
} from '../../src/lib/releaseScoring.ts';
import { verifyScoreAuditPayloadContracts } from './score-audit-contracts.mjs';

export const knownProofStatuses = new Set(CLOSURE_PROOF_STATUSES);

const knownCommitProofStatuses = new Set(['reachable', 'not_reachable', 'unknown']);
const knownReachabilityEvidenceReasons = new Set([
  'merge_commit_in_release_history',
  'fix_commit_in_release_history',
  'not_reachable_from_release_tag',
  'release_commit_unavailable',
  'release_commit_fetch_failed',
  'merge_commit_oid_unavailable',
  'commit_fetch_failed',
  'commit_unavailable',
  'merge_base_error',
]);
const knownRiskDispositions = new Set(CLOSURE_RISK_DISPOSITIONS);
const riskDispositionByProofStatus = new Map(Object.entries(CLOSURE_RISK_DISPOSITION_BY_STATUS));
const riskDispositionWeights = new Map(Object.entries(CLOSURE_RISK_DISPOSITION_WEIGHT));
const severityRiskWeights = new Map([
  ['critical', 4],
  ['high', 2.5],
  ['medium', 0.8],
  ['low', 0],
]);
const functionalityRiskWeights = new Map([
  ['core', 1.25],
  ['integration', 1],
  ['provider', 0.8],
  ['docs', 0],
]);
const scopeRiskWeights = new Map([
  ['broad', 1.5],
  ['moderate', 1],
  ['niche', 0.4],
]);
const affectedUserRiskWeights = new Map([
  ['many', 1.3],
  ['some', 0.85],
  ['few', 0.35],
  ['unknown', 0.65],
]);
const fullCommitOidRe = /^[0-9a-f]{40}$/;
const knownCommitProofSources = new Set(['ClosureComment.fixProof', 'ClosedEvent.closer', 'ReferencedEvent.commit']);
const requiredProofDependencySources = new Set([
  'issue_rows',
  'issue_fetches',
  'classification_rows',
  'label_events',
  'label_snapshots',
  'closure_events',
  'reopen_events',
  'issue_pr_links',
  'issue_commit_references',
  'release_pr_reachability',
]);
const bugShapedTitleRe = /\b(bug|fail(?:s|ed|ure)?|error|crash|stuck|regression|broken|lost|timeout|leak|silently|dropped|corrupt|deadlock|stall)\b/i;
const scoreInputSchemaVersion = SCORE_INPUT_SCHEMA_VERSION;
const scoreComponentsSchemaVersion = SCORE_COMPONENTS_SCHEMA_VERSION;
const scoreAuditSummarySchemaVersion = 1;
const localAuditSchemaVersion = 1;
const comparisonPayloadSchemaVersion = 1;
const comparisonUpstreamSchemaVersion = 1;
const comparisonDeltaSchemaVersion = 1;
const statusPayloadSchemaVersion = 1;
const configPayloadSchemaVersion = 1;
const releaseRowSchemaVersion = 2;
const releaseHistoryRowSchemaVersion = 2;
const publicReleaseSchemaVersion = 4;
const gateEvidenceSchemaVersion = GATE_EVIDENCE_SCHEMA_VERSION;
const closureProofSchemaVersion = 1;
const closureProofAuditSchemaVersion = 1;
const releaseFixCreditSchemaVersion = 1;
const issueEvidenceSchemaVersion = ISSUE_EVIDENCE_SCHEMA_VERSION;
const issueEvidenceAuditSchemaVersion = RELEASE_ISSUE_EVIDENCE_SCHEMA_VERSION;
const labelTimelineSchemaVersion = LABEL_TIMELINE_SCHEMA_VERSION;
const releaseChecksSchemaVersion = RELEASE_CHECKS_SCHEMA_VERSION;
const artifactVerificationSchemaVersion = ARTIFACT_VERIFICATION_SCHEMA_VERSION;
const scoreExplanationSchemaVersion = 1;
const publicPayloadSchemaVersion = 4;
const knownIssueEvidenceTiers = new Set(RELEASE_ISSUE_EVIDENCE_TIERS);
const knownExplanationLimitCodes = new Set(SCORE_EXPLANATION_LIMIT_CODES);
const knownExplanationPositiveCodes = new Set(SCORE_EXPLANATION_POSITIVE_CODES);
const expectedExplanationDetailLabels = new Map(Object.entries(SCORE_EXPLANATION_DETAIL_LABELS));
const publicTopLevelKeys = new Set(['repo', 'releases', 'schemaVersion', 'updatedAt']);
const reviewPayloadKeys = new Set(['tag', 'local']);
const reviewLocalKeys = new Set([
  'schemaVersion',
  'score',
  'band',
  'status',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'scoredAt',
  'dataFreshness',
  'sourceProvenance',
  'modelVersion',
  'promptVersion',
  'input',
  'components',
  'issueEvidence',
  'gateEvidence',
]);
const comparisonPayloadKeys = new Set(['schemaVersion', 'snapshot', 'releases']);
const comparisonSnapshotKeys = new Set(['id', 'sourceUrl', 'capturedAt', 'pageTitle']);
const comparisonReleaseKeys = new Set(['tag', 'local', 'upstream', 'delta']);
const comparisonLocalKeys = new Set([
  'schemaVersion',
  'score',
  'band',
  'status',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'scoredAt',
  'dataFreshness',
  'modelVersion',
  'components',
  'input',
  'gateEvidence',
]);
const comparisonUpstreamKeys = new Set([
  'schemaVersion',
  'snapshotId',
  'tag',
  'score',
  'band',
  'status',
  'recommended',
  'reason',
  'negativeIssues',
  'positiveIssues',
  'totalAttributedIssues',
  'visibleIssues',
  'rawCardText',
]);
const comparisonDeltaKeys = new Set(['schemaVersion', 'score', 'negativeIssues']);
const releaseRowKeys = new Set([
  'advisories',
  'auditLinks',
  'band',
  'brokenSurfaces',
  'closedSeriousFixed',
  'dataFreshness',
  'explanation',
  'finalScore',
  'htmlUrl',
  'maintainerSignals',
  'name',
  'negativeIssues',
  'openedSeriousDuringReign',
  'positiveIssues',
  'publishedAt',
  'reason',
  'recommended',
  'schemaVersion',
  'scoreAudit',
  'scoredAt',
  'status',
  'tag',
]);
const releaseHistoryRowKeys = new Set([
  'schemaVersion',
  'tag',
  'publishedAt',
  'finalScore',
  'status',
  'band',
  'recommended',
  'scoredAt',
  'scoreAudit',
  'dataFreshness',
  'auditLinks',
]);
const publicReleaseKeys = new Set([
  'auditLinks',
  'band',
  'dataFreshness',
  'explanation',
  'issues',
  'negativeIssues',
  'positiveIssues',
  'profileEvidence',
  'publishedAt',
  'reason',
  'recommended',
  'score',
  'scoreAudit',
  'scoredAt',
  'schemaVersion',
  'status',
  'tag',
  'totalAttributedIssues',
  'url',
  'watchIssues',
]);
const publicProfileEvidenceKeys = new Set([
  'schemaVersion',
  'sourceMode',
  'issueEvidenceSchemaVersion',
  'issueCount',
  'weightedIssueCount',
  'surfaceIssueCount',
  'surfaceWeight',
  'surfaces',
]);
const publicProfileEvidenceSurfaceKeys = new Set(['label', 'icon', 'count', 'weight', 'tiers', 'weightByTier']);
const publicIssueKeys = new Set([
  'affectedUsers',
  'closedAt',
  'hasWorkaround',
  'number',
  'scope',
  'sentiment',
  'severity',
  'state',
  'surface',
  'title',
  'url',
]);
const issueEvidenceAuditKeys = new Set([
  'schemaVersion',
  'tag',
  'sourceMode',
  'scoredAt',
  'dataFreshness',
  'labelCutoffAt',
  'filters',
  'countsByTier',
  'summaryByTier',
  'unfilteredCountsByTier',
  'unfilteredSummaryByTier',
  'filteredCountsByTier',
  'filteredSummaryByTier',
  'filteredSummary',
  'tierInfo',
  'totals',
  'total',
  'totalRows',
  'distinctIssueCount',
  'limit',
  'cursor',
  'nextCursor',
  'rows',
]);
const issueEvidenceAuditFilterKeys = new Set([
  'tier',
  'tiers',
  'impact',
  'impacts',
  'state',
  'states',
  'sentiment',
  'sentiments',
  'severity',
  'severities',
  'functionality',
  'functionalities',
  'scope',
  'scopes',
  'affectedUsers',
  'affectedUsersList',
  'fieldConfirmed',
  'minWeight',
  'maxWeight',
  'sort',
  'direction',
  'summaryOnly',
]);
const issueEvidenceAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredDistinctIssues', 'filteredDistinctIssues']);
const issueEvidenceAuditRowKeys = new Set([
  'tier',
  'tierLabel',
  'tierDescription',
  'issue',
  'weight',
  'duplicateCluster',
  'humanReporterCount',
  'commentCount',
  'fieldConfirmed',
  'humanCommenterCount',
  'maintainerCommenterCount',
  'contributorCommenterCount',
  'reactionTotal',
  'positiveReactionCount',
  'commenterScanTruncated',
  'installImpactClass',
  'installImpactMultiplier',
  'clusterReleaseLocal',
  'debtClassification',
  'debtClassificationDiff',
]);
const issueEvidenceIssueKeys = new Set([
  'number',
  'title',
  'url',
  'state',
  'createdAt',
  'updatedAt',
  'closedAt',
  'author',
  'authorAssociation',
  'isBot',
  'comments',
  'uniqueHumanCommenters',
  'maintainerCommenters',
  'contributorCommenters',
  'commenterScanTruncated',
  'reactionTotal',
  'positiveReactions',
  'labels',
  'currentLabels',
  'labelSource',
  'labelTimelineEventCount',
  'labelSnapshotCount',
  'labelCutoffAt',
  'rawClassification',
  'classification',
  'classificationDiff',
  'affectsVersion',
  'duplicateCluster',
  'missing',
]);
const closureProofAuditKeys = new Set([
  'schemaVersion',
  'tag',
  'sourceMode',
  'scoredAt',
  'dataFreshness',
  'filters',
  'totals',
  'total',
  'totalRows',
  'distinctIssueCount',
  'unfilteredCountsByStatus',
  'filteredCountsByStatus',
  'unfilteredCountsByRiskDisposition',
  'filteredCountsByRiskDisposition',
  'limit',
  'cursor',
  'nextCursor',
  'rows',
]);
const closureProofAuditFilterKeys = new Set(['status', 'riskDisposition']);
const closureProofAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredDistinctIssues', 'filteredDistinctIssues']);
const closureProofAuditRowKeys = new Set([
  'issueNumber',
  'title',
  'url',
  'closedAt',
  'status',
  'summary',
  'riskDisposition',
  'riskDispositionLabel',
  'riskWeight',
  'riskWeightLabel',
  'checkedAt',
  'labels',
  'classification',
  'classificationDiff',
  'evidence',
]);
const closureProofAuditEvidenceKeys = new Set([
  'stateReasons',
  'closureActors',
  'closureContextCommentCount',
  'hasClosingLink',
  'hasMergedClosingPr',
  'hasReachableClosingPr',
  'hasNotReachableClosingPr',
  'hasReachableFixCommit',
  'hasNotReachableFixCommit',
  'canonicalIssues',
  'canonicalIssueDetails',
  'canonicalResolution',
  'closingPrs',
  'linkedPrs',
  'relatedPrContext',
  'reachableTrustedFixProofPrs',
  'matchingComments',
  'nonActionableRationaleComments',
  'laterFixProof',
  'unscoredFixProof',
  'fixCommitProof',
  'canonicalFixCommitProof',
  'reachableFixCommits',
  'notReachableFixCommits',
]);
const reachabilityAuditKeys = new Set([
  'schemaVersion',
  'tag',
  'sourceMode',
  'scoredAt',
  'dataFreshness',
  'filters',
  'totals',
  'total',
  'totalRows',
  'distinctPullRequestCount',
  'countsByStatus',
  'filteredCountsByStatus',
  'unfilteredCountsByStatus',
  'limit',
  'cursor',
  'nextCursor',
  'rows',
]);
const reachabilityAuditFilterKeys = new Set(['status', 'pr']);
const reachabilityAuditTotalsKeys = new Set(['unfilteredRows', 'filteredRows', 'unfilteredPullRequests', 'filteredPullRequests']);
const auditLinkKeys = new Set(['review', 'issues', 'closureProofs', 'reachability']);
const reachabilityAuditRowKeys = new Set([
  'repositoryNameWithOwner',
  'number',
  'title',
  'url',
  'state',
  'merged',
  'mergedAt',
  'status',
  'method',
  'checkedAt',
  'tagCommitOid',
  'mergeCommitOid',
  'prMergeCommitOid',
  'baseRefName',
  'evidence',
]);
const publicSentimentRank = new Map([['negative', 0], ['positive', 1], ['neutral', 2]]);
const publicSeverityRank = new Map([['critical', 0], ['high', 1], ['medium', 2], ['low', 3]]);
const publicScopeRank = new Map([['broad', 0], ['moderate', 1], ['niche', 2]]);
const publicAffectedUsersRank = new Map([['many', 0], ['some', 1], ['few', 2], ['unknown', 3]]);
const componentLedgerRows = [
  ['base', 'Base'],
  ['verifiedDebt', 'Field blocker debt'],
  ['carryoverDebt', 'Open unconfirmed issue risk'],
  ['staleDebt', 'Weak or stale evidence'],
  ['closureRisk', 'Closed-issue proof gap'],
  ['coverage', 'Classification coverage'],
  ['survival', 'Stable survival'],
  ['shakeout', 'Beta shakeout'],
  ['regression', 'Opened vs fixed balance'],
  ['breaking', 'Breaking changes'],
  ['releaseVerification', 'Release checks'],
  ['artifactVerification', 'Artifact verification'],
];
const componentLedgerLabels = new Map(componentLedgerRows);
const gateLedgerLabels = new Map([
  ['cveGate', 'CVE install gate'],
  ['settleGate', 'Settle-time gate'],
]);
const optionalLedgerLabels = new Map([
  ['precisionAdjustment', 'Unrounded model adjustment'],
]);
const ledgerCapLabels = new Map([
  ['closureRiskCeiling', 'Closed issue proof ceiling'],
  ['hotfixCeiling', 'Hotfix successor ceiling'],
]);
const ledgerKeys = new Set(['schemaVersion', 'finalScore', 'status', 'band', 'subtotalBeforeCaps', 'scoreAfterCaps', 'rows', 'caps']);
const ledgerRowKeys = new Set(['key', 'label', 'points', 'kind', 'metric', 'note']);
const ledgerCapKeys = new Set(['key', 'label', 'ceiling', 'applied', 'before', 'after', 'reason']);
const explanationDetailKeys = new Set(['code', 'label', 'text', 'metrics', 'buckets', 'riskBuckets', 'issueRefs']);
const explanationIssueRefKeys = new Set(['number', 'title', 'url', 'state', 'status', 'tier', 'weight', 'fieldConfirmed', 'releaseLocal', 'scoringReason', 'installImpactClass', 'installImpactMultiplier', 'proof']);
const explanationIssueProofKeys = new Set(['status', 'statusLabel', 'riskDisposition', 'riskDispositionLabel', 'summary', 'riskWeight', 'canonicalIssue', 'canonicalPath', 'openPrs', 'reachablePrs', 'notReachablePrs']);
const explanationLinkedRefKeys = new Set(['number', 'title', 'url', 'state', 'status']);
const forbiddenPublicKeys = new Set([
  'comparison',
  'delta',
  'local',
  'pageText',
  'rawCardText',
  'snapshot',
  'sourceUrl',
  'upstream',
]);
const forbiddenReviewComparisonKeys = new Set([
  'comparison',
  'delta',
  'pageText',
  'rawCardText',
  'snapshot',
  'sourceUrl',
  'upstream',
]);

export async function verifyReleaseAudit({ reader, apiBase = null, fetchJson = defaultFetchJson, limit = 10, scoredOnly = false }) {
  const releases = reader.listReleases(limit, { scoredOnly });
  const failures = [];
  const rows = [];
  const latestScoredStableRelease = releases.find((release) =>
    release.final_score != null || release.score != null || release.scored_at != null || release.scoredAt != null);
  verifyRecommendedReleaseInvariant({ failures, releases });

  for (const release of releases) {
    const tag = release.tag;
    const closed = reader.closedDuringReign(tag);
    const rawClosed = typeof reader.rawClosedDuringReign === 'function'
      ? reader.rawClosedDuringReign(tag)
      : closed;
    const verified = reader.verifiedFixedForRelease(tag);
    const unverified = reader.unverifiedClosedForRelease(tag);
    const proofRows = reader.proofRowsFor(tag);
    const sourceFreshnessRows = typeof reader.sourceFreshnessFor === 'function'
      ? reader.sourceFreshnessFor(tag)
      : [];
    const fixedProof = proofRows.filter((row) => row.status === 'fixed_in_release');
    const notCountedProof = proofRows.filter((row) => row.status !== 'fixed_in_release');
    const releaseIsScored = release.final_score != null || release.score != null ||
      release.scored_at != null || release.scoredAt != null;
    const enforceRawClosedCoverage = releaseIsScored || proofRows.length > 0;

    rows.push({
      tag,
      closed: closed.length,
      verified: verified.length,
      unverified: unverified.length,
      proof: proofRows.length,
      counted: fixedProof.length,
      notCounted: notCountedProof.length,
    });

    if (enforceRawClosedCoverage) {
      expect(failures, tag, rawClosed.length === closed.length,
        `raw closed release-window issues (${rawClosed.length}) must equal classified closed issues (${closed.length})`);
    }
    expect(failures, tag, closed.length === verified.length + unverified.length,
      `closedDuringReign (${closed.length}) must equal verified + unverified (${verified.length + unverified.length})`);
    expect(failures, tag, proofRows.length === (enforceRawClosedCoverage ? rawClosed.length : closed.length),
      enforceRawClosedCoverage
        ? `closure proofs (${proofRows.length}) must cover raw closed release-window issues (${rawClosed.length})`
        : `closure proofs (${proofRows.length}) must cover classified closed release-window issues (${closed.length})`);
    expect(failures, tag, fixedProof.length + notCountedProof.length === proofRows.length,
      'counted + not-counted proof rows must equal all proof rows');

    const verifiedNumbers = new Set(verified.map((row) => row.number));
    const rawClosedNumbers = new Set(rawClosed.map((row) => row.number));
    const proofByNumber = new Map(proofRows.map((row) => [row.issue_number, row]));
    for (const row of proofRows) {
      expect(failures, tag, rawClosedNumbers.has(row.issue_number),
        `proof issue #${row.issue_number} must belong to the raw closed release window`);
    }
    for (const row of fixedProof) {
      expect(failures, tag, verifiedNumbers.has(row.issue_number),
        `fixed_in_release issue #${row.issue_number} must be present in verifiedFixedForRelease`);
    }

    for (const row of verified) {
      const proof = proofByNumber.get(row.number);
      if (!proof) continue;
      const evidence = parseJson(proof.evidence_json, {});
      if (proof.status !== 'fixed_in_release') {
        expect(failures, tag, row.sentiment !== 'negative',
          `verified issue #${row.number} has proof status ${proof.status}; only non-negative verified closures may avoid fixed_in_release`);
      }
      expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
        `verified issue #${row.number} must have final COMPLETED closure evidence`);
    }

    for (const row of proofRows) {
      expect(failures, tag, knownProofStatuses.has(row.status), `unknown proof status ${row.status} for issue #${row.issue_number}`);
      const evidence = parseJson(row.evidence_json, {});
      verifyProofEvidenceShape({ failures, tag, row, evidence });
      const prEvidence = typeof reader.prReachabilityEvidenceForIssue === 'function'
        ? reader.prReachabilityEvidenceForIssue(tag, row.issue_number)
        : [];
      verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence });
      if (row.status === 'fixed_in_release') {
        expect(failures, tag, evidence.hasReachableClosingPr === true || evidence.hasReachableFixCommit === true,
          `fixed_in_release issue #${row.issue_number} must have reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_after_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_after_release issue #${row.issue_number} must have COMPLETED state reason`);
      }
      if (row.status === 'fixed_in_later_release') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_in_later_release issue #${row.issue_number} must have not-reachable PR or commit evidence for this tag`);
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('COMPLETED'),
          `fixed_in_later_release issue #${row.issue_number} must have COMPLETED state reason`);
        expect(failures, tag, evidence.laterFixProof?.releaseTag && ['pr', 'commit'].includes(evidence.laterFixProof?.proofType),
          `fixed_in_later_release issue #${row.issue_number} must include laterFixProof metadata`);
      }
      if (row.status === 'fixed_not_in_scored_releases') {
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `fixed_not_in_scored_releases issue #${row.issue_number} must have not-reachable PR or commit evidence`);
        expect(failures, tag, !evidence.laterFixProof,
          `fixed_not_in_scored_releases issue #${row.issue_number} must not include laterFixProof metadata`);
      }
      if (row.status === 'fixed_after_latest_release') {
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'after_latest_release',
          `fixed_after_latest_release issue #${row.issue_number} must include after-latest unscoredFixProof metadata`);
        verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease });
      }
      if (row.status === 'fixed_skipped_by_later_releases') {
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'skipped_by_later_releases',
          `fixed_skipped_by_later_releases issue #${row.issue_number} must include skipped-by-later unscoredFixProof metadata`);
      }
      if (row.status === 'duplicate_to_fixed_after_release') {
        expect(failures, tag, canonicalFixedAfterRelease(evidence),
          `duplicate_to_fixed_after_release issue #${row.issue_number} must resolve to fixed-after canonical proof`);
      }
      if (row.status === 'duplicate_with_release_fix_proof') {
        expect(failures, tag, trustedReachableFixProofPrs(evidence).length > 0,
          `duplicate_with_release_fix_proof issue #${row.issue_number} must include trusted reachable closure-comment fix proof PR evidence`);
      }
      if (row.status === 'duplicate_to_fixed_in_release') {
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_in_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'reachable'),
        `duplicate_to_fixed_in_release issue #${row.issue_number} must resolve to fixed-in-release canonical proof`);
      }
      if (row.status === 'duplicate_to_open_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
          `duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
      }
      if (row.status === 'superseded_to_open_pr') {
        expect(failures, tag, Array.isArray(evidence.canonicalOpenPrs) &&
          evidence.canonicalOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' &&
            Number(pr?.merged ?? 0) === 0 && pr?.source === 'ClosureComment.prMention'),
          `superseded_to_open_pr issue #${row.issue_number} must include trusted closure-comment open PR evidence`);
      }
      if (row.status === 'duplicate_with_open_pr_context') {
        expect(failures, tag, Array.isArray(evidence.relatedOpenPrs) &&
          evidence.relatedOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) === 0),
          `duplicate_with_open_pr_context issue #${row.issue_number} must include related open PR evidence`);
      }
      if (row.status === 'duplicate_related_closed_unmerged_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `duplicate_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_not_reachable_context') {
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `duplicate_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `duplicate_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'duplicate_related_merged_pr_reachability_unknown') {
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `duplicate_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'duplicate_related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `duplicate_related_pr_without_release_fix issue #${row.issue_number} must include linked PR context`);
      }
      if (row.status === 'duplicate_to_closed_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, !!evidence.canonicalResolution?.terminalProof,
          `duplicate_to_closed_canonical issue #${row.issue_number} must include terminal proof; missing terminal proof should use duplicate_to_closed_canonical_missing_proof`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'unsupported_closure_claim',
          `duplicate_to_closed_canonical issue #${row.issue_number} must resolve to unsupported terminal proof; use a more specific canonical status for resolved/open/missing proof`);
      }
      if (row.status === 'duplicate_to_non_actionable_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_non_actionable_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'neutral_or_non_actionable',
          `duplicate_to_non_actionable_canonical issue #${row.issue_number} must resolve to neutral/non-actionable terminal proof`);
      }
      if (row.status === 'duplicate_to_known_not_in_release_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_known_not_in_release_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'known_not_in_release',
          `duplicate_to_known_not_in_release_canonical issue #${row.issue_number} must resolve to known-not-in-release terminal proof`);
      }
      if (row.status === 'duplicate_to_open_pr_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_open_pr_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag,
          riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'open_canonical_risk' ||
          evidence.canonicalResolution?.terminalProof?.status === 'related_open_pr_context',
          `duplicate_to_open_pr_canonical issue #${row.issue_number} must resolve to open-risk terminal proof`);
      }
      if (row.status === 'duplicate_to_unverified_closed_canonical') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_unverified_closed_canonical issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'unsupported_closure_claim' ||
          riskDispositionForStatus(evidence.canonicalResolution?.terminalProof?.status) === 'missing_evidence',
          `duplicate_to_unverified_closed_canonical issue #${row.issue_number} must resolve to unsupported/missing terminal proof`);
      }
      if (row.status === 'duplicate_to_closed_canonical_missing_proof') {
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must resolve to a closed terminal`);
        expect(failures, tag, !evidence.canonicalResolution?.terminalProof ||
          ['no_timeline_event', 'unknown'].includes(evidence.canonicalResolution.terminalProof.status),
          `duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must have missing/incomplete terminal proof`);
      }
      if (row.status === 'admin_not_planned_unverified') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `admin_not_planned_unverified issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Number(evidence.closureContextCommentCount ?? 0) > 0,
          `admin_not_planned_unverified issue #${row.issue_number} must include close-time context; use admin_not_planned_no_context when none exists`);
        expect(failures, tag, evidence.hasReachableFixCommit !== true && evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableFixCommit !== true && evidence.hasNotReachableClosingPr !== true,
          `admin_not_planned_unverified issue #${row.issue_number} must not have direct fix proof; use a not_planned_* proof status`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `admin_not_planned_unverified issue #${row.issue_number} must not include linked PR context; use a not_planned_* proof status`);
      }
      if (row.status === 'admin_not_planned_no_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `admin_not_planned_no_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Number(evidence.closureContextCommentCount ?? -1) === 0,
          `admin_not_planned_no_context issue #${row.issue_number} must have zero close-time rationale comments`);
        expect(failures, tag, evidence.hasReachableFixCommit !== true && evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableFixCommit !== true && evidence.hasNotReachableClosingPr !== true,
          `admin_not_planned_no_context issue #${row.issue_number} must not have direct fix proof; use a not_planned_* proof status`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `admin_not_planned_no_context issue #${row.issue_number} must not include linked PR context; use a not_planned_* proof status`);
      }
      if (row.status === 'insufficient_info') {
        expect(failures, tag, Array.isArray(evidence.matchingComments) && evidence.matchingComments.length > 0,
          `insufficient_info issue #${row.issue_number} must include close-time matching rationale`);
      }
      if (row.status === 'not_planned_with_release_fix_proof') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_with_release_fix_proof issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, evidence.hasReachableFixCommit === true || evidence.hasReachableClosingPr === true ||
          trustedReachableFixProofPrs(evidence).length > 0,
          `not_planned_with_release_fix_proof issue #${row.issue_number} must have reachable PR or commit evidence`);
      }
      if (row.status === 'not_planned_fixed_after_release') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_fixed_after_release issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, evidence.hasNotReachableFixCommit === true || evidence.hasNotReachableClosingPr === true,
          `not_planned_fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
      }
      if (row.status === 'not_planned_with_open_pr_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_with_open_pr_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) &&
          evidence.linkedPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `not_planned_with_open_pr_context issue #${row.issue_number} must include open PR context`);
      }
      if (row.status === 'not_planned_linked_pr_not_merged') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_linked_pr_not_merged issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) &&
          evidence.linkedPrs.some((pr) => Number(pr?.willCloseTarget ?? 0) === 1 && Number(pr?.merged ?? 0) !== 1),
          `not_planned_linked_pr_not_merged issue #${row.issue_number} must include an unmerged linked closing PR`);
      }
      if (row.status === 'not_planned_related_closed_unmerged_pr_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_closed_unmerged_pr_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `not_planned_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_not_reachable_context') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_not_reachable_context issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `not_planned_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `not_planned_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'not_planned_related_merged_pr_reachability_unknown') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_merged_pr_reachability_unknown issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `not_planned_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'not_planned_related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.stateReasons) && evidence.stateReasons.includes('NOT_PLANNED'),
          `not_planned_related_pr_without_release_fix issue #${row.issue_number} must have NOT_PLANNED state reason`);
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `not_planned_related_pr_without_release_fix issue #${row.issue_number} must include related PR references`);
      }
      if (row.status === 'linked_closing_pr_not_merged') {
        expect(failures, tag, evidence.hasClosingLink === true && evidence.hasMergedClosingPr !== true,
          `linked_closing_pr_not_merged issue #${row.issue_number} must have an unmerged/unknown closing PR`);
      }
      if (row.status === 'linked_closing_pr_open') {
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `linked_closing_pr_open issue #${row.issue_number} must have open linked closing PR evidence`);
      }
      if (row.status === 'linked_closing_pr_closed_unmerged') {
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'CLOSED' && Number(pr?.merged ?? 0) !== 1),
          `linked_closing_pr_closed_unmerged issue #${row.issue_number} must have closed-unmerged linked closing PR evidence`);
      }
      if (row.status === 'linked_closing_pr_reachability_unknown') {
        expect(failures, tag, evidence.hasClosingLink === true &&
          evidence.hasMergedClosingPr === true &&
          evidence.hasReachableClosingPr !== true &&
          evidence.hasNotReachableClosingPr !== true,
          `linked_closing_pr_reachability_unknown issue #${row.issue_number} must have merged closing PR with unknown reachability`);
      }
      if (row.status === 'related_pr_without_release_fix') {
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `related_pr_without_release_fix issue #${row.issue_number} must include related PR references`);
        expect(failures, tag, evidence.hasClosingLink !== true,
          `related_pr_without_release_fix issue #${row.issue_number} must not have a credited closing PR link`);
      }
      if (row.status === 'external_repo_closing_pr_unscored') {
        expect(failures, tag, relatedPrContext(evidence).externalClosing.length > 0,
          `external_repo_closing_pr_unscored issue #${row.issue_number} must include external closing PR context`);
      }
      if (row.status === 'related_open_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).open.length > 0,
          `related_open_pr_context issue #${row.issue_number} must include open related PR context`);
      }
      if (row.status === 'related_closed_unmerged_pr_context') {
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'related_merged_pr_not_reachable_context') {
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'related_merged_pr_reachable_context_without_fix_credit') {
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'related_merged_pr_reachability_unknown') {
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'closed_without_release_fix_proof') {
        expect(failures, tag, evidence.hasClosingLink !== true,
          `closed_without_release_fix_proof issue #${row.issue_number} must not have a credited closing PR link`);
        expect(failures, tag, !Array.isArray(evidence.linkedPrs) || evidence.linkedPrs.length === 0,
          `closed_without_release_fix_proof issue #${row.issue_number} must not include related PR references`);
      }
      if (row.status === 'non_bug_fixed_in_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasReachableClosingPr === true || evidence.hasReachableFixCommit === true,
          `non_bug_fixed_in_release issue #${row.issue_number} must have reachable PR or commit evidence`);
      }
      if (row.status === 'non_bug_fixed_after_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
          `non_bug_fixed_after_release issue #${row.issue_number} must have not-reachable PR or commit evidence`);
      }
      if (row.status === 'non_bug_fixed_in_later_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.laterFixProof?.releaseTag && ['pr', 'commit'].includes(evidence.laterFixProof?.proofType),
          `non_bug_fixed_in_later_release issue #${row.issue_number} must include laterFixProof metadata`);
      }
      if (row.status === 'non_bug_fixed_not_in_scored_releases') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, !evidence.laterFixProof,
          `non_bug_fixed_not_in_scored_releases issue #${row.issue_number} must not include laterFixProof metadata`);
      }
      if (row.status === 'non_bug_fixed_after_latest_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'after_latest_release',
          `non_bug_fixed_after_latest_release issue #${row.issue_number} must include after-latest unscoredFixProof metadata`);
        verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease });
      }
      if (row.status === 'non_bug_fixed_skipped_by_later_releases') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.unscoredFixProof?.timing === 'skipped_by_later_releases',
          `non_bug_fixed_skipped_by_later_releases issue #${row.issue_number} must include skipped-by-later unscoredFixProof metadata`);
      }
      if (row.status === 'non_bug_linked_without_merge') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.hasClosingLink === true && evidence.hasMergedClosingPr !== true,
          `non_bug_linked_without_merge issue #${row.issue_number} must have an unmerged/unknown linked PR`);
      }
      if (row.status === 'non_bug_linked_pr_open') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) !== 1),
          `non_bug_linked_pr_open issue #${row.issue_number} must have open linked closing PR evidence`);
      }
      if (row.status === 'non_bug_linked_pr_closed_unmerged') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, linkedClosingPrEvidence(evidence).some((pr) =>
          String(pr?.state ?? '').toUpperCase() === 'CLOSED' && Number(pr?.merged ?? 0) !== 1),
          `non_bug_linked_pr_closed_unmerged issue #${row.issue_number} must have closed-unmerged linked closing PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_to_fixed_in_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalProof?.status === 'fixed_in_release' ||
          canonicalFixCommitProof(evidence).some((proof) => proof.status === 'reachable'),
          `non_bug_duplicate_to_fixed_in_release issue #${row.issue_number} must resolve to fixed-in-release canonical proof`);
      }
      if (row.status === 'non_bug_duplicate_to_fixed_after_release') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, canonicalFixedAfterRelease(evidence),
          `non_bug_duplicate_to_fixed_after_release issue #${row.issue_number} must resolve to fixed-after canonical proof`);
      }
      if (row.status === 'non_bug_duplicate_to_open_canonical') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'open',
          `non_bug_duplicate_to_open_canonical issue #${row.issue_number} must resolve to an open terminal`);
      }
      if (row.status === 'non_bug_duplicate_to_closed_canonical') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed' &&
          !!evidence.canonicalResolution?.terminalProof,
          `non_bug_duplicate_to_closed_canonical issue #${row.issue_number} must resolve to a closed terminal with proof`);
      }
      if (row.status === 'non_bug_duplicate_to_closed_canonical_missing_proof') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, evidence.canonicalResolution?.terminalIssue?.state === 'closed',
          `non_bug_duplicate_to_closed_canonical_missing_proof issue #${row.issue_number} must resolve to a closed terminal`);
      }
      if (row.status === 'non_bug_superseded_to_open_pr') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.canonicalOpenPrs) &&
          evidence.canonicalOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' &&
            Number(pr?.merged ?? 0) === 0 && pr?.source === 'ClosureComment.prMention'),
          `non_bug_superseded_to_open_pr issue #${row.issue_number} must include trusted closure-comment open PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_with_open_pr_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.relatedOpenPrs) &&
          evidence.relatedOpenPrs.some((pr) => String(pr?.state ?? '').toUpperCase() === 'OPEN' && Number(pr?.merged ?? 0) === 0),
          `non_bug_duplicate_with_open_pr_context issue #${row.issue_number} must include related open PR evidence`);
      }
      if (row.status === 'non_bug_duplicate_related_closed_unmerged_pr_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).closedUnmerged.length > 0,
          `non_bug_duplicate_related_closed_unmerged_pr_context issue #${row.issue_number} must include closed-unmerged related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_not_reachable_context') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).notReachable.length > 0,
          `non_bug_duplicate_related_merged_pr_not_reachable_context issue #${row.issue_number} must include not-reachable related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).reachable.length > 0,
          `non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit issue #${row.issue_number} must include reachable related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_merged_pr_reachability_unknown') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, relatedPrContext(evidence).unknownReachability.length > 0,
          `non_bug_duplicate_related_merged_pr_reachability_unknown issue #${row.issue_number} must include unknown-reachability related PR context`);
      }
      if (row.status === 'non_bug_duplicate_related_pr_without_release_fix') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.linkedPrs) && evidence.linkedPrs.length > 0,
          `non_bug_duplicate_related_pr_without_release_fix issue #${row.issue_number} must include linked PR context`);
      }
      if (row.status === 'non_bug_duplicate_or_superseded') {
        expectNonNegativeProof({ failures, tag, row });
      }
      if (row.status === 'non_bug_not_actionable') {
        expectNonNegativeProof({ failures, tag, row });
        expect(failures, tag, Array.isArray(evidence.nonActionableRationaleComments) &&
          evidence.nonActionableRationaleComments.length > 0,
          `non_bug_not_actionable issue #${row.issue_number} must include concrete non-actionable rationale`);
      }
      if (isNegativeBareNotPlannedNeutral(row, evidence)) {
        expect(failures, tag, false,
          `negative NOT_PLANNED issue #${row.issue_number} cannot be neutral/non-actionable without concrete close-time rationale`);
      }
      if (row.status === 'canonical_cycle_or_self_reference') {
        expect(failures, tag, evidence.canonicalResolution?.cycle === true || evidence.canonicalResolution?.selfReference === true,
          `canonical_cycle_or_self_reference issue #${row.issue_number} must record cycle/self-reference evidence`);
      }
    }

    const audit = reader.getReleaseScoreAudit(tag);
    if (audit) {
      const scoreInput = parseJson(audit.input_json, {});
      const scoreComponents = parseJson(audit.components_json, {});
      const gate = parseJson(audit.gate_evidence_json, {});
      const issueEvidence = parseJson(audit.issue_evidence_json, {});
      failures.push(...verifyScoreAuditPayloadContracts({
        tag,
        input: scoreInput,
        components: scoreComponents,
        issueEvidence,
        gateEvidence: gate,
        versions: {
          scoreInput: scoreInputSchemaVersion,
          scoreComponents: scoreComponentsSchemaVersion,
          issueEvidence: issueEvidenceSchemaVersion,
          gateEvidence: gateEvidenceSchemaVersion,
        },
      }));
      verifyPersistedAuditTuple({ failures, tag, release, audit, scoreInput, scoreComponents });
      expect(failures, tag, scoreInput.schemaVersion === scoreInputSchemaVersion,
        `persisted score input schemaVersion (${scoreInput.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
      expect(failures, tag, scoreComponents.schemaVersion === scoreComponentsSchemaVersion,
        `persisted score components schemaVersion (${scoreComponents.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
      expect(failures, tag, gate.schemaVersion === gateEvidenceSchemaVersion,
        `persisted gateEvidence schemaVersion (${gate.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
      verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit });
      verifyLabelTimelineGate({ failures, tag, labelTimeline: gate.labelTimeline });
      verifyReleaseChecksGate({ failures, tag, releaseChecks: gate.releaseChecks });
      verifyArtifactVerificationGate({ failures, tag, artifactVerification: gate.artifactVerification });
      verifyClosedClassificationPromptVersion({ failures, tag, closed, audit });
      verifyProofFreshness({ failures, tag, proofRows, audit, reader });
      expect(failures, tag, issueEvidence.schemaVersion === issueEvidenceSchemaVersion,
        `persisted issueEvidence schemaVersion (${issueEvidence.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    const fix = gate.fixProvenance ?? {};
    expect(failures, tag, fix.verifiedFixedCount === verified.length,
      `audit verifiedFixedCount (${fix.verifiedFixedCount}) must match verifiedFixedForRelease (${verified.length})`);
    expect(failures, tag, fix.unverifiedClosedCount === unverified.length,
      `audit unverifiedClosedCount (${fix.unverifiedClosedCount}) must match unverifiedClosedForRelease (${unverified.length})`);
    if (proofRows.length) {
      expect(failures, tag, !!fix.closureProof && !!fix.releaseFixCredit,
        'persisted audit gateEvidence must include closureProof and releaseFixCredit when proof rows exist');
      if (fix.closureProof && fix.releaseFixCredit) {
        const expectedRisk = riskSummaryForProofRows(proofRows);
        expect(failures, tag, fix.closureProof.schemaVersion === closureProofSchemaVersion,
          `persisted closureProof schemaVersion (${fix.closureProof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
        expect(failures, tag, fix.releaseFixCredit.schemaVersion === releaseFixCreditSchemaVersion,
          `persisted releaseFixCredit schemaVersion (${fix.releaseFixCredit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
        expect(failures, tag, fix.releaseFixCredit.countedClosedCount === fixedProof.length,
          `persisted countedClosedCount (${fix.releaseFixCredit.countedClosedCount}) must match fixed_in_release proof rows (${fixedProof.length})`);
        expect(failures, tag, fix.releaseFixCredit.notCountedClosedCount === notCountedProof.length,
          `persisted notCountedClosedCount (${fix.releaseFixCredit.notCountedClosedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
        expect(failures, tag, fix.releaseFixCredit.analyzedClosedCount === proofRows.length,
          `persisted analyzedClosedCount (${fix.releaseFixCredit.analyzedClosedCount}) must match proof rows (${proofRows.length})`);
        expect(failures, tag, fix.closureProof.creditedCount === fixedProof.length,
          `persisted closureProof creditedCount (${fix.closureProof.creditedCount}) must match fixed proof rows (${fixedProof.length})`);
        expect(failures, tag, fix.closureProof.notCreditedCount === notCountedProof.length,
          `persisted closureProof notCreditedCount (${fix.closureProof.notCreditedCount}) must match non-fixed proof rows (${notCountedProof.length})`);
        expectJsonEqual(failures, tag, 'persisted closureProof byRiskDisposition must match proof row dispositions',
          fix.closureProof.byRiskDisposition, expectedRisk.counts);
        expectJsonEqual(failures, tag, 'persisted closureProof riskSummary must match proof row dispositions',
          fix.closureProof.riskSummary, expectedRisk.summary);
        expect(failures, tag,
          Number(scoreInput.unresolvedClosureIssueCount ?? 0) === Number(expectedRisk.summary.unresolvedForReleaseCount ?? 0),
          `score input unresolvedClosureIssueCount (${scoreInput.unresolvedClosureIssueCount}) must match closureProof riskSummary unresolvedForReleaseCount (${expectedRisk.summary.unresolvedForReleaseCount})`);
        expect(failures, tag,
          roundMetric(Number(scoreInput.unresolvedClosureRiskWeight ?? 0)) === Number(expectedRisk.summary.unresolvedWeightedRisk ?? 0),
          `score input unresolvedClosureRiskWeight (${scoreInput.unresolvedClosureRiskWeight}) must match closureProof riskSummary unresolvedWeightedRisk (${expectedRisk.summary.unresolvedWeightedRisk})`);
        for (const [disposition] of Object.entries(fix.closureProof.byRiskDisposition ?? {})) {
          expect(failures, tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
        verifyClosureProofExamplesByStatus({
          failures,
          tag,
          proof: fix.closureProof,
          label: 'persisted closureProof',
        });
      }
    }
  } else {
      expect(failures, tag, false, 'release score audit row is missing');
    }
  }

  if (apiBase) {
    await verifyApi({ apiBase: apiBase.replace(/\/$/, ''), fetchJson, reader, releases, failures });
  }

  return { releases, rows, failures };
}

function verifySourceFreshness({ failures, tag, sourceFreshnessRows, audit }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  for (const row of sourceFreshnessRows ?? []) {
    if (!row?.max_ts) continue;
    const sourceAt = Date.parse(row.max_ts);
    expect(failures, tag, Number.isFinite(sourceAt),
      `${row.source} max timestamp must be valid, got ${row.max_ts}`);
    if (!Number.isFinite(sourceAt)) continue;
    expect(failures, tag, sourceAt <= scoredAt,
      `${row.source} changed at ${row.max_ts}, newer than audit scored_at ${audit.scored_at}`);
  }
}

function verifyLabelTimelineGate({ failures, tag, labelTimeline }) {
  expect(failures, tag, isObject(labelTimeline), 'persisted audit gateEvidence must include labelTimeline coverage');
  if (!isObject(labelTimeline)) return;
  expect(failures, tag, labelTimeline.schemaVersion === labelTimelineSchemaVersion,
    `labelTimeline schemaVersion (${labelTimeline.schemaVersion}) must equal ${labelTimelineSchemaVersion}`);
  for (const key of ['issueCount', 'currentLabelCount', 'timelineLabelCount', 'snapshotLabelCount', 'missingTimelineCount', 'missingTimelineWithCurrentLabelsCount']) {
    expect(failures, tag, Number.isInteger(labelTimeline[key]) && labelTimeline[key] >= 0,
      `labelTimeline ${key} must be a non-negative integer`);
  }
  const sourceTotal = Number(labelTimeline.currentLabelCount ?? -1) +
    Number(labelTimeline.timelineLabelCount ?? -1) +
    Number(labelTimeline.snapshotLabelCount ?? -1) +
    Number(labelTimeline.missingTimelineCount ?? -1);
  expect(failures, tag, sourceTotal === labelTimeline.issueCount,
    `labelTimeline source counts (${sourceTotal}) must equal issueCount (${labelTimeline.issueCount})`);
  expect(failures, tag, labelTimeline.missingTimelineWithCurrentLabelsCount <= labelTimeline.missingTimelineCount,
    'labelTimeline missingTimelineWithCurrentLabelsCount must not exceed missingTimelineCount');
  expect(failures, tag, typeof labelTimeline.historicalCurrentLabelFallbackAllowed === 'boolean',
    'labelTimeline historicalCurrentLabelFallbackAllowed must be boolean');
  if (labelTimeline.cutoffAt != null) {
    expect(failures, tag, labelTimeline.historicalCurrentLabelFallbackAllowed === false,
      'historical label cutoffs must not allow current-label fallback');
  }
}

function verifyReleaseChecksGate({ failures, tag, releaseChecks }) {
  if (releaseChecks == null) return;
  expect(failures, tag, isObject(releaseChecks), 'releaseChecks must be an object or null');
  if (!isObject(releaseChecks)) return;
  expect(failures, tag, releaseChecks.schemaVersion === releaseChecksSchemaVersion,
    `releaseChecks schemaVersion (${releaseChecks.schemaVersion}) must equal ${releaseChecksSchemaVersion}`);
  for (const key of ['total', 'success', 'failure', 'pending', 'skipped', 'contextCount', 'shownContextCount']) {
    expect(failures, tag, Number.isInteger(releaseChecks[key]) && releaseChecks[key] >= 0,
      `releaseChecks ${key} must be a non-negative integer`);
  }
  const counted = Number(releaseChecks.success ?? -1) + Number(releaseChecks.failure ?? -1) +
    Number(releaseChecks.pending ?? -1) + Number(releaseChecks.skipped ?? -1);
  expect(failures, tag, counted === releaseChecks.total,
    `releaseChecks counted contexts (${counted}) must equal total (${releaseChecks.total})`);
  expect(failures, tag, releaseChecks.contextCount === releaseChecks.total,
    `releaseChecks contextCount (${releaseChecks.contextCount}) must equal total (${releaseChecks.total})`);
  expect(failures, tag, typeof releaseChecks.contextsTruncated === 'boolean',
    'releaseChecks contextsTruncated must be boolean');
  expect(failures, tag, Array.isArray(releaseChecks.contexts),
    'releaseChecks contexts must be an array');
  if (Array.isArray(releaseChecks.contexts)) {
    expect(failures, tag, releaseChecks.contexts.length === releaseChecks.shownContextCount,
      `releaseChecks shownContextCount (${releaseChecks.shownContextCount}) must equal contexts length (${releaseChecks.contexts.length})`);
    expect(failures, tag, releaseChecks.shownContextCount <= releaseChecks.contextCount,
      `releaseChecks shownContextCount (${releaseChecks.shownContextCount}) must not exceed contextCount (${releaseChecks.contextCount})`);
    expect(failures, tag, releaseChecks.contextsTruncated === (releaseChecks.shownContextCount < releaseChecks.contextCount),
      'releaseChecks contextsTruncated must reflect whether contexts are omitted');
  }
}

function verifyArtifactVerificationGate({ failures, tag, artifactVerification }) {
  expect(failures, tag, isObject(artifactVerification), 'artifactVerification must be an object');
  if (!isObject(artifactVerification)) return;
  expect(failures, tag, artifactVerification.schemaVersion === artifactVerificationSchemaVersion,
    `artifactVerification schemaVersion (${artifactVerification.schemaVersion}) must equal ${artifactVerificationSchemaVersion}`);
  expect(failures, tag, typeof artifactVerification.verified === 'boolean',
    'artifactVerification verified must be boolean');
  if (artifactVerification.releaseShaMatches != null) {
    expect(failures, tag, typeof artifactVerification.releaseShaMatches === 'boolean',
      'artifactVerification releaseShaMatches must be boolean or null');
  }
  expect(failures, tag, typeof artifactVerification.ciReportVerified === 'boolean',
    'artifactVerification ciReportVerified must be boolean');
  expect(failures, tag, typeof artifactVerification.releaseValidationVerified === 'boolean',
    'artifactVerification releaseValidationVerified must be boolean');
}

function verifyClosedClassificationPromptVersion({ failures, tag, closed, audit }) {
  const expected = Number(audit.prompt_version);
  expect(failures, tag, Number.isInteger(expected) && expected >= 0,
    `audit prompt_version must be a non-negative integer, got ${audit.prompt_version}`);
  if (!Number.isInteger(expected)) return;
  for (const row of closed) {
    expect(failures, tag, Number(row.prompt_version) === expected,
      `closed issue #${row.number} classification prompt_version (${row.prompt_version}) must match audit prompt_version (${expected})`);
  }
}

function verifyProofFreshness({ failures, tag, proofRows, audit, reader }) {
  const scoredAt = Date.parse(audit.scored_at ?? '');
  expect(failures, tag, Number.isFinite(scoredAt),
    `audit scored_at must be a valid timestamp, got ${audit.scored_at}`);
  if (!Number.isFinite(scoredAt)) return;
  for (const row of proofRows) {
    const checkedAt = Date.parse(row.checked_at ?? '');
    expect(failures, tag, Number.isFinite(checkedAt),
      `proof issue #${row.issue_number} checked_at must be a valid timestamp`);
    if (!Number.isFinite(checkedAt)) continue;
    expect(failures, tag, checkedAt <= scoredAt,
      `proof issue #${row.issue_number} checked_at (${row.checked_at}) must not be newer than audit scored_at (${audit.scored_at})`);
    const evidence = parseJson(row.evidence_json, {});
    const closedAt = evidence?.closedAt ? Date.parse(evidence.closedAt) : NaN;
    if (Number.isFinite(closedAt)) {
      expect(failures, tag, checkedAt >= closedAt,
        `proof issue #${row.issue_number} checked_at (${row.checked_at}) must be newer than closure time (${evidence.closedAt})`);
    }
    if (typeof reader.proofDependencyFreshnessForIssue === 'function') {
      const dependencyFreshness = reader.proofDependencyFreshnessForIssue(tag, row.issue_number) ?? [];
      const dependencySources = new Set(dependencyFreshness.map((source) => source?.source).filter(Boolean));
      for (const required of requiredProofDependencySources) {
        expect(failures, tag, dependencySources.has(required),
          `proof issue #${row.issue_number} dependency freshness must include ${required}`);
      }
      for (const source of dependencyFreshness) {
        if (!source?.max_ts) continue;
        const sourceAt = Date.parse(source.max_ts);
        expect(failures, tag, Number.isFinite(sourceAt),
          `proof issue #${row.issue_number} ${source.source} dependency max timestamp must be valid, got ${source.max_ts}`);
        if (!Number.isFinite(sourceAt)) continue;
        expect(failures, tag, sourceAt <= checkedAt,
          `proof issue #${row.issue_number} checked_at (${row.checked_at}) must be newer than ${source.source} dependency (${source.max_ts})`);
      }
    }
  }
}

function verifyProofPrReachabilityEvidence({ failures, tag, row, evidence, prEvidence }) {
  verifyEmbeddedProofPrEvidenceShapes({ failures, tag, row, evidence });
  const prEvidenceByKey = new Map(prEvidence.map((pr) => [
    prKey(pr.pr_repository_name_with_owner, pr.pr_number),
    pr,
  ]));
  for (const linkedPr of Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : []) {
    const repo = String(linkedPr?.repositoryNameWithOwner ?? '');
    const number = Number(linkedPr?.number ?? 0);
    const merged = Number(linkedPr?.merged ?? 0) === 1;
    if (!merged || !Number.isInteger(number) || number <= 0) continue;
    if (repo !== 'openclaw/openclaw') {
      expect(failures, tag, linkedPr.reachabilityStatus === 'external_repo_unchecked',
        `proof issue #${row.issue_number} external linked PR ${repo}#${number} must carry external_repo_unchecked reachabilityStatus`);
      expect(failures, tag, linkedPr.reachabilityEvidence === 'external_repository_not_checked_against_openclaw_release_tag',
        `proof issue #${row.issue_number} external linked PR ${repo}#${number} must explain why release reachability is not checked`);
      continue;
    }
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(linkedPr.reachabilityStatus),
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityStatus`);
    expect(failures, tag, typeof linkedPr.reachabilityMethod === 'string' || linkedPr.reachabilityMethod == null,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityMethod`);
    expect(failures, tag, typeof linkedPr.reachabilityEvidence === 'string' && linkedPr.reachabilityEvidence.length > 0,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must carry reachabilityEvidence`);
    const persisted = prEvidenceByKey.get(prKey(repo, number));
    expect(failures, tag, !!persisted,
      `proof issue #${row.issue_number} linked PR ${repo}#${number} must have matching persisted reachability row`);
    if (persisted) {
      expect(failures, tag, linkedPr.reachabilityStatus === persisted.status,
        `proof issue #${row.issue_number} linked PR ${repo}#${number} reachabilityStatus (${linkedPr.reachabilityStatus}) must match persisted reachability (${persisted.status})`);
      if (linkedPr.mergeCommitOid != null && persisted.merge_commit_oid != null) {
        expect(failures, tag, linkedPr.mergeCommitOid === persisted.merge_commit_oid,
          `proof issue #${row.issue_number} linked PR ${repo}#${number} mergeCommitOid (${linkedPr.mergeCommitOid}) must match persisted reachability (${persisted.merge_commit_oid})`);
      }
    }
  }
  for (const pr of prEvidence) {
    const prLabel = `${pr.pr_repository_name_with_owner ?? 'unknown-repo'}#${pr.pr_number}`;
    expect(failures, tag, typeof pr.pr_repository_name_with_owner === 'string' && pr.pr_repository_name_with_owner.includes('/'),
      `proof issue #${row.issue_number} PR #${pr.pr_number} reachability evidence must include repository identity`);
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(pr.status),
      `proof issue #${row.issue_number} PR ${prLabel} reachability status ${pr.status} must be known`);
    if (pr.release_tag_commit_oid != null) {
      expect(failures, tag, pr.tag_commit_oid === pr.release_tag_commit_oid,
        `proof issue #${row.issue_number} PR ${prLabel} reachability tag commit (${pr.tag_commit_oid}) must match release commit (${pr.release_tag_commit_oid})`);
    }
    if (pr.status === 'unknown') {
      const prReachabilityEvidence = parseJson(pr.evidence_json, {});
      expect(failures, tag, typeof prReachabilityEvidence.evidence === 'string' && prReachabilityEvidence.evidence.length > 0,
        `proof issue #${row.issue_number} PR ${prLabel} unknown reachability must include evidence reason`);
    }
  }
  if (evidence.hasReachableClosingPr === true) {
    expect(failures, tag, linkedMergedPrEvidence(evidence).some((linkedPr) =>
      matchingReachabilityPr(prEvidenceByKey, linkedPr, 'reachable')),
      `proof issue #${row.issue_number} hasReachableClosingPr must have a merged reachable PR row`);
  }
  if (evidence.hasNotReachableClosingPr === true) {
    expect(failures, tag, linkedMergedPrEvidence(evidence).some((linkedPr) =>
      matchingReachabilityPr(prEvidenceByKey, linkedPr, 'not_reachable')),
      `proof issue #${row.issue_number} hasNotReachableClosingPr must have a merged not-reachable PR row`);
  }
}

function verifyEmbeddedProofPrEvidenceShapes({ failures, tag, row, evidence }) {
  for (const [idx, pr] of (Array.isArray(evidence.linkedPrs) ? evidence.linkedPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `linkedPrs[${idx}]` });
  }
  const context = relatedPrContext(evidence);
  for (const [bucket, prs] of Object.entries(context)) {
    for (const [idx, pr] of prs.entries()) {
      verifyEmbeddedProofPr({ failures, tag, row, pr, label: `relatedPrContext.${bucket}[${idx}]` });
    }
  }
  for (const [idx, pr] of (Array.isArray(evidence.canonicalOpenPrs) ? evidence.canonicalOpenPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `canonicalOpenPrs[${idx}]` });
  }
  for (const [idx, pr] of (Array.isArray(evidence.relatedOpenPrs) ? evidence.relatedOpenPrs : []).entries()) {
    verifyEmbeddedProofPr({ failures, tag, row, pr, label: `relatedOpenPrs[${idx}]` });
  }
}

function verifyEmbeddedProofPr({ failures, tag, row, pr, label }) {
  expect(failures, tag, isObject(pr),
    `proof issue #${row.issue_number} ${label} must be a PR evidence object`);
  if (!isObject(pr)) return;
  const repo = String(pr.repositoryNameWithOwner ?? '');
  const number = Number(pr.number ?? 0);
  const state = String(pr.state ?? '');
  const merged = pr.merged;
  const source = String(pr.source ?? '');
  expect(failures, tag, Number.isInteger(number) && number > 0,
    `proof issue #${row.issue_number} ${label} must include a positive PR number`);
  expect(failures, tag, repo.includes('/'),
    `proof issue #${row.issue_number} ${label} PR #${number || 'unknown'} must include repositoryNameWithOwner`);
  expect(failures, tag, source.length > 0,
    `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include source`);
  expect(failures, tag, ['OPEN', 'CLOSED', 'MERGED'].includes(state),
    `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include known state`);
  expect(failures, tag, merged === 0 || merged === 1 || merged === false || merged === true,
    `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} must include merged flag`);
  if (merged === 1 || merged === true) {
    expect(failures, tag, state === 'MERGED',
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} merged PR must have MERGED state`);
    expect(failures, tag, typeof pr.mergedAt === 'string' && Number.isFinite(Date.parse(pr.mergedAt)),
      `proof issue #${row.issue_number} ${label} ${repo || 'unknown-repo'}#${number || 'unknown'} merged PR must include mergedAt`);
  }
}

function prKey(repo, number) {
  return `${String(repo ?? '')}#${Number(number ?? 0)}`;
}

function matchingReachabilityPr(prEvidenceByKey, linkedPr, status) {
  const repo = String(linkedPr?.repositoryNameWithOwner ?? '');
  const number = Number(linkedPr?.number ?? 0);
  const persisted = prEvidenceByKey.get(prKey(repo, number));
  return !!persisted && persisted.merged === 1 && persisted.status === status;
}

function verifyAllowedKeys({ failures, tag, label, value, allowed }) {
  expect(failures, tag, isObject(value), `${label} must be an object`);
  if (!isObject(value)) return;
  const extra = Object.keys(value).filter((key) => !allowed.has(key)).sort();
  expect(failures, tag, extra.length === 0,
    `${label} must not expose unknown keys: ${extra.join(', ')}`);
}

function verifyDataFreshness({ failures, tag, dataFreshness, releaseTag, scoredAt = null }) {
  expect(failures, tag, isObject(dataFreshness), 'dataFreshness must be present');
  if (!isObject(dataFreshness)) return;
  expect(failures, tag, dataFreshness.schemaVersion === 1,
    `dataFreshness schemaVersion must be 1, got ${JSON.stringify(dataFreshness.schemaVersion)}`);
  expect(failures, tag, dataFreshness.tag === releaseTag,
    `dataFreshness tag (${dataFreshness.tag}) must match release tag (${releaseTag})`);
  if (scoredAt != null) {
    expect(failures, tag, dataFreshness.scoredAt === scoredAt,
      `dataFreshness scoredAt (${dataFreshness.scoredAt}) must match release scored_at (${scoredAt})`);
  }
  expect(failures, tag, Array.isArray(dataFreshness.sources) && dataFreshness.sources.length > 0,
    'dataFreshness sources must be a non-empty array');
  const sources = new Map((dataFreshness.sources ?? []).map((source) => [source?.source, source]));
  for (const required of ['issue_rows', 'classification_rows', 'closure_proofs', 'release_metadata']) {
    expect(failures, tag, sources.has(required), `dataFreshness sources must include ${required}`);
  }
  expect(failures, tag, dataFreshness.issueUpdatedAtMax === (sources.get('issue_rows')?.maxAt ?? null),
    'dataFreshness issueUpdatedAtMax must match issue_rows source');
  expect(failures, tag, dataFreshness.closureProofCheckedAtMax === (sources.get('closure_proofs')?.maxAt ?? null),
    'dataFreshness closureProofCheckedAtMax must match closure_proofs source');
  const sourceFetchedAtMax = maxFreshnessTimestamp((dataFreshness.sources ?? []).map((source) => source?.maxAt ?? null));
  expect(failures, tag, dataFreshness.sourceFetchedAtMax === sourceFetchedAtMax,
    `dataFreshness sourceFetchedAtMax (${dataFreshness.sourceFetchedAtMax}) must equal max source timestamp (${sourceFetchedAtMax})`);
  for (const source of dataFreshness.sources ?? []) {
    expect(failures, tag, typeof source?.source === 'string' && source.source.length > 0,
      'dataFreshness source name must be present');
    expect(failures, tag, Number.isInteger(source?.count) && source.count >= 0,
      `dataFreshness ${source?.source} count must be a non-negative integer`);
    expect(failures, tag, Number.isInteger(source?.nullCount) && source.nullCount >= 0,
      `dataFreshness ${source?.source} nullCount must be a non-negative integer`);
    expect(failures, tag, Number(source?.nullCount ?? 0) <= Number(source?.count ?? 0),
      `dataFreshness ${source?.source} nullCount (${source?.nullCount}) must not exceed count (${source?.count})`);
    expect(failures, tag, Number(source?.nullCount ?? 0) === 0,
      `dataFreshness ${source?.source} must not have null freshness timestamps`);
    if (source?.maxAt != null) {
      expect(failures, tag, Number.isFinite(Date.parse(source.maxAt)),
        `dataFreshness ${source.source} maxAt must be a valid timestamp`);
      if (dataFreshness.scoredAt != null && Number.isFinite(Date.parse(source.maxAt)) && Number.isFinite(Date.parse(dataFreshness.scoredAt))) {
        expect(failures, tag, Date.parse(source.maxAt) <= Date.parse(dataFreshness.scoredAt),
          `dataFreshness ${source.source} changed at ${source.maxAt}, newer than scoredAt ${dataFreshness.scoredAt}`);
      }
    }
    if (source?.ageHoursAtScore != null) {
      expect(failures, tag, typeof source.ageHoursAtScore === 'number' && Number.isFinite(source.ageHoursAtScore),
        `dataFreshness ${source.source} ageHoursAtScore must be numeric`);
      expect(failures, tag, source.ageHoursAtScore === ageHoursAtScore(source.maxAt, dataFreshness.scoredAt),
        `dataFreshness ${source.source} ageHoursAtScore (${source.ageHoursAtScore}) must equal scoredAt - maxAt (${ageHoursAtScore(source.maxAt, dataFreshness.scoredAt)})`);
    }
  }
  expect(failures, tag, dataFreshness.issueUpdatedAgeHoursAtScore === ageHoursAtScore(dataFreshness.issueUpdatedAtMax, dataFreshness.scoredAt),
    `dataFreshness issueUpdatedAgeHoursAtScore (${dataFreshness.issueUpdatedAgeHoursAtScore}) must equal scoredAt - issueUpdatedAtMax (${ageHoursAtScore(dataFreshness.issueUpdatedAtMax, dataFreshness.scoredAt)})`);
  expect(failures, tag, dataFreshness.sourceFetchedAgeHoursAtScore === ageHoursAtScore(dataFreshness.sourceFetchedAtMax, dataFreshness.scoredAt),
    `dataFreshness sourceFetchedAgeHoursAtScore (${dataFreshness.sourceFetchedAgeHoursAtScore}) must equal scoredAt - sourceFetchedAtMax (${ageHoursAtScore(dataFreshness.sourceFetchedAtMax, dataFreshness.scoredAt)})`);
  for (const key of ['issueUpdatedAgeHoursAtScore', 'sourceFetchedAgeHoursAtScore']) {
    const value = dataFreshness[key];
    if (value != null) {
      expect(failures, tag, typeof value === 'number' && Number.isFinite(value),
        `dataFreshness ${key} must be numeric`);
    }
  }
}

function verifyPersistedAuditTuple({ failures, tag, release, audit, scoreInput, scoreComponents }) {
  if ('final_score' in audit) {
    expect(failures, tag, sameNumberOrNull(audit.final_score, release.final_score),
      `audit final_score (${audit.final_score}) must match DB final_score (${release.final_score})`);
  }
  if ('status' in audit) {
    expect(failures, tag, audit.status === release.state,
      `audit status (${audit.status}) must match DB state (${release.state})`);
  }
  if ('band' in audit) {
    expect(failures, tag, typeof audit.band === 'string' && audit.band.length > 0,
      `audit band (${audit.band}) must be present`);
  }
  if ('recommended' in audit) {
    expect(failures, tag, Number(audit.recommended) === Number(release.recommended ?? 0),
      `audit recommended (${audit.recommended}) must match DB recommended (${release.recommended})`);
  }
  if ('scored_at' in audit) {
    expect(failures, tag, audit.scored_at === release.scored_at,
      `audit scored_at (${audit.scored_at}) must match DB scored_at (${release.scored_at})`);
  }
  if (scoreComponents?.reason != null) {
    expect(failures, tag, scoreComponents.reason === release.score_reason,
      `score components reason (${scoreComponents.reason}) must match DB score_reason (${release.score_reason})`);
  }
  const ledger = scoreComponents?.explanation?.scoreLedger;
  if (ledger) {
    expect(failures, tag, sameNumberOrNull(ledger.finalScore, release.final_score),
      `score ledger finalScore (${ledger.finalScore}) must match DB final_score (${release.final_score})`);
    expect(failures, tag, ledger.status === release.state,
      `score ledger status (${ledger.status}) must match DB state (${release.state})`);
  }
  if (typeof scoreInput.rawIssueCount === 'number' && typeof scoreInput.classifiedIssueCount === 'number') {
    expect(failures, tag, scoreInput.classifiedIssueCount <= scoreInput.rawIssueCount,
      `score input classifiedIssueCount (${scoreInput.classifiedIssueCount}) must not exceed rawIssueCount (${scoreInput.rawIssueCount})`);
  }
}

function verifyReviewSourceProvenance({ failures, tag, sourceProvenance, dataFreshness, scoredAt }) {
  expect(failures, tag, isObject(sourceProvenance), 'review sourceProvenance must be present');
  if (!isObject(sourceProvenance)) return;
  expect(failures, tag, sourceProvenance.sourceMode === 'current_db',
    `review sourceProvenance sourceMode (${sourceProvenance.sourceMode}) must be current_db`);
  expect(failures, tag, sourceProvenance.scoreTable === 'release_score_audits',
    `review sourceProvenance scoreTable (${sourceProvenance.scoreTable}) must be release_score_audits`);
  expect(failures, tag, sourceProvenance.scoredAt === scoredAt,
    `review sourceProvenance scoredAt (${sourceProvenance.scoredAt}) must match DB scored_at (${scoredAt})`);
  expect(failures, tag, sourceProvenance.dataFreshnessScoredAt === dataFreshness?.scoredAt,
    `review sourceProvenance dataFreshnessScoredAt (${sourceProvenance.dataFreshnessScoredAt}) must match dataFreshness scoredAt (${dataFreshness?.scoredAt})`);
  expect(failures, tag, sourceProvenance.scoreTimestampAligned === (scoredAt === dataFreshness?.scoredAt),
    `review sourceProvenance scoreTimestampAligned (${sourceProvenance.scoreTimestampAligned}) must reflect scoredAt/dataFreshness alignment`);
  expectJsonEqual(failures, tag, 'review sourceProvenance sources must match review dataFreshness sources',
    sourceProvenance.sources, dataFreshness?.sources);
  const encodedTag = encodeURIComponent(tag);
  const expectedRawRows = {
    issues: `/api/releases/${encodedTag}/review/issues`,
    closureProofs: `/api/releases/${encodedTag}/review/closure-proofs`,
    reachability: `/api/releases/${encodedTag}/review/reachability`,
  };
  expectJsonEqual(failures, tag, 'review sourceProvenance rawRows must point at review row endpoints',
    sourceProvenance.rawRows, expectedRawRows);
}

function expectedAuditLinks(tag) {
  const encodedTag = encodeURIComponent(tag);
  return {
    review: `/api/releases/${encodedTag}/review`,
    issues: `/api/releases/${encodedTag}/review/issues`,
    closureProofs: `/api/releases/${encodedTag}/review/closure-proofs`,
    reachability: `/api/releases/${encodedTag}/review/reachability`,
  };
}

function verifyAuditLinks({ failures, tag, label, auditLinks }) {
  verifyAllowedKeys({ failures, tag, label, value: auditLinks, allowed: auditLinkKeys });
  if (!isObject(auditLinks)) return;
  expectJsonEqual(failures, tag, `${label} must point at release audit endpoints`,
    auditLinks, expectedAuditLinks(tag));
}

function ageHoursAtScore(sourceAt, scoredAt) {
  if (!sourceAt || !scoredAt) return null;
  const sourceMs = Date.parse(sourceAt);
  const scoredMs = Date.parse(scoredAt);
  if (!Number.isFinite(sourceMs) || !Number.isFinite(scoredMs)) return null;
  return Math.round(((scoredMs - sourceMs) / 3_600_000) * 100) / 100;
}

function maxFreshnessTimestamp(values) {
  return values
    .filter((value) => typeof value === 'string' && Number.isFinite(Date.parse(value)))
    .sort((a, b) => Date.parse(b) - Date.parse(a))[0] ?? null;
}

function verifyNoForbiddenPublicKeys({ failures, tag, value, path = 'public release', forbidden = forbiddenPublicKeys }) {
  if (Array.isArray(value)) {
    value.forEach((item, idx) => verifyNoForbiddenPublicKeys({ failures, tag, value: item, path: `${path}[${idx}]`, forbidden }));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, child] of Object.entries(value)) {
    expect(failures, tag, !forbidden.has(key),
      `${path} must not expose internal/comparison key ${key}`);
    verifyNoForbiddenPublicKeys({ failures, tag, value: child, path: `${path}.${key}`, forbidden });
  }
}

function verifyPublicIssueSummaries({ failures, tag, publicRelease }) {
  const issues = Array.isArray(publicRelease.issues) ? publicRelease.issues : [];
  const watchIssues = Array.isArray(publicRelease.watchIssues) ? publicRelease.watchIssues : [];
  for (const [name, rows] of [['issues', issues], ['watchIssues', watchIssues]]) {
    rows.forEach((issue, index) => {
      verifyAllowedKeys({
        failures,
        tag,
        label: `public ${name}[${index}]`,
        value: issue,
        allowed: publicIssueKeys,
      });
      expect(failures, tag, Number.isInteger(issue.number) && issue.number > 0,
        `public ${name}[${index}] must expose a positive issue number`);
      expect(failures, tag, typeof issue.title === 'string' && issue.title.length > 0,
        `public ${name}[${index}] must expose a title`);
      expect(failures, tag, typeof issue.url === 'string' && /^https:\/\/github\.com\//.test(issue.url),
        `public ${name}[${index}] must expose a GitHub URL`);
      expect(failures, tag, typeof issue.affectedUsers === 'string' && publicAffectedUsersRank.has(issue.affectedUsers),
        `public ${name}[${index}] must expose affectedUsers`);
    });
  }
  for (let i = 1; i < issues.length; i++) {
    expect(failures, tag, publicIssueSortKey(issues[i - 1]) <= publicIssueSortKey(issues[i]),
      'public issues must be sorted by effective sentiment/severity/scope');
  }
  expect(failures, tag, issues.length <= 25, 'public issues must stay capped at 25');
  expect(failures, tag, watchIssues.length <= 25, 'public watchIssues must stay capped at 25');
  for (let i = 1; i < watchIssues.length; i++) {
    expect(failures, tag, publicIssueSortKey(watchIssues[i - 1]) <= publicIssueSortKey(watchIssues[i]),
      'public watchIssues must be sorted by effective sentiment/severity/scope');
  }
  for (const issue of watchIssues) {
    expect(failures, tag, issue.state === 'open',
      `public watch issue #${issue.number} must be open`);
    expect(failures, tag, issue.sentiment === 'negative',
      `public watch issue #${issue.number} must be negative`);
    expect(failures, tag, issue.severity === 'critical' || issue.severity === 'high',
      `public watch issue #${issue.number} must be high/critical`);
  }
}

function verifyPublicProfileEvidence({ failures, tag, publicRelease }) {
  const evidence = publicRelease.profileEvidence;
  verifyAllowedKeys({ failures, tag, label: 'public profileEvidence', value: evidence, allowed: publicProfileEvidenceKeys });
  if (!isObject(evidence)) return;
  expect(failures, tag, evidence.schemaVersion === 1,
    `public profileEvidence schemaVersion (${evidence.schemaVersion}) must be 1`);
  expect(failures, tag, evidence.sourceMode === 'audit_issue_evidence',
    `public profileEvidence sourceMode (${evidence.sourceMode}) must be audit_issue_evidence`);
  expect(failures, tag, evidence.issueEvidenceSchemaVersion === issueEvidenceSchemaVersion || evidence.issueEvidenceSchemaVersion == null,
    `public profileEvidence issueEvidenceSchemaVersion (${evidence.issueEvidenceSchemaVersion}) must match issue evidence schema`);
  for (const key of ['issueCount', 'weightedIssueCount', 'surfaceIssueCount']) {
    expect(failures, tag, Number.isInteger(evidence[key]) && evidence[key] >= 0,
      `public profileEvidence ${key} must be a non-negative integer`);
  }
  expect(failures, tag, typeof evidence.surfaceWeight === 'number' && Number.isFinite(evidence.surfaceWeight) && evidence.surfaceWeight >= 0,
    'public profileEvidence surfaceWeight must be a non-negative number');
  expect(failures, tag, Array.isArray(evidence.surfaces),
    'public profileEvidence surfaces must be an array');
  let surfaceWeight = 0;
  for (const [index, surface] of (evidence.surfaces ?? []).entries()) {
    verifyAllowedKeys({ failures, tag, label: `public profileEvidence surfaces[${index}]`, value: surface, allowed: publicProfileEvidenceSurfaceKeys });
    expect(failures, tag, typeof surface.label === 'string' && surface.label.length > 0,
      `public profileEvidence surfaces[${index}] label must be present`);
    expect(failures, tag, typeof surface.icon === 'string' && surface.icon.length > 0,
      `public profileEvidence surfaces[${index}] icon must be present`);
    expect(failures, tag, Number.isInteger(surface.count) && surface.count > 0,
      `public profileEvidence surfaces[${index}] count must be positive`);
    expect(failures, tag, typeof surface.weight === 'number' && Number.isFinite(surface.weight) && surface.weight > 0,
      `public profileEvidence surfaces[${index}] weight must be positive`);
    expect(failures, tag, isObject(surface.tiers), `public profileEvidence surfaces[${index}] tiers must be an object`);
    expect(failures, tag, isObject(surface.weightByTier), `public profileEvidence surfaces[${index}] weightByTier must be an object`);
    surfaceWeight += Number(surface.weight ?? 0);
  }
  expect(failures, tag, Math.abs(Math.round(surfaceWeight * 1000) / 1000 - Number(evidence.surfaceWeight ?? 0)) <= 0.002,
    `public profileEvidence surfaceWeight (${evidence.surfaceWeight}) must equal summed surface weights (${surfaceWeight})`);
}

function publicIssueSortKey(issue) {
  return [
    publicSentimentRank.get(issue.sentiment) ?? 9,
    publicSeverityRank.get(issue.severity) ?? 9,
    publicScopeRank.get(issue.scope) ?? 9,
    publicAffectedUsersRank.get(issue.affectedUsers) ?? 9,
  ].join(':');
}

function verifyProofEvidenceShape({ failures, tag, row, evidence }) {
  expect(failures, tag, isObject(evidence),
    `proof issue #${row.issue_number} evidence_json must parse to an object`);
  if (!isObject(evidence)) return;

  if ('stateReasons' in evidence) {
    expect(failures, tag, isStringArray(evidence.stateReasons),
      `proof issue #${row.issue_number} stateReasons must be a string array`);
  }
  if ('closureEventClosedAt' in evidence) {
    expect(failures, tag, isStringArray(evidence.closureEventClosedAt),
      `proof issue #${row.issue_number} closureEventClosedAt must be a string array when present`);
    if (isStringArray(evidence.closureEventClosedAt) && evidence.closedAt) {
      const issueClosedAtMs = Date.parse(evidence.closedAt);
      for (const closedAt of evidence.closureEventClosedAt) {
        const eventClosedAtMs = Date.parse(closedAt);
        const closeDeltaSeconds = Number.isFinite(issueClosedAtMs) && Number.isFinite(eventClosedAtMs)
          ? Math.abs(issueClosedAtMs - eventClosedAtMs) / 1000
          : Infinity;
        expect(failures, tag, closeDeltaSeconds <= 2,
          `proof issue #${row.issue_number} closure event timestamp ${closedAt} must match issue closedAt ${evidence.closedAt}`);
      }
    }
  }
  for (const flag of ['hasReachableFixCommit', 'hasNotReachableFixCommit']) {
    expect(failures, tag, typeof evidence[flag] === 'boolean',
      `proof issue #${row.issue_number} ${flag} must be boolean`);
  }

  const reachableFixCommits = normalizeStringArray(evidence.reachableFixCommits);
  const notReachableFixCommits = normalizeStringArray(evidence.notReachableFixCommits);
  const fixCommitProof = Array.isArray(evidence.fixCommitProof) ? evidence.fixCommitProof : [];
  const canonicalCommitProof = canonicalFixCommitProof(evidence);

  expect(failures, tag, Array.isArray(evidence.reachableFixCommits),
    `proof issue #${row.issue_number} reachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.notReachableFixCommits),
    `proof issue #${row.issue_number} notReachableFixCommits must be an array`);
  expect(failures, tag, Array.isArray(evidence.fixCommitProof),
    `proof issue #${row.issue_number} fixCommitProof must be an array`);
  if ('canonicalFixCommitProof' in evidence) {
    expect(failures, tag, Array.isArray(evidence.canonicalFixCommitProof),
      `proof issue #${row.issue_number} canonicalFixCommitProof must be an array when present`);
  }

  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'reachableFixCommits', commits: reachableFixCommits });
  verifyCommitArray({ failures, tag, issueNumber: row.issue_number, name: 'notReachableFixCommits', commits: notReachableFixCommits });
  expect(failures, tag, intersection(reachableFixCommits, notReachableFixCommits).length === 0,
    `proof issue #${row.issue_number} reachable and not-reachable fix commit arrays must not overlap`);

  const proofReachable = [];
  const proofNotReachable = [];
  for (const proof of fixCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} fixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} fixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0,
      `proof issue #${row.issue_number} fixCommitProof sourceIssueNumber must be a positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} fixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofSources.has(proof.source),
      `proof issue #${row.issue_number} fixCommitProof has unknown source ${proof.source}`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} fixCommitProof has unknown status ${proof.status}`);
    expect(failures, tag, proof.tagCommitOid == null || (typeof proof.tagCommitOid === 'string' && fullCommitOidRe.test(proof.tagCommitOid)),
      `proof issue #${row.issue_number} fixCommitProof tagCommitOid must be null or full lowercase 40-hex SHA`);
    expect(failures, tag, typeof proof.evidence === 'string' && proof.evidence.length > 0,
      `proof issue #${row.issue_number} fixCommitProof evidence must be present`);
    expect(failures, tag, typeof proof.snippet === 'string' && proof.snippet.length > 0,
      `proof issue #${row.issue_number} fixCommitProof snippet must be present`);
    if (proof.source === 'ClosureComment.fixProof') {
      expect(failures, tag, proof.trustedSource === true,
        `proof issue #${row.issue_number} closure-comment commit proof must come from a trusted source`);
      expect(failures, tag, typeof proof.author === 'string' && proof.author.length > 0,
        `proof issue #${row.issue_number} closure-comment commit proof must record an author`);
    }
    if (proof.status === 'reachable' && typeof proof.commitOid === 'string') proofReachable.push(proof.commitOid);
    if (proof.status === 'not_reachable' && typeof proof.commitOid === 'string') proofNotReachable.push(proof.commitOid);
  }
  for (const proof of canonicalCommitProof) {
    expect(failures, tag, isObject(proof),
      `proof issue #${row.issue_number} canonicalFixCommitProof entries must be objects`);
    if (!isObject(proof)) continue;
    expect(failures, tag, proof.issueNumber === row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof issueNumber (${proof.issueNumber}) must match proof row`);
    expect(failures, tag, Number.isInteger(proof.sourceIssueNumber) && proof.sourceIssueNumber > 0 && proof.sourceIssueNumber !== row.issue_number,
      `proof issue #${row.issue_number} canonicalFixCommitProof sourceIssueNumber must be a different positive integer`);
    expect(failures, tag, typeof proof.commitOid === 'string' && fullCommitOidRe.test(proof.commitOid),
      `proof issue #${row.issue_number} canonicalFixCommitProof commitOid must be a full lowercase 40-hex SHA`);
    expect(failures, tag, knownCommitProofStatuses.has(proof.status),
      `proof issue #${row.issue_number} canonicalFixCommitProof has unknown status ${proof.status}`);
  }

  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} reachableFixCommits`, reachableFixCommits, uniqueSorted(proofReachable));
  expectArrayEqual(failures, tag, `proof issue #${row.issue_number} notReachableFixCommits`, notReachableFixCommits, uniqueSorted(proofNotReachable));
  expect(failures, tag, evidence.hasReachableFixCommit === (reachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasReachableFixCommit must match reachableFixCommits`);
  expect(failures, tag, evidence.hasNotReachableFixCommit === (notReachableFixCommits.length > 0),
    `proof issue #${row.issue_number} hasNotReachableFixCommit must match notReachableFixCommits`);
}

function canonicalFixCommitProof(evidence) {
  return Array.isArray(evidence?.canonicalFixCommitProof) ? evidence.canonicalFixCommitProof : [];
}

function linkedClosingPrEvidence(evidence) {
  const linkedPrs = Array.isArray(evidence?.linkedPrs) ? evidence.linkedPrs : [];
  return linkedPrs.filter((pr) => {
    const source = String(pr?.source ?? '');
    return Number(pr?.willCloseTarget ?? 0) === 1 ||
      source === 'closedByPullRequestsReferences' ||
      source === 'ClosedEvent.closer';
  });
}

function linkedMergedPrEvidence(evidence) {
  const linkedPrs = Array.isArray(evidence?.linkedPrs) ? evidence.linkedPrs : [];
  return linkedPrs.filter((pr) => Number(pr?.merged ?? 0) === 1);
}

function relatedPrContext(evidence) {
  const context = evidence?.relatedPrContext && typeof evidence.relatedPrContext === 'object'
    ? evidence.relatedPrContext
    : {};
  return {
    externalClosing: Array.isArray(context.externalClosing) ? context.externalClosing : [],
    open: Array.isArray(context.open) ? context.open : [],
    closedUnmerged: Array.isArray(context.closedUnmerged) ? context.closedUnmerged : [],
    notReachable: Array.isArray(context.notReachable) ? context.notReachable : [],
    reachable: Array.isArray(context.reachable) ? context.reachable : [],
    unknownReachability: Array.isArray(context.unknownReachability) ? context.unknownReachability : [],
  };
}

function trustedReachableFixProofPrs(evidence) {
  return relatedPrContext(evidence).reachable.filter((pr) =>
    String(pr?.source ?? '') === 'ClosureComment.fixProof' &&
    String(pr?.repositoryNameWithOwner ?? '').toLowerCase() === 'openclaw/openclaw');
}

function canonicalFixedAfterRelease(evidence) {
  const terminalProof = evidence?.canonicalResolution?.terminalProof;
  return terminalProof?.status === 'fixed_after_release' ||
    (terminalProof?.crossRelease === true &&
      terminalProof?.timing === 'after' &&
      ['fixed_in_release', 'fixed_after_release'].includes(terminalProof?.status)) ||
    canonicalFixCommitProof(evidence).some((proof) => proof.status === 'not_reachable');
}

function verifyAfterLatestFixProof({ failures, tag, row, evidence, latestScoredStableRelease }) {
  const proof = evidence?.unscoredFixProof;
  expect(failures, tag, proof?.latestScoredReleaseTag === latestScoredStableRelease?.tag,
    `${row.status} issue #${row.issue_number} must name latest scored stable release ${latestScoredStableRelease?.tag ?? 'unknown'}`);
  const proofMs = proof?.proofTime ? Date.parse(proof.proofTime) : NaN;
  const latestPublishedMs = proof?.latestScoredReleasePublishedAt ? Date.parse(proof.latestScoredReleasePublishedAt) : NaN;
  expect(failures, tag, Number.isFinite(proofMs) && Number.isFinite(latestPublishedMs) && proofMs > latestPublishedMs,
    `${row.status} issue #${row.issue_number} must have proofTime after latest scored stable published_at`);
  expect(failures, tag, proof?.proofType === 'pr' ? Number.isInteger(Number(proof.prNumber)) && Number(proof.prNumber) > 0 : fullCommitOidRe.test(String(proof?.commitOid ?? '')),
    `${row.status} issue #${row.issue_number} must include a PR number or full commit OID for after-latest proof`);
  expect(failures, tag, evidence.hasNotReachableClosingPr === true || evidence.hasNotReachableFixCommit === true,
    `${row.status} issue #${row.issue_number} must include not-reachable PR or commit evidence`);
}

function expectNonNegativeProof({ failures, tag, row }) {
  const classification = effectiveClassificationForProofRow(row);
  expect(failures, tag, classification.sentiment !== 'negative',
    `${row.status} issue #${row.issue_number} must not be effectively negative`);
}

function verifyCommitArray({ failures, tag, issueNumber, name, commits }) {
  for (const commit of commits) {
    expect(failures, tag, fullCommitOidRe.test(commit),
      `proof issue #${issueNumber} ${name} entries must be full lowercase 40-hex SHAs`);
  }
  expectArrayEqual(failures, tag, `proof issue #${issueNumber} ${name}`, commits, uniqueSorted(commits));
}

function parseJson(raw, fallback) {
  try {
    return raw ? JSON.parse(raw) : fallback;
  } catch {
    return fallback;
  }
}

function riskDispositionForStatus(status) {
  return riskDispositionByProofStatus.get(status) ?? 'missing_evidence';
}

function riskDispositionCountsForProofRows(proofRows) {
  const counts = {};
  for (const row of proofRows) {
    const disposition = riskDispositionForStatus(row.status);
    counts[disposition] = (counts[disposition] ?? 0) + 1;
  }
  return counts;
}

function riskSummaryFromCounts(counts, neutralAuditCounts = { highImpact: 0, bugShaped: 0 }) {
  const summary = {
    creditedReleaseFixCount: counts.credited_release_fix ?? 0,
    resolvedByCanonicalReleaseFixCount: counts.resolved_by_canonical_release_fix ?? 0,
    resolvedByReleaseFixProofCount: counts.resolved_by_release_fix_proof ?? 0,
    knownNotInReleaseCount: counts.known_not_in_release ?? 0,
    openCanonicalRiskCount: counts.open_canonical_risk ?? 0,
    unsupportedClosureClaimCount: counts.unsupported_closure_claim ?? 0,
    neutralOrNonActionableCount: counts.neutral_or_non_actionable ?? 0,
    neutralHighImpactCount: neutralAuditCounts.highImpact ?? 0,
    neutralBugShapedCount: neutralAuditCounts.bugShaped ?? 0,
    missingEvidenceCount: counts.missing_evidence ?? 0,
  };
  return {
    ...summary,
    unresolvedForReleaseCount: summary.knownNotInReleaseCount +
      summary.openCanonicalRiskCount +
      summary.unsupportedClosureClaimCount +
      summary.missingEvidenceCount,
    unresolvedWeightedRisk: 0,
    weightedRiskByDisposition: {},
  };
}

function riskSummaryForProofRows(proofRows) {
  const counts = riskDispositionCountsForProofRows(proofRows);
  const neutralAuditCounts = neutralAuditSignalCountsForProofRows(proofRows);
  const summary = riskSummaryFromCounts(counts, neutralAuditCounts);
  const byDisposition = {};
  for (const row of proofRows) {
    const disposition = riskDispositionForStatus(row.status);
    const weight = closureRiskWeightForProofRow(row);
    if (weight <= 0) continue;
    byDisposition[disposition] = (byDisposition[disposition] ?? 0) + weight;
  }
  return {
    counts,
    summary: {
      ...summary,
      unresolvedWeightedRisk: roundMetric(Object.values(byDisposition).reduce((sum, value) => sum + Number(value ?? 0), 0)),
      weightedRiskByDisposition: roundRiskMap(byDisposition),
    },
  };
}

function neutralAuditSignalCountsForProofRows(proofRows) {
  let highImpact = 0;
  let bugShaped = 0;
  for (const row of proofRows) {
    if (riskDispositionForStatus(row.status) !== 'neutral_or_non_actionable') continue;
    const classification = effectiveClassificationForProofRow(row);
    if (classification.sentiment !== 'neutral') continue;
    if (classification.severity === 'high' || classification.severity === 'critical') highImpact++;
    if (bugShapedTitleRe.test(row.title ?? '')) bugShaped++;
  }
  return { highImpact, bugShaped };
}

function closureRiskWeightForProofRow(row) {
  const disposition = riskDispositionForStatus(row.status);
  const dispositionWeight = riskDispositionWeights.get(disposition) ?? 0;
  if (dispositionWeight <= 0) return 0;
  const classification = effectiveClassificationForProofRow(row);
  if (classification.sentiment !== 'negative') return 0;
  const severity = severityRiskWeights.get(classification.severity) ?? 0;
  const functionality = functionalityRiskWeights.get(classification.functionality) ?? 0;
  if (severity <= 0 || functionality <= 0) return 0;
  return dispositionWeight *
    severity *
    functionality *
    (scopeRiskWeights.get(classification.scope) ?? 1) *
    (affectedUserRiskWeights.get(classification.affectedUsers ?? 'unknown') ?? affectedUserRiskWeights.get('unknown'));
}

function effectiveClassificationForProofRow(row) {
  const labels = Array.isArray(row.effective_labels)
    ? row.effective_labels.filter((label) => typeof label === 'string')
    : [];
  return applyClosureRiskSentimentHint(
    applyTitleIssueShapeHint(
      applyLabelOverrides(
        applyTitleFunctionalityHint(rawClassificationForProofRow(row), row.title ?? ''),
        labels,
      ),
      row.title ?? '',
      labels,
    ),
    row.title ?? '',
    labels,
  );
}

function rawClassificationForProofRow(row) {
  const workaroundStatus = ['none', 'partial', 'confirmed', 'unknown'].includes(row.workaround_status ?? '')
    ? row.workaround_status
    : row.has_workaround === 1
      ? 'confirmed'
      : 'unknown';
  return {
    sentiment: row.sentiment,
    severity: row.severity,
    scope: row.scope,
    functionality: row.functionality,
    affectedUsers: row.affected_users,
    workaroundStatus,
    duplicateCluster: row.duplicate_cluster ?? null,
    affectsVersion: row.affects_version ?? null,
    confidence: typeof row.confidence === 'number' ? row.confidence : 0.5,
    rationale: row.rationale ?? '',
  };
}

function roundRiskMap(map) {
  const rounded = {};
  for (const [key, value] of Object.entries(map)) {
    const roundedValue = roundMetric(Number(value ?? 0));
    if (roundedValue > 0) rounded[key] = roundedValue;
  }
  return rounded;
}

function roundMetric(value) {
  return Math.round(Number(value ?? 0) * 1000) / 1000;
}

function expect(failures, tag, condition, message) {
  if (!condition) failures.push(`${tag}: ${message}`);
}

function verifyRecommendedReleaseInvariant({ failures, releases }) {
  const actualRecommendedTags = releases
    .filter((release) => release.recommended === true || Number(release.recommended ?? 0) === 1)
    .map((release) => release.tag);
  const expectedRecommendedTag = releases.find((release) =>
    String(release.state ?? release.status ?? '') === 'eligible' &&
    releaseScoreValue(release) != null &&
    Number(releaseScoreValue(release)) >= REC_THRESHOLD)?.tag ?? null;
  const expectedRecommendedTags = expectedRecommendedTag ? [expectedRecommendedTag] : [];
  expect(failures, 'recommendation', stableJson(actualRecommendedTags) === stableJson(expectedRecommendedTags),
    `recommended release tags (${JSON.stringify(actualRecommendedTags)}) must equal newest eligible score >= ${REC_THRESHOLD} (${JSON.stringify(expectedRecommendedTags)})`);
}

function releaseScoreValue(release) {
  const value = release.final_score ?? release.score ?? null;
  return typeof value === 'number' && Number.isFinite(value) ? value : null;
}

function expectArrayEqual(failures, tag, label, actual, expected) {
  expect(failures, tag, actual.length === expected.length && actual.every((item, idx) => item === expected[idx]),
    `${label} must equal sorted unique proof commits; got ${JSON.stringify(actual)}, expected ${JSON.stringify(expected)}`);
}

function expectJsonEqual(failures, tag, message, actual, expected) {
  expect(failures, tag, stableJson(actual) === stableJson(expected), message);
}

function stableJson(value) {
  return JSON.stringify(sortJson(value));
}

function sortJson(value) {
  if (Array.isArray(value)) return value.map(sortJson);
  if (!isObject(value)) return value;
  return Object.fromEntries(Object.keys(value).sort().map((key) => [key, sortJson(value[key])]));
}

function isObject(value) {
  return !!value && typeof value === 'object' && !Array.isArray(value);
}

function isStringArray(value) {
  return Array.isArray(value) && value.every((item) => typeof item === 'string');
}

function normalizeStringArray(value) {
  return Array.isArray(value) ? value.filter((item) => typeof item === 'string') : [];
}

function uniqueSorted(values) {
  return [...new Set(values)].sort();
}

function intersection(left, right) {
  const rightSet = new Set(right);
  return left.filter((item) => rightSet.has(item));
}

const concreteNonActionableRationaleRe =
  /\b(won't fix|wont fix|expected behavior|working as intended|by design|outside\s+(?:the\s+)?OpenClaw\s+source|outside\s+(?:the\s+)?(?:repo|repository)|repo(?:sitory)?\s+boundary|plugin-owned|not\s+present\s+in\s+(?:the\s+)?OpenClaw\s+source|not\s+actionable|out\s+of\s+scope|unsupported)\b/i;

function isNegativeBareNotPlannedNeutral(row, evidence) {
  if (riskDispositionForStatus(row.status) !== 'neutral_or_non_actionable') return false;
  if (row.status !== 'not_planned') return false;
  const classification = effectiveClassificationForProofRow(row);
  if (classification.sentiment !== 'negative') return false;
  if (!Array.isArray(evidence.stateReasons) || !evidence.stateReasons.includes('NOT_PLANNED')) return false;
  return !hasConcreteNonActionableRationale(evidence);
}

function hasConcreteNonActionableRationale(evidence) {
  if (Array.isArray(evidence.nonActionableRationaleComments) && evidence.nonActionableRationaleComments.length > 0) {
    return true;
  }
  const comments = Array.isArray(evidence.matchingComments) ? evidence.matchingComments : [];
  return comments.some((comment) => concreteNonActionableRationaleRe.test(String(comment?.snippet ?? '')));
}

async function verifyApi({ apiBase, fetchJson, reader, releases, failures }) {
  const status = await fetchJson(`${apiBase}/api/status`);
  expect(failures, 'api/status', status.schemaVersion === statusPayloadSchemaVersion,
    `status schemaVersion must be ${statusPayloadSchemaVersion}, got ${JSON.stringify(status.schemaVersion)}`);
  expect(failures, 'api/status', status.refreshing === false, `refreshing must be false, got ${status.refreshing}`);
  expect(failures, 'api/status', status.lastError == null, `lastError must be null, got ${status.lastError}`);
  expect(failures, 'api/status', status.lastScoredAt == null || Number.isFinite(Date.parse(status.lastScoredAt)),
    `lastScoredAt must be null or a valid timestamp, got ${status.lastScoredAt}`);
  expect(failures, 'api/status', status.lastRefreshAt == null || status.lastRefreshAt === status.processLastRefreshAt,
    `lastRefreshAt (${status.lastRefreshAt}) must match processLastRefreshAt (${status.processLastRefreshAt})`);
  expect(failures, 'api/status', status.processLastRefreshAt == null || Number.isFinite(Date.parse(status.processLastRefreshAt)),
    `processLastRefreshAt must be null or a valid timestamp, got ${status.processLastRefreshAt}`);
  if (status.dataFreshness) {
    verifyDataFreshness({ failures, tag: 'api/status', dataFreshness: status.dataFreshness, releaseTag: status.dataFreshness.tag });
  }

  const configPayload = await fetchJson(`${apiBase}/api/config`);
  expect(failures, 'api/config', configPayload.schemaVersion === configPayloadSchemaVersion,
    `config schemaVersion must be ${configPayloadSchemaVersion}, got ${JSON.stringify(configPayload.schemaVersion)}`);
  expect(failures, 'api/config', Number.isInteger(configPayload.releases) && configPayload.releases > 0,
    'config releases must be a positive integer');
  expect(failures, 'api/config', Number.isInteger(configPayload.refreshMinutes) && configPayload.refreshMinutes >= 0,
    'config refreshMinutes must be a non-negative integer; 0 means periodic refresh is disabled');

  const publicPayload = await fetchJson(`${apiBase}/api/public`);
  verifyAllowedKeys({ failures, tag: 'api/public', label: 'public top-level', value: publicPayload, allowed: publicTopLevelKeys });
  expect(failures, 'api/public', publicPayload.schemaVersion === publicPayloadSchemaVersion,
    `public schemaVersion must be ${publicPayloadSchemaVersion}, got ${JSON.stringify(publicPayload.schemaVersion)}`);
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('comparison'), 'public payload must not include comparison data');
  expect(failures, 'api/public', !JSON.stringify(publicPayload).includes('upstream'), 'public payload must not include upstream data');
  if (status.lastScoredAt) {
    expect(failures, 'api/public', publicPayload.updatedAt === status.lastScoredAt,
      `public updatedAt (${publicPayload.updatedAt}) must equal status lastScoredAt (${status.lastScoredAt})`);
  }

  const releasesPayload = await fetchJson(`${apiBase}/api/releases`);
  const releaseApiByTag = new Map((Array.isArray(releasesPayload) ? releasesPayload : []).map((release) => [release.tag, release]));
  const historyPayload = await fetchJson(`${apiBase}/api/releases/history`);
  expect(failures, 'api/releases/history', Array.isArray(historyPayload), 'history payload must be an array');
  for (const row of historyPayload ?? []) {
    verifyAllowedKeys({ failures, tag: row?.tag ?? 'api/releases/history', label: 'history row', value: row, allowed: releaseHistoryRowKeys });
    expect(failures, row?.tag ?? 'api/releases/history', row.schemaVersion === releaseHistoryRowSchemaVersion,
      `history row schemaVersion must be ${releaseHistoryRowSchemaVersion}, got ${JSON.stringify(row?.schemaVersion)}`);
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.tag === 'string' && row.tag.length > 0,
      'history row tag must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.publishedAt === 'string' && row.publishedAt.length > 0,
      'history row publishedAt must be present');
    expect(failures, row?.tag ?? 'api/releases/history', row.finalScore == null || typeof row.finalScore === 'number',
      'history row finalScore must be numeric or null');
    expect(failures, row?.tag ?? 'api/releases/history', row.scoredAt == null || typeof row.scoredAt === 'string',
      'history row scoredAt must be string or null');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.status === 'string' && row.status.length > 0,
      'history row status must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.band === 'string' && row.band.length > 0,
      'history row band must be present');
    expect(failures, row?.tag ?? 'api/releases/history', typeof row.recommended === 'boolean',
      'history row recommended must be boolean');
    verifyAuditLinks({ failures, tag: row?.tag ?? 'api/releases/history', label: 'history row auditLinks', auditLinks: row.auditLinks });
    const releaseApi = releaseApiByTag.get(row.tag);
    if (releaseApi) {
      expectJsonEqual(failures, row.tag, 'history row scoreAudit must match releases row scoreAudit',
        row.scoreAudit, releaseApi.scoreAudit);
      expectJsonEqual(failures, row.tag, 'history row dataFreshness must match releases row dataFreshness',
        row.dataFreshness, releaseApi.dataFreshness);
      expect(failures, row.tag, row.scoredAt === releaseApi.scoredAt,
        `history scoredAt (${row.scoredAt}) must match releases scoredAt (${releaseApi.scoredAt})`);
      expect(failures, row.tag, row.finalScore === releaseApi.finalScore,
        `history finalScore (${row.finalScore}) must match releases finalScore (${releaseApi.finalScore})`);
      expect(failures, row.tag, row.status === releaseApi.status,
        `history status (${row.status}) must match releases status (${releaseApi.status})`);
      expect(failures, row.tag, row.band === releaseApi.band,
        `history band (${row.band}) must match releases band (${releaseApi.band})`);
      expect(failures, row.tag, row.recommended === releaseApi.recommended,
        `history recommended (${row.recommended}) must match releases recommended (${releaseApi.recommended})`);
    } else {
      verifyScoreAuditSummary({ failures, tag: row.tag, summary: row.scoreAudit });
      verifyDataFreshness({ failures, tag: row.tag, dataFreshness: row.dataFreshness, releaseTag: row.tag, scoredAt: row.scoredAt });
    }
  }
  const publicByTag = new Map((publicPayload.releases ?? []).map((release) => [release.tag, release]));
  for (const release of publicPayload.releases ?? []) {
    verifyAllowedKeys({ failures, tag: release.tag ?? 'api/public', label: 'public release', value: release, allowed: publicReleaseKeys });
    verifyNoForbiddenPublicKeys({ failures, tag: release.tag ?? 'api/public', value: release });
    expect(failures, release.tag ?? 'api/public', release.schemaVersion === publicReleaseSchemaVersion,
      `public release schemaVersion must be ${publicReleaseSchemaVersion}, got ${JSON.stringify(release.schemaVersion)}`);
    verifyAuditLinks({ failures, tag: release.tag ?? 'api/public', label: 'public release auditLinks', auditLinks: release.auditLinks });
  }
  const comparisonPayload = await fetchOptionalComparisonPayload({ apiBase, fetchJson, failures });
  if (comparisonPayload) {
    verifyAllowedKeys({ failures, tag: 'api/comparison', label: 'comparison payload', value: comparisonPayload, allowed: comparisonPayloadKeys });
    expect(failures, 'api/comparison', comparisonPayload.schemaVersion === comparisonPayloadSchemaVersion,
      `comparison schemaVersion must be ${comparisonPayloadSchemaVersion}, got ${JSON.stringify(comparisonPayload.schemaVersion)}`);
    verifyComparisonSnapshot({ failures, label: 'api/comparison', snapshot: comparisonPayload.snapshot });
  }
  const comparisonByTag = new Map((comparisonPayload?.releases ?? []).map((release) => [release.tag, release]));

  for (const release of releases) {
    const releaseApi = releaseApiByTag.get(release.tag);
    expect(failures, release.tag, !!releaseApi, 'releases API must include monitored release');
    if (releaseApi) {
      verifyAllowedKeys({ failures, tag: release.tag, label: 'releases row', value: releaseApi, allowed: releaseRowKeys });
      expect(failures, release.tag, releaseApi.schemaVersion === releaseRowSchemaVersion,
        `releases row schemaVersion must be ${releaseRowSchemaVersion}, got ${JSON.stringify(releaseApi.schemaVersion)}`);
      verifyAuditLinks({ failures, tag: release.tag, label: 'releases row auditLinks', auditLinks: releaseApi.auditLinks });
      expect(failures, release.tag, releaseApi.finalScore === release.final_score,
        `releases finalScore (${releaseApi.finalScore}) must match DB final_score (${release.final_score})`);
      expect(failures, release.tag, releaseApi.status === release.state,
        `releases status (${releaseApi.status}) must match DB state (${release.state})`);
      expect(failures, release.tag, releaseApi.reason === release.score_reason,
        `releases reason (${releaseApi.reason}) must match DB score_reason (${release.score_reason})`);
      expect(failures, release.tag, releaseApi.negativeIssues === release.negative_issues,
        `releases negativeIssues (${releaseApi.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
      expect(failures, release.tag, releaseApi.positiveIssues === release.positive_issues,
        `releases positiveIssues (${releaseApi.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
      expect(failures, release.tag, releaseApi.recommended === (release.recommended === 1),
        `releases recommended (${releaseApi.recommended}) must match DB recommended (${release.recommended === 1})`);
      expect(failures, release.tag, releaseApi.scoredAt === release.scored_at,
        `releases scoredAt (${releaseApi.scoredAt}) must match DB scored_at (${release.scored_at})`);
      verifyScoreAuditSummary({ failures, tag: release.tag, summary: releaseApi.scoreAudit });
      verifyDataFreshness({ failures, tag: release.tag, dataFreshness: releaseApi.dataFreshness, releaseTag: release.tag, scoredAt: release.scored_at });
      verifyScoreExplanation({
        failures,
        tag: release.tag,
        explanation: releaseApi.explanation,
        recommended: release.recommended === 1,
        expectedBand: releaseApi.band,
        source: 'releases',
      });
    }

    const publicRelease = publicByTag.get(release.tag);
    expect(failures, release.tag, !!publicRelease, 'public API must include monitored release');
    if (publicRelease) {
      expect(failures, release.tag, publicRelease.score === release.final_score,
        `public score (${publicRelease.score}) must match DB final_score (${release.final_score})`);
      expect(failures, release.tag, publicRelease.status === release.state,
        `public status (${publicRelease.status}) must match DB state (${release.state})`);
      expect(failures, release.tag, publicRelease.reason === release.score_reason,
        `public reason (${publicRelease.reason}) must match DB score_reason (${release.score_reason})`);
      expect(failures, release.tag, publicRelease.negativeIssues === Number(release.negative_issues ?? 0),
        `public negativeIssues (${publicRelease.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
      expect(failures, release.tag, publicRelease.positiveIssues === Number(release.positive_issues ?? 0),
        `public positiveIssues (${publicRelease.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
      expect(failures, release.tag, publicRelease.recommended === (release.recommended === 1),
        `public recommended (${publicRelease.recommended}) must match DB recommended (${release.recommended === 1})`);
      expect(failures, release.tag, publicRelease.scoredAt === release.scored_at,
        `public scoredAt (${publicRelease.scoredAt}) must match DB scored_at (${release.scored_at})`);
      verifyScoreAuditSummary({ failures, tag: release.tag, summary: publicRelease.scoreAudit });
      verifyDataFreshness({ failures, tag: release.tag, dataFreshness: publicRelease.dataFreshness, releaseTag: release.tag, scoredAt: release.scored_at });
      expect(failures, release.tag, publicRelease.totalAttributedIssues === publicRelease.scoreAudit?.rawIssueCount,
        `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match scoreAudit rawIssueCount (${publicRelease.scoreAudit?.rawIssueCount})`);
      if (typeof reader.issueNumbersForVersion === 'function') {
        const issueUniverse = reader.issueNumbersForVersion(release.tag);
        const issueNumbers = new Set(issueUniverse);
        const expectedIssueCount = Math.min(25, issueUniverse.length);
        const actualIssueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
        expect(failures, release.tag, actualIssueCount === expectedIssueCount,
          `public issues length (${actualIssueCount}) must equal capped issue universe count (${expectedIssueCount})`);
        for (const issue of publicRelease.issues ?? []) {
          expect(failures, release.tag, issueNumbers.has(issue.number),
            `public issue #${issue.number} must belong to release issue universe`);
        }
        if (typeof reader.issuesForVersion === 'function') {
          const releaseIssues = reader.issuesForVersion(release.tag);
          const labelCutoff = publicRelease.dataFreshness?.labelCutoffAt ?? null;
          const expectedIssues = publicIssueSummariesForRelease({
            issues: releaseIssues,
            openedIssues: reader.openedDuringReign?.(release.tag) ?? [],
            labelCutoff,
            labelsForIssue: (issueNumber, fallbackLabels, cutoff, options) =>
              reader.labelsForIssueAt(issueNumber, fallbackLabels, cutoff, options),
          });
          expectArrayEqual(
            failures,
            release.tag,
            'public issues',
            (publicRelease.issues ?? []).map((issue) => issue.number),
            expectedIssues.topIssues.map((issue) => issue.number),
          );
          expectArrayEqual(
            failures,
            release.tag,
            'public watchIssues',
            (publicRelease.watchIssues ?? []).map((issue) => issue.number),
            expectedIssues.watchIssues.map((issue) => issue.number),
          );
        }
      } else if (publicRelease.totalAttributedIssues > 0) {
        const issueCount = Array.isArray(publicRelease.issues) ? publicRelease.issues.length : 0;
        expect(failures, release.tag, issueCount > 0,
          'public release with attributed issues must expose capped issue summaries');
      }
      verifyPublicProfileEvidence({ failures, tag: release.tag, publicRelease });
      verifyPublicIssueSummaries({ failures, tag: release.tag, publicRelease });
      verifyScoreExplanation({
        failures,
        tag: release.tag,
        explanation: publicRelease.explanation,
        recommended: release.recommended === 1,
        expectedBand: publicRelease.band,
        source: 'public',
      });
    }

    const comparison = comparisonByTag.get(release.tag);
    if (comparisonPayload) {
      verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison release row', value: comparison, allowed: comparisonReleaseKeys });
      expect(failures, release.tag, !!comparison?.local && 'upstream' in comparison && !!comparison?.delta,
        'comparison payload must include local, upstream, and delta objects');
      if (comparison?.local) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison local', value: comparison.local, allowed: comparisonLocalKeys });
      }
      if (comparison?.upstream) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison upstream', value: comparison.upstream, allowed: comparisonUpstreamKeys });
        expect(failures, release.tag, comparison.upstream.schemaVersion === comparisonUpstreamSchemaVersion,
          `comparison upstream schemaVersion (${comparison.upstream.schemaVersion}) must equal ${comparisonUpstreamSchemaVersion}`);
      }
      if (comparison?.delta) {
        verifyAllowedKeys({ failures, tag: release.tag, label: 'comparison delta', value: comparison.delta, allowed: comparisonDeltaKeys });
        expect(failures, release.tag, comparison.delta.schemaVersion === comparisonDeltaSchemaVersion,
          `comparison delta schemaVersion (${comparison.delta.schemaVersion}) must equal ${comparisonDeltaSchemaVersion}`);
      }
    }

    const review = await fetchJson(`${apiBase}/api/releases/${encodeURIComponent(release.tag)}/review`);
    const persistedAuditForReview = reader.getReleaseScoreAudit(release.tag);
    const persistedInput = parseJson(persistedAuditForReview?.input_json, null);
    const persistedComponents = parseJson(persistedAuditForReview?.components_json, null);
    const persistedIssueEvidence = parseJson(persistedAuditForReview?.issue_evidence_json, null);
    const persistedGateEvidence = parseJson(persistedAuditForReview?.gate_evidence_json, null);
    verifyNoForbiddenPublicKeys({
      failures,
      tag: release.tag,
      value: review,
      path: 'review payload',
      forbidden: forbiddenReviewComparisonKeys,
    });
    verifyAllowedKeys({ failures, tag: release.tag, label: 'review payload', value: review, allowed: reviewPayloadKeys });
    verifyAllowedKeys({ failures, tag: release.tag, label: 'review local', value: review.local, allowed: reviewLocalKeys });
    expect(failures, release.tag, review.tag === release.tag,
      `review tag (${review.tag}) must match DB tag (${release.tag})`);
    expect(failures, release.tag, review.local?.schemaVersion === localAuditSchemaVersion,
      `review local schemaVersion (${review.local?.schemaVersion}) must equal ${localAuditSchemaVersion}`);
    expect(failures, release.tag, review.local?.score === release.final_score,
      `review score (${review.local?.score}) must match DB final_score (${release.final_score})`);
    expect(failures, release.tag, review.local?.status === release.state,
      `review status (${review.local?.status}) must match DB state (${release.state})`);
    expect(failures, release.tag, review.local?.reason === release.score_reason,
      `review reason (${review.local?.reason}) must match DB score_reason (${release.score_reason})`);
    expect(failures, release.tag, review.local?.negativeIssues === release.negative_issues,
      `review negativeIssues (${review.local?.negativeIssues}) must match DB negative_issues (${release.negative_issues})`);
    expect(failures, release.tag, review.local?.positiveIssues === release.positive_issues,
      `review positiveIssues (${review.local?.positiveIssues}) must match DB positive_issues (${release.positive_issues})`);
    expect(failures, release.tag, review.local?.recommended === (release.recommended === 1),
      `review recommended (${review.local?.recommended}) must match DB recommended (${release.recommended === 1})`);
    expect(failures, release.tag, review.local?.scoredAt === release.scored_at,
      `review scoredAt (${review.local?.scoredAt}) must match DB scored_at (${release.scored_at})`);
    verifyDataFreshness({ failures, tag: release.tag, dataFreshness: review.local?.dataFreshness, releaseTag: release.tag, scoredAt: release.scored_at });
    verifyReviewSourceProvenance({
      failures,
      tag: release.tag,
      sourceProvenance: review.local?.sourceProvenance,
      dataFreshness: review.local?.dataFreshness,
      scoredAt: release.scored_at,
    });
    if (releaseApi) {
      expect(failures, release.tag, releaseApi.band === review.local?.band,
        `releases band (${releaseApi.band}) must match review band (${review.local?.band})`);
    }
    expect(failures, release.tag, review.local?.input?.schemaVersion === scoreInputSchemaVersion,
      `review score input schemaVersion (${review.local?.input?.schemaVersion}) must equal ${scoreInputSchemaVersion}`);
    expect(failures, release.tag, review.local?.components?.schemaVersion === scoreComponentsSchemaVersion,
      `review score components schemaVersion (${review.local?.components?.schemaVersion}) must equal ${scoreComponentsSchemaVersion}`);
    expect(failures, release.tag, review.local?.gateEvidence?.schemaVersion === gateEvidenceSchemaVersion,
      `review gateEvidence schemaVersion (${review.local?.gateEvidence?.schemaVersion}) must equal ${gateEvidenceSchemaVersion}`);
    expect(failures, release.tag, review.local?.issueEvidence?.schemaVersion === issueEvidenceSchemaVersion,
      `review issueEvidence schemaVersion (${review.local?.issueEvidence?.schemaVersion}) must equal ${issueEvidenceSchemaVersion}`);
    expectJsonEqual(failures, release.tag, 'review input must match persisted audit input',
      review.local?.input, persistedInput);
    expectJsonEqual(failures, release.tag, 'review components must match persisted audit components',
      review.local?.components, persistedComponents);
    expectJsonEqual(failures, release.tag, 'review issueEvidence must match persisted audit issueEvidence',
      review.local?.issueEvidence, persistedIssueEvidence);
    expectJsonEqual(failures, release.tag, 'review gateEvidence must match persisted audit gateEvidence',
      review.local?.gateEvidence, persistedGateEvidence);
    await verifyIssueEvidenceAuditEndpoint({
      apiBase,
      fetchJson,
      failures,
      reader,
      tag: release.tag,
      issueEvidence: review.local?.issueEvidence,
      scoredAt: release.scored_at,
    });
    verifyReleaseChecksGate({
      failures,
      tag: release.tag,
      releaseChecks: review.local?.gateEvidence?.releaseChecks,
    });
    verifyArtifactVerificationGate({
      failures,
      tag: release.tag,
      artifactVerification: review.local?.gateEvidence?.artifactVerification,
    });
    if (publicRelease) {
      expect(failures, release.tag, publicRelease.band === review.local?.band,
        `public band (${publicRelease.band}) must match review band (${review.local?.band})`);
      expect(failures, release.tag, publicRelease.totalAttributedIssues === review.local?.input?.rawIssueCount,
        `public totalAttributedIssues (${publicRelease.totalAttributedIssues}) must match review rawIssueCount (${review.local?.input?.rawIssueCount})`);
    }
    verifyScoreExplanation({
      failures,
      tag: release.tag,
      explanation: review.local?.components?.explanation,
      recommended: release.recommended === 1,
      expectedBand: review.local?.band,
      source: 'review',
    });
    if (releaseApi) {
      expectJsonEqual(failures, release.tag, 'releases explanation must match review explanation',
        releaseApi.explanation, review.local?.components?.explanation);
    }
    if (publicRelease) {
      expectJsonEqual(failures, release.tag, 'public explanation must match review explanation',
        publicRelease.explanation, review.local?.components?.explanation);
    }
    if (comparison?.local) {
      expect(failures, release.tag, comparison.local.schemaVersion === localAuditSchemaVersion,
        `comparison local schemaVersion (${comparison.local.schemaVersion}) must equal ${localAuditSchemaVersion}`);
      for (const [field, expected] of Object.entries({
        score: review.local?.score,
        band: review.local?.band,
        status: review.local?.status,
        recommended: review.local?.recommended,
        reason: review.local?.reason,
        negativeIssues: review.local?.negativeIssues,
        positiveIssues: review.local?.positiveIssues,
        scoredAt: review.local?.scoredAt,
      })) {
        expect(failures, release.tag, comparison.local[field] === expected,
          `comparison local ${field} (${comparison.local[field]}) must match review (${expected})`);
      }
      expectJsonEqual(failures, release.tag, 'comparison local dataFreshness must match review dataFreshness',
        comparison.local.dataFreshness, review.local?.dataFreshness);
      expectJsonEqual(failures, release.tag, 'comparison local explanation must match review explanation',
        comparison.local.components?.explanation, review.local?.components?.explanation);
    }

    const proof = review.local?.gateEvidence?.fixProvenance?.closureProof;
    const credit = review.local?.gateEvidence?.fixProvenance?.releaseFixCredit;
    if (proof || credit) {
      const persistedGate = parseJson(reader.getReleaseScoreAudit(release.tag)?.gate_evidence_json, {});
      const persistedFix = persistedGate?.fixProvenance ?? {};
      expect(failures, release.tag, !!proof && !!credit, 'review must expose closureProof and releaseFixCredit together');
      expectJsonEqual(failures, release.tag, 'review closureProof must match persisted audit closureProof',
        proof, persistedFix.closureProof);
      expectJsonEqual(failures, release.tag, 'review releaseFixCredit must match persisted audit releaseFixCredit',
        credit, persistedFix.releaseFixCredit);
      expect(failures, release.tag, proof.schemaVersion === closureProofSchemaVersion,
        `closureProof schemaVersion (${proof.schemaVersion}) must equal ${closureProofSchemaVersion}`);
      expect(failures, release.tag, credit.schemaVersion === releaseFixCreditSchemaVersion,
        `releaseFixCredit schemaVersion (${credit.schemaVersion}) must equal ${releaseFixCreditSchemaVersion}`);
      expect(failures, release.tag, credit.countedClosedCount === proof.creditedCount,
        'releaseFixCredit countedClosedCount must match closureProof creditedCount');
      expect(failures, release.tag, credit.notCountedClosedCount === proof.notCreditedCount,
        'releaseFixCredit notCountedClosedCount must match closureProof notCreditedCount');
      expect(failures, release.tag, credit.analyzedClosedCount === proof.creditedCount + proof.notCreditedCount,
        'releaseFixCredit analyzedClosedCount must equal credited + notCredited');
      expect(failures, release.tag, (proof.byStatus?.fixed_in_release ?? 0) === proof.creditedCount,
        'closureProof creditedCount must equal fixed_in_release bucket');
      expect(failures, release.tag, isObject(proof.byRiskDisposition),
        'closureProof must expose byRiskDisposition');
      expect(failures, release.tag, isObject(proof.riskSummary),
        'closureProof must expose riskSummary');
      if (isObject(proof.byRiskDisposition)) {
        for (const [disposition] of Object.entries(proof.byRiskDisposition)) {
          expect(failures, release.tag, knownRiskDispositions.has(disposition),
            `closureProof byRiskDisposition contains unknown disposition ${disposition}`);
        }
      }
      verifyClosureProofExamplesByStatus({
        failures,
        tag: release.tag,
        proof,
        label: 'closureProof',
      });
      for (const example of proof.examples ?? []) {
        expect(failures, release.tag, isObject(example.rawClassification),
          `closure proof example #${example.number} must expose rawClassification`);
        expect(failures, release.tag, isObject(example.classification),
          `closure proof example #${example.number} must expose effective classification`);
        expect(failures, release.tag, isObject(example.classificationDiff),
          `closure proof example #${example.number} must expose classificationDiff`);
        expect(failures, release.tag, typeof example.riskWeight === 'number',
          `closure proof example #${example.number} must expose numeric riskWeight`);
      }
      for (let i = 1; i < (proof.examples ?? []).length; i++) {
        expect(failures, release.tag,
          Number(proof.examples[i - 1].riskWeight ?? 0) >= Number(proof.examples[i].riskWeight ?? 0),
          'closure proof examples must be sorted by descending riskWeight');
      }
      await verifyClosureProofAuditEndpoint({
        apiBase,
        fetchJson,
        failures,
        proof,
        tag: release.tag,
        scoredAt: release.scored_at,
      });
      await verifyPrReachabilityAuditEndpoint({
        apiBase,
        fetchJson,
        failures,
        reader,
        tag: release.tag,
        scoredAt: release.scored_at,
      });

      if (comparison?.local) {
        const comparisonFix = comparison.local.gateEvidence?.fixProvenance;
        const comparisonProof = comparisonFix?.closureProof;
        const comparisonCredit = comparisonFix?.releaseFixCredit;
        expect(failures, release.tag, !!comparisonProof && !!comparisonCredit,
          'comparison local gateEvidence must expose closureProof and releaseFixCredit when review does');
        expect(failures, release.tag, comparisonCredit?.countedClosedCount === credit.countedClosedCount,
          'comparison countedClosedCount must match review countedClosedCount');
        expect(failures, release.tag, comparisonCredit?.notCountedClosedCount === credit.notCountedClosedCount,
          'comparison notCountedClosedCount must match review notCountedClosedCount');
        expect(failures, release.tag, comparisonProof?.creditedCount === proof.creditedCount,
          'comparison closureProof creditedCount must match review');
        expect(failures, release.tag, comparisonProof?.notCreditedCount === proof.notCreditedCount,
          'comparison closureProof notCreditedCount must match review');
        expectJsonEqual(failures, release.tag, 'comparison closureProof byRiskDisposition must match review',
          comparisonProof?.byRiskDisposition, proof.byRiskDisposition);
        expectJsonEqual(failures, release.tag, 'comparison closureProof riskSummary must match review',
          comparisonProof?.riskSummary, proof.riskSummary);
        expectJsonEqual(failures, release.tag, 'comparison closureProof examplesByStatus must match review',
          comparisonProof?.examplesByStatus, proof.examplesByStatus);
      }
    }
  }
}

function verifyClosureProofExamplesByStatus({ failures, tag, proof, label }) {
  expect(failures, tag, isObject(proof?.examplesByStatus),
    `${label} must expose examplesByStatus`);
  for (const [status, count] of Object.entries(proof?.byStatus ?? {})) {
    if (status === 'fixed_in_release' || Number(count ?? 0) <= 0) continue;
    const statusExamples = proof?.examplesByStatus?.[status];
    expect(failures, tag, Array.isArray(statusExamples) && statusExamples.length > 0,
      `${label} examplesByStatus must include at least one ${status} example`);
    for (const example of statusExamples ?? []) {
      expect(failures, tag, example.status === status,
        `${label} examplesByStatus ${status} contains example with status ${example.status}`);
    }
  }
}

async function verifyIssueEvidenceAuditEndpoint({ apiBase, fetchJson, failures, reader, tag, issueEvidence, scoredAt }) {
  const base = `${apiBase}/api/releases/${encodeURIComponent(tag)}/review/issues`;
  const firstPage = await fetchJson(`${base}?limit=11`);
  const invalidFilterCases = [
    ['issue evidence audit invalid tier', `${base}?tier=not-a-tier`, 'invalid tier'],
    ['issue evidence audit invalid fieldConfirmed', `${base}?fieldConfirmed=maybe`, 'invalid fieldConfirmed'],
    ['issue evidence audit repeated fieldConfirmed', `${base}?fieldConfirmed=true&fieldConfirmed=maybe`, 'invalid fieldConfirmed'],
    ['issue evidence audit invalid weight range', `${base}?minWeight=10&maxWeight=1`, 'invalid weight range'],
    ['issue evidence audit repeated minWeight', `${base}?minWeight=1&minWeight=2`, 'invalid minWeight'],
    ['issue evidence audit invalid sort', `${base}?sort=not-a-sort`, 'invalid sort'],
    ['issue evidence audit repeated sort', `${base}?sort=rank&sort=weight`, 'invalid sort'],
    ['issue evidence audit invalid direction', `${base}?direction=sideways`, 'invalid direction'],
    ['issue evidence audit repeated direction', `${base}?direction=asc&direction=desc`, 'invalid direction'],
    ['issue evidence audit invalid summaryOnly', `${base}?summaryOnly=wat`, 'invalid summaryOnly'],
    ['issue evidence audit invalid limit', `${base}?limit=abc`, 'invalid limit'],
    ['issue evidence audit decimal limit', `${base}?limit=1.9`, 'invalid limit'],
    ['issue evidence audit repeated limit', `${base}?limit=1&limit=2`, 'invalid limit'],
    ['issue evidence audit invalid cursor', `${base}?cursor=abc`, 'invalid cursor'],
    ['issue evidence audit decimal cursor', `${base}?cursor=1.9`, 'invalid cursor'],
    ['issue evidence audit repeated cursor', `${base}?cursor=0&cursor=1`, 'invalid cursor'],
  ];
  for (const [label, url, error] of invalidFilterCases) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === issueEvidenceAuditSchemaVersion,
    `issue evidence audit schemaVersion must be ${issueEvidenceAuditSchemaVersion}, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit payload', value: firstPage, allowed: issueEvidenceAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit filters', value: firstPage.filters, allowed: issueEvidenceAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'issue evidence audit totals', value: firstPage.totals, allowed: issueEvidenceAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `issue evidence audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `issue evidence audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `issue evidence audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({ failures, tag, dataFreshness: firstPage.dataFreshness, releaseTag: tag, scoredAt });
  expect(failures, tag, firstPage.limit === 11,
    `issue evidence audit limit must be 11, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0,
    `issue evidence audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, isObject(firstPage.countsByTier),
    'issue evidence audit countsByTier must be an object');
  expect(failures, tag, isObject(firstPage.summaryByTier),
    'issue evidence audit summaryByTier must be an object');
  expect(failures, tag, isObject(firstPage.filteredSummary),
    'issue evidence audit filteredSummary must be an object');
  expect(failures, tag, firstPage.filters?.sort === 'rank',
    `issue evidence audit default sort (${firstPage.filters?.sort}) must be rank`);
  expect(failures, tag, firstPage.filters?.direction === 'asc',
    `issue evidence audit default direction (${firstPage.filters?.direction}) must be asc`);
  expect(failures, tag, firstPage.filters?.summaryOnly === false,
    `issue evidence audit default summaryOnly (${firstPage.filters?.summaryOnly}) must be false`);
  expectJsonEqual(failures, tag, 'issue evidence audit tierInfo must match shared tier metadata',
    firstPage.tierInfo, RELEASE_ISSUE_EVIDENCE_TIER_INFO);
  for (const [tier, count] of Object.entries(firstPage.countsByTier ?? {})) {
    expect(failures, tag, knownIssueEvidenceTiers.has(tier),
      `issue evidence audit countsByTier contains unknown tier ${tier}`);
    expect(failures, tag, Number.isInteger(count) && count >= 0,
      `issue evidence audit count for ${tier} must be a non-negative integer`);
    const summary = firstPage.summaryByTier?.[tier];
    expect(failures, tag, isObject(summary),
      `issue evidence audit summaryByTier.${tier} must be an object`);
    expect(failures, tag, summary?.count === count,
      `issue evidence audit summaryByTier.${tier}.count (${summary?.count}) must match countsByTier (${count})`);
    expect(failures, tag, typeof summary?.weight === 'number',
      `issue evidence audit summaryByTier.${tier}.weight must be numeric`);
  }
  const countSum = Object.values(firstPage.countsByTier ?? {}).reduce((sum, count) => sum + Number(count ?? 0), 0);
  expect(failures, tag, firstPage.total === countSum,
    `issue evidence audit total (${firstPage.total}) must equal countsByTier sum (${countSum})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `issue evidence audit totalRows (${firstPage.totalRows}) must match filtered total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'issue evidence audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === countSum,
    `issue evidence audit totals.unfilteredRows (${firstPage.totals?.unfilteredRows}) must equal countsByTier sum (${countSum})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `issue evidence audit totals.filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, Number.isInteger(firstPage.distinctIssueCount) && firstPage.distinctIssueCount >= 0,
    `issue evidence audit distinctIssueCount (${firstPage.distinctIssueCount}) must be a non-negative integer`);
  expect(failures, tag, firstPage.totals?.filteredDistinctIssues === firstPage.distinctIssueCount,
    `issue evidence audit totals.filteredDistinctIssues (${firstPage.totals?.filteredDistinctIssues}) must match distinctIssueCount (${firstPage.distinctIssueCount})`);
  expectJsonEqual(failures, tag, 'issue evidence audit unfilteredCountsByTier must match countsByTier',
    firstPage.unfilteredCountsByTier, firstPage.countsByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit filteredCountsByTier must match unfiltered counts without filters',
    firstPage.filteredCountsByTier, firstPage.countsByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit unfilteredSummaryByTier must match summaryByTier',
    firstPage.unfilteredSummaryByTier, firstPage.summaryByTier);
  expectJsonEqual(failures, tag, 'issue evidence audit filteredSummaryByTier must match summaryByTier without filters',
    firstPage.filteredSummaryByTier, firstPage.summaryByTier);
  expect(failures, tag, firstPage.filteredSummary?.count === firstPage.total,
    `issue evidence audit filteredSummary count (${firstPage.filteredSummary?.count}) must match total (${firstPage.total})`);
  expect(failures, tag, Array.isArray(firstPage.rows),
    'issue evidence audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 11,
    `issue evidence audit rows length must respect limit, got ${firstPage.rows.length}`);
  if (firstPage.total > firstPage.rows.length) {
    expect(failures, tag, Number.isInteger(firstPage.nextCursor) && firstPage.nextCursor === firstPage.rows.length,
      `issue evidence audit nextCursor (${firstPage.nextCursor}) must advance by returned rows (${firstPage.rows.length})`);
    const nextPage = await fetchJson(`${base}?limit=11&cursor=${firstPage.nextCursor}`);
    expect(failures, tag, nextPage.cursor === firstPage.nextCursor,
      `issue evidence audit next page cursor (${nextPage.cursor}) must equal requested cursor (${firstPage.nextCursor})`);
    expectNoPaginationOverlap({
      failures,
      tag,
      label: 'issue evidence audit',
      firstRows: firstPage.rows,
      nextRows: nextPage.rows,
      identity: (row) => `${row?.tier}:${row?.issue?.number ?? 'missing'}`,
    });
  } else {
    expect(failures, tag, firstPage.nextCursor == null,
      `issue evidence audit nextCursor must be null at end, got ${firstPage.nextCursor}`);
  }
  const summaryOnlyPage = await fetchJson(`${base}?summaryOnly=true&tier=carryoverDebt,staleDebt`);
  const expectedSummaryOnlyTotal = Number(firstPage.countsByTier?.carryoverDebt ?? 0) + Number(firstPage.countsByTier?.staleDebt ?? 0);
  expect(failures, tag, summaryOnlyPage.filters?.summaryOnly === true,
    `issue evidence audit summaryOnly echo (${summaryOnlyPage.filters?.summaryOnly}) must be true`);
  expect(failures, tag, summaryOnlyPage.limit === 0,
    `issue evidence audit summaryOnly limit (${summaryOnlyPage.limit}) must be 0`);
  expect(failures, tag, summaryOnlyPage.cursor === 0,
    `issue evidence audit summaryOnly cursor (${summaryOnlyPage.cursor}) must be 0`);
  expect(failures, tag, summaryOnlyPage.nextCursor == null,
    `issue evidence audit summaryOnly nextCursor (${summaryOnlyPage.nextCursor}) must be null`);
  expect(failures, tag, Array.isArray(summaryOnlyPage.rows) && summaryOnlyPage.rows.length === 0,
    'issue evidence audit summaryOnly rows must be empty');
  expect(failures, tag, summaryOnlyPage.total === expectedSummaryOnlyTotal,
    `issue evidence audit summaryOnly total (${summaryOnlyPage.total}) must match selected tier counts (${expectedSummaryOnlyTotal})`);
  expect(failures, tag, summaryOnlyPage.totals?.unfilteredRows === countSum,
    `issue evidence audit summaryOnly unfilteredRows (${summaryOnlyPage.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
  expect(failures, tag, summaryOnlyPage.totals?.filteredRows === summaryOnlyPage.total,
    `issue evidence audit summaryOnly filteredRows (${summaryOnlyPage.totals?.filteredRows}) must match total (${summaryOnlyPage.total})`);
  expect(failures, tag, summaryOnlyPage.totalRows === summaryOnlyPage.total,
    `issue evidence audit summaryOnly totalRows (${summaryOnlyPage.totalRows}) must match total (${summaryOnlyPage.total})`);
  expect(failures, tag, summaryOnlyPage.filteredSummary?.count === summaryOnlyPage.total,
    `issue evidence audit summaryOnly filteredSummary count (${summaryOnlyPage.filteredSummary?.count}) must match total (${summaryOnlyPage.total})`);

  for (const row of firstPage.rows ?? []) {
    verifyAllowedKeys({ failures, tag, label: 'issue evidence audit row', value: row, allowed: issueEvidenceAuditRowKeys });
    expect(failures, tag, knownIssueEvidenceTiers.has(row.tier),
      `issue evidence audit row tier must be known, got ${row.tier}`);
    const tierInfo = RELEASE_ISSUE_EVIDENCE_TIER_INFO[row.tier];
    expect(failures, tag, row.tierLabel === tierInfo?.label,
      `issue evidence audit row ${row.tier} tierLabel (${row.tierLabel}) must match ${tierInfo?.label}`);
    expect(failures, tag, row.tierDescription === tierInfo?.description,
      `issue evidence audit row ${row.tier} tierDescription must match shared metadata`);
    expect(failures, tag, isObject(row.issue),
      `issue evidence audit row ${row.tier} must expose issue object`);
    verifyAllowedKeys({ failures, tag, label: 'issue evidence audit row issue', value: row.issue, allowed: issueEvidenceIssueKeys });
    expect(failures, tag,
      Number.isInteger(row.issue?.number) && row.issue.number > 0 || row.issue?.missing === true,
      `issue evidence audit row ${row.tier} issue number must be positive or explicitly missing`);
    if (row.issue?.missing !== true) {
      expect(failures, tag, typeof row.issue?.title === 'string' && row.issue.title.length > 0,
        `issue evidence audit row #${row.issue?.number} title must be present`);
      expect(failures, tag, Array.isArray(row.issue?.labels),
        `issue evidence audit row #${row.issue?.number} labels must be an array`);
      if (['verifiedDebt', 'carryoverDebt', 'staleDebt', 'openedFeltSerious', 'verifiedFixed', 'unverifiedClosed'].includes(row.tier)) {
        expect(failures, tag, isObject(row.issue?.classification),
          `issue evidence audit row #${row.issue?.number} must expose effective classification`);
        expect(failures, tag, isObject(row.issue?.rawClassification),
          `issue evidence audit row #${row.issue?.number} must expose raw classification`);
        expect(failures, tag, isObject(row.issue?.classificationDiff),
          `issue evidence audit row #${row.issue?.number} must expose classificationDiff`);
      }
    }
    if (['verifiedDebt', 'carryoverDebt', 'staleDebt'].includes(row.tier)) {
      expect(failures, tag, typeof row.weight === 'number' && Number.isFinite(row.weight),
        `issue evidence audit debt row #${row.issue?.number} must expose numeric weight`);
      expect(failures, tag, typeof row.installImpactClass === 'string' && row.installImpactClass.length > 0,
        `issue evidence audit debt row #${row.issue?.number} must expose installImpactClass`);
      if (row.debtClassification != null) {
        expect(failures, tag, isObject(row.debtClassification),
          `issue evidence audit debt row #${row.issue?.number} debtClassification must be an object`);
      }
      if (row.debtClassificationDiff != null) {
        expect(failures, tag, isObject(row.debtClassificationDiff),
          `issue evidence audit debt row #${row.issue?.number} debtClassificationDiff must be an object`);
      }
    }
  }

  const expectedDebtCounts = {
    verifiedDebt: Number(issueEvidence?.debtSummary?.verified?.count ?? 0),
    carryoverDebt: Number(issueEvidence?.debtSummary?.carryover?.count ?? 0),
    staleDebt: Number(issueEvidence?.debtSummary?.stale?.count ?? 0),
  };
  for (const [tier, expected] of Object.entries(expectedDebtCounts)) {
    if (!Number.isFinite(expected)) continue;
    expect(failures, tag, Number(firstPage.countsByTier?.[tier] ?? 0) === expected,
      `issue evidence audit ${tier} count (${firstPage.countsByTier?.[tier]}) must match persisted debtSummary count (${expected})`);
  }
  if (typeof reader.verifiedFixedForRelease === 'function') {
    const expected = reader.verifiedFixedForRelease(tag).length;
    expect(failures, tag, Number(firstPage.countsByTier?.verifiedFixed ?? 0) === expected,
      `issue evidence audit verifiedFixed count (${firstPage.countsByTier?.verifiedFixed}) must match DB verified fixed (${expected})`);
  }
  if (typeof reader.unverifiedClosedForRelease === 'function') {
    const expected = reader.unverifiedClosedForRelease(tag).length;
    expect(failures, tag, Number(firstPage.countsByTier?.unverifiedClosed ?? 0) === expected,
      `issue evidence audit unverifiedClosed count (${firstPage.countsByTier?.unverifiedClosed}) must match DB unverified closed (${expected})`);
  }

  const tiersToProbe = Object.entries(firstPage.countsByTier ?? {})
    .filter(([, count]) => Number(count ?? 0) > 0)
    .slice(0, 3);
  for (const [tier, count] of tiersToProbe) {
    const page = await fetchJson(`${base}?limit=5&tier=${encodeURIComponent(tier)}`);
    expect(failures, tag, page.total === Number(count),
      `issue evidence audit tier filter total (${page.total}) must match ${tier} count (${count})`);
    expect(failures, tag, page.totals?.unfilteredRows === countSum,
      `issue evidence audit tier filter unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `issue evidence audit tier filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByTier?.[tier] === Number(count),
      `issue evidence audit filteredCountsByTier.${tier} (${page.filteredCountsByTier?.[tier]}) must match ${count}`);
    expect(failures, tag, page.filteredSummaryByTier?.[tier]?.count === Number(count),
      `issue evidence audit filteredSummaryByTier.${tier}.count (${page.filteredSummaryByTier?.[tier]?.count}) must match ${count}`);
    expect(failures, tag, page.filters?.tier === tier,
      `issue evidence audit tier filter echo (${page.filters?.tier}) must equal ${tier}`);
    expect(failures, tag, Array.isArray(page.filters?.tiers) && page.filters.tiers.length === 1 && page.filters.tiers[0] === tier,
      `issue evidence audit tiers filter echo must contain only ${tier}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit filteredSummary count (${page.filteredSummary?.count}) must match filtered total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.tier === tier),
      `issue evidence audit tier filter must return only ${tier} rows`);
  }
  if (tiersToProbe.length >= 2) {
    const selected = tiersToProbe.slice(0, 2);
    const tierParam = selected.map(([tier]) => tier).join(',');
    const expectedTotal = selected.reduce((sum, [, count]) => sum + Number(count), 0);
    const page = await fetchJson(`${base}?limit=5&tier=${encodeURIComponent(tierParam)}`);
    expect(failures, tag, page.total === expectedTotal,
      `issue evidence audit multi-tier filter total (${page.total}) must match selected tier counts (${expectedTotal})`);
    expect(failures, tag, page.totals?.unfilteredRows === countSum,
      `issue evidence audit multi-tier unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${countSum})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `issue evidence audit multi-tier filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filters?.tier == null,
      'issue evidence audit multi-tier filter must not echo singular tier');
    expectJsonEqual(failures, tag, 'issue evidence audit multi-tier filter echo',
      page.filters?.tiers, selected.map(([tier]) => tier));
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit multi-tier filteredSummary count (${page.filteredSummary?.count}) must match filtered total (${page.total})`);
    const selectedSet = new Set(selected.map(([tier]) => tier));
    expect(failures, tag, (page.rows ?? []).every((row) => selectedSet.has(row.tier)),
      `issue evidence audit multi-tier filter must return only ${tierParam} rows`);
  }
  const impactToProbe = Object.entries(firstPage.summaryByTier ?? {})
    .flatMap(([, summary]) => Object.entries(summary?.byInstallImpactClass ?? {}))
    .find(([, count]) => Number(count ?? 0) > 0)?.[0] ?? null;
  if (impactToProbe) {
    const page = await fetchJson(`${base}?limit=5&impact=${encodeURIComponent(impactToProbe)}`);
    expect(failures, tag, page.filters?.impact === impactToProbe,
      `issue evidence audit impact filter echo (${page.filters?.impact}) must equal ${impactToProbe}`);
    expect(failures, tag, Array.isArray(page.filters?.impacts) && page.filters.impacts.length === 1 && page.filters.impacts[0] === impactToProbe,
      `issue evidence audit impacts filter echo must contain only ${impactToProbe}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit impact filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.installImpactClass === impactToProbe),
      `issue evidence audit impact filter must return only ${impactToProbe} rows`);
  }
  const stateToProbe = (firstPage.rows ?? []).find((row) => row.issue?.state === 'open' || row.issue?.state === 'closed')?.issue?.state ?? null;
  if (stateToProbe) {
    const page = await fetchJson(`${base}?limit=5&state=${encodeURIComponent(stateToProbe)}`);
    expect(failures, tag, page.filters?.state === stateToProbe,
      `issue evidence audit state filter echo (${page.filters?.state}) must equal ${stateToProbe}`);
    expect(failures, tag, Array.isArray(page.filters?.states) && page.filters.states.length === 1 && page.filters.states[0] === stateToProbe,
      `issue evidence audit states filter echo must contain only ${stateToProbe}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit state filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.issue?.state === stateToProbe),
      `issue evidence audit state filter must return only ${stateToProbe} rows`);
  }
  const classificationFilters = [
    ['sentiment', 'sentiments'],
    ['severity', 'severities'],
    ['functionality', 'functionalities'],
    ['scope', 'scopes'],
    ['affectedUsers', 'affectedUsersList'],
  ];
  for (const [field, pluralField] of classificationFilters) {
    const value = (firstPage.rows ?? [])
      .map((row) => row.issue?.classification?.[field])
      .find((candidate) => typeof candidate === 'string');
    if (!value) continue;
    const page = await fetchJson(`${base}?limit=5&${field}=${encodeURIComponent(value)}`);
    expect(failures, tag, page.filters?.[field] === value,
      `issue evidence audit ${field} filter echo (${page.filters?.[field]}) must equal ${value}`);
    expect(failures, tag, Array.isArray(page.filters?.[pluralField]) && page.filters[pluralField].length === 1 && page.filters[pluralField][0] === value,
      `issue evidence audit ${pluralField} filter echo must contain only ${value}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit ${field} filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.issue?.classification?.[field] === value),
      `issue evidence audit ${field} filter must return only ${value} rows`);
  }
  const fieldConfirmedProbe = (firstPage.rows ?? []).find((row) => row.fieldConfirmed === true || row.fieldConfirmed === false);
  if (fieldConfirmedProbe) {
    const value = fieldConfirmedProbe.fieldConfirmed === true ? 'true' : 'false';
    const page = await fetchJson(`${base}?limit=5&fieldConfirmed=${value}`);
    expect(failures, tag, page.filters?.fieldConfirmed === fieldConfirmedProbe.fieldConfirmed,
      `issue evidence audit fieldConfirmed filter echo (${page.filters?.fieldConfirmed}) must equal ${fieldConfirmedProbe.fieldConfirmed}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit fieldConfirmed filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.fieldConfirmed === fieldConfirmedProbe.fieldConfirmed),
      `issue evidence audit fieldConfirmed filter must return only ${value} rows`);
  }
  const weightedProbe = (firstPage.rows ?? []).find((row) => typeof row.weight === 'number' && Number.isFinite(row.weight));
  if (weightedProbe) {
    const minWeight = Math.max(0, Math.floor(Number(weightedProbe.weight)));
    const maxWeight = Math.ceil(Number(weightedProbe.weight));
    const page = await fetchJson(`${base}?limit=5&minWeight=${minWeight}&maxWeight=${maxWeight}`);
    expect(failures, tag, page.filters?.minWeight === minWeight,
      `issue evidence audit minWeight filter echo (${page.filters?.minWeight}) must equal ${minWeight}`);
    expect(failures, tag, page.filters?.maxWeight === maxWeight,
      `issue evidence audit maxWeight filter echo (${page.filters?.maxWeight}) must equal ${maxWeight}`);
    expect(failures, tag, page.filteredSummary?.count === page.total,
      `issue evidence audit weight filteredSummary count (${page.filteredSummary?.count}) must match total (${page.total})`);
    expect(failures, tag, (page.rows ?? []).every((row) =>
      Number(row.weight ?? 0) >= minWeight && Number(row.weight ?? 0) <= maxWeight),
    `issue evidence audit weight filter must return only rows between ${minWeight} and ${maxWeight}`);
  }
  const weightSorted = await fetchJson(`${base}?limit=7&sort=weight&direction=desc`);
  expect(failures, tag, weightSorted.filters?.sort === 'weight',
    `issue evidence audit sort echo (${weightSorted.filters?.sort}) must be weight`);
  expect(failures, tag, weightSorted.filters?.direction === 'desc',
    `issue evidence audit direction echo (${weightSorted.filters?.direction}) must be desc`);
  expect(failures, tag, isNonIncreasing((weightSorted.rows ?? []).map((row) => Number(row.weight ?? 0))),
    'issue evidence audit weight desc sort must be non-increasing');
  const numberSorted = await fetchJson(`${base}?limit=7&sort=number&direction=asc`);
  expect(failures, tag, numberSorted.filters?.sort === 'number',
    `issue evidence audit sort echo (${numberSorted.filters?.sort}) must be number`);
  expect(failures, tag, numberSorted.filters?.direction === 'asc',
    `issue evidence audit direction echo (${numberSorted.filters?.direction}) must be asc`);
  expect(failures, tag, isNonDecreasing((numberSorted.rows ?? []).map((row) => Number(row.issue?.number ?? 0))),
    'issue evidence audit number asc sort must be non-decreasing');
  const closedSorted = await fetchJson(`${base}?limit=25&state=open,closed&sort=closed&direction=desc`);
  expect(failures, tag, closedSorted.filters?.sort === 'closed',
    `issue evidence audit sort echo (${closedSorted.filters?.sort}) must be closed`);
  expect(failures, tag, closedSorted.filters?.direction === 'desc',
    `issue evidence audit direction echo (${closedSorted.filters?.direction}) must be desc`);
  const closedTimestamps = (closedSorted.rows ?? []).map((row) => timestampOrNull(row.issue?.closedAt));
  expect(failures, tag, sortValuesKeepMissingLast(closedTimestamps, 'desc'),
    'issue evidence audit closed desc sort must be non-increasing with missing closedAt values last');
  if (
    Number(closedSorted.filteredSummary?.openCount ?? 0) > 0 &&
    Number(closedSorted.filteredSummary?.closedCount ?? 0) > 0 &&
    (closedSorted.rows ?? []).length > 0
  ) {
    expect(failures, tag, closedTimestamps[0] != null,
      'issue evidence audit closed desc sort must not put open issues before closed issues with close timestamps');
  }
}

function isNonIncreasing(values) {
  for (let i = 1; i < values.length; i++) {
    if (values[i - 1] < values[i]) return false;
  }
  return true;
}

function isNonDecreasing(values) {
  for (let i = 1; i < values.length; i++) {
    if (values[i - 1] > values[i]) return false;
  }
  return true;
}

function sortValuesKeepMissingLast(values, direction) {
  let sawMissing = false;
  let previous = null;
  for (const value of values) {
    const missing = value == null || Number.isNaN(value);
    if (missing) {
      sawMissing = true;
      continue;
    }
    if (sawMissing) return false;
    if (previous != null) {
      if (direction === 'asc' && previous > value) return false;
      if (direction === 'desc' && previous < value) return false;
    }
    previous = value;
  }
  return true;
}

function timestampOrNull(value) {
  if (typeof value !== 'string') return null;
  const timestamp = Date.parse(value);
  return Number.isFinite(timestamp) ? timestamp : null;
}

async function verifyClosureProofAuditEndpoint({ apiBase, fetchJson, failures, tag, proof, scoredAt }) {
  const base = `${apiBase}/api/releases/${encodeURIComponent(tag)}/review/closure-proofs`;
  const firstPage = await fetchJson(`${base}?limit=5`);
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: `${base}?status=fixed-in-release`,
    status: 400,
    label: 'closure proof audit invalid status',
    payloadCheck: (payload) => payload?.error === 'invalid status' && Array.isArray(payload.allowedStatuses),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: `${base}?status=fixed_in_release&status=closed_without_release_fix_proof`,
    status: 400,
    label: 'closure proof audit repeated status',
    payloadCheck: (payload) => payload?.error === 'invalid status' && Array.isArray(payload.allowedStatuses),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: `${base}?riskDisposition=not-a-real-disposition`,
    status: 400,
    label: 'closure proof audit invalid riskDisposition',
    payloadCheck: (payload) => payload?.error === 'invalid riskDisposition' && Array.isArray(payload.allowedRiskDispositions),
  });
  await expectFetchJsonStatus({
    failures,
    tag,
    fetchJson,
    url: `${base}?riskDisposition=credited_release_fix&riskDisposition=known_not_in_release`,
    status: 400,
    label: 'closure proof audit repeated riskDisposition',
    payloadCheck: (payload) => payload?.error === 'invalid riskDisposition' && Array.isArray(payload.allowedRiskDispositions),
  });
  for (const [label, url, error] of [
    ['closure proof audit invalid limit', `${base}?limit=abc`, 'invalid limit'],
    ['closure proof audit decimal limit', `${base}?limit=1.9`, 'invalid limit'],
    ['closure proof audit repeated limit', `${base}?limit=1&limit=2`, 'invalid limit'],
    ['closure proof audit invalid cursor', `${base}?cursor=abc`, 'invalid cursor'],
    ['closure proof audit decimal cursor', `${base}?cursor=1.9`, 'invalid cursor'],
    ['closure proof audit repeated cursor', `${base}?cursor=0&cursor=1`, 'invalid cursor'],
  ]) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === closureProofAuditSchemaVersion,
    `closure proof audit schemaVersion must be ${closureProofAuditSchemaVersion}, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit payload', value: firstPage, allowed: closureProofAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit filters', value: firstPage.filters, allowed: closureProofAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'closure proof audit totals', value: firstPage.totals, allowed: closureProofAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `closure proof audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `closure proof audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `closure proof audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({ failures, tag, dataFreshness: firstPage.dataFreshness, releaseTag: tag, scoredAt });
  expect(failures, tag, firstPage.total === proof.creditedCount + proof.notCreditedCount,
    `closure proof audit total (${firstPage.total}) must match analyzed proof count (${proof.creditedCount + proof.notCreditedCount})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `closure proof audit totalRows (${firstPage.totalRows}) must match total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'closure proof audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === firstPage.total,
    `closure proof audit totals.unfilteredRows (${firstPage.totals?.unfilteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `closure proof audit totals.filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.totals?.filteredDistinctIssues === firstPage.distinctIssueCount,
    `closure proof audit filteredDistinctIssues (${firstPage.totals?.filteredDistinctIssues}) must match distinctIssueCount (${firstPage.distinctIssueCount})`);
  expectJsonEqual(failures, tag, 'closure proof audit unfilteredCountsByStatus must match proof byStatus',
    firstPage.unfilteredCountsByStatus ?? {}, proof.byStatus ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit filteredCountsByStatus must match proof byStatus without filters',
    firstPage.filteredCountsByStatus ?? {}, proof.byStatus ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit unfilteredCountsByRiskDisposition must match proof byRiskDisposition',
    firstPage.unfilteredCountsByRiskDisposition ?? {}, proof.byRiskDisposition ?? {});
  expectJsonEqual(failures, tag, 'closure proof audit filteredCountsByRiskDisposition must match proof byRiskDisposition without filters',
    firstPage.filteredCountsByRiskDisposition ?? {}, proof.byRiskDisposition ?? {});
  expect(failures, tag, firstPage.limit === 5, `closure proof audit limit must be 5, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0, `closure proof audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, Array.isArray(firstPage.rows), 'closure proof audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 5, `closure proof audit rows length must respect limit, got ${firstPage.rows.length}`);
  if (firstPage.total > firstPage.rows.length) {
    expect(failures, tag, Number.isInteger(firstPage.nextCursor) && firstPage.nextCursor === firstPage.rows.length,
      `closure proof audit nextCursor (${firstPage.nextCursor}) must advance by returned rows (${firstPage.rows.length})`);
    const nextPage = await fetchJson(`${base}?limit=5&cursor=${firstPage.nextCursor}`);
    expect(failures, tag, nextPage.cursor === firstPage.nextCursor,
      `closure proof audit next page cursor (${nextPage.cursor}) must equal requested cursor (${firstPage.nextCursor})`);
    expectNoPaginationOverlap({
      failures,
      tag,
      label: 'closure proof audit',
      firstRows: firstPage.rows,
      nextRows: nextPage.rows,
      identity: (row) => `${row?.issueNumber}:${row?.status}`,
    });
  } else {
    expect(failures, tag, firstPage.nextCursor == null,
      `closure proof audit nextCursor must be null at end, got ${firstPage.nextCursor}`);
  }
  for (const row of firstPage.rows ?? []) {
    verifyAllowedKeys({ failures, tag, label: 'closure proof audit row', value: row, allowed: closureProofAuditRowKeys });
    expect(failures, tag, Number.isInteger(row.issueNumber) && row.issueNumber > 0,
      `closure proof audit row issueNumber must be positive integer, got ${row.issueNumber}`);
    expect(failures, tag, typeof row.status === 'string' && knownProofStatuses.has(row.status),
      `closure proof audit row status must be known, got ${row.status}`);
    expect(failures, tag, typeof row.summary === 'string' && row.summary.length > 0,
      `closure proof audit row #${row.issueNumber} summary must be present`);
    expect(failures, tag, typeof row.riskDisposition === 'string' && knownRiskDispositions.has(row.riskDisposition),
      `closure proof audit row #${row.issueNumber} riskDisposition must be known, got ${row.riskDisposition}`);
    expect(failures, tag, typeof row.riskDispositionLabel === 'string' && row.riskDispositionLabel.length > 0,
      `closure proof audit row #${row.issueNumber} riskDispositionLabel must be present`);
    expect(failures, tag, typeof row.riskWeight === 'number',
      `closure proof audit row #${row.issueNumber} riskWeight must be numeric`);
    expect(failures, tag, typeof row.riskWeightLabel === 'string' && row.riskWeightLabel.length > 0,
      `closure proof audit row #${row.issueNumber} riskWeightLabel must be present`);
    expect(failures, tag, isObject(row.evidence),
      `closure proof audit row #${row.issueNumber} evidence must be present`);
    verifyAllowedKeys({ failures, tag, label: 'closure proof audit row evidence', value: row.evidence, allowed: closureProofAuditEvidenceKeys });
  }

  const [status, statusCount] = Object.entries(proof.byStatus ?? {}).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (status) {
    const page = await fetchJson(`${base}?limit=3&status=${encodeURIComponent(status)}`);
    expect(failures, tag, page.total === Number(statusCount ?? 0),
      `closure proof audit status filter total (${page.total}) must match ${status} count (${statusCount})`);
    expect(failures, tag, page.totals?.unfilteredRows === firstPage.total,
      `closure proof audit status filter unfilteredRows (${page.totals?.unfilteredRows}) must match unfiltered total (${firstPage.total})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `closure proof audit status filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByStatus?.[status] === Number(statusCount ?? 0),
      `closure proof audit filteredCountsByStatus.${status} (${page.filteredCountsByStatus?.[status]}) must match ${statusCount}`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.status === status),
      `closure proof audit status filter must return only ${status} rows`);
  }
  const proofMetadataStatuses = [
    ['fixed_in_later_release', 'laterFixProof', (proof) => proof?.releaseTag && ['pr', 'commit'].includes(proof?.proofType)],
    ['non_bug_fixed_in_later_release', 'laterFixProof', (proof) => proof?.releaseTag && ['pr', 'commit'].includes(proof?.proofType)],
    ['fixed_after_latest_release', 'unscoredFixProof', (proof) => proof?.timing === 'after_latest_release'],
    ['non_bug_fixed_after_latest_release', 'unscoredFixProof', (proof) => proof?.timing === 'after_latest_release'],
    ['fixed_skipped_by_later_releases', 'unscoredFixProof', (proof) => proof?.timing === 'skipped_by_later_releases'],
    ['non_bug_fixed_skipped_by_later_releases', 'unscoredFixProof', (proof) => proof?.timing === 'skipped_by_later_releases'],
  ];
  for (const [proofStatus, evidenceField, isValidProof] of proofMetadataStatuses) {
    if (Number(proof.byStatus?.[proofStatus] ?? 0) <= 0) continue;
    const page = await fetchJson(`${base}?limit=3&status=${encodeURIComponent(proofStatus)}`);
    expect(failures, tag, (page.rows ?? []).length > 0,
      `closure proof audit ${proofStatus} filter must return at least one row`);
    expect(failures, tag, (page.rows ?? []).every((row) => isValidProof(row.evidence?.[evidenceField])),
      `closure proof audit ${proofStatus} rows must expose valid ${evidenceField} metadata`);
  }

  const [disposition, dispositionCount] = Object.entries(proof.byRiskDisposition ?? {}).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (disposition) {
    const page = await fetchJson(`${base}?limit=3&riskDisposition=${encodeURIComponent(disposition)}`);
    expect(failures, tag, page.total === Number(dispositionCount ?? 0),
      `closure proof audit riskDisposition filter total (${page.total}) must match ${disposition} count (${dispositionCount})`);
    expect(failures, tag, page.filteredCountsByRiskDisposition?.[disposition] === Number(dispositionCount ?? 0),
      `closure proof audit filteredCountsByRiskDisposition.${disposition} (${page.filteredCountsByRiskDisposition?.[disposition]}) must match ${dispositionCount}`);
    expect(failures, tag, (page.rows ?? []).every((row) => row.riskDisposition === disposition),
      `closure proof audit riskDisposition filter must return only ${disposition} rows`);
  }
}

async function verifyPrReachabilityAuditEndpoint({ apiBase, fetchJson, failures, reader, tag, scoredAt }) {
  if (typeof reader.prReachabilityRowsForRelease !== 'function') return;
  const rows = reader.prReachabilityRowsForRelease(tag);
  const base = `${apiBase}/api/releases/${encodeURIComponent(tag)}/review/reachability`;
  const firstPage = await fetchJson(`${base}?limit=7`);
  for (const [label, url, error] of [
    ['PR reachability audit invalid status', `${base}?status=bad`, 'invalid status'],
    ['PR reachability audit repeated status', `${base}?status=reachable&status=bad`, 'invalid status'],
    ['PR reachability audit invalid pr', `${base}?pr=not-a-pr`, 'invalid pr filter'],
    ['PR reachability audit repeated pr', `${base}?pr=123&pr=not-a-pr`, 'invalid pr filter'],
    ['PR reachability audit invalid limit', `${base}?limit=abc`, 'invalid limit'],
    ['PR reachability audit decimal limit', `${base}?limit=1.9`, 'invalid limit'],
    ['PR reachability audit repeated limit', `${base}?limit=1&limit=2`, 'invalid limit'],
    ['PR reachability audit invalid cursor', `${base}?cursor=abc`, 'invalid cursor'],
    ['PR reachability audit decimal cursor', `${base}?cursor=1.9`, 'invalid cursor'],
    ['PR reachability audit repeated cursor', `${base}?cursor=0&cursor=1`, 'invalid cursor'],
  ]) {
    await expectFetchJsonStatus({
      failures,
      tag,
      fetchJson,
      url,
      status: 400,
      label,
      payloadCheck: (payload) => payload?.error === error,
    });
  }
  expect(failures, tag, firstPage.schemaVersion === 1,
    `PR reachability audit schemaVersion must be 1, got ${JSON.stringify(firstPage.schemaVersion)}`);
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit payload', value: firstPage, allowed: reachabilityAuditKeys });
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit filters', value: firstPage.filters, allowed: reachabilityAuditFilterKeys });
  verifyAllowedKeys({ failures, tag, label: 'PR reachability audit totals', value: firstPage.totals, allowed: reachabilityAuditTotalsKeys });
  expect(failures, tag, firstPage.tag === tag,
    `PR reachability audit tag (${firstPage.tag}) must match release tag (${tag})`);
  expect(failures, tag, firstPage.sourceMode === 'current_db',
    `PR reachability audit sourceMode (${firstPage.sourceMode}) must be current_db`);
  expect(failures, tag, firstPage.scoredAt === scoredAt,
    `PR reachability audit scoredAt (${firstPage.scoredAt}) must match DB scored_at (${scoredAt})`);
  verifyDataFreshness({ failures, tag, dataFreshness: firstPage.dataFreshness, releaseTag: tag, scoredAt });
  expect(failures, tag, firstPage.total === rows.length,
    `PR reachability audit total (${firstPage.total}) must match DB rows (${rows.length})`);
  expect(failures, tag, firstPage.totalRows === firstPage.total,
    `PR reachability audit totalRows (${firstPage.totalRows}) must match total (${firstPage.total})`);
  expect(failures, tag, isObject(firstPage.totals),
    'PR reachability audit totals must be an object');
  expect(failures, tag, firstPage.totals?.unfilteredRows === rows.length,
    `PR reachability audit unfilteredRows (${firstPage.totals?.unfilteredRows}) must match DB rows (${rows.length})`);
  expect(failures, tag, firstPage.totals?.filteredRows === firstPage.total,
    `PR reachability audit filteredRows (${firstPage.totals?.filteredRows}) must match total (${firstPage.total})`);
  expect(failures, tag, firstPage.limit === 7,
    `PR reachability audit limit must be 7, got ${firstPage.limit}`);
  expect(failures, tag, firstPage.cursor === 0,
    `PR reachability audit cursor must be 0, got ${firstPage.cursor}`);
  expect(failures, tag, Array.isArray(firstPage.rows), 'PR reachability audit rows must be an array');
  expect(failures, tag, firstPage.rows.length <= 7,
    `PR reachability audit rows length must respect limit, got ${firstPage.rows.length}`);
  const expectedCounts = countBy(rows, (row) => row.status);
  expectJsonEqual(failures, tag, 'PR reachability audit countsByStatus must match DB rows',
    firstPage.countsByStatus ?? {}, expectedCounts);
  expectJsonEqual(failures, tag, 'PR reachability audit unfilteredCountsByStatus must match DB rows',
    firstPage.unfilteredCountsByStatus ?? {}, expectedCounts);
  expectJsonEqual(failures, tag, 'PR reachability audit filteredCountsByStatus must match countsByStatus without filters',
    firstPage.filteredCountsByStatus ?? {}, expectedCounts);
  for (const row of firstPage.rows ?? []) {
    verifyAllowedKeys({ failures, tag, label: 'PR reachability audit row', value: row, allowed: reachabilityAuditRowKeys });
    expect(failures, tag, Number.isInteger(row.number) && row.number > 0,
      `PR reachability audit row number must be positive integer, got ${row.number}`);
    expect(failures, tag, typeof row.repositoryNameWithOwner === 'string' && row.repositoryNameWithOwner.includes('/'),
      `PR reachability audit row repositoryNameWithOwner must be present, got ${row.repositoryNameWithOwner}`);
    expect(failures, tag, ['reachable', 'not_reachable', 'unknown'].includes(row.status),
      `PR reachability audit row status must be known, got ${row.status}`);
    expect(failures, tag, typeof row.method === 'string' && row.method.length > 0,
      `PR reachability audit row method must be present for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, typeof row.checkedAt === 'string' && Number.isFinite(Date.parse(row.checkedAt)),
      `PR reachability audit row checkedAt must be a timestamp for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, isObject(row.evidence),
      `PR reachability audit row evidence must be an object for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, row.evidence?.schemaVersion === 1,
      `PR reachability audit row evidence schemaVersion must be 1 for ${row.repositoryNameWithOwner}#${row.number}`);
    expect(failures, tag, knownReachabilityEvidenceReasons.has(row.evidence?.evidence),
      `PR reachability audit row evidence reason must be known for ${row.repositoryNameWithOwner}#${row.number}, got ${row.evidence?.evidence}`);
    if (row.status === 'reachable' || row.status === 'not_reachable') {
      expect(failures, tag, typeof row.tagCommitOid === 'string' && fullCommitOidRe.test(row.tagCommitOid),
        `PR reachability ${row.status} row must include full tagCommitOid for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, typeof row.mergeCommitOid === 'string' && fullCommitOidRe.test(row.mergeCommitOid),
        `PR reachability ${row.status} row must include full mergeCommitOid for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, row.method === 'git-merge-base',
        `PR reachability ${row.status} row must use git-merge-base for ${row.repositoryNameWithOwner}#${row.number}`);
      expect(failures, tag, row.evidence.evidence !== 'merge_base_error',
        `PR reachability ${row.status} row must not use merge_base_error evidence for ${row.repositoryNameWithOwner}#${row.number}`);
    }
    if (row.status === 'unknown') {
      expect(failures, tag, row.evidence.evidence !== 'merge_commit_in_release_history' && row.evidence.evidence !== 'fix_commit_in_release_history',
        `unknown PR reachability row cannot use reachable evidence for ${row.repositoryNameWithOwner}#${row.number}`);
    }
  }
  if (firstPage.total > firstPage.rows.length) {
    expect(failures, tag, Number.isInteger(firstPage.nextCursor) && firstPage.nextCursor === firstPage.rows.length,
      `PR reachability audit nextCursor (${firstPage.nextCursor}) must advance by returned rows (${firstPage.rows.length})`);
    const nextPage = await fetchJson(`${base}?limit=7&cursor=${firstPage.nextCursor}`);
    expect(failures, tag, nextPage.cursor === firstPage.nextCursor,
      `PR reachability audit next page cursor (${nextPage.cursor}) must equal requested cursor (${firstPage.nextCursor})`);
    expectNoPaginationOverlap({
      failures,
      tag,
      label: 'PR reachability audit',
      firstRows: firstPage.rows,
      nextRows: nextPage.rows,
      identity: (row) => `${String(row?.repositoryNameWithOwner ?? '').toLowerCase()}#${row?.number}`,
    });
  } else {
    expect(failures, tag, firstPage.nextCursor == null,
      `PR reachability audit nextCursor must be null at end, got ${firstPage.nextCursor}`);
  }
  const [status, statusCount] = Object.entries(expectedCounts).find(([, count]) => Number(count ?? 0) > 0) ?? [];
  if (status) {
    const page = await fetchJson(`${base}?limit=5&status=${encodeURIComponent(status)}`);
    expect(failures, tag, page.total === statusCount,
      `PR reachability audit status filter total (${page.total}) must match ${status} count (${statusCount})`);
    expect(failures, tag, page.totals?.unfilteredRows === rows.length,
      `PR reachability audit status filter unfilteredRows (${page.totals?.unfilteredRows}) must match DB rows (${rows.length})`);
    expect(failures, tag, page.totals?.filteredRows === page.total,
      `PR reachability audit status filter filteredRows (${page.totals?.filteredRows}) must match total (${page.total})`);
    expect(failures, tag, page.filteredCountsByStatus?.[status] === statusCount,
      `PR reachability audit filteredCountsByStatus.${status} (${page.filteredCountsByStatus?.[status]}) must match ${statusCount}`);
    expectJsonEqual(failures, tag, 'PR reachability audit status filter unfilteredCountsByStatus must match DB rows',
      page.unfilteredCountsByStatus ?? {}, expectedCounts);
    expect(failures, tag, (page.rows ?? []).every((row) => row.status === status),
      `PR reachability audit status filter must return only ${status} rows`);
  }
  const first = rows[0];
  if (first) {
    const pr = `${first.pr_repository_name_with_owner}#${first.pr_number}`;
    const page = await fetchJson(`${base}?limit=5&pr=${encodeURIComponent(pr)}`);
    expect(failures, tag, page.total === rows.filter((row) =>
      row.pr_repository_name_with_owner === first.pr_repository_name_with_owner &&
      Number(row.pr_number) === Number(first.pr_number)).length,
    `PR reachability audit pr filter total (${page.total}) must match DB rows for ${pr}`);
    expect(failures, tag, (page.rows ?? []).every((row) =>
      row.repositoryNameWithOwner === first.pr_repository_name_with_owner &&
      Number(row.number) === Number(first.pr_number)),
    `PR reachability audit pr filter must return only ${pr}`);
  }
}

function countBy(rows, keyFn) {
  const out = {};
  for (const row of rows) {
    const key = keyFn(row);
    out[key] = (out[key] ?? 0) + 1;
  }
  return out;
}

function expectNoPaginationOverlap({ failures, tag, label, firstRows, nextRows, identity }) {
  if (!Array.isArray(firstRows) || !Array.isArray(nextRows)) return;
  const firstIds = new Set(firstRows.map(identity).filter(Boolean));
  const repeated = nextRows.map(identity).filter((id) => id && firstIds.has(id));
  expect(failures, tag, repeated.length === 0,
    `${label} pagination must not repeat rows on adjacent pages: ${repeated.slice(0, 5).join(', ')}`);
}

function verifyComparisonSnapshot({ failures, label, snapshot }) {
  if (snapshot == null) return;
  verifyAllowedKeys({ failures, tag: label, label: 'comparison snapshot', value: snapshot, allowed: comparisonSnapshotKeys });
  expect(failures, label, typeof snapshot.id === 'number', 'comparison snapshot id must be numeric');
  expect(failures, label, typeof snapshot.sourceUrl === 'string' && snapshot.sourceUrl.length > 0,
    'comparison snapshot sourceUrl must be present');
  expect(failures, label, typeof snapshot.capturedAt === 'string' && snapshot.capturedAt.length > 0,
    'comparison snapshot capturedAt must be present');
  expect(failures, label, typeof snapshot.pageTitle === 'string',
    'comparison snapshot pageTitle must be present');
  expect(failures, label, !('source_url' in snapshot) && !('captured_at' in snapshot) && !('page_text' in snapshot),
    'comparison snapshot must use normalized camelCase fields and omit page_text');
}

async function defaultFetchJson(url) {
  const res = await fetch(url);
  if (!res.ok) {
    const body = await res.text();
    const error = new Error(`${url} returned ${res.status}${body ? `: ${body}` : ''}`);
    error.status = res.status;
    error.body = body;
    try {
      error.payload = body ? JSON.parse(body) : null;
    } catch {
      error.payload = null;
    }
    throw error;
  }
  return res.json();
}

async function expectFetchJsonStatus({ failures, tag, fetchJson, url, status, label, payloadCheck = null }) {
  try {
    await fetchJson(url);
    expect(failures, tag, false, `${label} must return HTTP ${status}`);
  } catch (error) {
    const message = String(error?.message ?? error);
    const actual = Number(error?.status ?? (/returned\s+(\d+)/.exec(message)?.[1] ?? NaN));
    expect(failures, tag, actual === status,
      `${label} returned HTTP ${Number.isFinite(actual) ? actual : 'unknown'} instead of ${status}: ${message}`);
    if (payloadCheck) {
      const payload = error?.payload ?? parseJson(error?.body, null);
      expect(failures, tag, payloadCheck(payload),
        `${label} response body must expose expected error metadata`);
    }
  }
}

async function fetchOptionalComparisonPayload({ apiBase, fetchJson, failures }) {
  try {
    return await fetchJson(`${apiBase}/api/comparison`);
  } catch (error) {
    const message = String(error?.message ?? error);
    if (/\/api\/comparison returned 404\b/.test(message)) return null;
    failures.push(`api/comparison fetch failed: ${message}`);
    return null;
  }
}

function verifyScoreAuditSummary({ failures, tag, summary }) {
  expect(failures, tag, !!summary, 'scoreAudit summary must be present');
  if (!summary) return;
  expect(failures, tag, summary.schemaVersion === scoreAuditSummarySchemaVersion,
    `scoreAudit schemaVersion must be ${scoreAuditSummarySchemaVersion}, got ${JSON.stringify(summary.schemaVersion)}`);
  expect(failures, tag, typeof summary.modelVersion === 'string' && summary.modelVersion.length > 0,
    'scoreAudit modelVersion must be present');
  expect(failures, tag, Number.isInteger(summary.promptVersion),
    'scoreAudit promptVersion must be an integer');
  expect(failures, tag, typeof summary.evidenceCoverage === 'number' && summary.evidenceCoverage >= 0 && summary.evidenceCoverage <= 1,
    `scoreAudit evidenceCoverage must be in [0,1], got ${summary.evidenceCoverage}`);
  expect(failures, tag, Number.isInteger(summary.rawIssueCount) && summary.rawIssueCount >= 0,
    `scoreAudit rawIssueCount must be a non-negative integer, got ${summary.rawIssueCount}`);
  expect(failures, tag, Number.isInteger(summary.classifiedIssueCount) && summary.classifiedIssueCount >= 0,
    `scoreAudit classifiedIssueCount must be a non-negative integer, got ${summary.classifiedIssueCount}`);
}

function verifyScoreExplanation({ failures, tag, explanation, recommended, expectedBand = null, source }) {
  expect(failures, tag, isObject(explanation), `${source} score explanation must be present`);
  if (!isObject(explanation)) return;
  expect(failures, tag, explanation.schemaVersion === scoreExplanationSchemaVersion,
    `${source} score explanation schemaVersion must be ${scoreExplanationSchemaVersion}, got ${JSON.stringify(explanation.schemaVersion)}`);
  expect(failures, tag, explanation.title === 'Why not 10?',
    `${source} score explanation title must be "Why not 10?", got ${JSON.stringify(explanation.title)}`);
  verifyScoreLedger({ failures, tag, source, ledger: explanation.scoreLedger, expectedBand });
  expect(failures, tag, isStringArray(explanation.positives) && explanation.positives.length > 0,
    `${source} score explanation positives must be a non-empty string array`);
  expect(failures, tag, isStringArray(explanation.limits) && explanation.limits.length > 0,
    `${source} score explanation limits must be a non-empty string array`);
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'positiveDetails',
    details: explanation.positiveDetails,
    expectedCodes: knownExplanationPositiveCodes,
    text: explanation.positives,
  });
  verifyExplanationDetails({
    failures,
    tag,
    source,
    label: 'limitDetails',
    details: explanation.limitDetails,
    expectedCodes: knownExplanationLimitCodes,
    text: explanation.limits,
  });
  expect(failures, tag, typeof explanation.verdict === 'string' && explanation.verdict.length > 0,
    `${source} score explanation verdict must be present`);
  if (recommended) {
    expect(failures, tag, explanation.positives.some((line) => /recommended/i.test(line)),
      `${source} recommended release explanation must include a recommended positive signal`);
  }
  expect(failures, tag, !/looks safe to install|safe target|broadly safe/i.test(explanation.verdict),
    `${source} score explanation verdict must not overclaim safety`);
  for (const line of [...explanation.positives, ...explanation.limits]) {
    expect(failures, tag, !/\.\.\.\./.test(line), `${source} score explanation lines must not contain four-dot truncation`);
  }
}

function verifyScoreLedger({ failures, tag, source, ledger, expectedBand = null }) {
  expect(failures, tag, isObject(ledger), `${source} score explanation scoreLedger must be present`);
  if (!isObject(ledger)) return;
  verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger`, value: ledger, allowed: ledgerKeys });
  expect(failures, tag, ledger.schemaVersion === 1,
    `${source} scoreLedger schemaVersion must be 1, got ${JSON.stringify(ledger.schemaVersion)}`);
  expect(failures, tag, ledger.finalScore == null || typeof ledger.finalScore === 'number',
    `${source} scoreLedger finalScore must be numeric or null`);
  expect(failures, tag, typeof ledger.status === 'string' && ledger.status.length > 0,
    `${source} scoreLedger status must be present`);
  expect(failures, tag, typeof ledger.band === 'string' && ledger.band.length > 0,
    `${source} scoreLedger band must be present`);
  if (expectedBand != null) {
    expect(failures, tag, ledger.band === expectedBand,
      `${source} scoreLedger band (${ledger.band}) must match release band (${expectedBand})`);
  }
  expect(failures, tag, Array.isArray(ledger.rows) && ledger.rows.length > 0,
    `${source} scoreLedger rows must include score components`);
  verifyScoreLedgerIdentity({ failures, tag, source, ledger });
  let subtotal = 0;
  for (const row of ledger.rows ?? []) {
    expect(failures, tag, isObject(row), `${source} scoreLedger row must be an object`);
    if (!isObject(row)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger row ${String(row.key ?? '?')}`, value: row, allowed: ledgerRowKeys });
    expect(failures, tag, typeof row.key === 'string' && row.key.length > 0,
      `${source} scoreLedger row key must be present`);
    expect(failures, tag, typeof row.label === 'string' && row.label.length > 0,
      `${source} scoreLedger row label must be present`);
    expect(failures, tag, typeof row.points === 'number' && Number.isFinite(row.points),
      `${source} scoreLedger row ${row.key} points must be numeric`);
    expect(failures, tag, ['base', 'bonus', 'penalty', 'neutral'].includes(row.kind),
      `${source} scoreLedger row ${row.key} kind must be known`);
    const expectedKind = expectedScoreLedgerRowKind(row);
    expect(failures, tag, row.kind === expectedKind,
      `${source} scoreLedger row ${row.key} kind (${row.kind}) must match expected kind (${expectedKind}) for points ${row.points}`);
    if ('metric' in row) {
      expect(failures, tag, row.metric == null || ['number', 'string'].includes(typeof row.metric),
        `${source} scoreLedger row ${row.key} metric must be null, number, or string`);
    }
    if ('note' in row) {
      expect(failures, tag, row.note == null || typeof row.note === 'string',
        `${source} scoreLedger row ${row.key} note must be null or string`);
    }
    subtotal += Number(row.points ?? 0);
  }
  subtotal = roundMetric(subtotal);
  expect(failures, tag, sameNumber(ledger.subtotalBeforeCaps, subtotal),
    `${source} scoreLedger subtotalBeforeCaps (${ledger.subtotalBeforeCaps}) must equal row total (${subtotal})`);
  let afterCaps = subtotal;
  expect(failures, tag, Array.isArray(ledger.caps), `${source} scoreLedger caps must be an array`);
  verifyScoreLedgerCapIdentity({ failures, tag, source, caps: ledger.caps ?? [] });
  for (const cap of ledger.caps ?? []) {
    expect(failures, tag, isObject(cap), `${source} scoreLedger cap must be an object`);
    if (!isObject(cap)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} scoreLedger cap ${String(cap.key ?? '?')}`, value: cap, allowed: ledgerCapKeys });
    expect(failures, tag, typeof cap.key === 'string' && cap.key.length > 0,
      `${source} scoreLedger cap key must be present`);
    expect(failures, tag, typeof cap.label === 'string' && cap.label.length > 0,
      `${source} scoreLedger cap ${cap.key} label must be present`);
    expect(failures, tag, typeof cap.ceiling === 'number' && Number.isFinite(cap.ceiling),
      `${source} scoreLedger cap ${cap.key} ceiling must be numeric`);
    expect(failures, tag, typeof cap.applied === 'boolean',
      `${source} scoreLedger cap ${cap.key} applied must be boolean`);
    expect(failures, tag, cap.reason == null || typeof cap.reason === 'string',
      `${source} scoreLedger cap ${cap.key} reason must be string`);
    const expectedAfter = roundMetric(Math.min(afterCaps, Number(cap.ceiling)));
    expect(failures, tag, sameNumber(cap.before, afterCaps),
      `${source} scoreLedger cap ${cap.key} before (${cap.before}) must equal prior score (${afterCaps})`);
    expect(failures, tag, sameNumber(cap.after, expectedAfter),
      `${source} scoreLedger cap ${cap.key} after (${cap.after}) must equal capped score (${expectedAfter})`);
    expect(failures, tag, cap.applied === (afterCaps > Number(cap.ceiling)),
      `${source} scoreLedger cap ${cap.key} applied must reflect whether it was binding`);
    afterCaps = expectedAfter;
  }
  expect(failures, tag, sameNumber(ledger.scoreAfterCaps, afterCaps),
    `${source} scoreLedger scoreAfterCaps (${ledger.scoreAfterCaps}) must equal capped subtotal (${afterCaps})`);
  if (typeof ledger.finalScore === 'number') {
    expect(failures, tag, sameNumber(ledger.finalScore, roundMetric(afterCaps)),
      `${source} scoreLedger finalScore (${ledger.finalScore}) must match scoreAfterCaps (${afterCaps})`);
  }
}

function verifyScoreLedgerIdentity({ failures, tag, source, ledger }) {
  const rows = Array.isArray(ledger.rows) ? ledger.rows.filter(isObject) : [];
  const keys = rows.map((row) => row.key);
  const duplicateKeys = keys.filter((key, index) => typeof key === 'string' && keys.indexOf(key) !== index);
  expect(failures, tag, duplicateKeys.length === 0,
    `${source} scoreLedger rows must not contain duplicate keys: ${[...new Set(duplicateKeys)].join(', ')}`);

  const componentStatus = ledger.status === 'eligible' || ledger.status === 'skip-hotfix';
  if (componentStatus) {
    const expectedKeys = componentLedgerRows.map(([key]) => key);
    const prefix = keys.slice(0, expectedKeys.length);
    expect(failures, tag, stableJson(prefix) === stableJson(expectedKeys),
      `${source} scoreLedger component row order must be ${expectedKeys.join(', ')}, got ${keys.join(', ')}`);
    const trailing = keys.slice(expectedKeys.length);
    expect(failures, tag, trailing.length === 0 || stableJson(trailing) === stableJson(['precisionAdjustment']),
      `${source} scoreLedger precisionAdjustment must be the only optional trailing row, got ${trailing.join(', ')}`);
  } else {
    expect(failures, tag, keys.length === 1 && gateLedgerLabels.has(keys[0]),
      `${source} scoreLedger gate rows must contain exactly one known gate row, got ${keys.join(', ')}`);
  }

  for (const row of rows) {
    const expectedLabel = componentLedgerLabels.get(row.key) ?? optionalLedgerLabels.get(row.key) ?? gateLedgerLabels.get(row.key);
    expect(failures, tag, !!expectedLabel,
      `${source} scoreLedger unknown row key ${JSON.stringify(row.key)}`);
    if (expectedLabel) {
      expect(failures, tag, row.label === expectedLabel,
        `${source} scoreLedger row ${row.key} label (${JSON.stringify(row.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
  }
}

function verifyScoreLedgerCapIdentity({ failures, tag, source, caps }) {
  const validCaps = Array.isArray(caps) ? caps.filter(isObject) : [];
  const keys = validCaps.map((cap) => cap.key);
  const duplicateKeys = keys.filter((key, index) => typeof key === 'string' && keys.indexOf(key) !== index);
  expect(failures, tag, duplicateKeys.length === 0,
    `${source} scoreLedger caps must not contain duplicate keys: ${[...new Set(duplicateKeys)].join(', ')}`);
  const knownCapOrder = [...ledgerCapLabels.keys()];
  let lastOrder = -1;
  for (const cap of validCaps) {
    const expectedLabel = ledgerCapLabels.get(cap.key);
    expect(failures, tag, !!expectedLabel,
      `${source} scoreLedger unknown cap key ${JSON.stringify(cap.key)}`);
    if (expectedLabel) {
      const order = knownCapOrder.indexOf(cap.key);
      expect(failures, tag, order > lastOrder,
        `${source} scoreLedger cap order must be ${knownCapOrder.join(', ')}, got ${keys.join(', ')}`);
      lastOrder = order;
      expect(failures, tag, cap.label === expectedLabel,
        `${source} scoreLedger cap ${cap.key} label (${JSON.stringify(cap.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
  }
}

function scoreLedgerKindForPoints(points) {
  if (points > 0) return 'bonus';
  if (points < 0) return 'penalty';
  if (points === 0) return 'neutral';
  return null;
}

function expectedScoreLedgerRowKind(row) {
  if (row.key === 'base') return 'base';
  if (row.key === 'cveGate') return 'penalty';
  if (row.key === 'settleGate') return 'neutral';
  return scoreLedgerKindForPoints(row.points);
}

function sameNumber(left, right) {
  return typeof left === 'number' && typeof right === 'number' && Math.abs(left - right) <= 1e-9;
}

function sameNumberOrNull(left, right) {
  if (left == null || right == null) return left == null && right == null;
  return sameNumber(Number(left), Number(right));
}

function verifyExplanationDetails({ failures, tag, source, label, details, expectedCodes, text }) {
  expect(failures, tag, Array.isArray(details),
    `${source} score explanation ${label} must be an array`);
  if (!Array.isArray(details)) return;
  expect(failures, tag, details.length === text.length,
    `${source} score explanation ${label} length (${details.length}) must match text length (${text.length})`);
  for (let idx = 0; idx < details.length; idx++) {
    const detail = details[idx];
    expect(failures, tag, isObject(detail),
      `${source} score explanation ${label}[${idx}] must be an object`);
    if (!isObject(detail)) continue;
    verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}]`, value: detail, allowed: explanationDetailKeys });
    expect(failures, tag, typeof detail.code === 'string' && /^[a-z0-9_]+$/.test(detail.code),
      `${source} score explanation ${label}[${idx}] code must be snake_case`);
    expect(failures, tag, expectedCodes.has(detail.code),
      `${source} score explanation ${label}[${idx}] code ${JSON.stringify(detail.code)} must be known for ${label}`);
    expect(failures, tag, detail.text === text[idx],
      `${source} score explanation ${label}[${idx}] text must match prose line`);
    const expectedLabel = expectedExplanationDetailLabels.get(detail.code);
    expect(failures, tag, typeof detail.label === 'string' && detail.label.length > 0,
      `${source} score explanation ${label}[${idx}] label must be present`);
    if (expectedLabel) {
      expect(failures, tag, detail.label === expectedLabel,
        `${source} score explanation ${label}[${idx}] label (${JSON.stringify(detail.label)}) must be ${JSON.stringify(expectedLabel)}`);
    }
    if ('metrics' in detail) {
      expect(failures, tag, isObject(detail.metrics),
        `${source} score explanation ${label}[${idx}] metrics must be an object when present`);
      if (isObject(detail.metrics)) {
        for (const [metricKey, value] of Object.entries(detail.metrics)) {
          expect(failures, tag, isMetricValue(value),
            `${source} score explanation ${label}[${idx}] metrics.${metricKey} must be scalar or a scalar map`);
        }
      }
    }
    if ('buckets' in detail) {
      expect(failures, tag, isObject(detail.buckets),
        `${source} score explanation ${label}[${idx}] buckets must be an object when present`);
      if (isObject(detail.buckets)) verifyNumericMap({ failures, tag, source, label, idx, field: 'buckets', value: detail.buckets });
    }
    if ('riskBuckets' in detail) {
      expect(failures, tag, isObject(detail.riskBuckets),
        `${source} score explanation ${label}[${idx}] riskBuckets must be an object when present`);
      if (isObject(detail.riskBuckets)) verifyNumericMap({ failures, tag, source, label, idx, field: 'riskBuckets', value: detail.riskBuckets });
    }
    if ('issueRefs' in detail) {
      expect(failures, tag, Array.isArray(detail.issueRefs),
        `${source} score explanation ${label}[${idx}] issueRefs must be an array when present`);
      if (Array.isArray(detail.issueRefs)) {
        for (const issue of detail.issueRefs) {
          if (isObject(issue)) {
            verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef`, value: issue, allowed: explanationIssueRefKeys });
            if (isObject(issue.proof)) verifyExplanationIssueProof({ failures, tag, source, label, idx, proof: issue.proof });
          }
          expect(failures, tag, isObject(issue) && Number.isInteger(issue.number) && issue.number > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a positive issue number`);
          expect(failures, tag, isObject(issue) && typeof issue.title === 'string' && issue.title.length > 0,
            `${source} score explanation ${label}[${idx}] issueRefs entries must include a title`);
          expect(failures, tag, isObject(issue) && (issue.url == null || typeof issue.url === 'string'),
            `${source} score explanation ${label}[${idx}] issueRefs url must be null or string`);
          expect(failures, tag, isObject(issue) && (issue.fieldConfirmed == null || typeof issue.fieldConfirmed === 'boolean'),
            `${source} score explanation ${label}[${idx}] issueRefs fieldConfirmed must be null or boolean`);
          expect(failures, tag, isObject(issue) && (issue.releaseLocal == null || typeof issue.releaseLocal === 'boolean'),
            `${source} score explanation ${label}[${idx}] issueRefs releaseLocal must be null or boolean`);
          expect(failures, tag, isObject(issue) && (issue.scoringReason == null || typeof issue.scoringReason === 'string'),
            `${source} score explanation ${label}[${idx}] issueRefs scoringReason must be null or string`);
        }
      }
    }
  }
}

function isMetricValue(value) {
  if (value == null || ['number', 'string', 'boolean'].includes(typeof value)) return true;
  if (!isObject(value)) return false;
  return Object.values(value).every((child) => child == null || ['number', 'string', 'boolean'].includes(typeof child));
}

function verifyNumericMap({ failures, tag, source, label, idx, field, value }) {
  for (const [key, count] of Object.entries(value)) {
    expect(failures, tag, typeof key === 'string' && key.length > 0,
      `${source} score explanation ${label}[${idx}] ${field} keys must be non-empty strings`);
    expect(failures, tag, typeof count === 'number' && Number.isFinite(count),
      `${source} score explanation ${label}[${idx}] ${field}.${key} must be numeric`);
  }
}

function verifyExplanationIssueProof({ failures, tag, source, label, idx, proof }) {
  verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef proof`, value: proof, allowed: explanationIssueProofKeys });
  for (const [key, value] of Object.entries(proof)) {
    if (key === 'canonicalPath' && value != null) {
      expect(failures, tag, Array.isArray(value) && value.every((item) => Number.isInteger(item) && item > 0),
        `${source} score explanation ${label}[${idx}] issueRef proof canonicalPath must contain positive issue numbers`);
    }
    if (key === 'canonicalIssue' && value != null) {
      verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value });
    }
    if (['openPrs', 'reachablePrs', 'notReachablePrs'].includes(key) && value != null) {
      expect(failures, tag, Array.isArray(value),
        `${source} score explanation ${label}[${idx}] issueRef proof ${key} must be an array`);
      if (Array.isArray(value)) {
        for (const ref of value) verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value: ref });
      }
    }
  }
}

function verifyLinkedExplanationRef({ failures, tag, source, label, idx, key, value }) {
  expect(failures, tag, isObject(value),
    `${source} score explanation ${label}[${idx}] issueRef proof ${key} entries must be objects`);
  if (!isObject(value)) return;
  verifyAllowedKeys({ failures, tag, label: `${source} score explanation ${label}[${idx}] issueRef proof ${key}`, value, allowed: explanationLinkedRefKeys });
  expect(failures, tag, Number.isInteger(value.number) && value.number > 0,
    `${source} score explanation ${label}[${idx}] issueRef proof ${key} entries must include a positive number`);
  if ('title' in value) {
    expect(failures, tag, value.title == null || typeof value.title === 'string',
      `${source} score explanation ${label}[${idx}] issueRef proof ${key} title must be null or string`);
  }
  if ('url' in value) {
    expect(failures, tag, value.url == null || typeof value.url === 'string',
      `${source} score explanation ${label}[${idx}] issueRef proof ${key} url must be null or string`);
  }
}
