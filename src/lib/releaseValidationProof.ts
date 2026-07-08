import { createHash } from 'node:crypto';

export const RELEASE_VALIDATION_PROOF_SCHEMA_VERSION = 1;
export const RELEASE_VALIDATION_FORECAST_V2_SCHEMA_VERSION = 2;
export const RELEASE_VALIDATION_OUTCOME_V2_SCHEMA_VERSION = 2;
export const RELEASE_VALIDATION_SPLIT_POLICY_CODE =
  'chronological_catalog_admission_v1';
export const RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT = 10;

const SHA256_RE = /^[0-9a-f]{64}$/;
const OID_RE = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/;
const CANONICAL_TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export type ReleaseValidationProofJsonValue =
  | null
  | boolean
  | number
  | string
  | readonly ReleaseValidationProofJsonValue[]
  | { readonly [key: string]: ReleaseValidationProofJsonValue };

export interface ReleaseValidationStableReleaseIdentity {
  readonly releaseId: string;
  readonly repository: string;
  readonly nodeId: string;
  readonly tagCommitOid: string;
  readonly publishedAt: string;
  readonly aliases: readonly string[];
}

interface EpochChainLink {
  readonly proofEpochId: string;
  readonly epochSequence: number;
  readonly previousEpochContentHash: string | null;
  readonly contentHash: string;
}

interface CohortChainLink {
  readonly proofEpochId: string;
  readonly cohortId: string;
  readonly cohortSequence: number;
  readonly previousCohortContentHash: string | null;
  readonly contentHash: string;
}

export interface ReleaseValidationProofEpoch {
  readonly kind: 'proof_epoch';
  readonly schemaVersion: 1;
  readonly proofEpochId: string;
  readonly repository: string;
  readonly recordedAt: string;
  readonly startsAt: string;
  readonly contentHash: string;
}

export interface ReleaseValidationProofEpochRetirement
  extends EpochChainLink {
  readonly kind: 'proof_epoch_retirement';
  readonly schemaVersion: 1;
  readonly retirementId: string;
  readonly epochContentHash: string;
  readonly recordedAt: string;
  readonly retiredAt: string;
  readonly reason: string;
}

export interface ReleaseValidationPolicyCell {
  readonly cellId: string;
  readonly opportunityCode: string;
  readonly horizonCode: string;
}

export interface ReleaseValidationPolicy extends EpochChainLink {
  readonly kind: 'policy';
  readonly schemaVersion: 1;
  readonly policyId: string;
  readonly policyCode: string;
  readonly policyVersion: number;
  readonly recordedAt: string;
  readonly effectiveAt: string;
  readonly retiredAt: string | null;
  readonly splitPolicyCode: string;
  readonly developmentArm: 'production' | 'calibration';
  readonly developmentReleaseCount: number;
  readonly splitPolicyHash: string;
  readonly requiredCells: readonly ReleaseValidationPolicyCell[];
  readonly requiredCellCount: number;
  readonly requiredCellOrderedHash: string;
  readonly requiredCellSetHash: string;
}

export interface ReleaseValidationCohort extends EpochChainLink {
  readonly kind: 'cohort';
  readonly schemaVersion: 1;
  readonly cohortId: string;
  readonly policyId: string;
  readonly policyContentHash: string;
  readonly modelVersion: string;
  readonly promptVersion: number;
  readonly codeRevision: string;
  readonly recordedAt: string;
  readonly startsAt: string;
  readonly retiredAt: string | null;
  readonly requiredCellIds: readonly string[];
  readonly requiredCellCount: number;
  readonly requiredCellOrderedHash: string;
  readonly requiredCellSetHash: string;
}

export interface ReleaseValidationCatalogMember {
  readonly kind: 'catalog_member';
  readonly schemaVersion: 1;
  readonly memberId: string;
  readonly observationId: string;
  readonly ordinal: number;
  readonly release: ReleaseValidationStableReleaseIdentity;
  readonly contentHash: string;
}

export interface ReleaseValidationCatalogObservation extends EpochChainLink {
  readonly kind: 'catalog_observation';
  readonly schemaVersion: 1;
  readonly observationId: string;
  readonly source: string;
  readonly observedAt: string;
  readonly exhaustive: true;
  readonly stabilized: true;
  readonly memberCount: number;
  readonly memberIdOrderedHash: string;
  readonly memberIdSetHash: string;
  readonly memberContentOrderedHash: string;
  readonly memberContentSetHash: string;
  readonly releaseIdSetHash: string;
}

export type ReleaseValidationCatalogReconciliationStatus =
  | 'added'
  | 'retained'
  | 'retired';

export interface ReleaseValidationCatalogReconciliationRow {
  readonly kind: 'catalog_reconciliation_row';
  readonly schemaVersion: 1;
  readonly reconciliationRowId: string;
  readonly reconciliationId: string;
  readonly ordinal: number;
  readonly releaseId: string;
  readonly status: ReleaseValidationCatalogReconciliationStatus;
  readonly previousMemberId: string | null;
  readonly previousMemberContentHash: string | null;
  readonly currentMemberId: string | null;
  readonly currentMemberContentHash: string | null;
  readonly retiredAt: string | null;
  readonly contentHash: string;
}

export interface ReleaseValidationCatalogReconciliation
  extends EpochChainLink {
  readonly kind: 'catalog_reconciliation';
  readonly schemaVersion: 1;
  readonly reconciliationId: string;
  readonly previousObservationId: string | null;
  readonly previousObservationContentHash: string | null;
  readonly currentObservationId: string;
  readonly currentObservationContentHash: string;
  readonly reconciledAt: string;
  readonly rowCount: number;
  readonly rowIdOrderedHash: string;
  readonly rowIdSetHash: string;
  readonly rowContentOrderedHash: string;
  readonly rowContentSetHash: string;
}

export interface ReleaseValidationObligation extends CohortChainLink {
  readonly kind: 'obligation';
  readonly schemaVersion: 1;
  readonly obligationId: string;
  readonly cellId: string;
  readonly opportunityCode: string;
  readonly horizonCode: string;
  readonly release: ReleaseValidationStableReleaseIdentity;
  readonly recordedAt: string;
  readonly opensAt: string;
  readonly closesAtExclusive: string;
  readonly outcomeDueAt: string;
  readonly catalogObservationId: string;
  readonly catalogObservationContentHash: string;
  readonly reconciliationId: string;
  readonly reconciliationContentHash: string;
}

export type ReleaseValidationSplitArm =
  | 'production'
  | 'calibration'
  | 'holdout';

export interface ReleaseValidationSplitAssignment extends CohortChainLink {
  readonly kind: 'split_assignment';
  readonly schemaVersion: 1;
  readonly assignmentId: string;
  readonly obligationId: string;
  readonly assignedAt: string;
  readonly arm: ReleaseValidationSplitArm;
  readonly splitPolicyHash: string;
  readonly seedHash: string;
}

export interface ReleaseValidationForecastV2 extends CohortChainLink {
  readonly kind: 'forecast_v2';
  readonly schemaVersion: 2;
  readonly forecastId: string;
  readonly obligationId: string;
  readonly splitAssignmentId: string;
  readonly policyId: string;
  readonly policyContentHash: string;
  readonly recordedAt: string;
  readonly latestRelease: ReleaseValidationStableReleaseIdentity;
  readonly candidates: readonly ReleaseValidationStableReleaseIdentity[];
  readonly candidateCount: number;
  readonly candidateReleaseIdOrderedHash: string;
  readonly candidateReleaseIdSetHash: string;
  readonly candidateIdentityOrderedHash: string;
  readonly selectedReleaseId: string | null;
  readonly forecast: ReleaseValidationProofJsonValue;
}

export type ReleaseValidationOutcomeStatus =
  | 'safe'
  | 'adverse'
  | 'censored';

export interface ReleaseValidationOutcomeV2 extends CohortChainLink {
  readonly kind: 'outcome_v2';
  readonly schemaVersion: 2;
  readonly outcomeId: string;
  readonly forecastId: string;
  readonly obligationId: string;
  readonly cellId: string;
  readonly releaseId: string;
  readonly observedAt: string;
  readonly status: ReleaseValidationOutcomeStatus;
  readonly evidenceContentHashes: readonly string[];
  readonly evidenceCount: number;
  readonly evidenceOrderedHash: string;
  readonly evidenceSetHash: string;
  readonly outcome: ReleaseValidationProofJsonValue;
}

export type ReleaseValidationObservationBatchDisposition =
  | 'observed'
  | 'pending';

export interface ReleaseValidationObservationBatchCell {
  readonly batchCellId: string;
  readonly obligationId: string;
  readonly forecastId: string;
  readonly outcomeId: string | null;
  readonly disposition: ReleaseValidationObservationBatchDisposition;
}

export interface ReleaseValidationObservationBatch extends CohortChainLink {
  readonly kind: 'observation_batch';
  readonly schemaVersion: 1;
  readonly batchId: string;
  readonly observedAt: string;
  readonly sourceIdentityHash: string;
  readonly expectedObligationIds: readonly string[];
  readonly expectedObligationCount: number;
  readonly expectedObligationOrderedHash: string;
  readonly expectedObligationSetHash: string;
  readonly cells: readonly ReleaseValidationObservationBatchCell[];
  readonly cellCount: number;
  readonly cellOrderedHash: string;
  readonly cellSetHash: string;
  readonly cellObligationSetHash: string;
}

export type ReleaseValidationEvaluationStatus =
  | 'validated'
  | 'insufficient'
  | 'measurable_but_failed';

export interface ReleaseValidationEvaluationReceipt extends EpochChainLink {
  readonly kind: 'evaluation_receipt';
  readonly schemaVersion: 1;
  readonly evaluationId: string;
  readonly evaluatedAt: string;
  readonly status: ReleaseValidationEvaluationStatus;
  readonly cohortIds: readonly string[];
  readonly cohortCount: number;
  readonly cohortOrderedHash: string;
  readonly cohortSetHash: string;
  readonly requiredCellKeys: readonly string[];
  readonly requiredCellCount: number;
  readonly requiredCellOrderedHash: string;
  readonly requiredCellSetHash: string;
  readonly observationBatchIds: readonly string[];
  readonly observationBatchCount: number;
  readonly observationBatchSetHash: string;
  readonly outcomeIds: readonly string[];
  readonly outcomeCount: number;
  readonly outcomeSetHash: string;
  readonly metrics: ReleaseValidationProofJsonValue;
}

export type ReleaseValidationPromotionEnvironment =
  | 'production'
  | 'calibration';

export interface ReleaseValidationPromotionReceipt extends EpochChainLink {
  readonly kind: 'promotion_receipt';
  readonly schemaVersion: 1;
  readonly promotionId: string;
  readonly environment: ReleaseValidationPromotionEnvironment;
  readonly promotedAt: string;
  readonly evaluationId: string;
  readonly evaluationContentHash: string;
  readonly cohortIds: readonly string[];
  readonly cohortCount: number;
  readonly cohortSetHash: string;
  readonly forecastIds: readonly string[];
  readonly forecastCount: number;
  readonly forecastSetHash: string;
  readonly outcomeIds: readonly string[];
  readonly outcomeCount: number;
  readonly outcomeSetHash: string;
  readonly sourceProofHash: string;
  readonly destinationProofHash: string;
}

export interface ReleaseValidationProofBundle {
  readonly epochs: readonly ReleaseValidationProofEpoch[];
  readonly retirements: readonly ReleaseValidationProofEpochRetirement[];
  readonly policies: readonly ReleaseValidationPolicy[];
  readonly cohorts: readonly ReleaseValidationCohort[];
  readonly catalogObservations: readonly ReleaseValidationCatalogObservation[];
  readonly catalogMembers: readonly ReleaseValidationCatalogMember[];
  readonly catalogReconciliations:
    readonly ReleaseValidationCatalogReconciliation[];
  readonly catalogReconciliationRows:
    readonly ReleaseValidationCatalogReconciliationRow[];
  readonly obligations: readonly ReleaseValidationObligation[];
  readonly splitAssignments: readonly ReleaseValidationSplitAssignment[];
  readonly forecasts: readonly ReleaseValidationForecastV2[];
  readonly outcomes: readonly ReleaseValidationOutcomeV2[];
  readonly observationBatches: readonly ReleaseValidationObservationBatch[];
  readonly evaluationReceipts: readonly ReleaseValidationEvaluationReceipt[];
  readonly promotionReceipts: readonly ReleaseValidationPromotionReceipt[];
}

export interface ReleaseValidationProofVerification {
  readonly valid: boolean;
  readonly problems: readonly string[];
  readonly epochChainTips: Readonly<Record<string, string | null>>;
  readonly cohortChainTips: Readonly<Record<string, string | null>>;
}

export class ReleaseValidationProofValidationError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Invalid release validation proof: ${problems.join('; ')}`);
    this.name = 'ReleaseValidationProofValidationError';
    this.problems = [...problems];
  }
}

export function canonicalReleaseValidationProofJson(value: unknown): string {
  const canonical = canonicalValue(value, new WeakSet<object>(), '$');
  const serialized = JSON.stringify(canonical);
  if (serialized === undefined) {
    throw new Error('Canonical release validation proof JSON cannot encode this value');
  }
  return serialized;
}

export function releaseValidationProofHash(
  domain: string,
  value: unknown,
): string {
  const normalizedDomain = requiredToken(domain, 'hash domain');
  return sha256(
    `${normalizedDomain}\0${canonicalReleaseValidationProofJson(value)}`,
  );
}

export function releaseValidationProofOrderedHash(
  domain: string,
  values: readonly string[],
): string {
  const normalized = normalizedUniqueStrings(values, `${domain} ordered values`);
  return releaseValidationProofHash(`${domain}-ordered`, normalized);
}

export function releaseValidationProofExactSetHash(
  domain: string,
  values: readonly string[],
): string {
  const normalized = normalizedUniqueStrings(values, `${domain} set values`);
  return releaseValidationProofHash(
    `${domain}-set`,
    normalized.slice().sort((left, right) => left.localeCompare(right)),
  );
}

export function releaseValidationSplitPolicyHash(input: {
  splitPolicyCode: string;
  developmentArm: 'production' | 'calibration';
  developmentReleaseCount: number;
}): string {
  const splitPolicyCode = requiredToken(
    input.splitPolicyCode,
    'splitPolicyCode',
  );
  if (!['production', 'calibration'].includes(input.developmentArm)) {
    throw new Error('Validation development arm is invalid');
  }
  const developmentReleaseCount = nonNegativeInteger(
    input.developmentReleaseCount,
    'developmentReleaseCount',
  );
  return releaseValidationProofHash(
    'release-validation-split-policy-v1',
    {
      splitPolicyCode,
      developmentArm: input.developmentArm,
      developmentReleaseCount,
    },
  );
}

export function releaseValidationSplitSeedHash(input: {
  proofEpochId: string;
  cohortId: string;
  releaseId: string;
  admissionOrdinal: number;
  splitPolicyHash: string;
}): string {
  return releaseValidationProofHash(
    'release-validation-split-seed-v1',
    {
      proofEpochId: requiredSha256(input.proofEpochId, 'proofEpochId'),
      cohortId: requiredSha256(input.cohortId, 'cohortId'),
      releaseId: requiredSha256(input.releaseId, 'releaseId'),
      admissionOrdinal: positiveInteger(
        input.admissionOrdinal,
        'admissionOrdinal',
      ),
      splitPolicyHash: requiredSha256(
        input.splitPolicyHash,
        'splitPolicyHash',
      ),
    },
  );
}

export function normalizeReleaseValidationProofTimestamp(
  value: string,
  label = 'timestamp',
): string {
  const text = requiredToken(value, label);
  const timestamp = Date.parse(text);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} must be a valid timestamp`);
  }
  return new Date(timestamp).toISOString();
}

export function normalizeReleaseValidationProofOid(
  value: string,
  label = 'OID',
): string {
  const normalized = requiredToken(value, label).toLowerCase();
  if (!OID_RE.test(normalized)) {
    throw new Error(`${label} must be a 40- or 64-character hexadecimal OID`);
  }
  return normalized;
}

export function normalizeReleaseValidationRepository(
  value: string,
): string {
  const normalized = requiredToken(value, 'repository').toLowerCase();
  if (!/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/.test(normalized)) {
    throw new Error('repository must be a canonical owner/name pair');
  }
  return normalized;
}

export function releaseValidationStableReleaseId(input: {
  repository: string;
  nodeId: string;
  tagCommitOid: string;
  publishedAt: string;
  aliases?: readonly string[];
}): string {
  return releaseValidationProofHash('release-validation-stable-release-id-v1', {
    repository: normalizeReleaseValidationRepository(input.repository),
    nodeId: requiredToken(input.nodeId, 'release nodeId'),
    tagCommitOid: normalizeReleaseValidationProofOid(input.tagCommitOid),
    publishedAt: normalizeReleaseValidationProofTimestamp(
      input.publishedAt,
      'release publishedAt',
    ),
  });
}

export function createReleaseValidationStableReleaseIdentity(input: {
  repository: string;
  nodeId: string;
  tagCommitOid: string;
  publishedAt: string;
  aliases?: readonly string[];
}): ReleaseValidationStableReleaseIdentity {
  const repository = normalizeReleaseValidationRepository(input.repository);
  const nodeId = requiredToken(input.nodeId, 'release nodeId');
  const tagCommitOid = normalizeReleaseValidationProofOid(input.tagCommitOid);
  const publishedAt = normalizeReleaseValidationProofTimestamp(
    input.publishedAt,
    'release publishedAt',
  );
  const aliases = normalizedAliases(input.aliases ?? []);
  return {
    releaseId: releaseValidationStableReleaseId({
      repository,
      nodeId,
      tagCommitOid,
      publishedAt,
    }),
    repository,
    nodeId,
    tagCommitOid,
    publishedAt,
    aliases,
  };
}

export function sealReleaseValidationProofEpoch(input: {
  repository: string;
  recordedAt: string;
  startsAt: string;
}): ReleaseValidationProofEpoch {
  const repository = normalizeReleaseValidationRepository(input.repository);
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'epoch recordedAt',
  );
  const startsAt = normalizeReleaseValidationProofTimestamp(
    input.startsAt,
    'epoch startsAt',
  );
  if (Date.parse(startsAt) < Date.parse(recordedAt)) {
    throw new Error('Proof epoch cannot start before it is recorded');
  }
  const proofEpochId = releaseValidationProofHash(
    'release-validation-proof-epoch-id-v1',
    { repository, startsAt },
  );
  const row = {
    kind: 'proof_epoch' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    proofEpochId,
    repository,
    recordedAt,
    startsAt,
  };
  return {
    ...row,
    contentHash: releaseValidationProofEpochContentHash(row),
  };
}

export function releaseValidationProofEpochContentHash(
  row: Omit<ReleaseValidationProofEpoch, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-proof-epoch-v1',
    row,
  );
}

export function sealReleaseValidationProofEpochRetirement(input: {
  proofEpochId: string;
  epochContentHash: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  recordedAt: string;
  retiredAt: string;
  reason: string;
}): ReleaseValidationProofEpochRetirement {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const epochContentHash = requiredSha256(
    input.epochContentHash,
    'epochContentHash',
  );
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'retirement recordedAt',
  );
  const retiredAt = normalizeReleaseValidationProofTimestamp(
    input.retiredAt,
    'retiredAt',
  );
  if (Date.parse(retiredAt) < Date.parse(recordedAt)) {
    throw new Error('Proof epoch retirement cannot be backdated');
  }
  const reason = requiredToken(input.reason, 'retirement reason');
  const retirementId = releaseValidationProofHash(
    'release-validation-proof-epoch-retirement-id-v1',
    { proofEpochId, retiredAt },
  );
  const row = {
    kind: 'proof_epoch_retirement' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    retirementId,
    proofEpochId,
    epochContentHash,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    recordedAt,
    retiredAt,
    reason,
  };
  return {
    ...row,
    contentHash: releaseValidationProofEpochRetirementContentHash(row),
  };
}

export function releaseValidationProofEpochRetirementContentHash(
  row: Omit<ReleaseValidationProofEpochRetirement, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-proof-epoch-retirement-v1',
    row,
  );
}

export function releaseValidationPolicyCell(input: {
  opportunityCode: string;
  horizonCode: string;
}): ReleaseValidationPolicyCell {
  const opportunityCode = requiredToken(
    input.opportunityCode,
    'opportunityCode',
  );
  const horizonCode = requiredToken(input.horizonCode, 'horizonCode');
  return {
    cellId: releaseValidationProofHash(
      'release-validation-policy-cell-id-v1',
      { opportunityCode, horizonCode },
    ),
    opportunityCode,
    horizonCode,
  };
}

export function sealReleaseValidationPolicy(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  policyCode: string;
  policyVersion: number;
  recordedAt: string;
  effectiveAt: string;
  retiredAt?: string | null;
  splitPolicyCode?: string;
  developmentArm?: 'production' | 'calibration';
  developmentReleaseCount?: number;
  requiredCells: readonly {
    opportunityCode: string;
    horizonCode: string;
  }[];
}): ReleaseValidationPolicy {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const policyCode = requiredToken(input.policyCode, 'policyCode');
  const policyVersion = positiveInteger(
    input.policyVersion,
    'policyVersion',
  );
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'policy recordedAt',
  );
  const effectiveAt = normalizeReleaseValidationProofTimestamp(
    input.effectiveAt,
    'policy effectiveAt',
  );
  if (Date.parse(effectiveAt) < Date.parse(recordedAt)) {
    throw new Error('Validation policy cannot be effective before it is recorded');
  }
  const retiredAt = normalizedOptionalTimestamp(
    input.retiredAt,
    'policy retiredAt',
  );
  if (retiredAt && Date.parse(retiredAt) < Date.parse(effectiveAt)) {
    throw new Error('Validation policy retirement cannot predate activation');
  }
  const splitPolicyCode = requiredToken(
    input.splitPolicyCode ?? RELEASE_VALIDATION_SPLIT_POLICY_CODE,
    'splitPolicyCode',
  );
  const developmentArm = input.developmentArm ?? 'production';
  const developmentReleaseCount = nonNegativeInteger(
    input.developmentReleaseCount ??
      RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
    'developmentReleaseCount',
  );
  const splitPolicyHash = releaseValidationSplitPolicyHash({
    splitPolicyCode,
    developmentArm,
    developmentReleaseCount,
  });
  const requiredCells = input.requiredCells.map(releaseValidationPolicyCell);
  if (requiredCells.length === 0) {
    throw new Error('Validation policy requires at least one cell');
  }
  const cellIds = requiredCells.map((cell) => cell.cellId);
  assertUnique(cellIds, 'validation policy cell');
  const requiredCellOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-policy-required-cells-v1',
    cellIds,
  );
  const requiredCellSetHash = releaseValidationProofExactSetHash(
    'release-validation-policy-required-cells-v1',
    cellIds,
  );
  const policyId = releaseValidationProofHash(
    'release-validation-policy-id-v1',
    { proofEpochId, policyCode, policyVersion, effectiveAt },
  );
  const row = {
    kind: 'policy' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    policyId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    policyCode,
    policyVersion,
    recordedAt,
    effectiveAt,
    retiredAt,
    splitPolicyCode,
    developmentArm,
    developmentReleaseCount,
    splitPolicyHash,
    requiredCells,
    requiredCellCount: requiredCells.length,
    requiredCellOrderedHash,
    requiredCellSetHash,
  };
  return {
    ...row,
    contentHash: releaseValidationPolicyContentHash(row),
  };
}

export function releaseValidationPolicyContentHash(
  row: Omit<ReleaseValidationPolicy, 'contentHash'>,
): string {
  return releaseValidationProofHash('release-validation-policy-v1', row);
}

export function sealReleaseValidationCohort(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  policyId: string;
  policyContentHash: string;
  modelVersion: string;
  promptVersion: number;
  codeRevision: string;
  recordedAt: string;
  startsAt: string;
  retiredAt?: string | null;
  requiredCellIds: readonly string[];
}): ReleaseValidationCohort {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const policyId = requiredSha256(input.policyId, 'policyId');
  const policyContentHash = requiredSha256(
    input.policyContentHash,
    'policyContentHash',
  );
  const modelVersion = requiredToken(input.modelVersion, 'modelVersion');
  const promptVersion = nonNegativeInteger(
    input.promptVersion,
    'promptVersion',
  );
  const codeRevision = requiredToken(input.codeRevision, 'codeRevision');
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'cohort recordedAt',
  );
  const startsAt = normalizeReleaseValidationProofTimestamp(
    input.startsAt,
    'cohort startsAt',
  );
  if (Date.parse(startsAt) < Date.parse(recordedAt)) {
    throw new Error('Validation cohort cannot start before it is recorded');
  }
  const retiredAt = normalizedOptionalTimestamp(
    input.retiredAt,
    'cohort retiredAt',
  );
  if (retiredAt && Date.parse(retiredAt) < Date.parse(startsAt)) {
    throw new Error('Validation cohort retirement cannot predate its start');
  }
  const requiredCellIds = input.requiredCellIds.map((value) =>
    requiredSha256(value, 'requiredCellId'));
  if (requiredCellIds.length === 0) {
    throw new Error('Validation cohort requires at least one policy cell');
  }
  assertUnique(requiredCellIds, 'validation cohort cell');
  const requiredCellOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-policy-required-cells-v1',
    requiredCellIds,
  );
  const requiredCellSetHash = releaseValidationProofExactSetHash(
    'release-validation-policy-required-cells-v1',
    requiredCellIds,
  );
  const cohortId = releaseValidationProofHash(
    'release-validation-cohort-id-v1',
    {
      proofEpochId,
      policyId,
      policyContentHash,
      modelVersion,
      promptVersion,
      codeRevision,
      startsAt,
    },
  );
  const row = {
    kind: 'cohort' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    cohortId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    policyId,
    policyContentHash,
    modelVersion,
    promptVersion,
    codeRevision,
    recordedAt,
    startsAt,
    retiredAt,
    requiredCellIds,
    requiredCellCount: requiredCellIds.length,
    requiredCellOrderedHash,
    requiredCellSetHash,
  };
  return {
    ...row,
    contentHash: releaseValidationCohortContentHash(row),
  };
}

export function releaseValidationCohortContentHash(
  row: Omit<ReleaseValidationCohort, 'contentHash'>,
): string {
  return releaseValidationProofHash('release-validation-cohort-v1', row);
}

export function releaseValidationCatalogObservationId(input: {
  proofEpochId: string;
  source: string;
  observedAt: string;
}): string {
  return releaseValidationProofHash(
    'release-validation-catalog-observation-id-v1',
    {
      proofEpochId: requiredSha256(input.proofEpochId, 'proofEpochId'),
      source: requiredToken(input.source, 'catalog source'),
      observedAt: normalizeReleaseValidationProofTimestamp(
        input.observedAt,
        'catalog observedAt',
      ),
    },
  );
}

export function sealReleaseValidationCatalogMember(input: {
  observationId: string;
  ordinal: number;
  release: {
    repository: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases?: readonly string[];
  };
}): ReleaseValidationCatalogMember {
  const observationId = requiredSha256(
    input.observationId,
    'observationId',
  );
  const ordinal = nonNegativeInteger(input.ordinal, 'catalog member ordinal');
  const release = createReleaseValidationStableReleaseIdentity(input.release);
  const memberId = releaseValidationProofHash(
    'release-validation-catalog-member-id-v1',
    { observationId, ordinal, releaseId: release.releaseId },
  );
  const row = {
    kind: 'catalog_member' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    memberId,
    observationId,
    ordinal,
    release,
  };
  return {
    ...row,
    contentHash: releaseValidationCatalogMemberContentHash(row),
  };
}

export function releaseValidationCatalogMemberContentHash(
  row: Omit<ReleaseValidationCatalogMember, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-catalog-member-v1',
    row,
  );
}

export function sealReleaseValidationCatalogObservation(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  source: string;
  observedAt: string;
  exhaustive: true;
  stabilized: true;
  releases: readonly {
    repository: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases?: readonly string[];
  }[];
}): {
  observation: ReleaseValidationCatalogObservation;
  members: readonly ReleaseValidationCatalogMember[];
} {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const source = requiredToken(input.source, 'catalog source');
  const observedAt = normalizeReleaseValidationProofTimestamp(
    input.observedAt,
    'catalog observedAt',
  );
  if (input.exhaustive !== true || input.stabilized !== true) {
    throw new Error('Catalog observation must be exhaustive and stabilized');
  }
  const observationId = releaseValidationCatalogObservationId({
    proofEpochId,
    source,
    observedAt,
  });
  const members = input.releases.map((release, ordinal) =>
    sealReleaseValidationCatalogMember({ observationId, ordinal, release }));
  assertCatalogMemberUniqueness(members);
  if (members.some((member) =>
    Date.parse(member.release.publishedAt) > Date.parse(observedAt))) {
    throw new Error('Catalog observation cannot contain a future release');
  }
  const memberIds = members.map((member) => member.memberId);
  const memberContentHashes = members.map((member) => member.contentHash);
  const releaseIds = members.map((member) => member.release.releaseId);
  const row = {
    kind: 'catalog_observation' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    observationId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    source,
    observedAt,
    exhaustive: true as const,
    stabilized: true as const,
    memberCount: members.length,
    memberIdOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-member-ids-v1',
      memberIds,
    ),
    memberIdSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-member-ids-v1',
      memberIds,
    ),
    memberContentOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    memberContentSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    releaseIdSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-release-ids-v1',
      releaseIds,
    ),
  };
  return {
    observation: {
      ...row,
      contentHash: releaseValidationCatalogObservationContentHash(row),
    },
    members,
  };
}

export function releaseValidationCatalogObservationContentHash(
  row: Omit<ReleaseValidationCatalogObservation, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-catalog-observation-v1',
    row,
  );
}

export function sealReleaseValidationCatalogReconciliation(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  reconciledAt: string;
  previousObservation: ReleaseValidationCatalogObservation | null;
  previousMembers?: readonly ReleaseValidationCatalogMember[];
  currentObservation: ReleaseValidationCatalogObservation;
  currentMembers: readonly ReleaseValidationCatalogMember[];
}): {
  reconciliation: ReleaseValidationCatalogReconciliation;
  rows: readonly ReleaseValidationCatalogReconciliationRow[];
} {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const reconciledAt = normalizeReleaseValidationProofTimestamp(
    input.reconciledAt,
    'catalog reconciledAt',
  );
  if (
    input.currentObservation.proofEpochId !== proofEpochId ||
    (input.previousObservation != null &&
      input.previousObservation.proofEpochId !== proofEpochId)
  ) {
    throw new Error('Catalog reconciliation observations must share the proof epoch');
  }
  assertCatalogObservationMembers(
    input.currentObservation,
    input.currentMembers,
  );
  const previousMembers = input.previousMembers ?? [];
  if (input.previousObservation) {
    assertCatalogObservationMembers(input.previousObservation, previousMembers);
  } else if (previousMembers.length > 0) {
    throw new Error('Initial catalog reconciliation cannot have previous members');
  }
  if (Date.parse(reconciledAt) < Date.parse(input.currentObservation.observedAt)) {
    throw new Error('Catalog reconciliation cannot predate its current observation');
  }
  const reconciliationId = releaseValidationProofHash(
    'release-validation-catalog-reconciliation-id-v1',
    {
      proofEpochId,
      previousObservationId: input.previousObservation?.observationId ?? null,
      currentObservationId: input.currentObservation.observationId,
      reconciledAt,
    },
  );
  const rows = buildReconciliationRows({
    reconciliationId,
    reconciledAt,
    previousMembers,
    currentMembers: input.currentMembers,
  });
  const rowIds = rows.map((row) => row.reconciliationRowId);
  const rowContentHashes = rows.map((row) => row.contentHash);
  const row = {
    kind: 'catalog_reconciliation' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    reconciliationId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    previousObservationId:
      input.previousObservation?.observationId ?? null,
    previousObservationContentHash:
      input.previousObservation?.contentHash ?? null,
    currentObservationId: input.currentObservation.observationId,
    currentObservationContentHash: input.currentObservation.contentHash,
    reconciledAt,
    rowCount: rows.length,
    rowIdOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-reconciliation-row-ids-v1',
      rowIds,
    ),
    rowIdSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-reconciliation-row-ids-v1',
      rowIds,
    ),
    rowContentOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-reconciliation-row-content-v1',
      rowContentHashes,
    ),
    rowContentSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-reconciliation-row-content-v1',
      rowContentHashes,
    ),
  };
  return {
    reconciliation: {
      ...row,
      contentHash: releaseValidationCatalogReconciliationContentHash(row),
    },
    rows,
  };
}

export function releaseValidationCatalogReconciliationRowContentHash(
  row: Omit<ReleaseValidationCatalogReconciliationRow, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-catalog-reconciliation-row-v1',
    row,
  );
}

export function releaseValidationCatalogReconciliationContentHash(
  row: Omit<ReleaseValidationCatalogReconciliation, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-catalog-reconciliation-v1',
    row,
  );
}

export function sealReleaseValidationObligation(input: {
  proofEpochId: string;
  cohortId: string;
  cohortSequence: number;
  previousCohortContentHash: string | null;
  cellId: string;
  opportunityCode: string;
  horizonCode: string;
  release: {
    repository: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases?: readonly string[];
  };
  recordedAt: string;
  opensAt: string;
  closesAtExclusive: string;
  outcomeDueAt: string;
  catalogObservationId: string;
  catalogObservationContentHash: string;
  reconciliationId: string;
  reconciliationContentHash: string;
}): ReleaseValidationObligation {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const cohortId = requiredSha256(input.cohortId, 'cohortId');
  const cellId = requiredSha256(input.cellId, 'cellId');
  const opportunityCode = requiredToken(
    input.opportunityCode,
    'opportunityCode',
  );
  const horizonCode = requiredToken(input.horizonCode, 'horizonCode');
  const expectedCell = releaseValidationPolicyCell({
    opportunityCode,
    horizonCode,
  });
  if (expectedCell.cellId !== cellId) {
    throw new Error('Obligation cell identity does not match its policy coordinates');
  }
  const release = createReleaseValidationStableReleaseIdentity(input.release);
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'obligation recordedAt',
  );
  const opensAt = normalizeReleaseValidationProofTimestamp(
    input.opensAt,
    'obligation opensAt',
  );
  const closesAtExclusive = normalizeReleaseValidationProofTimestamp(
    input.closesAtExclusive,
    'obligation closesAtExclusive',
  );
  const outcomeDueAt = normalizeReleaseValidationProofTimestamp(
    input.outcomeDueAt,
    'obligation outcomeDueAt',
  );
  if (
    Date.parse(release.publishedAt) > Date.parse(recordedAt) ||
    Date.parse(opensAt) < Date.parse(release.publishedAt) ||
    Date.parse(closesAtExclusive) <= Date.parse(opensAt) ||
    Date.parse(outcomeDueAt) < Date.parse(closesAtExclusive)
  ) {
    throw new Error('Obligation chronology is invalid');
  }
  const obligationId = releaseValidationProofHash(
    'release-validation-obligation-id-v1',
    { cohortId, releaseId: release.releaseId, cellId },
  );
  const row = {
    kind: 'obligation' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    obligationId,
    proofEpochId,
    cohortId,
    cohortSequence: positiveInteger(
      input.cohortSequence,
      'cohortSequence',
    ),
    previousCohortContentHash: optionalSha256(
      input.previousCohortContentHash,
      'previousCohortContentHash',
    ),
    cellId,
    opportunityCode,
    horizonCode,
    release,
    recordedAt,
    opensAt,
    closesAtExclusive,
    outcomeDueAt,
    catalogObservationId: requiredSha256(
      input.catalogObservationId,
      'catalogObservationId',
    ),
    catalogObservationContentHash: requiredSha256(
      input.catalogObservationContentHash,
      'catalogObservationContentHash',
    ),
    reconciliationId: requiredSha256(
      input.reconciliationId,
      'reconciliationId',
    ),
    reconciliationContentHash: requiredSha256(
      input.reconciliationContentHash,
      'reconciliationContentHash',
    ),
  };
  return {
    ...row,
    contentHash: releaseValidationObligationContentHash(row),
  };
}

export function releaseValidationObligationContentHash(
  row: Omit<ReleaseValidationObligation, 'contentHash'>,
): string {
  return releaseValidationProofHash('release-validation-obligation-v1', row);
}

export function sealReleaseValidationSplitAssignment(input: {
  proofEpochId: string;
  cohortId: string;
  cohortSequence: number;
  previousCohortContentHash: string | null;
  obligationId: string;
  assignedAt: string;
  arm: ReleaseValidationSplitArm;
  splitPolicyHash: string;
  seedHash: string;
}): ReleaseValidationSplitAssignment {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const cohortId = requiredSha256(input.cohortId, 'cohortId');
  const obligationId = requiredSha256(input.obligationId, 'obligationId');
  const assignedAt = normalizeReleaseValidationProofTimestamp(
    input.assignedAt,
    'split assignedAt',
  );
  if (!['production', 'calibration', 'holdout'].includes(input.arm)) {
    throw new Error('Split assignment arm is invalid');
  }
  const splitPolicyHash = requiredSha256(
    input.splitPolicyHash,
    'splitPolicyHash',
  );
  const seedHash = requiredSha256(input.seedHash, 'seedHash');
  const assignmentId = releaseValidationProofHash(
    'release-validation-split-assignment-id-v1',
    { cohortId, obligationId, splitPolicyHash, seedHash },
  );
  const row = {
    kind: 'split_assignment' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    assignmentId,
    proofEpochId,
    cohortId,
    cohortSequence: positiveInteger(
      input.cohortSequence,
      'cohortSequence',
    ),
    previousCohortContentHash: optionalSha256(
      input.previousCohortContentHash,
      'previousCohortContentHash',
    ),
    obligationId,
    assignedAt,
    arm: input.arm,
    splitPolicyHash,
    seedHash,
  };
  return {
    ...row,
    contentHash: releaseValidationSplitAssignmentContentHash(row),
  };
}

export function releaseValidationSplitAssignmentContentHash(
  row: Omit<ReleaseValidationSplitAssignment, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-split-assignment-v1',
    row,
  );
}

export function sealReleaseValidationForecastV2(input: {
  proofEpochId: string;
  cohortId: string;
  cohortSequence: number;
  previousCohortContentHash: string | null;
  obligationId: string;
  splitAssignmentId: string;
  policyId: string;
  policyContentHash: string;
  recordedAt: string;
  latestRelease: {
    repository: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases?: readonly string[];
  };
  candidates: readonly {
    repository: string;
    nodeId: string;
    tagCommitOid: string;
    publishedAt: string;
    aliases?: readonly string[];
  }[];
  selectedReleaseId: string | null;
  forecast: ReleaseValidationProofJsonValue;
}): ReleaseValidationForecastV2 {
  canonicalReleaseValidationProofJson(input.forecast);
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const cohortId = requiredSha256(input.cohortId, 'cohortId');
  const obligationId = requiredSha256(input.obligationId, 'obligationId');
  const splitAssignmentId = requiredSha256(
    input.splitAssignmentId,
    'splitAssignmentId',
  );
  const policyId = requiredSha256(input.policyId, 'policyId');
  const policyContentHash = requiredSha256(
    input.policyContentHash,
    'policyContentHash',
  );
  const recordedAt = normalizeReleaseValidationProofTimestamp(
    input.recordedAt,
    'forecast recordedAt',
  );
  const latestRelease =
    createReleaseValidationStableReleaseIdentity(input.latestRelease);
  const candidates = input.candidates.map(
    createReleaseValidationStableReleaseIdentity,
  );
  if (candidates.length === 0) {
    throw new Error('Forecast v2 requires at least one candidate release');
  }
  const candidateReleaseIds = candidates.map((release) => release.releaseId);
  assertUnique(candidateReleaseIds, 'forecast candidate release');
  const selectedReleaseId = input.selectedReleaseId == null
    ? null
    : requiredSha256(input.selectedReleaseId, 'selectedReleaseId');
  if (selectedReleaseId && !candidateReleaseIds.includes(selectedReleaseId)) {
    throw new Error('Forecast selected release is absent from its exact candidate set');
  }
  const candidateIdentityHashes = candidates.map((release) =>
    releaseValidationProofHash(
      'release-validation-forecast-candidate-identity-v1',
      release,
    ));
  const candidateReleaseIdOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-forecast-candidate-release-ids-v2',
    candidateReleaseIds,
  );
  const candidateReleaseIdSetHash = releaseValidationProofExactSetHash(
    'release-validation-forecast-candidate-release-ids-v2',
    candidateReleaseIds,
  );
  const candidateIdentityOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-forecast-candidate-identities-v2',
    candidateIdentityHashes,
  );
  const forecastId = releaseValidationProofHash(
    'release-validation-forecast-id-v2',
    {
      cohortId,
      obligationId,
      splitAssignmentId,
      policyId,
      recordedAt,
    },
  );
  const row = {
    kind: 'forecast_v2' as const,
    schemaVersion: RELEASE_VALIDATION_FORECAST_V2_SCHEMA_VERSION as 2,
    forecastId,
    proofEpochId,
    cohortId,
    cohortSequence: positiveInteger(
      input.cohortSequence,
      'cohortSequence',
    ),
    previousCohortContentHash: optionalSha256(
      input.previousCohortContentHash,
      'previousCohortContentHash',
    ),
    obligationId,
    splitAssignmentId,
    policyId,
    policyContentHash,
    recordedAt,
    latestRelease,
    candidates,
    candidateCount: candidates.length,
    candidateReleaseIdOrderedHash,
    candidateReleaseIdSetHash,
    candidateIdentityOrderedHash,
    selectedReleaseId,
    forecast: input.forecast,
  };
  return {
    ...row,
    contentHash: releaseValidationForecastV2ContentHash(row),
  };
}

export function releaseValidationForecastV2ContentHash(
  row: Omit<ReleaseValidationForecastV2, 'contentHash'>,
): string {
  return releaseValidationProofHash('release-validation-forecast-v2', row);
}

export function sealReleaseValidationOutcomeV2(input: {
  proofEpochId: string;
  cohortId: string;
  cohortSequence: number;
  previousCohortContentHash: string | null;
  forecastId: string;
  obligationId: string;
  cellId: string;
  releaseId: string;
  observedAt: string;
  status: ReleaseValidationOutcomeStatus;
  evidenceContentHashes: readonly string[];
  outcome: ReleaseValidationProofJsonValue;
}): ReleaseValidationOutcomeV2 {
  canonicalReleaseValidationProofJson(input.outcome);
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const cohortId = requiredSha256(input.cohortId, 'cohortId');
  const forecastId = requiredSha256(input.forecastId, 'forecastId');
  const obligationId = requiredSha256(input.obligationId, 'obligationId');
  const cellId = requiredSha256(input.cellId, 'cellId');
  const releaseId = requiredSha256(input.releaseId, 'releaseId');
  const observedAt = normalizeReleaseValidationProofTimestamp(
    input.observedAt,
    'outcome observedAt',
  );
  if (!['safe', 'adverse', 'censored'].includes(input.status)) {
    throw new Error('Outcome v2 status is invalid');
  }
  const evidenceContentHashes = input.evidenceContentHashes.map((value) =>
    requiredSha256(value, 'outcome evidence content hash'));
  assertUnique(evidenceContentHashes, 'outcome evidence hash');
  if (input.status === 'adverse' && evidenceContentHashes.length === 0) {
    throw new Error('Adverse outcome requires immutable evidence');
  }
  const outcomeId = releaseValidationProofHash(
    'release-validation-outcome-id-v2',
    { cohortId, forecastId, obligationId, cellId },
  );
  const row = {
    kind: 'outcome_v2' as const,
    schemaVersion: RELEASE_VALIDATION_OUTCOME_V2_SCHEMA_VERSION as 2,
    outcomeId,
    proofEpochId,
    cohortId,
    cohortSequence: positiveInteger(
      input.cohortSequence,
      'cohortSequence',
    ),
    previousCohortContentHash: optionalSha256(
      input.previousCohortContentHash,
      'previousCohortContentHash',
    ),
    forecastId,
    obligationId,
    cellId,
    releaseId,
    observedAt,
    status: input.status,
    evidenceContentHashes,
    evidenceCount: evidenceContentHashes.length,
    evidenceOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-outcome-evidence-v2',
      evidenceContentHashes,
    ),
    evidenceSetHash: releaseValidationProofExactSetHash(
      'release-validation-outcome-evidence-v2',
      evidenceContentHashes,
    ),
    outcome: input.outcome,
  };
  return {
    ...row,
    contentHash: releaseValidationOutcomeV2ContentHash(row),
  };
}

export function releaseValidationOutcomeV2ContentHash(
  row: Omit<ReleaseValidationOutcomeV2, 'contentHash'>,
): string {
  return releaseValidationProofHash('release-validation-outcome-v2', row);
}

export function sealReleaseValidationObservationBatch(input: {
  proofEpochId: string;
  cohortId: string;
  cohortSequence: number;
  previousCohortContentHash: string | null;
  observedAt: string;
  sourceIdentityHash: string;
  expectedObligationIds: readonly string[];
  cells: readonly {
    obligationId: string;
    forecastId: string;
    outcomeId: string | null;
    disposition: ReleaseValidationObservationBatchDisposition;
  }[];
}): ReleaseValidationObservationBatch {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const cohortId = requiredSha256(input.cohortId, 'cohortId');
  const observedAt = normalizeReleaseValidationProofTimestamp(
    input.observedAt,
    'observation batch observedAt',
  );
  const sourceIdentityHash = requiredSha256(
    input.sourceIdentityHash,
    'sourceIdentityHash',
  );
  const expectedObligationIds = input.expectedObligationIds.map((value) =>
    requiredSha256(value, 'expected obligation ID'));
  assertUnique(expectedObligationIds, 'expected obligation');
  const cells = input.cells.map((cell) => {
    const obligationId = requiredSha256(cell.obligationId, 'obligationId');
    const forecastId = requiredSha256(cell.forecastId, 'forecastId');
    const outcomeId = cell.outcomeId == null
      ? null
      : requiredSha256(cell.outcomeId, 'outcomeId');
    if (!['observed', 'pending'].includes(cell.disposition)) {
      throw new Error('Observation batch cell disposition is invalid');
    }
    if ((cell.disposition === 'observed') !== (outcomeId != null)) {
      throw new Error(
        'Observed batch cells require outcomes and pending cells must omit them',
      );
    }
    return {
      batchCellId: releaseValidationProofHash(
        'release-validation-observation-batch-cell-id-v1',
        { cohortId, obligationId },
      ),
      obligationId,
      forecastId,
      outcomeId,
      disposition: cell.disposition,
    };
  });
  assertUnique(cells.map((cell) => cell.obligationId), 'observation batch cell');
  assertExactStringSet(
    cells.map((cell) => cell.obligationId),
    expectedObligationIds,
    'Observation batch cell obligations',
  );
  const expectedObligationOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-observation-batch-obligations-v1',
    expectedObligationIds,
  );
  const expectedObligationSetHash = releaseValidationProofExactSetHash(
    'release-validation-observation-batch-obligations-v1',
    expectedObligationIds,
  );
  const cellHashes = cells.map((cell) =>
    releaseValidationProofHash(
      'release-validation-observation-batch-cell-v1',
      cell,
    ));
  const batchId = releaseValidationProofHash(
    'release-validation-observation-batch-id-v1',
    { cohortId, observedAt, sourceIdentityHash },
  );
  const row = {
    kind: 'observation_batch' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    batchId,
    proofEpochId,
    cohortId,
    cohortSequence: positiveInteger(
      input.cohortSequence,
      'cohortSequence',
    ),
    previousCohortContentHash: optionalSha256(
      input.previousCohortContentHash,
      'previousCohortContentHash',
    ),
    observedAt,
    sourceIdentityHash,
    expectedObligationIds,
    expectedObligationCount: expectedObligationIds.length,
    expectedObligationOrderedHash,
    expectedObligationSetHash,
    cells,
    cellCount: cells.length,
    cellOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-observation-batch-cells-v1',
      cellHashes,
    ),
    cellSetHash: releaseValidationProofExactSetHash(
      'release-validation-observation-batch-cells-v1',
      cellHashes,
    ),
    cellObligationSetHash: releaseValidationProofExactSetHash(
      'release-validation-observation-batch-cell-obligations-v1',
      cells.map((cell) => cell.obligationId),
    ),
  };
  return {
    ...row,
    contentHash: releaseValidationObservationBatchContentHash(row),
  };
}

export function releaseValidationObservationBatchContentHash(
  row: Omit<ReleaseValidationObservationBatch, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-observation-batch-v1',
    row,
  );
}

export function releaseValidationCohortCellKey(
  cohortId: string,
  cellId: string,
): string {
  return `${requiredSha256(cohortId, 'cohortId')}:` +
    requiredSha256(cellId, 'cellId');
}

export function releaseValidationActiveCohortsAt(
  bundle: ReleaseValidationProofBundle,
  proofEpochId: string,
  evaluatedAt: string,
): ReleaseValidationCohort[] {
  const normalizedProofEpochId = requiredSha256(
    proofEpochId,
    'proofEpochId',
  );
  const normalizedEvaluatedAt = normalizeReleaseValidationProofTimestamp(
    evaluatedAt,
    'evaluation evaluatedAt',
  );
  return bundle.cohorts
    .filter((cohort) =>
      cohort.proofEpochId === normalizedProofEpochId &&
      Date.parse(cohort.startsAt) <= Date.parse(normalizedEvaluatedAt) &&
      (
        cohort.retiredAt == null ||
        Date.parse(cohort.retiredAt) > Date.parse(normalizedEvaluatedAt)
      ))
    .slice()
    .sort((left, right) =>
      left.epochSequence - right.epochSequence ||
      left.cohortId.localeCompare(right.cohortId));
}

export function releaseValidationUnevaluatedCohortEvidence(
  bundle: ReleaseValidationProofBundle,
  input: {
    readonly cohortIds: readonly string[];
    readonly evaluatedAt: string;
    readonly observedAt: string;
  },
): string[] {
  const cohortIds = new Set(input.cohortIds);
  const evaluatedAtMs = Date.parse(input.evaluatedAt);
  const observedAtMs = Date.parse(input.observedAt);
  const isUnevaluated = (value: string) => {
    const timestamp = Date.parse(value);
    return timestamp > evaluatedAtMs && timestamp <= observedAtMs;
  };
  return [
    ...bundle.obligations
      .filter((row) =>
        cohortIds.has(row.cohortId) && isUnevaluated(row.recordedAt))
      .map((row) => `obligation:${row.obligationId}`),
    ...bundle.splitAssignments
      .filter((row) =>
        cohortIds.has(row.cohortId) && isUnevaluated(row.assignedAt))
      .map((row) => `split:${row.assignmentId}`),
    ...bundle.forecasts
      .filter((row) =>
        cohortIds.has(row.cohortId) && isUnevaluated(row.recordedAt))
      .map((row) => `forecast:${row.forecastId}`),
    ...bundle.outcomes
      .filter((row) =>
        cohortIds.has(row.cohortId) && isUnevaluated(row.observedAt))
      .map((row) => `outcome:${row.outcomeId}`),
    ...bundle.observationBatches
      .filter((row) =>
        cohortIds.has(row.cohortId) && isUnevaluated(row.observedAt))
      .map((row) => `batch:${row.batchId}`),
  ].sort();
}

export function sealReleaseValidationEvaluationReceipt(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  evaluatedAt: string;
  status: ReleaseValidationEvaluationStatus;
  cohortIds: readonly string[];
  requiredCellKeys: readonly string[];
  observationBatchIds: readonly string[];
  outcomeIds: readonly string[];
  metrics: ReleaseValidationProofJsonValue;
}): ReleaseValidationEvaluationReceipt {
  canonicalReleaseValidationProofJson(input.metrics);
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  const evaluatedAt = normalizeReleaseValidationProofTimestamp(
    input.evaluatedAt,
    'evaluation evaluatedAt',
  );
  if (!['validated', 'insufficient', 'measurable_but_failed']
    .includes(input.status)) {
    throw new Error('Evaluation status is invalid');
  }
  const cohortIds = input.cohortIds.map((value) =>
    requiredSha256(value, 'evaluation cohortId'));
  const requiredCellKeys = normalizedUniqueStrings(
    input.requiredCellKeys,
    'evaluation required cell keys',
  );
  const observationBatchIds = input.observationBatchIds.map((value) =>
    requiredSha256(value, 'evaluation observation batch ID'));
  const outcomeIds = input.outcomeIds.map((value) =>
    requiredSha256(value, 'evaluation outcome ID'));
  assertUnique(cohortIds, 'evaluation cohort');
  assertUnique(observationBatchIds, 'evaluation observation batch');
  assertUnique(outcomeIds, 'evaluation outcome');
  const cohortOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-evaluation-cohorts-v1',
    cohortIds,
  );
  const cohortSetHash = releaseValidationProofExactSetHash(
    'release-validation-evaluation-cohorts-v1',
    cohortIds,
  );
  const requiredCellOrderedHash = releaseValidationProofOrderedHash(
    'release-validation-evaluation-required-cells-v1',
    requiredCellKeys,
  );
  const requiredCellSetHash = releaseValidationProofExactSetHash(
    'release-validation-evaluation-required-cells-v1',
    requiredCellKeys,
  );
  const observationBatchSetHash = releaseValidationProofExactSetHash(
    'release-validation-evaluation-batches-v1',
    observationBatchIds,
  );
  const outcomeSetHash = releaseValidationProofExactSetHash(
    'release-validation-evaluation-outcomes-v1',
    outcomeIds,
  );
  const evaluationId = releaseValidationProofHash(
    'release-validation-evaluation-id-v1',
    { proofEpochId, evaluatedAt, cohortSetHash, requiredCellSetHash },
  );
  const row = {
    kind: 'evaluation_receipt' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    evaluationId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    evaluatedAt,
    status: input.status,
    cohortIds,
    cohortCount: cohortIds.length,
    cohortOrderedHash,
    cohortSetHash,
    requiredCellKeys,
    requiredCellCount: requiredCellKeys.length,
    requiredCellOrderedHash,
    requiredCellSetHash,
    observationBatchIds,
    observationBatchCount: observationBatchIds.length,
    observationBatchSetHash,
    outcomeIds,
    outcomeCount: outcomeIds.length,
    outcomeSetHash,
    metrics: input.metrics,
  };
  return {
    ...row,
    contentHash: releaseValidationEvaluationReceiptContentHash(row),
  };
}

export function releaseValidationEvaluationReceiptContentHash(
  row: Omit<ReleaseValidationEvaluationReceipt, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-evaluation-receipt-v1',
    row,
  );
}

export function sealReleaseValidationPromotionReceipt(input: {
  proofEpochId: string;
  epochSequence: number;
  previousEpochContentHash: string | null;
  environment: ReleaseValidationPromotionEnvironment;
  promotedAt: string;
  evaluationId: string;
  evaluationContentHash: string;
  cohortIds: readonly string[];
  forecastIds: readonly string[];
  outcomeIds: readonly string[];
  sourceProofHash: string;
  destinationProofHash: string;
}): ReleaseValidationPromotionReceipt {
  const proofEpochId = requiredSha256(input.proofEpochId, 'proofEpochId');
  if (!['production', 'calibration'].includes(input.environment)) {
    throw new Error('Promotion environment is invalid');
  }
  const promotedAt = normalizeReleaseValidationProofTimestamp(
    input.promotedAt,
    'promotion promotedAt',
  );
  const evaluationId = requiredSha256(input.evaluationId, 'evaluationId');
  const evaluationContentHash = requiredSha256(
    input.evaluationContentHash,
    'evaluationContentHash',
  );
  const cohortIds = input.cohortIds.map((value) =>
    requiredSha256(value, 'promotion cohortId'));
  const forecastIds = input.forecastIds.map((value) =>
    requiredSha256(value, 'promotion forecastId'));
  const outcomeIds = input.outcomeIds.map((value) =>
    requiredSha256(value, 'promotion outcomeId'));
  assertUnique(cohortIds, 'promotion cohort');
  assertUnique(forecastIds, 'promotion forecast');
  assertUnique(outcomeIds, 'promotion outcome');
  const cohortSetHash = releaseValidationProofExactSetHash(
    'release-validation-promotion-cohorts-v1',
    cohortIds,
  );
  const forecastSetHash = releaseValidationProofExactSetHash(
    'release-validation-promotion-forecasts-v1',
    forecastIds,
  );
  const outcomeSetHash = releaseValidationProofExactSetHash(
    'release-validation-promotion-outcomes-v1',
    outcomeIds,
  );
  const sourceProofHash = requiredSha256(
    input.sourceProofHash,
    'sourceProofHash',
  );
  const destinationProofHash = requiredSha256(
    input.destinationProofHash,
    'destinationProofHash',
  );
  const promotionId = releaseValidationProofHash(
    'release-validation-promotion-id-v1',
    {
      proofEpochId,
      environment: input.environment,
      promotedAt,
      evaluationId,
      cohortSetHash,
    },
  );
  const row = {
    kind: 'promotion_receipt' as const,
    schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
    promotionId,
    proofEpochId,
    epochSequence: positiveInteger(input.epochSequence, 'epochSequence'),
    previousEpochContentHash: optionalSha256(
      input.previousEpochContentHash,
      'previousEpochContentHash',
    ),
    environment: input.environment,
    promotedAt,
    evaluationId,
    evaluationContentHash,
    cohortIds,
    cohortCount: cohortIds.length,
    cohortSetHash,
    forecastIds,
    forecastCount: forecastIds.length,
    forecastSetHash,
    outcomeIds,
    outcomeCount: outcomeIds.length,
    outcomeSetHash,
    sourceProofHash,
    destinationProofHash,
  };
  return {
    ...row,
    contentHash: releaseValidationPromotionReceiptContentHash(row),
  };
}

export function releaseValidationPromotionReceiptContentHash(
  row: Omit<ReleaseValidationPromotionReceipt, 'contentHash'>,
): string {
  return releaseValidationProofHash(
    'release-validation-promotion-receipt-v1',
    row,
  );
}

export function assertValidReleaseValidationProofEpoch(
  value: unknown,
): asserts value is ReleaseValidationProofEpoch {
  assertExactRecord(value, 'proof epoch', [
    'kind',
    'schemaVersion',
    'proofEpochId',
    'repository',
    'recordedAt',
    'startsAt',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationProofEpoch;
  const expected = sealReleaseValidationProofEpoch({
    repository: requiredString(row.repository, 'epoch repository'),
    recordedAt: requiredString(row.recordedAt, 'epoch recordedAt'),
    startsAt: requiredString(row.startsAt, 'epoch startsAt'),
  });
  assertCanonicalReplay(row, expected, 'proof epoch');
}

export function assertValidReleaseValidationProofEpochRetirement(
  value: unknown,
): asserts value is ReleaseValidationProofEpochRetirement {
  assertExactRecord(value, 'proof epoch retirement', [
    'kind',
    'schemaVersion',
    'retirementId',
    'proofEpochId',
    'epochContentHash',
    'epochSequence',
    'previousEpochContentHash',
    'recordedAt',
    'retiredAt',
    'reason',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationProofEpochRetirement;
  const expected = sealReleaseValidationProofEpochRetirement({
    proofEpochId: row.proofEpochId,
    epochContentHash: row.epochContentHash,
    epochSequence: row.epochSequence,
    previousEpochContentHash: row.previousEpochContentHash,
    recordedAt: row.recordedAt,
    retiredAt: row.retiredAt,
    reason: row.reason,
  });
  assertCanonicalReplay(row, expected, 'proof epoch retirement');
}

export function assertValidReleaseValidationPolicy(
  value: unknown,
): asserts value is ReleaseValidationPolicy {
  assertExactRecord(value, 'policy', [
    'kind',
    'schemaVersion',
    'policyId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'policyCode',
    'policyVersion',
    'recordedAt',
    'effectiveAt',
    'retiredAt',
    'splitPolicyCode',
    'developmentArm',
    'developmentReleaseCount',
    'splitPolicyHash',
    'requiredCells',
    'requiredCellCount',
    'requiredCellOrderedHash',
    'requiredCellSetHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationPolicy;
  if (!Array.isArray(row.requiredCells)) {
    throw new Error('policy requiredCells must be an array');
  }
  for (const cell of row.requiredCells) {
    assertExactRecord(cell, 'policy cell', [
      'cellId',
      'opportunityCode',
      'horizonCode',
    ]);
  }
  const expected = sealReleaseValidationPolicy({
    proofEpochId: row.proofEpochId,
    epochSequence: row.epochSequence,
    previousEpochContentHash: row.previousEpochContentHash,
    policyCode: row.policyCode,
    policyVersion: row.policyVersion,
    recordedAt: row.recordedAt,
    effectiveAt: row.effectiveAt,
    retiredAt: row.retiredAt,
    splitPolicyCode: row.splitPolicyCode,
    developmentArm: row.developmentArm,
    developmentReleaseCount: row.developmentReleaseCount,
    requiredCells: row.requiredCells,
  });
  assertCanonicalReplay(row, expected, 'policy');
}

export function assertValidReleaseValidationCohort(
  value: unknown,
): asserts value is ReleaseValidationCohort {
  assertExactRecord(value, 'cohort', [
    'kind',
    'schemaVersion',
    'cohortId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'policyId',
    'policyContentHash',
    'modelVersion',
    'promptVersion',
    'codeRevision',
    'recordedAt',
    'startsAt',
    'retiredAt',
    'requiredCellIds',
    'requiredCellCount',
    'requiredCellOrderedHash',
    'requiredCellSetHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationCohort;
  if (!Array.isArray(row.requiredCellIds)) {
    throw new Error('cohort requiredCellIds must be an array');
  }
  const expected = sealReleaseValidationCohort({
    proofEpochId: row.proofEpochId,
    epochSequence: row.epochSequence,
    previousEpochContentHash: row.previousEpochContentHash,
    policyId: row.policyId,
    policyContentHash: row.policyContentHash,
    modelVersion: row.modelVersion,
    promptVersion: row.promptVersion,
    codeRevision: row.codeRevision,
    recordedAt: row.recordedAt,
    startsAt: row.startsAt,
    retiredAt: row.retiredAt,
    requiredCellIds: row.requiredCellIds,
  });
  assertCanonicalReplay(row, expected, 'cohort');
}

export function assertValidReleaseValidationCatalogMember(
  value: unknown,
): asserts value is ReleaseValidationCatalogMember {
  assertExactRecord(value, 'catalog member', [
    'kind',
    'schemaVersion',
    'memberId',
    'observationId',
    'ordinal',
    'release',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationCatalogMember;
  assertStableReleaseIdentity(row.release, 'catalog member release');
  const expected = sealReleaseValidationCatalogMember({
    observationId: row.observationId,
    ordinal: row.ordinal,
    release: row.release,
  });
  assertCanonicalReplay(row, expected, 'catalog member');
}

export function assertValidReleaseValidationCatalogObservation(
  value: unknown,
): asserts value is ReleaseValidationCatalogObservation {
  assertExactRecord(value, 'catalog observation', [
    'kind',
    'schemaVersion',
    'observationId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'source',
    'observedAt',
    'exhaustive',
    'stabilized',
    'memberCount',
    'memberIdOrderedHash',
    'memberIdSetHash',
    'memberContentOrderedHash',
    'memberContentSetHash',
    'releaseIdSetHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationCatalogObservation;
  if (
    row.kind !== 'catalog_observation' ||
    row.schemaVersion !== 1 ||
    row.exhaustive !== true ||
    row.stabilized !== true
  ) {
    throw new Error('catalog observation schema or completeness flags are invalid');
  }
  const observedAt = normalizeReleaseValidationProofTimestamp(
    row.observedAt,
    'catalog observedAt',
  );
  if (observedAt !== row.observedAt) {
    throw new Error('catalog observation timestamp is not canonical');
  }
  const observationId = releaseValidationCatalogObservationId({
    proofEpochId: row.proofEpochId,
    source: row.source,
    observedAt,
  });
  if (observationId !== row.observationId) {
    throw new Error('catalog observation ID mismatch');
  }
  nonNegativeInteger(row.memberCount, 'catalog memberCount');
  positiveInteger(row.epochSequence, 'epochSequence');
  optionalSha256(
    row.previousEpochContentHash,
    'previousEpochContentHash',
  );
  for (const [label, hash] of [
    ['memberIdOrderedHash', row.memberIdOrderedHash],
    ['memberIdSetHash', row.memberIdSetHash],
    ['memberContentOrderedHash', row.memberContentOrderedHash],
    ['memberContentSetHash', row.memberContentSetHash],
    ['releaseIdSetHash', row.releaseIdSetHash],
  ] as const) {
    requiredSha256(hash, label);
  }
  const { contentHash: _contentHash, ...hashInput } = row;
  if (
    releaseValidationCatalogObservationContentHash(hashInput) !==
    row.contentHash
  ) {
    throw new Error('catalog observation content hash mismatch');
  }
}

export function assertValidReleaseValidationCatalogReconciliationRow(
  value: unknown,
): asserts value is ReleaseValidationCatalogReconciliationRow {
  assertExactRecord(value, 'catalog reconciliation row', [
    'kind',
    'schemaVersion',
    'reconciliationRowId',
    'reconciliationId',
    'ordinal',
    'releaseId',
    'status',
    'previousMemberId',
    'previousMemberContentHash',
    'currentMemberId',
    'currentMemberContentHash',
    'retiredAt',
    'contentHash',
  ]);
  const row =
    value as unknown as ReleaseValidationCatalogReconciliationRow;
  if (
    row.kind !== 'catalog_reconciliation_row' ||
    row.schemaVersion !== 1 ||
    !['added', 'retained', 'retired'].includes(row.status)
  ) {
    throw new Error('catalog reconciliation row schema or status is invalid');
  }
  nonNegativeInteger(row.ordinal, 'catalog reconciliation row ordinal');
  const reconciliationId = requiredSha256(
    row.reconciliationId,
    'reconciliationId',
  );
  const releaseId = requiredSha256(row.releaseId, 'releaseId');
  const previousMemberId = optionalSha256(
    row.previousMemberId,
    'previousMemberId',
  );
  const previousMemberContentHash = optionalSha256(
    row.previousMemberContentHash,
    'previousMemberContentHash',
  );
  const currentMemberId = optionalSha256(
    row.currentMemberId,
    'currentMemberId',
  );
  const currentMemberContentHash = optionalSha256(
    row.currentMemberContentHash,
    'currentMemberContentHash',
  );
  const retiredAt = normalizedOptionalTimestamp(row.retiredAt, 'retiredAt');
  const shapeValid =
    (row.status === 'added' &&
      previousMemberId == null &&
      previousMemberContentHash == null &&
      currentMemberId != null &&
      currentMemberContentHash != null &&
      retiredAt == null) ||
    (row.status === 'retained' &&
      previousMemberId != null &&
      previousMemberContentHash != null &&
      currentMemberId != null &&
      currentMemberContentHash != null &&
      retiredAt == null) ||
    (row.status === 'retired' &&
      previousMemberId != null &&
      previousMemberContentHash != null &&
      currentMemberId == null &&
      currentMemberContentHash == null &&
      retiredAt != null);
  if (!shapeValid) {
    throw new Error('catalog reconciliation row membership shape is invalid');
  }
  const reconciliationRowId = releaseValidationProofHash(
    'release-validation-catalog-reconciliation-row-id-v1',
    { reconciliationId, releaseId },
  );
  if (reconciliationRowId !== row.reconciliationRowId) {
    throw new Error('catalog reconciliation row ID mismatch');
  }
  const { contentHash: _contentHash, ...hashInput } = row;
  if (
    releaseValidationCatalogReconciliationRowContentHash(hashInput) !==
    row.contentHash
  ) {
    throw new Error('catalog reconciliation row content hash mismatch');
  }
}

export function assertValidReleaseValidationCatalogReconciliation(
  value: unknown,
): asserts value is ReleaseValidationCatalogReconciliation {
  assertExactRecord(value, 'catalog reconciliation', [
    'kind',
    'schemaVersion',
    'reconciliationId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'previousObservationId',
    'previousObservationContentHash',
    'currentObservationId',
    'currentObservationContentHash',
    'reconciledAt',
    'rowCount',
    'rowIdOrderedHash',
    'rowIdSetHash',
    'rowContentOrderedHash',
    'rowContentSetHash',
    'contentHash',
  ]);
  const row =
    value as unknown as ReleaseValidationCatalogReconciliation;
  if (row.kind !== 'catalog_reconciliation' || row.schemaVersion !== 1) {
    throw new Error('catalog reconciliation schema is invalid');
  }
  const proofEpochId = requiredSha256(row.proofEpochId, 'proofEpochId');
  const previousObservationId = optionalSha256(
    row.previousObservationId,
    'previousObservationId',
  );
  const previousObservationContentHash = optionalSha256(
    row.previousObservationContentHash,
    'previousObservationContentHash',
  );
  if (
    (previousObservationId == null) !==
    (previousObservationContentHash == null)
  ) {
    throw new Error('catalog reconciliation previous observation is partial');
  }
  const currentObservationId = requiredSha256(
    row.currentObservationId,
    'currentObservationId',
  );
  const reconciledAt = normalizeReleaseValidationProofTimestamp(
    row.reconciledAt,
    'catalog reconciledAt',
  );
  if (reconciledAt !== row.reconciledAt) {
    throw new Error('catalog reconciliation timestamp is not canonical');
  }
  const expectedId = releaseValidationProofHash(
    'release-validation-catalog-reconciliation-id-v1',
    {
      proofEpochId,
      previousObservationId,
      currentObservationId,
      reconciledAt,
    },
  );
  if (expectedId !== row.reconciliationId) {
    throw new Error('catalog reconciliation ID mismatch');
  }
  positiveInteger(row.epochSequence, 'epochSequence');
  nonNegativeInteger(row.rowCount, 'catalog reconciliation rowCount');
  optionalSha256(
    row.previousEpochContentHash,
    'previousEpochContentHash',
  );
  requiredSha256(
    row.currentObservationContentHash,
    'currentObservationContentHash',
  );
  for (const [label, hash] of [
    ['rowIdOrderedHash', row.rowIdOrderedHash],
    ['rowIdSetHash', row.rowIdSetHash],
    ['rowContentOrderedHash', row.rowContentOrderedHash],
    ['rowContentSetHash', row.rowContentSetHash],
  ] as const) {
    requiredSha256(hash, label);
  }
  const { contentHash: _contentHash, ...hashInput } = row;
  if (
    releaseValidationCatalogReconciliationContentHash(hashInput) !==
    row.contentHash
  ) {
    throw new Error('catalog reconciliation content hash mismatch');
  }
}

export function assertValidReleaseValidationObligation(
  value: unknown,
): asserts value is ReleaseValidationObligation {
  assertExactRecord(value, 'obligation', [
    'kind',
    'schemaVersion',
    'obligationId',
    'proofEpochId',
    'cohortId',
    'cohortSequence',
    'previousCohortContentHash',
    'cellId',
    'opportunityCode',
    'horizonCode',
    'release',
    'recordedAt',
    'opensAt',
    'closesAtExclusive',
    'outcomeDueAt',
    'catalogObservationId',
    'catalogObservationContentHash',
    'reconciliationId',
    'reconciliationContentHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationObligation;
  assertStableReleaseIdentity(row.release, 'obligation release');
  const expected = sealReleaseValidationObligation({
    proofEpochId: row.proofEpochId,
    cohortId: row.cohortId,
    cohortSequence: row.cohortSequence,
    previousCohortContentHash: row.previousCohortContentHash,
    cellId: row.cellId,
    opportunityCode: row.opportunityCode,
    horizonCode: row.horizonCode,
    release: row.release,
    recordedAt: row.recordedAt,
    opensAt: row.opensAt,
    closesAtExclusive: row.closesAtExclusive,
    outcomeDueAt: row.outcomeDueAt,
    catalogObservationId: row.catalogObservationId,
    catalogObservationContentHash: row.catalogObservationContentHash,
    reconciliationId: row.reconciliationId,
    reconciliationContentHash: row.reconciliationContentHash,
  });
  assertCanonicalReplay(row, expected, 'obligation');
}

export function assertValidReleaseValidationSplitAssignment(
  value: unknown,
): asserts value is ReleaseValidationSplitAssignment {
  assertExactRecord(value, 'split assignment', [
    'kind',
    'schemaVersion',
    'assignmentId',
    'proofEpochId',
    'cohortId',
    'cohortSequence',
    'previousCohortContentHash',
    'obligationId',
    'assignedAt',
    'arm',
    'splitPolicyHash',
    'seedHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationSplitAssignment;
  const expected = sealReleaseValidationSplitAssignment({
    proofEpochId: row.proofEpochId,
    cohortId: row.cohortId,
    cohortSequence: row.cohortSequence,
    previousCohortContentHash: row.previousCohortContentHash,
    obligationId: row.obligationId,
    assignedAt: row.assignedAt,
    arm: row.arm,
    splitPolicyHash: row.splitPolicyHash,
    seedHash: row.seedHash,
  });
  assertCanonicalReplay(row, expected, 'split assignment');
}

export function assertValidReleaseValidationForecastV2(
  value: unknown,
): asserts value is ReleaseValidationForecastV2 {
  assertExactRecord(value, 'forecast v2', [
    'kind',
    'schemaVersion',
    'forecastId',
    'proofEpochId',
    'cohortId',
    'cohortSequence',
    'previousCohortContentHash',
    'obligationId',
    'splitAssignmentId',
    'policyId',
    'policyContentHash',
    'recordedAt',
    'latestRelease',
    'candidates',
    'candidateCount',
    'candidateReleaseIdOrderedHash',
    'candidateReleaseIdSetHash',
    'candidateIdentityOrderedHash',
    'selectedReleaseId',
    'forecast',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationForecastV2;
  if (row.schemaVersion !== 2 || row.kind !== 'forecast_v2') {
    throw new Error('Legacy forecasts cannot be upgraded into forecast v2');
  }
  assertStableReleaseIdentity(row.latestRelease, 'forecast latestRelease');
  if (!Array.isArray(row.candidates)) {
    throw new Error('forecast v2 candidates must be an array');
  }
  for (const candidate of row.candidates) {
    assertStableReleaseIdentity(candidate, 'forecast candidate');
  }
  const expected = sealReleaseValidationForecastV2({
    proofEpochId: row.proofEpochId,
    cohortId: row.cohortId,
    cohortSequence: row.cohortSequence,
    previousCohortContentHash: row.previousCohortContentHash,
    obligationId: row.obligationId,
    splitAssignmentId: row.splitAssignmentId,
    policyId: row.policyId,
    policyContentHash: row.policyContentHash,
    recordedAt: row.recordedAt,
    latestRelease: row.latestRelease,
    candidates: row.candidates,
    selectedReleaseId: row.selectedReleaseId,
    forecast: row.forecast,
  });
  assertCanonicalReplay(row, expected, 'forecast v2');
}

export function assertValidReleaseValidationOutcomeV2(
  value: unknown,
): asserts value is ReleaseValidationOutcomeV2 {
  assertExactRecord(value, 'outcome v2', [
    'kind',
    'schemaVersion',
    'outcomeId',
    'proofEpochId',
    'cohortId',
    'cohortSequence',
    'previousCohortContentHash',
    'forecastId',
    'obligationId',
    'cellId',
    'releaseId',
    'observedAt',
    'status',
    'evidenceContentHashes',
    'evidenceCount',
    'evidenceOrderedHash',
    'evidenceSetHash',
    'outcome',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationOutcomeV2;
  if (row.schemaVersion !== 2 || row.kind !== 'outcome_v2') {
    throw new Error('Legacy outcomes cannot be upgraded into outcome v2');
  }
  if (!Array.isArray(row.evidenceContentHashes)) {
    throw new Error('outcome v2 evidenceContentHashes must be an array');
  }
  const expected = sealReleaseValidationOutcomeV2({
    proofEpochId: row.proofEpochId,
    cohortId: row.cohortId,
    cohortSequence: row.cohortSequence,
    previousCohortContentHash: row.previousCohortContentHash,
    forecastId: row.forecastId,
    obligationId: row.obligationId,
    cellId: row.cellId,
    releaseId: row.releaseId,
    observedAt: row.observedAt,
    status: row.status,
    evidenceContentHashes: row.evidenceContentHashes,
    outcome: row.outcome,
  });
  assertCanonicalReplay(row, expected, 'outcome v2');
}

export function assertValidReleaseValidationObservationBatch(
  value: unknown,
): asserts value is ReleaseValidationObservationBatch {
  assertExactRecord(value, 'observation batch', [
    'kind',
    'schemaVersion',
    'batchId',
    'proofEpochId',
    'cohortId',
    'cohortSequence',
    'previousCohortContentHash',
    'observedAt',
    'sourceIdentityHash',
    'expectedObligationIds',
    'expectedObligationCount',
    'expectedObligationOrderedHash',
    'expectedObligationSetHash',
    'cells',
    'cellCount',
    'cellOrderedHash',
    'cellSetHash',
    'cellObligationSetHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationObservationBatch;
  if (!Array.isArray(row.expectedObligationIds) ||
    !Array.isArray(row.cells)) {
    throw new Error('observation batch sets must be arrays');
  }
  for (const cell of row.cells) {
    assertExactRecord(cell, 'observation batch cell', [
      'batchCellId',
      'obligationId',
      'forecastId',
      'outcomeId',
      'disposition',
    ]);
  }
  const expected = sealReleaseValidationObservationBatch({
    proofEpochId: row.proofEpochId,
    cohortId: row.cohortId,
    cohortSequence: row.cohortSequence,
    previousCohortContentHash: row.previousCohortContentHash,
    observedAt: row.observedAt,
    sourceIdentityHash: row.sourceIdentityHash,
    expectedObligationIds: row.expectedObligationIds,
    cells: row.cells,
  });
  assertCanonicalReplay(row, expected, 'observation batch');
}

export function assertValidReleaseValidationEvaluationReceipt(
  value: unknown,
): asserts value is ReleaseValidationEvaluationReceipt {
  assertExactRecord(value, 'evaluation receipt', [
    'kind',
    'schemaVersion',
    'evaluationId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'evaluatedAt',
    'status',
    'cohortIds',
    'cohortCount',
    'cohortOrderedHash',
    'cohortSetHash',
    'requiredCellKeys',
    'requiredCellCount',
    'requiredCellOrderedHash',
    'requiredCellSetHash',
    'observationBatchIds',
    'observationBatchCount',
    'observationBatchSetHash',
    'outcomeIds',
    'outcomeCount',
    'outcomeSetHash',
    'metrics',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationEvaluationReceipt;
  if (
    !Array.isArray(row.cohortIds) ||
    !Array.isArray(row.requiredCellKeys) ||
    !Array.isArray(row.observationBatchIds) ||
    !Array.isArray(row.outcomeIds)
  ) {
    throw new Error('evaluation receipt sets must be arrays');
  }
  const expected = sealReleaseValidationEvaluationReceipt({
    proofEpochId: row.proofEpochId,
    epochSequence: row.epochSequence,
    previousEpochContentHash: row.previousEpochContentHash,
    evaluatedAt: row.evaluatedAt,
    status: row.status,
    cohortIds: row.cohortIds,
    requiredCellKeys: row.requiredCellKeys,
    observationBatchIds: row.observationBatchIds,
    outcomeIds: row.outcomeIds,
    metrics: row.metrics,
  });
  assertCanonicalReplay(row, expected, 'evaluation receipt');
}

export function assertValidReleaseValidationPromotionReceipt(
  value: unknown,
): asserts value is ReleaseValidationPromotionReceipt {
  assertExactRecord(value, 'promotion receipt', [
    'kind',
    'schemaVersion',
    'promotionId',
    'proofEpochId',
    'epochSequence',
    'previousEpochContentHash',
    'environment',
    'promotedAt',
    'evaluationId',
    'evaluationContentHash',
    'cohortIds',
    'cohortCount',
    'cohortSetHash',
    'forecastIds',
    'forecastCount',
    'forecastSetHash',
    'outcomeIds',
    'outcomeCount',
    'outcomeSetHash',
    'sourceProofHash',
    'destinationProofHash',
    'contentHash',
  ]);
  const row = value as unknown as ReleaseValidationPromotionReceipt;
  if (
    !Array.isArray(row.cohortIds) ||
    !Array.isArray(row.forecastIds) ||
    !Array.isArray(row.outcomeIds)
  ) {
    throw new Error('promotion receipt sets must be arrays');
  }
  const expected = sealReleaseValidationPromotionReceipt({
    proofEpochId: row.proofEpochId,
    epochSequence: row.epochSequence,
    previousEpochContentHash: row.previousEpochContentHash,
    environment: row.environment,
    promotedAt: row.promotedAt,
    evaluationId: row.evaluationId,
    evaluationContentHash: row.evaluationContentHash,
    cohortIds: row.cohortIds,
    forecastIds: row.forecastIds,
    outcomeIds: row.outcomeIds,
    sourceProofHash: row.sourceProofHash,
    destinationProofHash: row.destinationProofHash,
  });
  assertCanonicalReplay(row, expected, 'promotion receipt');
}

export function verifyReleaseValidationProofBundle(
  bundle: ReleaseValidationProofBundle,
): ReleaseValidationProofVerification {
  const problems: string[] = [];
  const epochChainTips: Record<string, string | null> = {};
  const cohortChainTips: Record<string, string | null> = {};

  validateRows(bundle.epochs, assertValidReleaseValidationProofEpoch, problems);
  validateRows(
    bundle.retirements,
    assertValidReleaseValidationProofEpochRetirement,
    problems,
  );
  validateRows(bundle.policies, assertValidReleaseValidationPolicy, problems);
  validateRows(bundle.cohorts, assertValidReleaseValidationCohort, problems);
  validateRows(
    bundle.catalogMembers,
    assertValidReleaseValidationCatalogMember,
    problems,
  );
  validateRows(
    bundle.catalogObservations,
    assertValidReleaseValidationCatalogObservation,
    problems,
  );
  validateRows(
    bundle.catalogReconciliationRows,
    assertValidReleaseValidationCatalogReconciliationRow,
    problems,
  );
  validateRows(
    bundle.catalogReconciliations,
    assertValidReleaseValidationCatalogReconciliation,
    problems,
  );
  validateRows(
    bundle.obligations,
    assertValidReleaseValidationObligation,
    problems,
  );
  validateRows(
    bundle.splitAssignments,
    assertValidReleaseValidationSplitAssignment,
    problems,
  );
  validateRows(bundle.forecasts, assertValidReleaseValidationForecastV2, problems);
  validateRows(bundle.outcomes, assertValidReleaseValidationOutcomeV2, problems);
  validateRows(
    bundle.observationBatches,
    assertValidReleaseValidationObservationBatch,
    problems,
  );
  validateRows(
    bundle.evaluationReceipts,
    assertValidReleaseValidationEvaluationReceipt,
    problems,
  );
  validateRows(
    bundle.promotionReceipts,
    assertValidReleaseValidationPromotionReceipt,
    problems,
  );

  for (const [label, rows, hash] of [
    [
      'epoch retirement',
      bundle.retirements,
      releaseValidationProofEpochRetirementContentHash,
    ],
    [
      'catalog member',
      bundle.catalogMembers,
      releaseValidationCatalogMemberContentHash,
    ],
    [
      'catalog observation',
      bundle.catalogObservations,
      releaseValidationCatalogObservationContentHash,
    ],
    [
      'catalog reconciliation row',
      bundle.catalogReconciliationRows,
      releaseValidationCatalogReconciliationRowContentHash,
    ],
    [
      'catalog reconciliation',
      bundle.catalogReconciliations,
      releaseValidationCatalogReconciliationContentHash,
    ],
    [
      'obligation',
      bundle.obligations,
      releaseValidationObligationContentHash,
    ],
    [
      'split assignment',
      bundle.splitAssignments,
      releaseValidationSplitAssignmentContentHash,
    ],
    [
      'observation batch',
      bundle.observationBatches,
      releaseValidationObservationBatchContentHash,
    ],
    [
      'evaluation receipt',
      bundle.evaluationReceipts,
      releaseValidationEvaluationReceiptContentHash,
    ],
    [
      'promotion receipt',
      bundle.promotionReceipts,
      releaseValidationPromotionReceiptContentHash,
    ],
  ] as const) {
    for (const row of rows as readonly { contentHash: string }[]) {
      try {
        const { contentHash: _contentHash, ...hashInput } = row;
        const expected = (
          hash as (value: Record<string, unknown>) => string
        )(hashInput);
        if (!SHA256_RE.test(row.contentHash) || expected !== row.contentHash) {
          problems.push(`${label} content hash mismatch`);
        }
        canonicalReleaseValidationProofJson(row);
      } catch (error) {
        problems.push(`${label}: ${errorMessage(error)}`);
      }
    }
  }

  const epochsById = uniqueMap(
    bundle.epochs,
    (row) => row.proofEpochId,
    'proof epoch',
    problems,
  );
  const policiesById = uniqueMap(
    bundle.policies,
    (row) => row.policyId,
    'policy',
    problems,
  );
  const cohortsById = uniqueMap(
    bundle.cohorts,
    (row) => row.cohortId,
    'cohort',
    problems,
  );
  const observationsById = uniqueMap(
    bundle.catalogObservations,
    (row) => row.observationId,
    'catalog observation',
    problems,
  );
  const catalogMembersById = uniqueMap(
    bundle.catalogMembers,
    (row) => row.memberId,
    'catalog member',
    problems,
  );
  const reconciliationsById = uniqueMap(
    bundle.catalogReconciliations,
    (row) => row.reconciliationId,
    'catalog reconciliation',
    problems,
  );
  const obligationsById = uniqueMap(
    bundle.obligations,
    (row) => row.obligationId,
    'obligation',
    problems,
  );
  const assignmentsById = uniqueMap(
    bundle.splitAssignments,
    (row) => row.assignmentId,
    'split assignment',
    problems,
  );
  const forecastsById = uniqueMap(
    bundle.forecasts,
    (row) => row.forecastId,
    'forecast',
    problems,
  );
  const outcomesById = uniqueMap(
    bundle.outcomes,
    (row) => row.outcomeId,
    'outcome',
    problems,
  );
  const batchesById = uniqueMap(
    bundle.observationBatches,
    (row) => row.batchId,
    'observation batch',
    problems,
  );
  const evaluationsById = uniqueMap(
    bundle.evaluationReceipts,
    (row) => row.evaluationId,
    'evaluation receipt',
    problems,
  );

  verifyEpochChains(bundle, epochsById, epochChainTips, problems);
  verifyCohortChains(bundle, cohortsById, cohortChainTips, problems);

  for (const policy of bundle.policies) {
    const epoch = epochsById.get(policy.proofEpochId);
    if (!epoch) {
      problems.push(`Policy ${policy.policyId} references a missing proof epoch`);
    } else if (Date.parse(policy.effectiveAt) < Date.parse(epoch.startsAt)) {
      problems.push(`Policy ${policy.policyId} predates its proof epoch`);
    }
  }

  for (const cohort of bundle.cohorts) {
    const epoch = epochsById.get(cohort.proofEpochId);
    const policy = policiesById.get(cohort.policyId);
    if (!epoch) {
      problems.push(`Cohort ${cohort.cohortId} references a missing proof epoch`);
    }
    if (!policy ||
      policy.contentHash !== cohort.policyContentHash ||
      policy.proofEpochId !== cohort.proofEpochId) {
      problems.push(`Cohort ${cohort.cohortId} does not bind its exact policy`);
    } else {
      if (Date.parse(cohort.startsAt) < Date.parse(policy.effectiveAt)) {
        problems.push(`Cohort ${cohort.cohortId} predates its policy`);
      }
      if (policy.retiredAt &&
        Date.parse(cohort.startsAt) >= Date.parse(policy.retiredAt)) {
        problems.push(`Cohort ${cohort.cohortId} starts after policy retirement`);
      }
      if (
        cohort.requiredCellCount !== policy.requiredCellCount ||
        cohort.requiredCellOrderedHash !== policy.requiredCellOrderedHash ||
        cohort.requiredCellSetHash !== policy.requiredCellSetHash ||
        !sameOrderedStrings(
          cohort.requiredCellIds,
          policy.requiredCells.map((cell) => cell.cellId),
        )
      ) {
        problems.push(`Cohort ${cohort.cohortId} omits or reorders policy cells`);
      }
    }
  }

  const membersByObservation = groupBy(
    bundle.catalogMembers,
    (row) => row.observationId,
  );
  for (const observation of bundle.catalogObservations) {
    try {
      assertCatalogObservationMembers(
        observation,
        membersByObservation.get(observation.observationId) ?? [],
      );
    } catch (error) {
      problems.push(
        `Catalog observation ${observation.observationId}: ${errorMessage(error)}`,
      );
    }
  }
  for (const member of bundle.catalogMembers) {
    if (!observationsById.has(member.observationId)) {
      problems.push(`Catalog member ${member.memberId} is orphaned`);
    }
  }

  const rowsByReconciliation = groupBy(
    bundle.catalogReconciliationRows,
    (row) => row.reconciliationId,
  );
  for (const reconciliation of bundle.catalogReconciliations) {
    const current = observationsById.get(reconciliation.currentObservationId);
    const previous = reconciliation.previousObservationId
      ? observationsById.get(reconciliation.previousObservationId) ?? null
      : null;
    if (!current ||
      current.contentHash !== reconciliation.currentObservationContentHash) {
      problems.push(
        `Catalog reconciliation ${reconciliation.reconciliationId} ` +
        'does not bind its current observation',
      );
      continue;
    }
    if (reconciliation.previousObservationId &&
      (!previous ||
        previous.contentHash !==
          reconciliation.previousObservationContentHash)) {
      problems.push(
        `Catalog reconciliation ${reconciliation.reconciliationId} ` +
        'does not bind its previous observation',
      );
      continue;
    }
    try {
      const expected = sealReleaseValidationCatalogReconciliation({
        proofEpochId: reconciliation.proofEpochId,
        epochSequence: reconciliation.epochSequence,
        previousEpochContentHash: reconciliation.previousEpochContentHash,
        reconciledAt: reconciliation.reconciledAt,
        previousObservation: previous,
        previousMembers: previous
          ? membersByObservation.get(previous.observationId) ?? []
          : [],
        currentObservation: current,
        currentMembers:
          membersByObservation.get(current.observationId) ?? [],
      });
      assertCanonicalReplay(
        reconciliation,
        expected.reconciliation,
        'catalog reconciliation',
      );
      const actualRows =
        rowsByReconciliation.get(reconciliation.reconciliationId) ?? [];
      if (
        canonicalReleaseValidationProofJson(actualRows) !==
        canonicalReleaseValidationProofJson(expected.rows)
      ) {
        problems.push(
          `Catalog reconciliation ${reconciliation.reconciliationId} ` +
          'has an incomplete or divergent row set',
        );
      }
    } catch (error) {
      problems.push(
        `Catalog reconciliation ${reconciliation.reconciliationId}: ` +
        errorMessage(error),
      );
    }
  }
  for (const row of bundle.catalogReconciliationRows) {
    if (!reconciliationsById.has(row.reconciliationId)) {
      problems.push(
        `Catalog reconciliation row ${row.reconciliationRowId} is orphaned`,
      );
    }
  }

  const assignmentsByObligation = groupBy(
    bundle.splitAssignments,
    (row) => row.obligationId,
  );
  for (const obligation of bundle.obligations) {
    const cohort = cohortsById.get(obligation.cohortId);
    const observation = observationsById.get(obligation.catalogObservationId);
    const reconciliation =
      reconciliationsById.get(obligation.reconciliationId);
    if (!cohort ||
      cohort.proofEpochId !== obligation.proofEpochId ||
      !cohort.requiredCellIds.includes(obligation.cellId)) {
      problems.push(
        `Obligation ${obligation.obligationId} is outside its cohort cell set`,
      );
    }
    if (!observation ||
      observation.contentHash !== obligation.catalogObservationContentHash) {
      problems.push(
        `Obligation ${obligation.obligationId} lacks its exact catalog observation`,
      );
    } else {
      const releasePresent = (
        membersByObservation.get(observation.observationId) ?? []
      ).some((member) =>
        member.release.releaseId === obligation.release.releaseId);
      if (!releasePresent) {
        problems.push(
          `Obligation ${obligation.obligationId} release is absent from its catalog`,
        );
      }
    }
    if (!reconciliation ||
      reconciliation.contentHash !== obligation.reconciliationContentHash) {
      problems.push(
        `Obligation ${obligation.obligationId} lacks exact reconciliation`,
      );
    }
    const assignments =
      assignmentsByObligation.get(obligation.obligationId) ?? [];
    if (assignments.length !== 1) {
      problems.push(
        `Obligation ${obligation.obligationId} must have one immutable split assignment`,
      );
    } else if (
      assignments[0].cohortId !== obligation.cohortId ||
      Date.parse(assignments[0].assignedAt) < Date.parse(obligation.recordedAt)
    ) {
      problems.push(
        `Obligation ${obligation.obligationId} has an invalid split assignment`,
      );
    }
  }
  for (const assignment of bundle.splitAssignments) {
    if (!obligationsById.has(assignment.obligationId)) {
      problems.push(`Split assignment ${assignment.assignmentId} is orphaned`);
    }
  }

  const obligationsByCohortReleaseCell = groupBy(
    bundle.obligations,
    (row) => `${row.cohortId}\0${row.release.releaseId}\0${row.cellId}`,
  );
  for (const cohort of bundle.cohorts) {
    const policy = policiesById.get(cohort.policyId);
    if (!policy) continue;
    const expectedSplitPolicyHash = releaseValidationSplitPolicyHash({
      splitPolicyCode: policy.splitPolicyCode,
      developmentArm: policy.developmentArm,
      developmentReleaseCount: policy.developmentReleaseCount,
    });
    if (policy.splitPolicyHash !== expectedSplitPolicyHash) {
      problems.push(
        `Policy ${policy.policyId} has an invalid split policy hash`,
      );
    }

    const seenReleaseIds = new Set<string>();
    const admissions: Array<{
      readonly member: ReleaseValidationCatalogMember;
      readonly reconciliation: ReleaseValidationCatalogReconciliation;
    }> = [];
    const orderedReconciliations = bundle.catalogReconciliations
      .filter((row) =>
        row.proofEpochId === cohort.proofEpochId &&
        row.epochSequence > cohort.epochSequence &&
        Date.parse(row.reconciledAt) >= Date.parse(cohort.startsAt) &&
        (
          cohort.retiredAt == null ||
          Date.parse(row.reconciledAt) < Date.parse(cohort.retiredAt)
        ))
      .sort((left, right) => left.epochSequence - right.epochSequence);
    for (const reconciliation of orderedReconciliations) {
      const orderedRows = (
        rowsByReconciliation.get(reconciliation.reconciliationId) ?? []
      ).slice().sort((left, right) => left.ordinal - right.ordinal);
      for (const row of orderedRows) {
        if (row.status !== 'added' || row.currentMemberId == null) continue;
        const member = catalogMembersById.get(row.currentMemberId);
        if (
          !member ||
          member.observationId !== reconciliation.currentObservationId ||
          Date.parse(member.release.publishedAt) < Date.parse(cohort.startsAt) ||
          seenReleaseIds.has(member.release.releaseId)
        ) {
          continue;
        }
        seenReleaseIds.add(member.release.releaseId);
        admissions.push({ member, reconciliation });
      }
    }

    const expectedObligationKeys = new Set<string>();
    for (const [admissionIndex, admission] of admissions.entries()) {
      const admissionOrdinal = admissionIndex + 1;
      const expectedArm: ReleaseValidationSplitArm =
        admissionOrdinal <= policy.developmentReleaseCount
          ? policy.developmentArm
          : 'holdout';
      const expectedSeedHash = releaseValidationSplitSeedHash({
        proofEpochId: cohort.proofEpochId,
        cohortId: cohort.cohortId,
        releaseId: admission.member.release.releaseId,
        admissionOrdinal,
        splitPolicyHash: policy.splitPolicyHash,
      });
      for (const cell of policy.requiredCells) {
        const key =
          `${cohort.cohortId}\0${admission.member.release.releaseId}\0` +
          cell.cellId;
        expectedObligationKeys.add(key);
        const obligations = obligationsByCohortReleaseCell.get(key) ?? [];
        if (obligations.length !== 1) {
          problems.push(
            `Cohort ${cohort.cohortId} admission ` +
            `${admission.member.release.releaseId} must have one obligation ` +
            `for cell ${cell.cellId}`,
          );
          continue;
        }
        const obligation = obligations[0];
        if (
          obligation.catalogObservationId !==
            admission.reconciliation.currentObservationId ||
          obligation.catalogObservationContentHash !==
            admission.reconciliation.currentObservationContentHash ||
          obligation.reconciliationId !==
            admission.reconciliation.reconciliationId ||
          obligation.reconciliationContentHash !==
            admission.reconciliation.contentHash ||
          canonicalReleaseValidationProofJson(obligation.release) !==
            canonicalReleaseValidationProofJson(admission.member.release) ||
          Date.parse(obligation.recordedAt) <
            Date.parse(admission.reconciliation.reconciledAt)
        ) {
          problems.push(
            `Obligation ${obligation.obligationId} does not bind its first ` +
            'prospective catalog admission',
          );
        }
        const assignments =
          assignmentsByObligation.get(obligation.obligationId) ?? [];
        if (
          assignments.length === 1 &&
          (
            assignments[0].arm !== expectedArm ||
            assignments[0].splitPolicyHash !== policy.splitPolicyHash ||
            assignments[0].seedHash !== expectedSeedHash
          )
        ) {
          problems.push(
            `Split assignment ${assignments[0].assignmentId} violates ` +
            `the cohort admission policy at ordinal ${admissionOrdinal}`,
          );
        }
      }
    }
    for (const obligation of bundle.obligations.filter(
      (row) => row.cohortId === cohort.cohortId,
    )) {
      const key =
        `${cohort.cohortId}\0${obligation.release.releaseId}\0` +
        obligation.cellId;
      if (!expectedObligationKeys.has(key)) {
        problems.push(
          `Obligation ${obligation.obligationId} is not a prospective ` +
          'post-inception catalog admission',
        );
      }
    }
  }

  const forecastsByObligation = groupBy(
    bundle.forecasts,
    (row) => row.obligationId,
  );
  for (const forecast of bundle.forecasts) {
    const obligation = obligationsById.get(forecast.obligationId);
    const assignment = assignmentsById.get(forecast.splitAssignmentId);
    const cohort = cohortsById.get(forecast.cohortId);
    if (!obligation ||
      obligation.cohortId !== forecast.cohortId ||
      obligation.release.releaseId !== forecast.latestRelease.releaseId ||
      Date.parse(forecast.recordedAt) < Date.parse(obligation.opensAt) ||
      Date.parse(forecast.recordedAt) >=
        Date.parse(obligation.closesAtExclusive)) {
      problems.push(`Forecast ${forecast.forecastId} violates its obligation`);
    }
    if (!assignment ||
      assignment.obligationId !== forecast.obligationId ||
      assignment.cohortId !== forecast.cohortId) {
      problems.push(`Forecast ${forecast.forecastId} lacks its exact split`);
    }
    if (!cohort ||
      cohort.policyId !== forecast.policyId ||
      cohort.policyContentHash !== forecast.policyContentHash) {
      problems.push(`Forecast ${forecast.forecastId} lacks its cohort policy`);
    }
  }
  for (const [obligationId, forecasts] of forecastsByObligation) {
    if (forecasts.length > 1) {
      problems.push(
        `Obligation ${obligationId} has multiple immutable forecasts`,
      );
    }
  }

  const outcomesByForecast = groupBy(
    bundle.outcomes,
    (row) => row.forecastId,
  );
  for (const outcome of bundle.outcomes) {
    const forecast = forecastsById.get(outcome.forecastId);
    const obligation = obligationsById.get(outcome.obligationId);
    if (!forecast ||
      forecast.obligationId !== outcome.obligationId ||
      forecast.cohortId !== outcome.cohortId ||
      !obligation ||
      obligation.cellId !== outcome.cellId ||
      obligation.release.releaseId !== outcome.releaseId ||
      Date.parse(outcome.observedAt) < Date.parse(obligation.outcomeDueAt)) {
      problems.push(`Outcome ${outcome.outcomeId} violates its forecast cell`);
    }
  }
  for (const [forecastId, outcomes] of outcomesByForecast) {
    if (outcomes.length > 1) {
      problems.push(`Forecast ${forecastId} has multiple outcome v2 rows`);
    }
  }

  for (const batch of bundle.observationBatches) {
    const exactForecastObligations = bundle.forecasts
      .filter((forecast) => forecast.cohortId === batch.cohortId)
      .map((forecast) => forecast.obligationId);
    try {
      assertExactStringSet(
        batch.expectedObligationIds,
        exactForecastObligations,
        `Observation batch ${batch.batchId} forecast obligation set`,
      );
    } catch (error) {
      problems.push(errorMessage(error));
    }
    if (batch.expectedObligationCount !== batch.cells.length ||
      batch.expectedObligationSetHash !==
        releaseValidationProofExactSetHash(
          'release-validation-observation-batch-obligations-v1',
          batch.cells.map((cell) => cell.obligationId),
        )) {
      problems.push(`Observation batch ${batch.batchId} omits expected cells`);
    }
    for (const cell of batch.cells) {
      const obligation = obligationsById.get(cell.obligationId);
      const forecast = forecastsById.get(cell.forecastId);
      const outcome = cell.outcomeId ? outcomesById.get(cell.outcomeId) : null;
      if (!obligation ||
        obligation.cohortId !== batch.cohortId ||
        !forecast ||
        forecast.obligationId !== cell.obligationId) {
        problems.push(
          `Observation batch ${batch.batchId} has an invalid cell reference`,
        );
      }
      if (cell.disposition === 'observed' &&
        (!outcome ||
          outcome.forecastId !== cell.forecastId ||
          outcome.obligationId !== cell.obligationId)) {
        problems.push(
          `Observation batch ${batch.batchId} has an invalid observed outcome`,
        );
      }
    }
  }

  for (const evaluation of bundle.evaluationReceipts) {
    const activeCohorts = releaseValidationActiveCohortsAt(
      bundle,
      evaluation.proofEpochId,
      evaluation.evaluatedAt,
    );
    const expectedCohortIds = activeCohorts.map((cohort) => cohort.cohortId);
    const expectedCellKeys = activeCohorts.flatMap((cohort) =>
      cohort.requiredCellIds.map((cellId) =>
        releaseValidationCohortCellKey(cohort.cohortId, cellId)));
    const expectedBatchIds = bundle.observationBatches
      .filter((batch) =>
        evaluation.cohortIds.includes(batch.cohortId) &&
        Date.parse(batch.observedAt) <= Date.parse(evaluation.evaluatedAt))
      .map((batch) => batch.batchId);
    const expectedOutcomeIds = bundle.outcomes
      .filter((outcome) =>
        evaluation.cohortIds.includes(outcome.cohortId) &&
        Date.parse(outcome.observedAt) <= Date.parse(evaluation.evaluatedAt))
      .map((outcome) => outcome.outcomeId);
    try {
      assertExactStringSet(
        evaluation.cohortIds,
        expectedCohortIds,
        `Evaluation ${evaluation.evaluationId} cohort set`,
      );
      assertExactStringSet(
        evaluation.requiredCellKeys,
        expectedCellKeys,
        `Evaluation ${evaluation.evaluationId} required cell set`,
      );
      assertExactStringSet(
        evaluation.observationBatchIds,
        expectedBatchIds,
        `Evaluation ${evaluation.evaluationId} observation batch set`,
      );
      assertExactStringSet(
        evaluation.outcomeIds,
        expectedOutcomeIds,
        `Evaluation ${evaluation.evaluationId} outcome set`,
      );
    } catch (error) {
      problems.push(errorMessage(error));
    }
    for (const batchId of evaluation.observationBatchIds) {
      const batch = batchesById.get(batchId);
      if (!batch ||
        batch.proofEpochId !== evaluation.proofEpochId ||
        Date.parse(batch.observedAt) > Date.parse(evaluation.evaluatedAt)) {
        problems.push(
          `Evaluation ${evaluation.evaluationId} has an invalid batch set`,
        );
      }
    }
    for (const outcomeId of evaluation.outcomeIds) {
      const outcome = outcomesById.get(outcomeId);
      if (!outcome ||
        outcome.proofEpochId !== evaluation.proofEpochId ||
        Date.parse(outcome.observedAt) > Date.parse(evaluation.evaluatedAt)) {
        problems.push(
          `Evaluation ${evaluation.evaluationId} has an invalid outcome set`,
        );
      }
    }
  }

  for (const promotion of bundle.promotionReceipts) {
    const evaluation = evaluationsById.get(promotion.evaluationId);
    if (!evaluation ||
      evaluation.contentHash !== promotion.evaluationContentHash ||
      evaluation.proofEpochId !== promotion.proofEpochId ||
      Date.parse(promotion.promotedAt) < Date.parse(evaluation.evaluatedAt)) {
      problems.push(
        `Promotion ${promotion.promotionId} lacks its exact evaluation receipt`,
      );
      continue;
    }
    const currentEvaluation = bundle.evaluationReceipts
      .filter((candidate) =>
        candidate.proofEpochId === promotion.proofEpochId &&
        candidate.epochSequence < promotion.epochSequence &&
        Date.parse(candidate.evaluatedAt) <=
          Date.parse(promotion.promotedAt))
      .slice()
      .sort((left, right) =>
        Date.parse(right.evaluatedAt) - Date.parse(left.evaluatedAt) ||
        right.epochSequence - left.epochSequence ||
        right.evaluationId.localeCompare(left.evaluationId))[0] ?? null;
    if (
      !currentEvaluation ||
      currentEvaluation.evaluationId !== evaluation.evaluationId ||
      currentEvaluation.contentHash !== evaluation.contentHash
    ) {
      problems.push(
        `Promotion ${promotion.promotionId} does not bind the latest ` +
        `evaluation receipt`,
      );
    }
    if (promotion.environment === 'production' &&
      evaluation.status !== 'validated') {
      problems.push(
        `Production promotion ${promotion.promotionId} requires validated evidence`,
      );
    }
    try {
      assertExactStringSet(
        promotion.cohortIds,
        evaluation.cohortIds,
        `Promotion ${promotion.promotionId} cohort set`,
      );
      assertExactStringSet(
        promotion.cohortIds,
        releaseValidationActiveCohortsAt(
          bundle,
          promotion.proofEpochId,
          promotion.promotedAt,
        )
          .filter((cohort) =>
            cohort.epochSequence < promotion.epochSequence)
          .map((cohort) => cohort.cohortId),
        `Promotion ${promotion.promotionId} active cohort set`,
      );
      const promotedForecastIds = bundle.forecasts
        .filter((forecast) =>
          promotion.cohortIds.includes(forecast.cohortId) &&
          Date.parse(forecast.recordedAt) <=
            Date.parse(evaluation.evaluatedAt))
        .map((forecast) => forecast.forecastId);
      const promotedOutcomeIds = bundle.outcomes
        .filter((outcome) =>
          promotion.cohortIds.includes(outcome.cohortId) &&
          Date.parse(outcome.observedAt) <=
            Date.parse(evaluation.evaluatedAt))
        .map((outcome) => outcome.outcomeId);
      assertExactStringSet(
        promotion.forecastIds,
        promotedForecastIds,
        `Promotion ${promotion.promotionId} forecast set`,
      );
      assertExactStringSet(
        promotion.outcomeIds,
        promotedOutcomeIds,
        `Promotion ${promotion.promotionId} outcome set`,
      );
    } catch (error) {
      problems.push(errorMessage(error));
    }
    const unevaluatedEvidence = releaseValidationUnevaluatedCohortEvidence(
      bundle,
      {
        cohortIds: promotion.cohortIds,
        evaluatedAt: evaluation.evaluatedAt,
        observedAt: promotion.promotedAt,
      },
    );
    if (unevaluatedEvidence.length > 0) {
      problems.push(
        `Promotion ${promotion.promotionId} includes post-evaluation ` +
        `cohort evidence: ${unevaluatedEvidence.slice(0, 10).join(', ')}`,
      );
    }
  }

  return {
    valid: problems.length === 0,
    problems: [...new Set(problems)],
    epochChainTips,
    cohortChainTips,
  };
}

export function assertValidReleaseValidationProofBundle(
  bundle: ReleaseValidationProofBundle,
): void {
  const verification = verifyReleaseValidationProofBundle(bundle);
  if (!verification.valid) {
    throw new ReleaseValidationProofValidationError(verification.problems);
  }
}

function buildReconciliationRows(input: {
  reconciliationId: string;
  reconciledAt: string;
  previousMembers: readonly ReleaseValidationCatalogMember[];
  currentMembers: readonly ReleaseValidationCatalogMember[];
}): ReleaseValidationCatalogReconciliationRow[] {
  const previousByRelease = new Map(
    input.previousMembers.map((member) => [member.release.releaseId, member]),
  );
  const currentByRelease = new Map(
    input.currentMembers.map((member) => [member.release.releaseId, member]),
  );
  const orderedReleaseIds = [
    ...input.currentMembers.map((member) => member.release.releaseId),
    ...input.previousMembers
      .map((member) => member.release.releaseId)
      .filter((releaseId) => !currentByRelease.has(releaseId)),
  ];
  return orderedReleaseIds.map((releaseId, ordinal) => {
    const previous = previousByRelease.get(releaseId) ?? null;
    const current = currentByRelease.get(releaseId) ?? null;
    const status: ReleaseValidationCatalogReconciliationStatus =
      previous && current ? 'retained' : current ? 'added' : 'retired';
    const reconciliationRowId = releaseValidationProofHash(
      'release-validation-catalog-reconciliation-row-id-v1',
      { reconciliationId: input.reconciliationId, releaseId },
    );
    const row = {
      kind: 'catalog_reconciliation_row' as const,
      schemaVersion: RELEASE_VALIDATION_PROOF_SCHEMA_VERSION as 1,
      reconciliationRowId,
      reconciliationId: input.reconciliationId,
      ordinal,
      releaseId,
      status,
      previousMemberId: previous?.memberId ?? null,
      previousMemberContentHash: previous?.contentHash ?? null,
      currentMemberId: current?.memberId ?? null,
      currentMemberContentHash: current?.contentHash ?? null,
      retiredAt: status === 'retired' ? input.reconciledAt : null,
    };
    return {
      ...row,
      contentHash: releaseValidationCatalogReconciliationRowContentHash(row),
    };
  });
}

function assertCatalogObservationMembers(
  observation: ReleaseValidationCatalogObservation,
  unorderedMembers: readonly ReleaseValidationCatalogMember[],
): void {
  const members = unorderedMembers
    .slice()
    .sort((left, right) => left.ordinal - right.ordinal);
  if (members.some((member, index) =>
    member.observationId !== observation.observationId ||
    member.ordinal !== index)) {
    throw new Error('catalog members have missing, duplicate, or non-contiguous ordinals');
  }
  for (const member of members) {
    const expected = sealReleaseValidationCatalogMember({
      observationId: member.observationId,
      ordinal: member.ordinal,
      release: member.release,
    });
    assertCanonicalReplay(member, expected, 'catalog member');
  }
  assertCatalogMemberUniqueness(members);
  const memberIds = members.map((member) => member.memberId);
  const memberContentHashes = members.map((member) => member.contentHash);
  const releaseIds = members.map((member) => member.release.releaseId);
  const expected = {
    memberCount: members.length,
    memberIdOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-member-ids-v1',
      memberIds,
    ),
    memberIdSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-member-ids-v1',
      memberIds,
    ),
    memberContentOrderedHash: releaseValidationProofOrderedHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    memberContentSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-member-content-v1',
      memberContentHashes,
    ),
    releaseIdSetHash: releaseValidationProofExactSetHash(
      'release-validation-catalog-release-ids-v1',
      releaseIds,
    ),
  };
  for (const [key, value] of Object.entries(expected)) {
    if (observation[key as keyof typeof expected] !== value) {
      throw new Error(`catalog observation ${key} mismatch`);
    }
  }
  const { contentHash: _contentHash, ...hashInput } = observation;
  if (releaseValidationCatalogObservationContentHash(hashInput) !==
    observation.contentHash) {
    throw new Error('catalog observation content hash mismatch');
  }
}

function assertCatalogMemberUniqueness(
  members: readonly ReleaseValidationCatalogMember[],
): void {
  assertUnique(
    members.map((member) => member.release.releaseId),
    'catalog release identity',
  );
  const aliasOwner = new Map<string, string>();
  for (const member of members) {
    for (const alias of member.release.aliases) {
      const owner = aliasOwner.get(alias);
      if (owner && owner !== member.release.releaseId) {
        throw new Error(
          `Catalog alias ${JSON.stringify(alias)} maps to multiple release identities`,
        );
      }
      aliasOwner.set(alias, member.release.releaseId);
    }
  }
}

function verifyEpochChains(
  bundle: ReleaseValidationProofBundle,
  epochsById: Map<string, ReleaseValidationProofEpoch>,
  tips: Record<string, string | null>,
  problems: string[],
): void {
  const rows: Array<EpochChainLink & {
    readonly kind: string;
    readonly recordedAt?: string;
    readonly observedAt?: string;
    readonly reconciledAt?: string;
    readonly evaluatedAt?: string;
    readonly promotedAt?: string;
  }> = [
    ...bundle.retirements,
    ...bundle.policies,
    ...bundle.cohorts,
    ...bundle.catalogObservations,
    ...bundle.catalogReconciliations,
    ...bundle.evaluationReceipts,
    ...bundle.promotionReceipts,
  ];
  const rowsByEpoch = groupBy(rows, (row) => row.proofEpochId);
  for (const [proofEpochId, epochRows] of rowsByEpoch) {
    const epoch = epochsById.get(proofEpochId);
    if (!epoch) {
      problems.push(`Epoch chain ${proofEpochId} references a missing epoch`);
      continue;
    }
    const ordered = epochRows.slice().sort((left, right) =>
      left.epochSequence - right.epochSequence);
    let previous: string | null = null;
    let previousArtifactAtMs = Date.parse(epoch.startsAt);
    for (const [index, row] of ordered.entries()) {
      if (row.epochSequence !== index + 1) {
        problems.push(
          `Epoch chain ${proofEpochId} diverges at sequence ${row.epochSequence}`,
        );
      }
      if (row.previousEpochContentHash !== previous) {
        problems.push(
          `Epoch chain ${proofEpochId} previous hash mismatch at sequence ` +
          row.epochSequence,
        );
      }
      const artifactAt = epochArtifactTime(row);
      if (artifactAt != null &&
        Date.parse(artifactAt) < Date.parse(epoch.startsAt)) {
        problems.push(
          `Epoch chain ${proofEpochId} contains a pre-epoch ${row.kind}`,
        );
      }
      if (artifactAt != null) {
        const artifactAtMs = Date.parse(artifactAt);
        if (artifactAtMs < previousArtifactAtMs) {
          problems.push(
            `Epoch chain ${proofEpochId} backdates ${row.kind} at sequence ` +
            row.epochSequence,
          );
        }
        previousArtifactAtMs = Math.max(previousArtifactAtMs, artifactAtMs);
      }
      previous = row.contentHash;
    }
    tips[proofEpochId] = previous;
    const retirements = ordered.filter(
      (row): row is ReleaseValidationProofEpochRetirement =>
        row.kind === 'proof_epoch_retirement',
    );
    if (retirements.length > 1) {
      problems.push(`Proof epoch ${proofEpochId} has multiple retirements`);
    }
    const retirement = retirements[0];
    if (retirement) {
      if (retirement.epochContentHash !== epoch.contentHash) {
        problems.push(`Proof epoch ${proofEpochId} retirement binds wrong epoch`);
      }
      if (retirement !== ordered.at(-1)) {
        problems.push(`Proof epoch ${proofEpochId} has records after retirement`);
      }
      if (Date.parse(retirement.retiredAt) < Date.parse(epoch.startsAt)) {
        problems.push(`Proof epoch ${proofEpochId} retirement is backdated`);
      }
      for (const row of ordered) {
        const artifactAt = epochArtifactTime(row);
        if (artifactAt != null &&
          Date.parse(artifactAt) > Date.parse(retirement.retiredAt)) {
          problems.push(
            `Proof epoch ${proofEpochId} contains post-retirement ${row.kind}`,
          );
        }
      }
    }
  }
  for (const epoch of bundle.epochs) {
    tips[epoch.proofEpochId] ??= null;
  }
}

function verifyCohortChains(
  bundle: ReleaseValidationProofBundle,
  cohortsById: Map<string, ReleaseValidationCohort>,
  tips: Record<string, string | null>,
  problems: string[],
): void {
  const rows: Array<CohortChainLink & { readonly kind: string }> = [
    ...bundle.obligations,
    ...bundle.splitAssignments,
    ...bundle.forecasts,
    ...bundle.outcomes,
    ...bundle.observationBatches,
  ];
  const rowsByCohort = groupBy(rows, (row) => row.cohortId);
  for (const [cohortId, cohortRows] of rowsByCohort) {
    const cohort = cohortsById.get(cohortId);
    if (!cohort) {
      problems.push(`Cohort chain ${cohortId} references a missing cohort`);
      continue;
    }
    const ordered = cohortRows.slice().sort((left, right) =>
      left.cohortSequence - right.cohortSequence);
    let previous: string | null = null;
    let previousArtifactAtMs = Date.parse(cohort.startsAt);
    for (const [index, row] of ordered.entries()) {
      if (row.cohortSequence !== index + 1) {
        problems.push(
          `Cohort chain ${cohortId} diverges at sequence ${row.cohortSequence}`,
        );
      }
      if (row.previousCohortContentHash !== previous) {
        problems.push(
          `Cohort chain ${cohortId} previous hash mismatch at sequence ` +
          row.cohortSequence,
        );
      }
      if (row.proofEpochId !== cohort.proofEpochId) {
        problems.push(`Cohort chain ${cohortId} crosses proof epochs`);
      }
      const artifactAt = cohortArtifactTime(row);
      if (artifactAt != null &&
        Date.parse(artifactAt) < Date.parse(cohort.startsAt)) {
        problems.push(
          `Cohort chain ${cohortId} contains a pre-cohort ${row.kind}`,
        );
      }
      if (artifactAt != null && cohort.retiredAt != null &&
        Date.parse(artifactAt) >= Date.parse(cohort.retiredAt)) {
        problems.push(
          `Cohort chain ${cohortId} contains post-retirement ${row.kind}`,
        );
      }
      if (artifactAt != null) {
        const artifactAtMs = Date.parse(artifactAt);
        if (artifactAtMs < previousArtifactAtMs) {
          problems.push(
            `Cohort chain ${cohortId} backdates ${row.kind} at sequence ` +
            row.cohortSequence,
          );
        }
        previousArtifactAtMs = Math.max(previousArtifactAtMs, artifactAtMs);
      }
      previous = row.contentHash;
    }
    tips[cohortId] = previous;
  }
  for (const cohort of bundle.cohorts) {
    tips[cohort.cohortId] ??= null;
  }
}

function epochArtifactTime(
  row: EpochChainLink & { readonly kind: string },
): string | null {
  switch (row.kind) {
    case 'proof_epoch_retirement':
      return (row as ReleaseValidationProofEpochRetirement).retiredAt;
    case 'policy':
      return (row as ReleaseValidationPolicy).effectiveAt;
    case 'cohort':
      return (row as ReleaseValidationCohort).startsAt;
    case 'catalog_observation':
      return (row as ReleaseValidationCatalogObservation).observedAt;
    case 'catalog_reconciliation':
      return (row as ReleaseValidationCatalogReconciliation).reconciledAt;
    case 'evaluation_receipt':
      return (row as ReleaseValidationEvaluationReceipt).evaluatedAt;
    case 'promotion_receipt':
      return (row as ReleaseValidationPromotionReceipt).promotedAt;
    default:
      return null;
  }
}

function cohortArtifactTime(
  row: CohortChainLink & { readonly kind: string },
): string | null {
  switch (row.kind) {
    case 'obligation':
      return (row as ReleaseValidationObligation).recordedAt;
    case 'split_assignment':
      return (row as ReleaseValidationSplitAssignment).assignedAt;
    case 'forecast_v2':
      return (row as ReleaseValidationForecastV2).recordedAt;
    case 'outcome_v2':
      return (row as ReleaseValidationOutcomeV2).observedAt;
    case 'observation_batch':
      return (row as ReleaseValidationObservationBatch).observedAt;
    default:
      return null;
  }
}

function assertStableReleaseIdentity(
  value: unknown,
  label: string,
): asserts value is ReleaseValidationStableReleaseIdentity {
  assertExactRecord(value, label, [
    'releaseId',
    'repository',
    'nodeId',
    'tagCommitOid',
    'publishedAt',
    'aliases',
  ]);
  const release = value as unknown as ReleaseValidationStableReleaseIdentity;
  if (!Array.isArray(release.aliases)) {
    throw new Error(`${label}.aliases must be an array`);
  }
  const expected = createReleaseValidationStableReleaseIdentity(release);
  assertCanonicalReplay(release, expected, label);
}

function assertCanonicalReplay(
  actual: unknown,
  expected: unknown,
  label: string,
): void {
  if (
    canonicalReleaseValidationProofJson(actual) !==
    canonicalReleaseValidationProofJson(expected)
  ) {
    throw new Error(`${label} is not a canonical deterministic replay`);
  }
}

function validateRows<T>(
  rows: readonly T[],
  validator: (value: unknown) => void,
  problems: string[],
): void {
  for (const row of rows) {
    try {
      validator(row);
    } catch (error) {
      problems.push(errorMessage(error));
    }
  }
}

function uniqueMap<T>(
  rows: readonly T[],
  key: (row: T) => string,
  label: string,
  problems: string[],
): Map<string, T> {
  const values = new Map<string, T>();
  for (const row of rows) {
    const identity = key(row);
    if (values.has(identity)) {
      problems.push(`Duplicate ${label} identity ${JSON.stringify(identity)}`);
    } else {
      values.set(identity, row);
    }
  }
  return values;
}

function groupBy<T>(
  rows: readonly T[],
  key: (row: T) => string,
): Map<string, T[]> {
  const values = new Map<string, T[]>();
  for (const row of rows) {
    const grouped = values.get(key(row)) ?? [];
    grouped.push(row);
    values.set(key(row), grouped);
  }
  return values;
}

function canonicalValue(
  value: unknown,
  ancestors: WeakSet<object>,
  path: string,
): ReleaseValidationProofJsonValue {
  if (
    value === null ||
    typeof value === 'boolean' ||
    typeof value === 'string'
  ) {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} contains a non-finite number`);
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (value === undefined) {
    throw new Error(`${path} contains undefined`);
  }
  if (
    typeof value === 'bigint' ||
    typeof value === 'function' ||
    typeof value === 'symbol'
  ) {
    throw new Error(`${path} contains a non-JSON value`);
  }
  if (typeof value !== 'object') {
    throw new Error(`${path} cannot be canonicalized`);
  }
  if (ancestors.has(value)) {
    throw new Error(`${path} contains a cycle`);
  }
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      const output: ReleaseValidationProofJsonValue[] = [];
      for (let index = 0; index < value.length; index++) {
        if (!Object.hasOwn(value, index)) {
          throw new Error(`${path}[${index}] is a sparse array cell`);
        }
        output.push(canonicalValue(value[index], ancestors, `${path}[${index}]`));
      }
      return output;
    }
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new Error(`${path} must be a plain JSON object`);
    }
    if (Object.getOwnPropertySymbols(value).length > 0) {
      throw new Error(`${path} contains symbol keys`);
    }
    const record = value as Record<string, unknown>;
    const output: Record<string, ReleaseValidationProofJsonValue> = {};
    for (const key of Object.keys(record).sort((left, right) =>
      left.localeCompare(right))) {
      output[key] = canonicalValue(record[key], ancestors, `${path}.${key}`);
    }
    return output;
  } finally {
    ancestors.delete(value);
  }
}

function assertExactRecord(
  value: unknown,
  label: string,
  keys: readonly string[],
): asserts value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`${label} must be an object`);
  }
  const actual = Object.keys(value).sort();
  const expected = [...keys].sort();
  if (!sameOrderedStrings(actual, expected)) {
    throw new Error(
      `${label} keys mismatch: expected ${expected.join(', ')}, ` +
      `received ${actual.join(', ')}`,
    );
  }
}

function normalizedAliases(values: readonly string[]): string[] {
  if (!Array.isArray(values)) {
    throw new Error('release aliases must be an array');
  }
  const normalized = values.map((value) =>
    requiredToken(value, 'release alias'));
  assertUnique(normalized, 'release alias');
  return normalized;
}

function normalizedUniqueStrings(
  values: readonly string[],
  label: string,
): string[] {
  if (!Array.isArray(values)) {
    throw new Error(`${label} must be an array`);
  }
  const normalized = values.map((value) => requiredToken(value, label));
  assertUnique(normalized, label);
  return normalized;
}

function requiredString(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a string`);
  }
  return value;
}

function requiredToken(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`${label} must be a string`);
  }
  const normalized = value.trim();
  if (
    normalized.length === 0 ||
    normalized.length > 1_024 ||
    /[\u0000-\u001f\u007f]/.test(normalized)
  ) {
    throw new Error(`${label} must be a non-empty printable token`);
  }
  return normalized;
}

function requiredSha256(value: unknown, label: string): string {
  const normalized = requiredToken(value, label).toLowerCase();
  if (!SHA256_RE.test(normalized)) {
    throw new Error(`${label} must be a SHA-256 hash`);
  }
  return normalized;
}

function optionalSha256(value: unknown, label: string): string | null {
  return value == null ? null : requiredSha256(value, label);
}

function normalizedOptionalTimestamp(
  value: string | null | undefined,
  label: string,
): string | null {
  return value == null
    ? null
    : normalizeReleaseValidationProofTimestamp(value, label);
}

function nonNegativeInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || Number(value) < 0) {
    throw new Error(`${label} must be a non-negative integer`);
  }
  return Number(value);
}

function positiveInteger(value: unknown, label: string): number {
  if (!Number.isInteger(value) || Number(value) <= 0) {
    throw new Error(`${label} must be a positive integer`);
  }
  return Number(value);
}

function assertUnique(values: readonly string[], label: string): void {
  if (new Set(values).size !== values.length) {
    throw new Error(`${label} values must be unique`);
  }
}

function assertExactStringSet(
  actual: readonly string[],
  expected: readonly string[],
  label: string,
): void {
  assertUnique(actual, `${label} actual`);
  assertUnique(expected, `${label} expected`);
  const actualHash = releaseValidationProofExactSetHash(
    'release-validation-exact-comparison-v1',
    actual,
  );
  const expectedHash = releaseValidationProofExactSetHash(
    'release-validation-exact-comparison-v1',
    expected,
  );
  if (actual.length !== expected.length || actualHash !== expectedHash) {
    throw new Error(
      `${label} mismatch: same counts are insufficient without the exact set`,
    );
  }
}

function sameOrderedStrings(
  left: readonly string[],
  right: readonly string[],
): boolean {
  return left.length === right.length &&
    left.every((value, index) => value === right[index]);
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

export const __releaseValidationProofTest = {
  assertCatalogObservationMembers,
  assertExactStringSet,
  canonicalTimestampPattern: CANONICAL_TIMESTAMP_RE,
};
