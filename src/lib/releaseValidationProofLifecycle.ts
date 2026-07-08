import { normalizeCodeRevision } from './codeRevision';
import {
  RELEASE_VALIDATION_HORIZONS,
  type ReleaseValidationHorizonCode,
} from './releaseValidation';
import {
  RELEASE_VALIDATION_OPPORTUNITIES,
  type ReleaseValidationOpportunityCode,
} from './releaseValidationOpportunityDenominator';
import {
  RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT,
  RELEASE_VALIDATION_SPLIT_POLICY_CODE,
  assertValidReleaseValidationProofBundle,
  canonicalReleaseValidationProofJson,
  createReleaseValidationStableReleaseIdentity,
  normalizeReleaseValidationProofTimestamp,
  normalizeReleaseValidationRepository,
  releaseValidationCatalogObservationId,
  releaseValidationPolicyCell,
  releaseValidationSplitPolicyHash,
  releaseValidationSplitSeedHash,
  sealReleaseValidationCatalogObservation,
  sealReleaseValidationCatalogReconciliation,
  sealReleaseValidationCohort,
  sealReleaseValidationObligation,
  sealReleaseValidationPolicy,
  sealReleaseValidationProofEpoch,
  sealReleaseValidationProofEpochRetirement,
  sealReleaseValidationSplitAssignment,
  verifyReleaseValidationProofBundle,
  type ReleaseValidationCatalogMember,
  type ReleaseValidationCatalogObservation,
  type ReleaseValidationCatalogReconciliation,
  type ReleaseValidationCatalogReconciliationRow,
  type ReleaseValidationCohort,
  type ReleaseValidationObligation,
  type ReleaseValidationPolicy,
  type ReleaseValidationProofBundle,
  type ReleaseValidationProofEpoch,
  type ReleaseValidationProofEpochRetirement,
  type ReleaseValidationProofVerification,
  type ReleaseValidationSplitAssignment,
} from './releaseValidationProof';

const HOUR_MS = 3_600_000;

export const RELEASE_VALIDATION_REQUIRED_POLICY_CELLS = (
  Object.keys(RELEASE_VALIDATION_OPPORTUNITIES) as
    ReleaseValidationOpportunityCode[]
).flatMap((opportunityCode) =>
  (Object.keys(RELEASE_VALIDATION_HORIZONS) as
    ReleaseValidationHorizonCode[]).map((horizonCode) => ({
    opportunityCode,
    horizonCode,
  })));

export interface ReleaseValidationProofLifecycleReleaseInput {
  readonly repository: string;
  readonly nodeId: string;
  readonly tagCommitOid: string;
  readonly publishedAt: string;
  readonly aliases?: readonly string[];
}

export interface ReleaseValidationProofLifecycleInput {
  readonly existing: ReleaseValidationProofBundle;
  readonly repository: string;
  readonly observedAt: string;
  readonly source: string;
  readonly releases: readonly ReleaseValidationProofLifecycleReleaseInput[];
  readonly modelVersion: string;
  readonly promptVersion: number;
  readonly codeRevision: string;
  readonly policyCode?: string;
  readonly policyVersion?: number;
  readonly developmentArm: 'production' | 'calibration';
  readonly developmentReleaseCount?: number;
}

export interface ReleaseValidationProofLifecycleAppend {
  readonly epochs: readonly ReleaseValidationProofEpoch[];
  readonly retirements: readonly ReleaseValidationProofEpochRetirement[];
  readonly policies: readonly ReleaseValidationPolicy[];
  readonly cohorts: readonly ReleaseValidationCohort[];
  readonly catalogObservations:
    readonly ReleaseValidationCatalogObservation[];
  readonly catalogMembers: readonly ReleaseValidationCatalogMember[];
  readonly catalogReconciliations:
    readonly ReleaseValidationCatalogReconciliation[];
  readonly catalogReconciliationRows:
    readonly ReleaseValidationCatalogReconciliationRow[];
  readonly obligations: readonly ReleaseValidationObligation[];
  readonly splitAssignments: readonly ReleaseValidationSplitAssignment[];
}

export interface ReleaseValidationProofLifecyclePlan {
  readonly append: ReleaseValidationProofLifecycleAppend;
  readonly bundle: ReleaseValidationProofBundle;
  readonly verification: ReleaseValidationProofVerification;
  readonly epoch: ReleaseValidationProofEpoch;
  readonly policy: ReleaseValidationPolicy;
  readonly cohort: ReleaseValidationCohort;
  readonly catalogObservation: ReleaseValidationCatalogObservation;
  readonly catalogReconciliation: ReleaseValidationCatalogReconciliation;
  readonly admittedReleaseCount: number;
  readonly excludedPreInceptionReleaseCount: number;
}

export function planReleaseValidationProofLifecycle(
  input: ReleaseValidationProofLifecycleInput,
): ReleaseValidationProofLifecyclePlan {
  assertValidReleaseValidationProofBundle(input.existing);
  const repository = normalizeReleaseValidationRepository(input.repository);
  const observedAt = normalizeReleaseValidationProofTimestamp(
    input.observedAt,
    'lifecycle observedAt',
  );
  const codeRevision = normalizeCodeRevision(input.codeRevision);
  if (!codeRevision) {
    throw new Error('Release validation lifecycle requires a concrete code revision');
  }
  const releases = input.releases
    .map((release) => createReleaseValidationStableReleaseIdentity(release))
    .sort((left, right) =>
      Date.parse(right.publishedAt) - Date.parse(left.publishedAt) ||
      left.releaseId.localeCompare(right.releaseId));
  assertUniqueReleaseIds(releases.map((release) => release.releaseId));
  if (releases.some((release) =>
    release.repository !== repository ||
    Date.parse(release.publishedAt) > Date.parse(observedAt))) {
    throw new Error(
      'Release validation lifecycle catalog has a foreign or future release',
    );
  }

  const modelVersion = input.modelVersion.trim();
  const policyCode =
    (input.policyCode ?? 'prospective-release-validation').trim();
  const policyVersion = input.policyVersion ?? 1;
  const developmentReleaseCount =
    input.developmentReleaseCount ??
    RELEASE_VALIDATION_DEFAULT_DEVELOPMENT_RELEASE_COUNT;
  const splitPolicyHash = releaseValidationSplitPolicyHash({
    splitPolicyCode: RELEASE_VALIDATION_SPLIT_POLICY_CODE,
    developmentArm: input.developmentArm,
    developmentReleaseCount,
  });
  const requiredCellIds = RELEASE_VALIDATION_REQUIRED_POLICY_CELLS.map(
    releaseValidationPolicyCell,
  );
  const append = mutableLifecycleAppend();
  const retirementsByEpochId = new Map(
    input.existing.retirements.map((row) => [row.proofEpochId, row]),
  );
  const repositoryEpochs = input.existing.epochs.filter((row) =>
    row.repository === repository);
  const activeEpochs = repositoryEpochs.filter((row) => {
    const retirement = retirementsByEpochId.get(row.proofEpochId);
    return (
      Date.parse(row.startsAt) <= Date.parse(observedAt) &&
      (
        retirement == null ||
        Date.parse(retirement.retiredAt) > Date.parse(observedAt)
      )
    );
  });
  if (activeEpochs.length > 1) {
    throw new Error(`Repository ${repository} has multiple active proof epochs`);
  }
  let epoch = activeEpochs[0];
  if (
    !epoch &&
    repositoryEpochs.some((row) =>
      Date.parse(row.startsAt) > Date.parse(observedAt))
  ) {
    throw new Error('Release validation lifecycle observation predates its epoch');
  }
  const pendingRetirement = epoch
    ? retirementsByEpochId.get(epoch.proofEpochId)
    : null;
  if (pendingRetirement) {
    throw new Error(
      `Release validation lifecycle epoch is sealed pending retirement at ` +
      pendingRetirement.retiredAt,
    );
  }
  const baseVerification = verifyReleaseValidationProofBundle(input.existing);
  if (
    epoch &&
    shouldRotateProductionEpoch({
      bundle: input.existing,
      epoch,
      observedAt,
      modelVersion,
      promptVersion: input.promptVersion,
      codeRevision,
      policyCode,
      policyVersion,
      splitPolicyHash,
      requiredCellIds: requiredCellIds.map((cell) => cell.cellId),
      developmentArm: input.developmentArm,
    })
  ) {
    const retirement = sealReleaseValidationProofEpochRetirement({
      proofEpochId: epoch.proofEpochId,
      epochContentHash: epoch.contentHash,
      epochSequence:
        maximumEpochSequence(input.existing, epoch.proofEpochId) + 1,
      previousEpochContentHash:
        baseVerification.epochChainTips[epoch.proofEpochId] ?? null,
      recordedAt: observedAt,
      retiredAt: observedAt,
      reason: 'superseded by a new production validation stratum',
    });
    append.retirements.push(retirement);
    epoch = sealReleaseValidationProofEpoch({
      repository,
      recordedAt: observedAt,
      startsAt: observedAt,
    });
    append.epochs.push(epoch);
  }
  if (!epoch) {
    epoch = sealReleaseValidationProofEpoch({
      repository,
      recordedAt: observedAt,
      startsAt: observedAt,
    });
    append.epochs.push(epoch);
  }

  let epochSequence = maximumEpochSequence(
    input.existing,
    epoch.proofEpochId,
  );
  let epochTip =
    baseVerification.epochChainTips[epoch.proofEpochId] ?? null;
  const policyCollisions = input.existing.policies.filter((row) =>
    row.proofEpochId === epoch.proofEpochId &&
    row.policyCode === policyCode &&
    row.policyVersion === policyVersion);
  const exactPolicies = policyCollisions.filter((row) =>
    row.retiredAt == null &&
    Date.parse(row.effectiveAt) <= Date.parse(observedAt) &&
    row.splitPolicyHash === splitPolicyHash &&
    canonicalReleaseValidationProofJson(row.requiredCells) ===
      canonicalReleaseValidationProofJson(requiredCellIds));
  if (exactPolicies.length > 1) {
    throw new Error('Release validation lifecycle has duplicate active policies');
  }
  if (policyCollisions.length > 0 && exactPolicies.length === 0) {
    throw new Error(
      `Validation policy ${policyCode}@${policyVersion} already has ` +
      'different immutable semantics',
    );
  }
  let policy = exactPolicies[0];
  if (!policy) {
    policy = sealReleaseValidationPolicy({
      proofEpochId: epoch.proofEpochId,
      epochSequence: ++epochSequence,
      previousEpochContentHash: epochTip,
      policyCode,
      policyVersion,
      recordedAt: observedAt,
      effectiveAt: observedAt,
      splitPolicyCode: RELEASE_VALIDATION_SPLIT_POLICY_CODE,
      developmentArm: input.developmentArm,
      developmentReleaseCount,
      requiredCells: RELEASE_VALIDATION_REQUIRED_POLICY_CELLS,
    });
    append.policies.push(policy);
    epochTip = policy.contentHash;
  }

  const cohortCandidates = input.existing.cohorts.filter((row) =>
    row.proofEpochId === epoch.proofEpochId &&
    row.policyId === policy.policyId &&
    row.policyContentHash === policy.contentHash &&
    row.modelVersion === modelVersion &&
    row.promptVersion === input.promptVersion &&
    row.codeRevision === codeRevision &&
    row.retiredAt == null &&
    Date.parse(row.startsAt) <= Date.parse(observedAt));
  if (cohortCandidates.length > 1) {
    throw new Error('Release validation lifecycle has duplicate active cohorts');
  }
  let cohort = cohortCandidates[0];
  if (!cohort) {
    cohort = sealReleaseValidationCohort({
      proofEpochId: epoch.proofEpochId,
      epochSequence: ++epochSequence,
      previousEpochContentHash: epochTip,
      policyId: policy.policyId,
      policyContentHash: policy.contentHash,
      modelVersion: input.modelVersion,
      promptVersion: input.promptVersion,
      codeRevision,
      recordedAt: observedAt,
      startsAt: observedAt,
      requiredCellIds: policy.requiredCells.map((cell) => cell.cellId),
    });
    append.cohorts.push(cohort);
    epochTip = cohort.contentHash;
  }

  const observationId = releaseValidationCatalogObservationId({
    proofEpochId: epoch.proofEpochId,
    source: input.source,
    observedAt,
  });
  const existingObservation = input.existing.catalogObservations.find(
    (row) => row.observationId === observationId,
  );
  let catalogObservation: ReleaseValidationCatalogObservation;
  let catalogMembers: readonly ReleaseValidationCatalogMember[];
  if (existingObservation) {
    const existingMembers = input.existing.catalogMembers
      .filter((row) => row.observationId === observationId)
      .sort((left, right) => left.ordinal - right.ordinal);
    const expected = sealReleaseValidationCatalogObservation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: existingObservation.epochSequence,
      previousEpochContentHash:
        existingObservation.previousEpochContentHash,
      source: input.source,
      observedAt,
      exhaustive: true,
      stabilized: true,
      releases,
    });
    if (
      canonicalReleaseValidationProofJson(existingObservation) !==
        canonicalReleaseValidationProofJson(expected.observation) ||
      canonicalReleaseValidationProofJson(existingMembers) !==
        canonicalReleaseValidationProofJson(expected.members)
    ) {
      throw new Error(
        'Existing release validation catalog observation differs from retry input',
      );
    }
    catalogObservation = existingObservation;
    catalogMembers = existingMembers;
  } else {
    const sealed = sealReleaseValidationCatalogObservation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: ++epochSequence,
      previousEpochContentHash: epochTip,
      source: input.source,
      observedAt,
      exhaustive: true,
      stabilized: true,
      releases,
    });
    catalogObservation = sealed.observation;
    catalogMembers = sealed.members;
    append.catalogObservations.push(catalogObservation);
    append.catalogMembers.push(...catalogMembers);
    epochTip = catalogObservation.contentHash;
  }

  const matchingReconciliations =
    input.existing.catalogReconciliations.filter((row) =>
      row.currentObservationId === catalogObservation.observationId);
  if (matchingReconciliations.length > 1) {
    throw new Error(
      'Release validation catalog observation has multiple reconciliations',
    );
  }
  let catalogReconciliation = matchingReconciliations[0];
  if (!catalogReconciliation) {
    const previousObservation = latestCatalogObservationBefore(
      mergeLifecycleBundle(input.existing, append),
      epoch.proofEpochId,
      catalogObservation.epochSequence,
    );
    const currentBundle = mergeLifecycleBundle(input.existing, append);
    const previousMembers = previousObservation
      ? currentBundle.catalogMembers
        .filter((row) => row.observationId === previousObservation.observationId)
        .sort((left, right) => left.ordinal - right.ordinal)
      : [];
    const sealed = sealReleaseValidationCatalogReconciliation({
      proofEpochId: epoch.proofEpochId,
      epochSequence: ++epochSequence,
      previousEpochContentHash: epochTip,
      reconciledAt: observedAt,
      previousObservation,
      previousMembers,
      currentObservation: catalogObservation,
      currentMembers: catalogMembers,
    });
    catalogReconciliation = sealed.reconciliation;
    append.catalogReconciliations.push(catalogReconciliation);
    append.catalogReconciliationRows.push(...sealed.rows);
    epochTip = catalogReconciliation.contentHash;
  }

  let workingBundle = mergeLifecycleBundle(input.existing, append);
  const activeCohorts = workingBundle.cohorts
    .filter((row) =>
      row.proofEpochId === epoch.proofEpochId &&
      Date.parse(row.startsAt) <= Date.parse(observedAt) &&
      (
        row.retiredAt == null ||
        Date.parse(row.retiredAt) > Date.parse(observedAt)
      ))
    .sort((left, right) => left.epochSequence - right.epochSequence);
  let admittedReleaseCount = 0;
  let excludedPreInceptionReleaseCount = 0;

  for (const activeCohort of activeCohorts) {
    const activePolicy = workingBundle.policies.find(
      (row) => row.policyId === activeCohort.policyId,
    );
    if (!activePolicy) {
      throw new Error(`Cohort ${activeCohort.cohortId} has no policy`);
    }
    const admissions = cohortAdmissions(workingBundle, activeCohort);
    admittedReleaseCount += admissions.length;
    excludedPreInceptionReleaseCount += workingBundle.catalogMembers
      .filter((member) =>
        member.observationId === catalogObservation.observationId &&
        Date.parse(member.release.publishedAt) <
          Date.parse(activeCohort.startsAt))
      .length;
    let cohortSequence = maximumCohortSequence(
      workingBundle,
      activeCohort.cohortId,
    );
    let cohortTip = verifyReleaseValidationProofBundle(workingBundle)
      .cohortChainTips[activeCohort.cohortId] ?? null;

    for (const [admissionIndex, admission] of admissions.entries()) {
      const admissionOrdinal = admissionIndex + 1;
      const arm =
        admissionOrdinal <= activePolicy.developmentReleaseCount
          ? activePolicy.developmentArm
          : 'holdout';
      const seedHash = releaseValidationSplitSeedHash({
        proofEpochId: activeCohort.proofEpochId,
        cohortId: activeCohort.cohortId,
        releaseId: admission.member.release.releaseId,
        admissionOrdinal,
        splitPolicyHash: activePolicy.splitPolicyHash,
      });
      for (const cell of activePolicy.requiredCells) {
        const existingObligations = workingBundle.obligations.filter((row) =>
          row.cohortId === activeCohort.cohortId &&
          row.release.releaseId === admission.member.release.releaseId &&
          row.cellId === cell.cellId);
        if (existingObligations.length > 1) {
          throw new Error(
            `Release validation obligation is duplicated for ${cell.cellId}`,
          );
        }
        if (existingObligations.length === 1) continue;
        const timing = obligationTiming({
          publishedAt: admission.member.release.publishedAt,
          opportunityCode: cell.opportunityCode,
          horizonCode: cell.horizonCode,
        });
        const obligation = sealReleaseValidationObligation({
          proofEpochId: activeCohort.proofEpochId,
          cohortId: activeCohort.cohortId,
          cohortSequence: ++cohortSequence,
          previousCohortContentHash: cohortTip,
          cellId: cell.cellId,
          opportunityCode: cell.opportunityCode,
          horizonCode: cell.horizonCode,
          release: admission.member.release,
          recordedAt: observedAt,
          ...timing,
          catalogObservationId:
            admission.reconciliation.currentObservationId,
          catalogObservationContentHash:
            admission.reconciliation.currentObservationContentHash,
          reconciliationId: admission.reconciliation.reconciliationId,
          reconciliationContentHash: admission.reconciliation.contentHash,
        });
        append.obligations.push(obligation);
        cohortTip = obligation.contentHash;
        const assignment = sealReleaseValidationSplitAssignment({
          proofEpochId: activeCohort.proofEpochId,
          cohortId: activeCohort.cohortId,
          cohortSequence: ++cohortSequence,
          previousCohortContentHash: cohortTip,
          obligationId: obligation.obligationId,
          assignedAt: observedAt,
          arm,
          splitPolicyHash: activePolicy.splitPolicyHash,
          seedHash,
        });
        append.splitAssignments.push(assignment);
        cohortTip = assignment.contentHash;
        workingBundle = mergeLifecycleBundle(input.existing, append);
      }
    }
  }

  const bundle = mergeLifecycleBundle(input.existing, append);
  assertValidReleaseValidationProofBundle(bundle);
  const verification = verifyReleaseValidationProofBundle(bundle);
  return {
    append: freezeLifecycleAppend(append),
    bundle,
    verification,
    epoch,
    policy,
    cohort,
    catalogObservation,
    catalogReconciliation,
    admittedReleaseCount,
    excludedPreInceptionReleaseCount,
  };
}

function cohortAdmissions(
  bundle: ReleaseValidationProofBundle,
  cohort: ReleaseValidationCohort,
): Array<{
  readonly member: ReleaseValidationCatalogMember;
  readonly reconciliation: ReleaseValidationCatalogReconciliation;
}> {
  const membersById = new Map(
    bundle.catalogMembers.map((member) => [member.memberId, member]),
  );
  const rowsByReconciliation = new Map<string,
    ReleaseValidationCatalogReconciliationRow[]>();
  for (const row of bundle.catalogReconciliationRows) {
    const rows = rowsByReconciliation.get(row.reconciliationId) ?? [];
    rows.push(row);
    rowsByReconciliation.set(row.reconciliationId, rows);
  }
  const seenReleaseIds = new Set<string>();
  const admissions: Array<{
    readonly member: ReleaseValidationCatalogMember;
    readonly reconciliation: ReleaseValidationCatalogReconciliation;
  }> = [];
  const reconciliations = bundle.catalogReconciliations
    .filter((row) =>
      row.proofEpochId === cohort.proofEpochId &&
      row.epochSequence > cohort.epochSequence &&
      Date.parse(row.reconciledAt) >= Date.parse(cohort.startsAt) &&
      (
        cohort.retiredAt == null ||
        Date.parse(row.reconciledAt) < Date.parse(cohort.retiredAt)
      ))
    .sort((left, right) => left.epochSequence - right.epochSequence);
  for (const reconciliation of reconciliations) {
    const rows = (
      rowsByReconciliation.get(reconciliation.reconciliationId) ?? []
    ).slice().sort((left, right) => left.ordinal - right.ordinal);
    for (const row of rows) {
      if (row.status !== 'added' || row.currentMemberId == null) continue;
      const member = membersById.get(row.currentMemberId);
      if (
        !member ||
        Date.parse(member.release.publishedAt) < Date.parse(cohort.startsAt) ||
        seenReleaseIds.has(member.release.releaseId)
      ) {
        continue;
      }
      seenReleaseIds.add(member.release.releaseId);
      admissions.push({ member, reconciliation });
    }
  }
  return admissions;
}

function obligationTiming(input: {
  publishedAt: string;
  opportunityCode: string;
  horizonCode: string;
}): {
  opensAt: string;
  closesAtExclusive: string;
  outcomeDueAt: string;
} {
  const opportunity = (
    RELEASE_VALIDATION_OPPORTUNITIES as Record<string, {
      minAgeHours: number;
      maxAgeHours: number;
    }>
  )[input.opportunityCode];
  const horizon = (
    RELEASE_VALIDATION_HORIZONS as Record<string, { durationMs: number }>
  )[input.horizonCode];
  if (!opportunity || !horizon) {
    throw new Error(
      `Unsupported validation cell ${input.opportunityCode}/` +
      input.horizonCode,
    );
  }
  const publishedAtMs = Date.parse(input.publishedAt);
  const opensAtMs = publishedAtMs + opportunity.minAgeHours * HOUR_MS;
  const closesAtExclusiveMs =
    publishedAtMs + opportunity.maxAgeHours * HOUR_MS;
  return {
    opensAt: new Date(opensAtMs).toISOString(),
    closesAtExclusive: new Date(closesAtExclusiveMs).toISOString(),
    outcomeDueAt: new Date(
      closesAtExclusiveMs + horizon.durationMs,
    ).toISOString(),
  };
}

function latestCatalogObservationBefore(
  bundle: ReleaseValidationProofBundle,
  proofEpochId: string,
  epochSequence: number,
): ReleaseValidationCatalogObservation | null {
  return bundle.catalogObservations
    .filter((row) =>
      row.proofEpochId === proofEpochId &&
      row.epochSequence < epochSequence)
    .sort((left, right) => right.epochSequence - left.epochSequence)[0] ?? null;
}

function shouldRotateProductionEpoch(input: {
  bundle: ReleaseValidationProofBundle;
  epoch: ReleaseValidationProofEpoch;
  observedAt: string;
  modelVersion: string;
  promptVersion: number;
  codeRevision: string;
  policyCode: string;
  policyVersion: number;
  splitPolicyHash: string;
  requiredCellIds: readonly string[];
  developmentArm: 'production' | 'calibration';
}): boolean {
  if (input.developmentArm !== 'production') return false;
  const policiesById = new Map(
    input.bundle.policies.map((policy) => [policy.policyId, policy]),
  );
  const activeProductionCohorts = input.bundle.cohorts.filter((cohort) => {
    if (
      cohort.proofEpochId !== input.epoch.proofEpochId ||
      Date.parse(cohort.startsAt) > Date.parse(input.observedAt) ||
      (
        cohort.retiredAt != null &&
        Date.parse(cohort.retiredAt) <= Date.parse(input.observedAt)
      )
    ) {
      return false;
    }
    return policiesById.get(cohort.policyId)?.developmentArm === 'production';
  });
  if (activeProductionCohorts.length === 0) return false;

  return activeProductionCohorts.some((cohort) => {
    const policy = policiesById.get(cohort.policyId);
    return (
      !policy ||
      policy.policyCode !== input.policyCode ||
      policy.policyVersion !== input.policyVersion ||
      policy.retiredAt != null ||
      Date.parse(policy.effectiveAt) > Date.parse(input.observedAt) ||
      policy.splitPolicyHash !== input.splitPolicyHash ||
      canonicalReleaseValidationProofJson(
        policy.requiredCells.map((cell) => cell.cellId),
      ) !== canonicalReleaseValidationProofJson(input.requiredCellIds) ||
      cohort.policyContentHash !== policy.contentHash ||
      cohort.modelVersion !== input.modelVersion ||
      cohort.promptVersion !== input.promptVersion ||
      cohort.codeRevision !== input.codeRevision
    );
  });
}

function maximumEpochSequence(
  bundle: ReleaseValidationProofBundle,
  proofEpochId: string,
): number {
  return Math.max(0, ...[
    ...bundle.retirements,
    ...bundle.policies,
    ...bundle.cohorts,
    ...bundle.catalogObservations,
    ...bundle.catalogReconciliations,
    ...bundle.evaluationReceipts,
    ...bundle.promotionReceipts,
  ].filter((row) => row.proofEpochId === proofEpochId)
    .map((row) => row.epochSequence));
}

function maximumCohortSequence(
  bundle: ReleaseValidationProofBundle,
  cohortId: string,
): number {
  return Math.max(0, ...[
    ...bundle.obligations,
    ...bundle.splitAssignments,
    ...bundle.forecasts,
    ...bundle.outcomes,
    ...bundle.observationBatches,
  ].filter((row) => row.cohortId === cohortId)
    .map((row) => row.cohortSequence));
}

function mergeLifecycleBundle(
  existing: ReleaseValidationProofBundle,
  append: MutableReleaseValidationProofLifecycleAppend,
): ReleaseValidationProofBundle {
  return {
    ...existing,
    epochs: [...existing.epochs, ...append.epochs],
    retirements: [...existing.retirements, ...append.retirements],
    policies: [...existing.policies, ...append.policies],
    cohorts: [...existing.cohorts, ...append.cohorts],
    catalogObservations: [
      ...existing.catalogObservations,
      ...append.catalogObservations,
    ],
    catalogMembers: [...existing.catalogMembers, ...append.catalogMembers],
    catalogReconciliations: [
      ...existing.catalogReconciliations,
      ...append.catalogReconciliations,
    ],
    catalogReconciliationRows: [
      ...existing.catalogReconciliationRows,
      ...append.catalogReconciliationRows,
    ],
    obligations: [...existing.obligations, ...append.obligations],
    splitAssignments: [
      ...existing.splitAssignments,
      ...append.splitAssignments,
    ],
  };
}

type MutableReleaseValidationProofLifecycleAppend = {
  -readonly [Key in keyof ReleaseValidationProofLifecycleAppend]:
    Array<ReleaseValidationProofLifecycleAppend[Key][number]>;
};

function mutableLifecycleAppend():
  MutableReleaseValidationProofLifecycleAppend {
  return {
    epochs: [],
    retirements: [],
    policies: [],
    cohorts: [],
    catalogObservations: [],
    catalogMembers: [],
    catalogReconciliations: [],
    catalogReconciliationRows: [],
    obligations: [],
    splitAssignments: [],
  };
}

function freezeLifecycleAppend(
  append: MutableReleaseValidationProofLifecycleAppend,
): ReleaseValidationProofLifecycleAppend {
  return {
    epochs: [...append.epochs],
    retirements: [...append.retirements],
    policies: [...append.policies],
    cohorts: [...append.cohorts],
    catalogObservations: [...append.catalogObservations],
    catalogMembers: [...append.catalogMembers],
    catalogReconciliations: [...append.catalogReconciliations],
    catalogReconciliationRows: [...append.catalogReconciliationRows],
    obligations: [...append.obligations],
    splitAssignments: [...append.splitAssignments],
  };
}

function assertUniqueReleaseIds(releaseIds: readonly string[]): void {
  if (new Set(releaseIds).size !== releaseIds.length) {
    throw new Error('Release validation lifecycle catalog repeats a release');
  }
}
