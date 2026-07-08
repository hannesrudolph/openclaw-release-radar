import {
  closureClaimAuthorityEvidenceForCandidate,
  getClosureClaimCandidate,
  getCurrentClosureClaimExtractionReceipt,
  getScoreAuthorityResolutionRun,
  listClosureClaimCandidatesForIssue,
  type ClosureProofJoinedRow,
} from './db';
import {
  buildScoreClosureClaimAuthorityResolution,
  scoreClosureClaimAuthorityResolutionProblems,
  type ScoreClosureClaimAuthorityResolution,
} from './scoreAuthorityResolution';
import {
  closureRiskDisposition,
  type ClosureRiskDisposition,
} from './closureProofTaxonomy';
import { canonicalIssueNumbersFromEvidence } from './closureRiskAggregation';
import type { ClosureClaimCandidate } from './closureClaimCandidates';

export interface ClosureClaimAuthorityBinding {
  candidate: ClosureClaimCandidate;
  resolution: ScoreClosureClaimAuthorityResolution;
}

export interface ClosureDispositionAuthoritySelection {
  required: boolean;
  satisfied: boolean;
  claims: ClosureClaimAuthorityBinding[];
}

export interface ReleaseClosureAuthorityEvaluation {
  releaseExplicitlyUnaffected(issueNumber: number, releaseTag: string): boolean;
  closureDisposition(
    row: Pick<ClosureProofJoinedRow, 'issue_number' | 'status' | 'evidence_json'>,
  ): ClosureRiskDisposition;
}

export interface ReleaseClosureAuthorityEvaluationOptions {
  loadClaimsForIssue?: (issueNumber: number) => ClosureClaimAuthorityBinding[];
  onAuthorizedClaim?: (binding: ClosureClaimAuthorityBinding) => void;
}

const NON_ACTIONABLE_CLOSURE_RATIONALES = new Set([
  'not_planned',
  'expected_behavior',
  'not_reproducible',
  'insufficient_info',
  'out_of_scope',
  'inactivity',
  'reporter_request',
]);

export function createReleaseClosureAuthorityEvaluation(
  options: ReleaseClosureAuthorityEvaluationOptions = {},
): ReleaseClosureAuthorityEvaluation {
  const claimsByIssue = new Map<number, ClosureClaimAuthorityBinding[]>();
  const loadClaimsForIssue = options.loadClaimsForIssue ?? loadCurrentClosureClaimsForIssue;
  const claimsForIssue = (issueNumber: number): ClosureClaimAuthorityBinding[] => {
    const cached = claimsByIssue.get(issueNumber);
    if (cached) return cached;
    const loaded = loadClaimsForIssue(issueNumber);
    claimsByIssue.set(issueNumber, loaded);
    return loaded;
  };

  const unaffectedByIssueAndRelease = new Map<string, boolean>();
  const dispositionByProofIdentity = new Map<string, ClosureRiskDisposition>();

  return {
    releaseExplicitlyUnaffected(issueNumber, releaseTag) {
      const key = `${issueNumber}\0${normalizeReleaseToken(releaseTag)}`;
      const cached = unaffectedByIssueAndRelease.get(key);
      if (cached != null) return cached;
      const claim = selectAuthorizedReleaseNotAffectedClaim(
        claimsForIssue(issueNumber),
        releaseTag,
      );
      if (claim) options.onAuthorizedClaim?.(claim);
      const unaffected = claim != null;
      unaffectedByIssueAndRelease.set(key, unaffected);
      return unaffected;
    },

    closureDisposition(row) {
      const key =
        `${row.issue_number}\0${row.status}\0${row.evidence_json}`;
      const cached = dispositionByProofIdentity.get(key);
      if (cached) return cached;

      const canonicalIssueNumbers = canonicalIssueNumbersFromEvidence(
        row.evidence_json,
      );
      const relevantClaims = new Map<
        number,
        readonly ClosureClaimAuthorityBinding[]
      >();
      for (const issueNumber of [
        row.issue_number,
        ...canonicalIssueNumbers,
      ]) {
        if (!relevantClaims.has(issueNumber)) {
          relevantClaims.set(issueNumber, claimsForIssue(issueNumber));
        }
      }
      const authority = selectClosureDispositionAuthority({
        status: row.status,
        sourceIssueNumber: row.issue_number,
        canonicalIssueNumbers,
        evidenceJson: row.evidence_json,
        claimsByIssue: relevantClaims,
      });
      const disposition =
        authority.required && !authority.satisfied
          ? 'unsupported_closure_claim'
          : closureRiskDisposition(row.status);
      if (authority.satisfied) {
        for (const claim of authority.claims) {
          options.onAuthorizedClaim?.(claim);
        }
      }
      dispositionByProofIdentity.set(key, disposition);
      return disposition;
    },
  };
}

export function createReleaseClosureAuthorityEvaluationForRun(
  authorityRunId: string,
): ReleaseClosureAuthorityEvaluation {
  const run = getScoreAuthorityResolutionRun(authorityRunId);
  if (!run) {
    throw new Error(
      `Score authority resolution run ${authorityRunId} is missing`,
    );
  }
  const bindingsByIssue = new Map<number, ClosureClaimAuthorityBinding[]>();
  for (const row of run.rows) {
    if (row.subjectKind !== 'closure_claim') continue;
    let resolution: ScoreClosureClaimAuthorityResolution;
    try {
      resolution = JSON.parse(
        row.resolutionJson,
      ) as ScoreClosureClaimAuthorityResolution;
    } catch (error) {
      throw new Error(
        `Score authority closure claim ${row.subjectIdentity} has invalid ` +
          `resolution JSON: ${
            error instanceof Error ? error.message : String(error)
          }`,
      );
    }
    const problems = scoreClosureClaimAuthorityResolutionProblems(
      resolution,
    );
    if (problems.length > 0) {
      throw new Error(
        `Score authority closure claim ${row.subjectIdentity} is invalid: ` +
          problems.join('; '),
      );
    }
    const candidateId = row.candidateId;
    const candidate = candidateId
      ? getClosureClaimCandidate(candidateId)
      : null;
    if (
      !candidate ||
      row.authorizedForScoring !== true ||
      resolution.authorizedForScoring !== true ||
      row.subjectIdentity !== candidateId ||
      resolution.candidateId !== candidateId ||
      row.issueNumber !== candidate.issue.number ||
      resolution.issueNumber !== candidate.issue.number
    ) {
      throw new Error(
        `Score authority closure claim ${row.subjectIdentity} does not ` +
          'match its immutable candidate and stored authorization',
      );
    }
    const issueBindings = bindingsByIssue.get(row.issueNumber) ?? [];
    issueBindings.push({ candidate, resolution });
    bindingsByIssue.set(row.issueNumber, issueBindings);
  }
  for (const bindings of bindingsByIssue.values()) {
    bindings.sort((left, right) =>
      String(left.candidate.candidateId).localeCompare(
        String(right.candidate.candidateId),
      ));
  }
  return createReleaseClosureAuthorityEvaluation({
    loadClaimsForIssue: (issueNumber) =>
      bindingsByIssue.get(issueNumber) ?? [],
  });
}

function loadCurrentClosureClaimsForIssue(
  issueNumber: number,
): ClosureClaimAuthorityBinding[] {
  if (listClosureClaimCandidatesForIssue(issueNumber).length === 0) {
    return [];
  }
  const receipt = getCurrentClosureClaimExtractionReceipt(issueNumber);
  if (!receipt) return [];
  return receipt.members.map((member) => {
    const evidence = closureClaimAuthorityEvidenceForCandidate(
      member.candidateId,
    );
    if (
      evidence.extractionReceiptId !== receipt.receiptId ||
      evidence.extractionReceiptContentHash !== receipt.contentHash ||
      evidence.candidate.issue.number !== issueNumber ||
      evidence.candidate.candidateId !== member.candidateId
    ) {
      throw new Error(
        `Closure claim candidate ${member.candidateId} does not match ` +
          `current extraction receipt ${receipt.receiptId} for issue ` +
          `#${issueNumber}`,
      );
    }
    return {
      candidate: evidence.candidate,
      resolution: buildScoreClosureClaimAuthorityResolution(evidence),
    };
  });
}

export function selectAuthorizedReleaseNotAffectedClaim(
  claims: readonly ClosureClaimAuthorityBinding[],
  releaseTag: string,
): ClosureClaimAuthorityBinding | null {
  const normalizedReleaseTag = normalizeReleaseToken(releaseTag);
  const relevantClaims = authorizedClosureClaims(claims, ({ candidate }) =>
    candidate.claim.kind === 'release_local' &&
    ['not_affected', 'affected', 'not_fixed'].includes(
      candidate.claim.assertion,
    ) &&
    normalizeReleaseToken(candidate.claim.releaseTag) === normalizedReleaseTag);
  if (relevantClaims.length === 0) return null;

  const chronological = relevantClaims.map((binding) => ({
    binding,
    updatedAt: closureClaimUpdatedAt(binding),
  }));
  if (chronological.some(({ updatedAt }) => updatedAt == null)) {
    return null;
  }

  const latestUpdatedAt = chronological
    .map(({ updatedAt }) => updatedAt as string)
    .sort()
    .at(-1) as string;
  const latestClaims = chronological
    .filter(({ updatedAt }) => updatedAt === latestUpdatedAt)
    .map(({ binding }) => binding);
  if (latestClaims.some(({ candidate }) =>
    candidate.claim.kind === 'release_local' &&
    (
      candidate.claim.assertion === 'affected' ||
      candidate.claim.assertion === 'not_fixed'
    ))) {
    return null;
  }
  return firstAuthorizedClosureClaim(latestClaims, ({ candidate }) =>
    candidate.claim.kind === 'release_local' &&
    candidate.claim.assertion === 'not_affected');
}

export function selectClosureDispositionAuthority(input: {
  status: string;
  sourceIssueNumber: number;
  canonicalIssueNumbers: readonly number[];
  evidenceJson?: string | Record<string, unknown> | null;
  claimsByIssue: ReadonlyMap<
    number,
    readonly ClosureClaimAuthorityBinding[]
  >;
}): ClosureDispositionAuthoritySelection {
  const sourceClaims = (
    input.claimsByIssue.get(input.sourceIssueNumber) ?? []
  ).filter((binding) =>
    binding.candidate.issue.number === input.sourceIssueNumber);
  const requireSourceClaim = (
    predicate: (binding: ClosureClaimAuthorityBinding) => boolean,
  ): ClosureDispositionAuthoritySelection => {
    const claim = firstAuthorizedClosureClaim(sourceClaims, predicate);
    return {
      required: true,
      satisfied: claim != null,
      claims: claim ? [claim] : [],
    };
  };

  if (input.status === 'reporter_replaced') {
    return requireSourceClaim(({ candidate }) =>
      candidate.claim.kind === 'reporter_action' &&
      candidate.claim.action === 'replaced_or_refiled');
  }
  if (input.status === 'reporter_withdrawn') {
    return requireSourceClaim(({ candidate }) =>
      candidate.claim.kind === 'reporter_action' &&
      (
        candidate.claim.action === 'withdrawn' ||
        candidate.claim.action === 'requested_closure'
      ));
  }
  if (input.status === 'reporter_self_closed') {
    return requireSourceClaim(({ candidate }) =>
      candidate.claim.kind === 'reporter_action' &&
      candidate.claim.action === 'self_closed');
  }
  if (input.status === 'not_planned') {
    const claim = selectAuthorizedNonActionableClosureClaim(sourceClaims);
    return {
      required: true,
      satisfied: claim != null,
      claims: claim ? [claim] : [],
    };
  }
  if (input.status === 'duplicate_to_non_actionable_canonical') {
    const canonicalIssueNumbers = [...new Set(input.canonicalIssueNumbers)]
      .filter((issueNumber) =>
        Number.isInteger(issueNumber) &&
        issueNumber > 0 &&
        issueNumber !== input.sourceIssueNumber);
    const proofContexts = canonicalAuthorityProofContexts(
      input.evidenceJson,
      input.sourceIssueNumber,
      canonicalIssueNumbers,
    );
    if (proofContexts.length === 0) {
      return { required: true, satisfied: false, claims: [] };
    }

    const claims: ClosureClaimAuthorityBinding[] = [];
    const selectedCandidateIds = new Set<string>();
    for (const proofContext of proofContexts) {
      const terminalClaims = (
        input.claimsByIssue.get(proofContext.terminalIssueNumber) ?? []
      ).filter((binding) =>
        binding.candidate.issue.number === proofContext.terminalIssueNumber);
      const canonicalRepositories = [...new Set(
        terminalClaims
          .map(candidateRepositoryName)
          .filter((repository): repository is string => repository != null),
      )].sort();
      let selectedClaims: [
        ClosureClaimAuthorityBinding,
        ClosureClaimAuthorityBinding,
      ] | null = null;
      for (const canonicalRepository of canonicalRepositories) {
        if (
          proofContext.repositoryNameWithOwner != null &&
          canonicalRepository !== proofContext.repositoryNameWithOwner
        ) {
          continue;
        }
        const canonicalClaim = selectAuthorizedNonActionableClosureClaim(
          terminalClaims.filter((binding) =>
            candidateRepositoryName(binding) === canonicalRepository),
        );
        if (!canonicalClaim) continue;
        const sourceClaim = firstAuthorizedClosureClaim(
          sourceClaims,
          ({ candidate }) => {
            if (candidate.claim.kind !== 'duplicate_or_superseded') return false;
            if (candidate.issue.number !== input.sourceIssueNumber) return false;
            const sourceRepository = normalizeRepositoryName(
              candidate.repository?.nameWithOwner,
            );
            const target = candidate.claim.target;
            return sourceRepository === canonicalRepository &&
              target?.resource === 'issue' &&
              normalizeRepositoryName(target.repositoryNameWithOwner) ===
                canonicalRepository &&
              proofContext.sourceTargetIssueNumbers.includes(target.number);
          },
        );
        if (sourceClaim) {
          selectedClaims = [sourceClaim, canonicalClaim];
          break;
        }
      }
      if (!selectedClaims) {
        return {
          required: true,
          satisfied: false,
          claims: [],
        };
      }
      for (const claim of selectedClaims) {
        const candidateId = claim.candidate.candidateId;
        if (candidateId == null || selectedCandidateIds.has(candidateId)) {
          continue;
        }
        selectedCandidateIds.add(candidateId);
        claims.push(claim);
      }
    }
    return {
      required: true,
      satisfied: true,
      claims,
    };
  }
  return {
    required: false,
    satisfied: true,
    claims: [],
  };
}

function isAuthorizedNonActionableClosureClaim(
  binding: ClosureClaimAuthorityBinding,
): boolean {
  const claim = binding.candidate.claim;
  if (claim.kind === 'closure_rationale') {
    return NON_ACTIONABLE_CLOSURE_RATIONALES.has(claim.rationale);
  }
  return claim.kind === 'reporter_action' &&
    [
      'self_closed',
      'requested_closure',
      'withdrawn',
      'resolved_on_reporter_side',
    ].includes(claim.action);
}

function selectAuthorizedNonActionableClosureClaim(
  claims: readonly ClosureClaimAuthorityBinding[],
): ClosureClaimAuthorityBinding | null {
  const relevantClaims = authorizedClosureClaims(claims, (binding) =>
    isAuthorizedNonActionableClosureClaim(binding) ||
    isAuthorizedOngoingFailureClaim(binding));
  if (relevantClaims.length === 0) return null;

  const chronological = relevantClaims.map((binding) => ({
    binding,
    updatedAt: closureClaimUpdatedAt(binding),
  }));
  if (chronological.some(({ updatedAt }) => updatedAt == null)) return null;
  const latestUpdatedAt = chronological
    .map(({ updatedAt }) => updatedAt as string)
    .sort()
    .at(-1) as string;
  const latestClaims = chronological
    .filter(({ updatedAt }) => updatedAt === latestUpdatedAt)
    .map(({ binding }) => binding);
  const sourceKeys = new Set(latestClaims.map(closureClaimSourceKey));
  if (
    sourceKeys.size === 1 &&
    latestClaims.every(({ candidate }) =>
      Number.isSafeInteger(candidate.span?.start))
  ) {
    const latestInSource = latestClaims.slice().sort((left, right) =>
      Number(left.candidate.span?.start) - Number(right.candidate.span?.start) ||
      String(left.candidate.candidateId).localeCompare(
        String(right.candidate.candidateId),
      )).at(-1) as ClosureClaimAuthorityBinding;
    return isAuthorizedOngoingFailureClaim(latestInSource)
      ? null
      : latestInSource;
  }
  if (latestClaims.some(isAuthorizedOngoingFailureClaim)) return null;
  return firstAuthorizedClosureClaim(
    latestClaims,
    isAuthorizedNonActionableClosureClaim,
  );
}

function isAuthorizedOngoingFailureClaim(
  binding: ClosureClaimAuthorityBinding,
): boolean {
  return binding.candidate.claim.kind === 'field_confirmation' &&
    binding.candidate.claim.confirmation === 'still_failing';
}

function firstAuthorizedClosureClaim(
  claims: readonly ClosureClaimAuthorityBinding[],
  predicate: (binding: ClosureClaimAuthorityBinding) => boolean,
): ClosureClaimAuthorityBinding | null {
  return authorizedClosureClaims(claims, predicate)[0] ?? null;
}

function authorizedClosureClaims(
  claims: readonly ClosureClaimAuthorityBinding[],
  predicate: (binding: ClosureClaimAuthorityBinding) => boolean,
): ClosureClaimAuthorityBinding[] {
  return claims.filter((binding) => {
    const candidateId = binding.candidate.candidateId;
    return candidateId != null &&
      binding.resolution.authorizedForScoring === true &&
      binding.resolution.candidateId === candidateId &&
      binding.resolution.issueNumber === binding.candidate.issue.number &&
      predicate(binding);
  })
    .sort((left, right) =>
      String(left.candidate.candidateId).localeCompare(
        String(right.candidate.candidateId),
      ));
}

function closureClaimUpdatedAt(
  binding: ClosureClaimAuthorityBinding,
): string | null {
  const updatedAt = binding.candidate.source?.updatedAt;
  if (
    typeof updatedAt !== 'string' ||
    !updatedAt ||
    !Number.isFinite(Date.parse(updatedAt))
  ) {
    return null;
  }
  return new Date(Date.parse(updatedAt)).toISOString();
}

function closureClaimSourceKey(
  binding: ClosureClaimAuthorityBinding,
): string {
  const source = binding.candidate.source;
  return [
    source?.kind ?? '',
    source?.nodeId ?? '',
    source?.createdAt ?? '',
    source?.updatedAt ?? '',
  ].join('\0');
}

function candidateRepositoryName(
  binding: ClosureClaimAuthorityBinding,
): string | null {
  return normalizeRepositoryName(
    binding.candidate.repository?.nameWithOwner,
  );
}

interface CanonicalAuthorityProofContext {
  terminalIssueNumber: number;
  sourceTargetIssueNumbers: number[];
  repositoryNameWithOwner: string | null;
}

function canonicalAuthorityProofContexts(
  evidenceJson: string | Record<string, unknown> | null | undefined,
  sourceIssueNumber: number,
  canonicalIssueNumbers: readonly number[],
): CanonicalAuthorityProofContext[] {
  if (evidenceJson == null) {
    const terminalIssueNumber = canonicalIssueNumbers.length === 1
      ? canonicalIssueNumbers[0]
      : null;
    return terminalIssueNumber == null
      ? []
      : [{
          terminalIssueNumber,
          sourceTargetIssueNumbers: [terminalIssueNumber],
          repositoryNameWithOwner: null,
        }];
  }

  const evidence = parseRecord(evidenceJson);
  const resolution = recordValue(evidence?.canonicalResolution);
  if (!resolution) return [];

  const proofSources: Array<{
    terminalIssue: Record<string, unknown>;
    path: number[];
  }> = [];
  const rootTerminalIssue = recordValue(resolution.terminalIssue);
  const rootTerminalProof = recordValue(resolution.terminalProof);
  if (
    rootTerminalIssue &&
    rootTerminalProof &&
    terminalProofSupportsNonActionableAuthority(rootTerminalProof)
  ) {
    proofSources.push({
      terminalIssue: rootTerminalIssue,
      path: canonicalProofPath(
        resolution,
        sourceIssueNumber,
        positiveIssueNumber(rootTerminalIssue.number),
      ),
    });
  }
  if (Array.isArray(resolution.branches)) {
    for (const branchValue of resolution.branches) {
      const branch = recordValue(branchValue);
      const terminalIssue = recordValue(branch?.terminalIssue);
      const terminalProof = recordValue(branch?.terminalProof);
      if (
        !branch ||
        !terminalIssue ||
        !terminalProof ||
        !terminalProofSupportsNonActionableAuthority(terminalProof)
      ) {
        continue;
      }
      proofSources.push({
        terminalIssue,
        path: issueNumberArray(branch.path),
      });
    }
  }

  const contexts = new Map<string, CanonicalAuthorityProofContext>();
  for (const proofSource of proofSources) {
    const terminalIssueNumber = positiveIssueNumber(
      proofSource.terminalIssue.number,
    );
    if (
      terminalIssueNumber == null ||
      !canonicalIssueNumbers.includes(terminalIssueNumber)
    ) {
      continue;
    }
    const sourceIndex = proofSource.path.indexOf(sourceIssueNumber);
    const nextIssueNumber = sourceIndex >= 0
      ? proofSource.path[sourceIndex + 1] ?? null
      : null;
    const context = {
      terminalIssueNumber,
      sourceTargetIssueNumbers: nextIssueNumber == null
        ? [terminalIssueNumber]
        : [nextIssueNumber],
      repositoryNameWithOwner: repositoryNameFromIssueUrl(
        proofSource.terminalIssue.url,
      ),
    };
    const key = [
      context.terminalIssueNumber,
      context.sourceTargetIssueNumbers.join(','),
      context.repositoryNameWithOwner ?? '',
    ].join('\0');
    contexts.set(key, context);
  }
  return [...contexts.values()].sort((left, right) =>
    left.terminalIssueNumber - right.terminalIssueNumber ||
    left.sourceTargetIssueNumbers.join(',').localeCompare(
      right.sourceTargetIssueNumbers.join(','),
    ) ||
    String(left.repositoryNameWithOwner ?? '').localeCompare(
      String(right.repositoryNameWithOwner ?? ''),
    ));
}

function canonicalProofPath(
  resolution: Record<string, unknown>,
  sourceIssueNumber: number,
  terminalIssueNumber: number | null,
): number[] {
  const candidates = [
    issueNumberArray(resolution.blockingBranch),
    issueNumberArray(resolution.path),
  ];
  if (Array.isArray(resolution.branches)) {
    for (const branchValue of resolution.branches) {
      const branch = recordValue(branchValue);
      if (branch) candidates.push(issueNumberArray(branch.path));
    }
  }
  return candidates.find((path) =>
    path.includes(sourceIssueNumber) &&
    (terminalIssueNumber == null || path.includes(terminalIssueNumber))) ?? [];
}

function parseRecord(
  value: string | Record<string, unknown>,
): Record<string, unknown> | null {
  if (typeof value !== 'string') return recordValue(value);
  try {
    return recordValue(JSON.parse(value));
  } catch {
    return null;
  }
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function issueNumberArray(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return value
    .map(positiveIssueNumber)
    .filter((issueNumber): issueNumber is number => issueNumber != null);
}

function positiveIssueNumber(value: unknown): number | null {
  const issueNumber = Number(value);
  return Number.isInteger(issueNumber) && issueNumber > 0
    ? issueNumber
    : null;
}

function repositoryNameFromIssueUrl(value: unknown): string | null {
  if (typeof value !== 'string') return null;
  const match = /^https?:\/\/github\.com\/([^/\s]+)\/([^/\s]+)\/issues\/\d+\b/i.exec(
    value,
  );
  return match ? normalizeRepositoryName(`${match[1]}/${match[2]}`) : null;
}

function normalizeRepositoryName(value: unknown): string | null {
  if (
    typeof value !== 'string' ||
    !/^[^/\s]+\/[^/\s]+$/.test(value.trim())
  ) {
    return null;
  }
  return value.trim().toLowerCase();
}

function terminalProofSupportsNonActionableAuthority(
  proof: Record<string, unknown>,
): boolean {
  const status = typeof proof.status === 'string' ? proof.status : '';
  if (closureRiskDisposition(status) !== 'neutral_or_non_actionable') {
    return false;
  }
  return status !== 'not_planned' ||
    proof.concreteNonActionableRationale === true;
}

function normalizeReleaseToken(value: string): string {
  return value.trim().replace(/^v/i, '').toLowerCase();
}
