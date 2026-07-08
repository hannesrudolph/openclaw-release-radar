import { createHash } from 'node:crypto';

export const CLOSURE_CLAIM_CANDIDATE_SCHEMA_VERSION = 2;
export const CLOSURE_CLAIM_SOURCE_IDENTITY_SCHEMA_VERSION = 1;
export const CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION = 3;
export const CLOSURE_CLAIM_SOURCE_SNAPSHOT_LEDGER_SCHEMA_VERSION = 1;
export const CLOSURE_CLAIM_CANDIDATE_LEDGER_SCHEMA_VERSION = 1;
export const CLOSURE_CLAIM_EXTRACTION_RECEIPT_SCHEMA_VERSION = 1;

export const CLOSURE_CLAIM_KINDS = [
  'duplicate_or_superseded',
  'fix_proof',
  'release_local',
  'closure_rationale',
  'field_confirmation',
  'reporter_action',
] as const;

export type ClosureClaimKind = (typeof CLOSURE_CLAIM_KINDS)[number];
export type ClosureClaimSourceKind = 'issue_body' | 'comment' | 'closure_event';
export type ClosureClaimCandidateEligibility = 'immutable' | 'display_only';

export interface ClosureClaimActorIdentity {
  nodeId: string | null;
  login: string | null;
  type: string | null;
}

export interface ClosureClaimRepositoryIdentity {
  nodeId: string | null;
  nameWithOwner: string;
}

export interface ClosureClaimIssueIdentity {
  nodeId: string | null;
  number: number;
  author: ClosureClaimActorIdentity;
}

export interface ClosureClaimTextSource {
  nodeId: string | null;
  databaseId?: number | null;
  url?: string | null;
  actor: ClosureClaimActorIdentity;
  createdAt: string | null;
  updatedAt: string | null;
  text?: string | null;
  body?: string | null;
}

export interface ClosureClaimCloserIdentity {
  nodeId: string | null;
  type: string | null;
  number?: number | null;
  oid?: string | null;
  repositoryNameWithOwner?: string | null;
}

export interface ClosureClaimClosureEventSource {
  nodeId: string | null;
  url?: string | null;
  actor: ClosureClaimActorIdentity;
  occurredAt: string | null;
  stateReason: string | null;
  closer?: ClosureClaimCloserIdentity | null;
}

export interface ClosureClaimExtractionInput {
  repository: ClosureClaimRepositoryIdentity;
  issue: ClosureClaimIssueIdentity;
  issueBodies?: readonly ClosureClaimTextSource[];
  issueBody?: ClosureClaimTextSource | null;
  comments?: readonly ClosureClaimTextSource[];
  closureEvents?: readonly ClosureClaimClosureEventSource[];
}

export interface ClosureClaimTarget {
  resource: 'issue' | 'pull_request';
  repositoryNameWithOwner: string;
  number: number;
}

export interface DuplicateOrSupersededClaim {
  kind: 'duplicate_or_superseded';
  relation: 'duplicate' | 'superseded' | 'consolidated' | 'canonical';
  target: ClosureClaimTarget | null;
}

export interface FixProofClaim {
  kind: 'fix_proof';
  proofType: 'pull_request' | 'commit' | 'release' | 'branch' | 'assertion';
  target:
    | ClosureClaimTarget
    | { resource: 'commit'; repositoryNameWithOwner: string | null; oid: string }
    | { resource: 'release'; tag: string }
    | { resource: 'branch'; name: string }
    | null;
}

export interface ReleaseLocalClaim {
  kind: 'release_local';
  assertion: 'affected' | 'not_affected' | 'fixed' | 'not_fixed' | 'available';
  releaseTag: string;
}

export interface ClosureRationaleClaim {
  kind: 'closure_rationale';
  rationale:
    | 'completed'
    | 'fixed'
    | 'duplicate'
    | 'superseded'
    | 'not_planned'
    | 'expected_behavior'
    | 'not_reproducible'
    | 'insufficient_info'
    | 'out_of_scope'
    | 'inactivity'
    | 'reporter_request'
    | 'other';
}

export interface FieldConfirmationClaim {
  kind: 'field_confirmation';
  confirmation:
    | 'reproduced'
    | 'same_failure'
    | 'deployment_affected'
    | 'still_failing';
}

export interface ReporterActionClaim {
  kind: 'reporter_action';
  action:
    | 'self_closed'
    | 'requested_closure'
    | 'withdrawn'
    | 'resolved_on_reporter_side'
    | 'replaced_or_refiled';
  reporterNodeId: string;
  target: ClosureClaimTarget | null;
}

export type ClosureClaim =
  | DuplicateOrSupersededClaim
  | FixProofClaim
  | ReleaseLocalClaim
  | ClosureRationaleClaim
  | FieldConfirmationClaim
  | ReporterActionClaim;

export interface ClosureClaimSourceSnapshot {
  kind: ClosureClaimSourceKind;
  nodeId: string | null;
  databaseId: number | null;
  url: string | null;
  actor: ClosureClaimActorIdentity;
  createdAt: string;
  updatedAt: string;
  textFormat: 'utf8_text' | 'canonical_event_json';
  textDigest: string;
}

export type ClosureClaimIdentityProblem =
  | 'missing_repository_node_id'
  | 'missing_issue_node_id'
  | 'missing_source_node_id'
  | 'missing_actor_node_id'
  | 'missing_actor_type';

export interface ClosureClaimCandidate {
  schemaVersion: typeof CLOSURE_CLAIM_CANDIDATE_SCHEMA_VERSION;
  candidateId: string | null;
  sourceIdentity: string | null;
  canonicalSourceIdentityJson: string | null;
  eligibility: ClosureClaimCandidateEligibility;
  identityProblems: ClosureClaimIdentityProblem[];
  repository: ClosureClaimRepositoryIdentity;
  issue: Pick<ClosureClaimIssueIdentity, 'nodeId' | 'number'>;
  source: ClosureClaimSourceSnapshot;
  claimKind: ClosureClaimKind;
  claim: ClosureClaim;
  canonicalClaimJson: string;
  excerpt: string | null;
  span: { start: number; end: number } | null;
}

export interface ClosureClaimSourceSnapshotLedgerEntry {
  schemaVersion: typeof CLOSURE_CLAIM_SOURCE_SNAPSHOT_LEDGER_SCHEMA_VERSION;
  sourceIdentity: string;
  sourceRevisionIdentity: string;
  repository: ClosureClaimRepositoryIdentity;
  issue: Pick<ClosureClaimIssueIdentity, 'nodeId' | 'number'>;
  source: ClosureClaimSourceSnapshot;
  canonicalSourceJson: string;
  contentHash: string;
}

export interface ClosureClaimCandidateLedgerEntry {
  schemaVersion: typeof CLOSURE_CLAIM_CANDIDATE_LEDGER_SCHEMA_VERSION;
  candidateId: string;
  sourceIdentity: string;
  issue: Pick<ClosureClaimIssueIdentity, 'nodeId' | 'number'>;
  claimKind: ClosureClaimKind;
  canonicalClaimJson: string;
  excerpt: string | null;
  span: { start: number; end: number } | null;
  canonicalCandidateJson: string;
  contentHash: string;
}

export interface ClosureClaimSourceRejection {
  sourceKind: ClosureClaimSourceKind;
  sourceNodeId: string | null;
  code:
    | 'invalid_source'
    | 'conflicting_source_replay';
  detail: string;
}

export interface ClosureClaimExtractionResult {
  schemaVersion: typeof CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION;
  candidates: ClosureClaimCandidate[];
  rejections: ClosureClaimSourceRejection[];
  digest: string;
}

export interface ClosureClaimExtractionEvidenceBinding {
  repository: {
    nodeId: string;
    nameWithOwner: string;
  };
  issue: {
    nodeId: string;
    number: number;
    revision: number;
    updatedAt: string;
    bodyDigest: string;
    authorNodeId: string;
    authorType: string;
  };
  commentSnapshot: {
    revision: number;
    authorityDigest: string;
    stabilizationIdentityDigest: string;
  };
  stateSnapshot: {
    revision: number;
    authorityDigest: string;
    stabilizationIdentityDigest: string;
  };
}

export interface ClosureClaimExtractionReceiptMember {
  ordinal: number;
  candidateId: string;
  candidateContentHash: string;
  sourceIdentity: string;
}

export interface ClosureClaimExtractionReceipt {
  schemaVersion: typeof CLOSURE_CLAIM_EXTRACTION_RECEIPT_SCHEMA_VERSION;
  receiptId: string;
  extractionSchemaVersion: typeof CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION;
  repository: {
    nodeId: string;
    nameWithOwner: string;
  };
  issue: {
    nodeId: string;
    number: number;
    revision: number;
    updatedAt: string;
    bodyDigest: string;
    authorNodeId: string;
    authorType: string;
  };
  commentSnapshot: {
    revision: number;
    authorityDigest: string;
    stabilizationIdentityDigest: string;
  };
  stateSnapshot: {
    revision: number;
    authorityDigest: string;
    stabilizationIdentityDigest: string;
  };
  extractionDigest: string;
  candidateSetDigest: string;
  candidateCount: number;
  members: ClosureClaimExtractionReceiptMember[];
  canonicalReceiptJson: string;
  contentHash: string;
}

interface NormalizedSource {
  source: ClosureClaimSourceSnapshot;
  sourceText: string;
  event: ClosureClaimClosureEventSource | null;
  revisionKey: string | null;
}

interface ExtractedClaim {
  claim: ClosureClaim;
  start: number | null;
  end: number | null;
  excerpt: string | null;
}

interface ActiveClause {
  text: string;
  excerpt: string;
  start: number;
  end: number;
}

interface ReleaseLocalAssertionCue {
  assertion: ReleaseLocalClaim['assertion'];
  start: number;
  end: number;
  priority: number;
}

const KIND_ORDER = new Map<ClosureClaimKind, number>(
  CLOSURE_CLAIM_KINDS.map((kind, index) => [kind, index]),
);
const SOURCE_KIND_ORDER: Record<ClosureClaimSourceKind, number> = {
  issue_body: 0,
  comment: 1,
  closure_event: 2,
};
const SHA256_RE = /^sha256:[0-9a-f]{64}$/;
const HEX_SHA256_RE = /^[0-9a-f]{64}$/;
const RELEASE_TAG_RE = /\bv?(20\d{2}\.\d+(?:\.\d+)?(?:-[0-9a-z][0-9a-z.-]*)?)\b/gi;
const ISSUE_URL_RE =
  /https?:\/\/github\.com\/([a-z0-9_.-]+)\/([a-z0-9_.-]+)\/issues\/(\d+)\b/gi;
const PULL_URL_RE =
  /https?:\/\/github\.com\/([a-z0-9_.-]+)\/([a-z0-9_.-]+)\/pull\/(\d+)\b/gi;
const COMMIT_URL_RE =
  /https?:\/\/github\.com\/([a-z0-9_.-]+)\/([a-z0-9_.-]+)\/commit\/([0-9a-f]{7,40})\b/gi;
const FULL_COMMIT_RE = /\b[0-9a-f]{40}\b/gi;
const BARE_REFERENCE_RE = /#(\d+)\b/g;
const CLAUSE_BOUNDARY_RE =
  /[\r\n]+|[!?;]+|\.(?=\s|$)|\b(?:but|however|yet|nevertheless)\b/gi;
const RELEASE_LOCAL_ASSERTION_PATTERNS: ReadonlyArray<{
  assertion: ReleaseLocalClaim['assertion'];
  re: RegExp;
}> = [
  {
    assertion: 'not_affected',
    re: /\b(?:not affected|does not affect|doesn't affect|unaffected)\b/gi,
  },
  {
    assertion: 'not_fixed',
    re: /\b(?:not fixed|isn't fixed|is not fixed|still (?:broken|fails?|failing|reproduces?))\b/gi,
  },
  {
    assertion: 'fixed',
    re: /\b(?:fixed|resolved|works?|working)\b/gi,
  },
  {
    assertion: 'affected',
    re: /\b(?:affected|affects|broken|fails?|failing|reproduces?|regression)\b/gi,
  },
  {
    assertion: 'available',
    re: /\b(?:available|shipped|included|contains?)\b/gi,
  },
];

export function extractClosureClaimCandidates(
  input: ClosureClaimExtractionInput,
): ClosureClaimExtractionResult {
  assertRepositoryAndIssue(input.repository, input.issue);
  const normalized: NormalizedSource[] = [];
  const rejections: ClosureClaimSourceRejection[] = [];

  const issueBodies = [
    ...(input.issueBodies ?? []),
    ...(input.issueBody ? [input.issueBody] : []),
  ];
  for (const source of issueBodies) {
    normalizeTextSource('issue_body', source, rejections, normalized);
  }
  for (const source of input.comments ?? []) {
    normalizeTextSource('comment', source, rejections, normalized);
  }
  for (const source of input.closureEvents ?? []) {
    normalizeClosureEvent(source, rejections, normalized);
  }

  const acceptedSources = rejectConflictingReplays(normalized, rejections);
  const candidates = acceptedSources.flatMap((source) =>
    candidatesForSource(input.repository, input.issue, source));
  candidates.sort(compareCandidates);

  const orderedRejections = rejections.slice().sort(compareRejections);
  return {
    schemaVersion: CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION,
    candidates,
    rejections: orderedRejections,
    digest: closureClaimCandidateSetDigest(candidates, orderedRejections),
  };
}

export function closureClaimCandidates(
  input: ClosureClaimExtractionInput,
): ClosureClaimCandidate[] {
  return extractClosureClaimCandidates(input).candidates;
}

export const buildClosureClaimCandidates = extractClosureClaimCandidates;

export function canonicalClosureClaimJson(claim: ClosureClaim): string {
  return canonicalJson(claim);
}

export function closureClaimCandidateSetDigest(
  candidates: readonly ClosureClaimCandidate[],
  rejections: readonly ClosureClaimSourceRejection[] = [],
): string {
  const orderedCandidates = candidates.slice().sort(compareCandidates);
  const orderedRejections = rejections.slice().sort(compareRejections);
  return digestCanonical({
    schemaVersion: CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION,
    candidates: orderedCandidates,
    rejections: orderedRejections,
  });
}

export function closureClaimIssueBodyDigest(body: string | null | undefined): string {
  return digestHex(`closure-claim-issue-body-v1\0${body ?? ''}`);
}

export function buildClosureClaimExtractionReceipt(
  binding: ClosureClaimExtractionEvidenceBinding,
  extraction: ClosureClaimExtractionResult,
): ClosureClaimExtractionReceipt {
  assertExtractionEvidenceBinding(binding);
  if (extraction.schemaVersion !== CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION) {
    throw new Error(
      `Closure claim extraction schema version must be ` +
        CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION,
    );
  }
  if (
    extraction.digest !==
      closureClaimCandidateSetDigest(extraction.candidates, extraction.rejections)
  ) {
    throw new Error('Closure claim extraction digest does not replay');
  }
  if (extraction.rejections.length > 0) {
    throw new Error(
      'Closure claim extraction receipt cannot authorize rejected source evidence',
    );
  }

  const members = extraction.candidates.map((candidate) => {
    assertImmutableClosureClaimCandidate(candidate);
    if (
      candidate.repository.nodeId !== binding.repository.nodeId ||
      candidate.repository.nameWithOwner !== binding.repository.nameWithOwner ||
      candidate.issue.nodeId !== binding.issue.nodeId ||
      candidate.issue.number !== binding.issue.number
    ) {
      throw new Error(
        `Closure claim candidate ${candidate.candidateId} does not match ` +
          'the extraction receipt evidence binding',
      );
    }
    if (
      candidate.claim.kind === 'reporter_action' &&
      candidate.claim.reporterNodeId !== binding.issue.authorNodeId
    ) {
      throw new Error(
        `Closure claim candidate ${candidate.candidateId} reporter identity ` +
          'does not match the extraction receipt issue author',
      );
    }
    const entry = buildClosureClaimCandidateLedgerEntry(candidate);
    return {
      ordinal: 0,
      candidateId: entry.candidateId,
      candidateContentHash: entry.contentHash,
      sourceIdentity: entry.sourceIdentity,
    };
  }).sort((left, right) =>
    compareBinary(left.candidateId, right.candidateId) ||
    compareBinary(left.candidateContentHash, right.candidateContentHash) ||
    compareBinary(left.sourceIdentity, right.sourceIdentity)
  ).map((member, ordinal) => ({ ...member, ordinal }));
  if (new Set(members.map((member) => member.candidateId)).size !== members.length) {
    throw new Error('Closure claim extraction receipt contains duplicate candidates');
  }

  const candidateSetDigest = closureClaimExtractionReceiptCandidateSetDigest(members);
  const payload = closureClaimExtractionReceiptPayload({
    schemaVersion: CLOSURE_CLAIM_EXTRACTION_RECEIPT_SCHEMA_VERSION,
    extractionSchemaVersion: extraction.schemaVersion,
    repository: binding.repository,
    issue: {
      ...binding.issue,
      updatedAt: canonicalTimestamp(
        binding.issue.updatedAt,
        'closure claim extraction receipt issue updatedAt',
      ),
    },
    commentSnapshot: binding.commentSnapshot,
    stateSnapshot: binding.stateSnapshot,
    extractionDigest: extraction.digest,
    candidateSetDigest,
    candidateCount: members.length,
    members,
  });
  const receiptId = digestHex(
    `closure-claim-extraction-receipt-id-v1\0${canonicalJson(payload)}`,
  );
  const canonicalReceiptJson = canonicalJson({
    ...payload,
    receiptId,
  });
  const receipt: ClosureClaimExtractionReceipt = {
    ...payload,
    receiptId,
    canonicalReceiptJson,
    contentHash: digestHex(
      `closure-claim-extraction-receipt-content-v1\0${canonicalReceiptJson}`,
    ),
  };
  assertClosureClaimExtractionReceipt(receipt);
  return receipt;
}

export function closureClaimExtractionReceiptProblems(
  receipt: ClosureClaimExtractionReceipt,
): string[] {
  const problems: string[] = [];
  if (receipt.schemaVersion !== CLOSURE_CLAIM_EXTRACTION_RECEIPT_SCHEMA_VERSION) {
    problems.push('receipt schemaVersion is unsupported');
  }
  if (receipt.extractionSchemaVersion !== CLOSURE_CLAIM_EXTRACTION_SCHEMA_VERSION) {
    problems.push('receipt extractionSchemaVersion is unsupported');
  }
  try {
    assertExtractionEvidenceBinding(receipt);
  } catch (error) {
    problems.push(errorMessage(error));
  }
  if (!SHA256_RE.test(receipt.extractionDigest)) {
    problems.push('receipt extractionDigest is not prefixed SHA-256');
  }
  if (!HEX_SHA256_RE.test(receipt.candidateSetDigest)) {
    problems.push('receipt candidateSetDigest is not SHA-256');
  }
  if (!Number.isSafeInteger(receipt.candidateCount) || receipt.candidateCount < 0) {
    problems.push('receipt candidateCount is invalid');
  }
  if (!Array.isArray(receipt.members)) {
    problems.push('receipt members are missing');
    return problems;
  }
  if (receipt.candidateCount !== receipt.members.length) {
    problems.push('receipt candidateCount does not match members');
  }
  const candidateIds = new Set<string>();
  for (const [index, member] of receipt.members.entries()) {
    if (member.ordinal !== index) {
      problems.push(`receipt member ${index} ordinal is not canonical`);
    }
    if (!SHA256_RE.test(member.candidateId)) {
      problems.push(`receipt member ${index} candidateId is invalid`);
    }
    if (!HEX_SHA256_RE.test(member.candidateContentHash)) {
      problems.push(`receipt member ${index} candidateContentHash is invalid`);
    }
    if (!SHA256_RE.test(member.sourceIdentity)) {
      problems.push(`receipt member ${index} sourceIdentity is invalid`);
    }
    if (candidateIds.has(member.candidateId)) {
      problems.push(`receipt member ${index} duplicates candidateId`);
    }
    candidateIds.add(member.candidateId);
  }
  const orderedMembers = receipt.members.slice().sort((left, right) =>
    compareBinary(left.candidateId, right.candidateId) ||
    compareBinary(left.candidateContentHash, right.candidateContentHash) ||
    compareBinary(left.sourceIdentity, right.sourceIdentity)
  );
  if (
    canonicalJson(orderedMembers.map((member, ordinal) => ({ ...member, ordinal }))) !==
      canonicalJson(receipt.members)
  ) {
    problems.push('receipt members are not in canonical order');
  }
  if (
    receipt.candidateSetDigest !==
      closureClaimExtractionReceiptCandidateSetDigest(receipt.members)
  ) {
    problems.push('receipt candidateSetDigest does not replay');
  }
  let payload: ReturnType<typeof closureClaimExtractionReceiptPayload> | null = null;
  try {
    payload = closureClaimExtractionReceiptPayload(receipt);
  } catch (error) {
    problems.push(errorMessage(error));
  }
  if (payload) {
    const expectedReceiptId = digestHex(
      `closure-claim-extraction-receipt-id-v1\0${canonicalJson(payload)}`,
    );
    if (receipt.receiptId !== expectedReceiptId) {
      problems.push('receipt receiptId does not replay');
    }
    const expectedCanonicalReceiptJson = canonicalJson({
      ...payload,
      receiptId: expectedReceiptId,
    });
    if (receipt.canonicalReceiptJson !== expectedCanonicalReceiptJson) {
      problems.push('receipt canonicalReceiptJson does not replay');
    }
    const expectedContentHash = digestHex(
      `closure-claim-extraction-receipt-content-v1\0` +
        expectedCanonicalReceiptJson,
    );
    if (receipt.contentHash !== expectedContentHash) {
      problems.push('receipt contentHash does not replay');
    }
  }
  return problems;
}

export function assertClosureClaimExtractionReceipt(
  receipt: ClosureClaimExtractionReceipt,
): void {
  const problems = closureClaimExtractionReceiptProblems(receipt);
  if (problems.length > 0) {
    throw new Error(
      `Invalid closure claim extraction receipt: ${problems.join('; ')}`,
    );
  }
}

export function closureClaimExtractionReceiptMemberContentHash(
  receiptId: string,
  member: ClosureClaimExtractionReceiptMember,
): string {
  return digestHex(
    `closure-claim-extraction-receipt-member-v1\0${canonicalJson({
      receiptId,
      ordinal: member.ordinal,
      candidateId: member.candidateId,
      candidateContentHash: member.candidateContentHash,
      sourceIdentity: member.sourceIdentity,
    })}`,
  );
}

export function replayClosureClaimCandidateIdentity(candidate: ClosureClaimCandidate): {
  canonicalClaimJson: string;
  canonicalSourceIdentityJson: string | null;
  sourceIdentity: string | null;
  candidateId: string | null;
  eligibility: ClosureClaimCandidateEligibility;
  identityProblems: ClosureClaimIdentityProblem[];
} {
  const canonicalClaimJson = canonicalClosureClaimJson(candidate.claim);
  const identityProblems = sourceIdentityProblems(
    candidate.repository,
    candidate.issue,
    candidate.source,
  );
  if (identityProblems.length > 0) {
    return {
      canonicalClaimJson,
      canonicalSourceIdentityJson: null,
      sourceIdentity: null,
      candidateId: null,
      eligibility: 'display_only',
      identityProblems,
    };
  }
  const canonicalSourceIdentityJson = canonicalSourceIdentity(
    candidate.repository,
    candidate.issue,
    candidate.source,
  );
  const sourceIdentity = digestText(`closure-claim-source-v1\0${canonicalSourceIdentityJson}`);
  const candidateId = digestText(`closure-claim-candidate-v2\0${canonicalJson({
    schemaVersion: CLOSURE_CLAIM_CANDIDATE_SCHEMA_VERSION,
    sourceIdentity,
    claimKind: candidate.claimKind,
    canonicalClaimJson,
    excerpt: candidate.excerpt,
    span: candidate.span,
  })}`);
  return {
    canonicalClaimJson,
    canonicalSourceIdentityJson,
    sourceIdentity,
    candidateId,
    eligibility: 'immutable',
    identityProblems,
  };
}

export function buildClosureClaimSourceSnapshotLedgerEntry(
  candidate: ClosureClaimCandidate,
): ClosureClaimSourceSnapshotLedgerEntry {
  assertImmutableClosureClaimCandidate(candidate);
  const sourceIdentity = candidate.sourceIdentity as string;
  const sourceRevisionIdentity = digestText(
    `closure-claim-source-revision-v1\0${canonicalJson({
      repositoryNodeId: candidate.repository.nodeId,
      issueNodeId: candidate.issue.nodeId,
      issueNumber: candidate.issue.number,
      sourceKind: candidate.source.kind,
      sourceNodeId: candidate.source.nodeId,
      createdAt: candidate.source.createdAt,
      updatedAt: candidate.source.updatedAt,
    })}`,
  );
  const canonicalSourceJson = canonicalJson({
    schemaVersion: CLOSURE_CLAIM_SOURCE_SNAPSHOT_LEDGER_SCHEMA_VERSION,
    sourceIdentity,
    sourceRevisionIdentity,
    repository: candidate.repository,
    issue: candidate.issue,
    source: candidate.source,
  });
  return {
    schemaVersion: CLOSURE_CLAIM_SOURCE_SNAPSHOT_LEDGER_SCHEMA_VERSION,
    sourceIdentity,
    sourceRevisionIdentity,
    repository: candidate.repository,
    issue: candidate.issue,
    source: candidate.source,
    canonicalSourceJson,
    contentHash: digestHex(
      `closure-claim-source-snapshot-ledger-v1\0${canonicalSourceJson}`,
    ),
  };
}

export function buildClosureClaimCandidateLedgerEntry(
  candidate: ClosureClaimCandidate,
): ClosureClaimCandidateLedgerEntry {
  assertImmutableClosureClaimCandidate(candidate);
  const canonicalCandidateJson = canonicalJson(candidate);
  return {
    schemaVersion: CLOSURE_CLAIM_CANDIDATE_LEDGER_SCHEMA_VERSION,
    candidateId: candidate.candidateId as string,
    sourceIdentity: candidate.sourceIdentity as string,
    issue: candidate.issue,
    claimKind: candidate.claimKind,
    canonicalClaimJson: candidate.canonicalClaimJson,
    excerpt: candidate.excerpt,
    span: candidate.span,
    canonicalCandidateJson,
    contentHash: digestHex(
      `closure-claim-candidate-ledger-v1\0${canonicalCandidateJson}`,
    ),
  };
}

export function assertImmutableClosureClaimCandidate(
  candidate: ClosureClaimCandidate,
): asserts candidate is ClosureClaimCandidate & {
  eligibility: 'immutable';
  candidateId: string;
  sourceIdentity: string;
  canonicalSourceIdentityJson: string;
} {
  assertClosureClaimCandidate(candidate);
  if (
    candidate.eligibility !== 'immutable' ||
    candidate.candidateId == null ||
    candidate.sourceIdentity == null ||
    candidate.canonicalSourceIdentityJson == null
  ) {
    throw new Error(
      'Closure claim candidate is display-only and cannot enter the immutable ledger',
    );
  }
}

export function closureClaimCandidateProblems(
  candidate: ClosureClaimCandidate,
): string[] {
  const problems: string[] = [];
  if (candidate.schemaVersion !== CLOSURE_CLAIM_CANDIDATE_SCHEMA_VERSION) {
    problems.push('candidate schemaVersion is unsupported');
  }
  if (!CLOSURE_CLAIM_KINDS.includes(candidate.claimKind)) {
    problems.push('candidate claimKind is unsupported');
  }
  if (candidate.claim.kind !== candidate.claimKind) {
    problems.push('candidate claim.kind does not match claimKind');
  }
  if (!SHA256_RE.test(candidate.source.textDigest)) {
    problems.push('candidate source textDigest is not SHA-256');
  }
  if (
    candidate.span != null &&
    (
      !Number.isSafeInteger(candidate.span.start) ||
      !Number.isSafeInteger(candidate.span.end) ||
      candidate.span.start < 0 ||
      candidate.span.end <= candidate.span.start
    )
  ) {
    problems.push('candidate span is invalid');
  }
  const replay = replayClosureClaimCandidateIdentity(candidate);
  if (candidate.canonicalClaimJson !== replay.canonicalClaimJson) {
    problems.push('candidate canonicalClaimJson does not match claim');
  }
  if (candidate.canonicalSourceIdentityJson !== replay.canonicalSourceIdentityJson) {
    problems.push('candidate canonicalSourceIdentityJson does not replay');
  }
  if (candidate.sourceIdentity !== replay.sourceIdentity) {
    problems.push('candidate sourceIdentity does not replay');
  }
  if (candidate.candidateId !== replay.candidateId) {
    problems.push('candidate candidateId does not replay');
  }
  if (candidate.eligibility !== replay.eligibility) {
    problems.push('candidate eligibility does not match identity completeness');
  }
  if (canonicalJson(candidate.identityProblems) !== canonicalJson(replay.identityProblems)) {
    problems.push('candidate identityProblems do not match identity completeness');
  }
  return problems;
}

export function assertClosureClaimCandidate(candidate: ClosureClaimCandidate): void {
  const problems = closureClaimCandidateProblems(candidate);
  if (problems.length > 0) {
    throw new Error(`Invalid closure claim candidate: ${problems.join('; ')}`);
  }
}

export function closureClaimCandidateSourceTextMatches(
  candidate: ClosureClaimCandidate,
  sourceText: string,
): boolean {
  return candidate.source.textDigest === digestText(sourceText);
}

export function mergeClosureClaimCandidates(
  existing: readonly ClosureClaimCandidate[],
  incoming: readonly ClosureClaimCandidate[],
): ClosureClaimCandidate[] {
  const merged = new Map<string, ClosureClaimCandidate>();
  for (const candidate of [...existing, ...incoming]) {
    assertClosureClaimCandidate(candidate);
    const key = candidate.candidateId ??
      `display:${canonicalJson(candidate)}`;
    merged.set(key, candidate);
  }
  return [...merged.values()].sort(compareCandidates);
}

function assertRepositoryAndIssue(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
): void {
  if (
    typeof repository.nameWithOwner !== 'string' ||
    repository.nameWithOwner.trim() !== repository.nameWithOwner ||
    !/^[^/\s]+\/[^/\s]+$/.test(repository.nameWithOwner)
  ) {
    throw new Error('Closure claim repository nameWithOwner must be canonical owner/name');
  }
  assertNullableCanonicalIdentity(repository.nodeId, 'repository node ID');
  if (!Number.isSafeInteger(issue.number) || issue.number <= 0) {
    throw new Error('Closure claim issue number must be a positive safe integer');
  }
  assertNullableCanonicalIdentity(issue.nodeId, 'issue node ID');
  assertActorShape(issue.author, 'issue author');
}

function normalizeTextSource(
  kind: 'issue_body' | 'comment',
  input: ClosureClaimTextSource,
  rejections: ClosureClaimSourceRejection[],
  output: NormalizedSource[],
): void {
  try {
    assertNullableCanonicalIdentity(input.nodeId, `${kind} source node ID`);
    assertActorShape(input.actor, `${kind} source actor`);
    const createdAt = canonicalTimestamp(input.createdAt, `${kind} createdAt`);
    const updatedAt = canonicalTimestamp(input.updatedAt, `${kind} updatedAt`);
    if (Date.parse(updatedAt) < Date.parse(createdAt)) {
      throw new Error(`${kind} updatedAt precedes createdAt`);
    }
    if (
      input.databaseId != null &&
      (!Number.isSafeInteger(input.databaseId) || input.databaseId <= 0)
    ) {
      throw new Error(`${kind} databaseId must be a positive safe integer`);
    }
    if (input.url != null && (typeof input.url !== 'string' || !input.url.trim())) {
      throw new Error(`${kind} URL must be a non-empty string when present`);
    }
    const sourceText = textSourceBody(input, kind);
    const source = {
      kind,
      nodeId: input.nodeId,
      databaseId: input.databaseId ?? null,
      url: input.url ?? null,
      actor: normalizedActor(input.actor),
      createdAt,
      updatedAt,
      textFormat: 'utf8_text' as const,
      textDigest: digestText(sourceText),
    };
    output.push({
      source,
      sourceText,
      event: null,
      revisionKey: sourceRevisionKey(source),
    });
  } catch (error) {
    rejections.push({
      sourceKind: kind,
      sourceNodeId: input?.nodeId ?? null,
      code: 'invalid_source',
      detail: errorMessage(error),
    });
  }
}

function normalizeClosureEvent(
  input: ClosureClaimClosureEventSource,
  rejections: ClosureClaimSourceRejection[],
  output: NormalizedSource[],
): void {
  try {
    assertNullableCanonicalIdentity(input.nodeId, 'closure event source node ID');
    assertActorShape(input.actor, 'closure event actor');
    const occurredAt = canonicalTimestamp(input.occurredAt, 'closure event occurredAt');
    if (input.url != null && (typeof input.url !== 'string' || !input.url.trim())) {
      throw new Error('closure event URL must be a non-empty string when present');
    }
    const closer = normalizedCloser(input.closer ?? null);
    const eventProjection = {
      stateReason: nullableCanonicalString(input.stateReason, 'closure event stateReason'),
      closer,
    };
    const sourceText = canonicalJson(eventProjection);
    const source = {
      kind: 'closure_event' as const,
      nodeId: input.nodeId,
      databaseId: null,
      url: input.url ?? null,
      actor: normalizedActor(input.actor),
      createdAt: occurredAt,
      updatedAt: occurredAt,
      textFormat: 'canonical_event_json' as const,
      textDigest: digestText(sourceText),
    };
    output.push({
      source,
      sourceText,
      event: {
        ...input,
        actor: source.actor,
        occurredAt,
        stateReason: eventProjection.stateReason,
        closer,
      },
      revisionKey: sourceRevisionKey(source),
    });
  } catch (error) {
    rejections.push({
      sourceKind: 'closure_event',
      sourceNodeId: input?.nodeId ?? null,
      code: 'invalid_source',
      detail: errorMessage(error),
    });
  }
}

function textSourceBody(
  source: ClosureClaimTextSource,
  kind: ClosureClaimSourceKind,
): string {
  if (source.text != null && typeof source.text !== 'string') {
    throw new Error(`${kind} text must be a string or null`);
  }
  if (source.body != null && typeof source.body !== 'string') {
    throw new Error(`${kind} body must be a string or null`);
  }
  if (source.text != null && source.body != null && source.text !== source.body) {
    throw new Error(`${kind} text and body conflict`);
  }
  return source.text ?? source.body ?? '';
}

function normalizedCloser(
  closer: ClosureClaimCloserIdentity | null,
): ClosureClaimCloserIdentity | null {
  if (closer == null) return null;
  assertNullableCanonicalIdentity(closer.nodeId, 'closure event closer node ID');
  const type = nullableCanonicalString(closer.type, 'closure event closer type');
  if (
    closer.number != null &&
    (!Number.isSafeInteger(closer.number) || closer.number <= 0)
  ) {
    throw new Error('closure event closer number must be a positive safe integer');
  }
  const oid = nullableCanonicalString(closer.oid ?? null, 'closure event closer OID');
  const repositoryNameWithOwner = nullableRepositoryName(
    closer.repositoryNameWithOwner ?? null,
    'closure event closer repository',
  );
  return {
    nodeId: closer.nodeId,
    type,
    number: closer.number ?? null,
    oid,
    repositoryNameWithOwner,
  };
}

function rejectConflictingReplays(
  sources: readonly NormalizedSource[],
  rejections: ClosureClaimSourceRejection[],
): NormalizedSource[] {
  const exact = new Map<string, NormalizedSource>();
  for (const source of sources) {
    exact.set(canonicalJson({
      source: source.source,
      sourceText: source.sourceText,
    }), source);
  }
  const unique = [...exact.values()];
  const groups = new Map<string, NormalizedSource[]>();
  const displayOnly: NormalizedSource[] = [];
  for (const source of unique) {
    if (source.revisionKey == null) {
      displayOnly.push(source);
      continue;
    }
    const group = groups.get(source.revisionKey) ?? [];
    group.push(source);
    groups.set(source.revisionKey, group);
  }
  const accepted = [...displayOnly];
  for (const group of groups.values()) {
    const projections = new Set(group.map((source) => canonicalJson({
      actor: source.source.actor,
      textDigest: source.source.textDigest,
      textFormat: source.source.textFormat,
    })));
    if (projections.size === 1) {
      accepted.push(group[0]);
      continue;
    }
    const representative = group.slice().sort(compareSources)[0];
    rejections.push({
      sourceKind: representative.source.kind,
      sourceNodeId: representative.source.nodeId,
      code: 'conflicting_source_replay',
      detail:
        'The same source node and revision timestamps were replayed with conflicting actor or content identity',
    });
  }
  return accepted.sort(compareSources);
}

function candidatesForSource(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
  normalized: NormalizedSource,
): ClosureClaimCandidate[] {
  const claims = normalized.event
    ? claimsFromClosureEvent(repository, issue, normalized.event)
    : claimsFromText(repository, issue, normalized.source.actor, normalized.sourceText);
  const seen = new Set<string>();
  const candidates: ClosureClaimCandidate[] = [];
  for (const extracted of claims) {
    const canonicalClaimJson = canonicalClosureClaimJson(extracted.claim);
    const span = extracted.start == null || extracted.end == null
      ? null
      : { start: extracted.start, end: extracted.end };
    const dedupeKey = canonicalJson({
      canonicalClaimJson,
      span,
    });
    if (seen.has(dedupeKey)) continue;
    seen.add(dedupeKey);
    candidates.push(buildCandidate(
      repository,
      issue,
      normalized.source,
      extracted.claim,
      canonicalClaimJson,
      extracted.excerpt,
      span,
    ));
  }
  return candidates;
}

function buildCandidate(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
  source: ClosureClaimSourceSnapshot,
  claim: ClosureClaim,
  canonicalClaimJson: string,
  excerpt: string | null,
  span: { start: number; end: number } | null,
): ClosureClaimCandidate {
  const candidate: ClosureClaimCandidate = {
    schemaVersion: CLOSURE_CLAIM_CANDIDATE_SCHEMA_VERSION,
    candidateId: null,
    sourceIdentity: null,
    canonicalSourceIdentityJson: null,
    eligibility: 'display_only',
    identityProblems: [],
    repository: {
      nodeId: repository.nodeId,
      nameWithOwner: repository.nameWithOwner,
    },
    issue: {
      nodeId: issue.nodeId,
      number: issue.number,
    },
    source,
    claimKind: claim.kind,
    claim,
    canonicalClaimJson,
    excerpt,
    span,
  };
  const replay = replayClosureClaimCandidateIdentity(candidate);
  return {
    ...candidate,
    candidateId: replay.candidateId,
    sourceIdentity: replay.sourceIdentity,
    canonicalSourceIdentityJson: replay.canonicalSourceIdentityJson,
    eligibility: replay.eligibility,
    identityProblems: replay.identityProblems,
  };
}

function claimsFromText(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
  actor: ClosureClaimActorIdentity,
  sourceText: string,
): ExtractedClaim[] {
  const claims: ExtractedClaim[] = [];
  for (const clause of activeClauses(sourceText)) {
    claims.push(
      ...duplicateClaims(repository, clause),
      ...fixProofClaims(repository, clause),
      ...releaseLocalClaims(clause),
      ...closureRationaleClaims(clause),
      ...fieldConfirmationClaims(clause),
      ...reporterActionClaims(repository, issue, actor, clause),
    );
  }
  return claims;
}

function claimsFromClosureEvent(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
  event: ClosureClaimClosureEventSource,
): ExtractedClaim[] {
  const claims: ExtractedClaim[] = [];
  const reason = (event.stateReason ?? '').toUpperCase();
  const rationale = reason === 'COMPLETED'
    ? 'completed'
    : reason === 'DUPLICATE'
      ? 'duplicate'
      : reason === 'NOT_PLANNED'
        ? 'not_planned'
        : reason
          ? 'other'
          : null;
  if (rationale) {
    claims.push(eventClaim({
      kind: 'closure_rationale',
      rationale,
    }));
  }
  if (reason === 'DUPLICATE') {
    claims.push(eventClaim({
      kind: 'duplicate_or_superseded',
      relation: 'duplicate',
      target: null,
    }));
  }
  const closer = event.closer ?? null;
  const closerType = (closer?.type ?? '').toLowerCase();
  if (
    closer &&
    closerType === 'pullrequest' &&
    Number.isSafeInteger(closer.number) &&
    Number(closer.number) > 0
  ) {
    claims.push(eventClaim({
      kind: 'fix_proof',
      proofType: 'pull_request',
      target: {
        resource: 'pull_request',
        repositoryNameWithOwner:
          closer.repositoryNameWithOwner ?? repository.nameWithOwner,
        number: Number(closer.number),
      },
    }));
  }
  if (closer?.oid) {
    claims.push(eventClaim({
      kind: 'fix_proof',
      proofType: 'commit',
      target: {
        resource: 'commit',
        repositoryNameWithOwner:
          closer.repositoryNameWithOwner ?? repository.nameWithOwner,
        oid: closer.oid.toLowerCase(),
      },
    }));
  }
  if (
    issue.author.nodeId != null &&
    event.actor.nodeId != null &&
    issue.author.nodeId === event.actor.nodeId
  ) {
    claims.push(eventClaim({
      kind: 'reporter_action',
      action: 'self_closed',
      reporterNodeId: issue.author.nodeId,
      target: null,
    }));
  }
  return claims;
}

function eventClaim(claim: ClosureClaim): ExtractedClaim {
  return { claim, start: null, end: null, excerpt: null };
}

function duplicateClaims(
  repository: ClosureClaimRepositoryIdentity,
  clause: ActiveClause,
): ExtractedClaim[] {
  const text = clause.text;
  if (
    !/\b(?:duplicate|dupe|superseded|canonical|consolidat(?:e|ed|ing)|already tracked|covered by)\b/i.test(text) ||
    /\b(?:not|isn't|is not|wasn't|was not|never|no longer)\s+(?:a\s+)?(?:duplicate|dupe|superseded|canonical)\b/i.test(text)
  ) {
    return [];
  }
  const relation: DuplicateOrSupersededClaim['relation'] =
    /\bsuperseded\b/i.test(text)
      ? 'superseded'
      : /\b(?:duplicate|dupe)\b/i.test(text)
        ? 'duplicate'
        : /\bconsolidat(?:e|ed|ing)\b/i.test(text)
          ? 'consolidated'
          : 'canonical';
  const targets = referencesInClause(repository.nameWithOwner, text, 'issue');
  if (targets.length === 0) {
    const match = text.match(
      /\b(?:duplicate|dupe|superseded|canonical|consolidat(?:e|ed|ing)|already tracked|covered by)\b/i,
    );
    return match
      ? [textClaim(clause, match.index ?? 0, match[0].length, {
        kind: 'duplicate_or_superseded',
        relation,
        target: null,
      })]
      : [];
  }
  return targets.map((target) => textClaim(clause, target.start, target.end - target.start, {
    kind: 'duplicate_or_superseded',
    relation,
    target: target.target,
  }));
}

function fixProofClaims(
  repository: ClosureClaimRepositoryIdentity,
  clause: ActiveClause,
): ExtractedClaim[] {
  const text = clause.text;
  if (!/\b(?:fix(?:e[sd])?|resolved?|implemented|landed|shipped|addressed)\b/i.test(text)) {
    return [];
  }
  if (
    /\b(?:not|never|isn't|is not|wasn't|was not|no longer)\s+(?:actually\s+)?(?:fixed|resolved|implemented|addressed)\b/i.test(text) ||
    /\b(?:does not|doesn't|did not|didn't|cannot|can't)\s+(?:fix|resolve|address)\b/i.test(text) ||
    /\bno\s+(?:fix|fix proof)\b/i.test(text)
  ) {
    return [];
  }
  const claims: ExtractedClaim[] = [];
  const occupiedCommitRanges: Array<{ start: number; end: number }> = [];
  for (const match of text.matchAll(COMMIT_URL_RE)) {
    const start = match.index ?? 0;
    occupiedCommitRanges.push({ start, end: start + match[0].length });
    claims.push(textClaim(clause, start, match[0].length, {
      kind: 'fix_proof',
      proofType: 'commit',
      target: {
        resource: 'commit',
        repositoryNameWithOwner: `${match[1]}/${match[2]}`,
        oid: match[3].toLowerCase(),
      },
    }));
  }
  for (const match of text.matchAll(FULL_COMMIT_RE)) {
    const start = match.index ?? 0;
    if (occupiedCommitRanges.some((range) => start >= range.start && start < range.end)) {
      continue;
    }
    claims.push(textClaim(clause, start, match[0].length, {
      kind: 'fix_proof',
      proofType: 'commit',
      target: {
        resource: 'commit',
        repositoryNameWithOwner: repository.nameWithOwner,
        oid: match[0].toLowerCase(),
      },
    }));
  }
  for (const reference of referencesInClause(
    repository.nameWithOwner,
    text,
    'pull_request',
  ).filter((reference) =>
    reference.target.resource === 'pull_request' &&
    (
      /\/pull\/\d+/i.test(text.slice(reference.start, reference.end)) ||
      /\b(?:pr|pull request)\s*:?\s*#?\d+/i.test(
        text.slice(Math.max(0, reference.start - 18), reference.end),
      ) ||
      /\b(?:fixed|resolved|implemented|landed|shipped|addressed)\s+(?:by|in|via|through)\s+#\d+/i.test(text)
    ))) {
    claims.push(textClaim(clause, reference.start, reference.end - reference.start, {
      kind: 'fix_proof',
      proofType: 'pull_request',
      target: reference.target,
    }));
  }
  for (const match of text.matchAll(RELEASE_TAG_RE)) {
    if (!/\b(?:fixed|resolved|implemented|landed|shipped|available)\b/i.test(text)) continue;
    claims.push(textClaim(clause, match.index ?? 0, match[0].length, {
      kind: 'fix_proof',
      proofType: 'release',
      target: {
        resource: 'release',
        tag: canonicalReleaseTag(match[1]),
      },
    }));
  }
  const main = /\b(?:current\s+)?main\b/i.exec(text);
  if (main && /\b(?:fixed|resolved|implemented|landed)\b/i.test(text)) {
    claims.push(textClaim(clause, main.index, main[0].length, {
      kind: 'fix_proof',
      proofType: 'branch',
      target: { resource: 'branch', name: 'main' },
    }));
  }
  if (claims.length === 0) {
    const cue = /\b(?:fix(?:e[sd])?|resolved?|implemented|landed|shipped|addressed)\b/i.exec(text);
    if (cue) {
      claims.push(textClaim(clause, cue.index, cue[0].length, {
        kind: 'fix_proof',
        proofType: 'assertion',
        target: null,
      }));
    }
  }
  return claims;
}

function releaseLocalClaims(clause: ActiveClause): ExtractedClaim[] {
  const text = clause.text;
  const cues = releaseLocalAssertionCues(text);
  if (cues.length === 0) return [];
  return [...text.matchAll(RELEASE_TAG_RE)].flatMap((match) => {
    const start = match.index ?? 0;
    const assertion = nearestReleaseLocalAssertion(
      text,
      start,
      start + match[0].length,
      cues,
    );
    return assertion
      ? [textClaim(clause, start, match[0].length, {
        kind: 'release_local',
        assertion,
        releaseTag: canonicalReleaseTag(match[1]),
      })]
      : [];
  });
}

function releaseLocalAssertionCues(text: string): ReleaseLocalAssertionCue[] {
  const cues: ReleaseLocalAssertionCue[] = [];
  for (const [priority, pattern] of RELEASE_LOCAL_ASSERTION_PATTERNS.entries()) {
    pattern.re.lastIndex = 0;
    for (const match of text.matchAll(pattern.re)) {
      const start = match.index ?? 0;
      const end = start + match[0].length;
      if (cues.some((cue) => start < cue.end && end > cue.start)) continue;
      cues.push({
        assertion: pattern.assertion,
        start,
        end,
        priority,
      });
    }
  }
  return cues.sort((left, right) =>
    left.start - right.start ||
    left.end - right.end ||
    left.priority - right.priority);
}

function nearestReleaseLocalAssertion(
  text: string,
  releaseStart: number,
  releaseEnd: number,
  cues: readonly ReleaseLocalAssertionCue[],
): ReleaseLocalClaim['assertion'] | null {
  return cues.slice().sort((left, right) =>
    releaseLocalBoundaryCount(text, releaseStart, releaseEnd, left) -
      releaseLocalBoundaryCount(text, releaseStart, releaseEnd, right) ||
    releaseLocalCueDistance(releaseStart, releaseEnd, left) -
      releaseLocalCueDistance(releaseStart, releaseEnd, right) ||
    Number(left.start < releaseEnd) - Number(right.start < releaseEnd) ||
    left.priority - right.priority ||
    left.start - right.start)[0]?.assertion ?? null;
}

function releaseLocalBoundaryCount(
  text: string,
  releaseStart: number,
  releaseEnd: number,
  cue: ReleaseLocalAssertionCue,
): number {
  const between = cue.end <= releaseStart
    ? text.slice(cue.end, releaseStart)
    : releaseEnd <= cue.start
      ? text.slice(releaseEnd, cue.start)
      : '';
  return between.match(/[,;:]|\b(?:while|whereas)\b/gi)?.length ?? 0;
}

function releaseLocalCueDistance(
  releaseStart: number,
  releaseEnd: number,
  cue: ReleaseLocalAssertionCue,
): number {
  if (cue.end <= releaseStart) return releaseStart - cue.end;
  if (releaseEnd <= cue.start) return cue.start - releaseEnd;
  return 0;
}

function closureRationaleClaims(clause: ActiveClause): ExtractedClaim[] {
  const text = clause.text;
  const closureCue =
    /\b(?:close[sd]?|closing|closure)\b/i.exec(text);
  if (
    !closureCue ||
    /\b(?:not|never|isn't|is not|wasn't|was not|do not|don't|should not|shouldn't|won't)\s+(?:be\s+)?(?:close[sd]?|closing)\b/i.test(text)
  ) {
    return [];
  }
  const rationale: ClosureRationaleClaim['rationale'] =
    /\bsuperseded\b/i.test(text)
      ? 'superseded'
      : /\b(?:duplicate|dupe|consolidat(?:e|ed|ing))\b/i.test(text)
        ? 'duplicate'
        : /\b(?:fixed|resolved|implemented)\b/i.test(text) &&
            !/\b(?:not|isn't|is not|wasn't|was not|never)\s+(?:fixed|resolved|implemented)\b/i.test(text)
          ? 'fixed'
          : /\b(?:not planned|won't fix|wont fix)\b/i.test(text)
            ? 'not_planned'
            : /\b(?:expected behavior|working as intended|by design)\b/i.test(text)
              ? 'expected_behavior'
              : /\b(?:not reproducible|cannot reproduce|can't reproduce|could not reproduce|no longer reproduces)\b/i.test(text)
                ? 'not_reproducible'
                : /\b(?:insufficient[-\s]?info|insufficient information|not enough (?:details|information)|missing (?:logs|details|reproduction))\b/i.test(text)
                  ? 'insufficient_info'
                  : /\b(?:out of scope|outside (?:the )?(?:repo|repository)|wrong (?:repo|repository))\b/i.test(text)
                    ? 'out_of_scope'
                    : /\binactiv(?:e|ity)\b/i.test(text)
                      ? 'inactivity'
                      : /\b(?:reporter|author)\b.{0,40}\b(?:request|asked)\b/i.test(text)
                        ? 'reporter_request'
                        : 'other';
  return [textClaim(clause, closureCue.index, closureCue[0].length, {
    kind: 'closure_rationale',
    rationale,
  })];
}

function fieldConfirmationClaims(clause: ActiveClause): ExtractedClaim[] {
  const text = clause.text;
  if (
    /\b(?:cannot|can't|could not|couldn't|do not|don't|does not|doesn't|not able to|no longer)\s+(?:still\s+)?(?:reproduce|repro|see|confirm|hit)\b/i.test(text) ||
    /\bnot (?:affected|seeing|experiencing)\b/i.test(text)
  ) {
    return [];
  }
  const patterns: Array<{
    re: RegExp;
    confirmation: FieldConfirmationClaim['confirmation'];
  }> = [
    {
      re: /\b(?:i|we)\s+(?:can\s+)?(?:also\s+)?(?:reproduce|reproduced|repro|confirmed)\b/i,
      confirmation: 'reproduced',
    },
    {
      re: /\b(?:same|identical)\s+(?:issue|error|failure|symptom|stack trace)\b/i,
      confirmation: 'same_failure',
    },
    {
      re: /\b(?:production|deployment|deployed|our users?|our team|our instance|customer)\b.{0,100}\b(?:affected|broken|fails?|failing|error|outage|data loss)\b/i,
      confirmation: 'deployment_affected',
    },
    {
      re: /\b(?:still|continues? to)\s+(?:fails?|failing|breaks?|broken|reproduces?|errors?)\b/i,
      confirmation: 'still_failing',
    },
  ];
  for (const pattern of patterns) {
    const match = pattern.re.exec(text);
    if (match) {
      return [textClaim(clause, match.index, match[0].length, {
        kind: 'field_confirmation',
        confirmation: pattern.confirmation,
      })];
    }
  }
  return [];
}

function reporterActionClaims(
  repository: ClosureClaimRepositoryIdentity,
  issue: ClosureClaimIssueIdentity,
  actor: ClosureClaimActorIdentity,
  clause: ActiveClause,
): ExtractedClaim[] {
  if (
    issue.author.nodeId == null ||
    actor.nodeId == null ||
    issue.author.nodeId !== actor.nodeId
  ) {
    return [];
  }
  const text = clause.text;
  const action: ReporterActionClaim['action'] | null =
    /\b(?:reopened|refiled|re-filed|opened|moved|replaced)\b.{0,100}\b(?:as|in|under|to|with)\b.{0,100}(?:#\d+|\/issues\/\d+)/i.test(text)
      ? 'replaced_or_refiled'
      : /\b(?:resolved on my side|fixed on my side|works for me now|working for me now)\b/i.test(text)
        ? 'resolved_on_reporter_side'
        : /\b(?:withdraw|withdrawn|please ignore|ignore this|opened by mistake|my mistake|false alarm)\b/i.test(text)
          ? 'withdrawn'
          : /\b(?:please|you can|feel free to)\s+close\b|\bclose this please\b/i.test(text)
            ? 'requested_closure'
            : /\b(?:i(?:'m| am)? closing|closing this myself|self-clos(?:e|ed|ing))\b/i.test(text)
              ? 'self_closed'
              : null;
  if (!action) return [];
  const match = /\b(?:reopened|refiled|re-filed|opened|moved|replaced|resolved|fixed|works|working|withdraw|withdrawn|please|ignore|closing|self-clos)/i.exec(text);
  const target = action === 'replaced_or_refiled'
    ? referencesInClause(repository.nameWithOwner, text, 'issue')
      .find((reference) => reference.target.resource === 'issue')?.target ?? null
    : null;
  return [textClaim(clause, match?.index ?? 0, match?.[0].length ?? 1, {
    kind: 'reporter_action',
    action,
    reporterNodeId: issue.author.nodeId,
    target,
  })];
}

function textClaim(
  clause: ActiveClause,
  relativeStart: number,
  length: number,
  claim: ClosureClaim,
): ExtractedClaim {
  return {
    claim,
    start: clause.start + relativeStart,
    end: clause.start + relativeStart + length,
    excerpt: clause.excerpt,
  };
}

function activeClauses(sourceText: string): ActiveClause[] {
  const masked = maskQuotedAndCode(sourceText);
  const clauses: ActiveClause[] = [];
  let start = 0;
  for (const boundary of masked.matchAll(CLAUSE_BOUNDARY_RE)) {
    const end = boundary.index ?? start;
    appendActiveClause(sourceText, masked, start, end, clauses);
    start = end + boundary[0].length;
  }
  appendActiveClause(sourceText, masked, start, sourceText.length, clauses);
  return clauses;
}

function appendActiveClause(
  sourceText: string,
  masked: string,
  start: number,
  end: number,
  output: ActiveClause[],
): void {
  let first = start;
  let last = end;
  while (first < last && /\s/.test(masked[first])) first++;
  while (last > first && /\s/.test(masked[last - 1])) last--;
  if (first >= last || !/\S/.test(masked.slice(first, last))) return;
  output.push({
    text: masked.slice(first, last),
    excerpt: sourceText.slice(first, last).trim(),
    start: first,
    end: last,
  });
}

function maskQuotedAndCode(text: string): string {
  const chars = text.split('');
  let fenced = false;
  let htmlQuote = false;
  let offset = 0;
  for (const lineWithEnding of text.match(/[^\n]*(?:\n|$)/g) ?? []) {
    if (!lineWithEnding) continue;
    const line = lineWithEnding.endsWith('\n')
      ? lineWithEnding.slice(0, -1)
      : lineWithEnding;
    const trimmed = line.trimStart();
    const fenceLine = /^(?:```|~~~)/.test(trimmed);
    const startsHtmlQuote = /^<blockquote(?:\s|>)/i.test(trimmed);
    const endsHtmlQuote = /<\/blockquote>\s*$/i.test(trimmed);
    if (
      fenced ||
      fenceLine ||
      htmlQuote ||
      startsHtmlQuote ||
      /^>/.test(trimmed)
    ) {
      maskRange(chars, offset, offset + line.length);
    } else {
      maskInlineCodeAndQuotes(chars, offset, line);
    }
    if (fenceLine) fenced = !fenced;
    if (startsHtmlQuote) htmlQuote = true;
    if (endsHtmlQuote) htmlQuote = false;
    offset += lineWithEnding.length;
  }
  return chars.join('');
}

function maskInlineCodeAndQuotes(chars: string[], offset: number, line: string): void {
  let inlineCode = false;
  let straightQuote = false;
  let curlyQuote = false;
  for (let index = 0; index < line.length; index++) {
    const char = line[index];
    if (char === '`') {
      inlineCode = !inlineCode;
      chars[offset + index] = ' ';
      continue;
    }
    if (inlineCode) {
      chars[offset + index] = ' ';
      continue;
    }
    if (char === '"') {
      straightQuote = !straightQuote;
      chars[offset + index] = ' ';
      continue;
    }
    if (char === '“') {
      curlyQuote = true;
      chars[offset + index] = ' ';
      continue;
    }
    if (char === '”') {
      curlyQuote = false;
      chars[offset + index] = ' ';
      continue;
    }
    if (straightQuote || curlyQuote) chars[offset + index] = ' ';
  }
}

function maskRange(chars: string[], start: number, end: number): void {
  for (let index = start; index < end; index++) {
    if (chars[index] !== '\n' && chars[index] !== '\r') chars[index] = ' ';
  }
}

function referencesInClause(
  currentRepository: string,
  text: string,
  bareDefault: 'issue' | 'pull_request',
): Array<{ target: ClosureClaimTarget; start: number; end: number }> {
  const references: Array<{ target: ClosureClaimTarget; start: number; end: number }> = [];
  const occupied: Array<{ start: number; end: number }> = [];
  for (const [resource, regex] of [
    ['issue', ISSUE_URL_RE],
    ['pull_request', PULL_URL_RE],
  ] as const) {
    for (const match of text.matchAll(regex)) {
      const start = match.index ?? 0;
      const end = start + match[0].length;
      occupied.push({ start, end });
      references.push({
        target: {
          resource,
          repositoryNameWithOwner: `${match[1]}/${match[2]}`,
          number: Number(match[3]),
        },
        start,
        end,
      });
    }
  }
  for (const match of text.matchAll(BARE_REFERENCE_RE)) {
    const start = match.index ?? 0;
    const end = start + match[0].length;
    if (occupied.some((range) => start >= range.start && start < range.end)) continue;
    const preceding = text.slice(Math.max(0, start - 20), start);
    const resource = /\b(?:pr|pull request)\s*:?\s*$/i.test(preceding)
      ? 'pull_request'
      : bareDefault;
    references.push({
      target: {
        resource,
        repositoryNameWithOwner: currentRepository,
        number: Number(match[1]),
      },
      start,
      end,
    });
  }
  return references.sort((left, right) =>
    left.start - right.start ||
    left.end - right.end ||
    compareBinary(canonicalJson(left.target), canonicalJson(right.target)));
}

function sourceIdentityProblems(
  repository: ClosureClaimRepositoryIdentity,
  issue: Pick<ClosureClaimIssueIdentity, 'nodeId' | 'number'>,
  source: ClosureClaimSourceSnapshot,
): ClosureClaimIdentityProblem[] {
  const problems: ClosureClaimIdentityProblem[] = [];
  if (repository.nodeId == null) problems.push('missing_repository_node_id');
  if (issue.nodeId == null) problems.push('missing_issue_node_id');
  if (source.nodeId == null) problems.push('missing_source_node_id');
  if (source.actor.nodeId == null) problems.push('missing_actor_node_id');
  if (source.actor.type == null) problems.push('missing_actor_type');
  return problems;
}

function canonicalSourceIdentity(
  repository: ClosureClaimRepositoryIdentity,
  issue: Pick<ClosureClaimIssueIdentity, 'nodeId' | 'number'>,
  source: ClosureClaimSourceSnapshot,
): string {
  return canonicalJson({
    schemaVersion: CLOSURE_CLAIM_SOURCE_IDENTITY_SCHEMA_VERSION,
    repository,
    issue,
    source: {
      kind: source.kind,
      nodeId: source.nodeId,
      actor: source.actor,
      createdAt: source.createdAt,
      updatedAt: source.updatedAt,
      textFormat: source.textFormat,
      textDigest: source.textDigest,
    },
  });
}

function sourceRevisionKey(source: ClosureClaimSourceSnapshot): string | null {
  if (source.nodeId == null) return null;
  return canonicalJson({
    kind: source.kind,
    nodeId: source.nodeId,
    createdAt: source.createdAt,
    updatedAt: source.updatedAt,
  });
}

function normalizedActor(actor: ClosureClaimActorIdentity): ClosureClaimActorIdentity {
  return {
    nodeId: actor.nodeId,
    login: nullableCanonicalString(actor.login, 'actor login'),
    type: nullableCanonicalString(actor.type, 'actor type'),
  };
}

function assertActorShape(actor: ClosureClaimActorIdentity, context: string): void {
  if (!actor || typeof actor !== 'object') {
    throw new Error(`${context} must be present`);
  }
  assertNullableCanonicalIdentity(actor.nodeId, `${context} node ID`);
  nullableCanonicalString(actor.login, `${context} login`);
  nullableCanonicalString(actor.type, `${context} type`);
}

function assertNullableCanonicalIdentity(value: string | null, context: string): void {
  if (value == null) return;
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${context} must be a canonical non-empty string or null`);
  }
}

function nullableCanonicalString(
  value: string | null | undefined,
  context: string,
): string | null {
  if (value == null) return null;
  if (typeof value !== 'string' || !value || value.trim() !== value) {
    throw new Error(`${context} must be a canonical non-empty string or null`);
  }
  return value;
}

function nullableRepositoryName(
  value: string | null,
  context: string,
): string | null {
  if (value == null) return null;
  if (value.trim() !== value || !/^[^/\s]+\/[^/\s]+$/.test(value)) {
    throw new Error(`${context} must be canonical owner/name or null`);
  }
  return value;
}

function canonicalTimestamp(value: string | null, context: string): string {
  if (typeof value !== 'string' || !value || !Number.isFinite(Date.parse(value))) {
    throw new Error(`${context} must be a valid timestamp`);
  }
  return new Date(Date.parse(value)).toISOString();
}

function canonicalReleaseTag(value: string): string {
  return `v${value.replace(/^v/i, '')}`;
}

function compareSources(left: NormalizedSource, right: NormalizedSource): number {
  return compareBinary(left.source.createdAt, right.source.createdAt) ||
    compareBinary(left.source.updatedAt, right.source.updatedAt) ||
    SOURCE_KIND_ORDER[left.source.kind] - SOURCE_KIND_ORDER[right.source.kind] ||
    compareBinary(left.source.nodeId ?? '', right.source.nodeId ?? '') ||
    compareBinary(left.source.textDigest, right.source.textDigest) ||
    compareBinary(canonicalJson(left.source), canonicalJson(right.source));
}

function compareCandidates(
  left: ClosureClaimCandidate,
  right: ClosureClaimCandidate,
): number {
  return compareBinary(left.source.createdAt, right.source.createdAt) ||
    compareBinary(left.source.updatedAt, right.source.updatedAt) ||
    SOURCE_KIND_ORDER[left.source.kind] - SOURCE_KIND_ORDER[right.source.kind] ||
    compareBinary(left.source.nodeId ?? '', right.source.nodeId ?? '') ||
    (left.span?.start ?? -1) - (right.span?.start ?? -1) ||
    (KIND_ORDER.get(left.claimKind) ?? Number.MAX_SAFE_INTEGER) -
      (KIND_ORDER.get(right.claimKind) ?? Number.MAX_SAFE_INTEGER) ||
    compareBinary(left.canonicalClaimJson, right.canonicalClaimJson) ||
    compareBinary(left.candidateId ?? '', right.candidateId ?? '') ||
    compareBinary(
      canonicalJson({
        repository: left.repository,
        issue: left.issue,
        source: left.source,
        claim: left.claim,
        excerpt: left.excerpt,
        span: left.span,
      }),
      canonicalJson({
        repository: right.repository,
        issue: right.issue,
        source: right.source,
        claim: right.claim,
        excerpt: right.excerpt,
        span: right.span,
      }),
    );
}

function compareRejections(
  left: ClosureClaimSourceRejection,
  right: ClosureClaimSourceRejection,
): number {
  return SOURCE_KIND_ORDER[left.sourceKind] - SOURCE_KIND_ORDER[right.sourceKind] ||
    compareBinary(left.sourceNodeId ?? '', right.sourceNodeId ?? '') ||
    compareBinary(left.code, right.code) ||
    compareBinary(left.detail, right.detail);
}

function assertExtractionEvidenceBinding(
  binding: ClosureClaimExtractionEvidenceBinding,
): void {
  assertNullableCanonicalIdentity(
    binding.repository.nodeId,
    'closure claim extraction receipt repository node ID',
  );
  if (binding.repository.nodeId == null) {
    throw new Error(
      'Closure claim extraction receipt repository node ID is required',
    );
  }
  if (
    typeof binding.repository.nameWithOwner !== 'string' ||
    !/^[^/\s]+\/[^/\s]+$/.test(binding.repository.nameWithOwner) ||
    binding.repository.nameWithOwner.trim() !== binding.repository.nameWithOwner
  ) {
    throw new Error(
      'Closure claim extraction receipt repository must be canonical owner/name',
    );
  }
  assertNullableCanonicalIdentity(
    binding.issue.nodeId,
    'closure claim extraction receipt issue node ID',
  );
  if (binding.issue.nodeId == null) {
    throw new Error('Closure claim extraction receipt issue node ID is required');
  }
  if (!Number.isSafeInteger(binding.issue.number) || binding.issue.number <= 0) {
    throw new Error(
      'Closure claim extraction receipt issue number must be a positive safe integer',
    );
  }
  if (!Number.isSafeInteger(binding.issue.revision) || binding.issue.revision <= 0) {
    throw new Error(
      'Closure claim extraction receipt issue revision must be a positive safe integer',
    );
  }
  canonicalTimestamp(
    binding.issue.updatedAt,
    'closure claim extraction receipt issue updatedAt',
  );
  if (!HEX_SHA256_RE.test(binding.issue.bodyDigest)) {
    throw new Error(
      'Closure claim extraction receipt issue bodyDigest must be SHA-256',
    );
  }
  assertNullableCanonicalIdentity(
    binding.issue.authorNodeId,
    'closure claim extraction receipt issue author node ID',
  );
  assertNullableCanonicalIdentity(
    binding.issue.authorType,
    'closure claim extraction receipt issue author type',
  );
  for (const [name, snapshot] of [
    ['comment', binding.commentSnapshot],
    ['state', binding.stateSnapshot],
  ] as const) {
    if (!Number.isSafeInteger(snapshot.revision) || snapshot.revision <= 0) {
      throw new Error(
        `Closure claim extraction receipt ${name} snapshot revision ` +
          'must be a positive safe integer',
      );
    }
    if (!HEX_SHA256_RE.test(snapshot.authorityDigest)) {
      throw new Error(
        `Closure claim extraction receipt ${name} authorityDigest must be SHA-256`,
      );
    }
    if (!HEX_SHA256_RE.test(snapshot.stabilizationIdentityDigest)) {
      throw new Error(
        `Closure claim extraction receipt ${name} stabilization identity ` +
          'must be SHA-256',
      );
    }
  }
}

function closureClaimExtractionReceiptCandidateSetDigest(
  members: readonly ClosureClaimExtractionReceiptMember[],
): string {
  return digestHex(
    `closure-claim-extraction-receipt-candidate-set-v1\0${canonicalJson(members)}`,
  );
}

function closureClaimExtractionReceiptPayload(
  receipt: Pick<
    ClosureClaimExtractionReceipt,
    | 'schemaVersion'
    | 'extractionSchemaVersion'
    | 'repository'
    | 'issue'
    | 'commentSnapshot'
    | 'stateSnapshot'
    | 'extractionDigest'
    | 'candidateSetDigest'
    | 'candidateCount'
    | 'members'
  >,
) {
  return {
    schemaVersion: receipt.schemaVersion,
    extractionSchemaVersion: receipt.extractionSchemaVersion,
    repository: receipt.repository,
    issue: receipt.issue,
    commentSnapshot: receipt.commentSnapshot,
    stateSnapshot: receipt.stateSnapshot,
    extractionDigest: receipt.extractionDigest,
    candidateSetDigest: receipt.candidateSetDigest,
    candidateCount: receipt.candidateCount,
    members: receipt.members,
  };
}

function canonicalJson(value: unknown, path = '$'): string {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') {
    return JSON.stringify(value);
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`Canonical closure claim JSON requires a finite number at ${path}`);
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) =>
      canonicalJson(item, `${path}[${index}]`)).join(',')}]`;
  }
  if (typeof value === 'object') {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).sort().map((key) =>
      `${JSON.stringify(key)}:${canonicalJson(record[key], `${path}.${key}`)}`).join(',')}}`;
  }
  throw new Error(`Unsupported canonical closure claim value at ${path}: ${typeof value}`);
}

function digestCanonical(value: unknown): string {
  return digestText(canonicalJson(value));
}

function digestText(value: string): string {
  return `sha256:${createHash('sha256').update(value).digest('hex')}`;
}

function digestHex(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function compareBinary(left: string, right: string): number {
  return Buffer.compare(Buffer.from(left, 'utf8'), Buffer.from(right, 'utf8'));
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
