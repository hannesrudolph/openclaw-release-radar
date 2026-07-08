import { closureRiskDisposition } from './closureProofTaxonomy';

export interface ClosureRiskAggregationItem {
  issueNumber: number;
  disposition: string;
  weight: number;
  duplicateCluster?: string | null;
  canonicalIssueNumber?: number | null;
  canonicalIssueNumbers?: readonly number[] | null;
  aliasGroup?: string | null;
}

export interface AggregatedClosureRisk {
  unresolvedForReleaseCount: number;
  unresolvedWeightedRisk: number;
  weightedRiskByDisposition: Record<string, number>;
  groups: Array<ClosureRiskAggregationItem & { key: string }>;
}

export interface IssueAliasIdentity {
  issueNumber?: number | null;
  duplicateCluster?: string | null;
  canonicalIssueNumber?: number | null;
  canonicalIssueNumbers?: readonly number[] | null;
  aliasGroup?: string | null;
  disposition?: string | null;
}

export interface IssueAliasGroup {
  key: string;
  issueNumbers: number[];
  duplicateClusters: string[];
  tokens: string[];
}

export interface IssueAliasGroupIndex {
  groups: IssueAliasGroup[];
  keyFor: (item: IssueAliasIdentity, fallbackIndex?: number) => string;
}

const DISPOSITION_PRIORITY: Record<string, number> = {
  missing_evidence: 4,
  open_canonical_risk: 3,
  known_not_in_release: 2,
  unsupported_closure_claim: 1,
};

export function aggregateClosureRisk(
  items: ClosureRiskAggregationItem[],
): AggregatedClosureRisk {
  const riskItems = items.filter((item) =>
    Number.isFinite(item.weight) && item.weight > 0);
  const aliases = buildIssueAliasGroups(riskItems);
  const byKey = new Map<string, ClosureRiskAggregationItem & { key: string }>();
  for (const [index, item] of riskItems.entries()) {
    const key = aliases.keyFor(item, index);
    const current = byKey.get(key);
    if (!current || shouldReplace(current, item)) byKey.set(key, { ...item, key });
  }
  const groups = [...byKey.values()].sort((left, right) =>
    right.weight - left.weight ||
    left.key.localeCompare(right.key) ||
    left.issueNumber - right.issueNumber
  );
  const weightedRiskByDisposition: Record<string, number> = {};
  for (const group of groups) {
    weightedRiskByDisposition[group.disposition] =
      (weightedRiskByDisposition[group.disposition] ?? 0) + group.weight;
  }
  return {
    unresolvedForReleaseCount: groups.length,
    unresolvedWeightedRisk: groups.reduce((sum, group) => sum + group.weight, 0),
    weightedRiskByDisposition,
    groups,
  };
}

export function closureRiskGroupKey(item: ClosureRiskAggregationItem): string {
  return buildIssueAliasGroups([item]).keyFor(item, 0);
}

export function buildIssueAliasGroups(items: readonly IssueAliasIdentity[]): IssueAliasGroupIndex {
  const union = new DeterministicUnionFind();
  const strongTokensByItem = items.map((item) => strongAliasTokens(item));
  for (const tokens of strongTokensByItem) {
    joinAliasTokens(union, tokens);
  }

  // Classifier-generated duplicate slugs are descriptive metadata, not identity
  // evidence. Only explicit issue/canonical links or a supplied aliasGroup may
  // merge rows.
  const duplicateClustersByRoot = new Map<string, Set<string>>();
  for (const [index, item] of items.entries()) {
    const firstToken = strongTokensByItem[index][0];
    const cluster = normalizeDuplicateCluster(item.duplicateCluster);
    if (!firstToken || !cluster) continue;
    const root = union.find(firstToken);
    const clusters = duplicateClustersByRoot.get(root) ?? new Set<string>();
    clusters.add(cluster);
    duplicateClustersByRoot.set(root, clusters);
  }

  const tokensByRoot = new Map<string, string[]>();
  for (const token of union.tokens()) {
    const root = union.find(token);
    const current = tokensByRoot.get(root) ?? [];
    current.push(token);
    tokensByRoot.set(root, current);
  }

  const keyByToken = new Map<string, string>();
  const groups = [...tokensByRoot.values()]
    .map((tokens): IssueAliasGroup => {
      const sortedTokens = [...tokens].sort(compareAliasTokens);
      const key = sortedTokens[0];
      for (const token of sortedTokens) keyByToken.set(token, key);
      return {
        key,
        issueNumbers: sortedTokens
          .filter((token) => token.startsWith('issue:'))
          .map((token) => Number(token.slice('issue:'.length)))
          .filter((value) => Number.isInteger(value) && value > 0),
        duplicateClusters: [...(duplicateClustersByRoot.get(union.find(tokens[0])) ?? [])]
          .sort(),
        tokens: sortedTokens,
      };
    })
    .sort((left, right) => left.key.localeCompare(right.key));

  return {
    groups,
    keyFor(item, fallbackIndex = 0) {
      for (const token of strongAliasTokens(item)) {
        const key = keyByToken.get(token);
        if (key) return key;
      }
      return `row:${fallbackIndex}`;
    },
  };
}

export function normalizeDuplicateCluster(cluster: string | null | undefined): string | null {
  if (typeof cluster !== 'string') return null;
  const normalized = cluster
    .normalize('NFKC')
    .trim()
    .replace(/\s+/g, ' ')
    .toLowerCase();
  return normalized || null;
}

export function canonicalIssueNumbersFromEvidence(
  evidenceJson: string | Record<string, unknown> | null | undefined,
): number[] {
  const evidence = parseEvidenceRecord(evidenceJson);
  if (!evidence) return [];

  const resolution = recordValue(evidence.canonicalResolution);
  if (resolution) {
    const selectedBranch = primaryCanonicalBranch(resolution);
    if (selectedBranch) {
      const branchPath = issueNumberArray(selectedBranch.path);
      if (branchPath.length > 0) {
        return canonicalAliasChain(branchPath, selectedBranch);
      }
      const branchTerminal = terminalChainIssueNumbers(selectedBranch);
      if (branchTerminal.length > 0) return branchTerminal;
    }
    const blockingBranch = issueNumberArray(resolution.blockingBranch);
    const selectedTerminal = terminalChainIssueNumbers(resolution);
    if (
      blockingBranch.length > 0 &&
      (
        selectedTerminal.length === 0 ||
        selectedTerminal.every((issueNumber) => blockingBranch.includes(issueNumber))
      )
    ) {
      return canonicalAliasChain(blockingBranch, resolution);
    }
    const explicitPath = issueNumberArray(resolution.path);
    if (explicitPath.length > 0) {
      return canonicalAliasChain(explicitPath, resolution);
    }
    const terminalChain = terminalChainIssueNumbers(resolution);
    if (terminalChain.length > 0) return terminalChain;
  }

  const deterministicFallback = [
    ...issueNumberArray(evidence.canonicalIssues),
    ...issueObjectNumbers(evidence.canonicalIssueDetails),
    ...canonicalFixProofIssueNumbers(evidence.canonicalFixCommitProof),
  ].sort((left, right) => left - right)[0];
  return deterministicFallback == null ? [] : [deterministicFallback];
}

export function allCanonicalIssueNumbersFromEvidence(
  evidenceJson: string | Record<string, unknown> | null | undefined,
): number[] {
  const evidence = parseEvidenceRecord(evidenceJson);
  if (!evidence) return [];

  const issueNumbers = new Set<number>();
  const addNumber = (value: unknown) => {
    const issueNumber = Number(value);
    if (Number.isInteger(issueNumber) && issueNumber > 0) issueNumbers.add(issueNumber);
  };
  const addNumberArray = (value: unknown) => {
    if (Array.isArray(value)) {
      for (const issueNumber of value) addNumber(issueNumber);
    }
  };
  const addIssueObject = (value: unknown) => {
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      addNumber((value as Record<string, unknown>).number);
    }
  };
  const addIssueObjectArray = (value: unknown) => {
    if (Array.isArray(value)) {
      for (const issue of value) addIssueObject(issue);
    }
  };
  const addTerminalProof = (value: unknown) => {
    if (!value || typeof value !== 'object' || Array.isArray(value)) return;
    const proof = value as Record<string, unknown>;
    addNumber(proof.issueNumber);
    addNumber(proof.terminalIssueNumber);
    addNumber(proof.sourceIssueNumber);
  };

  addNumberArray(evidence.canonicalIssues);
  addIssueObjectArray(evidence.canonicalIssueDetails);
  if (Array.isArray(evidence.canonicalFixCommitProof)) {
    for (const proof of evidence.canonicalFixCommitProof) {
      if (proof && typeof proof === 'object' && !Array.isArray(proof)) {
        addNumber((proof as Record<string, unknown>).sourceIssueNumber);
      }
    }
  }
  const resolution = evidence.canonicalResolution;
  if (resolution && typeof resolution === 'object' && !Array.isArray(resolution)) {
    const canonical = resolution as Record<string, unknown>;
    addNumberArray(canonical.path);
    addNumberArray(canonical.blockingBranch);
    addIssueObject(canonical.terminalIssue);
    addIssueObjectArray(canonical.terminalIssues);
    addIssueObject(canonical.cycleTerminalIssue);
    addTerminalProof(canonical.terminalProof);
    if (Array.isArray(canonical.branches)) {
      for (const branchValue of canonical.branches) {
        if (!branchValue || typeof branchValue !== 'object' || Array.isArray(branchValue)) continue;
        const branch = branchValue as Record<string, unknown>;
        addNumberArray(branch.path);
        addIssueObject(branch.terminalIssue);
        addTerminalProof(branch.terminalProof);
      }
    }
  }
  return [...issueNumbers].sort((left, right) => left - right);
}

function parseEvidenceRecord(
  evidenceJson: string | Record<string, unknown> | null | undefined,
): Record<string, unknown> | null {
  if (typeof evidenceJson === 'string') {
    try {
      const parsed = JSON.parse(evidenceJson);
      return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
        ? parsed as Record<string, unknown>
        : null;
    } catch {
      return null;
    }
  }
  return evidenceJson && typeof evidenceJson === 'object' && !Array.isArray(evidenceJson)
    ? evidenceJson
    : null;
}

function primaryCanonicalBranch(resolution: Record<string, unknown>): Record<string, unknown> | null {
  const branches = Array.isArray(resolution.branches)
    ? resolution.branches
      .map(recordValue)
      .filter((branch): branch is Record<string, unknown> =>
        branch != null && canonicalBranchIssueNumbers(branch).length > 0)
    : [];
  if (branches.length === 0) return null;

  const primaryTerminal = positiveIssueNumber(recordValue(resolution.terminalIssue)?.number);
  const blockingPath = issueNumberArray(resolution.blockingBranch);
  const primaryPath = issueNumberArray(resolution.path);
  return branches.sort((left, right) => {
    const riskDifference = canonicalBranchRiskPriority(right) -
      canonicalBranchRiskPriority(left);
    if (riskDifference !== 0) return riskDifference;
    const terminalPreference = Number(canonicalBranchMatchesTerminal(right, primaryTerminal)) -
      Number(canonicalBranchMatchesTerminal(left, primaryTerminal));
    if (terminalPreference !== 0) return terminalPreference;
    const blockingPreference = Number(sameIssueNumberPath(right, blockingPath)) -
      Number(sameIssueNumberPath(left, blockingPath));
    if (blockingPreference !== 0) return blockingPreference;
    const pathPreference = Number(sameIssueNumberPath(right, primaryPath)) -
      Number(sameIssueNumberPath(left, primaryPath));
    if (pathPreference !== 0) return pathPreference;
    return compareCanonicalBranches(left, right);
  })[0];
}

function canonicalBranchRiskPriority(branch: Record<string, unknown>): number {
  if (branch.fixedInRelease === true || branch.currentTagContainsFix === true) return 0;
  const terminalProof = recordValue(branch.terminalProof);
  const explicitDisposition = [
    branch.riskDisposition,
    branch.disposition,
    terminalProof?.riskDisposition,
    terminalProof?.disposition,
  ].find((value): value is string => typeof value === 'string' && value.length > 0);
  const status = [terminalProof?.status, branch.status]
    .find((value): value is string => typeof value === 'string' && value.length > 0);
  const disposition = explicitDisposition ?? (status ? closureRiskDisposition(status) : null);
  if (disposition) return DISPOSITION_PRIORITY[disposition] ?? 0;
  if (branch.fixedAfterRelease === true) return DISPOSITION_PRIORITY.known_not_in_release;
  const terminalState = String(recordValue(branch.terminalIssue)?.state ?? '').toLowerCase();
  if (terminalState === 'open') return DISPOSITION_PRIORITY.open_canonical_risk;
  if (terminalState === 'closed') return DISPOSITION_PRIORITY.missing_evidence;
  if (branch.cycle === true || branch.selfReference === true || branch.truncated === true) {
    return DISPOSITION_PRIORITY.unsupported_closure_claim;
  }
  return 0;
}

function canonicalBranchMatchesTerminal(
  branch: Record<string, unknown>,
  terminalIssueNumber: number | null,
): boolean {
  if (terminalIssueNumber == null) return false;
  return terminalChainIssueNumbers(branch).includes(terminalIssueNumber) ||
    issueNumberArray(branch.path).includes(terminalIssueNumber);
}

function sameIssueNumberPath(
  branch: Record<string, unknown>,
  expectedPath: readonly number[],
): boolean {
  if (expectedPath.length === 0) return false;
  const branchPath = issueNumberArray(branch.path);
  return branchPath.length === expectedPath.length &&
    branchPath.every((issueNumber, index) => issueNumber === expectedPath[index]);
}

function canonicalBranchIssueNumbers(branch: Record<string, unknown>): number[] {
  return canonicalAliasChain(issueNumberArray(branch.path), branch);
}

function compareCanonicalBranches(
  left: Record<string, unknown>,
  right: Record<string, unknown>,
): number {
  return canonicalBranchSortKey(left).localeCompare(canonicalBranchSortKey(right));
}

function canonicalBranchSortKey(branch: Record<string, unknown>): string {
  const path = issueNumberArray(branch.path);
  const terminal = terminalChainIssueNumbers(branch);
  return [...path, ...terminal]
    .map((number) => String(number).padStart(16, '0'))
    .join(':');
}

function canonicalAliasChain(
  path: readonly number[],
  terminalSource: Record<string, unknown>,
): number[] {
  const pathIssueNumbers = uniqueIssueNumbers(path);
  const terminalIssueNumbers = terminalChainIssueNumbers(terminalSource);
  if (pathIssueNumbers.length === 0) return terminalIssueNumbers;
  if (terminalIssueNumbers.length === 0) return pathIssueNumbers;
  return terminalIssueNumbers.every((issueNumber) => pathIssueNumbers.includes(issueNumber))
    ? pathIssueNumbers
    : terminalIssueNumbers;
}

function terminalChainIssueNumbers(value: Record<string, unknown>): number[] {
  const terminalIssue = positiveIssueNumber(recordValue(value.terminalIssue)?.number);
  const cycleTerminalIssue = positiveIssueNumber(recordValue(value.cycleTerminalIssue)?.number);
  const terminalProof = recordValue(value.terminalProof);
  const selectedTerminal = [
    terminalIssue,
    cycleTerminalIssue,
    positiveIssueNumber(terminalProof?.terminalIssueNumber),
    positiveIssueNumber(terminalProof?.issueNumber),
    positiveIssueNumber(terminalProof?.sourceIssueNumber),
  ].find((issueNumber): issueNumber is number => issueNumber != null);
  return selectedTerminal == null ? [] : [selectedTerminal];
}

function issueNumberArray(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return uniqueIssueNumbers(value.map(positiveIssueNumber));
}

function issueObjectNumbers(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return uniqueIssueNumbers(value.map((item) =>
    positiveIssueNumber(recordValue(item)?.number)));
}

function canonicalFixProofIssueNumbers(value: unknown): number[] {
  if (!Array.isArray(value)) return [];
  return uniqueIssueNumbers(value.map((item) =>
    positiveIssueNumber(recordValue(item)?.sourceIssueNumber)));
}

function uniqueIssueNumbers(values: readonly (number | null)[]): number[] {
  return [...new Set(values.filter((value): value is number => value != null))]
    .sort((left, right) => left - right);
}

function positiveIssueNumber(value: unknown): number | null {
  const issueNumber = Number(value);
  return Number.isInteger(issueNumber) && issueNumber > 0 ? issueNumber : null;
}

function recordValue(value: unknown): Record<string, unknown> | null {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : null;
}

function shouldReplace(
  current: ClosureRiskAggregationItem,
  candidate: ClosureRiskAggregationItem,
): boolean {
  if (candidate.weight !== current.weight) return candidate.weight > current.weight;
  const dispositionDifference =
    (DISPOSITION_PRIORITY[candidate.disposition] ?? 0) -
    (DISPOSITION_PRIORITY[current.disposition] ?? 0);
  if (dispositionDifference !== 0) return dispositionDifference > 0;
  return candidate.issueNumber < current.issueNumber;
}

function strongAliasTokens(item: IssueAliasIdentity): string[] {
  const tokens = new Set<string>();
  const aliasGroup = trustedAliasToken(item.aliasGroup);
  if (aliasGroup) tokens.add(aliasGroup);
  addIssueToken(tokens, item.issueNumber);
  addIssueToken(tokens, item.canonicalIssueNumber);
  for (const issueNumber of item.canonicalIssueNumbers ?? []) addIssueToken(tokens, issueNumber);
  return [...tokens].sort(compareAliasTokens);
}

function joinAliasTokens(union: DeterministicUnionFind, tokens: readonly string[]): void {
  const sortedTokens = [...new Set(tokens)].sort(compareAliasTokens);
  if (sortedTokens.length === 0) return;
  for (const token of sortedTokens) union.add(token);
  for (let index = 1; index < sortedTokens.length; index++) {
    union.join(sortedTokens[0], sortedTokens[index]);
  }
}

function addIssueToken(tokens: Set<string>, value: number | null | undefined): void {
  if (Number.isInteger(value) && Number(value) > 0) tokens.add(`issue:${Number(value)}`);
}

function normalizeAliasGroup(value: string | null | undefined): string | null {
  if (typeof value !== 'string') return null;
  const normalized = value.normalize('NFKC').trim().toLowerCase();
  return normalized || null;
}

function trustedAliasToken(value: string | null | undefined): string | null {
  const normalized = normalizeAliasGroup(value);
  if (!normalized || !/^issue:[1-9]\d*$/.test(normalized)) return null;
  return normalized;
}

function compareAliasTokens(left: string, right: string): number {
  const leftRank = aliasTokenRank(left);
  const rightRank = aliasTokenRank(right);
  if (leftRank !== rightRank) return leftRank - rightRank;
  if (left.startsWith('issue:') && right.startsWith('issue:')) {
    return Number(left.slice('issue:'.length)) - Number(right.slice('issue:'.length));
  }
  return left.localeCompare(right);
}

function aliasTokenRank(token: string): number {
  if (token.startsWith('issue:')) return 0;
  return 1;
}

class DeterministicUnionFind {
  private readonly parent = new Map<string, string>();

  add(token: string): void {
    if (!this.parent.has(token)) this.parent.set(token, token);
  }

  find(token: string): string {
    const parent = this.parent.get(token);
    if (!parent) {
      this.add(token);
      return token;
    }
    if (parent === token) return token;
    const root = this.find(parent);
    this.parent.set(token, root);
    return root;
  }

  join(left: string, right: string): void {
    const leftRoot = this.find(left);
    const rightRoot = this.find(right);
    if (leftRoot === rightRoot) return;
    const [root, child] = [leftRoot, rightRoot].sort(compareAliasTokens);
    this.parent.set(child, root);
  }

  tokens(): string[] {
    return [...this.parent.keys()].sort(compareAliasTokens);
  }
}
