import {
  compareRecommendationRecency,
  withinDecimalTolerance,
  type InstallStatus,
} from './score';

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
] as const;

export const RECOMMENDATION_DECISION_CODES = [
  'highest_confidence',
  'newest_within_confidence_tolerance',
  'higher_confidence_release_selected',
  'newer_release_within_tolerance_selected',
  'below_recommendation_threshold',
  'install_gate_active',
] as const;

export type RecommendationDecisionCode = (typeof RECOMMENDATION_DECISION_CODES)[number];

export interface RecommendationDecisionContract {
  schemaVersion: 1;
  policyCode: 'highest_confidence_with_recency_tolerance';
  threshold: number;
  recencyTolerance: number;
  selectedTag: string | null;
  selectedScore: number | null;
  highestScoringTag: string | null;
  highestScore: number | null;
  releaseTag: string;
  releaseScore: number | null;
  qualifies: boolean;
  selected: boolean;
  recencyRank: number;
  scoreRank: number | null;
  scoreDeltaToHighest: number | null;
  decisionCode: RecommendationDecisionCode;
  summary: string;
}

export interface RecommendationDecisionValidationInput {
  tag: string;
  componentsDecision: unknown;
  explanationDecision: unknown;
  expectedStatus: string | null;
  expectedScore: number | null;
  expectedSelected: boolean;
  expectedThreshold: number;
  expectedRecencyTolerance: number;
}

export interface RecommendationDecisionRunRow {
  tag: string;
  publishedAt: string;
  status: InstallStatus | string | null;
  score: number | null;
  recommended: boolean;
  componentsDecision: unknown;
  explanationDecision: unknown;
}

export interface RecommendationDecisionRunValidationInput {
  rows: RecommendationDecisionRunRow[];
  expectedSelectedTag: string | null;
  expectedThreshold: number;
  expectedRecencyTolerance: number;
}

const decisionCodes = new Set<string>(RECOMMENDATION_DECISION_CODES);
const decisionKeys = new Set<string>(RECOMMENDATION_DECISION_KEYS);

export function validateRecommendationDecisionCopies(
  input: RecommendationDecisionValidationInput,
): string[] {
  const failures = [
    ...validateRecommendationDecision({
      ...input,
      label: 'score components recommendationDecision',
      decision: input.componentsDecision,
    }),
    ...validateRecommendationDecision({
      ...input,
      label: 'score explanation recommendationDecision',
      decision: input.explanationDecision,
    }),
  ];

  if (isRecord(input.componentsDecision) && isRecord(input.explanationDecision)) {
    for (const key of RECOMMENDATION_DECISION_KEYS) {
      if (!sameJsonValue(input.componentsDecision[key], input.explanationDecision[key])) {
        failures.push(
          `${input.tag}: score components and explanation recommendationDecision field ${key} must match`,
        );
      }
    }
  }

  return failures;
}

export function validateRecommendationDecisionRun(
  input: RecommendationDecisionRunValidationInput,
): string[] {
  const failures: string[] = [];
  const tags = input.rows.map((row) => row.tag);
  const tagSet = new Set(tags);
  if (tagSet.size !== tags.length) failures.push('recommendation run candidate tags must be unique');

  if (!isFiniteNumber(input.expectedThreshold)) {
    failures.push('recommendation run threshold must be finite');
  }
  if (
    !isFiniteNumber(input.expectedRecencyTolerance) ||
    input.expectedRecencyTolerance < 0
  ) {
    failures.push(
      'recommendation run recency tolerance must be non-negative and finite',
    );
  }
  const selection = recomputeRecommendationSelection(
    input.rows,
    input.expectedThreshold,
    input.expectedRecencyTolerance,
  );
  if (selection.selectedTag !== input.expectedSelectedTag) {
    failures.push(
      `recommendation run selectedTag ${String(input.expectedSelectedTag)} must recompute to ${String(selection.selectedTag)}`,
    );
  }
  if (selection.selectedTag != null && !tagSet.has(selection.selectedTag)) {
    failures.push(`recommendation run selectedTag ${selection.selectedTag} must be in candidates`);
  }

  const recommendedRows = input.rows.filter((row) => row.recommended);
  const expectedRecommendedCount = selection.selectedTag == null ? 0 : 1;
  if (recommendedRows.length !== expectedRecommendedCount) {
    failures.push(
      `recommendation run must have exactly ${expectedRecommendedCount} selected row(s), got ${recommendedRows.length}`,
    );
  }
  if (
    selection.selectedTag != null &&
    recommendedRows[0]?.tag !== selection.selectedTag
  ) {
    failures.push(
      `recommendation run selected row ${recommendedRows[0]?.tag ?? 'none'} must match ${selection.selectedTag}`,
    );
  }

  const globalDecisionFields = [
    'policyCode',
    'threshold',
    'recencyTolerance',
    'selectedTag',
    'selectedScore',
    'highestScoringTag',
    'highestScore',
  ] as const;
  const recencyRankByTag = new Map(
    input.rows
      .slice()
      .sort(compareRecommendationRecency)
      .map((row, recencyIndex) => [row.tag, recencyIndex + 1]),
  );
  const scoreRankByTag = new Map(
    input.rows
      .filter((row) =>
        row.status === 'eligible' &&
        typeof row.score === 'number' &&
        Number.isFinite(row.score)
      )
      .sort((left, right) =>
        Number(right.score) - Number(left.score) ||
        compareRecommendationRecency(left, right)
      )
      .map((row, scoreIndex) => [row.tag, scoreIndex + 1]),
  );
  let referenceDecision: Record<string, unknown> | null = null;
  for (const row of input.rows) {
    if (
      (
        typeof row.publishedAt !== 'string' ||
        !Number.isFinite(Date.parse(row.publishedAt))
      )
    ) {
      failures.push(
        `${row.tag}: recommendation candidate publishedAt must be a valid timestamp`,
      );
    }
    if (!isInstallStatus(row.status)) {
      failures.push(
        `${row.tag}: recommendation candidate status must be a known install status`,
      );
    }
    failures.push(...validateRecommendationDecisionCopies({
      tag: row.tag,
      componentsDecision: row.componentsDecision,
      explanationDecision: row.explanationDecision,
      expectedStatus: row.status,
      expectedScore: row.score,
      expectedSelected: row.recommended,
      expectedThreshold: input.expectedThreshold,
      expectedRecencyTolerance: input.expectedRecencyTolerance,
    }));
    if (!isRecord(row.componentsDecision)) continue;
    const decision = row.componentsDecision;
    const expectedRecencyRank = recencyRankByTag.get(row.tag) ?? null;
    const expectedScoreRank = scoreRankByTag.get(row.tag) ?? null;
    if (decision.recencyRank !== expectedRecencyRank) {
      failures.push(
        `${row.tag}: recommendation decision recencyRank must recompute to ${expectedRecencyRank}`,
      );
    }
    if (decision.scoreRank !== expectedScoreRank) {
      failures.push(
        `${row.tag}: recommendation decision scoreRank must recompute to ${String(expectedScoreRank)}`,
      );
    }
    if (!referenceDecision) referenceDecision = decision;
    for (const field of globalDecisionFields) {
      if (
        referenceDecision &&
        !sameJsonValue(decision[field], referenceDecision[field])
      ) {
        failures.push(
          `${row.tag}: recommendation run decision field ${field} must agree across every candidate`,
        );
      }
    }
    if (decision.selectedTag != null && !tagSet.has(String(decision.selectedTag))) {
      failures.push(`${row.tag}: recommendation decision selectedTag must be in candidates`);
    }
    for (const [field, expected] of [
      ['selectedTag', selection.selectedTag],
      ['selectedScore', selection.selectedScore],
      ['highestScoringTag', selection.highestScoringTag],
      ['highestScore', selection.highestScore],
    ] as const) {
      if (!sameJsonValue(decision[field], expected)) {
        failures.push(
          `${row.tag}: recommendation decision ${field} must match recomputed run policy`,
        );
      }
    }
  }
  return [...new Set(failures)];
}

function recomputeRecommendationSelection(
  rows: readonly RecommendationDecisionRunRow[],
  threshold: number,
  recencyTolerance: number,
): {
  selectedTag: string | null;
  selectedScore: number | null;
  highestScoringTag: string | null;
  highestScore: number | null;
} {
  if (
    !isFiniteNumber(threshold) ||
    !isFiniteNumber(recencyTolerance) ||
    recencyTolerance < 0
  ) {
    return {
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
    };
  }
  const candidates = rows
    .filter((row): row is RecommendationDecisionRunRow & {
      status: 'eligible';
      score: number;
    } =>
      row.status === 'eligible' &&
      isFiniteNumber(row.score) &&
      row.score >= threshold)
    .slice()
    .sort(compareRecommendationRecency);
  if (candidates.length === 0) {
    return {
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
    };
  }
  const highestScore = Math.max(...candidates.map((row) => row.score));
  const highestScoring = candidates.find((row) =>
    row.score === highestScore)!;
  const selected = candidates.find((row) =>
    withinDecimalTolerance(row.score, highestScore, recencyTolerance))!;
  return {
    selectedTag: selected.tag,
    selectedScore: selected.score,
    highestScoringTag: highestScoring.tag,
    highestScore,
  };
}

export function recommendationDecisionSummary(
  decision: RecommendationDecisionContract,
): string {
  const context =
    `Decision ${decision.decisionCode}: release ${releaseLabel(decision.releaseTag, decision.releaseScore)}; ` +
    `selected ${releaseLabel(decision.selectedTag, decision.selectedScore)}; ` +
    `highest-scoring qualifying release ${releaseLabel(decision.highestScoringTag, decision.highestScore)}; ` +
    `threshold ${formatNumber(decision.threshold)}; ` +
    `recency tolerance ${formatNumber(decision.recencyTolerance)}.`;
  if (decision.decisionCode === 'highest_confidence') {
    return `${context} This release is recommended as the highest-confidence qualifying release.`;
  }
  if (decision.decisionCode === 'newest_within_confidence_tolerance') {
    return `${context} This release is recommended as the newest qualifying release within the recency tolerance of the highest score.`;
  }
  if (decision.decisionCode === 'higher_confidence_release_selected') {
    return `${context} The selected release has higher audited install confidence than this release.`;
  }
  if (decision.decisionCode === 'newer_release_within_tolerance_selected') {
    return `${context} The selected release is newer and remains within the recency tolerance of this release's higher score.`;
  }
  if (decision.decisionCode === 'below_recommendation_threshold') {
    return `${context} This release is not recommended because its score is below the recommendation threshold.`;
  }
  const gateReason = decision.releaseScore == null
    ? 'settle-time eligibility has not been established yet'
    : 'a security-advisory or rapid-hotfix install gate is active';
  return `${context} This release is not recommended because ${gateReason}.`;
}

function validateRecommendationDecision(
  input: RecommendationDecisionValidationInput & {
    label: string;
    decision: unknown;
  },
): string[] {
  const { decision, label, tag } = input;
  const failures: string[] = [];
  if (!isRecord(decision)) {
    failures.push(`${tag}: ${label} must be an object`);
    return failures;
  }

  for (const key of Object.keys(decision).sort()) {
    if (!decisionKeys.has(key)) failures.push(`${tag}: ${label} has unexpected key ${key}`);
  }
  for (const key of RECOMMENDATION_DECISION_KEYS) {
    if (!Object.hasOwn(decision, key)) {
      failures.push(`${tag}: ${label} is missing required field ${key}`);
    }
  }

  expect(
    failures,
    tag,
    isInstallStatus(input.expectedStatus),
    `${label} expected status must be a known install status`,
  );
  expect(
    failures,
    tag,
    isFiniteNumber(input.expectedThreshold),
    `${label} expected threshold must be finite`,
  );
  expect(
    failures,
    tag,
    isFiniteNumber(input.expectedRecencyTolerance) &&
      input.expectedRecencyTolerance >= 0,
    `${label} expected recency tolerance must be non-negative and finite`,
  );
  expect(failures, tag, decision.schemaVersion === 1, `${label} schemaVersion must be 1`);
  expect(
    failures,
    tag,
    decision.policyCode === 'highest_confidence_with_recency_tolerance',
    `${label} policyCode must be highest_confidence_with_recency_tolerance`,
  );
  expect(
    failures,
    tag,
    decision.threshold === input.expectedThreshold,
    `${label} threshold (${String(decision.threshold)}) must equal ${input.expectedThreshold}`,
  );
  expect(
    failures,
    tag,
    decision.recencyTolerance === input.expectedRecencyTolerance,
    `${label} recencyTolerance (${String(decision.recencyTolerance)}) must equal ${input.expectedRecencyTolerance}`,
  );
  expect(
    failures,
    tag,
    isNullableTag(decision.selectedTag),
    `${label} selectedTag must be a non-empty string or null`,
  );
  expect(
    failures,
    tag,
    isNullableFiniteNumber(decision.selectedScore),
    `${label} selectedScore must be a finite number or null`,
  );
  expect(
    failures,
    tag,
    isNullableTag(decision.highestScoringTag),
    `${label} highestScoringTag must be a non-empty string or null`,
  );
  expect(
    failures,
    tag,
    isNullableFiniteNumber(decision.highestScore),
    `${label} highestScore must be a finite number or null`,
  );
  expect(
    failures,
    tag,
    typeof decision.releaseTag === 'string' && decision.releaseTag.length > 0,
    `${label} releaseTag must be a non-empty string`,
  );
  expect(
    failures,
    tag,
    isNullableFiniteNumber(decision.releaseScore),
    `${label} releaseScore must be a finite number or null`,
  );
  expect(failures, tag, typeof decision.qualifies === 'boolean', `${label} qualifies must be boolean`);
  expect(failures, tag, typeof decision.selected === 'boolean', `${label} selected must be boolean`);
  expect(
    failures,
    tag,
    Number.isInteger(decision.recencyRank) && Number(decision.recencyRank) > 0,
    `${label} recencyRank must be a positive integer`,
  );
  expect(
    failures,
    tag,
    decision.scoreRank === null ||
      Number.isInteger(decision.scoreRank) && Number(decision.scoreRank) > 0,
    `${label} scoreRank must be a positive integer or null`,
  );
  expect(
    failures,
    tag,
    decision.scoreDeltaToHighest === null ||
      isFiniteNumber(decision.scoreDeltaToHighest) && decision.scoreDeltaToHighest >= 0,
    `${label} scoreDeltaToHighest must be a non-negative finite number or null`,
  );
  expect(
    failures,
    tag,
    typeof decision.decisionCode === 'string' && decisionCodes.has(decision.decisionCode),
    `${label} decisionCode must be known`,
  );
  expect(
    failures,
    tag,
    typeof decision.summary === 'string' && decision.summary.length > 0,
    `${label} summary must be present`,
  );

  const selectedPairPresent = isNonEmptyString(decision.selectedTag) &&
    isFiniteNumber(decision.selectedScore);
  const selectedPairAbsent =
    decision.selectedTag === null && decision.selectedScore === null;
  const highestPairPresent = isNonEmptyString(decision.highestScoringTag) &&
    isFiniteNumber(decision.highestScore);
  const highestPairAbsent =
    decision.highestScoringTag === null && decision.highestScore === null;
  expect(
    failures,
    tag,
    selectedPairPresent || selectedPairAbsent,
    `${label} selectedTag and selectedScore must both be present or both be null`,
  );
  expect(
    failures,
    tag,
    highestPairPresent || highestPairAbsent,
    `${label} highestScoringTag and highestScore must both be present or both be null`,
  );
  expect(
    failures,
    tag,
    selectedPairPresent === highestPairPresent,
    `${label} selected and highest-scoring release fields must become present together`,
  );

  expect(
    failures,
    tag,
    decision.releaseTag === tag,
    `${label} releaseTag (${String(decision.releaseTag)}) must match ${tag}`,
  );
  expect(
    failures,
    tag,
    sameJsonValue(decision.releaseScore, input.expectedScore),
    `${label} releaseScore (${String(decision.releaseScore)}) must match ${String(input.expectedScore)}`,
  );
  expect(
    failures,
    tag,
    decision.selected === input.expectedSelected,
    `${label} selected (${String(decision.selected)}) must match expected recommended (${input.expectedSelected})`,
  );

  const expectedQualifies =
    input.expectedStatus === 'eligible' &&
    isFiniteNumber(input.expectedScore) &&
    input.expectedScore >= input.expectedThreshold;
  expect(
    failures,
    tag,
    decision.qualifies === expectedQualifies,
    `${label} qualifies (${String(decision.qualifies)}) must match status, score, and threshold`,
  );
  expect(
    failures,
    tag,
    input.expectedStatus === 'eligible'
      ? Number.isInteger(decision.scoreRank) && Number(decision.scoreRank) > 0
      : decision.scoreRank === null,
    `${label} scoreRank presence must match eligible status`,
  );
  if (expectedQualifies) {
    expect(
      failures,
      tag,
      selectedPairPresent && highestPairPresent,
      `${label} qualifying releases require selected and highest-scoring release identity`,
    );
  }

  if (selectedPairPresent && highestPairPresent) {
    expect(
      failures,
      tag,
      Number(decision.highestScore) >= Number(decision.selectedScore),
      `${label} highestScore must be greater than or equal to selectedScore`,
    );
    expect(
      failures,
      tag,
      withinDecimalTolerance(
        Number(decision.selectedScore),
        Number(decision.highestScore),
        input.expectedRecencyTolerance,
      ),
      `${label} selectedScore must be within recencyTolerance of highestScore`,
    );
    if (decision.selectedTag === decision.highestScoringTag) {
      expect(
        failures,
        tag,
        decision.selectedScore === decision.highestScore,
        `${label} selectedScore and highestScore must match when their tags match`,
      );
    }
  }

  if (decision.selected === true) {
    expect(failures, tag, decision.qualifies === true, `${label} selected release must qualify`);
    expect(
      failures,
      tag,
      decision.selectedTag === decision.releaseTag,
      `${label} selectedTag must match releaseTag for the selected release`,
    );
    expect(
      failures,
      tag,
      decision.selectedScore === decision.releaseScore,
      `${label} selectedScore must match releaseScore for the selected release`,
    );
  } else if (decision.selectedTag != null) {
    expect(
      failures,
      tag,
      decision.selectedTag !== decision.releaseTag,
      `${label} unselected release must not name itself as selectedTag`,
    );
  }

  if (isFiniteNumber(decision.releaseScore) && isFiniteNumber(decision.highestScore)) {
    const expectedDelta = roundMetric(decision.highestScore - decision.releaseScore);
    expect(
      failures,
      tag,
      decision.scoreDeltaToHighest === expectedDelta,
      `${label} scoreDeltaToHighest (${String(decision.scoreDeltaToHighest)}) must equal ${expectedDelta}`,
    );
  } else {
    expect(
      failures,
      tag,
      decision.scoreDeltaToHighest === null,
      `${label} scoreDeltaToHighest must be null without both releaseScore and highestScore`,
    );
  }

  if (typeof decision.decisionCode === 'string' && decisionCodes.has(decision.decisionCode)) {
    const expectedCode = expectedDecisionCode({
      status: input.expectedStatus,
      qualifies: expectedQualifies,
      decision,
    });
    expect(
      failures,
      tag,
      decision.decisionCode === expectedCode,
      `${label} decisionCode (${decision.decisionCode}) must equal ${expectedCode}`,
    );
  }

  if (isRecommendationDecisionContract(decision)) {
    const expectedSummary = recommendationDecisionSummary(decision);
    expect(
      failures,
      tag,
      decision.summary === expectedSummary,
      `${label} summary must match the canonical recommendation decision summary`,
    );
  }

  return failures;
}

function expectedDecisionCode(input: {
  status: string | null;
  qualifies: boolean;
  decision: Record<string, unknown>;
}): RecommendationDecisionCode {
  if (input.status !== 'eligible') return 'install_gate_active';
  if (!input.qualifies) return 'below_recommendation_threshold';
  if (input.decision.selected === true &&
      input.decision.releaseTag === input.decision.highestScoringTag) {
    return 'highest_confidence';
  }
  if (input.decision.selected === true) return 'newest_within_confidence_tolerance';
  if (isFiniteNumber(input.decision.selectedScore) &&
      isFiniteNumber(input.decision.releaseScore) &&
      input.decision.releaseScore >= input.decision.selectedScore) {
    return 'newer_release_within_tolerance_selected';
  }
  return 'higher_confidence_release_selected';
}

function isRecommendationDecisionContract(
  value: Record<string, unknown>,
): value is Record<string, unknown> & RecommendationDecisionContract {
  return value.schemaVersion === 1 &&
    value.policyCode === 'highest_confidence_with_recency_tolerance' &&
    isFiniteNumber(value.threshold) &&
    isFiniteNumber(value.recencyTolerance) &&
    isNullableTag(value.selectedTag) &&
    isNullableFiniteNumber(value.selectedScore) &&
    isNullableTag(value.highestScoringTag) &&
    isNullableFiniteNumber(value.highestScore) &&
    isNonEmptyString(value.releaseTag) &&
    isNullableFiniteNumber(value.releaseScore) &&
    typeof value.qualifies === 'boolean' &&
    typeof value.selected === 'boolean' &&
    Number.isInteger(value.recencyRank) &&
    (value.scoreRank === null || Number.isInteger(value.scoreRank)) &&
    isNullableFiniteNumber(value.scoreDeltaToHighest) &&
    typeof value.decisionCode === 'string' &&
    decisionCodes.has(value.decisionCode) &&
    typeof value.summary === 'string';
}

function releaseLabel(tag: string | null, score: number | null): string {
  return `${tag ?? 'none'} (${score == null ? 'score n/a' : `score ${formatNumber(score)}`})`;
}

function formatNumber(value: number): string {
  return value.toFixed(1);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value != null && typeof value === 'object' && !Array.isArray(value);
}

function isFiniteNumber(value: unknown): value is number {
  return typeof value === 'number' && Number.isFinite(value);
}

function isNullableFiniteNumber(value: unknown): value is number | null {
  return value === null || isFiniteNumber(value);
}

function isNonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0;
}

function isNullableTag(value: unknown): value is string | null {
  return value === null || isNonEmptyString(value);
}

function isInstallStatus(value: unknown): value is InstallStatus {
  return value === 'wait' ||
    value === 'skip-cve' ||
    value === 'skip-hotfix' ||
    value === 'eligible';
}

function sameJsonValue(left: unknown, right: unknown): boolean {
  return JSON.stringify(left) === JSON.stringify(right);
}

function roundMetric(value: number): number {
  return Math.round(value * 1000) / 1000;
}

function expect(failures: string[], tag: string, condition: boolean, message: string): void {
  if (!condition) failures.push(`${tag}: ${message}`);
}
