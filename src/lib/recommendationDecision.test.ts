import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  RECOMMENDATION_DECISION_KEYS,
  recommendationDecisionSummary,
  validateRecommendationDecisionCopies,
  validateRecommendationDecisionRun,
  type RecommendationDecisionContract,
} from './recommendationDecision.ts';

function validDecision(
  overrides: Partial<RecommendationDecisionContract> = {},
): RecommendationDecisionContract {
  const decision: RecommendationDecisionContract = {
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
    summary: '',
    ...overrides,
  };
  decision.summary = overrides.summary ?? recommendationDecisionSummary(decision);
  return decision;
}

function validate(
  componentsDecision: unknown,
  explanationDecision: unknown = structuredClone(componentsDecision),
): string[] {
  return validateRecommendationDecisionCopies({
    tag: 'v-test',
    componentsDecision,
    explanationDecision,
    expectedStatus: 'eligible',
    expectedScore: 7.5,
    expectedSelected: true,
    expectedThreshold: 7,
    expectedRecencyTolerance: 0.5,
  });
}

function runDecision(input: {
  releaseTag: string;
  releaseScore: number;
  selectedTag: string;
  selectedScore: number;
  highestScoringTag: string;
  highestScore: number;
  selected: boolean;
  recencyRank: number;
  scoreRank: number;
  decisionCode: RecommendationDecisionContract['decisionCode'];
}): RecommendationDecisionContract {
  const decision = validDecision({
    releaseTag: input.releaseTag,
    releaseScore: input.releaseScore,
    selectedTag: input.selectedTag,
    selectedScore: input.selectedScore,
    highestScoringTag: input.highestScoringTag,
    highestScore: input.highestScore,
    selected: input.selected,
    qualifies: true,
    recencyRank: input.recencyRank,
    scoreRank: input.scoreRank,
    scoreDeltaToHighest: Math.round((input.highestScore - input.releaseScore) * 1000) / 1000,
    decisionCode: input.decisionCode,
  });
  decision.summary = recommendationDecisionSummary(decision);
  return decision;
}

describe('recommendation decision runtime contract', () => {
  it('accepts complete equal decision copies', () => {
    const decision = validDecision();
    assert.deepEqual(validate(decision), []);
  });

  it('rejects every missing decision field', () => {
    for (const field of RECOMMENDATION_DECISION_KEYS) {
      const decision = validDecision() as unknown as Record<string, unknown>;
      delete decision[field];
      const failures = validate(decision);
      assert.ok(
        failures.some((failure) => failure.includes(`missing required field ${field}`)),
        `expected a missing-field failure for ${field}`,
      );
    }
  });

  it('rejects malformed ranks, thresholds, scores, tags, code, and summary', () => {
    const decision = validDecision() as unknown as Record<string, unknown>;
    Object.assign(decision, {
      threshold: 6,
      recencyTolerance: -1,
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: '',
      highestScore: Number.NaN,
      releaseScore: 7.4,
      recencyRank: 0,
      scoreRank: null,
      scoreDeltaToHighest: 1,
      decisionCode: 'install_gate_active',
      summary: 'drifted summary',
    });
    const failures = validate(decision);
    for (const expected of [
      /threshold .* must equal 7/,
      /recencyTolerance .* must equal 0.5/,
      /highestScoringTag must be a non-empty string or null/,
      /highestScore must be a finite number or null/,
      /releaseScore .* must match 7.5/,
      /recencyRank must be a positive integer/,
      /scoreRank presence must match eligible status/,
      /decisionCode .* must equal/,
    ]) {
      assert.ok(failures.some((failure) => expected.test(failure)), String(expected));
    }

    const summaryDrift = validDecision({ summary: 'drifted summary' });
    assert.ok(validate(summaryDrift).some((failure) =>
      /summary must match the canonical recommendation decision summary/.test(failure)));
  });

  it('rejects any divergence between components and explanation copies', () => {
    const components = validDecision();
    for (const field of RECOMMENDATION_DECISION_KEYS) {
      const explanation = structuredClone(components) as unknown as Record<string, unknown>;
      explanation[field] = field === 'summary' ? 'drifted summary' : null;
      const failures = validate(components, explanation);
      assert.ok(
        failures.some((failure) =>
          failure.includes(`components and explanation recommendationDecision field ${field} must match`)),
        `expected a copy-divergence failure for ${field}`,
      );
    }
  });

  it('validates the complete run against the recomputed recommendation policy', () => {
    const newest = runDecision({
      releaseTag: 'v-new',
      releaseScore: 7.8,
      selectedTag: 'v-new',
      selectedScore: 7.8,
      highestScoringTag: 'v-old',
      highestScore: 8.3,
      selected: true,
      recencyRank: 1,
      scoreRank: 2,
      decisionCode: 'newest_within_confidence_tolerance',
    });
    const oldest = runDecision({
      releaseTag: 'v-old',
      releaseScore: 8.3,
      selectedTag: 'v-new',
      selectedScore: 7.8,
      highestScoringTag: 'v-old',
      highestScore: 8.3,
      selected: false,
      recencyRank: 2,
      scoreRank: 1,
      decisionCode: 'newer_release_within_tolerance_selected',
    });
    const rows = [
      {
        tag: 'v-new',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'eligible',
        score: 7.8,
        recommended: true,
        componentsDecision: newest,
        explanationDecision: structuredClone(newest),
      },
      {
        tag: 'v-old',
        publishedAt: '2026-07-03T00:00:00Z',
        status: 'eligible',
        score: 8.3,
        recommended: false,
        componentsDecision: oldest,
        explanationDecision: structuredClone(oldest),
      },
    ];

    assert.deepEqual(validateRecommendationDecisionRun({
      rows,
      expectedSelectedTag: 'v-new',
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    }), []);

    const drifted = structuredClone(rows);
    drifted[1].componentsDecision.selectedTag = 'v-missing';
    drifted[1].explanationDecision.selectedTag = 'v-missing';
    drifted[1].recommended = true;
    const failures = validateRecommendationDecisionRun({
      rows: drifted,
      expectedSelectedTag: 'v-new',
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    });
    assert.ok(failures.some((failure) => /exactly 1 selected row/.test(failure)));
    assert.ok(failures.some((failure) => /selectedTag must be in candidates/.test(failure)));
    assert.ok(failures.some((failure) => /must agree across every candidate/.test(failure)));
    assert.ok(failures.some((failure) => /must match recomputed run policy/.test(failure)));
  });

  it('recomputes recency and score ranks instead of trusting persisted values', () => {
    const newest = runDecision({
      releaseTag: 'v-new',
      releaseScore: 7.8,
      selectedTag: 'v-new',
      selectedScore: 7.8,
      highestScoringTag: 'v-old',
      highestScore: 8.3,
      selected: true,
      recencyRank: 2,
      scoreRank: 1,
      decisionCode: 'newest_within_confidence_tolerance',
    });
    const oldest = runDecision({
      releaseTag: 'v-old',
      releaseScore: 8.3,
      selectedTag: 'v-new',
      selectedScore: 7.8,
      highestScoringTag: 'v-old',
      highestScore: 8.3,
      selected: false,
      recencyRank: 1,
      scoreRank: 2,
      decisionCode: 'newer_release_within_tolerance_selected',
    });
    const failures = validateRecommendationDecisionRun({
      rows: [
        {
          tag: 'v-new',
          publishedAt: '2026-07-04T00:00:00Z',
          status: 'eligible',
          score: 7.8,
          recommended: true,
          componentsDecision: newest,
          explanationDecision: structuredClone(newest),
        },
        {
          tag: 'v-old',
          publishedAt: '2026-07-03T00:00:00Z',
          status: 'eligible',
          score: 8.3,
          recommended: false,
          componentsDecision: oldest,
          explanationDecision: structuredClone(oldest),
        },
      ],
      expectedSelectedTag: 'v-new',
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    });

    assert.ok(failures.some((failure) =>
      /v-new: recommendation decision recencyRank must recompute to 1/.test(failure)));
    assert.ok(failures.some((failure) =>
      /v-new: recommendation decision scoreRank must recompute to 2/.test(failure)));
    assert.ok(failures.some((failure) =>
      /v-old: recommendation decision recencyRank must recompute to 2/.test(failure)));
    assert.ok(failures.some((failure) =>
      /v-old: recommendation decision scoreRank must recompute to 1/.test(failure)));
  });

  it('keeps selection and ranks stable when candidate input order changes', () => {
    const decisions = {
      newest: runDecision({
        releaseTag: 'v2026.7.4',
        releaseScore: 7.8,
        selectedTag: 'v2026.7.4',
        selectedScore: 7.8,
        highestScoringTag: 'v2026.7.3',
        highestScore: 8.3,
        selected: true,
        recencyRank: 1,
        scoreRank: 2,
        decisionCode: 'newest_within_confidence_tolerance',
      }),
      older: runDecision({
        releaseTag: 'v2026.7.3',
        releaseScore: 8.3,
        selectedTag: 'v2026.7.4',
        selectedScore: 7.8,
        highestScoringTag: 'v2026.7.3',
        highestScore: 8.3,
        selected: false,
        recencyRank: 2,
        scoreRank: 1,
        decisionCode: 'newer_release_within_tolerance_selected',
      }),
    };
    const rows = [
      {
        tag: 'v2026.7.3',
        publishedAt: '2026-07-03T00:00:00Z',
        status: 'eligible',
        score: 8.3,
        recommended: false,
        componentsDecision: decisions.older,
        explanationDecision: structuredClone(decisions.older),
      },
      {
        tag: 'v2026.7.4',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'eligible',
        score: 7.8,
        recommended: true,
        componentsDecision: decisions.newest,
        explanationDecision: structuredClone(decisions.newest),
      },
    ];

    assert.deepEqual(validateRecommendationDecisionRun({
      rows,
      expectedSelectedTag: 'v2026.7.4',
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    }), []);
    assert.deepEqual(validateRecommendationDecisionRun({
      rows: rows.slice().reverse(),
      expectedSelectedTag: 'v2026.7.4',
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    }), []);
  });

  it('recomputes selection from the declared threshold and recency tolerance', () => {
    const newest = validDecision({
      threshold: 8,
      recencyTolerance: 0.1,
      selectedTag: 'v-old',
      selectedScore: 8,
      highestScoringTag: 'v-old',
      highestScore: 8,
      releaseTag: 'v-new',
      releaseScore: 7.9,
      qualifies: false,
      selected: false,
      recencyRank: 1,
      scoreRank: 2,
      scoreDeltaToHighest: 0.1,
      decisionCode: 'below_recommendation_threshold',
    });
    const oldest = validDecision({
      threshold: 8,
      recencyTolerance: 0.1,
      selectedTag: 'v-old',
      selectedScore: 8,
      highestScoringTag: 'v-old',
      highestScore: 8,
      releaseTag: 'v-old',
      releaseScore: 8,
      qualifies: true,
      selected: true,
      recencyRank: 2,
      scoreRank: 1,
      scoreDeltaToHighest: 0,
      decisionCode: 'highest_confidence',
    });

    assert.deepEqual(validateRecommendationDecisionRun({
      rows: [
        {
          tag: 'v-new',
          publishedAt: '2026-07-04T00:00:00Z',
          status: 'eligible',
          score: 7.9,
          recommended: false,
          componentsDecision: newest,
          explanationDecision: structuredClone(newest),
        },
        {
          tag: 'v-old',
          publishedAt: '2026-07-03T00:00:00Z',
          status: 'eligible',
          score: 8,
          recommended: true,
          componentsDecision: oldest,
          explanationDecision: structuredClone(oldest),
        },
      ],
      expectedSelectedTag: 'v-old',
      expectedThreshold: 8,
      expectedRecencyTolerance: 0.1,
    }), []);
  });

  it('rejects missing recency provenance, unknown statuses, and undefined nulls', () => {
    const gated = validDecision({
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
      releaseScore: null,
      qualifies: false,
      selected: false,
      scoreRank: null,
      scoreDeltaToHighest: null,
      decisionCode: 'install_gate_active',
    });
    const missingPublishedAt = validateRecommendationDecisionRun({
      rows: [{
        tag: 'v-test',
        publishedAt: undefined as unknown as string,
        status: 'wait',
        score: null,
        recommended: false,
        componentsDecision: gated,
        explanationDecision: structuredClone(gated),
      }],
      expectedSelectedTag: null,
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    });
    assert.ok(missingPublishedAt.some((failure) =>
      /publishedAt must be a valid timestamp/.test(failure)));

    const unknownStatus = validateRecommendationDecisionRun({
      rows: [{
        tag: 'v-test',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'unknown',
        score: null,
        recommended: false,
        componentsDecision: gated,
        explanationDecision: structuredClone(gated),
      }],
      expectedSelectedTag: null,
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    });
    assert.ok(unknownStatus.some((failure) =>
      /status must be a known install status/.test(failure)));

    const undefinedSelectedTag = structuredClone(gated) as unknown as
      Record<string, unknown>;
    undefinedSelectedTag.selectedTag = undefined;
    assert.ok(validateRecommendationDecisionCopies({
      tag: 'v-test',
      componentsDecision: undefinedSelectedTag,
      explanationDecision: structuredClone(undefinedSelectedTag),
      expectedStatus: 'wait',
      expectedScore: null,
      expectedSelected: false,
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    }).some((failure) =>
      /selectedTag must be a non-empty string or null/.test(failure)));
  });

  it('makes install-gate summaries self-contained', () => {
    const wait = validDecision({
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
      releaseScore: null,
      qualifies: false,
      selected: false,
      scoreRank: null,
      scoreDeltaToHighest: null,
      decisionCode: 'install_gate_active',
    });
    const skipped = validDecision({
      selectedTag: null,
      selectedScore: null,
      highestScoringTag: null,
      highestScore: null,
      releaseScore: 4.2,
      qualifies: false,
      selected: false,
      scoreRank: null,
      scoreDeltaToHighest: null,
      decisionCode: 'install_gate_active',
    });

    assert.match(wait.summary, /settle-time eligibility has not been established/);
    assert.match(skipped.summary, /security-advisory or rapid-hotfix install gate/);
    assert.doesNotMatch(wait.summary, /because an install gate is active/);
    assert.doesNotMatch(skipped.summary, /because an install gate is active/);
  });

  it('accepts zero-recommendation runs when every release is subthreshold or gated', () => {
    const rows = [
      {
        tag: 'v-new',
        publishedAt: '2026-07-04T00:00:00Z',
        status: 'eligible',
        score: 6.9,
        decision: validDecision({
          selectedTag: null,
          selectedScore: null,
          highestScoringTag: null,
          highestScore: null,
          releaseTag: 'v-new',
          releaseScore: 6.9,
          qualifies: false,
          selected: false,
          recencyRank: 1,
          scoreRank: 1,
          scoreDeltaToHighest: null,
          decisionCode: 'below_recommendation_threshold',
        }),
      },
      {
        tag: 'v-wait',
        publishedAt: '2026-07-03T00:00:00Z',
        status: 'wait',
        score: null,
        decision: validDecision({
          selectedTag: null,
          selectedScore: null,
          highestScoringTag: null,
          highestScore: null,
          releaseTag: 'v-wait',
          releaseScore: null,
          qualifies: false,
          selected: false,
          recencyRank: 2,
          scoreRank: null,
          scoreDeltaToHighest: null,
          decisionCode: 'install_gate_active',
        }),
      },
      {
        tag: 'v-skip',
        publishedAt: '2026-07-02T00:00:00Z',
        status: 'skip-cve',
        score: 4.2,
        decision: validDecision({
          selectedTag: null,
          selectedScore: null,
          highestScoringTag: null,
          highestScore: null,
          releaseTag: 'v-skip',
          releaseScore: 4.2,
          qualifies: false,
          selected: false,
          recencyRank: 3,
          scoreRank: null,
          scoreDeltaToHighest: null,
          decisionCode: 'install_gate_active',
        }),
      },
    ];
    for (const row of rows) {
      row.decision.summary = recommendationDecisionSummary(row.decision);
    }

    assert.deepEqual(validateRecommendationDecisionRun({
      rows: rows.map((row) => ({
        tag: row.tag,
        publishedAt: row.publishedAt,
        status: row.status,
        score: row.score,
        recommended: false,
        componentsDecision: row.decision,
        explanationDecision: structuredClone(row.decision),
      })),
      expectedSelectedTag: null,
      expectedThreshold: 7,
      expectedRecencyTolerance: 0.5,
    }), []);
  });
});
