import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import {
  canonicalJson,
  operationAttemptConfigHash,
  operationAttemptContentHash,
  operationCaptureReceiptContentHash,
  operationStageEventContentHash,
  type OperationAttemptLedgerRow,
  type OperationCaptureReceiptLedgerRow,
  type OperationStageEventLedgerRow,
} from './operationReceipts';
import {
  buildReleaseValidationOpportunityDenominatorLedger,
  planReleaseValidationOpportunityReconciliation,
  planReleaseValidationOpportunityEnrollments,
  releaseValidationCatalogMemberContentHash,
  releaseValidationOpportunityDenominatorContentHash,
  releaseValidationOpportunityObligationContentHash,
  releaseValidationOpportunityDenominatorCoverage,
  releaseValidationOpportunityEnrollmentContentHash,
  releaseValidationOpportunityId,
  releaseValidationReleaseSplitAssignmentContentHash,
  sealReleaseValidationCatalogSnapshot,
  validateReleaseValidationOpportunityEnrollmentLedger,
  validationCohortKey,
  type ReleaseValidationCatalogMember,
  type ReleaseValidationCatalogSnapshot,
  type ReleaseValidationForecastForDenominator,
  type ReleaseValidationOpportunityReconciliationPlan,
  type ReleaseValidationOpportunityEnrollmentRow,
} from './releaseValidationOpportunityDenominator';

const publishedAt = '2026-07-01T00:00:00.000Z';
const modelVersion = 'model-current';
const promptVersion = 8;
const codeRevision = 'revision-current';
const root = join(import.meta.dirname, '..', '..');
const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;

describe('complete catalog opportunity reconciliation planner', () => {
  it('uses complete catalog cardinality and repairs adversarial obligation omission', () => {
    const catalog = [
      catalogMember('release-a', 0, '2026-07-10T00:00:00.000Z'),
      catalogMember('release-b', 1, '2026-07-11T00:00:00.000Z'),
      catalogMember('release-c', 2, '2026-07-12T00:00:00.000Z'),
    ];
    const initial = reconciliationPlan({
      plannedAt: '2026-07-12T01:00:00.000Z',
      catalog,
      developmentReleaseCount: 1,
    });
    assert.equal(initial.rowCount, 6);
    assert.equal(initial.expectedRowCount, 6);
    assert.equal(initial.blocked, false, initial.errors.join('\n'));
    assert.equal(initial.obligations.length, 6);
    assert.equal(
      new Set(initial.obligations.map((row) => row.obligationId)).size,
      6,
    );
    assert.ok(initial.obligations.every((row) =>
      /^[0-9a-f]{64}$/.test(row.contentHash)));
    assert.ok(initial.splitAssignments.every((row) =>
      /^[0-9a-f]{64}$/.test(row.contentHash)));

    const persistedObligation = initial.obligations[0];
    const persistedSplit = initial.splitAssignments.find((row) =>
      row.releaseIdentity === persistedObligation.releaseIdentity)!;
    const reconciled = reconciliationPlan({
      plannedAt: '2026-07-12T01:00:00.000Z',
      catalog,
      developmentReleaseCount: 1,
      existingObligations: [persistedObligation],
      existingSplitAssignments: [persistedSplit],
    });
    assert.equal(reconciled.rowCount, 6);
    assert.equal(reconciled.obligations.length, 6);
    assert.equal(reconciled.obligationsToPersist.length, 5);
    assert.equal(
      reconciled.rows.filter((row) => row.persistedObligation).length,
      1,
    );
    assert.equal(
      reconciled.rows.filter((row) => row.actionCode === 'create_obligation')
        .length,
      5,
    );

    const incomplete = planReleaseValidationOpportunityReconciliation({
      plannedAt: '2026-07-12T01:00:00.000Z',
      cohort: reconciliationCohort(),
      catalog: {
        complete: false,
        snapshots: catalogHistory(
          '2026-07-12T01:00:00.000Z',
          [catalog[0]],
        ),
      },
    });
    assert.equal(incomplete.rowCount, 2);
    assert.ok(incomplete.rows.every((row) =>
      row.eligibilityCode === 'planner_error' &&
      row.actionCode === 'block'));
    assert.deepEqual(incomplete.obligationsToPersist, []);
    assert.deepEqual(incomplete.splitAssignmentsToPersist, []);
  });

  it('emits every malformed or excluded cell but exposes no writes when mixed input blocks', () => {
    const opportunity = [{
      code: 'verification',
      minAgeHours: 3,
      maxAgeHours: 6,
    }];
    const catalog: ReleaseValidationCatalogMember[] = [
      catalogMember('eligible', 0, '2026-07-10T08:00:00.000Z'),
      catalogMember('outside', 1, '2026-07-10T08:00:00.000Z', {
        inScope: false,
      }),
      catalogMember('draft', 2, '2026-07-10T08:00:00.000Z', {
        draft: true,
      }),
      catalogMember('prerelease', 3, '2026-07-10T08:00:00.000Z', {
        prerelease: true,
      }),
      catalogMember('pre-inception', 4, '2026-06-30T00:00:00.000Z', {
        firstSeenAt: '2026-07-01T00:05:00.000Z',
      }),
      catalogMember('retired', 5, '2026-07-10T08:00:00.000Z', {
        retiredAt: '2026-07-10T10:00:00.000Z',
      }),
      catalogMember('closed', 6, '2026-07-10T00:00:00.000Z'),
      catalogMember('missing', 7, '2026-07-10T08:00:00.000Z', {
        nodeId: null,
      }),
      catalogMember('malformed', 8, '2026-07-10T08:00:00.000Z', {
        publishedAt: 'not-a-timestamp',
      }),
    ];
    const plan = reconciliationPlan({
      plannedAt: '2026-07-10T12:00:00.000Z',
      catalog,
      opportunities: opportunity,
    });
    assert.equal(plan.expectedRowCount, catalog.length);
    assert.equal(plan.rowCount, catalog.length);
    assert.deepEqual(
      plan.rows.map((row) => row.eligibilityCode),
      [
        'eligible',
        'outside_scope',
        'draft',
        'prerelease',
        'pre_inception',
        'retired_before_open',
        'window_closed',
        'missing_identity',
        'planner_error',
      ],
    );
    const missing = plan.rows.find((row) =>
      row.catalogMemberId === 'member-missing')!;
    assert.equal(missing.releaseIdentity, null);
    assert.equal(missing.actionCode, 'block');
    assert.equal(missing.blocking, true);
    assert.equal(
      plan.rows.find((row) => row.catalogMemberId === 'member-eligible')
        ?.actionCode,
      'create_obligation',
    );
    assert.equal(plan.blocked, true);
    assert.deepEqual(plan.obligations, []);
    assert.deepEqual(plan.obligationsToPersist, []);
    assert.deepEqual(plan.splitAssignments, []);
    assert.deepEqual(plan.splitAssignmentsToPersist, []);
  });

  it('blocks duplicate identities and reused tags without dropping catalog rows', () => {
    const duplicate = catalogMember(
      'duplicate-a',
      0,
      '2026-07-10T00:00:00.000Z',
    );
    const catalog = [
      duplicate,
      catalogMember('duplicate-b', 1, '2026-07-10T00:00:00.000Z', {
        nodeId: duplicate.nodeId,
        tag: duplicate.tag,
        tagCommitOid: duplicate.tagCommitOid,
      }),
      catalogMember('tag-a', 2, '2026-07-11T00:00:00.000Z', {
        tag: 'v-reused',
      }),
      catalogMember('tag-b', 3, '2026-07-12T00:00:00.000Z', {
        tag: 'v-reused',
      }),
    ];
    const plan = reconciliationPlan({
      plannedAt: '2026-07-12T01:00:00.000Z',
      catalog,
    });
    assert.equal(plan.rowCount, 8);
    assert.equal(
      plan.rows.filter((row) =>
        row.eligibilityCode === 'duplicate_identity').length,
      4,
    );
    assert.equal(
      plan.rows.filter((row) =>
        row.eligibilityCode === 'tag_reuse_conflict').length,
      4,
    );
    assert.equal(plan.blockingRowCount, 8);
    assert.equal(plan.obligations.length, 0);
    assert.deepEqual(plan.obligationsToPersist, []);
    assert.deepEqual(plan.splitAssignmentsToPersist, []);
  });

  it('creates late_missed obligations for releases first admitted after close', () => {
    const catalog = [
      catalogMember('late', 0, '2026-07-10T00:00:00.000Z', {
        firstSeenAt: '2026-07-11T07:00:00.000Z',
      }),
    ];
    const plan = reconciliationPlan({
      plannedAt: '2026-07-11T07:00:00.000Z',
      catalog,
    });
    assert.equal(plan.rowCount, 2);
    assert.equal(plan.blocked, false, plan.errors.join('\n'));
    assert.ok(plan.rows.every((row) =>
      row.eligibilityCode === 'window_closed' &&
      row.actionCode === 'create_late_missed_obligation' &&
      row.obligationKind === 'late_missed'));
    assert.ok(plan.obligations.every((row) => row.kind === 'late_missed'));
  });

  it('assigns splits by authenticated first-seen order, not publication or outcomes', () => {
    const initialCatalog = [
      catalogMember('published-older', 0, '2026-07-09T00:00:00.000Z', {
        firstSeenAt: '2026-07-10T13:00:00.000Z',
      }),
      catalogMember('published-newer', 1, '2026-07-10T12:00:00.000Z', {
        firstSeenAt: '2026-07-10T12:05:00.000Z',
      }),
    ];
    const initialSnapshots = catalogHistory(
      '2026-07-11T01:00:00.000Z',
      initialCatalog,
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-11T01:00:00.000Z',
      catalog: initialCatalog,
      catalogSnapshots: initialSnapshots,
      developmentReleaseCount: 1,
    });
    assert.deepEqual(
      initial.splitAssignments.map((row) => [
        row.catalogMemberId,
        row.admissionOrdinal,
        row.split,
      ]),
      [
        ['member-published-newer', 1, 'development'],
        ['member-published-older', 2, 'holdout'],
      ],
    );

    const appendedCatalog = [
      ...initialCatalog,
      catalogMember('late-old-release', 2, '2026-07-08T00:00:00.000Z', {
        firstSeenAt: '2026-07-12T00:00:00.000Z',
      }),
    ];
    const appendedSnapshots = extendCatalogHistory(
      initialSnapshots,
      '2026-07-12T01:00:00.000Z',
      appendedCatalog,
    );
    const appendedInput = {
      plannedAt: '2026-07-12T01:00:00.000Z',
      cohort: reconciliationCohort(),
      catalog: { complete: true, snapshots: appendedSnapshots },
      policy: { developmentReleaseCount: 1 },
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
      outcomes: [{ releaseTag: 'v-later', adverse: true }],
    } as Parameters<
      typeof planReleaseValidationOpportunityReconciliation
    >[0];
    const appended = planReleaseValidationOpportunityReconciliation(
      appendedInput,
    );
    const withoutOutcomes = planReleaseValidationOpportunityReconciliation({
      plannedAt: appendedInput.plannedAt,
      cohort: appendedInput.cohort,
      catalog: appendedInput.catalog,
      policy: appendedInput.policy,
      existingObligations: appendedInput.existingObligations,
      existingSplitAssignments: appendedInput.existingSplitAssignments,
    });
    assert.equal(appended.contentHash, withoutOutcomes.contentHash);
    assert.deepEqual(
      appended.splitAssignments.map((row) => [
        row.catalogMemberId,
        row.admissionOrdinal,
        row.split,
      ]),
      [
        ['member-published-newer', 1, 'development'],
        ['member-published-older', 2, 'holdout'],
        ['member-late-old-release', 3, 'holdout'],
      ],
    );
  });

  it('blocks repair when an omitted earlier admission would rewrite persisted ordinals', () => {
    const catalog = [
      catalogMember('admitted-first', 0, '2026-07-10T00:00:00.000Z'),
      catalogMember('admitted-second', 1, '2026-07-10T01:00:00.000Z'),
    ];
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T02:00:00.000Z',
      catalog,
      developmentReleaseCount: 1,
    });
    const secondSplit = initial.splitAssignments.find((row) =>
      row.catalogMemberId === 'member-admitted-second')!;
    const secondObligations = initial.obligations.filter((row) =>
      row.catalogMemberId === 'member-admitted-second');
    const {
      contentHash: _secondSplitContentHash,
      ...secondSplitHashInput
    } = secondSplit;
    const shiftedSplit = {
      ...secondSplitHashInput,
      split: 'development' as const,
      admissionOrdinal: 1,
    };
    const repaired = reconciliationPlan({
      plannedAt: '2026-07-10T02:00:00.000Z',
      catalog,
      developmentReleaseCount: 1,
      existingObligations: secondObligations.map((obligation) => {
        const shifted = {
          ...obligation,
          split: 'development' as const,
        };
        const {
          contentHash: _contentHash,
          ...hashInput
        } = shifted;
        return {
          ...shifted,
          contentHash:
            releaseValidationOpportunityObligationContentHash(hashInput),
        };
      }),
      existingSplitAssignments: [{
        ...shiftedSplit,
        contentHash:
          releaseValidationReleaseSplitAssignmentContentHash(shiftedSplit),
      }],
    });
    assert.equal(repaired.blocked, true);
    assert.match(
      repaired.errors.join('\n'),
      /authenticated first-seen admission order/,
    );
    assert.deepEqual(repaired.obligationsToPersist, []);
    assert.deepEqual(repaired.splitAssignmentsToPersist, []);
  });

  it('rejects rewritten persisted obligations and splits even with recomputed hashes', () => {
    const member = catalogMember(
      'immutable',
      0,
      '2026-07-10T00:00:00.000Z',
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [member],
      developmentReleaseCount: 1,
    });
    const obligation = structuredClone(initial.obligations[0]);
    obligation.releaseTag = 'v-rewritten';
    const {
      contentHash: _obligationContentHash,
      ...obligationHashInput
    } = obligation;
    obligation.contentHash =
      releaseValidationOpportunityObligationContentHash(obligationHashInput);
    const obligationRewrite = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [member],
      developmentReleaseCount: 1,
      existingObligations: [obligation],
      existingSplitAssignments: [initial.splitAssignments[0]],
    });
    assert.equal(obligationRewrite.blocked, true);
    assert.match(
      obligationRewrite.errors.join('\n'),
      /Invalid persisted release validation obligation/,
    );
    assert.deepEqual(obligationRewrite.obligationsToPersist, []);
    assert.deepEqual(obligationRewrite.splitAssignmentsToPersist, []);

    const split = structuredClone(initial.splitAssignments[0]);
    split.assignedAt = '2026-07-10T00:06:00.000Z';
    const { contentHash: _splitContentHash, ...splitHashInput } = split;
    split.contentHash =
      releaseValidationReleaseSplitAssignmentContentHash(splitHashInput);
    const splitRewrite = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [member],
      developmentReleaseCount: 1,
      existingObligations: initial.obligations,
      existingSplitAssignments: [split],
    });
    assert.equal(splitRewrite.blocked, true);
    assert.match(
      splitRewrite.errors.join('\n'),
      /Invalid persisted release validation split/,
    );
    assert.deepEqual(splitRewrite.obligationsToPersist, []);
    assert.deepEqual(splitRewrite.splitAssignmentsToPersist, []);
  });

  it('uses injective cohort hashes bound to policy, inception, and retirement', () => {
    const collisionA = validationCohortKey({
      modelVersion: 'a',
      promptVersion: 1,
      codeRevision: 'x/prompt-2/revision-y',
    });
    const collisionB = validationCohortKey({
      modelVersion: 'a/prompt-1/revision-x',
      promptVersion: 2,
      codeRevision: 'y',
    });
    assert.notEqual(collisionA, collisionB);
    assert.notEqual(
      validationCohortKey({
        modelVersion,
        promptVersion,
        codeRevision,
        inceptionAt: '2026-07-01T00:00:00.000Z',
        retiredAt: null,
        policyHash: 'a'.repeat(64),
      }),
      validationCohortKey({
        modelVersion,
        promptVersion,
        codeRevision,
        inceptionAt: '2026-07-01T00:00:00.001Z',
        retiredAt: null,
        policyHash: 'a'.repeat(64),
      }),
    );
    assert.notEqual(
      validationCohortKey({
        modelVersion,
        promptVersion,
        codeRevision,
        inceptionAt: '2026-07-01T00:00:00.000Z',
        retiredAt: null,
        policyHash: 'a'.repeat(64),
      }),
      validationCohortKey({
        modelVersion,
        promptVersion,
        codeRevision,
        inceptionAt: '2026-07-01T00:00:00.000Z',
        retiredAt: '2026-07-31T00:00:00.000Z',
        policyHash: 'b'.repeat(64),
      }),
    );

    const member = catalogMember(
      'policy-bound',
      0,
      '2026-07-10T00:00:00.000Z',
    );
    const snapshots = catalogHistory(
      '2026-07-10T01:00:00.000Z',
      [member],
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [member],
      catalogSnapshots: snapshots,
      developmentReleaseCount: 1,
    });
    const changedPolicy = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [member],
      catalogSnapshots: snapshots,
      developmentReleaseCount: 0,
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.notEqual(changedPolicy.cohortKey, initial.cohortKey);
    assert.equal(changedPolicy.blocked, true);
    assert.deepEqual(changedPolicy.obligationsToPersist, []);
    assert.deepEqual(changedPolicy.splitAssignmentsToPersist, []);
  });

  it('requires inception-rooted append-only history and cannot hide prior obligations', () => {
    const first = catalogMember('history-a', 0, '2026-07-10T00:00:00.000Z');
    const second = catalogMember('history-b', 1, '2026-07-10T01:00:00.000Z');
    const initialSnapshots = catalogHistory(
      '2026-07-10T02:00:00.000Z',
      [first, second],
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T02:00:00.000Z',
      catalog: [first, second],
      catalogSnapshots: initialSnapshots,
    });
    const currentOnly = sealReleaseValidationCatalogSnapshot({
      source: 'github-release-catalog',
      sequence: 1,
      observedAt: '2026-07-10T03:00:00.000Z',
      previousContentHash: null,
      members: [first, second],
    });
    const currentOnlyPlan = reconciliationPlan({
      plannedAt: '2026-07-10T03:00:00.000Z',
      catalog: [first, second],
      catalogSnapshots: [currentOnly],
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(currentOnlyPlan.blocked, true);
    assert.match(
      currentOnlyPlan.errors.join('\n'),
      /not rooted at cohort inception/,
    );

    const hiddenHistory = extendCatalogHistory(
      initialSnapshots,
      '2026-07-10T03:00:00.000Z',
      [first],
    );
    const hidden = reconciliationPlan({
      plannedAt: '2026-07-10T03:00:00.000Z',
      catalog: [first],
      catalogSnapshots: hiddenHistory,
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(hidden.blocked, true);
    assert.match(hidden.errors.join('\n'), /does not retain prior catalog member/);
    assert.deepEqual(hidden.obligationsToPersist, []);
    assert.deepEqual(hidden.splitAssignmentsToPersist, []);

    const emptied = reconciliationPlan({
      plannedAt: '2026-07-10T03:00:00.000Z',
      catalog: [],
      catalogSnapshots: extendCatalogHistory(
        initialSnapshots,
        '2026-07-10T03:00:00.000Z',
        [],
      ),
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(emptied.blocked, true);
    assert.match(emptied.errors.join('\n'), /has no attested members/);
    assert.deepEqual(emptied.obligationsToPersist, []);
    assert.deepEqual(emptied.splitAssignmentsToPersist, []);
  });

  it('detects hidden historical tag reuse after a benign retag', () => {
    const original = catalogMember('tag-owner', 0, '2026-07-10T00:00:00.000Z', {
      tag: 'v-shared-history',
    });
    const initialSnapshots = catalogHistory(
      '2026-07-10T01:00:00.000Z',
      [original],
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [original],
      catalogSnapshots: initialSnapshots,
    });
    const retagged = rehashCatalogMember({
      ...original,
      tag: 'v-tag-owner-new',
    });
    const reused = catalogMember(
      'tag-thief',
      1,
      '2026-07-10T01:30:00.000Z',
      {
        tag: 'v-shared-history',
        firstSeenAt: '2026-07-10T02:00:00.000Z',
      },
    );
    const current = [retagged, reused];
    const plan = reconciliationPlan({
      plannedAt: '2026-07-10T03:00:00.000Z',
      catalog: current,
      catalogSnapshots: extendCatalogHistory(
        initialSnapshots,
        '2026-07-10T03:00:00.000Z',
        current,
      ),
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(plan.blocked, true);
    assert.ok(plan.rows.some((row) =>
      row.catalogMemberId === 'member-tag-thief' &&
      row.eligibilityCode === 'tag_reuse_conflict'));
    assert.deepEqual(plan.obligationsToPersist, []);
    assert.deepEqual(plan.splitAssignmentsToPersist, []);
  });

  it('blocks duplicate member/source identities and keeps reconciliation row IDs unique', () => {
    const first = catalogMember('id-a', 0, '2026-07-10T00:00:00.000Z');
    const second = rehashCatalogMember({
      ...catalogMember('id-b', 1, '2026-07-10T01:00:00.000Z'),
      catalogMemberId: first.catalogMemberId,
      sourceOrder: first.sourceOrder,
    });
    const plan = reconciliationPlan({
      plannedAt: '2026-07-10T02:00:00.000Z',
      catalog: [first, second],
    });
    assert.equal(plan.blocked, true);
    assert.equal(
      new Set(plan.rows.map((row) => row.reconciliationId)).size,
      plan.rows.length,
    );
    assert.ok(plan.rows.every((row) => row.releaseIdentity != null));
    assert.deepEqual(plan.obligationsToPersist, []);
    assert.deepEqual(plan.splitAssignmentsToPersist, []);
  });

  it('rejects altered first-seen provenance and retains sealed obligations through retirement', () => {
    const original = catalogMember(
      'stable',
      0,
      '2026-07-10T00:00:00.000Z',
    );
    const initialSnapshots = catalogHistory(
      '2026-07-10T01:00:00.000Z',
      [original],
    );
    const initial = reconciliationPlan({
      plannedAt: '2026-07-10T01:00:00.000Z',
      catalog: [original],
      catalogSnapshots: initialSnapshots,
      developmentReleaseCount: 1,
    });
    const rewrittenFirstSeen = rehashCatalogMember({
      ...original,
      firstSeenAt: '2026-07-10T00:06:00.000Z',
    });
    const rewritten = reconciliationPlan({
      plannedAt: '2026-07-10T02:30:00.000Z',
      catalog: [rewrittenFirstSeen],
      catalogSnapshots: extendCatalogHistory(
        initialSnapshots,
        '2026-07-10T02:30:00.000Z',
        [rewrittenFirstSeen],
      ),
      developmentReleaseCount: 1,
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(rewritten.blocked, true);
    assert.match(rewritten.errors.join('\n'), /rewrites immutable catalog member/);
    assert.deepEqual(rewritten.obligationsToPersist, []);
    assert.deepEqual(rewritten.splitAssignmentsToPersist, []);

    const retiredAndRetagged = rehashCatalogMember({
      ...original,
      tag: 'v-stable-retagged',
      retiredAt: '2026-07-10T02:00:00.000Z',
    });
    const reconciled = reconciliationPlan({
      plannedAt: '2026-07-10T02:30:00.000Z',
      catalog: [retiredAndRetagged],
      catalogSnapshots: extendCatalogHistory(
        initialSnapshots,
        '2026-07-10T02:30:00.000Z',
        [retiredAndRetagged],
      ),
      developmentReleaseCount: 1,
      existingObligations: initial.obligations,
      existingSplitAssignments: initial.splitAssignments,
    });
    assert.equal(reconciled.blocked, false, reconciled.errors.join('\n'));
    assert.equal(reconciled.obligationsToPersist.length, 0);
    assert.equal(reconciled.obligations.length, 2);
    assert.ok(reconciled.rows.every((row) =>
      row.eligibilityCode === 'retired_before_open' &&
      row.actionCode === 'retain_obligation' &&
      row.split === 'development'));
    assert.deepEqual(
      reconciled.obligations.map((row) => row.obligationId),
      initial.obligations.map((row) => row.obligationId),
    );
  });
});

describe('prospective release validation opportunity denominator', () => {
  it('enrolls only slots whose close is still prospective', () => {
    assert.deepEqual(
      plan('2026-07-01T04:00:00.000Z').map((row) => row.opportunity_code),
      ['first_verified_after_3h', 'first_verified_after_24h'],
    );
    assert.deepEqual(
      plan('2026-07-02T01:00:00.000Z').map((row) => row.opportunity_code),
      ['first_verified_after_24h'],
    );
    assert.deepEqual(
      plan('2026-07-02T06:00:00.000Z').map((row) => row.opportunity_code),
      [],
    );
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-03T00:00:00.000Z',
      enrollments: rows(plan('2026-07-02T06:00:00.000Z')),
      forecasts: [],
    });
    assert.equal(ledger.rowCount, 0);
    assert.equal(ledger.counts.missed, 0);
  });

  it('records late-discovered closed slots without backfilling pre-cohort releases', () => {
    const late = plan(
      '2026-07-02T06:00:00.000Z',
      'a'.repeat(64),
      '2026-07-01T00:00:00.000Z',
    );
    assert.deepEqual(
      late.map((row) => [row.opportunity_code, row.enrollment_kind]),
      [
        ['first_verified_after_3h', 'late_discovery_missed'],
        ['first_verified_after_24h', 'late_discovery_missed'],
      ],
    );
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-02T06:00:00.000Z',
      enrollments: rows(late),
      forecasts: [],
    });
    assert.equal(
      ledger.integrity.valid,
      true,
      ledger.integrity.errors.join('\n'),
    );
    assert.equal(ledger.counts.missed, 2);
    assert.ok(ledger.rows.every((row) => row.terminal));

    assert.deepEqual(
      plan(
        '2026-07-02T06:00:00.000Z',
        'a'.repeat(64),
        '2026-07-01T01:00:00.000Z',
      ),
      [],
    );
  });

  it('detects immutable enrollment identity, chain, and evidence hash tampering', () => {
    const enrolled = rows(plan('2026-07-01T01:00:00.000Z'));
    assert.deepEqual(
      validateReleaseValidationOpportunityEnrollmentLedger(enrolled),
      { valid: true, errors: [] },
    );
    const tampered = structuredClone(enrolled);
    tampered[0].catalog_digest = 'f'.repeat(64);
    const report = validateReleaseValidationOpportunityEnrollmentLedger(tampered);
    assert.equal(report.valid, false);
    assert.match(report.errors.join('\n'), /content hash mismatch/);

    const brokenChain = structuredClone(enrolled);
    brokenChain[1].previous_content_hash = null;
    assert.match(
      validateReleaseValidationOpportunityEnrollmentLedger(brokenChain)
        .errors.join('\n'),
      /previous content hash mismatch/,
    );

    const duplicate = structuredClone(enrolled);
    duplicate[1] = {
      ...structuredClone(duplicate[0]),
      id: 2,
      previous_content_hash: duplicate[0].content_hash,
      content_hash: '',
    };
    duplicate[1].content_hash = releaseValidationOpportunityEnrollmentContentHash({
      ...duplicate[1],
      previous_content_hash: duplicate[1].previous_content_hash,
    });
    const duplicateReport =
      validateReleaseValidationOpportunityEnrollmentLedger(duplicate);
    assert.equal(duplicateReport.valid, false);
    assert.match(
      duplicateReport.errors.join('\n'),
      /Duplicate validation opportunity enrollment identity/,
    );
    assert.match(
      duplicateReport.errors.join('\n'),
      /Duplicate validation opportunity ID/,
    );
  });

  it('reports denominator attrition without reconstructing missed forecasts', () => {
    const late = rows(plan(
      '2026-07-02T06:00:00.000Z',
      'a'.repeat(64),
      '2026-07-01T00:00:00.000Z',
    ));
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-03T00:00:00.000Z',
      enrollments: late,
      forecasts: [],
    });
    const errors: string[] = [];
    const coverage = releaseValidationOpportunityDenominatorCoverage({
      ledger,
      forecasts: [],
      currentModelVersion: modelVersion,
      currentPromptVersion: promptVersion,
      currentCodeRevision: codeRevision,
      errors,
    });
    assert.equal(coverage.valid, true);
    assert.equal(coverage.ready, true);
    assert.equal(coverage.capturedCount, 0);
    assert.equal(coverage.missedCount, 2);
    assert.equal(coverage.terminalCount, 2);
    assert.deepEqual(errors, []);

    const rehashed = structuredClone(ledger);
    rehashed.counts.missed = 0;
    const { contentHash: _contentHash, ...ledgerWithoutHash } = rehashed;
    rehashed.contentHash =
      releaseValidationOpportunityDenominatorContentHash(ledgerWithoutHash);
    const rejected = releaseValidationOpportunityDenominatorCoverage({
      ledger: rehashed,
      forecasts: [],
      currentModelVersion: modelVersion,
      currentPromptVersion: promptVersion,
      currentCodeRevision: codeRevision,
    });
    assert.equal(rejected.valid, false);
    assert.match(rejected.errors.join('\n'), /missed count does not match/);
  });

  it('rejects conflicting duplicate forecasts for one enrolled opportunity', () => {
    const enrolled = rows(plan('2026-07-01T01:00:00.000Z'))
      .filter((row) => row.opportunity_code === 'first_verified_after_3h');
    const first = forecastRow();
    const second = {
      ...forecastRow(),
      decision_id: 'decision-3h-conflict',
      content_hash: 'd'.repeat(64),
    };
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T05:00:00.000Z',
      enrollments: enrolled,
      forecasts: [first, second],
    });
    assert.equal(ledger.integrity.valid, false);
    assert.match(
      ledger.integrity.errors.join('\n'),
      /has multiple prospective forecasts/,
    );
  });

  it('reconciles a verified success receipt to exactly one enrolled forecast', () => {
    const attempt = operationAttempt();
    const enrolled = rows(plan('2026-07-01T01:00:00.000Z', attempt.content_hash))
      .filter((row) => row.opportunity_code === 'first_verified_after_3h');
    const forecast = forecastRow();
    const operation = successOperation(attempt, enrolled[0], forecast);
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T05:00:00.000Z',
      enrollments: enrolled,
      forecasts: [forecast],
      operationLedger: {
        attempts: [attempt],
        stageEvents: operation.stageEvents,
        receipts: [operation.receipt],
        auditHistory: [{
          run_id: 'history-run',
          recorded_at: forecast.recorded_at,
          score_model_version: modelVersion,
          prompt_version: promptVersion,
        }],
      },
    });
    assert.equal(
      ledger.integrity.valid,
      true,
      ledger.integrity.errors.join('\n'),
    );
    assert.equal(ledger.rows[0].disposition, 'captured');
    assert.equal(ledger.rows[0].capturedDecisionId, forecast.decision_id);
    assert.equal(ledger.rows[0].successEvidence.length, 1);

    const wrongCapture = structuredClone(operation.receipt);
    const payload = JSON.parse(wrongCapture.payload_json);
    payload.forecast.captures[0].enrollmentContentHash = 'f'.repeat(64);
    wrongCapture.payload_json = canonicalJson(payload);
    wrongCapture.content_hash = operationCaptureReceiptContentHash({
      receiptId: wrongCapture.receipt_id,
      runId: wrongCapture.run_id,
      status: wrongCapture.status,
      finishedAt: wrongCapture.finished_at,
      durationMs: wrongCapture.duration_ms,
      stageEventCount: wrongCapture.stage_event_count,
      stageChainHash: wrongCapture.stage_chain_hash,
      payloadJson: wrongCapture.payload_json,
      previousContentHash: wrongCapture.previous_content_hash,
    });
    const rejected = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T05:00:00.000Z',
      enrollments: enrolled,
      forecasts: [forecast],
      operationLedger: {
        attempts: [attempt],
        stageEvents: operation.stageEvents,
        receipts: [wrongCapture],
        auditHistory: [{
          run_id: 'history-run',
          recorded_at: forecast.recorded_at,
          score_model_version: modelVersion,
          prompt_version: promptVersion,
        }],
      },
    });
    assert.equal(rejected.integrity.valid, false);
    assert.match(rejected.integrity.errors.join('\n'), /unmatched forecast capture/);
  });

  it('projects denominator evidence at asOf before forecast and receipt reconciliation', () => {
    const attempt = operationAttempt();
    const enrolled = rows(plan('2026-07-01T01:00:00.000Z', attempt.content_hash))
      .filter((row) => row.opportunity_code === 'first_verified_after_3h');
    const forecast = forecastRow();
    const operation = successOperation(attempt, enrolled[0], forecast);
    const operationLedger = {
      attempts: [attempt],
      stageEvents: operation.stageEvents,
      receipts: [operation.receipt],
      leases: [],
      auditHistory: [{
        run_id: 'history-run',
        recorded_at: forecast.recorded_at,
        score_model_version: modelVersion,
        prompt_version: promptVersion,
      }],
    };

    const historical = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T03:59:59.500Z',
      enrollments: enrolled,
      forecasts: [forecast],
      operationLedger,
    });
    assert.equal(historical.rowCount, 1);
    assert.equal(historical.rows[0].disposition, 'eligible');
    assert.equal(historical.rows[0].capturedDecisionId, null);
    assert.deepEqual(historical.rows[0].successEvidence, []);
    assert.equal(historical.integrity.operationReceiptLedgerVerified, false);
    assert.match(
      historical.integrity.errors.join('\n'),
      /unterminated operation attempt/,
    );

    const captured = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: operation.receipt.finished_at,
      enrollments: enrolled,
      forecasts: [forecast],
      operationLedger,
    });
    assert.equal(
      captured.integrity.valid,
      true,
      captured.integrity.errors.join('\n'),
    );
    assert.equal(captured.rows[0].disposition, 'captured');
    assert.equal(captured.rows[0].capturedDecisionId, forecast.decision_id);
    assert.equal(captured.rows[0].successEvidence.length, 1);
  });

  it('excludes future enrollments and fails closed on unplaceable timestamps', () => {
    const futureEnrollments = rows(plan('2026-07-01T04:00:00.000Z'));
    const historical = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T03:59:59.999Z',
      enrollments: futureEnrollments,
      forecasts: [],
    });
    assert.equal(historical.rowCount, 0);
    assert.equal(historical.integrity.valid, true);

    assert.throws(
      () => buildReleaseValidationOpportunityDenominatorLedger({
        asOf: '2026-07-01T05:00:00.000Z',
        enrollments: futureEnrollments,
        forecasts: [{
          ...forecastRow(),
          recorded_at: 'not-a-timestamp',
        }],
      }),
      /validation forecast 1 authoritative timestamp must be a valid timestamp/,
    );
  });

  it('uses only hash-verified failure receipts and fails closed on corruption', () => {
    const attempt = operationAttempt();
    const enrolled = rows(plan('2026-07-01T01:00:00.000Z', attempt.content_hash))
      .filter((row) => row.opportunity_code === 'first_verified_after_3h');
    const operation = failedOperation(attempt, enrolled[0]);
    const ledger = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T05:00:00.000Z',
      enrollments: enrolled,
      forecasts: [],
      operationLedger: {
        attempts: [attempt],
        stageEvents: operation.stageEvents,
        receipts: [operation.receipt],
        auditHistory: [],
      },
    });
    assert.equal(
      ledger.integrity.valid,
      true,
      ledger.integrity.errors.join('\n'),
    );
    assert.equal(ledger.rows[0].disposition, 'failed');
    assert.equal(ledger.rows[0].failureCount, 1);
    assert.equal(
      ledger.rows[0].failures[0].receiptContentHash,
      operation.receipt.content_hash,
    );

    const corrupted = structuredClone(operation.receipt);
    corrupted.content_hash = '0'.repeat(64);
    const closed = buildReleaseValidationOpportunityDenominatorLedger({
      asOf: '2026-07-01T05:00:00.000Z',
      enrollments: enrolled,
      forecasts: [],
      operationLedger: {
        attempts: [attempt],
        stageEvents: operation.stageEvents,
        receipts: [corrupted],
        auditHistory: [],
      },
    });
    assert.equal(closed.integrity.valid, false);
    assert.equal(closed.integrity.operationReceiptLedgerVerified, false);
    assert.equal(closed.rows[0].failureCount, 0);
    assert.match(closed.integrity.errors.join('\n'), /content hash mismatch/);
  });

  it('keeps immutable slots after catalog deactivation', async () => {
    const ownedDir = assignedWorkerDatabasePath === null
      ? mkdtempSync(join(tmpdir(), 'radar-denominator-db-'))
      : null;
    const path = assignedWorkerDatabasePath ??
      join(ownedDir!, 'radar.db');
    const previousDbPath = process.env.DB_PATH;
    if (assignedWorkerDatabasePath) {
      assert.equal(
        process.env.DB_PATH,
        assignedWorkerDatabasePath,
        'release validation denominator tests must use their assigned worker database',
      );
    } else {
      process.env.DB_PATH = path;
    }
    const db = await import(`./db.ts?denominator-${Date.now()}-${Math.random()}`);
    try {
      const nowMs = Date.now();
      const enrolledAt = new Date(nowMs).toISOString();
      const releasePublishedAt = new Date(nowMs - HOUR_MS).toISOString();
      db.replaceActiveReleaseCatalog([{
        node_id: 'node-old',
        catalog_tag_commit_oid: '1'.repeat(40),
        tag: 'v-old',
        name: 'v-old',
        published_at: releasePublishedAt,
        created_at: releasePublishedAt,
        updated_at: releasePublishedAt,
        html_url: 'https://example.test/v-old',
        prerelease: false,
        body: '',
      }]);
      assert.equal(db.acquireRefreshLease(
        'denominator-test',
        'holder',
        enrolledAt,
        300_000,
      ), true);
      const attempt = db.beginRefreshOperationAttempt({
        run_id: 'denominator-run',
        operation: 'refresh',
        trigger: 'test',
        started_at: enrolledAt,
        lease_name: 'denominator-test',
        lease_holder_id: 'holder',
        lease_expires_at: new Date(nowMs + 300_000).toISOString(),
        code_revision: codeRevision,
        effective_config: { schemaVersion: 1 },
      }).attempt.row;
      const catalog = db.currentActiveReleaseCatalog();
      const result = db.insertReleaseValidationOpportunityEnrollments({
        enrollments: planReleaseValidationOpportunityEnrollments({
          enrolledAt,
          release: {
            nodeId: 'node-old',
            tag: 'v-old',
            tagCommitOid: '1'.repeat(40),
            publishedAt: releasePublishedAt,
          },
          cohort: {
            modelVersion,
            promptVersion,
            codeRevision,
          },
          evidence: {
            enrollmentRunId: attempt.run_id,
            operationAttemptContentHash: attempt.content_hash,
            catalogDigest: catalog.digest,
            catalogReleaseCount: catalog.releaseCount,
          },
        }),
        lease_name: 'denominator-test',
        lease_holder_id: 'holder',
      });
      assert.equal(result.insertedCount, 2);
      db.replaceActiveReleaseCatalog([{
        node_id: 'node-new',
        catalog_tag_commit_oid: '2'.repeat(40),
        tag: 'v-new',
        name: 'v-new',
        published_at: enrolledAt,
        created_at: enrolledAt,
        updated_at: enrolledAt,
        html_url: 'https://example.test/v-new',
        prerelease: false,
        body: '',
      }]);
      assert.equal(
        db.listReleaseValidationOpportunityEnrollments().length,
        2,
      );
      assert.equal(db.getRelease('v-old')?.catalog_active, 0);
      assert.throws(
        () => db.db.prepare(`
          DELETE FROM release_validation_opportunity_enrollments
        `).run(),
        /append-only/,
      );
      assert.throws(
        () => db.db.prepare(`
          UPDATE release_validation_opportunity_enrollments
          SET catalog_digest='${'f'.repeat(64)}'
        `).run(),
        /append-only/,
      );
    } finally {
      db.db.close();
      if (assignedWorkerDatabasePath === null) {
        if (previousDbPath == null) delete process.env.DB_PATH;
        else process.env.DB_PATH = previousDbPath;
      }
      if (ownedDir !== null) {
        rmSync(ownedDir, { recursive: true, force: true });
      }
    }
  });

  it('fails startup when the denominator schema cannot be migrated', () => {
    const ownedDir = mkdtempSync(join(
      assignedWorkerDatabasePath
        ? dirname(assignedWorkerDatabasePath)
        : tmpdir(),
      'radar-denominator-migration-',
    ));
    const path = join(ownedDir, 'radar.db');
    const childRunId = `denominator-migration-${process.pid}-${Date.now()}`;
    if (assignedWorkerDatabasePath) {
      assert.equal(
        process.env.DB_PATH,
        assignedWorkerDatabasePath,
        'release validation denominator migration tests must use their assigned worker database',
      );
    }
    try {
      const setup = spawnSync(process.execPath, [
        '--input-type=module',
        '--eval',
        `
        import { DatabaseSync } from 'node:sqlite';
        const database = new DatabaseSync(${JSON.stringify(path)});
        database.exec(
          'CREATE TABLE release_validation_opportunity_enrollments (' +
          'id INTEGER PRIMARY KEY AUTOINCREMENT)'
        );
        database.close();
        `,
      ], {
        cwd: root,
        env: { ...process.env, DB_PATH: path },
        encoding: 'utf8',
      });
      assert.equal(setup.status, 0, `${setup.stdout}\n${setup.stderr}`);

      const startupEnvironment = {
        ...process.env,
        DB_PATH: path,
        NODE_ENV: 'test',
        NODE_TEST_CONTEXT: undefined,
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
        ...(process.env.RADAR_TEST_RUN_ID
          ? {}
          : {
              RADAR_TEST_PROCESS_LOCK_ROOT: ownedDir!,
              RADAR_TEST_RUN_ID: childRunId,
              RADAR_TEST_TEMP_ROOT: ownedDir!,
            }),
      };
      if (!process.env.RADAR_TEST_RUN_ID) {
        delete startupEnvironment.RADAR_TEST_WRITER_LOCK_TOKEN;
        delete startupEnvironment.RADAR_TEST_WRITER_LOCK_PID;
        delete startupEnvironment.RADAR_TEST_WRITER_LEASE_PATH;
      }
      const startup = spawnSync(process.execPath, [
        '--import',
        'tsx',
        '--input-type=module',
        '--eval',
        `
        (async () => {
          await import('./src/lib/db.ts');
        })().catch((error) => {
          console.error(error);
          process.exitCode = 1;
        });
        `,
      ], {
        cwd: root,
        env: startupEnvironment,
        encoding: 'utf8',
      });
      assert.notEqual(startup.status, 0);
      assert.match(
        `${startup.stdout}\n${startup.stderr}`,
        /release_validation_opportunity_enrollments|score_model_version|no such column/i,
      );
    } finally {
      rmSync(ownedDir, { recursive: true, force: true });
    }
  });
});

const HOUR_MS = 3_600_000;

function reconciliationPlan(input: {
  plannedAt: string;
  catalog: ReleaseValidationCatalogMember[];
  catalogSnapshots?: ReleaseValidationCatalogSnapshot[];
  complete?: boolean;
  opportunities?: Array<{
    code: string;
    minAgeHours: number;
    maxAgeHours: number;
  }>;
  developmentReleaseCount?: number;
  existingObligations?: ReleaseValidationOpportunityReconciliationPlan['obligations'];
  existingSplitAssignments?:
    ReleaseValidationOpportunityReconciliationPlan['splitAssignments'];
  cohort?: ReturnType<typeof reconciliationCohort>;
}): ReleaseValidationOpportunityReconciliationPlan {
  return planReleaseValidationOpportunityReconciliation({
    plannedAt: input.plannedAt,
    cohort: input.cohort ?? reconciliationCohort(),
    catalog: {
      complete: input.complete ?? true,
      snapshots: input.catalogSnapshots ??
        catalogHistory(input.plannedAt, input.catalog),
    },
    policy: {
      opportunities: input.opportunities,
      developmentReleaseCount: input.developmentReleaseCount ?? 0,
    },
    existingObligations: input.existingObligations,
    existingSplitAssignments: input.existingSplitAssignments,
  });
}

function reconciliationCohort() {
  return {
    modelVersion,
    promptVersion,
    codeRevision,
    inceptionAt: '2026-07-01T00:00:00.000Z',
  };
}

function catalogMember(
  key: string,
  sourceOrder: number,
  publishedAtValue: string,
  overrides: Partial<
    Omit<ReleaseValidationCatalogMember, 'contentHash'>
  > = {},
): ReleaseValidationCatalogMember {
  const member = {
    catalogMemberId: `member-${key}`,
    sourceOrder,
    firstSeenAt: new Date(
      Date.parse(publishedAtValue) + 5 * 60_000,
    ).toISOString(),
    nodeId: `node-${key}`,
    tag: `v-${key}`,
    tagCommitOid: Math.max(1, sourceOrder + 1)
      .toString(16)
      .padStart(40, '0'),
    publishedAt: publishedAtValue,
    retiredAt: null,
    draft: false,
    prerelease: false,
    inScope: true,
    ...overrides,
  };
  return {
    ...member,
    contentHash: releaseValidationCatalogMemberContentHash(member),
  };
}

function rehashCatalogMember(
  member: ReleaseValidationCatalogMember,
): ReleaseValidationCatalogMember {
  const { contentHash: _contentHash, ...hashInput } = member;
  return {
    ...hashInput,
    contentHash: releaseValidationCatalogMemberContentHash(hashInput),
  };
}

function catalogHistory(
  observedAt: string,
  members: ReleaseValidationCatalogMember[],
): ReleaseValidationCatalogSnapshot[] {
  const genesis = sealReleaseValidationCatalogSnapshot({
    source: 'github-release-catalog',
    sequence: 1,
    observedAt: reconciliationCohort().inceptionAt,
    previousContentHash: null,
    members: [],
  });
  return observedAt === reconciliationCohort().inceptionAt
    ? [sealReleaseValidationCatalogSnapshot({
      source: 'github-release-catalog',
      sequence: 1,
      observedAt,
      previousContentHash: null,
      members,
    })]
    : extendCatalogHistory([genesis], observedAt, members);
}

function extendCatalogHistory(
  snapshots: ReleaseValidationCatalogSnapshot[],
  observedAt: string,
  members: ReleaseValidationCatalogMember[],
): ReleaseValidationCatalogSnapshot[] {
  const previous = snapshots.at(-1)!;
  return [
    ...snapshots,
    sealReleaseValidationCatalogSnapshot({
      source: previous.attestation.source,
      sequence: previous.attestation.sequence + 1,
      observedAt,
      previousContentHash: previous.attestation.contentHash,
      members,
    }),
  ];
}

function plan(
  enrolledAt: string,
  attemptContentHash: string = 'a'.repeat(64),
  cohortInceptionAt?: string,
) {
  return planReleaseValidationOpportunityEnrollments({
    enrolledAt,
    cohortInceptionAt,
    release: {
      nodeId: 'release-node',
      tag: 'v-release',
      tagCommitOid: '1'.repeat(40),
      publishedAt,
    },
    cohort: {
      modelVersion,
      promptVersion,
      codeRevision,
    },
    evidence: {
      enrollmentRunId: 'refresh-run',
      operationAttemptContentHash: attemptContentHash,
      catalogDigest: 'b'.repeat(64),
      catalogReleaseCount: 10,
    },
  });
}

function rows(inputs: ReturnType<typeof plan>):
ReleaseValidationOpportunityEnrollmentRow[] {
  let previousContentHash: string | null = null;
  return inputs.map((input, index) => {
    const opportunityId = releaseValidationOpportunityId(input);
    const contentHash = releaseValidationOpportunityEnrollmentContentHash({
      ...input,
      opportunity_id: opportunityId,
      previous_content_hash: previousContentHash,
    });
    const row = {
      id: index + 1,
      ...input,
      opportunity_id: opportunityId,
      previous_content_hash: previousContentHash,
      content_hash: contentHash,
    };
    previousContentHash = contentHash;
    return row;
  });
}

function forecastRow(): ReleaseValidationForecastForDenominator {
  return {
    decision_id: 'decision-3h',
    opportunity_code: 'first_verified_after_3h',
    recorded_at: '2026-07-01T04:00:00.000Z',
    latest_release_tag: 'v-release',
    latest_release_published_at: publishedAt,
    score_model_version: modelVersion,
    prompt_version: promptVersion,
    code_revision: codeRevision,
    content_hash: 'c'.repeat(64),
  };
}

function operationAttempt(): OperationAttemptLedgerRow {
  const effectiveConfigJson = canonicalJson({ schemaVersion: 1 });
  const input = {
    runId: 'refresh-run',
    operation: 'refresh',
    trigger: 'test',
    startedAt: '2026-07-01T00:30:00.000Z',
    leaseName: 'refresh',
    leaseHolderId: 'holder',
    leaseExpiresAt: '2026-07-01T06:30:00.000Z',
    codeRevision,
    effectiveConfigJson,
  };
  return {
    run_id: input.runId,
    operation: input.operation,
    trigger: input.trigger,
    started_at: input.startedAt,
    lease_name: input.leaseName,
    lease_holder_id: input.leaseHolderId,
    lease_expires_at: input.leaseExpiresAt,
    code_revision: input.codeRevision,
    effective_config_json: effectiveConfigJson,
    effective_config_hash: operationAttemptConfigHash(effectiveConfigJson),
    content_hash: operationAttemptContentHash(input),
  };
}

function successOperation(
  attempt: OperationAttemptLedgerRow,
  enrollment: ReleaseValidationOpportunityEnrollmentRow,
  forecast: ReleaseValidationForecastForDenominator,
): {
  stageEvents: OperationStageEventLedgerRow[];
  receipt: OperationCaptureReceiptLedgerRow;
} {
  const commitAt = forecast.recorded_at;
  const historyHash = 'd'.repeat(64);
  const authorityRunId = 'authority-run';
  const authorityHash = 'e'.repeat(64);
  const historyV2SealHash = 'f'.repeat(64);
  const stageEvents = stageRows(attempt.run_id, [
    {
      stage: 'score.persist',
      status: 'started',
      occurredAt: '2026-07-01T03:59:58.000Z',
      durationMs: null,
      counts: null,
      details: null,
    },
    {
      stage: 'score.persist',
      status: 'completed',
      occurredAt: '2026-07-01T03:59:59.000Z',
      durationMs: 1_000,
      counts: { scoredReleases: 1 },
      details: {
        historyRunId: 'history-run',
        historyRunContentHash: historyHash,
        authorityRunId,
        authorityRunContentHash: authorityHash,
        historyV2SealContentHash: historyV2SealHash,
        commitNotBefore: commitAt,
        commitNotAfter: commitAt,
      },
    },
    {
      stage: 'forecast.capture',
      status: 'started',
      occurredAt: commitAt,
      durationMs: null,
      counts: null,
      details: null,
    },
    {
      stage: 'forecast.capture',
      status: 'completed',
      occurredAt: '2026-07-01T04:00:01.000Z',
      durationMs: 1_000,
      counts: { validationForecasts: 1 },
      details: { eligibilityOutcome: 'eligible_and_captured' },
    },
  ]);
  const payload = canonicalJson({
    schemaVersion: 1,
    operation: 'refresh',
    trigger: 'test',
    scoreHistory: {
      runId: 'history-run',
      contentHash: historyHash,
    },
    scoreAuthority: {
      runId: authorityRunId,
      contentHash: authorityHash,
      historyV2SealContentHash: historyV2SealHash,
    },
    scoreCommit: {
      historyRunId: 'history-run',
      historyRunContentHash: historyHash,
      authorityRunId,
      authorityRunContentHash: authorityHash,
      historyV2SealContentHash: historyV2SealHash,
      commitNotBefore: commitAt,
      commitNotAfter: commitAt,
    },
    releaseTags: ['v-release'],
    releaseCatalog: {
      attestation: {
        latestStable: {
          tag: 'v-release',
          publishedAt,
        },
      },
    },
    forecast: {
      eligibilityOutcome: 'eligible_and_captured',
      decisionIds: [forecast.decision_id],
      captures: [{
        opportunityCode: enrollment.opportunity_code,
        status: 'inserted',
        decisionId: forecast.decision_id,
        opportunityId: enrollment.opportunity_id,
        enrollmentContentHash: enrollment.content_hash,
      }],
    },
  });
  const receiptInput = {
    receiptId: 'receipt-success',
    runId: attempt.run_id,
    status: 'success' as const,
    finishedAt: stageEvents.at(-1)!.occurred_at,
    durationMs:
      Date.parse(stageEvents.at(-1)!.occurred_at) -
      Date.parse(attempt.started_at),
    stageEventCount: stageEvents.length,
    stageChainHash: stageEvents.at(-1)!.content_hash,
    payloadJson: payload,
    previousContentHash: null,
  };
  return {
    stageEvents,
    receipt: {
      receipt_id: receiptInput.receiptId,
      run_id: receiptInput.runId,
      status: receiptInput.status,
      finished_at: receiptInput.finishedAt,
      duration_ms: receiptInput.durationMs,
      stage_event_count: receiptInput.stageEventCount,
      stage_chain_hash: receiptInput.stageChainHash,
      payload_json: payload,
      previous_content_hash: null,
      content_hash: operationCaptureReceiptContentHash(receiptInput),
    },
  };
}

function failedOperation(
  attempt: OperationAttemptLedgerRow,
  enrollment: ReleaseValidationOpportunityEnrollmentRow,
): {
  stageEvents: OperationStageEventLedgerRow[];
  receipt: OperationCaptureReceiptLedgerRow;
} {
  const failedAt = '2026-07-01T04:00:00.000Z';
  const stageEvents = stageRows(attempt.run_id, [
    {
      stage: 'score.persist',
      status: 'started',
      occurredAt: '2026-07-01T03:59:57.000Z',
      durationMs: null,
      counts: null,
      details: null,
    },
    {
      stage: 'score.persist',
      status: 'completed',
      occurredAt: '2026-07-01T03:59:58.000Z',
      durationMs: 1_000,
      counts: { scoredReleases: 1 },
      details: { historyRunId: 'history-run' },
    },
    {
      stage: 'forecast.capture',
      status: 'started',
      occurredAt: '2026-07-01T03:59:59.000Z',
      durationMs: null,
      counts: null,
      details: null,
    },
    {
      stage: 'forecast.capture',
      status: 'failed',
      occurredAt: failedAt,
      durationMs: 1_000,
      counts: null,
      details: {
        error: { message: 'capture failed' },
        forecastPlan: {
          schemaVersion: 1,
          latestReleaseTag: 'v-release',
          latestReleasePublishedAt: publishedAt,
          scoreModelVersion: modelVersion,
          promptVersion,
          codeRevision,
          slots: [{
            opportunityCode: enrollment.opportunity_code,
          }],
        },
        enrollments: [{
          opportunityId: enrollment.opportunity_id,
          opportunityCode: enrollment.opportunity_code,
          enrollmentContentHash: enrollment.content_hash,
        }],
      },
    },
  ]);
  const payload = canonicalJson({
    schemaVersion: 1,
    error: { message: 'capture failed' },
  });
  const receiptInput = {
    receiptId: 'receipt-failure',
    runId: attempt.run_id,
    status: 'failure' as const,
    finishedAt: failedAt,
    durationMs: Date.parse(failedAt) - Date.parse(attempt.started_at),
    stageEventCount: stageEvents.length,
    stageChainHash: stageEvents.at(-1)!.content_hash,
    payloadJson: payload,
    previousContentHash: null,
  };
  return {
    stageEvents,
    receipt: {
      receipt_id: receiptInput.receiptId,
      run_id: receiptInput.runId,
      status: receiptInput.status,
      finished_at: receiptInput.finishedAt,
      duration_ms: receiptInput.durationMs,
      stage_event_count: receiptInput.stageEventCount,
      stage_chain_hash: receiptInput.stageChainHash,
      payload_json: payload,
      previous_content_hash: null,
      content_hash: operationCaptureReceiptContentHash(receiptInput),
    },
  };
}

function stageRows(
  runId: string,
  inputs: Array<{
    stage: string;
    status: 'started' | 'completed' | 'failed';
    occurredAt: string;
    durationMs: number | null;
    counts: Record<string, unknown> | null;
    details: Record<string, unknown> | null;
  }>,
): OperationStageEventLedgerRow[] {
  let previousContentHash: string | null = null;
  return inputs.map((input, index) => {
    const sequence = index + 1;
    const eventId = `stage-${sequence}`;
    const countsJson = input.counts == null ? null : canonicalJson(input.counts);
    const detailsJson = input.details == null ? null : canonicalJson(input.details);
    const contentHash = operationStageEventContentHash({
      eventId,
      runId,
      sequence,
      stage: input.stage,
      status: input.status,
      occurredAt: input.occurredAt,
      durationMs: input.durationMs,
      countsJson,
      detailsJson,
      previousContentHash,
    });
    const row = {
      event_id: eventId,
      run_id: runId,
      sequence,
      stage: input.stage,
      status: input.status,
      occurred_at: input.occurredAt,
      duration_ms: input.durationMs,
      counts_json: countsJson,
      details_json: detailsJson,
      previous_content_hash: previousContentHash,
      content_hash: contentHash,
    };
    previousContentHash = contentHash;
    return row;
  });
}
