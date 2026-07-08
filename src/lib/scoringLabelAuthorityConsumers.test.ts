import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-label-authority-consumers-'))
  : null;
if (ownedTestDir !== null) {
  const emptyDotenvPath = join(ownedTestDir, 'empty.env');
  process.env.DB_PATH = join(ownedTestDir, 'radar.db');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

const TARGET_TAG = 'v2099.7.1';
const NEXT_TAG = 'v2099.7.2';
const ISSUE_NUMBER = 71_001;
const LABEL_CUTOFF = '2026-07-09T23:59:59Z';
const SCORE_NOW = Date.parse('2026-07-06T12:00:00Z');
const NON_PRIORITY_SCORE_AUTHORITY_LABELS = [
  'bug',
  'clawsweeper:current-main-repro',
  'clawsweeper:needs-info',
  'clawsweeper:needs-live-repro',
  'clawsweeper:not-repro-on-main',
  'clawsweeper:source-repro',
  'enhancement',
  'impact:auth-provider',
  'impact:crash-loop',
  'impact:data-loss',
  'impact:message-loss',
  'impact:security',
  'impact:session-state',
  'stale',
] as const;

let radarDb: typeof import('./db.ts');
let closureProof: typeof import('./closureProofPayload.ts');
let publicIssues: typeof import('./publicIssueSummary.ts');
let scoring: typeof import('./releaseScoring.ts');
let scoreModel: typeof import('./score.ts');

before(async () => {
  scoring = await import('./releaseScoring.ts');
  scoreModel = await import('./score.ts');
  radarDb = await import('./db.ts');
  closureProof = await import('./closureProofPayload.ts');
  publicIssues = await import('./publicIssueSummary.ts');

  radarDb.replaceActiveReleaseCatalog([
    {
      node_id: 'R_scoring_label_authority_next',
      catalog_tag_commit_oid: '2'.repeat(40),
      tag: NEXT_TAG,
      name: NEXT_TAG,
      published_at: '2026-07-10T00:00:00Z',
      created_at: '2026-07-10T00:00:00Z',
      updated_at: '2026-07-10T00:00:00Z',
      html_url: `https://example.test/releases/${NEXT_TAG}`,
      prerelease: false,
      body: '',
    },
    {
      node_id: 'R_scoring_label_authority_target',
      catalog_tag_commit_oid: '1'.repeat(40),
      tag: TARGET_TAG,
      name: TARGET_TAG,
      published_at: '2026-07-01T00:00:00Z',
      created_at: '2026-07-01T00:00:00Z',
      updated_at: '2026-07-01T00:00:00Z',
      html_url: `https://example.test/releases/${TARGET_TAG}`,
      prerelease: false,
      body: '',
    },
  ], {
    capture: { source: 'test_fixture' },
  });
  radarDb.upsertIssue({
    number: ISSUE_NUMBER,
    node_id: `I_${ISSUE_NUMBER}`,
    state: 'closed',
    title: 'Provider crash after upgrade',
    body: null,
    author: 'reporter',
    author_node_id: `U_reporter-${ISSUE_NUMBER}`,
    author_type: 'User',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${ISSUE_NUMBER}`,
    created_at: '2026-07-02T00:00:00Z',
    updated_at: '2026-07-05T00:00:00Z',
    closed_at: '2026-07-05T00:00:00Z',
    comments: 0,
    labels: JSON.stringify(['P0']),
    is_bot: 0,
  });
  radarDb.upsertClassification(ISSUE_NUMBER, {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'broad',
    functionality: 'core',
    affectedUsers: 'many',
    hasWorkaround: false,
    workaroundStatus: 'none',
    duplicateCluster: null,
    affectsVersion: TARGET_TAG,
    confidence: 0.9,
    rationale: 'authority consumer fixture',
  }, '2026-07-05T00:00:00Z', scoring.PROMPT_VERSION);
  radarDb.upsertIssueLabelEvent({
    issue_number: ISSUE_NUMBER,
    event_id: `label-${ISSUE_NUMBER}-P0`,
    action: 'labeled',
    label_name: 'P0',
    actor_login: 'human-looking-maintainer',
    actor_type: 'User',
    created_at: '2026-07-03T00:00:00Z',
  });
  radarDb.upsertIssueClosureEvent({
    issue_number: ISSUE_NUMBER,
    event_id: `close-${ISSUE_NUMBER}`,
    closed_at: '2026-07-05T00:00:00Z',
    actor_login: 'human-looking-maintainer',
    state_reason: 'COMPLETED',
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
  radarDb.upsertIssueClosureProof({
    release_tag: TARGET_TAG,
    issue_number: ISSUE_NUMBER,
    status: 'fixed_after_release',
    summary: 'The fix is not contained in the scored tag.',
    evidence_json: '{}',
  });
});

after(() => {
  radarDb.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

function eventIdForLabel(label: string): string {
  return `adversarial-label-${label.replace(/[^a-z0-9]+/gi, '-')}`;
}

function authorityReferenceForEvent(eventId: string) {
  return {
    subjectKind: 'label_event' as const,
    subjectIdentity: eventId,
    resolutionHash: 'a'.repeat(64),
    evidenceDigest: 'b'.repeat(64),
    authorizedForScoring: true as const,
  };
}

function resolvedLabelInfo(
  labels: readonly string[],
  authorizedLabels: readonly string[] = [],
) {
  const authorizedEventIds = new Set(
    authorizedLabels.map(eventIdForLabel),
  );
  return scoring.scoringLabelInfoAtCutoff(
    ISSUE_NUMBER + 1,
    [...labels],
    LABEL_CUTOFF,
    (eventId) => authorizedEventIds.has(eventId)
      ? authorityReferenceForEvent(eventId)
      : null,
    (_issueNumber, label) => ({
      event_id: eventIdForLabel(label),
      action: 'labeled',
      label_name: label,
      actor_login: 'human-looking-maintainer',
      actor_type: 'User',
      created_at: '2026-07-03T00:00:00Z',
    }),
  );
}

function scoringProjection({
  labels,
  authorizedLabels = [],
  rowOverrides = {},
}: {
  labels: readonly string[];
  authorizedLabels?: readonly string[];
  rowOverrides?: Record<string, unknown>;
}) {
  const labelInfo = resolvedLabelInfo(labels, authorizedLabels);
  const row = {
    title: 'Service crash after upgrade',
    sentiment: 'negative',
    severity: 'high',
    scope: 'broad',
    functionality: 'core',
    affected_users: 'many',
    has_workaround: 0,
    workaround_status: 'none',
    duplicate_cluster: null,
    affects_version: null,
    confidence: 0.4,
    rationale: 'score invariance fixture',
    ...rowOverrides,
  };
  const classification = scoring.classifyIssueRowForOpenDebtWithLabels(
    row as any,
    labelInfo.labels,
    labelInfo,
  );
  const issue = {
    ...classification,
    issueNumber: ISSUE_NUMBER + 1,
    issueNodeId: `I_${ISSUE_NUMBER + 1}`,
    title: row.title as string,
    state: 'open',
    author: 'reporter',
    authorNodeId: `U_reporter-${ISSUE_NUMBER + 1}`,
    authorType: 'User',
    authorAssociation: 'NONE',
    isBot: 0,
    comments: 0,
    labels: labelInfo.labels,
    releaseLocal: false,
  };
  const debt = scoreModel.explainOpenDebtLoad([issue]);
  const feltOpenedWeight = scoreModel.feltLoad([issue]);
  const scoreInput = {
    feltOpenedWeight,
    verifiedDebtWeight: debt.loads.verified,
    carryoverDebtWeight: debt.loads.carryover,
    staleDebtWeight: debt.loads.stale,
  };
  const confidence = scoreModel.installConfidence({
    publishedAt: '2026-07-01T00:00:00Z',
    isLatest: true,
    hoursToNextStable: null,
    hasHotfixSuccessor: false,
    betaCount: 0,
    breakingCount: 0,
    ...scoreInput,
    feltClosedWeight: 0,
    verifiedDebtIssueCount: debt.evidence.filter((item) =>
      item.tier === 'verified').length,
    carryoverDebtIssueCount: debt.evidence.filter((item) =>
      item.tier === 'carryover').length,
    staleDebtIssueCount: debt.evidence.filter((item) =>
      item.tier === 'stale').length,
    unresolvedClosureRiskWeight: 0,
    affirmativeClosureRiskCeilingWeight: 0,
    unresolvedClosureIssueCount: 0,
    rawIssueCount: 1,
    classifiedIssueCount: 1,
    cveAffected: false,
    cveLoad: 0,
  }, SCORE_NOW);
  return {
    labelInfo,
    classification,
    debtLoads: debt.loads,
    debtTiers: debt.evidence.map((item) => item.tier),
    scoreInput,
    confidence,
  };
}

describe('immutable label authority consumers', () => {
  it('keeps unauthorized human-looking P0 labels out of public and closure classifications', () => {
    const issue = radarDb.issuesForVersion(TARGET_TAG)
      .find((row) => row.number === ISSUE_NUMBER);
    assert.ok(issue);

    const summaries = publicIssues.publicIssueSummariesForRelease({
      issues: [issue],
      openedIssues: [issue],
      labelCutoff: LABEL_CUTOFF,
    });
    assert.equal(summaries.topIssues.length, 1);
    assert.equal(summaries.topIssues[0]?.severity, 'medium');

    const audit = closureProof.closureProofAuditRows(TARGET_TAG, LABEL_CUTOFF)
      .find((row) => row.number === ISSUE_NUMBER);
    assert.ok(audit);
    assert.equal(audit.severity, 'medium');
    assert.deepEqual(audit.labels, []);
    assert.equal(audit.riskWeight, 1.95);
  });

  it('keeps unauthorized non-priority authority labels score-invariant', () => {
    const baseline = scoringProjection({
      labels: ['triage'],
    });
    const adversarial = scoringProjection({
      labels: ['triage', ...NON_PRIORITY_SCORE_AUTHORITY_LABELS],
    });

    assert.deepEqual(adversarial.labelInfo.labels, baseline.labelInfo.labels);
    assert.deepEqual(adversarial.labelInfo.authorizedScoringLabels, []);
    assert.deepEqual(adversarial.classification, baseline.classification);
    assert.deepEqual(adversarial.debtLoads, baseline.debtLoads);
    assert.deepEqual(adversarial.debtTiers, baseline.debtTiers);
    assert.deepEqual(adversarial.scoreInput, baseline.scoreInput);
    assert.deepEqual(adversarial.confidence, baseline.confidence);
  });

  it('retains authorized non-priority labels and their scoring effects', () => {
    const authorizedInfo = resolvedLabelInfo(
      ['triage', ...NON_PRIORITY_SCORE_AUTHORITY_LABELS],
      NON_PRIORITY_SCORE_AUTHORITY_LABELS,
    );
    assert.deepEqual(
      authorizedInfo.labels,
      ['triage', ...NON_PRIORITY_SCORE_AUTHORITY_LABELS],
    );
    assert.deepEqual(
      authorizedInfo.authorizedScoringLabels,
      [...NON_PRIORITY_SCORE_AUTHORITY_LABELS].sort(),
    );
    for (const label of NON_PRIORITY_SCORE_AUTHORITY_LABELS) {
      assert.equal(
        authorizedInfo.authorityReferences[label]?.subjectIdentity,
        eventIdForLabel(label),
      );
    }

    for (const label of ['stale', 'enhancement'] as const) {
      const baseline = scoringProjection({
        labels: ['triage'],
        rowOverrides: {
          title: 'Optional dashboard theme request',
        },
      });
      const authorized = scoringProjection({
        labels: ['triage', label],
        authorizedLabels: [label],
        rowOverrides: {
          title: 'Optional dashboard theme request',
        },
      });
      assert.equal(authorized.classification.sentiment, 'neutral');
      assert.notDeepEqual(authorized.scoreInput, baseline.scoreInput);
      assert.notEqual(authorized.confidence.score, baseline.confidence.score);
    }

    const sourceBaseline = scoringProjection({
      labels: ['triage'],
    });
    const authorizedSource = scoringProjection({
      labels: ['triage', 'clawsweeper:source-repro'],
      authorizedLabels: ['clawsweeper:source-repro'],
    });
    assert.equal(authorizedSource.classification.confidence, 0.9);
    assert.deepEqual(authorizedSource.debtTiers, ['stale']);
    assert.notDeepEqual(authorizedSource.scoreInput, sourceBaseline.scoreInput);
    assert.notEqual(
      authorizedSource.confidence.components?.staleDebt,
      sourceBaseline.confidence.components?.staleDebt,
    );
    assert.notEqual(
      authorizedSource.confidence.components?.regression,
      sourceBaseline.confidence.components?.regression,
    );

    const impactBaseline = scoringProjection({
      labels: ['triage'],
      rowOverrides: {
        title: 'State handling report',
        severity: 'low',
        functionality: 'docs',
      },
    });
    const authorizedImpact = scoringProjection({
      labels: ['triage', 'impact:data-loss'],
      authorizedLabels: ['impact:data-loss'],
      rowOverrides: {
        title: 'State handling report',
        severity: 'low',
        functionality: 'docs',
      },
    });
    assert.equal(authorizedImpact.classification.severity, 'critical');
    assert.equal(authorizedImpact.classification.functionality, 'core');
    assert.notDeepEqual(authorizedImpact.scoreInput, impactBaseline.scoreInput);
    assert.notEqual(
      authorizedImpact.confidence.score,
      impactBaseline.confidence.score,
    );

    const categoryImpactBaseline = scoringProjection({
      labels: ['triage'],
      rowOverrides: {
        title: 'Delivery handling report',
        functionality: 'docs',
      },
    });
    const authorizedCategoryImpact = scoringProjection({
      labels: ['triage', 'impact:message-loss'],
      authorizedLabels: ['impact:message-loss'],
      rowOverrides: {
        title: 'Delivery handling report',
        functionality: 'docs',
      },
    });
    assert.equal(
      authorizedCategoryImpact.classification.functionality,
      'integration',
    );
    assert.notDeepEqual(
      authorizedCategoryImpact.scoreInput,
      categoryImpactBaseline.scoreInput,
    );
  });
});
