import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { applyClosureRiskSentimentHint, applyLabelOverrides, applyTitleIssueShapeHint } from './labelOverrides.ts';
import {
  LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
  repositoryPermissionObservationRowHash,
  type RepositoryPermissionObservation,
} from './labelAuthority.ts';
import type { IssueClassification } from './llm.ts';
import {
  buildScoreAuthorityReference,
  buildScoreAuthorityResolution,
} from './scoreAuthorityResolution.ts';

// Baseline classification — represents typical LLM output: "medium, moderate, integration".
function mk(overrides: Partial<IssueClassification> = {}): IssueClassification {
  return {
    sentiment: 'negative',
    severity: 'medium',
    scope: 'moderate',
    functionality: 'integration',
    affectedUsers: 'some',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    confidence: 0.7,
    rationale: '',
    ...overrides,
  };
}

function labelAuthorityReference(label: string, index: number) {
  const eventId = `label-event-${index}-${label}`;
  const eventTime = '2026-06-11T12:00:00Z';
  const actorNodeId = 'U_human-maintainer';
  const repositoryNodeId = 'R_label-overrides-test';
  const permissionBase: RepositoryPermissionObservation = {
    kind: 'repository_permission_observation',
    evidenceId: `permission-${eventId}`,
    sourceIdentity: `permission:${eventId}`,
    repositoryNodeId,
    repository: 'owner/repo',
    actorNodeId,
    actorLogin: 'human-maintainer',
    actorType: 'User',
    actorAssociation: 'MEMBER',
    permission: 'maintain',
    observedAt: '2026-06-11T11:00:00Z',
    runHash: 'a'.repeat(64),
  };
  const permission = {
    ...permissionBase,
    rowHash: repositoryPermissionObservationRowHash(permissionBase),
  };
  const resolution = buildScoreAuthorityResolution({
    schemaVersion: LABEL_AUTHORITY_EVIDENCE_SCHEMA_VERSION,
    event: {
      sourceIdentity: `label-event:${eventId}`,
      repositoryNodeId,
      repository: 'owner/repo',
      issueNumber: index + 1,
      eventId,
      action: 'labeled',
      label,
      eventTime,
      actor: {
        nodeId: actorNodeId,
        login: 'human-maintainer',
        type: 'User',
        association: 'MEMBER',
      },
    },
    permissionObservations: [permission],
    approvedRosterEntries: [],
  });
  return buildScoreAuthorityReference('label_event', eventId, resolution);
}

const authorizedLabelAuthority = (...labels: string[]) => ({
  labelActors: Object.fromEntries(labels.map((label) => [label, 'human-maintainer'])),
  authorizedScoringLabels: labels,
  authorityReferences: Object.fromEntries(
    labels.map((label, index) => [label, labelAuthorityReference(label, index)]),
  ),
});

const applyAuthorizedLabelOverrides = (
  classification: IssueClassification,
  labels: string[],
): IssueClassification =>
  applyLabelOverrides(classification, labels, authorizedLabelAuthority(...labels));

describe('applyLabelOverrides', () => {
  // ── Identity / noise ───────────────────────────────────────────────────
  it('no labels → identity', () => {
    const base = mk();
    assert.deepEqual(applyLabelOverrides(base, []), base);
  });

  it('unrelated routing labels (P2, clawsweeper noise) → identity', () => {
    const base = mk();
    const out = applyLabelOverrides(base, [
      'P2',
      'P3',
      'clawsweeper:fix-shape-clear',
      'clawsweeper:no-new-fix-pr',
      'clawsweeper:needs-maintainer-review',
      'size: M',
      'issue-rating: 🦞 diamond lobster',
    ]);
    assert.deepEqual(out, base);
  });

  it('P1 alone does not change severity, confidence, or sentiment', () => {
    const base = mk({ severity: 'medium', confidence: 0.7, sentiment: 'negative' });
    assert.deepEqual(applyLabelOverrides(base, ['P1']), base);
  });

  // ── Sentiment overrides (factual state) ────────────────────────────────
  it('enhancement → sentiment neutral', () => {
    const out = applyAuthorizedLabelOverrides(mk(), ['enhancement']);
    assert.equal(out.sentiment, 'neutral');
  });

  it('stale → sentiment neutral + confidence ≤ 0.5', () => {
    const out = applyAuthorizedLabelOverrides(mk({ confidence: 0.9 }), ['stale']);
    assert.equal(out.sentiment, 'neutral');
    assert.ok(out.confidence <= 0.5);
  });

  it('clawsweeper:not-repro-on-main → sentiment neutral + confidence ≤ 0.6', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ confidence: 1.0 }),
      ['clawsweeper:not-repro-on-main'],
    );
    assert.equal(out.sentiment, 'neutral');
    assert.ok(out.confidence <= 0.6);
  });

  // ── Severity: event-based + human-prioritization ───────────────────────
  it('impact:data-loss → severity critical (event-based)', () => {
    const out = applyAuthorizedLabelOverrides(mk({ severity: 'medium' }), ['impact:data-loss']);
    assert.equal(out.severity, 'critical');
  });

  it('impact:data-loss does NOT downgrade existing critical', () => {
    const out = applyAuthorizedLabelOverrides(mk({ severity: 'critical' }), ['impact:data-loss']);
    assert.equal(out.severity, 'critical');
  });

  it('P0 → severity critical', () => {
    const out = applyAuthorizedLabelOverrides(mk({ severity: 'low' }), ['P0']);
    assert.equal(out.severity, 'critical');
  });

  it('beta-blocker → severity critical', () => {
    const out = applyAuthorizedLabelOverrides(mk({ severity: 'medium' }), ['beta-blocker']);
    assert.equal(out.severity, 'critical');
  });

  it('regression bumps severity one rung', () => {
    assert.equal(applyAuthorizedLabelOverrides(mk({ severity: 'low' }), ['regression']).severity, 'medium');
    assert.equal(applyAuthorizedLabelOverrides(mk({ severity: 'medium' }), ['regression']).severity, 'high');
    assert.equal(applyAuthorizedLabelOverrides(mk({ severity: 'high' }), ['regression']).severity, 'critical');
    assert.equal(applyAuthorizedLabelOverrides(mk({ severity: 'critical' }), ['regression']).severity, 'critical');
  });

  // ── impact:* are NOT severity floors anymore (the big shift) ───────────
  it('impact:session-state does NOT raise severity (it is a categorization, not severity)', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:session-state']);
    assert.equal(out.severity, 'medium', 'LLM-chosen medium must be preserved');
  });

  it('impact:message-loss does NOT raise severity', () => {
    const out = applyLabelOverrides(mk({ severity: 'low' }), ['impact:message-loss']);
    assert.equal(out.severity, 'low');
  });

  it('impact:auth-provider does NOT raise severity', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:auth-provider']);
    assert.equal(out.severity, 'medium');
  });

  it('impact:crash-loop does NOT raise severity', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:crash-loop']);
    assert.equal(out.severity, 'medium');
  });

  it('impact:security does NOT raise severity', () => {
    const out = applyLabelOverrides(mk({ severity: 'medium' }), ['impact:security']);
    assert.equal(out.severity, 'medium');
  });

  // ── impact:* hints for functionality (event-based only) ─────────────────
  // Keyword-stamped labels (session-state, crash-loop, security) intentionally do
  // NOT change functionality — they fire on ~60% of issues from substring matches
  // and used to mass-route routine bugs into "core", inflating core-serious counts.
  it('impact:session-state does NOT change functionality (keyword-stamped, untrusted)', () => {
    const out = applyLabelOverrides(mk({ functionality: 'integration' }), ['impact:session-state']);
    assert.equal(out.functionality, 'integration', 'LLM choice must be preserved');
  });

  it('impact:crash-loop does NOT change functionality', () => {
    const out = applyLabelOverrides(mk({ functionality: 'integration' }), ['impact:crash-loop']);
    assert.equal(out.functionality, 'integration');
  });

  it('impact:security does NOT change functionality', () => {
    const out = applyLabelOverrides(mk({ functionality: 'docs' }), ['impact:security']);
    assert.equal(out.functionality, 'docs');
  });

  it('impact:data-loss → functionality core (event-based, trusted)', () => {
    const out = applyLabelOverrides(mk({ functionality: 'integration' }), ['impact:data-loss']);
    assert.equal(out.functionality, 'core');
  });

  it('impact:message-loss → functionality integration (channel delivery)', () => {
    const out = applyLabelOverrides(mk({ functionality: 'docs' }), ['impact:message-loss']);
    assert.equal(out.functionality, 'integration');
  });

  it('impact:auth-provider → functionality provider', () => {
    const out = applyLabelOverrides(mk({ functionality: 'docs' }), ['impact:auth-provider']);
    assert.equal(out.functionality, 'provider');
  });

  it('multiple impact labels: message-loss + auth-provider → provider (more core than integration)', () => {
    const out = applyLabelOverrides(mk({ functionality: 'docs' }), [
      'impact:message-loss',
      'impact:auth-provider',
    ]);
    assert.equal(out.functionality, 'provider');
  });

  it('trusted hint OVERRIDES LLM, including down-casting core → integration', () => {
    // LLM says core, label says message-loss (channel-delivery). Trust the label —
    // gpt-4o-mini systematically over-classifies as core (we observed ~92% of
    // attributed negatives ending up core+high/critical), and `impact:message-loss`
    // is event-based, so the label is the stronger signal.
    const out = applyLabelOverrides(mk({ functionality: 'core' }), ['impact:message-loss']);
    assert.equal(out.functionality, 'integration');
  });

  // ── Confidence overrides (verification status) ──────────────────────────
  it('clawsweeper:source-repro → confidence ≥ 0.9', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ confidence: 0.5 }),
      ['clawsweeper:source-repro'],
    );
    assert.ok(out.confidence >= 0.9);
  });

  it('clawsweeper:current-main-repro → confidence ≥ 0.9', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ confidence: 0.3 }),
      ['clawsweeper:current-main-repro'],
    );
    assert.ok(out.confidence >= 0.9);
  });

  it('clawsweeper:needs-info → confidence ≤ 0.5', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ confidence: 0.9 }),
      ['clawsweeper:needs-info'],
    );
    assert.ok(out.confidence <= 0.5);
  });

  it('clawsweeper:needs-live-repro → confidence ≤ 0.5', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ confidence: 0.95 }),
      ['clawsweeper:needs-live-repro'],
    );
    assert.ok(out.confidence <= 0.5);
  });

  it('automation and actorless labels cannot force sentiment, severity, or confidence', () => {
    const base = mk({ sentiment: 'negative', severity: 'low', confidence: 0.73 });
    const labels = [
      'stale',
      'P0',
      'regression',
      'impact:data-loss',
      'clawsweeper:source-repro',
      'clawsweeper:needs-live-repro',
    ];
    const actorless = applyLabelOverrides(base, labels);
    const automated = applyLabelOverrides(base, labels, {
      labelActors: Object.fromEntries(labels.map((label) => [label, 'openclaw-barnacle'])),
    });

    for (const out of [actorless, automated]) {
      assert.equal(out.sentiment, base.sentiment);
      assert.equal(out.severity, base.severity);
      assert.equal(out.confidence, base.confidence);
    }
  });

  it('human-looking label actors cannot grant authority without immutable authorization', () => {
    const base = mk({ sentiment: 'negative', severity: 'low', confidence: 0.73 });
    const labels = ['stale', 'P0', 'clawsweeper:source-repro'];
    const out = applyLabelOverrides(base, labels, {
      labelActors: Object.fromEntries(
        labels.map((label) => [label, 'human-looking-maintainer']),
      ),
    });

    assert.equal(out.sentiment, base.sentiment);
    assert.equal(out.severity, base.severity);
    assert.equal(out.confidence, base.confidence);
  });

  it('labels listed without canonical authority references fail closed', () => {
    const base = mk({ sentiment: 'negative', severity: 'low', confidence: 0.73 });
    const labels = ['stale', 'P0', 'clawsweeper:source-repro'];
    const out = applyLabelOverrides(base, labels, {
      labelActors: Object.fromEntries(
        labels.map((label) => [label, 'human-maintainer']),
      ),
      authorizedScoringLabels: labels,
    });

    assert.equal(out.sentiment, base.sentiment);
    assert.equal(out.severity, base.severity);
    assert.equal(out.confidence, base.confidence);
  });

  it('immutable authorized label events retain override authority', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ sentiment: 'negative', severity: 'low', confidence: 0.4 }),
      ['stale', 'P0', 'clawsweeper:source-repro'],
    );
    assert.equal(out.sentiment, 'neutral');
    assert.equal(out.severity, 'critical');
    assert.equal(out.confidence, 0.9);
  });

  // ── Passthrough & compound ──────────────────────────────────────────────
  it('passthrough fields are preserved', () => {
    const base = mk({
      duplicateCluster: 'ollama-timeout',
      affectsVersion: 'v2026.5.20',
      affectedUsers: 'many',
      workaroundStatus: 'confirmed',
      scope: 'broad',
    });
    const out = applyLabelOverrides(base, ['impact:data-loss']);
    assert.equal(out.duplicateCluster, 'ollama-timeout');
    assert.equal(out.affectsVersion, 'v2026.5.20');
    assert.equal(out.affectedUsers, 'many');
    assert.equal(out.workaroundStatus, 'confirmed');
    assert.equal(out.scope, 'broad');
  });

  it('enhancement + impact:data-loss → neutral + critical (mistagged feature request)', () => {
    const out = applyAuthorizedLabelOverrides(mk(), ['enhancement', 'impact:data-loss']);
    assert.equal(out.sentiment, 'neutral');
    assert.equal(out.severity, 'critical');
  });

  it('regression + impact:data-loss → critical (regression bump caps at critical)', () => {
    const out = applyAuthorizedLabelOverrides(
      mk({ severity: 'medium' }),
      ['regression', 'impact:data-loss'],
    );
    assert.equal(out.severity, 'critical');
  });
});

describe('applyTitleIssueShapeHint', () => {
  it('neutralizes feature-shaped issues without strong bug labels', () => {
    const out = applyTitleIssueShapeHint(
      mk({ sentiment: 'negative', severity: 'critical', confidence: 0.95 }),
      'Feature: fire session-memory hook on session reset/prune',
      ['clawsweeper:needs-product-decision'],
    );
    assert.equal(out.sentiment, 'neutral');
    assert.equal(out.severity, 'medium');
    assert.ok(out.confidence <= 0.65);
  });

  it('does not neutralize feature-shaped titles when regression is explicit', () => {
    const base = mk({ sentiment: 'negative', severity: 'high', confidence: 0.9 });
    const out = applyTitleIssueShapeHint(
      base,
      '[Feature]: login flow regression',
      ['regression'],
      authorizedLabelAuthority('regression'),
    );
    assert.deepEqual(out, base);
  });

  it('does not let actorless regression labels protect feature-shaped model output', () => {
    const out = applyTitleIssueShapeHint(
      mk({ sentiment: 'negative', severity: 'high', confidence: 0.9 }),
      '[Feature]: login flow regression',
      ['regression'],
    );
    assert.equal(out.sentiment, 'neutral');
    assert.equal(out.severity, 'medium');
    assert.equal(out.confidence, 0.65);
  });
});

describe('applyClosureRiskSentimentHint', () => {
  it('keeps stale-only neutral evidence neutral', () => {
    const out = applyClosureRiskSentimentHint(
      mk({ sentiment: 'neutral', severity: 'medium', affectsVersion: null }),
      'Question: should we support extra dashboard themes?',
      ['stale'],
    );
    assert.equal(out.sentiment, 'neutral');
  });

  it('promotes neutral source-repro impact evidence to negative for closure risk', () => {
    const neutral = applyLabelOverrides(
      mk({ sentiment: 'negative', severity: 'medium', affectsVersion: null }),
      ['stale', 'clawsweeper:source-repro', 'impact:message-loss'],
      authorizedLabelAuthority('stale', 'clawsweeper:source-repro', 'impact:message-loss'),
    );
    assert.equal(neutral.sentiment, 'neutral');
    const out = applyClosureRiskSentimentHint(
      neutral,
      'Cron announce delivery reports success but message never arrives',
      ['stale', 'clawsweeper:source-repro', 'impact:message-loss'],
      authorizedLabelAuthority('stale', 'clawsweeper:source-repro', 'impact:message-loss'),
    );
    assert.equal(out.sentiment, 'negative');
  });

  it('promotes neutral data-loss evidence even when the title is not bug-shaped', () => {
    const out = applyClosureRiskSentimentHint(
      mk({ sentiment: 'neutral', severity: 'critical', functionality: 'core' }),
      'feishu_create_doc: LaTeX backslashes eaten in complex block formulas',
      ['stale', 'impact:data-loss'],
      authorizedLabelAuthority('stale', 'impact:data-loss'),
    );
    assert.equal(out.sentiment, 'negative');
  });

  it('does not promote feature-only enhancement requests without live bug evidence', () => {
    const out = applyClosureRiskSentimentHint(
      mk({ sentiment: 'neutral', severity: 'critical', affectsVersion: null }),
      '[Feature]: safe/unsafe ClawdBot',
      ['enhancement', 'impact:security'],
    );
    assert.equal(out.sentiment, 'neutral');
  });

  it('does not promote feature requests solely because they name a release or impact area', () => {
    const out = applyClosureRiskSentimentHint(
      mk({ sentiment: 'neutral', severity: 'medium', affectsVersion: 'v2026.6.8' }),
      '[Feature Request] simplify the apply flow',
      ['impact:session-state'],
    );
    assert.equal(out.sentiment, 'neutral');
  });

  it('does not promote neutral output from automation-only validation labels', () => {
    const labels = ['bug', 'clawsweeper:source-repro', 'impact:message-loss'];
    const base = mk({ sentiment: 'neutral', severity: 'high', confidence: 0.99 });
    const actorless = applyClosureRiskSentimentHint(
      base,
      'Cron announce delivery reports success but message never arrives',
      labels,
    );
    const automated = applyClosureRiskSentimentHint(
      base,
      'Cron announce delivery reports success but message never arrives',
      labels,
      {
        labelActors: Object.fromEntries(labels.map((label) => [label, 'clawsweeper'])),
      },
    );
    assert.equal(actorless.sentiment, 'neutral');
    assert.equal(automated.sentiment, 'neutral');
  });
});
