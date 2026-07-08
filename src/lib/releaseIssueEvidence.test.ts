import { after, before, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const ownedTestDir = assignedWorkerDatabasePath === null
  ? mkdtempSync(join(tmpdir(), 'radar-release-issue-evidence-test-'))
  : null;
if (ownedTestDir !== null) {
  const emptyDotenvPath = join(ownedTestDir, 'empty.env');
  process.env.DB_PATH = join(ownedTestDir, 'radar.db');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
  writeFileSync(emptyDotenvPath, '');
}

const TARGET_TAG = 'v2026.6.1';
const NEXT_TAG = 'v2026.6.2';
const IN_WINDOW_CLASSIFIER_MISMATCH = 2001;
const OUT_OF_WINDOW_CLASSIFIER_TARGET = 2002;
const COMMENT_EXPLICITLY_UNAFFECTED = 2003;
const RELEASE_LOCAL_OPEN_DEBT = 2004;
const RELEASE_LOCAL_OPENED_REPORT = 2005;
const UNAUTHORIZED_HUMAN_PRIORITY = 2006;
const PARITY_TAG = 'v2099.7.1';
const PARITY_NEXT_TAG = 'v2099.7.2';
const SCORER_ONLY_POST_PUBLICATION_DEBT = 2101;
const CONTAINED_WITHHELD_FIX = 2102;
const GATE_ONLY_CONTAINED_FIX = 2103;
const POST_PUBLICATION_REPRODUCTION =
  `I reproduced the same session loss on ${PARITY_TAG} after a clean install and restart.`;
const WITHHELD_FIX_CREDIT_DECISION = {
  schemaVersion: 1,
  issueNumber: CONTAINED_WITHHELD_FIX,
  status: 'withheld',
  reasonCode: 'predecessor_reachable',
  targetTag: PARITY_TAG,
  predecessorTag: NEXT_TAG,
  proofIdentities: [],
} as const;
const GATE_ONLY_FIX_CREDIT_DECISION = {
  ...WITHHELD_FIX_CREDIT_DECISION,
  issueNumber: GATE_ONLY_CONTAINED_FIX,
} as const;

let radarDb: typeof import('./db.ts');
let scoring: typeof import('./releaseScoring.ts');
let evidence: typeof import('./releaseIssueEvidence.ts');
let commentEvidence: typeof import('./commentEvidence.ts');
let closureAuthority: typeof import('./closureClaimAuthorityEvaluation.ts');

before(async () => {
  scoring = await import('./releaseScoring.ts');
  radarDb = await import('./db.ts');
  evidence = await import('./releaseIssueEvidence.ts');
  commentEvidence = await import('./commentEvidence.ts');
  closureAuthority = await import('./closureClaimAuthorityEvaluation.ts');

  radarDb.replaceActiveReleaseCatalog([
    {
      node_id: 'R_release_issue_evidence_parity_next',
      catalog_tag_commit_oid: '4'.repeat(40),
      tag: PARITY_NEXT_TAG,
      name: PARITY_NEXT_TAG,
      published_at: '2026-07-10T00:00:00Z',
      created_at: '2026-07-10T00:00:00Z',
      updated_at: '2026-07-10T00:00:00Z',
      html_url: `https://example.test/releases/${PARITY_NEXT_TAG}`,
      prerelease: false,
      body: '',
    },
    {
      node_id: 'R_release_issue_evidence_parity',
      catalog_tag_commit_oid: '3'.repeat(40),
      tag: PARITY_TAG,
      name: PARITY_TAG,
      published_at: '2026-07-01T00:00:00Z',
      created_at: '2026-07-01T00:00:00Z',
      updated_at: '2026-07-01T00:00:00Z',
      html_url: `https://example.test/releases/${PARITY_TAG}`,
      prerelease: false,
      body: '',
    },
    {
      node_id: 'R_release_issue_evidence_next',
      catalog_tag_commit_oid: '2'.repeat(40),
      tag: NEXT_TAG,
      name: NEXT_TAG,
      published_at: '2026-06-10T00:00:00Z',
      created_at: '2026-06-10T00:00:00Z',
      updated_at: '2026-06-10T00:00:00Z',
      html_url: `https://example.test/releases/${NEXT_TAG}`,
      prerelease: false,
      body: '',
    },
    {
      node_id: 'R_release_issue_evidence_target',
      catalog_tag_commit_oid: '1'.repeat(40),
      tag: TARGET_TAG,
      name: TARGET_TAG,
      published_at: '2026-06-01T00:00:00Z',
      created_at: '2026-06-01T00:00:00Z',
      updated_at: '2026-06-01T00:00:00Z',
      html_url: `https://example.test/releases/${TARGET_TAG}`,
      prerelease: false,
      body: '',
    },
  ], {
    capture: { source: 'test_fixture' },
  });

  seedClosedIssue({
    number: IN_WINDOW_CLASSIFIER_MISMATCH,
    title: 'Gateway drops queued messages after upgrade',
    createdAt: '2026-06-02T00:00:00Z',
    closedAt: '2026-06-05T00:00:00Z',
    affectsVersion: NEXT_TAG,
    releaseProofTag: TARGET_TAG,
    releaseProofStatus: 'fixed_in_release',
  });
  seedClosedIssue({
    number: OUT_OF_WINDOW_CLASSIFIER_TARGET,
    title: 'Provider authentication fails after later release',
    createdAt: '2026-06-11T00:00:00Z',
    closedAt: '2026-06-12T00:00:00Z',
    affectsVersion: TARGET_TAG,
  });
  seedClosedIssue({
    number: COMMENT_EXPLICITLY_UNAFFECTED,
    title: 'SSE sanitizer behavior under investigation',
    createdAt: '2026-06-03T00:00:00Z',
    closedAt: '2026-06-06T00:00:00Z',
    affectsVersion: TARGET_TAG,
    releaseProofTag: TARGET_TAG,
    releaseProofStatus: 'fixed_after_release',
    comments: [{
      id: 20_030,
      node_id: 'IC_20030',
      node_type: 'IssueComment',
      url: 'https://example.test/issues/2003#issuecomment-20030',
      user: {
        id: 'U_human-maintainer',
        login: 'human-maintainer',
        type: 'User',
      },
      author_association: 'MEMBER',
      body: 'v2026.6.1 is unaffected; this only reproduces on current main.',
      created_at: '2026-06-04T00:00:00Z',
      updated_at: '2026-06-04T00:00:00Z',
    }],
  });
  seedOpenIssue({
    number: RELEASE_LOCAL_OPEN_DEBT,
    title: `${TARGET_TAG} drops queued gateway messages`,
    createdAt: '2026-06-02T12:00:00Z',
    severity: 'high',
  });
  seedClosedIssue({
    number: RELEASE_LOCAL_OPENED_REPORT,
    title: `${TARGET_TAG} corrupts provider session state`,
    createdAt: '2026-06-03T12:00:00Z',
    closedAt: '2026-06-07T00:00:00Z',
    affectsVersion: TARGET_TAG,
    functionality: 'provider',
    releaseProofTag: TARGET_TAG,
    releaseProofStatus: 'fixed_after_release',
  });
  seedOpenIssue({
    number: UNAUTHORIZED_HUMAN_PRIORITY,
    title: `${TARGET_TAG} intermittent provider warning`,
    createdAt: '2026-06-04T12:00:00Z',
    severity: 'medium',
    labels: ['P0'],
    labelEvent: {
      eventId: `label-${UNAUTHORIZED_HUMAN_PRIORITY}-P0`,
      label: 'P0',
      actor: 'human-looking-maintainer',
      createdAt: '2026-06-04T12:30:00Z',
    },
  });
  seedClosedIssue({
    number: SCORER_ONLY_POST_PUBLICATION_DEBT,
    title: 'Gateway loses session state after restart',
    createdAt: '2026-06-10T00:00:00Z',
    closedAt: '2026-06-20T00:00:00Z',
    updatedAt: '2026-07-05T00:00:00Z',
    affectsVersion: NEXT_TAG,
    comments: [{
      id: 21_010,
      node_id: 'IC_21010',
      node_type: 'IssueComment',
      url: 'https://example.test/issues/2101#issuecomment-21010',
      user: {
        id: 'U_parity-reporter',
        login: 'parity-reporter',
        type: 'User',
      },
      author_association: 'NONE',
      body: POST_PUBLICATION_REPRODUCTION,
      created_at: '2026-07-05T00:00:00Z',
      updated_at: '2026-07-05T00:00:00Z',
    }],
  });
  seedClosedIssue({
    number: CONTAINED_WITHHELD_FIX,
    title: 'Contained fix was already present in the predecessor',
    createdAt: '2026-07-02T00:00:00Z',
    closedAt: '2026-07-06T00:00:00Z',
    affectsVersion: PARITY_TAG,
    releaseProofTag: PARITY_TAG,
    releaseProofStatus: 'fixed_in_release',
  });
  seedClosedIssue({
    number: GATE_ONLY_CONTAINED_FIX,
    title: 'Contained fix omitted from truncated issue evidence',
    createdAt: '2026-07-03T00:00:00Z',
    closedAt: '2026-07-07T00:00:00Z',
    affectsVersion: PARITY_TAG,
    releaseProofTag: PARITY_TAG,
    releaseProofStatus: 'fixed_in_release',
  });
  radarDb.upsertReleaseScoreAudit({
    release_tag: PARITY_TAG,
    scored_at: '2026-07-09T00:00:00Z',
    score_model_version: 'release-issue-evidence-test',
    prompt_version: scoring.PROMPT_VERSION,
    final_score: 50,
    status: 'eligible',
    band: 'test',
    recommended: 0,
    input_json: '{}',
    components_json: null,
    issue_evidence_json: JSON.stringify({
      schemaVersion: scoring.ISSUE_EVIDENCE_SCHEMA_VERSION,
      evidenceCounts: {
        verifiedDebt: 1,
        carryoverDebt: 0,
        staleDebt: 0,
        openedFeltSerious: 0,
        verifiedFixed: 2,
        unverifiedClosed: 0,
        unclassifiedIssues: 0,
        targetEvidenceAttribution: 1,
      },
      targetEvidenceAttribution: [{
        issueNumber: SCORER_ONLY_POST_PUBLICATION_DEBT,
        reasonCode: 'post_publication_exact_version_human_reproduction',
        releaseLocalEvidence: {
          kind: 'exact-version',
          source: 'comment',
          version: PARITY_TAG,
          snippet: POST_PUBLICATION_REPRODUCTION,
        },
        issue: {
          number: SCORER_ONLY_POST_PUBLICATION_DEBT,
          title: 'Gateway loses session state after restart',
          state: 'closed',
        },
      }],
      debtSummary: {},
      verifiedDebt: [{
        issueNumber: SCORER_ONLY_POST_PUBLICATION_DEBT,
        tier: 'verified',
        releaseLocalEvidence: {
          kind: 'exact-version',
          source: 'comment',
          version: PARITY_TAG,
          snippet: POST_PUBLICATION_REPRODUCTION,
        },
        issue: {
          number: SCORER_ONLY_POST_PUBLICATION_DEBT,
          title: 'Gateway loses session state after restart',
          state: 'closed',
        },
      }],
      carryoverDebt: [],
      staleDebt: [],
      openedFeltSerious: [],
      verifiedFixed: [{
        number: CONTAINED_WITHHELD_FIX,
        fixCreditDecision: WITHHELD_FIX_CREDIT_DECISION,
      }],
      unverifiedClosed: [],
      unclassifiedIssues: [],
    }),
    gate_evidence_json: JSON.stringify({
      fixProvenance: {
        releaseFixCredit: {
          schemaVersion: 1,
          targetTag: PARITY_TAG,
          predecessorTag: NEXT_TAG,
          decisions: [
            WITHHELD_FIX_CREDIT_DECISION,
            GATE_ONLY_FIX_CREDIT_DECISION,
          ],
        },
      },
    }),
  });
});

after(() => {
  radarDb.db.close();
  if (ownedTestDir !== null) {
    rmSync(ownedTestDir, { recursive: true, force: true });
  }
});

function seedClosedIssue(input: {
  number: number;
  title: string;
  createdAt: string;
  closedAt: string;
  updatedAt?: string;
  affectsVersion: string;
  releaseProofTag?: string;
  releaseProofStatus?: string;
  functionality?: 'core' | 'provider';
  comments?: Array<{
    id: number;
    node_id: string;
    node_type: 'IssueComment';
    url: string;
    user: {
      id: string;
      login: string;
      type: 'User';
    };
    author_association: string;
    body: string;
    created_at: string;
    updated_at: string;
  }>;
}): void {
  const comments = input.comments ?? [];
  const updatedAt = input.updatedAt ?? input.closedAt;
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = `I_${input.number}`;
  const issueAuthorNodeId = `U_reporter-${input.number}`;
  radarDb.upsertIssue({
    number: input.number,
    node_id: issueNodeId,
    state: 'closed',
    title: input.title,
    body: null,
    author: 'reporter',
    author_node_id: issueAuthorNodeId,
    author_type: 'User',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: updatedAt,
    closed_at: input.closedAt,
    comments: comments.length,
    labels: '[]',
    is_bot: 0,
  });
  radarDb.upsertClassification(input.number, {
    sentiment: 'negative',
    severity: 'high',
    scope: 'broad',
    functionality: input.functionality ?? 'core',
    affectedUsers: 'many',
    hasWorkaround: false,
    workaroundStatus: 'none',
    duplicateCluster: null,
    affectsVersion: input.affectsVersion,
    confidence: 0.9,
    rationale: 'release issue evidence test fixture',
  }, input.closedAt, scoring.PROMPT_VERSION);
  radarDb.upsertIssueClosureEvent({
    issue_number: input.number,
    event_id: `close-${input.number}`,
    closed_at: input.closedAt,
    actor_login: 'human-maintainer',
    state_reason: 'COMPLETED',
    closer_type: null,
    closer_number: null,
    closer_oid: null,
    raw_json: '{}',
  });
  if (input.releaseProofTag) {
    radarDb.upsertIssueClosureProof({
      release_tag: input.releaseProofTag,
      issue_number: input.number,
      status: input.releaseProofStatus ?? 'fixed_in_release',
      summary: 'Release proof fixture.',
      evidence_json: '{}',
    });
  }
  if (comments.length > 0) {
    const snapshotIdentity = {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
      issueAuthor: {
        nodeId: issueAuthorNodeId,
        login: 'reporter',
        actorType: 'User',
      },
    };
    const sweep = {
      issueUpdatedAt: updatedAt,
      totalCount: comments.length,
      comments,
      snapshotIdentity,
    };
    const firstSweep = commentEvidence.commentEvidenceSweepIdentity({
      ...sweep,
      sweepOrdinal: 1,
    });
    const secondSweep = commentEvidence.commentEvidenceSweepIdentity({
      ...sweep,
      sweepOrdinal: 2,
    });
    const stabilization = commentEvidence.commentEvidenceStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    );
    radarDb.upsertIssueCommentSnapshot({
      issue_number: input.number,
      repository_node_id: repositoryNodeId,
      issue_node_id: issueNodeId,
      issue_author_node_id: issueAuthorNodeId,
      issue_author_login: 'reporter',
      issue_author_type: 'User',
      schema_version:
        commentEvidence.AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
      comment_count: comments.length,
      fetched_comment_count: comments.length,
      latest_comment_updated_at: comments.at(-1)?.updated_at ?? null,
      comments_digest: commentEvidence.commentEvidenceDigest(comments.length, comments),
      authority_digest: secondSweep.authorityDigest,
      issue_updated_at: updatedAt,
      comments_json: commentEvidence.serializeCommentEvidence(comments),
      stabilization_json: JSON.stringify(stabilization),
      stabilization_identity_digest: stabilization.identityDigest,
    });
  }
}

function seedOpenIssue(input: {
  number: number;
  title: string;
  createdAt: string;
  severity: 'medium' | 'high';
  labels?: string[];
  labelEvent?: {
    eventId: string;
    label: string;
    actor: string;
    createdAt: string;
  };
}): void {
  const labels = input.labels ?? [];
  radarDb.upsertIssue({
    number: input.number,
    node_id: `I_${input.number}`,
    state: 'open',
    title: input.title,
    body: null,
    author: 'reporter',
    author_node_id: `U_reporter-${input.number}`,
    author_type: 'User',
    author_association: 'NONE',
    html_url: `https://example.test/issues/${input.number}`,
    created_at: input.createdAt,
    updated_at: input.createdAt,
    closed_at: null,
    comments: 0,
    labels: JSON.stringify(labels),
    is_bot: 0,
  });
  radarDb.upsertClassification(input.number, {
    sentiment: 'negative',
    severity: input.severity,
    scope: 'broad',
    functionality: 'core',
    affectedUsers: 'many',
    hasWorkaround: false,
    workaroundStatus: 'none',
    duplicateCluster: null,
    affectsVersion: TARGET_TAG,
    confidence: 0.9,
    rationale: 'release issue evidence open fixture',
  }, input.createdAt, scoring.PROMPT_VERSION);
  if (input.labelEvent) {
    radarDb.upsertIssueLabelEvent({
      issue_number: input.number,
      event_id: input.labelEvent.eventId,
      action: 'labeled',
      label_name: input.labelEvent.label,
      actor_login: input.labelEvent.actor,
      created_at: input.labelEvent.createdAt,
    });
  }
}

describe('release issue evidence attribution', () => {
  it('uses release windows as authority and refuses raw unaffected text without immutable authority', () => {
    assert.deepEqual(
      radarDb.openedDuringReign(TARGET_TAG).map((row) => row.number).sort((a, b) => a - b),
      [
        IN_WINDOW_CLASSIFIER_MISMATCH,
        COMMENT_EXPLICITLY_UNAFFECTED,
        RELEASE_LOCAL_OPEN_DEBT,
        RELEASE_LOCAL_OPENED_REPORT,
        UNAUTHORIZED_HUMAN_PRIORITY,
      ],
    );
    const releaseLinked = scoring.__releaseScoringTest.releaseLinkedIssueRows(
      radarDb.openedDuringReign(TARGET_TAG),
      TARGET_TAG,
    );
    assert.equal(releaseLinked.some((row) =>
      row.number === IN_WINDOW_CLASSIFIER_MISMATCH), false);
    assert.equal(releaseLinked.some((row) =>
      row.number === OUT_OF_WINDOW_CLASSIFIER_TARGET), false);

    const review = evidence.releaseIssueEvidenceRows(TARGET_TAG);
    assert.ok(review);
    assert.ok(review.rows.some((row) =>
      row.issue.number === IN_WINDOW_CLASSIFIER_MISMATCH));
    assert.equal(review.rows.some((row) =>
      row.issue.number === OUT_OF_WINDOW_CLASSIFIER_TARGET), false);
    assert.equal(review.rows.some((row) =>
      row.issue.number === COMMENT_EXPLICITLY_UNAFFECTED), true);

    const attributed = radarDb.issuesForVersion(TARGET_TAG);
    const opened = radarDb.openedDuringReign(TARGET_TAG);
    const profile = evidence.releaseProfileEvidenceRows(TARGET_TAG, {
      attributed,
      opened,
      commentEvidenceCache: evidence.createReleaseProfileCommentEvidenceCache([TARGET_TAG]),
    });
    assert.ok(profile);
    assert.equal(profile.rows.some((row) =>
      row.issueNumber === OUT_OF_WINDOW_CLASSIFIER_TARGET), false);
    assert.equal(profile.rows.some((row) =>
      row.issueNumber === COMMENT_EXPLICITLY_UNAFFECTED), true);
  });

  it('excludes a release only when the exact not-affected claim is authorized', () => {
    const authorizedClosureAuthority =
      closureAuthority.createReleaseClosureAuthorityEvaluation({
        loadClaimsForIssue: (issueNumber) =>
          issueNumber === COMMENT_EXPLICITLY_UNAFFECTED
            ? [authorizedNotAffectedBinding(issueNumber, TARGET_TAG)]
            : [],
      });
    const profile = evidence.releaseProfileEvidenceRows(TARGET_TAG, {
      attributed: radarDb.issuesForVersion(TARGET_TAG),
      opened: radarDb.openedDuringReign(TARGET_TAG),
      commentEvidenceCache:
        evidence.createReleaseProfileCommentEvidenceCache([TARGET_TAG]),
      closureAuthority: authorizedClosureAuthority,
    });
    assert.ok(profile);
    assert.equal(profile.rows.some((row) =>
      row.issueNumber === COMMENT_EXPLICITLY_UNAFFECTED), false);
  });

  it('keeps compact public issue identity and profile evidence equal to full replay', () => {
    const fullAttributed = radarDb.issuesForVersion(TARGET_TAG);
    const fullOpened = radarDb.openedDuringReign(TARGET_TAG);
    const compactAttributed = radarDb.publicIssuesForVersion(TARGET_TAG);
    const compactOpened = radarDb.publicOpenedDuringReign(TARGET_TAG);
    const compactReporter = compactAttributed.find((row) =>
      row.number === RELEASE_LOCAL_OPEN_DEBT);

    assert.ok(compactReporter);
    assert.equal(compactReporter.node_id, `I_${RELEASE_LOCAL_OPEN_DEBT}`);
    assert.equal(
      compactReporter.author_node_id,
      `U_reporter-${RELEASE_LOCAL_OPEN_DEBT}`,
    );
    assert.equal(compactReporter.author_type, 'User');

    const fullProfile = evidence.releaseProfileEvidenceRows(TARGET_TAG, {
      attributed: fullAttributed,
      opened: fullOpened,
      commentEvidenceCache:
        evidence.createReleaseProfileCommentEvidenceCache([TARGET_TAG]),
    });
    const compactProfile = evidence.releaseProfileEvidenceRows(TARGET_TAG, {
      attributed: compactAttributed,
      opened: compactOpened,
      commentEvidenceCache:
        evidence.createReleaseProfileCommentEvidenceCache([TARGET_TAG]),
    });

    assert.deepEqual(compactProfile, fullProfile);
  });

  it('projects release-local provenance for debt and opened-report rows', () => {
    const review = evidence.releaseIssueEvidenceRows(TARGET_TAG);
    assert.ok(review);

    const debt = review.rows.find((row) =>
      row.issue.number === RELEASE_LOCAL_OPEN_DEBT);
    assert.ok(debt);
    assert.ok(['carryoverDebt', 'staleDebt', 'verifiedDebt'].includes(debt.tier));
    assert.deepEqual(debt.releaseLocalEvidence, {
      kind: 'exact-version',
      source: 'title',
      version: TARGET_TAG,
      snippet: `${TARGET_TAG} drops queued gateway messages`,
    });

    const opened = review.rows.find((row) =>
      row.issue.number === RELEASE_LOCAL_OPENED_REPORT);
    assert.ok(opened);
    assert.equal(opened.tier, 'openedFeltSerious');
    assert.deepEqual(opened.releaseLocalEvidence, {
      kind: 'exact-version',
      source: 'title',
      version: TARGET_TAG,
      snippet: `${TARGET_TAG} corrupts provider session state`,
    });
  });

  it('keeps human-looking labels without immutable authority out of compact scoring', () => {
    const review = evidence.releaseIssueEvidenceRows(TARGET_TAG);
    assert.ok(review);
    const row = review.rows.find((candidate) =>
      candidate.issue.number === UNAUTHORIZED_HUMAN_PRIORITY);
    assert.ok(row);
    assert.equal(row.tier, 'staleDebt');
    assert.equal(row.issue.labels.includes('P0'), false);
    assert.equal(row.fieldConfirmed, false);
    assert.deepEqual(row.confirmationReasons, []);

    const profile = evidence.releaseProfileEvidenceRows(TARGET_TAG, {
      attributed: radarDb.issuesForVersion(TARGET_TAG),
      opened: radarDb.openedDuringReign(TARGET_TAG),
      commentEvidenceCache: evidence.createReleaseProfileCommentEvidenceCache([TARGET_TAG]),
    });
    assert.ok(profile);
    const profileRow = profile.rows.find((candidate) =>
      candidate.issueNumber === UNAUTHORIZED_HUMAN_PRIORITY);
    assert.ok(profileRow);
    assert.equal(profileRow.tier, 'staleDebt');
  });

  it('restores scorer-only post-publication debt rows from persisted target evidence', () => {
    assert.equal(
      radarDb.issuesForVersion(PARITY_TAG).some((row) =>
        row.number === SCORER_ONLY_POST_PUBLICATION_DEBT),
      false,
      'the interval query must continue to exclude issues closed before publication',
    );

    const audit = radarDb.getReleaseScoreAudit(PARITY_TAG);
    assert.ok(audit);
    const persisted = JSON.parse(audit.issue_evidence_json);
    assert.ok(persisted.verifiedDebt.some((row: any) =>
      row.issueNumber === SCORER_ONLY_POST_PUBLICATION_DEBT));

    const review = evidence.releaseIssueEvidenceRows(PARITY_TAG);
    assert.ok(review);
    const restored = review.rows.find((row) =>
      row.issue.number === SCORER_ONLY_POST_PUBLICATION_DEBT);
    assert.ok(restored);
    assert.equal(restored.tier, 'verifiedDebt');
    assert.equal(restored.issue.state, 'closed');
    assert.equal(restored.releaseLocalEvidence?.source, 'comment');
    assert.equal(restored.releaseLocalEvidence?.version, PARITY_TAG);
    assert.equal(
      review.countsByTier.verifiedDebt,
      persisted.evidenceCounts.verifiedDebt,
    );
  });

  it('exposes persisted fix-credit decisions on contained verified fixes', () => {
    const review = evidence.releaseIssueEvidenceRows(PARITY_TAG);
    assert.ok(review);
    const contained = review.rows.find((row) =>
      row.tier === 'verifiedFixed' &&
      row.issue.number === CONTAINED_WITHHELD_FIX);
    assert.ok(contained);
    assert.deepEqual(
      contained.fixCreditDecision,
      WITHHELD_FIX_CREDIT_DECISION,
    );
    assert.equal(contained.fixCreditDecision?.status, 'withheld');
  });

  it('loads complete fix-credit decisions omitted from truncated issue evidence', () => {
    const review = evidence.releaseIssueEvidenceRows(PARITY_TAG);
    assert.ok(review);
    const gateOnly = review.rows.find((row) =>
      row.tier === 'verifiedFixed' &&
      row.issue.number === GATE_ONLY_CONTAINED_FIX);
    assert.ok(gateOnly);
    assert.deepEqual(
      gateOnly.fixCreditDecision,
      GATE_ONLY_FIX_CREDIT_DECISION,
    );
  });
});

function authorizedNotAffectedBinding(issueNumber: number, releaseTag: string) {
  const candidateId = `closure-claim-${issueNumber}`;
  return {
    candidate: {
      candidateId,
      issue: {
        number: issueNumber,
      },
      source: {
        kind: 'comment',
        nodeId: `COMMENT_${candidateId}`,
        createdAt: '2026-06-04T00:00:00Z',
        updatedAt: '2026-06-04T00:00:00Z',
      },
      claim: {
        kind: 'release_local',
        assertion: 'not_affected',
        releaseTag,
      },
    },
    resolution: {
      candidateId,
      issueNumber,
      authorizedForScoring: true,
    },
  } as any;
}
