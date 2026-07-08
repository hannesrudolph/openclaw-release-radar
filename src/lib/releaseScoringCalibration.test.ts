import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { describe, it } from 'node:test';

describe('release scoring evidence calibration', () => {
  it('refuses persistence for score-affecting missing closure evidence without scoring or capping it', () => {
    const assignedDatabasePath = process.env.RADAR_TEST_WORKER_DB_PATH?.trim();
    assert.ok(
      assignedDatabasePath,
      'release scoring calibration requires a runner-assigned database',
    );
    assert.equal(
      process.env.DB_PATH,
      assignedDatabasePath,
      'release scoring calibration must use its runner-assigned database',
    );
    assert.ok(
      process.env.DOTENV_CONFIG_PATH?.trim(),
      'release scoring calibration requires the runner-assigned empty dotenv',
    );
    const result = spawnSync(process.execPath, [
      '--import',
      'tsx',
      '--input-type=module',
      '--eval',
      calibrationScript,
    ], {
      cwd: process.cwd(),
      env: process.env,
      encoding: 'utf8',
    });
    assert.equal(
      result.status,
      0,
      `calibration subprocess failed:\n${result.stdout}\n${result.stderr}`,
    );
    assert.match(result.stdout, /CALIBRATION_OK/);
  });
});

const calibrationScript = String.raw`
  import assert from 'node:assert/strict';
  import { spawnSync } from 'node:child_process';
  import { createHash } from 'node:crypto';
void (async () => {
  const dbModule = await import('./src/lib/db.ts');
  const db = dbModule.default ?? dbModule;
  const scoringModule = await import('./src/lib/releaseScoring.ts');
  const scoring = scoringModule.default ?? scoringModule;
  const llmModule = await import('./src/lib/llm.ts');
  const llm = llmModule.default ?? llmModule;
  const commentEvidenceModule = await import('./src/lib/commentEvidence.ts');
  const commentEvidence = commentEvidenceModule.default ?? commentEvidenceModule;
  const stateEventsModule = await import('./src/lib/stateEventSnapshot.ts');
  const stateEvents = stateEventsModule.default ?? stateEventsModule;
  const analysisVersionsModule = await import('./src/lib/analysisVersions.ts');
  const analysisVersions = analysisVersionsModule.default ?? analysisVersionsModule;
  const classifierLedgerModule = await import('./src/lib/classifierAttemptLedger.ts');
  const classifierLedger = classifierLedgerModule.default ?? classifierLedgerModule;
  const operationReceiptsModule = await import('./src/lib/operationReceipts.ts');
  const operationReceipts = operationReceiptsModule.default ?? operationReceiptsModule;
  const seedRelease = (tag, publishedAt) => {
    const release = {
      node_id: 'R_' + tag.replace(/[^A-Za-z0-9]/g, '_'),
      catalog_tag_commit_oid: createHash('sha1')
        .update('release-scoring-calibration:' + tag)
        .digest('hex'),
      tag,
      name: tag,
      published_at: publishedAt,
      created_at: publishedAt,
      updated_at: publishedAt,
      html_url: 'https://example.test/releases/' + tag,
      prerelease: false,
      body: '',
    };
    db.upsertRelease(release);
    db.upsertReleaseCommit({
      tag,
      tag_commit_oid: release.catalog_tag_commit_oid,
      committed_at: publishedAt,
    });
    return release;
  };
  const previousRelease = seedRelease('v-prev', '2026-06-06T00:00:00Z');
  const targetRelease = seedRelease('v-target', '2026-06-07T00:00:00Z');
  const nextRelease = seedRelease('v-next', '2026-06-08T00:00:00Z');
  db.replaceActiveReleaseCatalog([
    nextRelease,
    targetRelease,
    previousRelease,
  ], {
    capture: { source: 'test_fixture' },
  });

  const issueNumber = 99001;
  const repositoryNodeId = 'REPO-node-openclaw';
  const issueNodeId = 'ISSUE-node-' + issueNumber;
  const issueAuthorNodeId = 'ACTOR-reporter-' + issueNumber;
  const createdAt = '2026-06-07T12:00:00Z';
  const closedAt = '2026-06-07T18:00:00Z';
  const issueTitle = 'v-target core failure closed without complete proof';
  const issueBody =
    'The v-target core gateway fails during startup for many default installs. ' +
    'No workaround exists.';
  const comments = [{
    id: issueNumber * 10,
    node_id: 'COMMENT-node-' + (issueNumber * 10),
    node_type: 'IssueComment',
    url: 'https://example.test/issues/' + issueNumber + '#comment',
    user: {
      id: 'ACTOR-commenter',
      login: 'commenter',
      type: 'User',
    },
    author_association: 'NONE',
    body: 'fixture comment',
    created_at: createdAt,
    updated_at: createdAt,
  }];
  const commentsDigest = commentEvidence.commentEvidenceDigest(1, comments);
  const commentSnapshotIdentity = {
    repositoryNodeId,
    issueNodeId,
    issueNodeType: 'Issue',
    issueAuthor: {
      nodeId: issueAuthorNodeId,
      login: 'reporter',
      actorType: 'User',
    },
  };
  const commentSweep = {
    issueUpdatedAt: closedAt,
    totalCount: comments.length,
    comments,
    snapshotIdentity: commentSnapshotIdentity,
  };
  const firstCommentSweep = commentEvidence.commentEvidenceSweepIdentity({
    ...commentSweep,
    sweepOrdinal: 1,
  });
  const secondCommentSweep = commentEvidence.commentEvidenceSweepIdentity({
    ...commentSweep,
    sweepOrdinal: 2,
  });
  const commentStabilization = commentEvidence.commentEvidenceStabilizationIdentity(
    firstCommentSweep,
    secondCommentSweep,
    2,
  );
  db.upsertIssue({
    number: issueNumber,
    node_id: issueNodeId,
    state: 'closed',
    title: issueTitle,
    author: 'reporter',
    author_node_id: issueAuthorNodeId,
    author_type: 'User',
    author_association: 'NONE',
    html_url: 'https://example.test/issues/' + issueNumber,
    created_at: createdAt,
    updated_at: closedAt,
    closed_at: closedAt,
    comments: 1,
    unique_human_commenters: 1,
    maintainer_commenters: 0,
    contributor_commenters: 0,
    commenter_scan_truncated: 0,
    reaction_total: 0,
    positive_reactions: 0,
    labels: JSON.stringify(['bug']),
    is_bot: 0,
  });
  db.upsertIssueCommentSnapshot({
    issue_number: issueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_author_node_id: issueAuthorNodeId,
    issue_author_login: 'reporter',
    issue_author_type: 'User',
    schema_version: commentEvidence.AUTHORITATIVE_COMMENT_EVIDENCE_SNAPSHOT_SCHEMA_VERSION,
    comment_count: 1,
    fetched_comment_count: 1,
    latest_comment_updated_at: createdAt,
    comments_digest: commentsDigest,
    authority_digest: secondCommentSweep.authorityDigest,
    issue_updated_at: closedAt,
    comments_json: commentEvidence.serializeCommentEvidence(comments),
    stabilization_json: JSON.stringify(commentStabilization),
    stabilization_identity_digest: commentStabilization.identityDigest,
  });
  db.upsertIssueLabelSnapshot({
    issue_number: issueNumber,
    snapshot_at: '2026-06-10T23:00:00Z',
    labels_json: JSON.stringify(['bug']),
  });
  const closureEvent = {
    issue_number: issueNumber,
    issue_node_id: issueNodeId,
    event_id: 'closed-' + issueNumber,
    closed_at: closedAt,
    connection_ordinal: 0,
    actor_node_id: 'ACTOR-maintainer',
    actor_login: 'maintainer',
    actor_type: 'User',
    state_reason: 'COMPLETED',
    closer_type: 'Commit',
    closer_number: null,
    closer_node_id: 'COMMIT-node-' + issueNumber,
    closer_oid: 'c'.repeat(40),
    raw_json: JSON.stringify({
      id: 'closed-' + issueNumber,
      __typename: 'ClosedEvent',
      actor: { id: 'ACTOR-maintainer', __typename: 'User', login: 'maintainer' },
      closer: { id: 'COMMIT-node-' + issueNumber, __typename: 'Commit' },
    }),
  };
  const normalizedStateEvents = stateEvents.normalizeIssueStateEvents([{
    eventId: closureEvent.event_id,
    eventNodeType: 'ClosedEvent',
    type: 'closed',
    occurredAt: closedAt,
    connectionOrdinal: 0,
    actorNodeId: closureEvent.actor_node_id,
    actorLogin: closureEvent.actor_login,
    actorType: closureEvent.actor_type,
    stateReason: closureEvent.state_reason,
    closerNodeId: closureEvent.closer_node_id,
    closerType: closureEvent.closer_type,
    closerNumber: null,
    closerOid: closureEvent.closer_oid,
  }]);
  const stateSweep = {
    repositoryNodeId,
    issueNumber,
    issueNodeId,
    issueNodeType: 'Issue',
    issueState: 'closed',
    issueUpdatedAt: closedAt,
    totalCount: normalizedStateEvents.length,
    events: normalizedStateEvents,
  };
  const firstStateSweep = stateEvents.issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 1,
  });
  const secondStateSweep = stateEvents.issueStateEventSweepIdentity({
    ...stateSweep,
    sweepOrdinal: 2,
  });
  db.replaceIssueStateEventSnapshot({
    issue_number: issueNumber,
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_node_type: 'Issue',
    issue_state: 'closed',
    issue_updated_at: closedAt,
    total_count: 1,
    fetched_count: 1,
    sweep_count: 2,
    stabilized: true,
    events_digest: stateEvents.issueStateEventsDigest(normalizedStateEvents, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType: 'Issue',
    }),
    authority_digest: secondStateSweep.sweepDigest,
    stabilization: stateEvents.issueStateEventStabilizationIdentity(
      firstStateSweep,
      secondStateSweep,
      2,
    ),
    closure_events: [closureEvent],
    reopen_events: [],
  });
  db.upsertIssueClosureProof({
    release_tag: 'v-target',
    issue_number: issueNumber,
    status: 'unknown',
    summary: 'closure proof is incomplete',
    evidence_json: JSON.stringify({
      proofAnalyzerVersion: analysisVersions.CLOSURE_PROOF_ANALYZER_VERSION,
    }),
  });
  db.replaceReleaseClosureDependencySnapshot(
    db.releaseClosureDependencyIdentity('v-target', [issueNumber]),
  );

  const sourceIdentity = db.classifierSourceIdentity(['v-target'], llm.PROMPT_VERSION);
  const promptInput = llm.__llmTest.buildClassifierPromptInput({
    number: issueNumber,
    state: 'closed',
    title: issueTitle,
    body: issueBody,
    user: { login: 'reporter' },
    created_at: createdAt,
    updated_at: closedAt,
    closed_at: closedAt,
    html_url: 'https://example.test/issues/' + issueNumber,
    comments: comments.length,
    labels: [{ name: 'bug' }],
  }, comments, ['v-target']);
  const rawModelOutput = JSON.stringify({
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affected_users: 'many',
    workaroundStatus: 'none',
    duplicateCluster: null,
    affectsVersion: 'v-target',
    evidence: {
      sentiment: [{ source_id: 'issue:body', excerpt: 'fails' }],
      severity: [{ source_id: 'issue:body', excerpt: 'fails during startup' }],
      scope: [{ source_id: 'issue:body', excerpt: 'default installs' }],
      functionality: [{ source_id: 'issue:body', excerpt: 'core gateway' }],
      affected_users: [{ source_id: 'issue:body', excerpt: 'many default installs' }],
      workaroundStatus: [{ source_id: 'issue:body', excerpt: 'No workaround exists.' }],
      duplicateCluster: [],
      affectsVersion: [{ source_id: 'issue:body', excerpt: 'v-target' }],
    },
    rationale: 'The cited issue body supports every persisted non-default classification field.',
  });
  const classification = llm.__llmTest.parseRawClassification(
    rawModelOutput,
    promptInput.inputTruncation.knownTags.includedValues,
    promptInput.groundingSources,
    promptInput.inputTruncation,
  );
  const provenance = {
    schemaVersion: 2,
    responseId: 'chatcmpl-fixture-' + issueNumber,
    requestedModel: sourceIdentity.model,
    responseModel: sourceIdentity.model,
    requestedServiceTier: sourceIdentity.serviceTier,
    responseServiceTier: sourceIdentity.serviceTier,
    reasoningEffort: sourceIdentity.reasoningEffort,
    promptVersion: llm.PROMPT_VERSION,
    promptTemplateHash: llm.CLASSIFICATION_PROMPT_TEMPLATE_HASH,
    promptHash: 'a'.repeat(64),
    rawModelOutputHash: createHash('sha256').update(rawModelOutput).digest('hex'),
    rawModelOutput,
    groundingSources: promptInput.groundingSources,
    groundingSourcesHash: createHash('sha256')
      .update(operationReceipts.canonicalJson(promptInput.groundingSources))
      .digest('hex'),
    inputTruncation: promptInput.inputTruncation,
  };
  const requestHash = createHash('sha256')
    .update('calibration-request-' + issueNumber)
    .digest('hex');
  const attemptRun = classifierLedger.createClassifierAttemptRun({
    runId: 'calibration-classifier-run-' + issueNumber,
    issueNumber,
    startedAt: '2026-06-10T23:00:00.000Z',
    maxAttempts: 1,
    classifierIdentityHash: sourceIdentity.promptTemplateHash,
    requestHash,
  });
  const rawResponse = JSON.stringify({
    id: provenance.responseId,
    model: provenance.responseModel,
    service_tier: provenance.responseServiceTier,
    choices: [{ message: { content: rawModelOutput } }],
  });
  const attempt = classifierLedger.appendClassifierAttempt(attemptRun, [], {
    attemptId: 'calibration-classifier-attempt-' + issueNumber,
    status: 'accepted_success',
    startedAt: '2026-06-10T23:00:00.000Z',
    finishedAt: '2026-06-10T23:00:01.000Z',
    rawResponse: classifierLedger.captureClassifierRawResponse(rawResponse),
    rawModelOutput:
      classifierLedger.captureClassifierRawModelOutput(rawModelOutput),
    error: null,
    retry: {
      decision: 'stop',
      retryable: false,
      delayMs: null,
      reason: 'accepted_success',
    },
    semanticDiagnostics: [],
    provenance: {
      requestHash,
      responseId: provenance.responseId,
      responseModel: provenance.responseModel,
      responseServiceTier: provenance.responseServiceTier,
    },
  });
  const receipt = classifierLedger.createClassifierAttemptTerminalReceipt(
    attemptRun,
    [attempt],
    {
      receiptId: 'calibration-classifier-receipt-' + issueNumber,
      status: 'accepted_success',
      finishedAt: '2026-06-10T23:00:02.000Z',
      error: null,
    },
  );
  const ledger = classifierLedger.createClassifierAttemptLedger(
    attemptRun,
    [attempt],
    receipt,
  );
  db.recordClassifierAttemptRun(attemptRun);
  db.recordClassifierAttempt(attempt);
  db.recordClassifierAttemptTerminalReceipt(receipt);
  const evidenceRevisions = db.issueEvidenceRevisions([issueNumber]).get(issueNumber);
  assert.ok(evidenceRevisions);
  assert.ok(receipt.selectedAttempt);
  db.upsertClassification(
    issueNumber,
    { ...classification, provenance },
    closedAt,
    llm.PROMPT_VERSION,
    commentsDigest,
    sourceIdentity,
    {
      ledger,
      selectedAttemptBinding: receipt.selectedAttempt,
      evidenceRevisions: {
        issueRevision: evidenceRevisions.issueRevision,
        snapshotRevision: evidenceRevisions.snapshotRevision,
        stateSnapshotRevision: evidenceRevisions.stateSnapshotRevision,
      },
    },
  );

  const run = scoring.buildReleaseScoreRun({
    releases: [db.getRelease('v-target')],
    oldestScoredStablePredecessorTag: 'v-prev',
    nowForRelease: () => Date.parse('2026-06-11T00:00:00Z'),
  });
  const scored = run.scored[0];
  assert.equal(scored.analysisCompleteness.complete, false);
  assert.deepEqual(
    scored.analysisCompleteness.missingClosureEvidence.map((row) => ({
      issueNumber: row.issueNumber,
      status: row.status,
    })),
    [{ issueNumber, status: 'unknown' }],
  );
  assert.equal(scored.input.unresolvedClosureRiskWeight, 0);
  assert.equal(scored.input.affirmativeClosureRiskCeilingWeight, 0);
  assert.equal(scored.input.unresolvedClosureIssueCount, 0);
  assert.equal(Math.abs(scored.conf.components?.closureRisk ?? NaN), 0);
  assert.equal(scored.conf.components?.closureRiskCeiling, 0);
  assert.throws(
    () => scoring.persistReleaseScoreRun(run),
    /v-target closure analysis is incomplete: score-affecting negative missing_evidence row #99001 status=unknown/,
  );
  assert.equal(db.getRelease('v-target')?.final_score, null);

  const declaredIncomplete = scoring.currentScoreCompletenessDiagnostic({
    tag: 'v-target',
    analysisCompleteness: {
      complete: false,
      missingClosureEvidence: [],
    },
    currentMissingClosureEvidence: [],
  });
  assert.equal(declaredIncomplete.complete, false);
  assert.match(
    declaredIncomplete.problems.join('; '),
    /analysisCompleteness\.complete must be true/,
  );

  const recommended = run.recommendedTag === scored.rel.tag ? 1 : 0;
  db.updateReleaseScore({
    tag: scored.rel.tag,
    final_score: scored.conf.score,
    negative_issues: scored.neg,
    positive_issues: scored.pos,
    state: scored.conf.status,
    recommended,
    score_reason: scored.conf.reason,
    broken_surfaces: scored.brokenSurfaces,
    closed_serious_fixed: scored.closedSerious,
    opened_serious_during_reign: scored.openedSerious,
    scored_at: scored.scoredAt,
  });
  db.upsertReleaseScoreAudit({
    release_tag: scored.rel.tag,
    scored_at: scored.scoredAt,
    score_model_version: scoring.SCORE_MODEL_VERSION,
    prompt_version: scoring.PROMPT_VERSION,
    final_score: scored.conf.score,
    status: scored.conf.status,
    band: scored.conf.band,
    recommended,
    input_json: JSON.stringify(scored.input),
    components_json: JSON.stringify({
      schemaVersion: scoring.SCORE_COMPONENTS_SCHEMA_VERSION,
      components: scored.conf.components,
      evidenceCoverage: scored.conf.evidenceCoverage,
      hotfix: scored.conf.hotfix,
      reason: scored.conf.reason,
      explanation: scored.explanation,
      recommendationDecision: scored.recommendationDecision,
    }),
    issue_evidence_json: JSON.stringify(scored.debtEvidence),
    gate_evidence_json: JSON.stringify(scored.gateEvidence),
    source_identity_json: JSON.stringify(run.sourceIdentity),
  });
  db.db.close();
  const verifier = spawnSync(
    process.execPath,
    ['--import', 'tsx', 'scripts/verify-new-scoring.mjs', '--all'],
    {
      cwd: process.cwd(),
      env: {
        ...process.env,
        RADAR_DB_BOOTSTRAP_MODE: 'existing',
      },
      encoding: 'utf8',
    },
  );
  assert.notEqual(verifier.status, 0);
  assert.match(
    verifier.stdout + '\n' + verifier.stderr,
    /score result analysisCompleteness\.complete must be true|score-affecting negative missing_evidence/,
  );
  console.log('CALIBRATION_OK');
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
`;
