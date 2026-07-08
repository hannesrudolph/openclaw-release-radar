import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { describe, it } from 'node:test';
import {
  CLASSIFIER_ERROR_MESSAGE_MAX_BYTES,
  CLASSIFIER_RAW_RESPONSE_MAX_BYTES,
  CLASSIFIER_SEMANTIC_DIAGNOSTIC_MESSAGE_MAX_BYTES,
  CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MAX_COUNT,
  CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MESSAGE_MAX_BYTES,
  appendClassifierAttempt,
  CLASSIFIER_MODEL_CORRECTABLE_GROUNDING_DIAGNOSTIC_CODES,
  canonicalClassifierAttemptLedgerJson,
  captureClassifierError,
  captureClassifierRawModelOutput,
  captureClassifierRawResponse,
  captureClassifierSemanticDiagnostics,
  classifierAttemptContentHash,
  classifierAttemptProvenanceHash,
  classifierAttemptRunContentHash,
  classifierAttemptTerminalReceiptContentHash,
  createClassifierAttemptLedger,
  createClassifierAttemptRun,
  createClassifierAttemptTerminalReceipt,
  isEligibleClassifierGroundingSemanticRetry,
  normalizeOpenAIClassifierUsage,
  validateClassifierAttempt,
  validateClassifierAttemptRun,
  validateClassifierAttemptTerminalReceipt,
  verifyClassifierAttemptLedger,
  type ClassifierAttempt,
  type ClassifierAttemptLedger,
  type ClassifierAttemptProvenance,
} from './classifierAttemptLedger';

const REQUEST_HASH = hash('classifier-request');
const SEMANTIC_RETRY_REQUEST_HASH = hash(
  'classifier-request-with-semantic-feedback',
);
const CLASSIFIER_IDENTITY_HASH = hash('classifier-identity');

describe('classifier attempt ledger', () => {
  it('builds a canonical immutable multi-attempt success with transport and semantic retries', () => {
    const ledger = successfulLedger();
    const verification = verifyClassifierAttemptLedger(ledger);

    assert.equal(verification.valid, true, problemText(verification.problems));
    assert.equal(verification.attemptCount, 3);
    assert.equal(verification.terminalStatus, 'accepted_success');
    assert.equal(verification.chainTipHash, ledger.receipt.contentHash);
    assert.deepEqual(
      ledger.attempts.map((attempt) => attempt.status),
      ['transport_failure', 'semantic_rejection', 'accepted_success'],
    );
    assert.equal(ledger.attempts[0].previousContentHash, ledger.run.contentHash);
    assert.equal(
      ledger.attempts[1].previousContentHash,
      ledger.attempts[0].contentHash,
    );
    assert.equal(
      ledger.attempts[2].previousContentHash,
      ledger.attempts[1].contentHash,
    );
    assert.equal(
      ledger.receipt.selectedAttempt?.attemptContentHash,
      ledger.attempts[2].contentHash,
    );
    assert.equal(
      ledger.receipt.selectedAttempt?.rawResponseHash,
      ledger.attempts[2].rawResponse?.fullContentHash,
    );
    assert.equal(
      ledger.receipt.selectedAttempt?.rawModelOutputHash,
      ledger.attempts[2].rawModelOutput?.fullContentHash,
    );
    assert.deepEqual(
      ledger.receipt.selectedAttempt?.provenance,
      ledger.attempts[2].provenance,
    );
    assert.equal(
      ledger.receipt.selectedAttempt?.provenanceHash,
      ledger.attempts[2].provenanceHash,
    );
    assert.deepEqual(
      ledger.attempts.map((attempt) => attempt.durationMs),
      [1_000, 1_000, 1_000],
    );
    assert.deepEqual(
      ledger.attempts.map((attempt) => attempt.retry.decision),
      ['retry', 'retry', 'stop'],
    );
    assert.equal(ledger.attempts[0].retry.delayMs, 250);
    assert.equal(
      ledger.attempts[1].semanticDiagnostics[0]?.code,
      'missing_support',
    );
    assert.equal(
      isEligibleClassifierGroundingSemanticRetry(ledger.attempts[1]),
      true,
    );
    assert.equal(ledger.run.requestHash, REQUEST_HASH);
    assert.deepEqual(
      ledger.attempts.map((attempt) => attempt.provenance.requestHash),
      [REQUEST_HASH, REQUEST_HASH, SEMANTIC_RETRY_REQUEST_HASH],
    );
    assert.equal(
      ledger.receipt.selectedAttempt?.provenance.requestHash,
      SEMANTIC_RETRY_REQUEST_HASH,
    );
    assert.equal(Object.isFrozen(ledger), true);
    assert.equal(Object.isFrozen(ledger.attempts), true);
    assert.equal(Object.isFrozen(ledger.attempts[2].provenance), true);

    assert.deepEqual(validateClassifierAttemptRun(ledger.run), ledger.run);
    assert.deepEqual(validateClassifierAttempt(ledger.attempts[2]), ledger.attempts[2]);
    assert.deepEqual(
      validateClassifierAttemptTerminalReceipt(ledger.receipt),
      ledger.receipt,
    );
  });

  it('creates bounded raw-response and error captures with full and retained hashes', () => {
    const raw = '😀'.repeat(Math.ceil(CLASSIFIER_RAW_RESPONSE_MAX_BYTES / 4) + 2);
    const captured = captureClassifierRawResponse(raw);

    assert.equal(captured.truncated, true);
    assert.equal(captured.originalByteLength, Buffer.byteLength(raw, 'utf8'));
    assert.ok(Buffer.byteLength(captured.text, 'utf8') <=
      CLASSIFIER_RAW_RESPONSE_MAX_BYTES);
    assert.equal(captured.fullContentHash, hash(raw));
    assert.equal(captured.retainedContentHash, hash(captured.text));
    assert.equal(Object.isFrozen(captured), true);

    const error = captureClassifierError({
      name: 'TransportError',
      code: 'ETIMEDOUT',
      message: 'x'.repeat(CLASSIFIER_ERROR_MESSAGE_MAX_BYTES + 1),
    });
    assert.equal(error.name, 'TransportError');
    assert.equal(error.code, 'ETIMEDOUT');
    assert.equal(error.message.truncated, true);
    assert.ok(Buffer.byteLength(error.message.text, 'utf8') <=
      CLASSIFIER_ERROR_MESSAGE_MAX_BYTES);
    assert.equal(error.message.retainedContentHash, hash(error.message.text));

    const ledger = successfulLedger();
    const tampered = clone(ledger);
    tampered.attempts[1].rawResponse.retainedContentHash = hash('different');
    assertInvalid(tampered, /retainedContentHash|contentHash/);
  });

  it('requires complete independently verifiable accepted response evidence', () => {
    const ledger = successfulLedger();
    const accepted = ledger.attempts[2];
    assert.equal(accepted.rawResponse?.truncated, false);
    assert.equal(accepted.rawModelOutput?.truncated, false);
    assert.equal(
      accepted.rawModelOutput?.fullContentHash,
      hash(accepted.rawModelOutput?.text ?? ''),
    );

    const truncated = clone(ledger);
    const original = truncated.attempts[2].rawResponse;
    original.text = original.text.slice(0, -1);
    original.originalByteLength += 10;
    original.truncated = true;
    original.retainedContentHash = hash(original.text);
    resealLedger(truncated);
    assertInvalid(
      truncated,
      /accepted_success requires a complete rawResponse/,
    );

    const forgedOutput = clone(ledger);
    const output = forgedOutput.attempts[2].rawModelOutput;
    output.text = output.text.slice(0, -1);
    output.originalByteLength += 10;
    output.truncated = true;
    output.retainedContentHash = hash(output.text);
    resealLedger(forgedOutput);
    assertInvalid(
      forgedOutput,
      /accepted_success requires complete rawModelOutput/,
    );
  });

  it('binds completed semantic rejections to provider response evidence', () => {
    const ledger = successfulLedger();
    const rejected = ledger.attempts[1];
    assert.equal(rejected.rawResponse?.truncated, false);
    assert.equal(rejected.rawModelOutput?.truncated, false);

    const forgedOutput = clone(ledger);
    const output = forgedOutput.attempts[1].rawModelOutput;
    output.text = '{"severity":"forged"}';
    output.originalByteLength = Buffer.byteLength(output.text, 'utf8');
    output.retainedContentHash = hash(output.text);
    output.fullContentHash = hash(output.text);
    resealLedger(forgedOutput);
    assertInvalid(
      forgedOutput,
      /rawModelOutput does not match the retained assistant message/,
    );

    const forgedProvenance = clone(ledger);
    forgedProvenance.attempts[1].provenance.responseId = 'forged-response';
    resealLedger(forgedProvenance);
    assertInvalid(
      forgedProvenance,
      /responseId does not match rawResponse\.id/,
    );

    const missingOutput = clone(ledger);
    missingOutput.attempts[1].rawModelOutput = null;
    resealLedger(missingOutput);
    assertInvalid(
      missingOutput,
      /requires rawModelOutput for assistant message content/,
    );
  });

  it('normalizes provider usage and leaves unpriced cost indeterminate', () => {
    assert.deepEqual(
      normalizeOpenAIClassifierUsage({
        prompt_tokens: 100,
        completion_tokens: 40,
        total_tokens: 140,
        prompt_tokens_details: { cached_tokens: 25 },
        completion_tokens_details: { reasoning_tokens: 12 },
      }),
      {
        provider: 'openai',
        inputTokens: 100,
        outputTokens: 40,
        totalTokens: 140,
        cachedInputTokens: 25,
        reasoningTokens: 12,
      },
    );
    assert.throws(
      () => normalizeOpenAIClassifierUsage({ total_tokens: -1 }),
      /non-negative safe integer/,
    );

    const ledger = successfulLedger();
    assert.equal(ledger.attempts[2].cost.confidence, 'indeterminate');
    assert.equal(ledger.attempts[2].cost.amountMicrounits, null);
  });

  it('accepts terminal failure after transport and semantic failures', () => {
    const run = runFixture('run-terminal-failure', 2);
    const first = appendClassifierAttempt(run, [], {
      attemptId: 'failure-attempt-1',
      status: 'transport_failure',
      startedAt: time(1),
      finishedAt: time(2),
      rawResponse: null,
      error: captureClassifierError(new Error('socket reset')),
      retry: retryMetadata(250, 'retryable_transport_failure'),
      semanticDiagnostics: [],
      provenance: transportProvenance(),
    });
    const second = appendClassifierAttempt(run, [first], {
      attemptId: 'failure-attempt-2',
      status: 'semantic_rejection',
      startedAt: time(3),
      finishedAt: time(4),
      rawResponse: acceptedRawResponse(
        'response-failure-2',
        '{"severity":"impossible"}',
      ),
      rawModelOutput: captureClassifierRawModelOutput(
        '{"severity":"impossible"}',
      ),
      error: captureClassifierError(new Error('semantic validation failed')),
      retry: stopMetadata(false, 'deterministic_semantic_rejection'),
      semanticDiagnostics: semanticDiagnostics(
        'severity',
        'schema_value_rejection',
        'severity is not recognized',
      ),
      provenance: responseProvenance('response-failure-2'),
    });
    const receipt = createClassifierAttemptTerminalReceipt(run, [first, second], {
      receiptId: 'receipt-terminal-failure',
      status: 'terminal_failure',
      finishedAt: time(5),
      error: captureClassifierError(new Error('attempt budget exhausted')),
    });
    const ledger = createClassifierAttemptLedger(run, [first, second], receipt);

    assert.equal(verifyClassifierAttemptLedger(ledger).valid, true);
    assert.equal(receipt.selectedAttempt, null);
    assert.equal(receipt.status, 'terminal_failure');
  });

  it('accepts explicit abandonment with or without prior failed attempts', () => {
    const emptyRun = runFixture('run-abandoned-empty', 3);
    const emptyReceipt = createClassifierAttemptTerminalReceipt(emptyRun, [], {
      receiptId: 'receipt-abandoned-empty',
      status: 'abandoned',
      finishedAt: time(1),
      error: captureClassifierError(new Error('caller cancelled')),
    });
    assert.equal(
      verifyClassifierAttemptLedger(
        createClassifierAttemptLedger(emptyRun, [], emptyReceipt),
      ).valid,
      true,
    );

    const attemptedRun = runFixture('run-abandoned-attempted', 3);
    const attempt = appendClassifierAttempt(attemptedRun, [], {
      attemptId: 'abandoned-attempt-1',
      status: 'transport_failure',
      startedAt: time(1),
      finishedAt: time(2),
      rawResponse: null,
      error: captureClassifierError(new Error('temporary outage')),
      retry: retryMetadata(100, 'retryable_transport_failure'),
      semanticDiagnostics: [],
      provenance: transportProvenance(),
    });
    const receipt = createClassifierAttemptTerminalReceipt(
      attemptedRun,
      [attempt],
      {
        receiptId: 'receipt-abandoned-attempted',
        status: 'abandoned',
        finishedAt: time(3),
        error: captureClassifierError(new Error('shutdown requested')),
      },
    );
    assert.equal(
      verifyClassifierAttemptLedger(
        createClassifierAttemptLedger(attemptedRun, [attempt], receipt),
      ).valid,
      true,
    );
  });

  it('detects tampering, reordering, deletion, and receipt removal', () => {
    const ledger = successfulLedger();

    const tampered = clone(ledger);
    tampered.attempts[1].rawResponse.text = '{"tampered":true}';
    assertInvalid(tampered, /retainedContentHash|contentHash/);

    const reordered = clone(ledger);
    [reordered.attempts[0], reordered.attempts[1]] =
      [reordered.attempts[1], reordered.attempts[0]];
    assertInvalid(reordered, /ordinal|append chain|contentHash/);

    const deleted = clone(ledger);
    deleted.attempts.splice(1, 1);
    assertInvalid(deleted, /ordinal|append chain|attemptCount|chain tip/);

    const missingReceipt = clone(ledger) as Record<string, unknown>;
    delete missingReceipt.receipt;
    assertInvalid(missingReceipt, /missing fields: receipt|receipt must be/);
  });

  it('rejects duplicate attempt ordinals and IDs even when hashes are resealed', () => {
    const duplicateOrdinal = clone(successfulLedger());
    duplicateOrdinal.attempts[1].ordinal = duplicateOrdinal.attempts[0].ordinal;
    resealLedger(duplicateOrdinal);
    assertInvalid(duplicateOrdinal, /ordinal must equal 2/);

    const duplicateId = clone(successfulLedger());
    duplicateId.attempts[1].attemptId = duplicateId.attempts[0].attemptId;
    resealLedger(duplicateId);
    assertInvalid(duplicateId, /attemptId duplicates/);
  });

  it('rejects cross-run, cross-issue, and request provenance mismatches', () => {
    const foreignRun = clone(successfulLedger());
    foreignRun.attempts[1].runId = 'foreign-run';
    resealLedger(foreignRun);
    assertInvalid(foreignRun, /runId does not match/);

    const foreignIssue = clone(successfulLedger());
    foreignIssue.attempts[1].issueNumber = 999_999;
    resealLedger(foreignIssue);
    assertInvalid(foreignIssue, /issueNumber does not match/);

    const foreignReceipt = clone(successfulLedger());
    foreignReceipt.receipt.runId = 'foreign-run';
    rehashReceipt(foreignReceipt);
    assertInvalid(foreignReceipt, /receipt\.runId does not match/);
  });

  it('rejects request-hash changes after transport or arbitrary retries', () => {
    const transportTransition = clone(successfulLedger());
    transportTransition.attempts[1].provenance.requestHash =
      hash('transport-transition');
    resealLedger(transportTransition);
    assertInvalid(
      transportTransition,
      /requestHash changed without an immediately preceding eligible grounding semantic retry/,
    );

    const arbitraryTransition = clone(successfulLedger());
    arbitraryTransition.attempts[1].retry = {
      decision: 'stop',
      retryable: true,
      delayMs: null,
      reason: 'attempt_budget_exhausted',
    };
    resealLedger(arbitraryTransition);
    assertInvalid(
      arbitraryTransition,
      /requestHash changed without an immediately preceding eligible grounding semantic retry/,
    );

    const unchangedSemanticTransition = clone(successfulLedger());
    unchangedSemanticTransition.attempts[2].provenance.requestHash =
      unchangedSemanticTransition.attempts[1].provenance.requestHash;
    resealLedger(unchangedSemanticTransition);
    assertInvalid(
      unchangedSemanticTransition,
      /requestHash must change after an immediately preceding eligible grounding semantic retry/,
    );

    const initialMismatch = clone(successfulLedger());
    initialMismatch.attempts[0].provenance.requestHash =
      hash('not-the-initial-request');
    resealLedger(initialMismatch);
    assertInvalid(initialMismatch, /does not match the initial run\.requestHash/);
  });

  it('rejects duplicate, schema, generic-error, and exhausted retry claims', () => {
    assert.deepEqual(
      CLASSIFIER_MODEL_CORRECTABLE_GROUNDING_DIAGNOSTIC_CODES,
      [
        'abstention_has_citations',
        'cross_field_citation_reuse',
        'duplicate_citation',
        'excerpt_not_exact',
        'excerpt_not_field_relevant',
        'missing_support',
        'source_id_not_included',
        'unsupported_affects_version',
        'unsupported_duplicate_cluster',
        'unsupported_workaround_status',
      ],
    );

    const duplicateSource = clone(successfulLedger());
    duplicateSource.attempts[1].semanticDiagnostics[0].code =
      'duplicate_source_id';
    resealLedger(duplicateSource);
    assertInvalid(
      duplicateSource,
      /duplicate_source_id cannot authorize a semantic retry/,
    );

    const schemaFailure = clone(successfulLedger());
    schemaFailure.attempts[1].semanticDiagnostics[0].code =
      'schema_shape_rejection';
    resealLedger(schemaFailure);
    assertInvalid(schemaFailure, /is not a model-correctable grounding failure/);

    const relabeledSchemaFailure = clone(successfulLedger());
    replaceAttemptRawModelOutput(
      relabeledSchemaFailure.attempts[1],
      '{"severity":"extreme"}',
    );
    resealLedger(relabeledSchemaFailure);
    assertInvalid(
      relabeledSchemaFailure,
      /rawModelOutput\.text.*classifier JSON|missing fields/,
    );

    const invalidUsage = clone(successfulLedger());
    const invalidUsageResponse = JSON.parse(
      invalidUsage.attempts[1].rawResponse.text,
    );
    invalidUsageResponse.usage = { prompt_tokens: -1 };
    invalidUsage.attempts[1].rawResponse =
      captureClassifierRawResponse(JSON.stringify(invalidUsageResponse));
    resealLedger(invalidUsage);
    assertInvalid(
      invalidUsage,
      /semantic retry requires verifiable provider usage/,
    );

    const delayedRetry = clone(successfulLedger());
    delayedRetry.attempts[1].retry.delayMs = 1;
    resealLedger(delayedRetry);
    assertInvalid(delayedRetry, /semantic retry requires delayMs=0/);

    const oversizedDiagnostic = clone(successfulLedger());
    oversizedDiagnostic.attempts[1].semanticDiagnostics =
      captureClassifierSemanticDiagnostics([{
        field: 'severity',
        code: 'missing_support',
        message: 'x'.repeat(
          CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MESSAGE_MAX_BYTES + 1,
        ),
      }]);
    resealLedger(oversizedDiagnostic);
    assertInvalid(
      oversizedDiagnostic,
      /message exceeds the semantic retry feedback limit/,
    );

    const excessiveDiagnostics = clone(successfulLedger());
    excessiveDiagnostics.attempts[1].semanticDiagnostics =
      captureClassifierSemanticDiagnostics(Array.from(
        { length: CLASSIFIER_SEMANTIC_RETRY_DIAGNOSTIC_MAX_COUNT + 1 },
        (_, index) => ({
          field: 'severity',
          code: 'missing_support',
          message: `missing support ${index}`,
        }),
      ));
    resealLedger(excessiveDiagnostics);
    assertInvalid(
      excessiveDiagnostics,
      /semantic retry diagnostics exceed the feedback limit/,
    );

    const genericError = clone(successfulLedger());
    genericError.attempts[1].error.name = 'Error';
    resealLedger(genericError);
    assertInvalid(
      genericError,
      /semantic retry requires an uncoded ClassificationGroundingError/,
    );

    const exhausted = clone(successfulLedger());
    exhausted.run.maxAttempts = 2;
    exhausted.attempts.splice(2, 1);
    exhausted.receipt.status = 'terminal_failure';
    exhausted.receipt.reason = 'attempt_budget_exhausted';
    exhausted.receipt.selectedAttempt = null;
    exhausted.receipt.error = captureClassifierError(
      new Error('attempt budget exhausted'),
    );
    resealLedger(exhausted);
    assertInvalid(exhausted, /retry cannot exceed the run attempt budget/);

    const prematureExhaustion = clone(successfulLedger());
    prematureExhaustion.attempts.splice(2, 1);
    prematureExhaustion.attempts[1].retry =
      stopMetadata(true, 'attempt_budget_exhausted');
    prematureExhaustion.receipt.status = 'terminal_failure';
    prematureExhaustion.receipt.reason = 'attempt_budget_exhausted';
    prematureExhaustion.receipt.selectedAttempt = null;
    prematureExhaustion.receipt.error = captureClassifierError(
      new Error('attempt budget exhausted'),
    );
    resealLedger(prematureExhaustion);
    assertInvalid(
      prematureExhaustion,
      /attempt_budget_exhausted is only valid at run\.maxAttempts/,
    );
  });

  it('rejects independently resealed selected attempt, raw, and provenance bindings', () => {
    const cases: Array<[keyof NonNullable<
      ClassifierAttemptLedger['receipt']['selectedAttempt']
    >, RegExp]> = [
      ['attemptContentHash', /attemptContentHash does not bind/],
      ['rawResponseHash', /rawResponseHash does not bind/],
      ['rawModelOutputHash', /rawModelOutputHash does not bind/],
      ['provenanceHash', /provenanceHash does not (?:bind|match)/],
    ];

    for (const [field, expected] of cases) {
      const ledger = clone(successfulLedger());
      ledger.receipt.selectedAttempt[field] = hash(`wrong-${field}`) as never;
      rehashReceipt(ledger);
      assertInvalid(ledger, expected);
    }

    const wrongSelectedId = clone(successfulLedger());
    wrongSelectedId.receipt.selectedAttempt.attemptId =
      wrongSelectedId.attempts[1].attemptId;
    rehashReceipt(wrongSelectedId);
    assertInvalid(wrongSelectedId, /attemptId does not bind/);

    const wrongProvenance = clone(successfulLedger());
    wrongProvenance.receipt.selectedAttempt.provenance.responseId = 'forged-id';
    wrongProvenance.receipt.selectedAttempt.provenanceHash =
      classifierAttemptProvenanceHash(
        wrongProvenance.receipt.selectedAttempt.provenance,
      );
    rehashReceipt(wrongProvenance);
    assertInvalid(wrongProvenance, /provenance does not bind/);
  });

  it('rejects invalid, non-canonical, reversed, and non-finite timestamps', () => {
    const variants = [
      mutate(successfulLedger(), (ledger) => {
        ledger.run.startedAt = '2026-07-04T00:00:00Z';
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[0].startedAt = Number.NaN;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[1].finishedAt = time(2);
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.receipt.finishedAt = Number.POSITIVE_INFINITY;
      }),
    ];
    for (const variant of variants) {
      assert.doesNotThrow(() => verifyClassifierAttemptLedger(variant));
      assertInvalid(variant, /timestamp|precede|contentHash/);
    }

    assert.throws(
      () => canonicalClassifierAttemptLedgerJson({ value: Number.NaN }),
      /non-finite/,
    );
    assert.throws(
      () => canonicalClassifierAttemptLedgerJson({ value: Number.POSITIVE_INFINITY }),
      /non-finite/,
    );
  });

  it('rejects unknown fields throughout the strict contract', () => {
    const variants = [
      mutate(successfulLedger(), (ledger) => {
        ledger.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.run.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[0].unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[0].retry.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[1].semanticDiagnostics[0].unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[0].error.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[1].rawResponse.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[2].rawModelOutput.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[2].provenance.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.attempts[2].cost.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.receipt.unknown = true;
      }),
      mutate(successfulLedger(), (ledger) => {
        ledger.receipt.selectedAttempt.unknown = true;
      }),
    ];

    for (const variant of variants) {
      assertInvalid(variant, /unknown fields: unknown/);
    }
  });

  it('enforces status semantics, attempt budget, and success finality', () => {
    const run = runFixture('run-status-semantics', 2);
    assert.throws(
      () => appendClassifierAttempt(run, [], {
        attemptId: 'transport-without-error',
        status: 'transport_failure',
        startedAt: time(1),
        finishedAt: time(2),
        rawResponse: null,
        error: null,
        retry: stopMetadata(false, 'non_retryable_transport_failure'),
        semanticDiagnostics: [],
        provenance: transportProvenance(),
      }),
      /transport_failure requires an error/,
    );
    assert.throws(
      () => appendClassifierAttempt(run, [], {
        attemptId: 'semantic-without-raw',
        status: 'semantic_rejection',
        startedAt: time(1),
        finishedAt: time(2),
        rawResponse: null,
        error: captureClassifierError(new Error('bad response')),
        retry: stopMetadata(true, 'attempt_budget_exhausted'),
        semanticDiagnostics: semanticDiagnostics(
          null,
          'missing_raw_response',
          'raw response is required',
        ),
        provenance: responseProvenance('response-semantic'),
      }),
      /semantic_rejection requires a rawResponse/,
    );
    assert.throws(
      () => appendClassifierAttempt(run, [], {
        attemptId: 'success-with-error',
        status: 'accepted_success',
        startedAt: time(1),
        finishedAt: time(2),
        rawResponse: acceptedRawResponse('response-success', '{"ok":true}'),
        rawModelOutput: captureClassifierRawModelOutput('{"ok":true}'),
        error: captureClassifierError(new Error('not allowed')),
        retry: stopMetadata(false, 'accepted_success'),
        semanticDiagnostics: [],
        provenance: responseProvenance('response-success'),
      }),
      /accepted_success cannot include an error/,
    );

    const success = appendClassifierAttempt(run, [], {
      attemptId: 'success-final',
      status: 'accepted_success',
      startedAt: time(1),
      finishedAt: time(2),
      rawResponse: acceptedRawResponse(
        'response-success-final',
        '{"ok":true}',
      ),
      rawModelOutput: captureClassifierRawModelOutput('{"ok":true}'),
      error: null,
      retry: stopMetadata(false, 'accepted_success'),
      semanticDiagnostics: [],
      provenance: responseProvenance('response-success-final'),
    });
    assert.throws(
      () => appendClassifierAttempt(run, [success], {
        attemptId: 'after-success',
        status: 'transport_failure',
        startedAt: time(3),
        finishedAt: time(4),
        rawResponse: null,
        error: captureClassifierError(new Error('late retry')),
        retry: stopMetadata(false, 'late_failure'),
        semanticDiagnostics: [],
        provenance: transportProvenance(),
      }),
      /cannot follow accepted_success/,
    );

    const budgetRun = runFixture('run-attempt-budget', 1);
    const failed = appendClassifierAttempt(budgetRun, [], {
      attemptId: 'budget-attempt-1',
      status: 'transport_failure',
      startedAt: time(1),
      finishedAt: time(2),
      rawResponse: null,
      error: captureClassifierError(new Error('temporary failure')),
      retry: stopMetadata(true, 'attempt_budget_exhausted'),
      semanticDiagnostics: [],
      provenance: transportProvenance(),
    });
    assert.throws(
      () => appendClassifierAttempt(budgetRun, [failed], {
        attemptId: 'budget-attempt-2',
        status: 'transport_failure',
        startedAt: time(3),
        finishedAt: time(4),
        rawResponse: null,
        error: captureClassifierError(new Error('over budget')),
        retry: stopMetadata(true, 'attempt_budget_exhausted'),
        semanticDiagnostics: [],
        provenance: transportProvenance(),
      }),
      /exceeds run\.maxAttempts/,
    );
  });

  it('enforces duration, retry metadata, and bounded semantic diagnostics', () => {
    const invalidDuration = clone(successfulLedger());
    invalidDuration.attempts[0].durationMs = 999;
    resealLedger(invalidDuration);
    assertInvalid(invalidDuration, /durationMs must equal/);

    const invalidRetry = clone(successfulLedger());
    invalidRetry.attempts[0].retry.decision = 'stop';
    invalidRetry.attempts[0].retry.delayMs = 250;
    resealLedger(invalidRetry);
    assertInvalid(invalidRetry, /stop decision requires delayMs=null|before a later attempt/);

    const missingDiagnostics = clone(successfulLedger());
    missingDiagnostics.attempts[1].semanticDiagnostics = [];
    resealLedger(missingDiagnostics);
    assertInvalid(missingDiagnostics, /requires semantic diagnostics/);

    const longMessage = 'x'.repeat(10_000);
    const captured = captureClassifierSemanticDiagnostics([{
      field: 'severity',
      code: 'invalid_enum',
      message: longMessage,
      citationIndex: 2,
      sourceId: 'issue:body',
    }]);
    assert.equal(captured[0].message.truncated, true);
    assert.equal(captured[0].message.fullContentHash, hash(longMessage));
    assert.equal(captured[0].citationIndex, 2);
    assert.equal(Object.isFrozen(captured), true);
  });

  it('canonicalizes object keys and rejects unsupported JSON values', () => {
    assert.equal(
      canonicalClassifierAttemptLedgerJson({
        z: 1,
        a: { d: 4, c: [3, { b: 2, a: 1 }] },
      }),
      '{"a":{"c":[3,{"a":1,"b":2}],"d":4},"z":1}',
    );
    assert.equal(
      canonicalClassifierAttemptLedgerJson({ value: -0 }),
      '{"value":0}',
    );
    assert.throws(
      () => canonicalClassifierAttemptLedgerJson({ value: undefined }),
      /non-JSON/,
    );
    assert.throws(
      () => canonicalClassifierAttemptLedgerJson({ value: new Date(0) }),
      /non-JSON/,
    );
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    assert.throws(
      () => canonicalClassifierAttemptLedgerJson(cyclic),
      /cycle/,
    );
  });
});

function successfulLedger(): ClassifierAttemptLedger {
  const run = runFixture('run-success', 3);
  const first = appendClassifierAttempt(run, [], {
    attemptId: 'success-attempt-1',
    status: 'transport_failure',
    startedAt: time(1),
    finishedAt: time(2),
    rawResponse: null,
    error: captureClassifierError({
      name: 'TransportError',
      code: 'ECONNRESET',
      message: 'connection reset',
    }),
    retry: retryMetadata(250, 'retryable_transport_failure'),
    semanticDiagnostics: [],
    provenance: transportProvenance(),
  });
  const second = appendClassifierAttempt(run, [first], {
    attemptId: 'success-attempt-2',
    status: 'semantic_rejection',
    startedAt: time(3),
    finishedAt: time(4),
    rawResponse: acceptedRawResponse(
      'response-success-2',
      classifierRawOutput(),
    ),
    rawModelOutput: captureClassifierRawModelOutput(classifierRawOutput()),
    error: captureClassifierError({
      name: 'ClassificationGroundingError',
      message: 'severity requires a supporting citation',
    }),
    retry: retryMetadata(0, 'retryable_semantic_rejection'),
    semanticDiagnostics: semanticDiagnostics(
      'severity',
      'missing_support',
      'severity requires a supporting citation',
    ),
    provenance: responseProvenance('response-success-2'),
  });
  const rawModelOutput = classifierRawOutput({ severity: 'medium' });
  const third = appendClassifierAttempt(run, [first, second], {
    attemptId: 'success-attempt-3',
    status: 'accepted_success',
    startedAt: time(5),
    finishedAt: time(6),
    rawResponse: acceptedRawResponse('response-success-3', rawModelOutput),
    rawModelOutput: captureClassifierRawModelOutput(rawModelOutput),
    error: null,
    retry: stopMetadata(false, 'accepted_success'),
    semanticDiagnostics: [],
    provenance: responseProvenance(
      'response-success-3',
      SEMANTIC_RETRY_REQUEST_HASH,
    ),
  });
  const receipt = createClassifierAttemptTerminalReceipt(
    run,
    [first, second, third],
    {
      receiptId: 'receipt-success',
      status: 'accepted_success',
      finishedAt: time(7),
      error: null,
    },
  );
  return createClassifierAttemptLedger(run, [first, second, third], receipt);
}

function runFixture(runId: string, maxAttempts: number) {
  return createClassifierAttemptRun({
    runId,
    issueNumber: 42_424,
    startedAt: time(0),
    maxAttempts,
    classifierIdentityHash: CLASSIFIER_IDENTITY_HASH,
    requestHash: REQUEST_HASH,
  });
}

function transportProvenance(): ClassifierAttemptProvenance {
  return {
    requestHash: REQUEST_HASH,
    responseId: null,
    responseModel: null,
    responseServiceTier: null,
  };
}

function responseProvenance(
  responseId: string,
  requestHash = REQUEST_HASH,
): ClassifierAttemptProvenance {
  return {
    requestHash,
    responseId,
    responseModel: 'classifier-model-1',
    responseServiceTier: 'standard',
  };
}

function retryMetadata(delayMs: number, reason: string) {
  return {
    decision: 'retry' as const,
    retryable: true,
    delayMs,
    reason,
  };
}

function stopMetadata(retryable: boolean, reason: string) {
  return {
    decision: 'stop' as const,
    retryable,
    delayMs: null,
    reason,
  };
}

function semanticDiagnostics(
  field: string | null,
  code: string,
  message: string,
) {
  return captureClassifierSemanticDiagnostics([{
    field,
    code,
    message,
  }]);
}

function resealLedger(ledger: any): void {
  const { contentHash: _runHash, ...runWithoutHash } = ledger.run;
  ledger.run.contentHash = classifierAttemptRunContentHash(runWithoutHash);
  let previousContentHash = ledger.run.contentHash;
  for (const attempt of ledger.attempts as any[]) {
    attempt.provenanceHash = classifierAttemptProvenanceHash(attempt.provenance);
    attempt.previousContentHash = previousContentHash;
    const { contentHash: _attemptHash, ...attemptWithoutHash } = attempt;
    attempt.contentHash = classifierAttemptContentHash(attemptWithoutHash);
    previousContentHash = attempt.contentHash;
  }
  ledger.receipt.previousContentHash = previousContentHash;
  ledger.receipt.attemptCount = ledger.attempts.length;
  if (ledger.receipt.status === 'accepted_success') {
    const selected = ledger.attempts.find(
      (attempt: ClassifierAttempt) => attempt.status === 'accepted_success',
    );
    ledger.receipt.selectedAttempt = {
      attemptId: selected.attemptId,
      ordinal: selected.ordinal,
      attemptContentHash: selected.contentHash,
      rawResponseHash: selected.rawResponse.fullContentHash,
      rawModelOutputHash: selected.rawModelOutput.fullContentHash,
      provenance: selected.provenance,
      provenanceHash: selected.provenanceHash,
    };
  }
  rehashReceipt(ledger);
}

function rehashReceipt(ledger: any): void {
  const { contentHash: _receiptHash, ...receiptWithoutHash } = ledger.receipt;
  ledger.receipt.contentHash =
    classifierAttemptTerminalReceiptContentHash(receiptWithoutHash);
}

function mutate(
  ledger: ClassifierAttemptLedger,
  mutator: (value: any) => void,
): any {
  const value = clone(ledger);
  mutator(value);
  return value;
}

function clone<T>(value: T): any {
  return structuredClone(value);
}

function assertInvalid(value: unknown, expected: RegExp): void {
  const verification = verifyClassifierAttemptLedger(value);
  assert.equal(verification.valid, false);
  assert.match(problemText(verification.problems), expected);
}

function problemText(problems: readonly string[]): string {
  return problems.join('\n');
}

function time(seconds: number): string {
  return new Date(Date.UTC(2026, 6, 4, 0, 0, seconds)).toISOString();
}

function hash(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}

function acceptedRawResponse(
  responseId: string,
  rawModelOutput: string,
) {
  return captureClassifierRawResponse(JSON.stringify({
    id: responseId,
    model: 'classifier-model-1',
    service_tier: 'standard',
    choices: [{ message: { content: rawModelOutput } }],
  }));
}

function classifierRawOutput(
  overrides: Record<string, unknown> = {},
): string {
  return JSON.stringify({
    sentiment: 'negative',
    severity: 'high',
    scope: 'moderate',
    functionality: 'core',
    affected_users: 'unknown',
    workaroundStatus: 'unknown',
    duplicateCluster: null,
    affectsVersion: null,
    evidence: {
      sentiment: [],
      severity: [],
      scope: [],
      functionality: [],
      affected_users: [],
      workaroundStatus: [],
      duplicateCluster: [],
      affectsVersion: [],
    },
    rationale: 'Grounding fixture requires corrected citations.',
    ...overrides,
  });
}

function replaceAttemptRawModelOutput(attempt: any, rawModelOutput: string): void {
  const rawResponse = JSON.parse(attempt.rawResponse.text);
  rawResponse.choices[0].message.content = rawModelOutput;
  attempt.rawResponse = captureClassifierRawResponse(JSON.stringify(rawResponse));
  attempt.rawModelOutput = captureClassifierRawModelOutput(rawModelOutput);
}
