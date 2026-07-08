import { createHash } from 'node:crypto';

export const CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION = 1;
export const CLASSIFIER_RAW_RESPONSE_MAX_BYTES = 1_048_576;
export const CLASSIFIER_RAW_MODEL_OUTPUT_MAX_BYTES = 1_048_576;
export const CLASSIFIER_ERROR_MESSAGE_MAX_BYTES = 65_536;
export const CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT = 128;
export const CLASSIFIER_SEMANTIC_DIAGNOSTIC_MESSAGE_MAX_BYTES = 4_096;

const IDENTIFIER_MAX_BYTES = 256;
const ERROR_NAME_MAX_BYTES = 256;
const ERROR_CODE_MAX_BYTES = 256;
const RETRY_REASON_MAX_BYTES = 256;
const DIAGNOSTIC_FIELD_MAX_BYTES = 128;
const DIAGNOSTIC_CODE_MAX_BYTES = 256;
const RESPONSE_ID_MAX_BYTES = 512;
const RESPONSE_MODEL_MAX_BYTES = 256;
const RESPONSE_SERVICE_TIER_MAX_BYTES = 128;
const PROVIDER_MAX_BYTES = 128;
const CURRENCY_MAX_BYTES = 32;
const PRICING_VERSION_MAX_BYTES = 256;
const COST_REASON_MAX_BYTES = 256;
const TERMINAL_REASON_MAX_BYTES = 256;
const SHA256_HEX_RE = /^[0-9a-f]{64}$/;
const CANONICAL_TIMESTAMP_RE =
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;

export type ClassifierAttemptStatus =
  | 'transport_failure'
  | 'semantic_rejection'
  | 'accepted_success';

export type ClassifierTerminalStatus =
  | 'accepted_success'
  | 'terminal_failure'
  | 'abandoned';

export interface ClassifierBoundedText {
  readonly text: string;
  readonly originalByteLength: number;
  readonly truncated: boolean;
  readonly retainedContentHash: string;
  readonly fullContentHash: string;
}

export interface ClassifierAttemptError {
  readonly name: string;
  readonly code: string | null;
  readonly message: ClassifierBoundedText;
}

export type ClassifierAttemptRetryDecision = 'retry' | 'stop';

export interface ClassifierAttemptRetryMetadata {
  readonly decision: ClassifierAttemptRetryDecision;
  readonly retryable: boolean;
  readonly delayMs: number | null;
  readonly reason: string;
}

export interface ClassifierAttemptSemanticDiagnostic {
  readonly field: string | null;
  readonly code: string;
  readonly message: ClassifierBoundedText;
  readonly citationIndex: number | null;
  readonly sourceId: string | null;
}

export interface ClassifierAttemptProvenance {
  readonly requestHash: string;
  readonly responseId: string | null;
  readonly responseModel: string | null;
  readonly responseServiceTier: string | null;
}

export interface ClassifierProviderUsage {
  readonly provider: string;
  readonly inputTokens: number | null;
  readonly outputTokens: number | null;
  readonly totalTokens: number | null;
  readonly cachedInputTokens: number | null;
  readonly reasoningTokens: number | null;
}

export type ClassifierCostConfidence =
  | 'known'
  | 'estimated'
  | 'indeterminate';

export interface ClassifierAttemptCost {
  readonly confidence: ClassifierCostConfidence;
  readonly amountMicrounits: number | null;
  readonly currency: string | null;
  readonly pricingVersion: string | null;
  readonly reason: string;
}

export interface ClassifierAttemptRun {
  readonly schemaVersion: 1;
  readonly runId: string;
  readonly issueNumber: number;
  readonly startedAt: string;
  readonly maxAttempts: number;
  readonly classifierIdentityHash: string;
  readonly requestHash: string;
  readonly contentHash: string;
}

export interface ClassifierAttempt {
  readonly schemaVersion: 1;
  readonly attemptId: string;
  readonly runId: string;
  readonly issueNumber: number;
  readonly ordinal: number;
  readonly status: ClassifierAttemptStatus;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly durationMs: number;
  readonly rawResponse: ClassifierBoundedText | null;
  readonly rawModelOutput: ClassifierBoundedText | null;
  readonly error: ClassifierAttemptError | null;
  readonly retry: ClassifierAttemptRetryMetadata;
  readonly semanticDiagnostics: readonly ClassifierAttemptSemanticDiagnostic[];
  readonly provenance: ClassifierAttemptProvenance;
  readonly provenanceHash: string;
  readonly usage: ClassifierProviderUsage | null;
  readonly cost: ClassifierAttemptCost;
  readonly previousContentHash: string;
  readonly contentHash: string;
}

export interface ClassifierSelectedAttemptBinding {
  readonly attemptId: string;
  readonly ordinal: number;
  readonly attemptContentHash: string;
  readonly rawResponseHash: string;
  readonly rawModelOutputHash: string;
  readonly provenance: ClassifierAttemptProvenance;
  readonly provenanceHash: string;
}

export interface ClassifierAttemptTerminalReceipt {
  readonly schemaVersion: 1;
  readonly receiptId: string;
  readonly runId: string;
  readonly issueNumber: number;
  readonly status: ClassifierTerminalStatus;
  readonly reason: string;
  readonly finishedAt: string;
  readonly attemptCount: number;
  readonly selectedAttempt: ClassifierSelectedAttemptBinding | null;
  readonly error: ClassifierAttemptError | null;
  readonly previousContentHash: string;
  readonly contentHash: string;
}

export interface ClassifierAttemptLedger {
  readonly schemaVersion: 1;
  readonly run: ClassifierAttemptRun;
  readonly attempts: readonly ClassifierAttempt[];
  readonly receipt: ClassifierAttemptTerminalReceipt;
}

export interface ClassifierAttemptLedgerVerification {
  readonly valid: boolean;
  readonly attemptCount: number;
  readonly terminalStatus: ClassifierTerminalStatus | null;
  readonly chainTipHash: string | null;
  readonly problems: readonly string[];
}

export interface ClassifierAttemptRecorder {
  recordRun(run: ClassifierAttemptRun): void | Promise<void>;
  recordAttempt(attempt: ClassifierAttempt): void | Promise<void>;
  recordTerminalReceipt(
    receipt: ClassifierAttemptTerminalReceipt,
  ): void | Promise<void>;
}

export interface CreateClassifierAttemptRunInput {
  readonly runId: string;
  readonly issueNumber: number;
  readonly startedAt: string;
  readonly maxAttempts: number;
  readonly classifierIdentityHash: string;
  readonly requestHash: string;
}

export interface AppendClassifierAttemptInput {
  readonly attemptId: string;
  readonly status: ClassifierAttemptStatus;
  readonly startedAt: string;
  readonly finishedAt: string;
  readonly rawResponse: ClassifierBoundedText | null;
  readonly rawModelOutput?: ClassifierBoundedText | null;
  readonly error: ClassifierAttemptError | null;
  readonly retry: ClassifierAttemptRetryMetadata;
  readonly semanticDiagnostics: readonly ClassifierAttemptSemanticDiagnostic[];
  readonly provenance: ClassifierAttemptProvenance;
  readonly usage?: ClassifierProviderUsage | null;
  readonly cost?: ClassifierAttemptCost;
}

export interface CaptureClassifierSemanticDiagnosticInput {
  readonly field?: string | null;
  readonly code: string;
  readonly message: string;
  readonly citationIndex?: number | null;
  readonly sourceId?: string | null;
}

export interface CreateClassifierAttemptTerminalReceiptInput {
  readonly receiptId: string;
  readonly status: ClassifierTerminalStatus;
  readonly reason?: string;
  readonly finishedAt: string;
  readonly error: ClassifierAttemptError | null;
}

export class ClassifierAttemptLedgerValidationError extends Error {
  readonly problems: readonly string[];

  constructor(problems: readonly string[]) {
    super(`Invalid classifier attempt ledger: ${problems.join('; ')}`);
    this.name = 'ClassifierAttemptLedgerValidationError';
    this.problems = [...problems];
  }
}

export function canonicalClassifierAttemptLedgerJson(value: unknown): string {
  const serialized = JSON.stringify(canonicalValue(value, new WeakSet<object>(), '$'));
  if (serialized === undefined) {
    throw new Error('Canonical classifier attempt ledger JSON cannot encode this value');
  }
  return serialized;
}

export function classifierRawResponseHash(rawResponse: string): string {
  return sha256(rawResponse);
}

export function classifierAttemptProvenanceHash(
  provenance: ClassifierAttemptProvenance,
): string {
  return sha256(
    `classifier-attempt-provenance-v1\0${canonicalClassifierAttemptLedgerJson({
      requestHash: provenance.requestHash,
      responseId: provenance.responseId,
      responseModel: provenance.responseModel,
      responseServiceTier: provenance.responseServiceTier,
    })}`,
  );
}

export function classifierAttemptRunContentHash(
  run: Omit<ClassifierAttemptRun, 'contentHash'>,
): string {
  return sha256(
    `classifier-attempt-run-v1\0${canonicalClassifierAttemptLedgerJson({
      schemaVersion: run.schemaVersion,
      runId: run.runId,
      issueNumber: run.issueNumber,
      startedAt: run.startedAt,
      maxAttempts: run.maxAttempts,
      classifierIdentityHash: run.classifierIdentityHash,
      requestHash: run.requestHash,
    })}`,
  );
}

export function classifierAttemptContentHash(
  attempt: Omit<ClassifierAttempt, 'contentHash'>,
): string {
  return sha256(
    `classifier-attempt-v1\0${attempt.previousContentHash}\0` +
    canonicalClassifierAttemptLedgerJson({
      schemaVersion: attempt.schemaVersion,
      attemptId: attempt.attemptId,
      runId: attempt.runId,
      issueNumber: attempt.issueNumber,
      ordinal: attempt.ordinal,
      status: attempt.status,
      startedAt: attempt.startedAt,
      finishedAt: attempt.finishedAt,
      durationMs: attempt.durationMs,
      rawResponse: attempt.rawResponse,
      rawModelOutput: attempt.rawModelOutput,
      error: attempt.error,
      retry: attempt.retry,
      semanticDiagnostics: attempt.semanticDiagnostics,
      provenance: attempt.provenance,
      provenanceHash: attempt.provenanceHash,
      usage: attempt.usage,
      cost: attempt.cost,
    }),
  );
}

export function classifierAttemptTerminalReceiptContentHash(
  receipt: Omit<ClassifierAttemptTerminalReceipt, 'contentHash'>,
): string {
  return sha256(
    `classifier-attempt-terminal-receipt-v1\0${receipt.previousContentHash}\0` +
    canonicalClassifierAttemptLedgerJson({
      schemaVersion: receipt.schemaVersion,
      receiptId: receipt.receiptId,
      runId: receipt.runId,
      issueNumber: receipt.issueNumber,
      status: receipt.status,
      reason: receipt.reason,
      finishedAt: receipt.finishedAt,
      attemptCount: receipt.attemptCount,
      selectedAttempt: receipt.selectedAttempt,
      error: receipt.error,
    }),
  );
}

export function captureClassifierRawResponse(
  rawResponse: string,
): ClassifierBoundedText {
  return captureBoundedText(rawResponse, CLASSIFIER_RAW_RESPONSE_MAX_BYTES);
}

export function captureClassifierRawModelOutput(
  rawModelOutput: string,
): ClassifierBoundedText {
  return captureBoundedText(
    rawModelOutput,
    CLASSIFIER_RAW_MODEL_OUTPUT_MAX_BYTES,
  );
}

export function createIndeterminateClassifierAttemptCost(
  reason: string,
): ClassifierAttemptCost {
  return deepFreeze({
    confidence: 'indeterminate',
    amountMicrounits: null,
    currency: null,
    pricingVersion: null,
    reason: boundedScalar(reason, COST_REASON_MAX_BYTES, 'cost_indeterminate'),
  });
}

export function normalizeOpenAIClassifierUsage(
  value: unknown,
): ClassifierProviderUsage | null {
  if (value == null) return null;
  if (!isRecord(value)) {
    throw new TypeError('OpenAI usage must be an object when provided');
  }
  const promptDetails = value.prompt_tokens_details == null
    ? null
    : requireUsageDetails(value.prompt_tokens_details, 'prompt_tokens_details');
  const completionDetails = value.completion_tokens_details == null
    ? null
    : requireUsageDetails(
      value.completion_tokens_details,
      'completion_tokens_details',
    );
  return deepFreeze({
    provider: 'openai',
    inputTokens: optionalUsageCount(value.prompt_tokens, 'prompt_tokens'),
    outputTokens: optionalUsageCount(
      value.completion_tokens,
      'completion_tokens',
    ),
    totalTokens: optionalUsageCount(value.total_tokens, 'total_tokens'),
    cachedInputTokens: promptDetails === null
      ? null
      : optionalUsageCount(promptDetails.cached_tokens, 'cached_tokens'),
    reasoningTokens: completionDetails === null
      ? null
      : optionalUsageCount(
        completionDetails.reasoning_tokens,
        'reasoning_tokens',
      ),
  });
}

export function captureClassifierError(error: unknown): ClassifierAttemptError {
  const errorRecord = isRecord(error) ? error : null;
  const errorObject = error && typeof error === 'object'
    ? error as { code?: unknown }
    : null;
  const name = error instanceof Error
    ? error.name || 'Error'
    : typeof errorRecord?.name === 'string'
      ? errorRecord.name
      : 'Error';
  const message = error instanceof Error
    ? error.message
    : typeof errorRecord?.message === 'string'
      ? errorRecord.message
      : String(error);
  const rawCode = errorObject?.code;
  const code = typeof rawCode === 'string' || typeof rawCode === 'number'
    ? String(rawCode)
    : null;
  return deepFreeze({
    name: boundedScalar(name, ERROR_NAME_MAX_BYTES, 'Error'),
    code: code == null ? null : boundedScalar(code, ERROR_CODE_MAX_BYTES, 'unknown'),
    message: captureBoundedText(message, CLASSIFIER_ERROR_MESSAGE_MAX_BYTES),
  });
}

export function captureClassifierSemanticDiagnostics(
  diagnostics: readonly CaptureClassifierSemanticDiagnosticInput[],
): readonly ClassifierAttemptSemanticDiagnostic[] {
  const retained = diagnostics.length <= CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT
    ? diagnostics
    : [
      ...diagnostics.slice(0, CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT - 1),
      {
        field: null,
        code: 'diagnostics_truncated',
        message:
          `${diagnostics.length - CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT + 1} ` +
          'additional semantic diagnostics were omitted',
        citationIndex: null,
        sourceId: null,
      },
    ];
  return deepFreeze(retained.map((diagnostic) => {
    const citationIndex = diagnostic.citationIndex ?? null;
    if (
      citationIndex !== null &&
      (!Number.isSafeInteger(citationIndex) || citationIndex < 0)
    ) {
      throw new TypeError(
        'Classifier semantic diagnostic citationIndex must be a non-negative safe integer',
      );
    }
    return {
      field: diagnostic.field == null
        ? null
        : boundedScalar(diagnostic.field, DIAGNOSTIC_FIELD_MAX_BYTES, 'unknown'),
      code: boundedScalar(
        diagnostic.code,
        DIAGNOSTIC_CODE_MAX_BYTES,
        'semantic_validation_error',
      ),
      message: captureBoundedText(
        diagnostic.message,
        CLASSIFIER_SEMANTIC_DIAGNOSTIC_MESSAGE_MAX_BYTES,
      ),
      citationIndex,
      sourceId: diagnostic.sourceId == null
        ? null
        : boundedScalar(diagnostic.sourceId, RESPONSE_ID_MAX_BYTES, 'unknown'),
    };
  }));
}

export function createClassifierAttemptRun(
  input: CreateClassifierAttemptRunInput,
): ClassifierAttemptRun {
  const withoutHash: Omit<ClassifierAttemptRun, 'contentHash'> = {
    schemaVersion: CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION,
    runId: input.runId,
    issueNumber: input.issueNumber,
    startedAt: input.startedAt,
    maxAttempts: input.maxAttempts,
    classifierIdentityHash: input.classifierIdentityHash,
    requestHash: input.requestHash,
  };
  return validateClassifierAttemptRun({
    ...withoutHash,
    contentHash: classifierAttemptRunContentHash(withoutHash),
  });
}

export function appendClassifierAttempt(
  run: ClassifierAttemptRun,
  existingAttempts: readonly ClassifierAttempt[],
  input: AppendClassifierAttemptInput,
): ClassifierAttempt {
  const prefixProblems = classifierAttemptChainProblems(run, existingAttempts);
  if (prefixProblems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(prefixProblems);
  }
  const previous = existingAttempts.at(-1);
  const withoutHash: Omit<ClassifierAttempt, 'contentHash'> = {
    schemaVersion: CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION,
    attemptId: input.attemptId,
    runId: run.runId,
    issueNumber: run.issueNumber,
    ordinal: existingAttempts.length + 1,
    status: input.status,
    startedAt: input.startedAt,
    finishedAt: input.finishedAt,
    durationMs: Date.parse(input.finishedAt) - Date.parse(input.startedAt),
    rawResponse: input.rawResponse,
    rawModelOutput: input.rawModelOutput ?? null,
    error: input.error,
    retry: input.retry,
    semanticDiagnostics: input.semanticDiagnostics,
    provenance: input.provenance,
    provenanceHash: classifierAttemptProvenanceHash(input.provenance),
    usage: input.usage ?? null,
    cost: input.cost ?? createIndeterminateClassifierAttemptCost(
      input.usage == null
        ? 'provider_usage_unavailable'
        : 'pricing_not_supplied',
    ),
    previousContentHash: previous?.contentHash ?? run.contentHash,
  };
  const attempt = validateClassifierAttempt({
    ...withoutHash,
    contentHash: classifierAttemptContentHash(withoutHash),
  });
  const problems = classifierAttemptChainProblems(run, [...existingAttempts, attempt]);
  if (problems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(problems);
  }
  return attempt;
}

export function createClassifierAttemptTerminalReceipt(
  run: ClassifierAttemptRun,
  attempts: readonly ClassifierAttempt[],
  input: CreateClassifierAttemptTerminalReceiptInput,
): ClassifierAttemptTerminalReceipt {
  const chainProblems = classifierAttemptChainProblems(run, attempts);
  if (chainProblems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(chainProblems);
  }
  const selected = input.status === 'accepted_success'
    ? attempts.find((attempt) => attempt.status === 'accepted_success') ?? null
    : null;
  const selectedAttempt = selected?.rawResponse
    ? {
      attemptId: selected.attemptId,
      ordinal: selected.ordinal,
      attemptContentHash: selected.contentHash,
      rawResponseHash: selected.rawResponse.fullContentHash,
      rawModelOutputHash: selected.rawModelOutput?.fullContentHash ?? '',
      provenance: selected.provenance,
      provenanceHash: selected.provenanceHash,
    }
    : null;
  const withoutHash: Omit<ClassifierAttemptTerminalReceipt, 'contentHash'> = {
    schemaVersion: CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION,
    receiptId: input.receiptId,
    runId: run.runId,
    issueNumber: run.issueNumber,
    status: input.status,
    reason: input.reason ?? (
      input.status === 'abandoned' ? 'caller_aborted' : input.status
    ),
    finishedAt: input.finishedAt,
    attemptCount: attempts.length,
    selectedAttempt,
    error: input.error,
    previousContentHash: attempts.at(-1)?.contentHash ?? run.contentHash,
  };
  const receipt = validateClassifierAttemptTerminalReceipt({
    ...withoutHash,
    contentHash: classifierAttemptTerminalReceiptContentHash(withoutHash),
  });
  const verification = verifyClassifierAttemptLedger({
    schemaVersion: CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION,
    run,
    attempts,
    receipt,
  });
  if (!verification.valid) {
    throw new ClassifierAttemptLedgerValidationError(verification.problems);
  }
  return receipt;
}

export function createClassifierAttemptLedger(
  run: ClassifierAttemptRun,
  attempts: readonly ClassifierAttempt[],
  receipt: ClassifierAttemptTerminalReceipt,
): ClassifierAttemptLedger {
  return validateClassifierAttemptLedger({
    schemaVersion: CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION,
    run,
    attempts,
    receipt,
  });
}

export function validateClassifierAttemptRun(
  value: unknown,
): ClassifierAttemptRun {
  const problems = classifierAttemptRunProblems(value, 'run');
  if (problems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(problems);
  }
  return freezeClone(value as ClassifierAttemptRun);
}

export function validateClassifierAttempt(
  value: unknown,
): ClassifierAttempt {
  const problems = classifierAttemptProblems(value, 'attempt');
  if (problems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(problems);
  }
  return freezeClone(value as ClassifierAttempt);
}

export function validateClassifierAttemptTerminalReceipt(
  value: unknown,
): ClassifierAttemptTerminalReceipt {
  const problems = classifierAttemptTerminalReceiptProblems(value, 'receipt');
  if (problems.length > 0) {
    throw new ClassifierAttemptLedgerValidationError(problems);
  }
  return freezeClone(value as ClassifierAttemptTerminalReceipt);
}

export function validateClassifierAttemptLedger(
  value: unknown,
): ClassifierAttemptLedger {
  const verification = verifyClassifierAttemptLedger(value);
  if (!verification.valid) {
    throw new ClassifierAttemptLedgerValidationError(verification.problems);
  }
  return freezeClone(value as ClassifierAttemptLedger);
}

export function verifyClassifierAttemptLedger(
  value: unknown,
): ClassifierAttemptLedgerVerification {
  const problems: string[] = [];
  if (!isRecord(value)) {
    return verificationResult(null, [], null, ['ledger must be a plain object']);
  }
  exactKeys(
    value,
    ['schemaVersion', 'run', 'attempts', 'receipt'],
    'ledger',
    problems,
  );
  if (value.schemaVersion !== CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION) {
    problems.push(
      `ledger.schemaVersion must equal ${CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION}`,
    );
  }

  const runProblems = classifierAttemptRunProblems(value.run, 'ledger.run');
  problems.push(...runProblems);
  let attemptsAreIndividuallyValid = Array.isArray(value.attempts);
  if (!Array.isArray(value.attempts)) {
    problems.push('ledger.attempts must be an array');
  } else {
    for (const [index, attempt] of value.attempts.entries()) {
      const attemptProblems = classifierAttemptProblems(
        attempt,
        `ledger.attempts[${index}]`,
      );
      problems.push(...attemptProblems);
      if (attemptProblems.length > 0) attemptsAreIndividuallyValid = false;
    }
  }
  const receiptProblems = classifierAttemptTerminalReceiptProblems(
    value.receipt,
    'ledger.receipt',
  );
  problems.push(...receiptProblems);

  const run = runProblems.length === 0 && isRecord(value.run)
    ? value.run as unknown as ClassifierAttemptRun
    : null;
  const attempts = attemptsAreIndividuallyValid && Array.isArray(value.attempts)
    ? value.attempts as unknown as ClassifierAttempt[]
    : [];
  const receipt = receiptProblems.length === 0 && isRecord(value.receipt)
    ? value.receipt as unknown as ClassifierAttemptTerminalReceipt
    : null;

  if (run && attemptsAreIndividuallyValid) {
    problems.push(...classifierAttemptChainProblems(run, attempts));
  }
  if (run && attemptsAreIndividuallyValid && receipt) {
    problems.push(...classifierTerminalSemanticProblems(run, attempts, receipt));
  }
  return verificationResult(run, attempts, receipt, unique(problems));
}

function classifierAttemptRunProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'schemaVersion',
      'runId',
      'issueNumber',
      'startedAt',
      'maxAttempts',
      'classifierIdentityHash',
      'requestHash',
      'contentHash',
    ],
    path,
    problems,
  );
  if (value.schemaVersion !== CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION) {
    problems.push(
      `${path}.schemaVersion must equal ${CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION}`,
    );
  }
  validateIdentifier(value.runId, `${path}.runId`, problems);
  validatePositiveSafeInteger(value.issueNumber, `${path}.issueNumber`, problems);
  validateTimestamp(value.startedAt, `${path}.startedAt`, problems);
  validatePositiveSafeInteger(value.maxAttempts, `${path}.maxAttempts`, problems);
  validateHash(value.classifierIdentityHash, `${path}.classifierIdentityHash`, problems);
  validateHash(value.requestHash, `${path}.requestHash`, problems);
  validateHash(value.contentHash, `${path}.contentHash`, problems);
  if (problems.length === 0) {
    const run = value as unknown as ClassifierAttemptRun;
    const { contentHash: _contentHash, ...withoutHash } = run;
    if (classifierAttemptRunContentHash(withoutHash) !== run.contentHash) {
      problems.push(`${path}.contentHash does not match the canonical run content`);
    }
  }
  return problems;
}

function classifierAttemptProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'schemaVersion',
      'attemptId',
      'runId',
      'issueNumber',
      'ordinal',
      'status',
      'startedAt',
      'finishedAt',
      'durationMs',
      'rawResponse',
      'rawModelOutput',
      'error',
      'retry',
      'semanticDiagnostics',
      'provenance',
      'provenanceHash',
      'usage',
      'cost',
      'previousContentHash',
      'contentHash',
    ],
    path,
    problems,
  );
  if (value.schemaVersion !== CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION) {
    problems.push(
      `${path}.schemaVersion must equal ${CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION}`,
    );
  }
  validateIdentifier(value.attemptId, `${path}.attemptId`, problems);
  validateIdentifier(value.runId, `${path}.runId`, problems);
  validatePositiveSafeInteger(value.issueNumber, `${path}.issueNumber`, problems);
  validatePositiveSafeInteger(value.ordinal, `${path}.ordinal`, problems);
  if (!isAttemptStatus(value.status)) {
    problems.push(`${path}.status must be a recognized classifier attempt status`);
  }
  validateTimestamp(value.startedAt, `${path}.startedAt`, problems);
  validateTimestamp(value.finishedAt, `${path}.finishedAt`, problems);
  validateNonNegativeSafeInteger(value.durationMs, `${path}.durationMs`, problems);
  if (isCanonicalTimestamp(value.startedAt) && isCanonicalTimestamp(value.finishedAt)) {
    if (Date.parse(value.finishedAt) < Date.parse(value.startedAt)) {
      problems.push(`${path}.finishedAt must not precede startedAt`);
    }
    if (
      Number.isSafeInteger(value.durationMs) &&
      value.durationMs !== Date.parse(value.finishedAt) - Date.parse(value.startedAt)
    ) {
      problems.push(`${path}.durationMs must equal finishedAt minus startedAt`);
    }
  }
  if (value.rawResponse !== null) {
    problems.push(...boundedTextProblems(
      value.rawResponse,
      CLASSIFIER_RAW_RESPONSE_MAX_BYTES,
      `${path}.rawResponse`,
    ));
  }
  if (value.rawModelOutput !== null) {
    problems.push(...boundedTextProblems(
      value.rawModelOutput,
      CLASSIFIER_RAW_MODEL_OUTPUT_MAX_BYTES,
      `${path}.rawModelOutput`,
    ));
  }
  if (value.error !== null) {
    problems.push(...classifierErrorProblems(value.error, `${path}.error`));
  }
  problems.push(...classifierRetryMetadataProblems(value.retry, `${path}.retry`));
  if (!Array.isArray(value.semanticDiagnostics)) {
    problems.push(`${path}.semanticDiagnostics must be an array`);
  } else {
    if (value.semanticDiagnostics.length > CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT) {
      problems.push(
        `${path}.semanticDiagnostics exceeds ` +
        `${CLASSIFIER_SEMANTIC_DIAGNOSTIC_MAX_COUNT} entries`,
      );
    }
    for (const [index, diagnostic] of value.semanticDiagnostics.entries()) {
      problems.push(...classifierSemanticDiagnosticProblems(
        diagnostic,
        `${path}.semanticDiagnostics[${index}]`,
      ));
    }
  }
  problems.push(...classifierProvenanceProblems(value.provenance, `${path}.provenance`));
  validateHash(value.provenanceHash, `${path}.provenanceHash`, problems);
  if (value.usage !== null) {
    problems.push(...classifierProviderUsageProblems(
      value.usage,
      `${path}.usage`,
    ));
  }
  problems.push(...classifierAttemptCostProblems(value.cost, `${path}.cost`));
  validateHash(value.previousContentHash, `${path}.previousContentHash`, problems);
  validateHash(value.contentHash, `${path}.contentHash`, problems);

  if (isRecord(value.provenance) && SHA256_HEX_RE.test(String(value.provenanceHash))) {
    try {
      if (
        classifierAttemptProvenanceHash(
          value.provenance as unknown as ClassifierAttemptProvenance,
        ) !== value.provenanceHash
      ) {
        problems.push(`${path}.provenanceHash does not match provenance`);
      }
    } catch {
      problems.push(`${path}.provenanceHash cannot be verified`);
    }
  }

  if (value.status === 'transport_failure') {
    if (value.error === null) {
      problems.push(`${path} transport_failure requires an error`);
    }
    if (value.rawModelOutput !== null) {
      problems.push(`${path} transport_failure cannot include rawModelOutput`);
    }
    if (Array.isArray(value.semanticDiagnostics) && value.semanticDiagnostics.length > 0) {
      problems.push(`${path} transport_failure cannot include semantic diagnostics`);
    }
  } else if (value.status === 'semantic_rejection') {
    if (value.rawResponse === null) {
      problems.push(`${path} semantic_rejection requires a rawResponse`);
    }
    if (value.error === null) {
      problems.push(`${path} semantic_rejection requires an error`);
    }
    if (
      Array.isArray(value.semanticDiagnostics) &&
      value.semanticDiagnostics.length === 0
    ) {
      problems.push(`${path} semantic_rejection requires semantic diagnostics`);
    }
    problems.push(...semanticResponseEvidenceProblems(value, path));
  } else if (value.status === 'accepted_success') {
    if (value.rawResponse === null) {
      problems.push(`${path} accepted_success requires a rawResponse`);
    }
    if (isRecord(value.rawResponse) && value.rawResponse.truncated !== false) {
      problems.push(`${path} accepted_success requires a complete rawResponse`);
    }
    if (value.rawModelOutput === null) {
      problems.push(`${path} accepted_success requires rawModelOutput`);
    }
    if (
      isRecord(value.rawModelOutput) &&
      value.rawModelOutput.truncated !== false
    ) {
      problems.push(`${path} accepted_success requires complete rawModelOutput`);
    }
    if (value.error !== null) {
      problems.push(`${path} accepted_success cannot include an error`);
    }
    if (Array.isArray(value.semanticDiagnostics) && value.semanticDiagnostics.length > 0) {
      problems.push(`${path} accepted_success cannot include semantic diagnostics`);
    }
    requireResponseProvenance(value.provenance, `${path}.provenance`, problems);
    if (isRecord(value.retry)) {
      if (value.retry.decision !== 'stop') {
        problems.push(`${path} accepted_success retry decision must be stop`);
      }
      if (value.retry.retryable !== false) {
        problems.push(`${path} accepted_success cannot be retryable`);
      }
    }
    problems.push(...acceptedResponseEvidenceProblems(value, path));
  }

  const structuralProblems = problems.length;
  if (structuralProblems === 0) {
    const attempt = value as unknown as ClassifierAttempt;
    const { contentHash: _contentHash, ...withoutHash } = attempt;
    if (classifierAttemptContentHash(withoutHash) !== attempt.contentHash) {
      problems.push(`${path}.contentHash does not match the canonical attempt content`);
    }
  }
  return unique(problems);
}

function classifierAttemptTerminalReceiptProblems(
  value: unknown,
  path: string,
): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'schemaVersion',
      'receiptId',
      'runId',
      'issueNumber',
      'status',
      'reason',
      'finishedAt',
      'attemptCount',
      'selectedAttempt',
      'error',
      'previousContentHash',
      'contentHash',
    ],
    path,
    problems,
  );
  if (value.schemaVersion !== CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION) {
    problems.push(
      `${path}.schemaVersion must equal ${CLASSIFIER_ATTEMPT_LEDGER_SCHEMA_VERSION}`,
    );
  }
  validateIdentifier(value.receiptId, `${path}.receiptId`, problems);
  validateIdentifier(value.runId, `${path}.runId`, problems);
  validatePositiveSafeInteger(value.issueNumber, `${path}.issueNumber`, problems);
  if (!isTerminalStatus(value.status)) {
    problems.push(`${path}.status must be a recognized classifier terminal status`);
  }
  validateBoundedScalar(
    value.reason,
    TERMINAL_REASON_MAX_BYTES,
    `${path}.reason`,
    problems,
  );
  validateTimestamp(value.finishedAt, `${path}.finishedAt`, problems);
  validateNonNegativeSafeInteger(value.attemptCount, `${path}.attemptCount`, problems);
  if (value.selectedAttempt !== null) {
    problems.push(...selectedAttemptProblems(
      value.selectedAttempt,
      `${path}.selectedAttempt`,
    ));
  }
  if (value.error !== null) {
    problems.push(...classifierErrorProblems(value.error, `${path}.error`));
  }
  validateHash(value.previousContentHash, `${path}.previousContentHash`, problems);
  validateHash(value.contentHash, `${path}.contentHash`, problems);

  if (value.status === 'accepted_success') {
    if (value.selectedAttempt === null) {
      problems.push(`${path} accepted_success requires selectedAttempt`);
    }
    if (value.error !== null) {
      problems.push(`${path} accepted_success cannot include an error`);
    }
  } else if (value.status === 'terminal_failure') {
    if (value.selectedAttempt !== null) {
      problems.push(`${path} terminal_failure cannot select an attempt`);
    }
    if (value.error === null) {
      problems.push(`${path} terminal_failure requires an error`);
    }
  } else if (value.status === 'abandoned') {
    if (value.selectedAttempt !== null) {
      problems.push(`${path} abandoned cannot select an attempt`);
    }
    if (value.error === null) {
      problems.push(`${path} abandoned requires an error`);
    }
  }

  if (problems.length === 0) {
    const receipt = value as unknown as ClassifierAttemptTerminalReceipt;
    const { contentHash: _contentHash, ...withoutHash } = receipt;
    if (
      classifierAttemptTerminalReceiptContentHash(withoutHash) !==
      receipt.contentHash
    ) {
      problems.push(`${path}.contentHash does not match canonical terminal content`);
    }
  }
  return unique(problems);
}

function classifierAttemptChainProblems(
  run: ClassifierAttemptRun,
  attempts: readonly ClassifierAttempt[],
): string[] {
  const problems: string[] = [];
  problems.push(...classifierAttemptRunProblems(run, 'run'));
  if (attempts.length > run.maxAttempts) {
    problems.push(
      `attempt count ${attempts.length} exceeds run.maxAttempts ${run.maxAttempts}`,
    );
  }
  const attemptIds = new Set<string>();
  let previousContentHash = run.contentHash;
  let previousFinishedAtMs = Date.parse(run.startedAt);
  let acceptedOrdinal: number | null = null;

  for (const [index, attempt] of attempts.entries()) {
    const path = `attempts[${index}]`;
    problems.push(...classifierAttemptProblems(attempt, path));
    if (attemptIds.has(attempt.attemptId)) {
      problems.push(`${path}.attemptId duplicates ${JSON.stringify(attempt.attemptId)}`);
    }
    attemptIds.add(attempt.attemptId);
    const expectedOrdinal = index + 1;
    if (attempt.ordinal !== expectedOrdinal) {
      problems.push(`${path}.ordinal must equal ${expectedOrdinal}`);
    }
    if (attempt.runId !== run.runId) {
      problems.push(`${path}.runId does not match run.runId`);
    }
    if (attempt.issueNumber !== run.issueNumber) {
      problems.push(`${path}.issueNumber does not match run.issueNumber`);
    }
    if (attempt.provenance.requestHash !== run.requestHash) {
      problems.push(`${path}.provenance.requestHash does not match run.requestHash`);
    }
    if (attempt.previousContentHash !== previousContentHash) {
      problems.push(`${path}.previousContentHash does not match the append chain`);
    }
    const startedAtMs = Date.parse(attempt.startedAt);
    const finishedAtMs = Date.parse(attempt.finishedAt);
    if (Number.isFinite(startedAtMs) && startedAtMs < previousFinishedAtMs) {
      problems.push(`${path}.startedAt overlaps or precedes the prior ledger event`);
    }
    if (Number.isFinite(finishedAtMs)) previousFinishedAtMs = finishedAtMs;
    if (attempt.status === 'accepted_success') {
      if (acceptedOrdinal !== null) {
        problems.push(
          `${path} is a second accepted_success after ordinal ${acceptedOrdinal}`,
        );
      }
      acceptedOrdinal = attempt.ordinal;
    } else if (acceptedOrdinal !== null) {
      problems.push(`${path} cannot follow accepted_success ordinal ${acceptedOrdinal}`);
    }
    if (index < attempts.length - 1 && attempt.retry.decision !== 'retry') {
      problems.push(`${path}.retry.decision must be retry before a later attempt`);
    }
    previousContentHash = attempt.contentHash;
  }
  return unique(problems);
}

function classifierTerminalSemanticProblems(
  run: ClassifierAttemptRun,
  attempts: readonly ClassifierAttempt[],
  receipt: ClassifierAttemptTerminalReceipt,
): string[] {
  const problems: string[] = [];
  if (receipt.runId !== run.runId) {
    problems.push('receipt.runId does not match run.runId');
  }
  if (receipt.issueNumber !== run.issueNumber) {
    problems.push('receipt.issueNumber does not match run.issueNumber');
  }
  if (receipt.attemptCount !== attempts.length) {
    problems.push('receipt.attemptCount does not match the number of attempts');
  }
  const expectedPreviousHash = attempts.at(-1)?.contentHash ?? run.contentHash;
  if (receipt.previousContentHash !== expectedPreviousHash) {
    problems.push('receipt.previousContentHash does not match the attempt chain tip');
  }
  const finalAttemptFinishedAt = attempts.at(-1)?.finishedAt ?? run.startedAt;
  if (
    isCanonicalTimestamp(receipt.finishedAt) &&
    isCanonicalTimestamp(finalAttemptFinishedAt) &&
    Date.parse(receipt.finishedAt) < Date.parse(finalAttemptFinishedAt)
  ) {
    problems.push('receipt.finishedAt precedes the final attempt');
  }

  const acceptedAttempts = attempts.filter(
    (attempt) => attempt.status === 'accepted_success',
  );
  if (receipt.status === 'accepted_success') {
    if (acceptedAttempts.length !== 1) {
      problems.push('accepted_success receipt requires exactly one accepted attempt');
      return unique(problems);
    }
    const selected = receipt.selectedAttempt;
    const accepted = acceptedAttempts[0];
    if (attempts.at(-1) !== accepted) {
      problems.push('the accepted attempt must be the final attempt');
    }
    if (!selected) {
      problems.push('accepted_success receipt is missing selectedAttempt');
      return unique(problems);
    }
    if (selected.attemptId !== accepted.attemptId) {
      problems.push('selectedAttempt.attemptId does not bind the accepted attempt');
    }
    if (selected.ordinal !== accepted.ordinal) {
      problems.push('selectedAttempt.ordinal does not bind the accepted attempt');
    }
    if (selected.attemptContentHash !== accepted.contentHash) {
      problems.push(
        'selectedAttempt.attemptContentHash does not bind the accepted attempt',
      );
    }
    if (
      !accepted.rawResponse ||
      selected.rawResponseHash !== accepted.rawResponse.fullContentHash
    ) {
      problems.push('selectedAttempt.rawResponseHash does not bind the accepted raw response');
    }
    if (
      !accepted.rawModelOutput ||
      selected.rawModelOutputHash !== accepted.rawModelOutput.fullContentHash
    ) {
      problems.push(
        'selectedAttempt.rawModelOutputHash does not bind the accepted raw model output',
      );
    }
    if (
      canonicalClassifierAttemptLedgerJson(selected.provenance) !==
      canonicalClassifierAttemptLedgerJson(accepted.provenance)
    ) {
      problems.push('selectedAttempt.provenance does not bind the accepted provenance');
    }
    if (selected.provenanceHash !== accepted.provenanceHash) {
      problems.push('selectedAttempt.provenanceHash does not bind the accepted provenance');
    }
  } else {
    if (acceptedAttempts.length > 0) {
      problems.push(`${receipt.status} receipt cannot terminate an accepted attempt`);
    }
    if (
      receipt.status === 'terminal_failure' &&
      attempts.length > 0 &&
      attempts.at(-1)?.retry.decision !== 'stop'
    ) {
      problems.push('terminal_failure final attempt retry decision must be stop');
    }
  }
  if (receipt.status === 'abandoned' && receipt.reason !== 'caller_aborted') {
    problems.push('abandoned receipt reason must be caller_aborted');
  }
  return unique(problems);
}

function acceptedResponseEvidenceProblems(
  value: Record<string, unknown>,
  path: string,
): string[] {
  return completedResponseEvidenceProblems(value, path, true);
}

function semanticResponseEvidenceProblems(
  value: Record<string, unknown>,
  path: string,
): string[] {
  return completedResponseEvidenceProblems(value, path, false);
}

function completedResponseEvidenceProblems(
  value: Record<string, unknown>,
  path: string,
  requireAssistantContent: boolean,
): string[] {
  const problems: string[] = [];
  if (
    !isRecord(value.rawResponse) ||
    typeof value.rawResponse.text !== 'string' ||
    !isRecord(value.provenance)
  ) {
    return problems;
  }
  if (value.rawResponse.truncated !== false) {
    return problems;
  }
  let response: Record<string, unknown>;
  try {
    const parsed = JSON.parse(value.rawResponse.text) as unknown;
    if (!isRecord(parsed)) {
      problems.push(`${path} completed rawResponse must contain a JSON object`);
      return problems;
    }
    response = parsed;
  } catch {
    problems.push(`${path} completed rawResponse must contain valid JSON`);
    return problems;
  }

  const choices = response.choices;
  const firstChoice = Array.isArray(choices) ? choices[0] : null;
  const message = isRecord(firstChoice) && isRecord(firstChoice.message)
    ? firstChoice.message
    : null;
  const content = message?.content;
  if (typeof content !== 'string' && requireAssistantContent) {
    problems.push(`${path} accepted rawResponse is missing assistant message content`);
  } else if (typeof content === 'string' && !isRecord(value.rawModelOutput)) {
    problems.push(
      `${path} completed response requires rawModelOutput for assistant message content`,
    );
  } else if (
    typeof content === 'string' &&
    isRecord(value.rawModelOutput) &&
    value.rawModelOutput.truncated !== false
  ) {
    problems.push(`${path} completed response requires complete rawModelOutput`);
  } else if (
    typeof content === 'string' &&
    isRecord(value.rawModelOutput) &&
    typeof value.rawModelOutput.text === 'string' &&
    content !== value.rawModelOutput.text
  ) {
    problems.push(
      `${path}.rawModelOutput does not match the retained assistant message`,
    );
  } else if (
    typeof content !== 'string' &&
    !requireAssistantContent &&
    value.rawModelOutput !== null
  ) {
    problems.push(
      `${path}.rawModelOutput must be null when the response has no assistant message content`,
    );
  }

  for (const [responseField, provenanceField, maxBytes] of [
    ['id', 'responseId', RESPONSE_ID_MAX_BYTES],
    ['model', 'responseModel', RESPONSE_MODEL_MAX_BYTES],
    ['service_tier', 'responseServiceTier', RESPONSE_SERVICE_TIER_MAX_BYTES],
  ] as const) {
    const responseIdentity = responseIdentityStringOrNull(
      response[responseField],
      maxBytes,
    );
    if (responseIdentity !== value.provenance[provenanceField]) {
      problems.push(
        `${path}.provenance.${provenanceField} does not match rawResponse.${responseField}`,
      );
    }
  }

  try {
    const normalizedUsage = normalizeOpenAIClassifierUsage(response.usage);
    if (
      canonicalClassifierAttemptLedgerJson(normalizedUsage) !==
      canonicalClassifierAttemptLedgerJson(value.usage)
    ) {
      problems.push(`${path}.usage does not match normalized rawResponse usage`);
    }
  } catch (error) {
    if (requireAssistantContent || value.usage !== null) {
      problems.push(
        `${path}.usage cannot be verified: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  }
  return problems;
}

function responseIdentityStringOrNull(
  value: unknown,
  maxBytes: number,
): string | null {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    Buffer.byteLength(value, 'utf8') > maxBytes
  ) {
    return null;
  }
  return value;
}

function classifierProvenanceProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    ['requestHash', 'responseId', 'responseModel', 'responseServiceTier'],
    path,
    problems,
  );
  validateHash(value.requestHash, `${path}.requestHash`, problems);
  validateNullableBoundedScalar(
    value.responseId,
    RESPONSE_ID_MAX_BYTES,
    `${path}.responseId`,
    problems,
  );
  validateNullableBoundedScalar(
    value.responseModel,
    RESPONSE_MODEL_MAX_BYTES,
    `${path}.responseModel`,
    problems,
  );
  validateNullableBoundedScalar(
    value.responseServiceTier,
    RESPONSE_SERVICE_TIER_MAX_BYTES,
    `${path}.responseServiceTier`,
    problems,
  );
  return problems;
}

function classifierProviderUsageProblems(
  value: unknown,
  path: string,
): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'provider',
      'inputTokens',
      'outputTokens',
      'totalTokens',
      'cachedInputTokens',
      'reasoningTokens',
    ],
    path,
    problems,
  );
  validateBoundedScalar(
    value.provider,
    PROVIDER_MAX_BYTES,
    `${path}.provider`,
    problems,
  );
  for (const key of [
    'inputTokens',
    'outputTokens',
    'totalTokens',
    'cachedInputTokens',
    'reasoningTokens',
  ] as const) {
    if (value[key] !== null) {
      validateNonNegativeSafeInteger(value[key], `${path}.${key}`, problems);
    }
  }
  return problems;
}

function classifierAttemptCostProblems(
  value: unknown,
  path: string,
): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'confidence',
      'amountMicrounits',
      'currency',
      'pricingVersion',
      'reason',
    ],
    path,
    problems,
  );
  if (
    value.confidence !== 'known' &&
    value.confidence !== 'estimated' &&
    value.confidence !== 'indeterminate'
  ) {
    problems.push(`${path}.confidence must be known, estimated, or indeterminate`);
  }
  if (value.amountMicrounits !== null) {
    validateNonNegativeSafeInteger(
      value.amountMicrounits,
      `${path}.amountMicrounits`,
      problems,
    );
  }
  validateNullableBoundedScalar(
    value.currency,
    CURRENCY_MAX_BYTES,
    `${path}.currency`,
    problems,
  );
  validateNullableBoundedScalar(
    value.pricingVersion,
    PRICING_VERSION_MAX_BYTES,
    `${path}.pricingVersion`,
    problems,
  );
  validateBoundedScalar(
    value.reason,
    COST_REASON_MAX_BYTES,
    `${path}.reason`,
    problems,
  );
  if (value.confidence === 'indeterminate') {
    if (value.amountMicrounits !== null || value.currency !== null) {
      problems.push(
        `${path} indeterminate cost cannot claim an amount or currency`,
      );
    }
  } else {
    if (value.amountMicrounits === null) {
      problems.push(`${path} ${value.confidence} cost requires amountMicrounits`);
    }
    if (value.currency === null) {
      problems.push(`${path} ${value.confidence} cost requires currency`);
    }
    if (value.pricingVersion === null) {
      problems.push(`${path} ${value.confidence} cost requires pricingVersion`);
    }
  }
  return problems;
}

function classifierRetryMetadataProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    ['decision', 'retryable', 'delayMs', 'reason'],
    path,
    problems,
  );
  if (value.decision !== 'retry' && value.decision !== 'stop') {
    problems.push(`${path}.decision must be retry or stop`);
  }
  if (typeof value.retryable !== 'boolean') {
    problems.push(`${path}.retryable must be a boolean`);
  }
  if (value.delayMs !== null) {
    validateNonNegativeSafeInteger(value.delayMs, `${path}.delayMs`, problems);
  }
  validateBoundedScalar(
    value.reason,
    RETRY_REASON_MAX_BYTES,
    `${path}.reason`,
    problems,
  );
  if (value.decision === 'retry') {
    if (value.retryable !== true) {
      problems.push(`${path} retry decision requires retryable=true`);
    }
    if (value.delayMs === null) {
      problems.push(`${path} retry decision requires delayMs`);
    }
  } else if (value.decision === 'stop' && value.delayMs !== null) {
    problems.push(`${path} stop decision requires delayMs=null`);
  }
  return problems;
}

function classifierSemanticDiagnosticProblems(
  value: unknown,
  path: string,
): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    ['field', 'code', 'message', 'citationIndex', 'sourceId'],
    path,
    problems,
  );
  validateNullableBoundedScalar(
    value.field,
    DIAGNOSTIC_FIELD_MAX_BYTES,
    `${path}.field`,
    problems,
  );
  validateBoundedScalar(
    value.code,
    DIAGNOSTIC_CODE_MAX_BYTES,
    `${path}.code`,
    problems,
  );
  problems.push(...boundedTextProblems(
    value.message,
    CLASSIFIER_SEMANTIC_DIAGNOSTIC_MESSAGE_MAX_BYTES,
    `${path}.message`,
  ));
  if (value.citationIndex !== null) {
    validateNonNegativeSafeInteger(
      value.citationIndex,
      `${path}.citationIndex`,
      problems,
    );
  }
  validateNullableBoundedScalar(
    value.sourceId,
    RESPONSE_ID_MAX_BYTES,
    `${path}.sourceId`,
    problems,
  );
  return problems;
}

function requireResponseProvenance(
  value: unknown,
  path: string,
  problems: string[],
): void {
  if (!isRecord(value)) return;
  for (const key of ['responseId', 'responseModel', 'responseServiceTier'] as const) {
    if (typeof value[key] !== 'string' || value[key].length === 0) {
      problems.push(`${path}.${key} is required for a received classifier response`);
    }
  }
}

function classifierErrorProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(value, ['name', 'code', 'message'], path, problems);
  validateBoundedScalar(value.name, ERROR_NAME_MAX_BYTES, `${path}.name`, problems);
  validateNullableBoundedScalar(
    value.code,
    ERROR_CODE_MAX_BYTES,
    `${path}.code`,
    problems,
  );
  problems.push(...boundedTextProblems(
    value.message,
    CLASSIFIER_ERROR_MESSAGE_MAX_BYTES,
    `${path}.message`,
  ));
  return problems;
}

function selectedAttemptProblems(value: unknown, path: string): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'attemptId',
      'ordinal',
      'attemptContentHash',
      'rawResponseHash',
      'rawModelOutputHash',
      'provenance',
      'provenanceHash',
    ],
    path,
    problems,
  );
  validateIdentifier(value.attemptId, `${path}.attemptId`, problems);
  validatePositiveSafeInteger(value.ordinal, `${path}.ordinal`, problems);
  validateHash(value.attemptContentHash, `${path}.attemptContentHash`, problems);
  validateHash(value.rawResponseHash, `${path}.rawResponseHash`, problems);
  validateHash(
    value.rawModelOutputHash,
    `${path}.rawModelOutputHash`,
    problems,
  );
  problems.push(...classifierProvenanceProblems(
    value.provenance,
    `${path}.provenance`,
  ));
  validateHash(value.provenanceHash, `${path}.provenanceHash`, problems);
  if (
    isRecord(value.provenance) &&
    typeof value.provenanceHash === 'string' &&
    SHA256_HEX_RE.test(value.provenanceHash)
  ) {
    try {
      if (
        classifierAttemptProvenanceHash(
          value.provenance as unknown as ClassifierAttemptProvenance,
        ) !== value.provenanceHash
      ) {
        problems.push(`${path}.provenanceHash does not match provenance`);
      }
    } catch {
      problems.push(`${path}.provenanceHash cannot be verified`);
    }
  }
  return problems;
}

function boundedTextProblems(
  value: unknown,
  maxBytes: number,
  path: string,
): string[] {
  const problems: string[] = [];
  if (!isRecord(value)) return [`${path} must be a plain object`];
  exactKeys(
    value,
    [
      'text',
      'originalByteLength',
      'truncated',
      'retainedContentHash',
      'fullContentHash',
    ],
    path,
    problems,
  );
  if (typeof value.text !== 'string') {
    problems.push(`${path}.text must be a string`);
  }
  validateNonNegativeSafeInteger(
    value.originalByteLength,
    `${path}.originalByteLength`,
    problems,
  );
  if (typeof value.truncated !== 'boolean') {
    problems.push(`${path}.truncated must be a boolean`);
  }
  validateHash(value.retainedContentHash, `${path}.retainedContentHash`, problems);
  validateHash(value.fullContentHash, `${path}.fullContentHash`, problems);
  if (
    typeof value.text === 'string' &&
    Number.isSafeInteger(value.originalByteLength) &&
    typeof value.truncated === 'boolean'
  ) {
    const originalByteLength = Number(value.originalByteLength);
    const retainedByteLength = Buffer.byteLength(value.text, 'utf8');
    if (retainedByteLength > maxBytes) {
      problems.push(`${path}.text exceeds ${maxBytes} UTF-8 bytes`);
    }
    if (originalByteLength < retainedByteLength) {
      problems.push(`${path}.originalByteLength is smaller than retained text`);
    }
    if (value.truncated !== (originalByteLength > retainedByteLength)) {
      problems.push(`${path}.truncated does not match its byte lengths`);
    }
    if (
      SHA256_HEX_RE.test(String(value.retainedContentHash)) &&
      classifierRawResponseHash(value.text) !== value.retainedContentHash
    ) {
      problems.push(`${path}.retainedContentHash does not match its retained text`);
    }
    if (
      !value.truncated &&
      SHA256_HEX_RE.test(String(value.fullContentHash)) &&
      classifierRawResponseHash(value.text) !== value.fullContentHash
    ) {
      problems.push(`${path}.fullContentHash does not match its complete text`);
    }
  }
  return problems;
}

function verificationResult(
  run: ClassifierAttemptRun | null,
  attempts: readonly ClassifierAttempt[],
  receipt: ClassifierAttemptTerminalReceipt | null,
  problems: readonly string[],
): ClassifierAttemptLedgerVerification {
  return deepFreeze({
    valid: problems.length === 0,
    attemptCount: attempts.length,
    terminalStatus: isTerminalStatus(receipt?.status) ? receipt.status : null,
    chainTipHash: receipt?.contentHash ??
      attempts.at(-1)?.contentHash ??
      run?.contentHash ??
      null,
    problems: [...problems],
  });
}

function captureBoundedText(text: string, maxBytes: number): ClassifierBoundedText {
  if (typeof text !== 'string') {
    throw new TypeError('Classifier captured text must be a string');
  }
  const originalByteLength = Buffer.byteLength(text, 'utf8');
  const retained = originalByteLength <= maxBytes
    ? text
    : truncateUtf8(text, maxBytes);
  return deepFreeze({
    text: retained,
    originalByteLength,
    truncated: originalByteLength > Buffer.byteLength(retained, 'utf8'),
    retainedContentHash: classifierRawResponseHash(retained),
    fullContentHash: classifierRawResponseHash(text),
  });
}

function requireUsageDetails(
  value: unknown,
  field: string,
): Record<string, unknown> {
  if (!isRecord(value)) {
    throw new TypeError(`OpenAI usage ${field} must be an object when provided`);
  }
  return value;
}

function optionalUsageCount(value: unknown, field: string): number | null {
  if (value == null) return null;
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    throw new TypeError(
      `OpenAI usage ${field} must be a non-negative safe integer`,
    );
  }
  return Number(value);
}

function truncateUtf8(value: string, maxBytes: number): string {
  let used = 0;
  let result = '';
  for (const character of value) {
    const characterBytes = Buffer.byteLength(character, 'utf8');
    if (used + characterBytes > maxBytes) break;
    result += character;
    used += characterBytes;
  }
  return result;
}

function boundedScalar(value: string, maxBytes: number, fallback: string): string {
  const normalized = value.trim() || fallback;
  return truncateUtf8(normalized, maxBytes);
}

function validateIdentifier(
  value: unknown,
  path: string,
  problems: string[],
): void {
  validateBoundedScalar(value, IDENTIFIER_MAX_BYTES, path, problems);
}

function validateBoundedScalar(
  value: unknown,
  maxBytes: number,
  path: string,
  problems: string[],
): void {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.trim() !== value ||
    Buffer.byteLength(value, 'utf8') > maxBytes
  ) {
    problems.push(
      `${path} must be a non-empty canonical string of at most ${maxBytes} UTF-8 bytes`,
    );
  }
}

function validateNullableBoundedScalar(
  value: unknown,
  maxBytes: number,
  path: string,
  problems: string[],
): void {
  if (value === null) return;
  validateBoundedScalar(value, maxBytes, path, problems);
}

function validatePositiveSafeInteger(
  value: unknown,
  path: string,
  problems: string[],
): void {
  if (!Number.isSafeInteger(value) || Number(value) <= 0) {
    problems.push(`${path} must be a positive safe integer`);
  }
}

function validateNonNegativeSafeInteger(
  value: unknown,
  path: string,
  problems: string[],
): void {
  if (!Number.isSafeInteger(value) || Number(value) < 0) {
    problems.push(`${path} must be a non-negative safe integer`);
  }
}

function validateTimestamp(
  value: unknown,
  path: string,
  problems: string[],
): void {
  if (!isCanonicalTimestamp(value)) {
    problems.push(`${path} must be a finite canonical UTC timestamp`);
  }
}

function isCanonicalTimestamp(value: unknown): value is string {
  if (typeof value !== 'string' || !CANONICAL_TIMESTAMP_RE.test(value)) return false;
  const milliseconds = Date.parse(value);
  return Number.isFinite(milliseconds) && new Date(milliseconds).toISOString() === value;
}

function validateHash(value: unknown, path: string, problems: string[]): void {
  if (typeof value !== 'string' || !SHA256_HEX_RE.test(value)) {
    problems.push(`${path} must be a lowercase SHA-256 hex string`);
  }
}

function exactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  path: string,
  problems: string[],
): void {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (canonicalClassifierAttemptLedgerJson(actual) !==
      canonicalClassifierAttemptLedgerJson(sortedExpected)) {
    const missing = sortedExpected.filter((key) => !Object.hasOwn(value, key));
    const unknown = actual.filter((key) => !expected.includes(key));
    if (missing.length > 0) {
      problems.push(`${path} is missing fields: ${missing.join(', ')}`);
    }
    if (unknown.length > 0) {
      problems.push(`${path} has unknown fields: ${unknown.join(', ')}`);
    }
  }
}

function isAttemptStatus(value: unknown): value is ClassifierAttemptStatus {
  return value === 'transport_failure' ||
    value === 'semantic_rejection' ||
    value === 'accepted_success';
}

function isTerminalStatus(value: unknown): value is ClassifierTerminalStatus {
  return value === 'accepted_success' ||
    value === 'terminal_failure' ||
    value === 'abandoned';
}

function isRecord(value: unknown): value is Record<string, unknown> {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function canonicalValue(
  value: unknown,
  ancestors: WeakSet<object>,
  path: string,
): unknown {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  ) {
    return value;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) {
      throw new Error(`${path} contains a non-finite number`);
    }
    return Object.is(value, -0) ? 0 : value;
  }
  if (Array.isArray(value)) {
    if (ancestors.has(value)) throw new Error(`${path} contains a cycle`);
    ancestors.add(value);
    const result = value.map((nested, index) => {
      if (!Object.hasOwn(value, index)) {
        throw new Error(`${path} contains a sparse array`);
      }
      return canonicalValue(nested, ancestors, `${path}[${index}]`);
    });
    ancestors.delete(value);
    return result;
  }
  if (isRecord(value)) {
    if (ancestors.has(value)) throw new Error(`${path} contains a cycle`);
    ancestors.add(value);
    const result: Record<string, unknown> = {};
    for (const key of Object.keys(value).sort()) {
      result[key] = canonicalValue(value[key], ancestors, `${path}.${key}`);
    }
    ancestors.delete(value);
    return result;
  }
  throw new Error(`${path} contains a non-JSON value`);
}

function freezeClone<T>(value: T): T {
  return deepFreeze(cloneJson(value)) as T;
}

function cloneJson(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(cloneJson);
  if (isRecord(value)) {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => [key, cloneJson(nested)]),
    );
  }
  return value;
}

function deepFreeze<T>(value: T): T {
  if (value && typeof value === 'object' && !Object.isFrozen(value)) {
    for (const nested of Object.values(value as Record<string, unknown>)) {
      deepFreeze(nested);
    }
    Object.freeze(value);
  }
  return value;
}

function unique(problems: readonly string[]): string[] {
  return [...new Set(problems)];
}

function sha256(value: string): string {
  return createHash('sha256').update(value).digest('hex');
}
