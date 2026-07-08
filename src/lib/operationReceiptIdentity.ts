import { createHash } from 'node:crypto';

export interface OperationCaptureReceiptSemanticIdentityInput {
  receiptId: string;
  runId: string;
  status: string;
  finishedAt: string;
  durationMs: number;
  stageEventCount: number;
  stageChainHash: string | null;
  payloadJson: string;
}

export function operationCaptureReceiptSemanticIdentity(
  input: OperationCaptureReceiptSemanticIdentityInput,
): string {
  return createHash('sha256')
    .update(JSON.stringify([
      input.receiptId,
      input.runId,
      input.status,
      input.finishedAt,
      input.durationMs,
      input.stageEventCount,
      input.stageChainHash,
      input.payloadJson,
    ]))
    .digest('hex');
}
