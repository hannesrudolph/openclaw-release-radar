import { createHash } from 'node:crypto';

export function releaseScoreAuditHistoryRowsContentHash(
  rows: Array<Record<string, unknown>>,
): string {
  return createHash('sha256')
    .update(JSON.stringify(rows.map((row) => [
      row.release_tag,
      row.scored_at,
      row.score_model_version,
      row.prompt_version,
      row.final_score,
      row.status,
      row.band,
      row.recommended,
      row.input_json,
      row.components_json ?? null,
      row.issue_evidence_json,
      row.gate_evidence_json,
      row.source_identity_json,
    ])))
    .digest('hex');
}

export function releaseScoreAuditHistoryRunContentHash(input: {
  runId: string;
  recordedAt: string;
  rowCount: number;
  rowsContentHash: string;
  previousContentHash: string | null;
}): string {
  return createHash('sha256')
    .update(
      `release-score-audit-history-run-v1\0${input.previousContentHash ?? ''}\0` +
      JSON.stringify([
        input.runId,
        input.recordedAt,
        input.rowCount,
        input.rowsContentHash,
      ]),
    )
    .digest('hex');
}
