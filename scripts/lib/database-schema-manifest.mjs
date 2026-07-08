export const IMMUTABLE_LEDGER_TABLES = Object.freeze([
  'advisory_snapshot_history',
  'advisory_snapshot_rows',
  'advisory_snapshot_v2_history',
  'advisory_snapshot_v2_rows',
  'issue_catalog_snapshots',
  'issue_catalog_snapshot_rows',
  'issue_catalog_snapshot_consumptions',
  'closure_claim_source_snapshots',
  'closure_claim_candidates',
  'closure_claim_extraction_receipts',
  'closure_claim_extraction_receipt_members',
  'classifier_attempt_runs',
  'classifier_attempts',
  'classifier_attempt_terminal_receipts',
  'classifier_classification_publications',
  'release_artifact_verification_receipts',
  'release_artifact_verification_observations',
  'issue_label_events',
  'repository_collaborator_permission_snapshots',
  'repository_collaborator_permission_rows',
  'approved_maintainer_roster_snapshots',
  'approved_maintainer_roster_entries',
  'issue_label_evidence_snapshots',
  'issue_label_evidence_rows',
  'repository_collaborator_permission_snapshots_v2',
  'repository_collaborator_permission_rows_v2',
  'signed_maintainer_roster_snapshots',
  'signed_maintainer_roster_entries',
  'release_score_audit_history',
  'release_score_audit_history_runs',
  'score_authority_resolution_runs',
  'score_authority_resolution_rows',
  'release_score_audit_history_v2_seals',
  'release_validation_forecasts',
  'release_validation_opportunity_enrollments',
  'release_validation_outcome_observations',
  'release_validation_observation_batches',
  'release_validation_proof_epochs',
  'release_validation_proof_epoch_retirements',
  'release_validation_policies',
  'release_validation_cohorts',
  'release_validation_catalog_observations',
  'release_validation_catalog_members',
  'release_validation_catalog_reconciliations',
  'release_validation_catalog_reconciliation_rows',
  'release_validation_obligations',
  'release_validation_split_assignments',
  'release_validation_forecasts_v2',
  'release_validation_outcomes_v2',
  'release_validation_proof_observation_batches',
  'release_validation_evaluation_receipts',
  'release_validation_promotion_receipts',
  'refresh_operation_attempts',
  'refresh_operation_stage_events',
  'refresh_capture_receipts',
  'release_catalog_capture_receipts',
]);

const APPEND_ONLY_TRIGGER_PREFIXES = new Map([
  ['release_validation_outcome_observations', 'release_validation_outcomes'],
]);

export const APPEND_ONLY_TRIGGER_SPECS = Object.freeze(
  IMMUTABLE_LEDGER_TABLES.flatMap((table) => {
    const prefix = APPEND_ONLY_TRIGGER_PREFIXES.get(table) ?? table;
    return [
      Object.freeze({
        name: `${prefix}_no_update`,
        table,
        event: 'UPDATE',
        message: `${table} is append-only`,
      }),
      Object.freeze({
        name: `${prefix}_no_delete`,
        table,
        event: 'DELETE',
        message: `${table} is append-only`,
      }),
    ];
  }),
);

export const REQUIRED_APPEND_ONLY_TRIGGERS = Object.freeze(
  APPEND_ONLY_TRIGGER_SPECS.map(({ name, table, event }) => Object.freeze([
    name,
    table,
    event,
  ])),
);

assertManifestInvariants();

function assertManifestInvariants() {
  const tableNames = new Set(IMMUTABLE_LEDGER_TABLES);
  if (tableNames.size !== IMMUTABLE_LEDGER_TABLES.length) {
    throw new Error('immutable ledger manifest contains duplicate table names');
  }
  const triggerNames = new Set(APPEND_ONLY_TRIGGER_SPECS.map(({ name }) => name));
  if (triggerNames.size !== APPEND_ONLY_TRIGGER_SPECS.length) {
    throw new Error('immutable ledger manifest contains duplicate trigger names');
  }
  for (const table of IMMUTABLE_LEDGER_TABLES) {
    const events = APPEND_ONLY_TRIGGER_SPECS
      .filter((spec) => spec.table === table)
      .map((spec) => spec.event)
      .sort();
    if (events.join(',') !== 'DELETE,UPDATE') {
      throw new Error(
        `immutable ledger ${table} must define exactly one UPDATE and DELETE guard`,
      );
    }
  }
}

export function unconditionalAbortTriggerShape(trigger) {
  const sql = String(trigger?.sql ?? '').trim();
  const match = sql.match(
    /^CREATE\s+TRIGGER(?:\s+IF\s+NOT\s+EXISTS)?\s+([A-Za-z_][A-Za-z0-9_]*)\s+BEFORE\s+(UPDATE|DELETE)\s+ON\s+([A-Za-z_][A-Za-z0-9_]*)\s+BEGIN\s+SELECT\s+RAISE\s*\(\s*ABORT\s*,\s*'((?:''|[^'])*)'\s*\)\s*;\s*END\s*;?$/i,
  );
  if (!match) return null;
  const [, sqlName, event, sqlTable, rawMessage] = match;
  const catalogName = String(trigger?.name ?? '');
  const catalogTable = String(trigger?.tbl_name ?? trigger?.table_name ?? '');
  if (
    (catalogName && catalogName !== sqlName) ||
    (catalogTable && catalogTable !== sqlTable)
  ) {
    return null;
  }
  return {
    name: sqlName,
    table: sqlTable,
    event: event.toUpperCase(),
    message: rawMessage.replaceAll("''", "'"),
  };
}

export function appendOnlyTriggerShape(trigger) {
  const shape = unconditionalAbortTriggerShape(trigger);
  return shape && /append-only/i.test(shape.message) ? shape : null;
}

export function undeclaredAppendOnlyTriggerShapes(triggers) {
  const parsed = triggers
    .map(unconditionalAbortTriggerShape)
    .filter(Boolean);
  const immutableTables = new Set(IMMUTABLE_LEDGER_TABLES);
  const requiredSignatures = new Set(
    APPEND_ONLY_TRIGGER_SPECS.map(({ name, table, event }) =>
      JSON.stringify([name, table, event])),
  );
  const nonManifestEvents = new Map();
  for (const trigger of parsed) {
    if (immutableTables.has(trigger.table)) continue;
    const events = nonManifestEvents.get(trigger.table) ?? new Set();
    events.add(trigger.event);
    nonManifestEvents.set(trigger.table, events);
  }
  return parsed
    .filter((trigger) => {
      const signature = JSON.stringify([
        trigger.name,
        trigger.table,
        trigger.event,
      ]);
      if (immutableTables.has(trigger.table)) {
        return !requiredSignatures.has(signature);
      }
      const events = nonManifestEvents.get(trigger.table);
      return events?.has('UPDATE') && events.has('DELETE');
    })
    .sort((left, right) =>
      left.table.localeCompare(right.table) ||
      (left.event === right.event ? 0 : left.event === 'UPDATE' ? -1 : 1) ||
      left.name.localeCompare(right.name));
}
