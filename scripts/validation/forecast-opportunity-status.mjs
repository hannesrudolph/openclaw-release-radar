const args = parseArgs(process.argv.slice(2));
if (args['db-path']) process.env.DB_PATH = args['db-path'];
if (!process.env.DB_PATH) {
  throw new Error(
    'DB_PATH or --db-path is required; refusing to inspect the default application database',
  );
}
process.env.RADAR_DB_READ_ONLY = '1';
process.env.REFRESH_ON_STARTUP = 'false';
process.env.REFRESH_MINUTES = '0';

const {
  db,
  getReleaseScoreAudit,
  listRefreshCaptureReceipts,
  listRefreshLeases,
  listRefreshOperationAttempts,
  listRefreshOperationStageEvents,
  listReleaseValidationForecasts,
  listReleaseValidationOpportunityEnrollments,
  listReleasesDb,
  runInReadTransaction,
} = await import('../../src/lib/db.ts');
const { PROMPT_VERSION } = await import('../../src/lib/llm.ts');
const { SCORE_MODEL_VERSION } = await import('../../src/lib/score.ts');
const { codeRevisionFromEnv } = await import('../../src/lib/codeRevision.ts');
const { buildPersistedOpportunityDenominator } =
  await import('./opportunity-denominator.mjs');
const {
  buildReleaseValidationOpportunityStatus,
  releaseValidationOpportunityStatusExitCode,
} = await import('../../src/lib/releaseValidationOpportunityStatus.ts');

const now = args.now ?? new Date().toISOString();
if (!Number.isFinite(Date.parse(now))) {
  throw new Error(`--now must be a valid timestamp, got ${JSON.stringify(now)}`);
}
const currentCodeRevision = codeRevisionFromEnv();
if (!currentCodeRevision) {
  throw new Error('validation:opportunities requires a deterministic code revision');
}

const source = runInReadTransaction(() => {
  const latest = listReleasesDb(1)[0];
  const audit = latest ? getReleaseScoreAudit(latest.tag) : null;
  const attempts = listRefreshOperationAttempts();
  const stageEvents = listRefreshOperationStageEvents();
  const receipts = listRefreshCaptureReceipts();
  const forecasts = listReleaseValidationForecasts();
  const enrollments = listReleaseValidationOpportunityEnrollments();
  const auditHistory = db.prepare(`
    SELECT run_id, recorded_at, score_model_version, prompt_version
    FROM release_score_audit_history
    ORDER BY recorded_at, id
  `).all();
  return {
    latest,
    audit,
    forecasts,
    denominatorLedger: buildPersistedOpportunityDenominator({
      asOf: now,
      enrollments,
      forecasts,
      attempts,
      stageEvents,
      receipts,
      leases: listRefreshLeases(),
      auditHistory,
    }),
  };
});

const report = buildReleaseValidationOpportunityStatus({
  now,
  denominatorLedger: source.denominatorLedger,
  forecasts: source.forecasts,
  currentSeries: {
    modelVersion: SCORE_MODEL_VERSION,
    promptVersion: PROMPT_VERSION,
    codeRevision: currentCodeRevision,
  },
  currentAudit: source.audit ? {
    scoreModelVersion: source.audit.score_model_version,
    promptVersion: source.audit.prompt_version,
    scoredAt: source.audit.scored_at,
  } : null,
});

console.log(JSON.stringify(report, null, 2));
if (args.check) {
  process.exitCode = releaseValidationOpportunityStatusExitCode(report);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index++) {
    const arg = argv[index];
    if (arg === '--check') {
      parsed.check = true;
      continue;
    }
    if (arg === '--db-path' || arg === '--now') {
      const value = argv[++index];
      if (!value || value.startsWith('--')) usage();
      parsed[arg.slice(2)] = value;
      continue;
    }
    usage();
  }
  return parsed;
}

function usage() {
  throw new Error(
    'Usage: validation:opportunities [--db-path <radar.db>] [--now <ISO timestamp>] [--check]',
  );
}
