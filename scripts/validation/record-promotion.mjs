if (process.env.RADAR_DB_READ_ONLY === '1') {
  throw new Error('record-promotion requires a writable database');
}

const options = parseArgs(process.argv.slice(2));
const {
  appendReleaseValidationProof,
  readReleaseValidationProofBundle,
} = await import('../../src/lib/db.ts');
const {
  planReleaseValidationProofPromotion,
} = await import('../../src/lib/releaseValidationProofPromotion.ts');

const plan = planReleaseValidationProofPromotion({
  bundle: readReleaseValidationProofBundle(),
  environment: options.environment,
  promotedAt: options.promotedAt,
  evaluationId: options.evaluationId,
  evaluationContentHash: options.evaluationContentHash,
  sourceProofHash: options.sourceProofHash,
  destinationProofHash: options.destinationProofHash,
});
const persistence = appendReleaseValidationProof(plan.append);

console.log(JSON.stringify({
  schemaVersion: 1,
  promotionId: plan.receipt.promotionId,
  contentHash: plan.receipt.contentHash,
  environment: plan.receipt.environment,
  promotedAt: plan.receipt.promotedAt,
  evaluationId: plan.receipt.evaluationId,
  evaluationContentHash: plan.receipt.evaluationContentHash,
  sourceProofHash: plan.receipt.sourceProofHash,
  destinationProofHash: plan.receipt.destinationProofHash,
  persistence: plan.status,
  insertedCount: persistence.insertedByType.promotionReceipts,
  equivalentCount: persistence.equivalentByType.promotionReceipts,
}, null, 2));

function parseArgs(args) {
  const values = new Map();
  const allowed = new Set([
    'environment',
    'promoted-at',
    'evaluation-id',
    'evaluation-content-hash',
    'source-proof-hash',
    'destination-proof-hash',
  ]);
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith('--')) {
      throw new Error(`Unexpected positional argument: ${arg}`);
    }
    const key = arg.slice(2);
    if (!allowed.has(key)) {
      throw new Error(`Unknown option: --${key}`);
    }
    const value = args[++index];
    if (!value || value.startsWith('--')) {
      throw new Error(`--${key} requires a value`);
    }
    if (values.has(key)) {
      throw new Error(`--${key} may be specified only once`);
    }
    values.set(key, value);
  }
  for (const key of allowed) {
    if (!values.has(key)) {
      throw new Error(`Missing required option: --${key}`);
    }
  }
  const environment = values.get('environment');
  if (environment !== 'production' && environment !== 'calibration') {
    throw new Error('--environment must be production or calibration');
  }
  const promotedAt = normalizedTimestamp(
    values.get('promoted-at'),
    '--promoted-at',
  );
  return {
    environment,
    promotedAt,
    evaluationId: requiredSha256(
      values.get('evaluation-id'),
      '--evaluation-id',
    ),
    evaluationContentHash: requiredSha256(
      values.get('evaluation-content-hash'),
      '--evaluation-content-hash',
    ),
    sourceProofHash: requiredSha256(
      values.get('source-proof-hash'),
      '--source-proof-hash',
    ),
    destinationProofHash: requiredSha256(
      values.get('destination-proof-hash'),
      '--destination-proof-hash',
    ),
  };
}

function normalizedTimestamp(value, label) {
  const timestamp = Date.parse(value);
  if (!Number.isFinite(timestamp)) {
    throw new Error(`${label} requires a valid ISO timestamp`);
  }
  return new Date(timestamp).toISOString();
}

function requiredSha256(value, label) {
  const normalized = String(value ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(normalized)) {
    throw new Error(`${label} requires a lowercase SHA-256 value`);
  }
  return normalized;
}
