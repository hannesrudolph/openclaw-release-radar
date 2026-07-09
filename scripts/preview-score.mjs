import {
  chmodSync,
  existsSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import {
  auditPreviewCatalog,
  buildPreviewScoreReport,
  buildScorePreview,
  closeScorePreviewDatabase,
  parsePreviewScoreArgs,
  previewInspectionDriftReasons,
  readPreviewInspection,
} from './lib/preview-score-runtime.ts';

const options = parsePreviewScoreArgs(process.argv.slice(2));
if (!existsSync(options.databasePath)) {
  throw new Error(`Database not found: ${options.databasePath}`);
}

process.env.DB_PATH = options.databasePath;
process.env.RADAR_DB_READ_ONLY = '1';
process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing';
process.env.REFRESH_MINUTES = '0';
process.env.REFRESH_ON_STARTUP = 'false';

const runtimeDirectory = mkdtempSync(join(tmpdir(), 'radar-score-preview-'));
chmodSync(runtimeDirectory, 0o700);
const emptyDotenvPath = join(runtimeDirectory, 'empty.env');
writeFileSync(emptyDotenvPath, '', { mode: 0o600 });
process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;

try {
  const evaluatedAt = new Date().toISOString();
  const initialInspection = inspectDatabase(options.databasePath);
  const initialAudit = auditPreviewCatalog(
    initialInspection,
    options.range,
  );
  let scoreBundle = null;
  let scoreError = null;
  if (
    initialAudit.reasons.length === 0 &&
    initialAudit.classifierKnownTags
  ) {
    try {
      scoreBundle = await buildScorePreview({
        range: options.range,
        classifierKnownTags: initialAudit.classifierKnownTags,
        issueCrawlMetadata: initialAudit.issueCrawlMetadata,
        evaluatedAt,
      });
    } catch (error) {
      scoreError = error instanceof Error ? error.message : String(error);
    }
  }

  const finalInspection = scoreBundle
    ? inspectDatabase(options.databasePath)
    : initialInspection;
  const finalAudit = auditPreviewCatalog(finalInspection, options.range);
  const additionalReasons = scoreBundle
    ? previewInspectionDriftReasons(initialInspection, finalInspection)
    : [];
  const report = buildPreviewScoreReport({
    databasePath: options.databasePath,
    range: options.range,
    inspection: finalInspection,
    audit: finalAudit,
    scoreBundle,
    additionalReasons,
    scoreError,
    evaluatedAt,
  });
  console.log(JSON.stringify(report, null, 2));
} finally {
  closeScorePreviewDatabase();
  rmSync(runtimeDirectory, { recursive: true, force: true });
}

function inspectDatabase(databasePath) {
  const inspection = new DatabaseSync(databasePath, { readOnly: true });
  try {
    inspection.exec('PRAGMA query_only = ON');
    return readPreviewInspection(inspection);
  } finally {
    inspection.close();
  }
}
