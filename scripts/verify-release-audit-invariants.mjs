import { resolveReleaseAuditInvocation } from './lib/release-audit-cli.mjs';

process.env.RADAR_DB_READ_ONLY = '1';

const {
  args,
  dbPath,
  apiBase,
} = resolveReleaseAuditInvocation(process.argv.slice(2));
process.env.DB_PATH = dbPath;

let databaseModule;
let reader;
let operationError = null;
const cleanupErrors = [];
try {
  databaseModule = await import('../src/lib/db.ts');
  const [{ openReleaseAuditReader }, { verifyReleaseAudit }] = await Promise.all([
    import('./lib/release-audit-reader.mjs'),
    import('./lib/release-audit-invariants.mjs'),
  ]);
  // Transitive classification and authority helpers use this singleton connection.
  reader = openReleaseAuditReader(dbPath, {
    database: databaseModule.db,
    closeDatabase: true,
  });
  reader.assertSnapshotActive();
  const limit = args.all ? reader.scoredStableReleaseCount() : Number(args.limit ?? process.env.RELEASES_LIMIT ?? 10);
  const result = await verifyReleaseAudit({ reader, apiBase, limit, scoredOnly: args.all === true });
  reader.assertSnapshotActive();
  console.table(result.rows);
  if (result.failures.length) {
    console.error(`\n${result.failures.length} release audit invariant failure(s):`);
    for (const failure of result.failures) console.error(`- ${failure}`);
    process.exitCode = 1;
  } else {
    console.log(`\nRelease audit invariants passed for ${result.releases.length} release(s).`);
  }
} catch (error) {
  operationError = error;
} finally {
  try {
    if (reader) reader.close();
    else databaseModule?.db.close();
  } catch (error) {
    cleanupErrors.push(error);
  }
}

if (operationError && cleanupErrors.length > 0) {
  throw new AggregateError(
    [operationError, ...cleanupErrors],
    'Release audit verification and cleanup both failed',
  );
}
if (operationError) throw operationError;
if (cleanupErrors.length > 0) {
  throw new AggregateError(
    cleanupErrors,
    'Release audit verification cleanup failed',
  );
}
