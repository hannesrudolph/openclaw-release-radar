import { openReleaseAuditReader } from './lib/release-audit-reader.mjs';
import { verifyReleaseAudit } from './lib/release-audit-invariants.mjs';

const args = parseArgs(process.argv.slice(2));
const limit = Number(args.limit ?? process.env.RELEASES_LIMIT ?? 10);
const dbPath = args['db-path'] ?? process.env.DB_PATH ?? './data/radar.db';
const apiBase = args['api-base'] ?? process.env.API_BASE ?? null;

let reader;
try {
  reader = openReleaseAuditReader(dbPath);
  const result = await verifyReleaseAudit({ reader, apiBase, limit });
  console.table(result.rows);
  if (result.failures.length) {
    console.error(`\n${result.failures.length} release audit invariant failure(s):`);
    for (const failure of result.failures) console.error(`- ${failure}`);
    process.exit(1);
  }
  console.log(`\nRelease audit invariants passed for ${result.releases.length} release(s).`);
} finally {
  reader?.close();
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg.startsWith('--')) continue;
    const key = arg.slice(2);
    const next = argv[i + 1];
    if (!next || next.startsWith('--')) {
      out[key] = true;
    } else {
      out[key] = next;
      i++;
    }
  }
  return out;
}
