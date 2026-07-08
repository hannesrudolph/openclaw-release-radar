export function resolveReleaseAuditInvocation(
  argv,
  environment = process.env,
) {
  const args = parseReleaseAuditArgs(argv);
  return {
    args,
    dbPath: args['db-path'] ?? environment.DB_PATH ?? './data/radar.db',
    apiBase: args['api-base'] ?? environment.API_BASE ?? null,
  };
}

export function parseReleaseAuditArgs(argv) {
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
