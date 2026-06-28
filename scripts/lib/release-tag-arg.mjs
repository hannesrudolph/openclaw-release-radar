export function releaseTagArg(argv, {
  defaultTag = 'v2026.6.10',
  command,
  description,
} = {}) {
  const args = [...argv];
  if (args.includes('--help') || args.includes('-h')) {
    console.log([
      description,
      '',
      `Usage: ${command ?? 'script'} [release-tag]`,
      '',
      `Default release tag: ${defaultTag}`,
      'Examples:',
      `  ${command ?? 'script'} ${defaultTag}`,
      `  ${command ?? 'script'} --help`,
    ].filter(Boolean).join('\n'));
    process.exit(0);
  }
  if (args.length > 1) {
    fail(`Expected at most one release tag, got ${args.length}.`, command);
  }
  const tag = args[0] ?? defaultTag;
  if (!tag || tag.startsWith('-') || /\s/.test(tag)) {
    fail(`Invalid release tag: ${JSON.stringify(tag)}.`, command);
  }
  return tag;
}

function fail(message, command) {
  console.error(message);
  console.error(`Run ${command ?? 'script'} --help for usage.`);
  process.exit(1);
}
