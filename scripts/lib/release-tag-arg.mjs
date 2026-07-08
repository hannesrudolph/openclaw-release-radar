export function releaseTagArg(argv, {
  command,
  description,
} = {}) {
  const args = [...argv];
  const invocation = command ?? 'script';
  if (args.includes('--help') || args.includes('-h')) {
    console.log([
      description,
      '',
      `Usage: ${invocation} <release-tag>`,
      '',
      'A release tag is required; this command never infers the latest release.',
      'Examples:',
      `  ${invocation} <release-tag>`,
      `  ${invocation} --help`,
    ].filter(Boolean).join('\n'));
    process.exit(0);
  }
  if (args.length !== 1) {
    fail(`Expected exactly one release tag, got ${args.length}.`, command);
  }
  const tag = args[0];
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
