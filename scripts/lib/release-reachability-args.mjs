const DEFAULT_COMMAND = 'npm run check:release-pr-reachability --';

export function releaseReachabilityUsage(command = DEFAULT_COMMAND) {
  return [
    'Check release reachability for PR merge commits or prove one direct commit is first-containing.',
    '',
    `Usage: ${command} <release-tag>`,
    `       ${command} <release-tag> --direct-commit <oid> --repository <owner/name> --predecessor <release-tag>`,
    '',
    'A release tag is required; this command never infers the latest release.',
  ].join('\n');
}

export function parseReleaseReachabilityArgs(
  argv,
  { command = DEFAULT_COMMAND } = {},
) {
  const args = [...argv];
  if (args.includes('--help') || args.includes('-h')) return { mode: 'help' };
  if (args.length === 1) {
    return {
      mode: 'pull_requests',
      tag: releaseTag(args[0], command),
    };
  }

  const values = new Map();
  const positional = [];
  for (let index = 0; index < args.length; index++) {
    const arg = args[index];
    if (!arg.startsWith('-')) {
      positional.push(arg);
      continue;
    }
    if (!['--direct-commit', '--repository', '--predecessor'].includes(arg)) {
      throw new Error(`Unknown option ${arg}. Run ${command} --help for usage.`);
    }
    if (values.has(arg)) {
      throw new Error(`Option ${arg} may be specified only once.`);
    }
    const value = args[++index];
    if (!value || value.startsWith('-')) {
      throw new Error(`Option ${arg} requires a value.`);
    }
    values.set(arg, value);
  }
  if (positional.length !== 1) {
    throw new Error(`Expected exactly one release tag, got ${positional.length}.`);
  }
  for (const option of ['--direct-commit', '--repository', '--predecessor']) {
    if (!values.has(option)) {
      throw new Error(`Direct commit mode requires ${option}.`);
    }
  }

  return {
    mode: 'direct_commit',
    tag: releaseTag(positional[0], command),
    commitOid: values.get('--direct-commit'),
    repositoryNameWithOwner: values.get('--repository'),
    predecessorTag: releaseTag(values.get('--predecessor'), command),
  };
}

function releaseTag(value, command) {
  if (typeof value !== 'string' || !value || value.startsWith('-') || /\s/.test(value)) {
    throw new Error(`Invalid release tag: ${JSON.stringify(value)}. Run ${command} --help for usage.`);
  }
  return value;
}
