export function assertSupportedNodeVersion(
  version = process.versions.node,
) {
  const match = String(version).match(/^(\d+)\.(\d+)\.(\d+)/);
  if (!match) {
    throw new Error(`Unable to parse Node.js version: ${String(version)}`);
  }
  const observed = match.slice(1).map(Number);
  const minimum = [22, 16, 0];
  for (let index = 0; index < minimum.length; index += 1) {
    if (observed[index] > minimum[index]) return;
    if (observed[index] < minimum[index]) {
      throw new Error(
        `Node.js >=22.16.0 is required by the authoritative test runner; ` +
        `observed ${version}.`,
      );
    }
  }
}
