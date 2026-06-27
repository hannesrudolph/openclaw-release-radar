export interface NpmArtifactEvidence {
  version: string | null;
  integrity: string | null;
  tarballUrl: string | null;
  verified: boolean;
  mismatch: string | null;
}

export function npmVersionFromTag(tag: string): string {
  return tag.replace(/^v/, '');
}

export async function verifyNpmArtifact(input: {
  tag: string;
  expectedIntegrity: string | null;
  expectedTarballUrl: string | null;
}): Promise<NpmArtifactEvidence> {
  const version = npmVersionFromTag(input.tag);
  const url = `https://registry.npmjs.org/openclaw/${encodeURIComponent(version)}`;
  const response = await fetch(url, {
    headers: { 'user-agent': 'openclaw-release-radar' },
  });
  if (response.status === 404) {
    return {
      version: null,
      integrity: null,
      tarballUrl: null,
      verified: false,
      mismatch: `npm version ${version} not found`,
    };
  }
  if (!response.ok) {
    throw new Error(`npm registry ${response.status}: ${await response.text()}`);
  }
  const json = await response.json() as {
    version?: string;
    dist?: { integrity?: string; tarball?: string };
  };
  const registryVersion = json.version ?? null;
  const registryIntegrity = json.dist?.integrity ?? null;
  const registryTarball = json.dist?.tarball ?? null;
  const mismatches: string[] = [];
  if (registryVersion !== version) mismatches.push(`registry version ${registryVersion ?? 'missing'} != ${version}`);
  if (input.expectedIntegrity && registryIntegrity !== input.expectedIntegrity) {
    mismatches.push('registry integrity mismatch');
  }
  if (input.expectedTarballUrl && registryTarball !== input.expectedTarballUrl) {
    mismatches.push('registry tarball mismatch');
  }
  return {
    version: registryVersion,
    integrity: registryIntegrity,
    tarballUrl: registryTarball,
    verified: mismatches.length === 0 && !!registryVersion && !!registryIntegrity && !!registryTarball,
    mismatch: mismatches.length ? mismatches.join('; ') : null,
  };
}
