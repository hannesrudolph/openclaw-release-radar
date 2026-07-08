import { createHash } from 'node:crypto';

export interface RepositoryAdvisoryDigestInput {
  ghsa_id: string;
  cve_id: string | null;
  summary: string;
  severity: string;
  state: string;
  published_at: string | null;
  withdrawn_at: string | null;
  updated_at: string | null;
  html_url: string;
  vulnerabilities: Array<{
    package: { ecosystem: string | null; name: string | null } | null;
    vulnerable_version_range: string | null;
    patched_versions: string | null;
  }>;
}

function compareBinary(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

function normalizedAdvisoryText(value: string): string {
  return value.trim().replace(/\s+/g, ' ');
}

function advisoryRangeIdentity(
  ghsaId: string,
  vulnerability: RepositoryAdvisoryDigestInput['vulnerabilities'][number],
): string {
  return [
    ghsaId,
    String(vulnerability.package?.ecosystem ?? '').trim().toLowerCase(),
    String(vulnerability.package?.name ?? '').trim().toLowerCase(),
    normalizedAdvisoryText(String(vulnerability.vulnerable_version_range ?? '')),
  ].map((part) => encodeURIComponent(part)).join(':');
}

export function repositoryAdvisoryCatalogContentDigest(
  advisories: readonly RepositoryAdvisoryDigestInput[],
): string {
  const ghsaIds = advisories.map((advisory) => advisory.ghsa_id);
  if (new Set(ghsaIds).size !== ghsaIds.length) {
    throw new Error(
      'Repository security advisory digest received duplicate GHSA nodes',
    );
  }
  const canonical = advisories
    .slice()
    .sort((left, right) => compareBinary(left.ghsa_id, right.ghsa_id))
    .map((advisory) => [
      advisory.ghsa_id,
      advisory.cve_id,
      advisory.summary,
      advisory.severity,
      advisory.state,
      advisory.published_at,
      advisory.withdrawn_at,
      advisory.html_url,
      advisory.updated_at,
      advisory.vulnerabilities
        .slice()
        .sort((left, right) =>
          compareBinary(
            advisoryRangeIdentity(advisory.ghsa_id, left),
            advisoryRangeIdentity(advisory.ghsa_id, right),
          ))
        .map((vulnerability) => [
          advisoryRangeIdentity(advisory.ghsa_id, vulnerability),
          vulnerability.package?.ecosystem ?? null,
          vulnerability.package?.name ?? null,
          vulnerability.vulnerable_version_range,
          vulnerability.patched_versions,
        ]),
    ]);
  return createHash('sha256')
    .update(JSON.stringify([advisories.length, canonical]))
    .digest('hex');
}
