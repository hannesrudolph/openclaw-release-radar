import type {
  ReleaseValidationProofBundle,
} from './releaseValidationProof';

type DatabaseGuardInstallation = {
  assertActive(options: {
    requirePrivateArtifacts: true;
  }): {
    policyKind: string;
    databaseIdentity: {
      dev: string;
      ino: string;
    } | null;
  };
};

const databaseGuard = require(
  '../../test/database-guard-runtime.cjs',
) as DatabaseGuardInstallation;
const guardAttestation = databaseGuard.assertActive({
  requirePrivateArtifacts: true,
});
if (
  guardAttestation.policyKind !==
  'authoritative-test-database-guard-policy'
) {
  throw new Error(
    'Release validation evaluation helper requires the authoritative kernel write boundary',
  );
}

async function main(): Promise<void> {
  const {
    planReleaseValidationProofLifecycle,
  } = await import('./releaseValidationProofLifecycle');
  const {
    appendReleaseValidationProof,
    db,
  } = await import('./db');

  const repository = 'openclaw/openclaw';
  const publishedAt = '2026-01-01T00:00:00.000Z';
  const lifecycle = planReleaseValidationProofLifecycle({
    existing: emptyProofBundle(),
    repository,
    observedAt: publishedAt,
    source: 'evaluation-cli-fixture-catalog',
    releases: [{
      repository,
      nodeId: 'R_evaluation_cli_fixture',
      tagCommitOid: 'a'.repeat(40),
      publishedAt,
      aliases: ['2026.1.0'],
    }],
    modelVersion: 'model-evaluation-cli',
    promptVersion: 9,
    codeRevision: 'evaluation-cli-revision',
    policyCode: 'prospective-release-validation',
    policyVersion: 1,
    developmentArm: 'production',
  });
  const persistence = appendReleaseValidationProof(lifecycle.bundle);
  db.close();

  console.log(JSON.stringify({
    insertedCount: persistence.insertedCount,
    proofEpochId: lifecycle.epoch.proofEpochId,
    cohortId: lifecycle.cohort.cohortId,
  }));
}

function emptyProofBundle(): ReleaseValidationProofBundle {
  return {
    epochs: [],
    retirements: [],
    policies: [],
    cohorts: [],
    catalogObservations: [],
    catalogMembers: [],
    catalogReconciliations: [],
    catalogReconciliationRows: [],
    obligations: [],
    splitAssignments: [],
    forecasts: [],
    outcomes: [],
    observationBatches: [],
    evaluationReceipts: [],
    promotionReceipts: [],
  };
}

void main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
