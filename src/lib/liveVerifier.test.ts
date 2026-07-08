import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verifyLiveEndpoints } from '../../scripts/verify-live.mjs';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const expectedRepository = 'openclaw/openclaw';
const expectedCurrentReleaseTag = 'v2026.7.5';
const requiredCheckNames = [
  'closureProof',
  'database',
  'ingestion',
  'recommendation',
  'releaseWindow',
  'scoreAudit',
  'sourceIdentity',
];

type HealthFixture = {
  schemaVersion: number;
  ok: boolean;
  status: string;
  checkedAt: string;
  repo: string;
  currentRelease: {
    tag: string;
    publishedAt: string;
    diagnosticScoredAt: string;
    diagnosticStatus: string;
    diagnosticPreviouslyRecommended: boolean;
  };
  checks: Record<string, { ok: boolean }>;
  failures: Array<Record<string, unknown>>;
};

function healthyLivePayload() {
  return {
    ok: true,
    status: 'live',
    repo: expectedRepository,
  };
}

function healthyHealthPayload(): HealthFixture {
  return {
    schemaVersion: 1,
    ok: true,
    status: 'ready',
    checkedAt: '2026-07-06T18:00:00.000Z',
    repo: expectedRepository,
    currentRelease: {
      tag: expectedCurrentReleaseTag,
      publishedAt: '2026-07-05T18:00:00Z',
      diagnosticScoredAt: '2026-07-06T17:00:00Z',
      diagnosticStatus: 'eligible',
      diagnosticPreviouslyRecommended: true,
    },
    checks: Object.fromEntries(requiredCheckNames.map((name) => [name, { ok: true }])),
    failures: [],
  };
}

function endpointFetch(input: {
  live?: unknown;
  health?: unknown;
} = {}) {
  const live = input.live ?? healthyLivePayload();
  const health = input.health ?? healthyHealthPayload();
  return async (url: string | URL | Request) => {
    const path = new URL(String(url)).pathname;
    return Response.json(path === '/api/live' ? live : health, { status: 200 });
  };
}

describe('live endpoint verifier', () => {
  it('checks liveness before semantic readiness and requires every readiness check to pass', async () => {
    const calls: string[] = [];
    const fetchImpl = endpointFetch();
    const result = await verifyLiveEndpoints({
      apiBase: 'https://radar.example.test/',
      expectedRepository,
      expectedCurrentReleaseTag,
      fetchImpl: async (url: string | URL | Request) => {
        const path = new URL(String(url)).pathname;
        calls.push(path);
        return fetchImpl(url);
      },
    });

    assert.deepEqual(calls, ['/api/live', '/api/health']);
    assert.equal(result.live.status, 'live');
    assert.equal(result.health.status, 'ready');
    assert.equal(result.health.currentRelease.tag, expectedCurrentReleaseTag);
  });

  it('allows explicit loopback HTTP for local verification', async () => {
    const result = await verifyLiveEndpoints({
      apiBase: 'http://127.0.0.1:8787/',
      expectedRepository,
      expectedCurrentReleaseTag,
      fetchImpl: endpointFetch(),
    });

    assert.equal(result.apiBase, 'http://127.0.0.1:8787');
  });

  it('rejects non-loopback HTTP before issuing a request', async () => {
    let fetched = false;
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'http://radar.example.test',
        expectedRepository,
        fetchImpl: async () => {
          fetched = true;
          return Response.json(healthyLivePayload());
        },
      }),
      /must use HTTPS unless it targets explicit loopback/,
    );
    assert.equal(fetched, false);
  });

  it('rejects ambiguous API base credentials, queries, and fragments', async () => {
    for (const apiBase of [
      'https://user@radar.example.test',
      'https://radar.example.test?target=other',
      'https://radar.example.test/#other',
    ]) {
      await assert.rejects(
        verifyLiveEndpoints({
          apiBase,
          expectedRepository,
          fetchImpl: endpointFetch(),
        }),
        /must not contain credentials, a query, or a fragment/,
      );
    }
  });

  it('rejects a non-ready health payload even when HTTP succeeds', async () => {
    const health = healthyHealthPayload();
    health.checks.recommendation = { ok: false };
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'https://radar.example.test',
        expectedRepository,
        expectedCurrentReleaseTag,
        fetchImpl: endpointFetch({ health }),
      }),
      /checks are not all ok: recommendation/,
    );
  });

  it('rejects incomplete ready payloads instead of accepting one successful process check', async () => {
    const cases: Array<{
      name: string;
      mutate: (payload: ReturnType<typeof healthyHealthPayload>) => void;
      pattern: RegExp;
    }> = [
      {
        name: 'process-only checks',
        mutate: (payload) => {
          payload.checks = { process: { ok: true } };
        },
        pattern: /\/api\/health checks keys must equal/,
      },
      {
        name: 'missing schema',
        mutate: (payload) => {
          delete (payload as Partial<typeof payload>).schemaVersion;
        },
        pattern: /\/api\/health must include keys/,
      },
      {
        name: 'wrong schema',
        mutate: (payload) => {
          payload.schemaVersion = 2;
        },
        pattern: /schemaVersion must equal 1/,
      },
      {
        name: 'top-level ok false',
        mutate: (payload) => {
          payload.ok = false;
        },
        pattern: /\/api\/health ok must equal true/,
      },
      {
        name: 'missing current release',
        mutate: (payload) => {
          delete (payload as Partial<typeof payload>).currentRelease;
        },
        pattern: /\/api\/health must include keys/,
      },
      {
        name: 'nonempty failures',
        mutate: (payload) => {
          payload.failures = [{ code: 'not_ready' }];
        },
        pattern: /failures must be an empty array/,
      },
      {
        name: 'missing required check',
        mutate: (payload) => {
          const { sourceIdentity: _sourceIdentity, ...remainingChecks } = payload.checks;
          payload.checks = remainingChecks;
        },
        pattern: /\/api\/health checks keys must equal/,
      },
      {
        name: 'blank current release tag',
        mutate: (payload) => {
          payload.currentRelease.tag = '';
        },
        pattern: /currentRelease\.tag must be a non-empty string/,
      },
    ];

    for (const testCase of cases) {
      const health = healthyHealthPayload();
      testCase.mutate(health);
      await assert.rejects(
        verifyLiveEndpoints({
          apiBase: 'https://radar.example.test',
          expectedRepository,
          expectedCurrentReleaseTag,
          fetchImpl: endpointFetch({ health }),
        }),
        testCase.pattern,
        testCase.name,
      );
    }
  });

  it('requires complete liveness identity before checking readiness', async () => {
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'https://radar.example.test',
        expectedRepository,
        expectedCurrentReleaseTag,
        fetchImpl: endpointFetch({
          live: { ok: true, status: 'live' },
        }),
      }),
      /\/api\/live must include keys/,
    );
  });

  it('requires both endpoints to identify the expected repository and current release', async () => {
    const health = healthyHealthPayload();
    health.repo = 'other/repository';
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'https://radar.example.test',
        expectedRepository,
        expectedCurrentReleaseTag,
        fetchImpl: endpointFetch({ health }),
      }),
      /\/api\/health repo must equal openclaw\/openclaw/,
    );

    const wrongRelease = healthyHealthPayload();
    wrongRelease.currentRelease.tag = 'v2026.7.4';
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'https://radar.example.test',
        expectedRepository,
        expectedCurrentReleaseTag,
        fetchImpl: endpointFetch({ health: wrongRelease }),
      }),
      /currentRelease\.tag must equal v2026\.7\.5/,
    );
  });

  it('reports a non-200 status before attempting to parse the response body', async () => {
    await assert.rejects(
      verifyLiveEndpoints({
        apiBase: 'https://radar.example.test',
        expectedRepository,
        expectedCurrentReleaseTag,
        fetchImpl: async () => new Response('<html>not found</html>', {
          status: 404,
          headers: { 'content-type': 'text/html' },
        }),
      }),
      /\/api\/live returned HTTP 404/,
    );
  });

  it('keeps the deployment workflow and installer on the two-phase safety contract', () => {
    const workflow = readFileSync(
      join(root, '.github/workflows/deploy-radar.yml'),
      'utf8',
    );
    const installer = readFileSync(
      join(root, 'ops/viralo/openclaw-release-radar-install-release.sh'),
      'utf8',
    );

    assert.match(workflow, /cancel-in-progress: false/);
    assert.doesNotMatch(workflow, /cancel-in-progress: true/);
    assert.doesNotMatch(workflow, /ssh-keyscan/);
    assert.match(workflow, /secrets\.DEPLOY_SSH_KNOWN_HOSTS/);
    assert.match(workflow, /StrictHostKeyChecking=yes/g);
    assert.match(workflow, /UserKnownHostsFile="\$HOME\/\.ssh\/known_hosts"/g);
    assert.match(workflow, /--connect-timeout 5/);
    assert.match(workflow, /--max-time 10/);
    assert.match(
      workflow,
      /timeout --signal=TERM --kill-after=15s 8m[\s\\]*bash -c 'API_BASE="\$public_base" npm run ui:smoke'/,
    );

    assert.match(workflow, /INSTALLER_PROTOCOL: "5"/);
    assert.match(workflow, /schemaVersion: 4/);
    assert.match(workflow, /provenance\.schemaVersion !== 2/);
    assert.match(workflow, /releaseName: process\.env\.RELEASE_NAME/);
    assert.match(workflow, /githubSha: process\.env\.GIT_SHA/);
    assert.match(workflow, /artifactDigest: process\.env\.ARTIFACT_DIGEST/);
    assert.match(workflow, /public', 'release-manifest\.json'/);
    assert.match(workflow, /payload\.githubSha !== process\.argv\[3\]/);
    assert.match(workflow, /payload\.artifactDigest !== process\.argv\[4\]/);

    const activate = workflow.indexOf('install-release activate');
    const publicHealth = workflow.indexOf('name: Verify public health endpoint');
    const ui = workflow.indexOf('name: Verify deployed public UI');
    const commit = workflow.indexOf('install-release commit');
    const rollbackStep = workflow.indexOf('install-release rollback');
    assert.ok(activate >= 0);
    assert.ok(activate < publicHealth);
    assert.ok(publicHealth < ui);
    assert.ok(ui < commit);
    assert.ok(commit < rollbackStep);
    assert.match(
      workflow,
      /if: \$\{\{ always\(\) && steps\.activate\.outcome != 'skipped' && steps\.commit\.outcome != 'success' \}\}/,
    );
    assert.match(
      workflow,
      /committed\|rolled_back\|not_found\)[\s\S]*?exit 0[\s\S]*?verified\|commit_decided\)[\s\S]*?install-release reconcile[\s\S]*?expected_state=committed[\s\S]*?pending_verification\)[\s\S]*?install-release rollback[\s\S]*?expected_state=rolled_back[\s\S]*?preparing\|rollback_decided\)[\s\S]*?install-release reconcile/,
    );
    assert.equal(
      (workflow.match(/install-release commit/g) ?? []).length,
      1,
      'lost commit responses must recover through installer reconciliation',
    );

    assert.match(installer, /"\$flock_bin" -w "\$lock_timeout_seconds" 9/);
    assert.match(installer, /write_pending_state/);
    assert.match(installer, /restore_previous_release/);
    assert.match(installer, /trap 'activation_signal HUP' HUP/);
    assert.match(installer, /trap 'activation_signal INT' INT/);
    assert.match(installer, /trap 'activation_signal TERM' TERM/);
    assert.match(installer, /watchdog_release/);
    assert.match(installer, /lock_timeout_seconds=.*120/);
    assert.match(installer, /pending_timeout_seconds=.*2400/);
    assert.match(installer, /validate_manifest_file "\$staging_dir"/);
    assert.match(installer, /computed_digest="\$\(release_digest "\$root"\)"/);
    assert.match(installer, /--connect-timeout "\$probe_connect_timeout_seconds"/);
    assert.match(installer, /--max-time "\$probe_max_time_seconds"/);
    assert.match(installer, /validate_auto_refresh_disabled/);
    assert.match(installer, /REFRESH_ON_STARTUP/);
    assert.match(installer, /REFRESH_MINUTES/);
    assert.match(installer, /write_finalization_record/);
    assert.match(installer, /recover_finalized_state/);
    assert.match(installer, /recover_completed_state/);
    assert.match(installer, /completion_root=.*deploy-completions/);
    const activationBody = installer.indexOf('\nactivate_release()');
    assert.ok(activationBody >= 0);
    const activationEnd = installer.indexOf('\nauthorize_release()', activationBody);
    assert.ok(activationEnd >= 0);
    assert.ok(activationBody < activationEnd);
    const activation = installer.slice(activationBody, activationEnd);
    const intentWrite = activation.indexOf('\n  write_activation_intent ');
    const serviceStop = activation.indexOf(
      '"$systemctl_bin" stop "$service_name"',
    );
    const snapshot = activation.indexOf(
      '\n  snapshot_database || exit 1\n',
    );
    const watchdogArm = activation.indexOf(
      '\n  start_watchdog || exit 1\n',
    );
    const pendingWrite = activation.indexOf(
      'write_pending_state "$previous_current_present"',
    );
    const promotion = activation.indexOf(
      '\n    run_quality_promotion || exit 1\n',
    );
    const liveSwitch = activation.indexOf('switch_current "$release_dir"', pendingWrite);
    assert.ok(intentWrite >= 0);
    assert.ok(serviceStop >= 0);
    assert.ok(snapshot >= 0);
    assert.ok(pendingWrite >= 0);
    assert.ok(watchdogArm >= 0);
    assert.ok(promotion >= 0);
    assert.ok(liveSwitch >= 0);
    assert.ok(activationBody + intentWrite < activationEnd);
    assert.ok(activationBody + serviceStop < activationEnd);
    assert.ok(activationBody + snapshot < activationEnd);
    assert.ok(activationBody + pendingWrite < activationEnd);
    assert.ok(activationBody + watchdogArm < activationEnd);
    assert.ok(activationBody + promotion < activationEnd);
    assert.ok(activationBody + liveSwitch < activationEnd);
    assert.ok(intentWrite < serviceStop);
    assert.ok(serviceStop < snapshot);
    assert.ok(snapshot < pendingWrite);
    assert.ok(pendingWrite < watchdogArm);
    assert.ok(watchdogArm < promotion);
    assert.ok(promotion < liveSwitch);
    assert.ok(pendingWrite < liveSwitch);

    const rollbackBody = installer.indexOf('\nrestore_previous_release()');
    assert.ok(rollbackBody >= 0);
    const rollbackEnd = installer.indexOf('\nactivation_exit()', rollbackBody);
    assert.ok(rollbackEnd >= 0);
    assert.ok(rollbackBody < rollbackEnd);
    const rollback = installer.slice(rollbackBody, rollbackEnd);
    const previousTargetBranch = rollback.indexOf(
      '\n  if [ "$previous_present" = "1" ]; then\n',
    );
    const previousTargetStop = rollback.indexOf(
      '\n      ! "$systemctl_bin" stop "$service_name"; then\n',
      previousTargetBranch,
    );
    const previousTargetRestore = rollback.indexOf(
      '\n    if ! restore_database_snapshot; then\n',
      previousTargetStop,
    );
    const previousTargetSwitch = rollback.indexOf(
      '\n      switch_current "$previous_target" || return 1\n',
      previousTargetRestore,
    );
    const firstReleaseBranch = rollback.indexOf(
      '\n  else\n    if [ "$current_target" != "$candidate_dir" ] && [ "$current_present" -eq 1 ]; then\n',
      previousTargetSwitch,
    );
    const firstReleaseStop = rollback.indexOf(
      '\n      ! "$systemctl_bin" stop "$service_name"; then\n',
      firstReleaseBranch,
    );
    const firstReleaseRestore = rollback.indexOf(
      '\n    if ! restore_database_snapshot; then\n',
      firstReleaseStop,
    );
    const firstReleaseRemoval = rollback.indexOf(
      '\n      rm -f "$current" || return 1\n',
      firstReleaseRestore,
    );
    const rollbackFinalization = rollback.indexOf(
      '\n  write_finalization_record rolled-back || return 1\n',
      firstReleaseRemoval,
    );
    assert.ok(previousTargetBranch >= 0);
    assert.ok(previousTargetStop >= 0);
    assert.ok(previousTargetRestore >= 0);
    assert.ok(previousTargetSwitch >= 0);
    assert.ok(firstReleaseBranch >= 0);
    assert.ok(firstReleaseStop >= 0);
    assert.ok(firstReleaseRestore >= 0);
    assert.ok(firstReleaseRemoval >= 0);
    assert.ok(rollbackFinalization >= 0);
    assert.ok(rollbackBody + previousTargetBranch < rollbackEnd);
    assert.ok(rollbackBody + previousTargetStop < rollbackEnd);
    assert.ok(rollbackBody + previousTargetRestore < rollbackEnd);
    assert.ok(rollbackBody + previousTargetSwitch < rollbackEnd);
    assert.ok(rollbackBody + firstReleaseBranch < rollbackEnd);
    assert.ok(rollbackBody + firstReleaseStop < rollbackEnd);
    assert.ok(rollbackBody + firstReleaseRestore < rollbackEnd);
    assert.ok(rollbackBody + firstReleaseRemoval < rollbackEnd);
    assert.ok(rollbackBody + rollbackFinalization < rollbackEnd);
    assert.ok(previousTargetBranch < previousTargetStop);
    assert.ok(previousTargetStop < previousTargetRestore);
    assert.ok(previousTargetRestore < previousTargetSwitch);
    assert.ok(previousTargetSwitch < firstReleaseBranch);
    assert.ok(previousTargetSwitch < rollbackFinalization);
    assert.ok(firstReleaseBranch < firstReleaseStop);
    assert.ok(firstReleaseStop < firstReleaseRestore);
    assert.ok(firstReleaseRestore < firstReleaseRemoval);
    assert.ok(firstReleaseRemoval < rollbackFinalization);
  });
});
