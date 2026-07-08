import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash, createHmac, randomUUID } from 'node:crypto';
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  readlinkSync,
  readdirSync,
  realpathSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';
import { DatabaseSync } from 'node:sqlite';
import { gzipSync } from 'node:zlib';
import {
  INSTALLER_PENDING_STATE_FIELDS,
  INSTALLER_PENDING_STATE_SCHEMA_VERSION,
  installerPendingStateHash,
} from '../../scripts/promote-quality-db.mjs';
import {
  type StartupAuthorizationPayload,
  type StartupAuthorizationRecord,
  startupAuthorizationContentHash,
  verifyProductionStartupAuthorization,
} from './startupAuthorization';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const productionInstaller = join(
  root,
  'ops/viralo/openclaw-release-radar-install-release.sh',
);
const installerFixturePath =
  process.env.RADAR_TEST_INSTALLER_FIXTURE_PATH || productionInstaller;
const runtimeUser = commandOutput('id', ['-un']);
const runtimeGroup = commandOutput('id', ['-gn']);
const githubSha = 'a'.repeat(40);
const scoreReceiptId = 'b'.repeat(64);
const testFaultNonce = 'c'.repeat(64);
const verificationId = '123456:1';
const verifierKey = 'release-radar-test-verifier-key-'.repeat(2);
const watchdogCompletionTimeoutMs = 30_000;

describe('release installer safety', () => {
  it('exposes and enforces the versioned installer protocol', () => {
    const current = spawnSync('bash', [installerFixturePath, 'protocol'], {
      cwd: root,
      encoding: 'utf8',
    });
    assert.equal(current.status, 0, current.stderr);
    assert.equal(current.stdout.trim(), '5');

    const mismatch = spawnSync(
      'bash',
      [installerFixturePath, 'protocol', '2'],
      {
        cwd: root,
        encoding: 'utf8',
      },
    );
    assert.notEqual(mismatch.status, 0);
    assert.match(mismatch.stderr, /installer protocol mismatch/);
  });

  it('scrubs inherited startup injection at every deployment launch boundary', () => {
    const environmentNames = [
      'NODE_OPTIONS',
      'NODE_PATH',
      'BASH_ENV',
      'ENV',
      'LD_PRELOAD',
      'LD_LIBRARY_PATH',
      'LD_AUDIT',
    ];
    const installer = readFileSync(productionInstaller, 'utf8');
    const preflight = readFileSync(
      join(root, 'test/run-installer-preflight.mjs'),
      'utf8',
    );
    const workflow = readFileSync(
      join(root, '.github/workflows/deploy-radar.yml'),
      'utf8',
    );

    assert.match(installer, /scrub_startup_injection_environment/);
    assert.doesNotMatch(preflight, /\.\.\.process\.env/);
    assert.match(
      preflight,
      /PATH: '\/usr\/bin:\/bin:\/usr\/sbin:\/sbin'/,
    );
    assert.match(
      workflow,
      /\/bin\/bash -p --noprofile --norc -e -o pipefail -- \{0\}/,
    );
    assert.match(
      workflow,
      /sudo \/usr\/bin\/env -i PATH=.*\/bin\/bash -p --noprofile --norc \/usr\/local\/bin\/openclaw-release-radar-install-release/,
    );
    assert.doesNotMatch(
      workflow,
      /sudo \/usr\/local\/bin\/openclaw-release-radar-install-release/,
    );

    for (const name of environmentNames) {
      assert.match(installer, new RegExp(`\\b${name}\\b`));
      assert.match(workflow, new RegExp(`^  ${name}: ""$`, 'm'));
    }

    for (const relativePath of [
      'ops/viralo/openclaw-release-radar.service',
      'ops/viralo/openclaw-release-radar-reconcile-boot.service',
      'ops/viralo/openclaw-release-radar-reconcile.service',
    ]) {
      const unit = readFileSync(join(root, relativePath), 'utf8');
      const unset = new Set(
        unit
          .split('\n')
          .filter((line) => line.startsWith('UnsetEnvironment='))
          .flatMap((line) =>
            line.slice('UnsetEnvironment='.length).trim().split(/\s+/)
          ),
      );
      for (const name of environmentNames) {
        assert.ok(unset.has(name), `${relativePath} must unset ${name}`);
      }
      assert.match(unit, /ExecStart(?:Pre)?=\/usr\/bin\/env -i /);
    }
  });

  it('accepts only the exact pending activation and committed completion startup authorization', () => {
    const fixture = createStartupAuthorizationFixture('accepted-lifecycle');
    try {
      fixture.writePendingAuthorization();
      assert.equal(fixture.verify().lifecycle, 'pending-activation');

      fixture.writeCommittedAuthorization();
      const committed = fixture.verify();
      assert.equal(committed.lifecycle, 'committed-completion');
      assert.equal(committed.releaseSha, fixture.releaseRevision);
      assert.equal(committed.databasePath, realpathSync(fixture.databasePath));
      assert.equal(committed.scoreReceiptId, scoreReceiptId);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects missing, tampered, release-mismatched, and database-mismatched startup authorization', () => {
    const missing = createStartupAuthorizationFixture('missing');
    try {
      assert.throws(
        () => missing.verify(),
        /required installer authorization is missing/,
      );
    } finally {
      missing.cleanup();
    }

    const tampered = createStartupAuthorizationFixture('tampered');
    try {
      tampered.writePendingAuthorization();
      const record = tampered.readAuthorization();
      record.scoreReceipt.receiptId = '0'.repeat(64);
      tampered.writeRawAuthorization(record);
      assert.throws(
        () => tampered.verify(),
        /authorization content is invalid or tampered/,
      );
    } finally {
      tampered.cleanup();
    }

    const releaseMismatch = createStartupAuthorizationFixture(
      'release-mismatch',
    );
    try {
      const record = releaseMismatch.pendingAuthorization();
      record.release.sha = 'd'.repeat(40);
      record.contentHash = startupAuthorizationContentHash(
        authorizationPayload(record),
      );
      releaseMismatch.writeRawAuthorization(record);
      assert.throws(
        () => releaseMismatch.verify(),
        /release identity does not match the current runtime/,
      );
    } finally {
      releaseMismatch.cleanup();
    }

    const databasePathMismatch = createStartupAuthorizationFixture(
      'database-path-mismatch',
    );
    try {
      const record = databasePathMismatch.pendingAuthorization();
      record.database.realPath = join(
        dirname(databasePathMismatch.databasePath),
        'other.db',
      );
      record.contentHash = startupAuthorizationContentHash(
        authorizationPayload(record),
      );
      databasePathMismatch.writeRawAuthorization(record);
      assert.throws(
        () => databasePathMismatch.verify(),
        /authorization database path does not match production DB_PATH/,
      );
    } finally {
      databasePathMismatch.cleanup();
    }

    const databaseMismatch = createStartupAuthorizationFixture(
      'database-mismatch',
    );
    try {
      databaseMismatch.writePendingAuthorization();
      writeFileSync(
        databaseMismatch.databasePath,
        Buffer.concat([
          readFileSync(databaseMismatch.databasePath),
          Buffer.from('post-authorization-mutation'),
        ]),
      );
      assert.throws(
        () => databaseMismatch.verify(),
        /installed database physical digest does not match authorization/,
      );
    } finally {
      databaseMismatch.cleanup();
    }
  });

  it('rejects traversal and non-basename release names before touching releases', () => {
    const fixture = createInstallerFixture('invalid-name');
    try {
      const release = fixture.createTarball('valid-payload', 'release-valid');
      for (const releaseName of [
        '../escape',
        'nested/release',
        '..',
        '.hidden',
        'release..shadow',
        'release\\shadow',
      ]) {
        const result = fixture.run('activate', [
          release.tarball,
          releaseName,
          release.githubSha,
          release.digest,
        ], {}, fixture.dir);
        assert.notEqual(result.status, 0, releaseName);
        assert.match(result.stderr, /invalid release name/);
      }
      assert.deepEqual(readdirSync(fixture.releases), []);
      assert.equal(existsSync(join(fixture.dir, 'escape')), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('keeps an activated release pending until the matching commit succeeds', () => {
    const fixture = createInstallerFixture('activate-commit');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(JSON.parse(activated.stdout).status, 'pending_verification');
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        readFileSync(join(fixture.pending, 'github_sha'), 'utf8').trim(),
        release.githubSha,
      );
      assert.equal(
        readFileSync(join(fixture.pending, 'artifact_digest'), 'utf8').trim(),
        release.digest,
      );
      const pendingFields = readInstallerPendingFields(fixture.pending);
      assert.equal(
        pendingFields.pending_schema_version,
        String(INSTALLER_PENDING_STATE_SCHEMA_VERSION),
      );
      assert.equal(
        readFileSync(
          join(fixture.pending, 'pending_state_hash'),
          'utf8',
        ).trim(),
        installerPendingStateHash(pendingFields),
      );
      assert.match(pendingFields.tarball_sha256, /^[0-9a-f]{64}$/);
      assert.match(pendingFields.tarball_size_bytes, /^[1-9][0-9]*$/);
      const snapshotPath = readFileSync(
        join(fixture.pending, 'db_snapshot_path'),
        'utf8',
      ).trim();
      assert.equal(existsSync(snapshotPath), true);
      assert.equal(existsSync(release.tarball), true);

      const committed = fixture.commit(release);
      assert.equal(committed.status, 0, committed.stderr);
      assert.match(committed.stdout, /release release-candidate committed/);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(snapshotPath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
      ]);
      assert.deepEqual(
        fixture.flockCalls(),
        Array.from({ length: 4 }, () => '-w 7 9'),
      );

      const repeated = fixture.commit(release);
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.match(repeated.stdout, /release release-candidate committed/);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('does not consume an unrelated upload while another transaction is pending', () => {
    const fixture = createInstallerFixture('unrelated-pending');
    try {
      const first = fixture.createTarball('first', 'release-first');
      const second = fixture.createTarball('second', 'release-second');
      assert.equal(fixture.activate(first).status, 0);

      const blocked = fixture.activate(second);
      assert.notEqual(blocked.status, 0);
      assert.match(blocked.stderr, /another deployment is pending/);
      assert.equal(existsSync(second.sourceTarball), true);
      assert.equal(
        readFileSync(join(fixture.pending, 'release_name'), 'utf8').trim(),
        first.releaseName,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('permanently reserves completed transaction IDs', () => {
    const fixture = createInstallerFixture('transaction-id-reuse');
    try {
      const first = fixture.createTarball('first', 'release-first');
      const transactionId = randomUUID();
      const activated = fixture.activateWithTransactionId(first, transactionId);
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.commit(first).status, 0);

      const second = fixture.createTarball('second', 'release-second');
      const reused = fixture.activateWithTransactionId(second, transactionId);
      assert.notEqual(reused.status, 0);
      assert.match(reused.stderr, /transaction ID is already permanently reserved/);
      assert.equal(existsSync(second.sourceTarball), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('leaves the external upload untouched when adoption was interrupted', () => {
    const fixture = createInstallerFixture('before-adoption-interruption');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const interrupted = fixture.activate(release, {
        RADAR_TEST_SIGKILL_BEFORE_ARTIFACT_ADOPTION: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(existsSync(release.sourceTarball), true);
      assert.equal(
        existsSync(
          join(
            fixture.shared,
            'deploy-artifacts',
            `${fixture.transactionId(release)}.tar.gz`,
          ),
        ),
        false,
      );

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(existsSync(release.sourceTarball), true);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(fixture.current), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('requires exact external authorization before commit', () => {
    const fixture = createInstallerFixture('authorization-required');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const unauthorized = fixture.commitWithoutAuthorization(release);
      assert.notEqual(unauthorized.status, 0);
      assert.match(
        unauthorized.stderr,
        /deployment verification authorization is not a regular file/,
      );
      const pendingStatus = fixture.status(release);
      assert.equal(pendingStatus.status, 0, pendingStatus.stderr);
      assert.equal(JSON.parse(pendingStatus.stdout).status, 'pending_verification');

      const authorized = fixture.authorize(release);
      assert.equal(authorized.status, 0, authorized.stderr);
      const authorization = JSON.parse(authorized.stdout);
      assert.equal(authorization.status, 'verified');
      assert.equal(authorization.verificationId, verificationId);

      const committed = fixture.commitWithoutAuthorization(release);
      assert.equal(committed.status, 0, committed.stderr);
      assert.equal(JSON.parse(fixture.status(release).stdout).status, 'committed');
    } finally {
      fixture.cleanup();
    }
  });

  it('journals authorization exactly once and rejects tampering or verifier conflicts', () => {
    const fixture = createInstallerFixture('authorization-journal');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const tampered = fixture.authorizeAs(
        release,
        verificationId,
        '0'.repeat(64),
      );
      assert.notEqual(tampered.status, 0);
      assert.match(tampered.stderr, /verifier attestation does not match/);
      assert.equal(
        existsSync(join(fixture.pending, 'verification-authorization.json')),
        false,
      );

      const authorized = fixture.authorize(release);
      assert.equal(authorized.status, 0, authorized.stderr);
      const authorizationBytes = readFileSync(
        join(fixture.pending, 'verification-authorization.json'),
        'utf8',
      );
      const phases = () =>
        readdirSync(fixture.pending)
          .filter((entry) => /^phase-transition-[0-9]{4}\.json$/.test(entry))
          .sort()
          .map((entry) =>
            JSON.parse(
              readFileSync(join(fixture.pending, entry), 'utf8'),
            ).phase
          );
      assert.deepEqual(phases(), ['prepared', 'activated', 'verified']);

      const repeated = fixture.authorize(release);
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.equal(
        readFileSync(
          join(fixture.pending, 'verification-authorization.json'),
          'utf8',
        ),
        authorizationBytes,
      );
      assert.deepEqual(phases(), ['prepared', 'activated', 'verified']);

      const conflicting = fixture.authorizeAs(release, '123456:2');
      assert.notEqual(conflicting.status, 0);
      assert.match(
        conflicting.stderr,
        /already authorized by a different verification run/,
      );
      assert.deepEqual(phases(), ['prepared', 'activated', 'verified']);
    } finally {
      fixture.cleanup();
    }
  });

  it('recovers an interrupted authorization after the HMAC record became durable', () => {
    const fixture = createInstallerFixture('authorization-recovery');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const interrupted = fixture.authorize(release, {
        RADAR_TEST_SIGKILL_AFTER_AUTHORIZATION_RECORD: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(
          readFileSync(
            join(fixture.pending, 'phase-transition-0002.json'),
            'utf8',
          ),
        ).phase,
        'activated',
      );

      const retried = fixture.authorize(release);
      assert.equal(retried.status, 0, retried.stderr);
      assert.equal(JSON.parse(retried.stdout).phase, 'verified');
      assert.equal(
        JSON.parse(
          readFileSync(
            join(fixture.pending, 'phase-transition-0003.json'),
            'utf8',
          ),
        ).phase,
        'verified',
      );
      assert.equal(
        existsSync(join(fixture.pending, 'verification-acceptance.json')),
        true,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('recovers a verified phase that became durable before acceptance', () => {
    const fixture = createInstallerFixture('authorization-pre-acceptance');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      assert.equal(fixture.activate(release).status, 0);

      const interrupted = fixture.authorize(release, {
        RADAR_TEST_SIGKILL_AFTER_VERIFIED_PHASE: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(
          readFileSync(
            join(fixture.pending, 'phase-transition-0003.json'),
            'utf8',
          ),
        ).phase,
        'verified',
      );
      assert.equal(
        existsSync(join(fixture.pending, 'verification-acceptance.json')),
        false,
      );

      const retried = fixture.authorize(release);
      assert.equal(retried.status, 0, retried.stderr);
      assert.equal(
        existsSync(join(fixture.pending, 'verification-acceptance.json')),
        true,
      );
      assert.equal(JSON.parse(retried.stdout).phase, 'verified');
    } finally {
      fixture.cleanup();
    }
  });

  it('fails closed when an accepted verified phase is truncated or substituted', () => {
    for (const mutation of ['truncate', 'substitute'] as const) {
      const fixture = createInstallerFixture(`accepted-phase-${mutation}`);
      try {
        const release = fixture.createTarball('candidate', 'release-candidate');
        assert.equal(fixture.activate(release).status, 0);
        assert.equal(fixture.authorize(release).status, 0);
        const phasePath = join(
          fixture.pending,
          'phase-transition-0003.json',
        );

        if (mutation === 'truncate') {
          rmSync(phasePath);
        } else {
          const record = JSON.parse(readFileSync(phasePath, 'utf8'));
          record.recordedAt = new Date(
            Date.parse(record.recordedAt) + 1_000,
          ).toISOString();
          const payload = {
            schemaVersion: record.schemaVersion,
            sequence: record.sequence,
            phase: record.phase,
            transactionId: record.transactionId,
            pendingStateHash: record.pendingStateHash,
            previousHash: record.previousHash,
            recordedAt: record.recordedAt,
          };
          record.contentHash = createHash('sha256')
            .update(
              `installer-phase-transition-v1\0${JSON.stringify(payload)}`,
            )
            .digest('hex');
          writeFileSync(phasePath, `${JSON.stringify(record, null, 2)}\n`);
        }

        const status = fixture.status(release);
        assert.notEqual(status.status, 0);
        assert.match(
          status.stderr,
          /authenticated verifier acceptance|durable verified phase/,
        );
        if (mutation === 'truncate') {
          assert.equal(existsSync(phasePath), false);
        }
        assert.equal(
          existsSync(join(fixture.pending, 'verification-acceptance.json')),
          true,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects replay of an accepted phase from another transaction', () => {
    const source = createInstallerFixture('accepted-phase-replay-source');
    const target = createInstallerFixture('accepted-phase-replay-target');
    try {
      const sourceRelease = source.createTarball(
        'candidate',
        'release-candidate',
      );
      const targetRelease = target.createTarball(
        'candidate',
        'release-candidate',
      );
      assert.equal(source.activate(sourceRelease).status, 0);
      assert.equal(target.activate(targetRelease).status, 0);
      assert.equal(source.authorize(sourceRelease).status, 0);
      assert.equal(target.authorize(targetRelease).status, 0);

      writeFileSync(
        join(target.pending, 'phase-transition-0003.json'),
        readFileSync(
          join(source.pending, 'phase-transition-0003.json'),
        ),
      );
      const replayed = target.status(targetRelease);
      assert.notEqual(replayed.status, 0);
      assert.match(replayed.stderr, /phase transition chain is invalid/);
      assert.equal(existsSync(target.pending), true);
    } finally {
      source.cleanup();
      target.cleanup();
    }
  });

  it('rejects phase-chain tampering without changing the pending transaction', () => {
    const fixture = createInstallerFixture('phase-chain-tamper');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      assert.equal(fixture.activate(release).status, 0);
      const transitionPath = join(
        fixture.pending,
        'phase-transition-0002.json',
      );
      const transition = JSON.parse(readFileSync(transitionPath, 'utf8'));
      transition.previousHash = 'f'.repeat(64);
      writeFileSync(transitionPath, `${JSON.stringify(transition, null, 2)}\n`);

      const status = fixture.status(release);
      assert.notEqual(status.status, 0);
      assert.match(status.stderr, /phase transition chain is invalid/);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
    } finally {
      fixture.cleanup();
    }
  });

  it('treats authorization as an irreversible commit decision', () => {
    const fixture = createInstallerFixture('authorization-irreversible');
    try {
      fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const authorized = fixture.authorize(release);
      assert.equal(authorized.status, 0, authorized.stderr);

      const rollback = fixture.rollback(release);
      assert.notEqual(rollback.status, 0);
      assert.match(
        rollback.stderr,
        /verified deployment cannot be rolled back/,
      );
      assert.equal(readlinkSync(fixture.current), release.releasePath);

      const reconciled = fixture.reconcile();
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'committed');
      assert.equal(JSON.parse(fixture.status(release).stdout).status, 'committed');
    } finally {
      fixture.cleanup();
    }
  });

  it('preserves a valid unexpired activated transaction during boot reconciliation', () => {
    const fixture = createInstallerFixture('boot-reconcile-activated');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(
        JSON.parse(reconciled.stdout).status,
        'pending_verification',
      );
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.notEqual(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        JSON.parse(fixture.status(release).stdout).status,
        'pending_verification',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rolls back an undecided transaction during boot reconciliation', () => {
    const fixture = createInstallerFixture('boot-reconcile-prepared');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const interrupted = fixture.activate(release, {
        RADAR_TEST_SIGKILL_AFTER_PENDING: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(
          readFileSync(
            join(fixture.pending, 'phase-transition-0001.json'),
            'utf8',
          ),
        ).phase,
        'prepared',
      );
      assert.equal(readlinkSync(fixture.current), previous);

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'rollback_decided');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);

      const finalized = fixture.reconcile();
      assert.equal(finalized.status, 0, finalized.stderr);
      assert.equal(JSON.parse(finalized.stdout).status, 'rolled_back');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('rolls back when boot reconciliation finds current already restored', () => {
    const fixture = createInstallerFixture('boot-reconcile-current-mismatch');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      rmSync(fixture.current);
      symlinkSync(previous, fixture.current);

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'rollback_decided');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);

      const finalized = fixture.reconcile();
      assert.equal(finalized.status, 0, finalized.stderr);
      assert.equal(JSON.parse(finalized.stdout).status, 'rolled_back');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('rolls back a transaction with a malformed activation phase during boot reconciliation', () => {
    const fixture = createInstallerFixture('boot-reconcile-malformed-phase');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const transitionPath = join(
        fixture.pending,
        'phase-transition-0002.json',
      );
      const transition = JSON.parse(readFileSync(transitionPath, 'utf8'));
      transition.previousHash = 'f'.repeat(64);
      writeFileSync(
        transitionPath,
        `${JSON.stringify(transition, null, 2)}\n`,
      );

      const reconciled = fixture.reconcile({ boot: true });
      assert.notEqual(reconciled.status, 0);
      assert.match(reconciled.stderr, /phase transition chain is invalid/);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.notEqual(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('allows synchronous boot reconciliation inside restart without deadlock or rollback', () => {
    const fixture = createInstallerFixture('restart-boot-reconcile');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_INSTALL_LOCK_TIMEOUT_SECONDS: '1',
        RADAR_TEST_RECONCILE_ON_RESTART: '1',
      });
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(JSON.parse(activated.stdout).status, 'pending_verification');
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(fixture.pending), true);
      assert.deepEqual(
        fixture.bootReconcileResults().map((line) => JSON.parse(line).status),
        ['pending_verification'],
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('defers a verified deployment at boot and commits it on timer reconciliation', () => {
    const fixture = createInstallerFixture('boot-reconcile-verified');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      assert.equal(fixture.activate(release).status, 0);
      assert.equal(fixture.authorize(release).status, 0);

      const boot = fixture.reconcile({ boot: true });
      assert.equal(boot.status, 0, boot.stderr);
      assert.equal(JSON.parse(boot.stdout).status, 'verified');
      assert.equal(existsSync(fixture.pending), true);

      const timer = fixture.reconcile();
      assert.equal(timer.status, 0, timer.stderr);
      assert.equal(JSON.parse(timer.stdout).status, 'committed');
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('recovers a pre-watchdog interruption through boot reconciliation', () => {
    const fixture = createInstallerFixture('pre-watchdog-interruption');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const interrupted = fixture.activate(release, {
        RADAR_TEST_SIGKILL_AFTER_ARTIFACT_ADOPTION: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(existsSync(release.sourceTarball), false);
      assert.equal(existsSync(release.tarball), true);
      assert.equal(existsSync(fixture.pending), false);

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'no_pending_transaction');
      assert.equal(existsSync(release.tarball), false);
      assert.equal(existsSync(fixture.current), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('recovers same-name redeployment crashes without deleting the current release', () => {
    for (const boundary of [
      'RADAR_TEST_SIGKILL_BEFORE_ARTIFACT_ADOPTION',
      'RADAR_TEST_SIGKILL_AFTER_ARTIFACT_ADOPTION',
      'RADAR_TEST_SIGKILL_AFTER_SNAPSHOT',
    ]) {
      const fixture = createInstallerFixture(
        `same-name-${boundary.toLowerCase()}`,
      );
      try {
        const first = fixture.createTarball(
          'first',
          'release-repeated',
          { payloadMarker: 'stable-release' },
        );
        assert.equal(fixture.activate(first).status, 0);
        assert.equal(fixture.commit(first).status, 0);

        const repeated = fixture.createTarball(
          'second',
          'release-repeated',
          { payloadMarker: 'stable-release' },
        );
        assert.equal(repeated.digest, first.digest);
        const interrupted = fixture.activate(repeated, { [boundary]: '1' });
        assert.equal(interrupted.status, null);
        assert.equal(interrupted.signal, 'SIGKILL');
        assert.equal(readlinkSync(fixture.current), first.releasePath);

        const reconciled = fixture.reconcile({ boot: true });
        assert.equal(reconciled.status, 0, reconciled.stderr);
        assert.equal(
          JSON.parse(reconciled.stdout).status,
          'no_pending_transaction',
        );
        assert.equal(readlinkSync(fixture.current), first.releasePath);
        assert.equal(existsSync(first.releasePath), true);
        assert.equal(existsSync(fixture.pending), false);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('keeps same-name promoted crash recovery split between boot and timer', () => {
    const fixture = createInstallerFixture('same-name-promoted-recovery');
    try {
      const first = fixture.createTarball(
        'first',
        'release-repeated',
        { payloadMarker: 'stable-release' },
      );
      assert.equal(fixture.activate(first).status, 0);
      assert.equal(fixture.commit(first).status, 0);

      const repeated = fixture.createTarball(
        'second',
        'release-repeated',
        { payloadMarker: 'stable-release' },
      );
      const interrupted = fixture.activateWithPromotion(repeated, {
        RADAR_TEST_SIGKILL_AFTER_SNAPSHOT: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(readlinkSync(fixture.current), first.releasePath);

      const boot = fixture.reconcile({ boot: true });
      assert.equal(boot.status, 0, boot.stderr);
      assert.equal(JSON.parse(boot.stdout).status, 'rollback_decided');
      assert.equal(readlinkSync(fixture.current), first.releasePath);

      const timer = fixture.reconcile();
      assert.equal(timer.status, 0, timer.stderr);
      assert.equal(
        JSON.parse(timer.stdout).status,
        'no_pending_transaction',
      );
      assert.equal(readlinkSync(fixture.current), first.releasePath);
      assert.equal(existsSync(first.releasePath), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('fails closed on an ambiguous same-name pre-pending identity', () => {
    const fixture = createInstallerFixture('same-name-ambiguous-recovery');
    try {
      const first = fixture.createTarball(
        'first',
        'release-repeated',
        { payloadMarker: 'stable-release' },
      );
      assert.equal(fixture.activate(first).status, 0);
      assert.equal(fixture.commit(first).status, 0);
      const repeated = fixture.createTarball(
        'second',
        'release-repeated',
        { payloadMarker: 'stable-release' },
      );
      const interrupted = fixture.activate(repeated, {
        RADAR_TEST_SIGKILL_AFTER_ARTIFACT_ADOPTION: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');

      const unrelated = fixture.installDetachedRelease('release-unrelated');
      rmSync(fixture.current);
      symlinkSync(unrelated, fixture.current);
      const reconciled = fixture.reconcile({ boot: true });
      assert.notEqual(reconciled.status, 0);
      assert.match(
        reconciled.stderr,
        /same-name release identity|previous release changed/,
      );
      assert.equal(existsSync(first.releasePath), true);
      assert.equal(existsSync(repeated.tarball), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('explicit rollback restores the previous release and removes the candidate', () => {
    const fixture = createInstallerFixture('explicit-rollback');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const rolledBack = fixture.rollback(release);
      assert.equal(rolledBack.status, 0, rolledBack.stderr);
      assert.match(rolledBack.stderr, /previous release restored/);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(release.releasePath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.equal(existsSync(fixture.pending), false);
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
        `restart|${previous}`,
      ]);

      const repeated = fixture.rollback(release);
      assert.equal(repeated.status, 0, repeated.stderr);
      assert.match(repeated.stderr, /previous release restored/);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('rolls back an expired unverified deployment during boot reconciliation', () => {
    const fixture = createInstallerFixture('expired-boot-reconcile');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_INSTALL_PENDING_TIMEOUT_SECONDS: '1',
      });
      assert.equal(activated.status, 0, activated.stderr);
      const deadline = Number(
        readFileSync(join(fixture.pending, 'deadline_epoch'), 'utf8').trim(),
      );
      const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
      while (Math.floor(Date.now() / 1000) <= deadline) {
        Atomics.wait(waitBuffer, 0, 0, 50);
      }

      const reconciled = fixture.reconcile({ boot: true });
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'rollback_decided');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);

      const finalized = fixture.reconcile();
      assert.equal(finalized.status, 0, finalized.stderr);
      assert.equal(JSON.parse(finalized.stdout).status, 'rolled_back');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('rolls back an expired unverified deployment during timer reconciliation', () => {
    const fixture = createInstallerFixture('expired-timer-reconcile');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_INSTALL_PENDING_TIMEOUT_SECONDS: '1',
      });
      assert.equal(activated.status, 0, activated.stderr);
      const deadline = Number(
        readFileSync(join(fixture.pending, 'deadline_epoch'), 'utf8').trim(),
      );
      const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
      while (Math.floor(Date.now() / 1000) <= deadline) {
        Atomics.wait(waitBuffer, 0, 0, 50);
      }

      const reconciled = fixture.reconcile();
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'rolled_back');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(
        JSON.parse(fixture.status(release).stdout).status,
        'rolled_back',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('reports every transaction status without mixing deployment identities', () => {
    const preparingFixture = createInstallerFixture('status-preparing');
    try {
      const release = preparingFixture.createTarball(
        'candidate',
        'release-preparing',
      );
      const interrupted = preparingFixture.activate(release, {
        RADAR_TEST_SIGKILL_BEFORE_ARTIFACT_ADOPTION: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(preparingFixture.status(release).stdout).status,
        'preparing',
      );
      assert.equal(preparingFixture.reconcile({ boot: true }).status, 0);
      assert.equal(
        JSON.parse(preparingFixture.status(release).stdout).status,
        'not_found',
      );
    } finally {
      preparingFixture.cleanup();
    }

    const committedFixture = createInstallerFixture('status-committed');
    try {
      const release = committedFixture.createTarball(
        'candidate',
        'release-committed',
      );
      assert.equal(committedFixture.activate(release).status, 0);
      const pending = JSON.parse(committedFixture.status(release).stdout);
      assert.equal(pending.status, 'pending_verification');
      assert.equal(pending.phase, 'activated');
      assert.equal(pending.authorized, false);
      assert.equal(committedFixture.authorize(release).status, 0);
      const verified = JSON.parse(committedFixture.status(release).stdout);
      assert.equal(verified.status, 'verified');
      assert.equal(verified.phase, 'verified');
      assert.equal(verified.authorized, true);
      assert.equal(committedFixture.commitWithoutAuthorization(release).status, 0);
      assert.equal(
        JSON.parse(committedFixture.status(release).stdout).status,
        'committed',
      );
    } finally {
      committedFixture.cleanup();
    }

    const rolledBackFixture = createInstallerFixture('status-rolled-back');
    try {
      const release = rolledBackFixture.createTarball(
        'candidate',
        'release-rolled-back',
      );
      assert.equal(rolledBackFixture.activate(release).status, 0);
      assert.equal(rolledBackFixture.rollback(release).status, 0);
      assert.equal(
        JSON.parse(rolledBackFixture.status(release).stdout).status,
        'rolled_back',
      );
    } finally {
      rolledBackFixture.cleanup();
    }

    const commitDecisionFixture = createInstallerFixture(
      'status-commit-decided',
    );
    try {
      const release = commitDecisionFixture.createTarball(
        'candidate',
        'release-commit-decided',
      );
      assert.equal(commitDecisionFixture.activate(release).status, 0);
      assert.equal(commitDecisionFixture.authorize(release).status, 0);
      const interrupted = commitDecisionFixture.commitWithoutAuthorization(
        release,
        { RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1' },
      );
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(commitDecisionFixture.status(release).stdout).status,
        'commit_decided',
      );
    } finally {
      commitDecisionFixture.cleanup();
    }

    const rollbackDecisionFixture = createInstallerFixture(
      'status-rollback-decided',
    );
    try {
      const release = rollbackDecisionFixture.createTarball(
        'candidate',
        'release-rollback-decided',
      );
      assert.equal(rollbackDecisionFixture.activate(release).status, 0);
      const interrupted = rollbackDecisionFixture.rollback(release, {
        RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(
        JSON.parse(rollbackDecisionFixture.status(release).stdout).status,
        'rollback_decided',
      );
    } finally {
      rollbackDecisionFixture.cleanup();
    }
  });

  it('automatically restores the previous release when candidate restart fails', () => {
    const fixture = createInstallerFixture('restart-rollback');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-restart-fails');
      const result = fixture.activate(release, {
        RADAR_TEST_FAIL_RESTART_TARGET: release.releaseName,
      });

      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /service restart failed/);
      assert.match(result.stderr, /previous release restored/);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(release.releasePath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.equal(existsSync(fixture.pending), false);
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
        `restart|${previous}`,
      ]);
    } finally {
      fixture.cleanup();
    }
  });

  it('automatically rolls back when local health or served manifest is not exact', () => {
    for (const failure of [
      { RADAR_TEST_NOT_READY_TARGET: 'release-not-ready' },
      { RADAR_TEST_MANIFEST_MISMATCH_TARGET: 'release-not-ready' },
      { RADAR_TEST_PROVENANCE_MISMATCH_TARGET: 'release-not-ready' },
    ]) {
      const fixture = createInstallerFixture('readiness-rollback');
      try {
        const previous = fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball('candidate', 'release-not-ready');
        const result = fixture.activate(release, failure);

        assert.notEqual(result.status, 0);
        assert.match(result.stderr, /did not reach exact semantic readiness/);
        assert.match(result.stderr, /previous release restored/);
        assert.equal(readlinkSync(fixture.current), previous);
        assert.equal(existsSync(release.releasePath), false);
        assert.equal(existsSync(fixture.pending), false);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('leaves retryable pending state when rollback restart fails partway through', () => {
    const fixture = createInstallerFixture('retry-rollback');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-not-ready');
      const activation = fixture.activate(release, {
        RADAR_TEST_NOT_READY_TARGET: release.releaseName,
        RADAR_TEST_FAIL_RESTART_TARGET: 'release-previous',
      });

      assert.equal(activation.status, 1, activation.stderr);
      assert.equal(activation.signal, null);
      assert.match(
        activation.stderr,
        /failed to restart the previous release after rollback/,
      );
      assert.match(activation.stderr, /automatic rollback did not restore/);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        existsSync(join(fixture.pending, 'finalization.json')),
        true,
      );
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.deepEqual(completionStatePaths(fixture.shared), []);
      const healthCallsBeforeRetry = fixture
        .curlCalls()
        .filter((call) => call.endsWith('/api/health')).length;

      const retry = fixture.rollback(release);
      assert.equal(retry.status, 0, retry.stderr);
      assert.match(retry.stderr, /previous release restored/);
      assert.ok(
        fixture
          .curlCalls()
          .filter((call) => call.endsWith('/api/health')).length >
          healthCallsBeforeRetry,
        'rollback retry did not recheck previous-service readiness',
      );
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
        `restart|${previous}`,
        `restart|${previous}`,
      ]);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(release.releasePath), false);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('rechecks previous-service readiness before completing a decided rollback', () => {
    const fixture = createInstallerFixture('retry-rollback-readiness');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);

      const rolledBack = fixture.rollback(release, {
        RADAR_TEST_NOT_READY_TARGET: 'release-previous',
      });
      assert.equal(rolledBack.status, 1, rolledBack.stderr);
      assert.equal(rolledBack.signal, null);
      assert.match(
        rolledBack.stderr,
        /previous release did not regain semantic readiness after rollback/,
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        existsSync(join(fixture.pending, 'finalization.json')),
        true,
      );
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.deepEqual(completionStatePaths(fixture.shared), []);
      const healthCallsBeforeRetry = fixture
        .curlCalls()
        .filter((call) => call.endsWith('/api/health')).length;

      const retry = fixture.rollback(release);
      assert.equal(retry.status, 0, retry.stderr);
      assert.match(retry.stderr, /previous release restored/);
      assert.ok(
        fixture
          .curlCalls()
          .filter((call) => call.endsWith('/api/health')).length >
          healthCallsBeforeRetry,
        'rollback retry did not recheck previous-service readiness',
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(release.releasePath), false);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('watchdog restores the previous release after untrappable activation interruption', () => {
    for (const interruption of [
      {
        env: { RADAR_TEST_SIGKILL_AFTER_PENDING: '1' },
        expectedStopTarget: 'release-previous',
      },
      {
        env: { RADAR_TEST_SIGKILL_AFTER_SWITCH: '1' },
        expectedStopTarget: 'release-interrupted',
      },
    ]) {
      const fixture = createInstallerFixture('sigkill-watchdog');
      try {
        const previous = fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball(
          'candidate',
          'release-interrupted',
        );
        const activation = fixture.activate(release, {
          RADAR_INSTALL_DISABLE_WATCHDOG: '0',
          RADAR_INSTALL_PENDING_TIMEOUT_SECONDS: '1',
          ...interruption.env,
        });
        const watchdogDiagnostics = deploymentLogContents(fixture.shared);

        assert.equal(
          activation.status,
          null,
          `${activation.stderr}\n${watchdogDiagnostics}`,
        );
        assert.equal(
          activation.signal,
          'SIGKILL',
          `${activation.stderr}\n${watchdogDiagnostics}`,
        );
        waitForCondition(
          () =>
            !existsSync(fixture.pending) &&
            !existsSync(release.releasePath) &&
            !existsSync(release.tarball),
          watchdogCompletionTimeoutMs,
          () =>
            'watchdog did not finish interrupted deployment cleanup\n' +
            deploymentLogContents(fixture.shared),
        );
        assert.equal(readlinkSync(fixture.current), previous);
        assert.equal(existsSync(release.releasePath), false);
        assert.equal(existsSync(release.tarball), false);
        assert.equal(fixture.databaseState(), 'before-deploy');
        assert.deepEqual(fixture.serviceActions(), [
          `stop|${join(fixture.releases, interruption.expectedStopTarget)}`,
          `restart|${previous}`,
        ]);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('fences a stale watchdog from a later transaction for the same artifact', () => {
    const fixture = createInstallerFixture('stale-watchdog-fence');
    try {
      const first = fixture.createTarball('repeated', 'release-repeated');
      const firstActivation = fixture.activate(first);
      assert.equal(firstActivation.status, 0, firstActivation.stderr);
      const firstTransactionId = readFileSync(
        join(fixture.pending, 'transaction_id'),
        'utf8',
      ).trim();
      const firstPendingHash = readFileSync(
        join(fixture.pending, 'pending_state_hash'),
        'utf8',
      ).trim();
      const firstDeadline = readFileSync(
        join(fixture.pending, 'deadline_epoch'),
        'utf8',
      ).trim();
      const firstCommit = fixture.commit(first);
      assert.equal(firstCommit.status, 0, firstCommit.stderr);

      const second = fixture.createTarball('repeated', 'release-repeated');
      assert.equal(second.digest, first.digest);
      const secondActivation = fixture.activate(second);
      assert.equal(secondActivation.status, 0, secondActivation.stderr);
      const secondTransactionId = readFileSync(
        join(fixture.pending, 'transaction_id'),
        'utf8',
      ).trim();
      assert.notEqual(secondTransactionId, firstTransactionId);

      const stale = fixture.watchdog(
        first,
        firstTransactionId,
        firstPendingHash,
        firstDeadline,
      );
      assert.equal(stale.status, 0, stale.stderr);
      assert.equal(
        readFileSync(join(fixture.pending, 'transaction_id'), 'utf8').trim(),
        secondTransactionId,
      );
      assert.equal(readlinkSync(fixture.current), second.releasePath);
      const staleReceiptPath = join(
        fixture.shared,
        'deploy-logs',
        `watchdog-${firstTransactionId}.receipt.json`,
      );
      assert.equal(existsSync(staleReceiptPath), true);
      const staleReceipt = JSON.parse(readFileSync(staleReceiptPath, 'utf8'));
      assert.equal(staleReceipt.transactionId, firstTransactionId);
      assert.equal(staleReceipt.pendingStateHash, firstPendingHash);
      assert.equal(staleReceipt.outcome, 'superseded');

      const secondCommit = fixture.commit(second);
      assert.equal(secondCommit.status, 0, secondCommit.stderr);
    } finally {
      fixture.cleanup();
    }
  });

  it('keeps rollback retryable when interrupted before its atomic finalization', () => {
    const fixture = createInstallerFixture('sigkill-rollback-retry');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const snapshotPath = readFileSync(
        join(fixture.pending, 'db_snapshot_path'),
        'utf8',
      ).trim();

      const interrupted = fixture.rollback(release, {
        RADAR_TEST_SIGKILL_ROLLBACK_BEFORE_FINALIZE: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(existsSync(snapshotPath), true);

      const retried = fixture.rollback(release);
      assert.equal(retried.status, 0, retried.stderr);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(snapshotPath), false);
      assert.equal(existsSync(release.releasePath), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('makes commit durable before deleting rollback artifacts', () => {
    const fixture = createInstallerFixture('sigkill-commit-finalize');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const snapshotPath = readFileSync(
        join(fixture.pending, 'db_snapshot_path'),
        'utf8',
      ).trim();

      const interrupted = fixture.commit(release, {
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(snapshotPath), true);
      assert.equal(existsSync(release.tarball), true);
      const finalized = finalizedStatePaths(fixture.base);
      assert.equal(finalized.length, 1);
      assert.match(
        finalized[0],
        /\.pending-deploy\.finalized-committed-release-candidate-/,
      );
      const record = JSON.parse(
        readFileSync(join(finalized[0], 'finalization.json'), 'utf8'),
      );
      assert.equal(record.outcome, 'committed');
      assert.equal(record.releaseName, release.releaseName);
      assert.equal(record.releaseSha, release.githubSha);
      assert.equal(record.artifactDigest, release.digest);
      assert.match(record.pendingStateHash, /^[0-9a-f]{64}$/);
      assert.match(record.contentHash, /^[0-9a-f]{64}$/);

      const retried = fixture.commit(release);
      assert.equal(retried.status, 0, retried.stderr);
      assert.match(retried.stdout, /release release-candidate committed/);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(snapshotPath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('recovers rolled-back finalization after SIGKILL and removes the marker last', () => {
    const fixture = createInstallerFixture('sigkill-rollback-finalize');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const snapshotPath = readFileSync(
        join(fixture.pending, 'db_snapshot_path'),
        'utf8',
      ).trim();
      const runtimeEnvPath = readFileSync(
        join(fixture.pending, 'runtime_env_path'),
        'utf8',
      ).trim();

      const interrupted = fixture.rollback(release, {
        RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.status, null);
      assert.equal(interrupted.signal, 'SIGKILL');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(release.releasePath), true);
      assert.equal(existsSync(runtimeEnvPath), true);
      assert.equal(existsSync(snapshotPath), true);
      assert.equal(existsSync(release.tarball), true);
      const finalized = finalizedStatePaths(fixture.base);
      assert.equal(finalized.length, 1);
      assert.match(finalized[0], /\.pending-deploy\.finalized-rolled-back-/);

      const retried = fixture.rollback(release);
      assert.equal(retried.status, 0, retried.stderr);
      assert.match(retried.stderr, /previous release restored/);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(release.releasePath), false);
      assert.equal(existsSync(runtimeEnvPath), false);
      assert.equal(existsSync(snapshotPath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('retries finalization when SIGKILL lands after the intent record but before rename', () => {
    for (const scenario of [
      {
        name: 'commit',
        interruptEnv: {
          RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZATION_RECORD: '1',
        },
      },
      {
        name: 'rollback',
        interruptEnv: {
          RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZATION_RECORD: '1',
        },
      },
    ] as const) {
      const fixture = createInstallerFixture(`sigkill-${scenario.name}-intent`);
      try {
        const previous = fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball('candidate', 'release-candidate');
        const activated = fixture.activate(release);
        assert.equal(activated.status, 0, activated.stderr);

        const interrupted =
          scenario.name === 'commit'
            ? fixture.commit(release, scenario.interruptEnv)
            : fixture.rollback(release, scenario.interruptEnv);
        assert.equal(interrupted.status, null);
        assert.equal(interrupted.signal, 'SIGKILL');
        assert.equal(existsSync(fixture.pending), true);
        assert.equal(
          existsSync(join(fixture.pending, 'finalization.json')),
          true,
        );
        assert.deepEqual(finalizedStatePaths(fixture.base), []);

        const retried =
          scenario.name === 'commit'
            ? fixture.commit(release)
            : fixture.rollback(release);
        assert.equal(retried.status, 0, retried.stderr);
        assert.equal(existsSync(fixture.pending), false);
        assert.deepEqual(finalizedStatePaths(fixture.base), []);
        assert.equal(
          readlinkSync(fixture.current),
          scenario.name === 'commit' ? release.releasePath : previous,
        );
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects tampered finalized records without deleting recovery artifacts', () => {
    const fixture = createInstallerFixture('tampered-finalization');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const snapshotPath = readFileSync(
        join(fixture.pending, 'db_snapshot_path'),
        'utf8',
      ).trim();
      const interrupted = fixture.commit(release, {
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      const [finalized] = finalizedStatePaths(fixture.base);
      const recordPath = join(finalized, 'finalization.json');
      const record = JSON.parse(readFileSync(recordPath, 'utf8'));
      record.contentHash = '0'.repeat(64);
      writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`);

      const retry = fixture.commit(release);
      assert.notEqual(retry.status, 0);
      assert.match(retry.stderr, /content hash mismatch/);
      assert.equal(existsSync(finalized), true);
      assert.equal(existsSync(snapshotPath), true);
      assert.equal(existsSync(release.tarball), true);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects finalized recovery when current contradicts the recorded outcome', () => {
    const fixture = createInstallerFixture('contradictory-finalization');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const interrupted = fixture.commit(release, {
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      const [finalized] = finalizedStatePaths(fixture.base);
      rmSync(fixture.current);
      symlinkSync(previous, fixture.current);

      const retry = fixture.commit(release);
      assert.notEqual(retry.status, 0);
      assert.match(retry.stderr, /contradictory current release/);
      assert.equal(existsSync(finalized), true);
      assert.equal(existsSync(release.releasePath), true);
      assert.equal(existsSync(release.tarball), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('keeps finalized cleanup retryable when recovery itself is SIGKILLed', () => {
    for (const scenario of [
      {
        name: 'commit',
        finalizeEnv: { RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1' },
        recoveryEnv: {
          RADAR_TEST_SIGKILL_RECOVERY_AFTER_SNAPSHOT_CLEANUP: '1',
        },
      },
      {
        name: 'rollback',
        finalizeEnv: { RADAR_TEST_SIGKILL_ROLLBACK_AFTER_FINALIZE: '1' },
        recoveryEnv: {
          RADAR_TEST_SIGKILL_RECOVERY_AFTER_RELEASE_CLEANUP: '1',
        },
      },
    ] as const) {
      const fixture = createInstallerFixture(
        `sigkill-${scenario.name}-recovery-cleanup`,
      );
      try {
        fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball('candidate', 'release-candidate');
        const activated = fixture.activate(release);
        assert.equal(activated.status, 0, activated.stderr);
        const snapshotPath = readFileSync(
          join(fixture.pending, 'db_snapshot_path'),
          'utf8',
        ).trim();
        const runtimeEnvPath = readFileSync(
          join(fixture.pending, 'runtime_env_path'),
          'utf8',
        ).trim();

        const finalized =
          scenario.name === 'commit'
            ? fixture.commit(release, scenario.finalizeEnv)
            : fixture.rollback(release, scenario.finalizeEnv);
        assert.equal(finalized.signal, 'SIGKILL');
        assert.equal(finalizedStatePaths(fixture.base).length, 1);

        const cleanupInterrupted =
          scenario.name === 'commit'
            ? fixture.commit(release, scenario.recoveryEnv)
            : fixture.rollback(release, scenario.recoveryEnv);
        assert.equal(cleanupInterrupted.status, null);
        assert.equal(cleanupInterrupted.signal, 'SIGKILL');
        assert.equal(finalizedStatePaths(fixture.base).length, 1);
        if (scenario.name === 'commit') {
          assert.equal(existsSync(snapshotPath), false);
          assert.equal(existsSync(release.tarball), true);
        } else {
          assert.equal(existsSync(release.releasePath), false);
          assert.equal(existsSync(runtimeEnvPath), true);
          assert.equal(existsSync(snapshotPath), true);
        }

        const recovered =
          scenario.name === 'commit'
            ? fixture.commit(release)
            : fixture.rollback(release);
        assert.equal(recovered.status, 0, recovered.stderr);
        assert.deepEqual(finalizedStatePaths(fixture.base), []);
        assert.equal(existsSync(snapshotPath), false);
        assert.equal(existsSync(release.tarball), false);
        if (scenario.name === 'rollback') {
          assert.equal(existsSync(runtimeEnvPath), false);
        }
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('rejects a finalized outcome that contradicts the requested action', () => {
    const fixture = createInstallerFixture('contradictory-finalized-outcome');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const interrupted = fixture.commit(release, {
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      const [finalized] = finalizedStatePaths(fixture.base);

      const wrongAction = fixture.rollback(release);
      assert.notEqual(wrongAction.status, 0);
      assert.match(
        wrongAction.stderr,
        /does not match the requested rolled-back transaction/,
      );
      assert.equal(existsSync(finalized), true);
      assert.equal(existsSync(release.tarball), true);

      const correctAction = fixture.commit(release);
      assert.equal(correctAction.status, 0, correctAction.stderr);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('uses immutable completion receipts for post-cleanup retries and outcome conflicts', () => {
    const fixture = createInstallerFixture('completion-retry');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const committed = fixture.commit(release);
      assert.equal(committed.status, 0, committed.stderr);
      const completed = completionStatePaths(fixture.shared);
      assert.equal(completed.length, 1);
      assert.equal(
        JSON.parse(
          readFileSync(join(completed[0], 'finalization.json'), 'utf8'),
        ).outcome,
        'committed',
      );

      const repeatedCommit = fixture.commit(release);
      assert.equal(repeatedCommit.status, 0, repeatedCommit.stderr);
      assert.match(repeatedCommit.stdout, /release release-candidate committed/);

      const contradictoryRollback = fixture.rollback(release);
      assert.notEqual(contradictoryRollback.status, 0);
      assert.match(
        contradictoryRollback.stderr,
        /contradictory terminal completion receipt/,
      );
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(completionStatePaths(fixture.shared).length, 1);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects tampered completion receipts on an idempotent retry', () => {
    const fixture = createInstallerFixture('completion-tamper');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const committed = fixture.commit(release);
      assert.equal(committed.status, 0, committed.stderr);
      const [completed] = completionStatePaths(fixture.shared);
      const recordPath = join(completed, 'finalization.json');
      const record = JSON.parse(readFileSync(recordPath, 'utf8'));
      record.pendingStateHash = '0'.repeat(64);
      writeFileSync(recordPath, `${JSON.stringify(record, null, 2)}\n`);

      const retry = fixture.commit(release);
      assert.notEqual(retry.status, 0);
      assert.match(
        retry.stderr,
        /deployment finalization record does not match pending identity/,
      );
      assert.equal(readlinkSync(fixture.current), release.releasePath);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects multiple finalized markers instead of choosing one', () => {
    const fixture = createInstallerFixture('multiple-finalized-markers');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const interrupted = fixture.commit(release, {
        RADAR_TEST_SIGKILL_COMMIT_AFTER_FINALIZE: '1',
      });
      assert.equal(interrupted.signal, 'SIGKILL');
      const finalized = finalizedStatePaths(fixture.base);
      assert.equal(finalized.length, 1);
      const extra = join(fixture.base, '.pending-deploy.finalized-extra');
      mkdirSync(extra);

      const retry = fixture.commit(release);
      assert.notEqual(retry.status, 0);
      assert.match(retry.stderr, /multiple finalized deployment markers/);
      assert.equal(existsSync(finalized[0]), true);
      assert.equal(existsSync(extra), true);
      assert.equal(existsSync(release.tarball), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects archive traversal, absolute links, chained escapes, hardlinks, and .env', () => {
    const cases: Array<{
      name: string;
      entries: RawTarEntry[];
      pattern: RegExp;
    }> = [
      {
        name: 'parent-member',
        entries: [{ name: '../escape', type: 'file', data: 'escape\n' }],
        pattern: /escapes the release root/,
      },
      {
        name: 'absolute-member',
        entries: [{ name: '/tmp/radar-escape', type: 'file', data: 'escape\n' }],
        pattern: /path is absolute/,
      },
      {
        name: 'parent-symlink',
        entries: [
          { name: 'escape-link', type: 'symlink', linkName: '../escape' },
        ],
        pattern: /link target escapes the release root/,
      },
      {
        name: 'absolute-symlink',
        entries: [
          { name: 'escape-link', type: 'symlink', linkName: '/tmp/escape' },
        ],
        pattern: /link target is absolute/,
      },
      {
        name: 'chained-symlink',
        entries: [
          { name: 'chain-a', type: 'symlink', linkName: 'chain-b' },
          { name: 'chain-b', type: 'symlink', linkName: '/tmp/escape' },
        ],
        pattern: /link target is absolute/,
      },
      {
        name: 'hardlink',
        entries: [
          { name: 'escape-link', type: 'hardlink', linkName: '../escape' },
        ],
        pattern: /hard links are unsupported/,
      },
      {
        name: 'archive-env',
        entries: [
          { name: '.env', type: 'symlink', linkName: '/tmp/escape' },
        ],
        pattern: /must not provide the managed \.env path/,
      },
    ];
    for (const attack of cases) {
      const fixture = createInstallerFixture(`archive-${attack.name}`);
      try {
        const release = fixture.createRawTarball(
          attack.name,
          `release-${attack.name}`,
          attack.entries,
        );
        const result = fixture.activate(release);
        assert.notEqual(result.status, 0);
        assert.match(result.stderr, attack.pattern);
        assert.equal(existsSync(fixture.current), false);
        assert.equal(existsSync(release.releasePath), false);
        assert.deepEqual(fixture.serviceActions(), []);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('allows contained archive symlinks and the exact installer-managed .env only', () => {
    const fixture = createInstallerFixture('contained-release-symlink');
    try {
      const release = fixture.createTarball(
        'candidate',
        'release-contained-link',
        {
          symlinks: [
            {
              path: 'dist/index-alias.js',
              target: 'index.js',
            },
          ],
        },
      );
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(
        realpathSync(join(release.releasePath, 'dist', 'index-alias.js')),
        realpathSync(join(release.releasePath, 'dist', 'index.js')),
      );
      assert.equal(
        readlinkSync(join(release.releasePath, '.env')),
        join(
          fixture.shared,
          'runtime-env',
          `${release.releaseName}.env`,
        ),
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects an escaping symlink in a reused existing release tree', () => {
    const fixture = createInstallerFixture('reused-tree-symlink-escape');
    try {
      const release = fixture.createTarball('candidate', 'release-existing');
      mkdirSync(release.releasePath, { recursive: true });
      const extracted = spawnSync(
        'tar',
        ['-xzf', release.tarball, '-C', release.releasePath],
        { encoding: 'utf8' },
      );
      assert.equal(extracted.status, 0, extracted.stderr);
      const outside = join(fixture.dir, 'outside-runtime.js');
      writeFileSync(outside, 'module.exports = {};\n');
      symlinkSync(
        '../../../../outside-runtime.js',
        join(release.releasePath, 'dist', 'escape.js'),
      );

      const result = fixture.activate(release);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /release symlink escapes the release root/);
      assert.equal(existsSync(fixture.current), false);
      assert.deepEqual(fixture.serviceActions(), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects incomplete runtime files before switching or restarting', () => {
    const fixture = createInstallerFixture('runtime-validation');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-incomplete', {
        omitApi: true,
      });
      const result = fixture.activate(release);

      assert.notEqual(result.status, 0);
      assert.match(
        result.stderr,
        /missing production runtime file: dist\/routes\/api\.js/,
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.deepEqual(fixture.serviceActions(), []);
      assert.equal(existsSync(release.releasePath), false);
      assert.equal(existsSync(release.sourceTarball), false);
      assert.equal(existsSync(release.tarball), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('refuses to reuse an existing release with an untrusted runtime env', () => {
    const fixture = createInstallerFixture('existing-env');
    try {
      const release = fixture.createTarball('candidate', 'release-existing');
      mkdirSync(release.releasePath, { recursive: true });
      const extracted = spawnSync(
        'tar',
        ['-xzf', release.tarball, '-C', release.releasePath],
        { encoding: 'utf8' },
      );
      assert.equal(extracted.status, 0, extracted.stderr);
      writeFileSync(join(release.releasePath, '.env'), 'REFRESH_ON_STARTUP=true\n');

      const result = fixture.activate(release);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /runtime env is not a release-specific symlink/);
      assert.equal(existsSync(fixture.current), false);
      assert.deepEqual(fixture.serviceActions(), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects manifest identity changes and payload digest drift', () => {
    const fixture = createInstallerFixture('manifest-digest');
    try {
      const badManifest = fixture.createTarball(
        'bad-manifest',
        'release-bad-manifest',
        { extraManifestKey: true },
      );
      const manifestResult = fixture.activate(badManifest);
      assert.notEqual(manifestResult.status, 0);
      assert.match(manifestResult.stderr, /release manifest keys are invalid/);

      const changedPayload = fixture.createTarball(
        'changed-payload',
        'release-changed-payload',
        { mutateAfterManifest: true },
      );
      const digestResult = fixture.activate(changedPayload);
      assert.notEqual(digestResult.status, 0);
      assert.match(digestResult.stderr, /release artifact digest mismatch/);

      const changedControlPlane = fixture.createTarball(
        'changed-control-plane',
        'release-changed-control-plane',
        { mutateControlPlaneAfterManifest: true },
      );
      const controlPlaneResult = fixture.activate(changedControlPlane);
      assert.notEqual(controlPlaneResult.status, 0);
      assert.match(
        controlPlaneResult.stderr,
        /release control-plane digest mismatch/,
      );

      assert.deepEqual(fixture.serviceActions(), []);
      assert.equal(existsSync(fixture.current), false);
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('fails closed when a transaction-owned release artifact is replaced', () => {
    const fixture = createInstallerFixture('owned-artifact-replacement');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const ownedTarball = release.tarball;
      assert.match(
        ownedTarball,
        new RegExp(
          `/deploy-artifacts/${fixture.transactionId(release)}\\.tar\\.gz$`,
        ),
      );
      writeFileSync(ownedTarball, 'replacement bytes\n');

      const rollback = fixture.rollback(release);
      assert.notEqual(rollback.status, 0);
      assert.match(
        rollback.stderr,
        /transaction-owned release artifact (metadata|content) is invalid/,
      );
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(existsSync(ownedTarball), true);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.notEqual(readlinkSync(fixture.current), previous);
    } finally {
      fixture.cleanup();
    }
  });

  it('requires production auto-refresh settings to remain explicitly disabled', () => {
    const fixture = createInstallerFixture('refresh-disabled');
    try {
      writeFileSync(
        fixture.sharedEnv,
        `DB_PATH=${fixture.databasePath}\nPORT=8787\nREFRESH_ON_STARTUP=true\nREFRESH_MINUTES=5\n`,
      );
      const release = fixture.createTarball('candidate', 'release-refreshing');
      const result = fixture.activate(release);

      assert.notEqual(result.status, 0);
      assert.match(
        result.stderr,
        /must explicitly disable REFRESH_ON_STARTUP and REFRESH_MINUTES/,
      );
      assert.equal(existsSync(fixture.current), false);
      assert.deepEqual(fixture.serviceActions(), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('restricts code-only activation to explicit installer test mode', () => {
    const fixture = createInstallerFixture('code-only-test-mode');
    try {
      const release = fixture.createTarball('candidate', 'release-code-only');
      const result = fixture.activate(release, {
        RADAR_INSTALL_ALLOW_CODE_ONLY_ACTIVATION: '1',
        RADAR_INSTALL_TEST_MODE: '0',
        RADAR_INSTALL_TEST_NONCE: '',
      });

      assert.notEqual(result.status, 0);
      assert.match(
        result.stderr,
        /code-only activation is restricted to explicit installer test mode/,
      );
      assert.equal(existsSync(fixture.current), false);
      assert.deepEqual(fixture.serviceActions(), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('fails closed when the server-side deployment lock cannot be acquired', () => {
    const fixture = createInstallerFixture('flock-failure');
    try {
      const release = fixture.createTarball('candidate', 'release-locked');
      const result = fixture.activate(release, {
        RADAR_TEST_FLOCK_FAIL: '1',
      });

      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /timed out waiting for deployment lock/);
      assert.deepEqual(fixture.flockCalls(), ['-w 7 9']);
      assert.equal(existsSync(fixture.current), false);
      assert.equal(existsSync(release.releasePath), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('bounds every local health and manifest probe', () => {
    const fixture = createInstallerFixture('probe-timeouts');
    try {
      const release = fixture.createTarball('candidate', 'release-probes');
      const result = fixture.activate(release);
      assert.equal(result.status, 0, result.stderr);

      const calls = fixture.curlCalls();
      assert.ok(calls.some((call) => call.endsWith('/api/health')));
      assert.ok(calls.some((call) => call.endsWith('/release-manifest.json')));
      for (const call of calls) {
        assert.match(call, /--connect-timeout 2/);
        assert.match(call, /--max-time 5/);
      }
      assert.ok(calls.some((call) => call.endsWith('/api/validation/opportunities')));
    } finally {
      fixture.cleanup();
    }
  });

  it('restores the consistent pre-migration DB snapshot before restarting old code', () => {
    const fixture = createInstallerFixture('database-rollback');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_TEST_MIGRATE_DB_TARGET: release.releaseName,
      });
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.databaseState(), 'candidate-migrated');
      assert.equal(
        existsSync(join(fixture.pending, 'db_snapshot_path')),
        true,
      );

      const rolledBack = fixture.rollback(release);
      assert.equal(rolledBack.status, 0, rolledBack.stderr);
      assert.match(rolledBack.stderr, /pre-migration database snapshot restored/);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
        `restart|${previous}`,
      ]);
    } finally {
      fixture.cleanup();
    }
  });

  it('preserves full database mode metadata across snapshot and rollback', () => {
    const fixture = createInstallerFixture('database-metadata-roundtrip');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const sourceMode = 0o2640;
      chmodSync(fixture.databasePath, sourceMode);
      assert.equal(statSync(fixture.databasePath).mode & 0o7777, sourceMode);
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_TEST_MIGRATE_DB_TARGET: release.releaseName,
      });
      assert.equal(activated.status, 0, activated.stderr);

      const snapshotPath = fixture.snapshotPath(release);
      const metadataPath = fixture.snapshotMetadataPath(release);
      const metadata = JSON.parse(readFileSync(metadataPath, 'utf8'));
      assert.equal(metadata.metadata.mode, sourceMode);
      assert.equal(statSync(snapshotPath).mode & 0o7777, sourceMode);
      assert.match(metadata.contentHash, /^[0-9a-f]{64}$/);
      assert.match(metadata.authenticationTag, /^[0-9a-f]{64}$/);

      const rolledBack = fixture.rollback(release);
      assert.equal(rolledBack.status, 0, rolledBack.stderr);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(statSync(fixture.databasePath).mode & 0o7777, sourceMode);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects missing or tampered authenticated snapshot metadata', () => {
    for (const scenario of [
      { mutation: 'missing', action: 'rollback' },
      { mutation: 'tampered', action: 'rollback' },
      { mutation: 'missing', action: 'commit' },
      { mutation: 'tampered', action: 'commit' },
    ] as const) {
      const fixture = createInstallerFixture(
        `snapshot-metadata-${scenario.mutation}-${scenario.action}`,
      );
      try {
        const previous = fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball('candidate', 'release-candidate');
        assert.equal(
          fixture.activate(release, {
            RADAR_TEST_MIGRATE_DB_TARGET: release.releaseName,
          }).status,
          0,
        );
        if (scenario.action === 'commit') {
          assert.equal(fixture.authorize(release).status, 0);
        }
        const metadataPath = fixture.snapshotMetadataPath(release);
        if (scenario.mutation === 'missing') {
          rmSync(metadataPath);
        } else {
          const record = JSON.parse(readFileSync(metadataPath, 'utf8'));
          record.metadata.mode ^= 0o1000;
          writeFileSync(metadataPath, `${JSON.stringify(record, null, 2)}\n`);
        }

        const result = scenario.action === 'commit'
          ? fixture.commitWithoutAuthorization(release)
          : fixture.rollback(release);
        assert.notEqual(result.status, 0);
        assert.match(
          result.stderr,
          /snapshot metadata|ENOENT|metadata sidecar/,
        );
        assert.equal(readlinkSync(fixture.current), release.releasePath);
        assert.notEqual(readlinkSync(fixture.current), previous);
        assert.equal(existsSync(fixture.pending), true);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('orders ownership restoration before full-mode restoration', () => {
    const installer = readFileSync(productionInstaller, 'utf8');
    const snapshotStart = installer.indexOf('snapshot_database() {');
    const snapshotEnd = installer.indexOf(
      'validate_database_snapshot_metadata_at() {',
    );
    const restoreStart = installer.indexOf('restore_database_snapshot() {');
    const restoreEnd = installer.indexOf('\nread_state_field() {');
    assert.ok(snapshotStart >= 0 && snapshotEnd > snapshotStart);
    assert.ok(restoreStart >= 0 && restoreEnd > restoreStart);
    for (const section of [
      installer.slice(snapshotStart, snapshotEnd),
      installer.slice(restoreStart, restoreEnd),
    ]) {
      const owner = section.indexOf('fs.chownSync(target');
      const mode = section.indexOf('fs.chmodSync(target, metadata.mode)');
      assert.ok(owner >= 0 && mode > owner);
      assert.match(section, /info\.mode & 0o7777n/);
    }
  });

  it('fails before activation when metadata-preserving copy tooling is absent', () => {
    const fixture = createInstallerFixture('metadata-tooling-missing');
    try {
      const release = fixture.createTarball('candidate', 'release-candidate');
      const result = fixture.activate(release, {
        RADAR_INSTALL_CP_BIN: join(fixture.dir, 'missing-cp'),
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /metadata-preserving copy runtime not found/);
      assert.equal(existsSync(fixture.current), false);
      assert.deepEqual(fixture.serviceActions(), []);
    } finally {
      fixture.cleanup();
    }
  });

  it('does not replace production when the rollback snapshot changes during cloning', () => {
    const fixture = createInstallerFixture('database-rollback-clone-race');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activate(release, {
        RADAR_TEST_MIGRATE_DB_TARGET: release.releaseName,
      });
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.databaseState(), 'candidate-migrated');
      const snapshotPath = fixture.snapshotPath(release);
      const pendingSnapshotDigest = readFileSync(
        join(fixture.pending, 'db_snapshot_sha256'),
        'utf8',
      ).trim();
      const fileDigest = (path: string) =>
        createHash('sha256').update(readFileSync(path)).digest('hex');
      const databaseIdentity = () => {
        const info = statSync(fixture.databasePath);
        return {
          dev: info.dev,
          ino: info.ino,
          size: info.size,
          digest: fileDigest(fixture.databasePath),
        };
      };
      const databaseBeforeRollback = databaseIdentity();

      const rolledBack = fixture.rollback(release, {
        RADAR_TEST_MUTATE_ROLLBACK_SNAPSHOT_AFTER_CLONE: '1',
      });
      assert.equal(
        rolledBack.status,
        1,
        `${rolledBack.stdout}\n${rolledBack.stderr}`,
      );
      assert.equal(rolledBack.signal, null);
      assert.match(
        rolledBack.stderr,
        /rollback snapshot changed while restore candidate was built/,
      );
      assert.match(
        rolledBack.stderr,
        /failed to restore the pre-migration database snapshot/,
      );
      assert.doesNotMatch(
        rolledBack.stderr,
        /pre-migration database snapshot restored|previous release restored/,
      );
      assert.equal(fixture.databaseState(), 'candidate-migrated');
      assert.deepEqual(databaseIdentity(), databaseBeforeRollback);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.notEqual(readlinkSync(fixture.current), previous);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        existsSync(join(fixture.pending, 'finalization.json')),
        false,
      );
      assert.equal(existsSync(snapshotPath), true);
      assert.notEqual(fileDigest(snapshotPath), pendingSnapshotDigest);
      assert.equal(existsSync(release.releasePath), true);
      assert.equal(existsSync(release.tarball), true);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.deepEqual(completionStatePaths(fixture.shared), []);
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
      ]);
      assert.equal(
        readdirSync(fixture.shared).some((entry) =>
          entry.startsWith('.radar.db.rollback-'),
        ),
        false,
      );

      const retried = fixture.rollback(release);
      assert.equal(retried.status, 1, retried.stderr);
      assert.equal(retried.signal, null);
      assert.match(
        retried.stderr,
        /pre-promotion rollback snapshot digest changed/,
      );
      assert.doesNotMatch(
        retried.stderr,
        /failed to restore the pre-migration database snapshot/,
      );
      assert.doesNotMatch(
        retried.stderr,
        /pre-migration database snapshot restored|previous release restored/,
      );
      assert.deepEqual(databaseIdentity(), databaseBeforeRollback);
      assert.equal(readlinkSync(fixture.current), release.releasePath);
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(
        existsSync(join(fixture.pending, 'finalization.json')),
        false,
      );
      assert.equal(existsSync(snapshotPath), true);
      assert.deepEqual(finalizedStatePaths(fixture.base), []);
      assert.deepEqual(completionStatePaths(fixture.shared), []);
      assert.deepEqual(fixture.serviceActions(), [
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
      ]);
    } finally {
      fixture.cleanup();
    }
  });

  it('promotes the quality database inside the pending code-and-database transaction', () => {
    const fixture = createInstallerFixture('promotion-commit');
    try {
      fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release);
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.databaseState(), 'quality-promoted');
      assert.equal(
        JSON.parse(fixture.status(release).stdout).phase,
        'activated',
      );
      assert.equal(
        existsSync(join(fixture.pending, 'promotion-report.json')),
        true,
      );
      assert.equal(
        existsSync(join(fixture.pending, 'promotion-binding.json')),
        true,
      );
      const binding = JSON.parse(
        readFileSync(join(fixture.pending, 'promotion-binding.json'), 'utf8'),
      );
      const promotionReport = JSON.parse(
        readFileSync(join(fixture.pending, 'promotion-report.json'), 'utf8'),
      );
      assert.equal(binding.releaseSha, release.githubSha);
      assert.equal(binding.artifactDigest, release.digest);
      assert.equal(binding.requiredScoreReceiptId, scoreReceiptId);
      assert.equal(
        binding.rollbackBackup.realPath,
        realpathSync(fixture.snapshotPath(release)),
      );
      assert.match(binding.promotedDatabase.logicalContentDigest, /^[0-9a-f]{64}$/);
      assert.match(binding.promotedDatabase.schemaDigest, /^[0-9a-f]{64}$/);
      assert.match(binding.promotedDatabase.physicalSha256, /^[0-9a-f]{64}$/);
      assert.deepEqual(
        Object.keys(binding.promotedDatabase).sort(),
        [
          'device',
          'inode',
          'logicalContentDigest',
          'physicalSha256',
          'realPath',
          'schemaDigest',
        ],
      );
      assert.deepEqual(
        {
          logicalContentDigest:
            binding.promotedDatabase.logicalContentDigest,
          schemaDigest: binding.promotedDatabase.schemaDigest,
          physicalSha256: binding.promotedDatabase.physicalSha256,
        },
        promotionReport.promotionAuthorization.installedDatabase,
      );
      const {
        contentHash: promotionBindingContentHash,
        ...promotionBindingPayload
      } = binding;
      assert.equal(
        promotionBindingContentHash,
        createHash('sha256')
          .update(
            `installer-promotion-binding-v1\0${JSON.stringify(
              promotionBindingPayload,
            )}`,
          )
          .digest('hex'),
      );
      const startupAuthorizationPath = join(
        fixture.shared,
        'startup-authorization',
        'active.json',
      );
      const pendingAuthorization = JSON.parse(
        readFileSync(startupAuthorizationPath, 'utf8'),
      );
      assert.equal(pendingAuthorization.lifecycle, 'pending-activation');
      assert.equal(pendingAuthorization.release.sha, release.githubSha);
      assert.equal(
        pendingAuthorization.database.realPath,
        realpathSync(fixture.databasePath),
      );
      assert.equal(
        pendingAuthorization.database.physicalSha256,
        binding.promotedDatabase.physicalSha256,
      );
      assert.equal(
        pendingAuthorization.scoreReceipt.receiptId,
        scoreReceiptId,
      );
      assert.equal(
        pendingAuthorization.promotionReceipt.promotionId,
        binding.promotionId,
      );
      const verifiedPendingAuthorization =
        fixture.verifyStartupAuthorization(release);
      assert.equal(
        verifiedPendingAuthorization.lifecycle,
        'pending-activation',
      );
      assert.equal(
        verifiedPendingAuthorization.authorizationContentHash,
        pendingAuthorization.contentHash,
      );
      assert.deepEqual(fixture.serviceActions(), [
        `stop|${join(fixture.releases, 'release-previous')}`,
        `restart|${release.releasePath}`,
      ]);

      const committed = fixture.commit(release);
      assert.equal(committed.status, 0, committed.stderr);
      assert.equal(fixture.databaseState(), 'quality-promoted');
      assert.equal(existsSync(fixture.pending), false);
      const committedAuthorization = JSON.parse(
        readFileSync(startupAuthorizationPath, 'utf8'),
      );
      assert.equal(
        committedAuthorization.lifecycle,
        'committed-completion',
      );
      assert.equal(
        committedAuthorization.state.path,
        completionStatePaths(fixture.shared)[0],
      );
      assert.equal(
        fixture.verifyStartupAuthorization(release).lifecycle,
        'committed-completion',
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects a promotion report without independent GitHub catalog proof', () => {
    const fixture = createInstallerFixture('promotion-github-proof');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release, {
        RADAR_TEST_PROMOTION_OMIT_GITHUB_PROOF: '1',
      });

      assert.notEqual(activated.status, 0);
      assert.match(
        activated.stderr,
        /exact independent GitHub catalog proof/,
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects a promotion report without an exact inherited lock proof', () => {
    const fixture = createInstallerFixture('promotion-lock-proof');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release, {
        RADAR_TEST_PROMOTION_BAD_LOCK_PROOF: '1',
      });

      assert.notEqual(activated.status, 0);
      assert.match(
        activated.stderr,
        /promotion report does not bind the complete installer transaction/,
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(existsSync(fixture.pending), false);
    } finally {
      fixture.cleanup();
    }
  });

  it('runs bundled promotion through the named lifecycle with an empty dotenv guard', () => {
    const fixture = createInstallerFixture('promotion-lifecycle');
    try {
      fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release, {
        RADAR_INSTALL_PROMOTION_BIN: '',
        RADAR_DEPLOY_LOCK_HELD: '1',
        RADAR_DEPLOY_LOCK_PATH: join(
          fixture.shared,
          'deploy-promotion.lock',
        ),
        RADAR_TEST_REQUIRE_NAMED_PROMOTION_LIFECYCLE: '1',
      });
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.databaseState(), 'quality-promoted');
      const lifecycle = fixture.promotionCalls()
        .find((line) => line.startsWith('lifecycle='));
      assert.ok(lifecycle, 'missing promotion lifecycle evidence');
      assert.match(
        lifecycle,
        /^lifecycle=promote:quality-db dotenv=.+\/\.pending-deploy\/\.promotion\.env\.empty legacy_lock= lock_path_env=$/,
      );
      const dotenvPath = lifecycle
        .slice(lifecycle.indexOf(' dotenv=') + 8)
        .split(' legacy_lock=', 1)[0];
      assert.equal(readFileSync(dotenvPath).length, 0);
      assert.ok(
        fixture.promotionCalls().some((line) =>
          /--deployment-lock-fd 9(?: |$)/.test(line)
        ),
        'promotion must receive inherited deployment lock fd 9',
      );
      assert.equal(
        existsSync(join(fixture.pending, 'promotion-binding.json')),
        true,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects rollback-backup drift immediately after quality promotion', () => {
    const fixture = createInstallerFixture('promotion-backup-drift');
    try {
      fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release, {
        RADAR_TEST_PROMOTION_MUTATE_BACKUP_AFTER_REPORT: '1',
      });
      assert.notEqual(activated.status, 0);
      assert.match(
        activated.stderr,
        /rollback backup physical digest does not match pending deployment state/,
      );
      assert.match(
        activated.stderr,
        /automatic rollback did not restore a ready previous release/,
      );
      assert.equal(existsSync(fixture.pending), true);
      assert.equal(existsSync(fixture.snapshotPath(release)), true);
    } finally {
      fixture.cleanup();
    }
  });

  it('rejects a same-path installed database mutation after the promoter reports success', () => {
    const fixture = createInstallerFixture('promotion-destination-drift');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release, {
        RADAR_TEST_PROMOTION_MUTATE_DESTINATION_AFTER_REPORT: '1',
      });
      assert.notEqual(activated.status, 0);
      assert.match(
        activated.stderr,
        /installed database physical digest does not match promotion authorization/,
      );
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(
        existsSync(
          join(fixture.shared, 'startup-authorization', 'active.json'),
        ),
        false,
      );
    } finally {
      fixture.cleanup();
    }
  });

  it('restores old code and the pre-promotion database after promoted activation rollback', () => {
    const fixture = createInstallerFixture('promotion-rollback');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-candidate');
      const activated = fixture.activateWithPromotion(release);
      assert.equal(activated.status, 0, activated.stderr);
      assert.equal(fixture.databaseState(), 'quality-promoted');

      const rolledBack = fixture.rollback(release);
      assert.equal(rolledBack.status, 0, rolledBack.stderr);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(existsSync(fixture.pending), false);
      assert.deepEqual(fixture.serviceActions(), [
        `stop|${previous}`,
        `restart|${release.releasePath}`,
        `stop|${release.releasePath}`,
        `restart|${previous}`,
      ]);
    } finally {
      fixture.cleanup();
    }
  });

  it('timer reconciliation recovers a promotion interrupted after stopping the previous service', () => {
    const fixture = createInstallerFixture('promotion-stop-sigkill');
    try {
      const previous = fixture.installPreviousRelease('release-previous');
      const release = fixture.createTarball('candidate', 'release-interrupted');
      const activation = fixture.activateWithPromotion(release, {
        RADAR_INSTALL_DISABLE_WATCHDOG: '0',
        RADAR_TEST_SIGKILL_AFTER_PROMOTION_STOP: '1',
      });
      assert.equal(activation.status, null);
      assert.equal(activation.signal, 'SIGKILL');
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(deploymentLogContents(fixture.shared), '');

      const reconciled = fixture.reconcile();
      assert.equal(reconciled.status, 0, reconciled.stderr);
      assert.equal(JSON.parse(reconciled.stdout).status, 'no_pending_transaction');
      assert.equal(readlinkSync(fixture.current), previous);
      assert.equal(fixture.databaseState(), 'before-deploy');
      assert.equal(existsSync(fixture.pending), false);
      assert.equal(existsSync(release.releasePath), false);
      assert.equal(existsSync(release.tarball), false);
      assert.deepEqual(fixture.serviceActions(), [
        `stop|${previous}`,
        `restart|${previous}`,
      ]);
    } finally {
      fixture.cleanup();
    }
  });

  it('watchdog restores the pre-promotion database after pending state exists', () => {
    for (const env of [
      { RADAR_TEST_SIGKILL_AFTER_PENDING: '1' },
      { RADAR_TEST_SIGKILL_AFTER_PROMOTION: '1' },
      { RADAR_TEST_SIGKILL_AFTER_SWITCH: '1' },
    ]) {
      const fixture = createInstallerFixture('promotion-sigkill');
      try {
        const previous = fixture.installPreviousRelease('release-previous');
        const release = fixture.createTarball('candidate', 'release-interrupted');
        const activation = fixture.activateWithPromotion(release, {
          RADAR_INSTALL_DISABLE_WATCHDOG: '0',
          RADAR_INSTALL_PENDING_TIMEOUT_SECONDS: '1',
          ...env,
        });
        assert.equal(activation.status, null);
        assert.equal(activation.signal, 'SIGKILL');
        waitForCondition(
          () =>
            !existsSync(fixture.pending) &&
            !existsSync(release.releasePath) &&
            !existsSync(release.tarball),
          watchdogCompletionTimeoutMs,
          () =>
            'watchdog did not finish interrupted promoted deployment cleanup\n' +
            deploymentLogContents(fixture.shared),
        );
        assert.equal(readlinkSync(fixture.current), previous);
        assert.equal(fixture.databaseState(), 'before-deploy');
        assert.equal(existsSync(release.releasePath), false);
      } finally {
        fixture.cleanup();
      }
    }
  });

  it('validates shared env permissions and rejects symlinked watchdog log directories', () => {
    const badMode = createInstallerFixture('shared-env-mode');
    try {
      chmodSync(badMode.sharedEnv, 0o644);
      const release = badMode.createTarball('candidate', 'release-bad-env-mode');
      const result = badMode.activate(release);
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /shared env owner\/mode mismatch/);
    } finally {
      badMode.cleanup();
    }

    const symlinkedLogs = createInstallerFixture('watchdog-log-symlink');
    try {
      const outside = join(symlinkedLogs.dir, 'outside-logs');
      mkdirSync(outside);
      symlinkSync(outside, join(symlinkedLogs.shared, 'deploy-logs'));
      const release = symlinkedLogs.createTarball(
        'candidate',
        'release-symlinked-logs',
      );
      const result = symlinkedLogs.activate(release, {
        RADAR_INSTALL_DISABLE_WATCHDOG: '0',
      });
      assert.notEqual(result.status, 0);
      assert.match(result.stderr, /control directory must not be a symlink/);
      assert.deepEqual(symlinkedLogs.serviceActions(), []);
    } finally {
      symlinkedLogs.cleanup();
    }
  });

  it('seals deployed code and binds the release env to the manifest SHA', () => {
    const fixture = createInstallerFixture('sealed-release');
    try {
      const release = fixture.createTarball('candidate', 'release-sealed');
      const activated = fixture.activate(release);
      assert.equal(activated.status, 0, activated.stderr);
      const runtimeEnv = readlinkSync(join(release.releasePath, '.env'));
      assert.match(runtimeEnv, /shared\/runtime-env\/release-sealed\.env$/);
      assert.match(
        readFileSync(runtimeEnv, 'utf8'),
        new RegExp(`RADAR_CODE_REVISION=${githubSha}`),
      );
      assert.match(
        readFileSync(runtimeEnv, 'utf8'),
        /RADAR_DB_READ_ONLY=1/,
      );
      assert.match(
        readFileSync(runtimeEnv, 'utf8'),
        /RADAR_DB_BOOTSTRAP_MODE=existing/,
      );
      assert.equal(statSync(runtimeEnv).mode & 0o777, 0o640);
      assert.equal(statSync(join(release.releasePath, 'dist', 'index.js')).mode & 0o022, 0);
      assert.equal(statSync(release.releasePath).mode & 0o022, 0);
    } finally {
      fixture.cleanup();
    }
  });
});

type ReleaseFixture = {
  tarball: string;
  sourceTarball: string;
  releaseName: string;
  releasePath: string;
  githubSha: string;
  digest: string;
};

type TarballOptions = {
  extraManifestKey?: boolean;
  mutateAfterManifest?: boolean;
  mutateControlPlaneAfterManifest?: boolean;
  omitApi?: boolean;
  payloadMarker?: string;
  symlinks?: Array<{ path: string; target: string }>;
};

type RawTarEntry = {
  name: string;
  type: 'file' | 'directory' | 'symlink' | 'hardlink';
  data?: string | Buffer;
  linkName?: string;
};

function createInstallerFixture(name: string) {
  const dir = mkdtempSync(join(tmpdir(), `radar-installer-${name}-`));
  const base = join(dir, 'radar');
  const shared = join(base, 'shared');
  const releases = join(base, 'releases');
  const current = join(base, 'current');
  const pending = join(base, '.pending-deploy');
  const bin = join(dir, 'bin');
  const serviceLog = join(dir, 'service.log');
  const curlLog = join(dir, 'curl.log');
  const flockLog = join(dir, 'flock.log');
  const reconcileLog = join(dir, 'reconcile.log');
  const restartFailureMarker = join(dir, 'restart-failed-once');
  const promotionLog = join(dir, 'promotion.log');
  const sharedEnv = join(shared, '.env');
  const databasePath = join(shared, 'radar.db');
  const qualityDatabasePath = join(shared, 'quality.db');
  const verifierKeyPath = join(dir, 'deploy-verifier.key');
  mkdirSync(shared, { recursive: true });
  mkdirSync(releases, { recursive: true });
  mkdirSync(bin, { recursive: true });
  const database = new DatabaseSync(databasePath);
  database.exec(`
    CREATE TABLE deployment_state (value TEXT NOT NULL);
    INSERT INTO deployment_state (value) VALUES ('before-deploy');
  `);
  database.close();
  const qualityDatabase = new DatabaseSync(qualityDatabasePath);
  qualityDatabase.exec(`
    CREATE TABLE deployment_state (value TEXT NOT NULL);
    INSERT INTO deployment_state (value) VALUES ('quality-promoted');
  `);
  qualityDatabase.close();
  writeFileSync(
    sharedEnv,
    `DB_PATH=${databasePath}\nPORT=8787\nREFRESH_ON_STARTUP=false\nREFRESH_MINUTES=0\n`,
  );
  chmodSync(sharedEnv, 0o640);
  writeFileSync(verifierKeyPath, `${verifierKey}\n`);
  chmodSync(verifierKeyPath, 0o600);

  const systemctl = join(bin, 'systemctl');
  writeExecutable(systemctl, `#!/usr/bin/env bash
set -euo pipefail
action="\${1:-}"
if [ "$action" = "restart" ]; then
  target="$(readlink "$RADAR_INSTALL_BASE/current" 2>/dev/null || true)"
  printf 'restart|%s\\n' "$target" >> "$RADAR_TEST_SERVICE_LOG"
  if [ "\${RADAR_TEST_RECONCILE_ON_RESTART:-0}" = "1" ]; then
    bash "$RADAR_TEST_INSTALLER_PATH" reconcile --boot \
      >> "$RADAR_TEST_RECONCILE_LOG" 2>&1
  fi
  if [[ "$target" == *"\${RADAR_TEST_FAIL_RESTART_TARGET:-__never__}"* ]] &&
     [ ! -e "$RADAR_TEST_RESTART_FAILURE_MARKER" ]; then
    : > "$RADAR_TEST_RESTART_FAILURE_MARKER"
    exit 1
  fi
  if [[ "$target" == *"\${RADAR_TEST_MIGRATE_DB_TARGET:-__never__}"* ]]; then
    "$RADAR_INSTALL_NODE_BIN" -e '
      const { DatabaseSync } = require("node:sqlite");
      const db = new DatabaseSync(process.argv[1]);
      try {
        db.prepare("UPDATE deployment_state SET value=?").run("candidate-migrated");
      } finally {
        db.close();
      }
    ' "$RADAR_TEST_DB_PATH"
  fi
elif [ "$action" = "stop" ]; then
  target="$(readlink "$RADAR_INSTALL_BASE/current" 2>/dev/null || true)"
  printf 'stop|%s\\n' "$target" >> "$RADAR_TEST_SERVICE_LOG"
fi
exit 0
`);

  const curl = join(bin, 'curl');
  writeExecutable(curl, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RADAR_TEST_CURL_LOG"
url="\${!#}"
target="$(readlink "$RADAR_INSTALL_BASE/current" 2>/dev/null || true)"
  if [[ "$url" == *"/release-manifest.json"* ]]; then
  if [[ "$target" == *"\${RADAR_TEST_MANIFEST_MISMATCH_TARGET:-__never__}"* ]]; then
    printf '%s\\n' '{"schemaVersion":3,"releaseName":"wrong","githubSha":"wrong","runtimeCodeRevision":"wrong","artifactDigest":"sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff","installerProtocol":4,"controlPlane":{}}'
  else
    cat "$target/public/release-manifest.json"
  fi
elif [[ "$url" == *"/api/validation/opportunities"* ]]; then
  if [[ "$target" == *"\${RADAR_TEST_PROVENANCE_MISMATCH_TARGET:-__never__}"* ]]; then
    printf '%s\\n' '{"schemaVersion":2,"currentSeries":{"codeRevision":"wrong"}}'
  else
    printf '%s\\n' '{"schemaVersion":2,"currentSeries":{"codeRevision":"${githubSha}"}}'
  fi
elif [[ "$url" == *"/api/status"* ]]; then
  printf '%s\\n' '{"schemaVersion":1,"refreshing":false,"lastError":null,"currentScoreAuthorizationStatus":"authorized","currentScoreReceiptStatus":"success","currentScoreReceiptId":"${scoreReceiptId}"}'
elif [[ "$url" == *"/api/receipts/"* ]]; then
  printf '%s\\n' '{"schemaVersion":1,"receipt":{"receiptId":"${scoreReceiptId}","outcome":"success","attempt":{"codeRevision":"${githubSha}"},"terminal":{"payload":{"codeRevision":"${githubSha}"}},"verification":{"verified":true}}}'
elif [[ "$target" == *"\${RADAR_TEST_NOT_READY_TARGET:-__never__}"* ]]; then
  printf '%s\\n' '{"schemaVersion":1,"ok":false,"status":"not_ready","failures":[{"code":"not_ready","message":"not ready"}],"checks":{"closureProof":{"ok":true},"database":{"ok":true},"ingestion":{"ok":true},"recommendation":{"ok":true},"releaseWindow":{"ok":false},"scoreAudit":{"ok":true},"sourceIdentity":{"ok":true}}}'
else
  printf '%s\\n' '{"schemaVersion":1,"ok":true,"status":"ready","failures":[],"checks":{"closureProof":{"ok":true},"database":{"ok":true},"ingestion":{"ok":true},"recommendation":{"ok":true},"releaseWindow":{"ok":true},"scoreAudit":{"ok":true},"sourceIdentity":{"ok":true}}}'
fi
`);

  const flock = join(bin, 'flock');
  writeExecutable(flock, `#!/usr/bin/env bash
set -euo pipefail
printf '%s\\n' "$*" >> "$RADAR_TEST_FLOCK_LOG"
[ "\${RADAR_TEST_FLOCK_FAIL:-0}" != "1" ]
timeout_seconds=
lock_fd=
while [ "$#" -gt 0 ]; do
  case "$1" in
    -w)
      timeout_seconds="\${2:?missing flock timeout}"
      shift 2
      ;;
    *)
      lock_fd="$1"
      shift
      ;;
  esac
done
[ -n "$timeout_seconds" ] && [ -n "$lock_fd" ]
perl -MFcntl=:flock -MTime::HiRes=time,sleep -e '
  my ($timeout, $fd) = @ARGV;
  open my $handle, "+<&=$fd" or die "cannot inherit lock fd $fd: $!";
  my $deadline = time() + $timeout;
  while (!flock($handle, LOCK_EX | LOCK_NB)) {
    exit 1 if time() >= $deadline;
    sleep 0.01;
  }
' "$timeout_seconds" "$lock_fd"
`);

  const journalctl = join(bin, 'journalctl');
  writeExecutable(journalctl, '#!/usr/bin/env bash\nexit 0\n');
  for (const command of ['getfacl', 'getfattr', 'lsof']) {
    writeExecutable(join(bin, command), '#!/usr/bin/env bash\nexit 0\n');
  }

  const promotionRuntime = join(bin, 'promote-quality-db.cjs');
  writeFileSync(promotionRuntime, `
const { createHash } = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const promotionArgs = process.argv.slice(2);
const promotionLog = process.env.RADAR_TEST_PROMOTION_LOG;
fs.appendFileSync(promotionLog, promotionArgs.join(' ') + '\\n');
fs.appendFileSync(
  promotionLog,
  'lifecycle=' + (process.env.npm_lifecycle_event || '') +
    ' dotenv=' + (process.env.DOTENV_CONFIG_PATH || '') +
    ' legacy_lock=' + (process.env.RADAR_DEPLOY_LOCK_HELD || '') +
    ' lock_path_env=' + (process.env.RADAR_DEPLOY_LOCK_PATH || '') + '\\n',
);
if (process.env.RADAR_TEST_REQUIRE_NAMED_PROMOTION_LIFECYCLE === '1') {
  if (process.env.npm_lifecycle_event !== 'promote:quality-db') {
    console.error('promotion did not run in the supported lifecycle');
    process.exit(1);
  }
  const dotenvPath = process.env.DOTENV_CONFIG_PATH || '';
  let dotenvInfo = null;
  try {
    dotenvInfo = fs.lstatSync(dotenvPath);
  } catch {}
  if (
    !dotenvInfo ||
    !dotenvInfo.isFile() ||
    dotenvInfo.isSymbolicLink() ||
    dotenvInfo.size !== 0
  ) {
    console.error('promotion dotenv guard is not one empty regular file');
    process.exit(1);
  }
}
if (process.env.RADAR_TEST_PROMOTION_FAIL === '1') {
  console.error('injected promotion failure');
  process.exit(1);
}
const args = new Map();
for (let index = 2; index < process.argv.length; index++) {
  const key = process.argv[index];
  if (!key.startsWith('--')) continue;
  if (key === '--apply') {
    args.set(key, true);
    continue;
  }
  args.set(key, process.argv[++index]);
}
const sourcePath = args.get('--source');
const destinationPath = args.get('--destination');
const backupPath = args.get('--rollback-backup');
const transactionId = args.get('--deployment-transaction-id');
const releaseName = args.get('--release-name');
const releaseSha = args.get('--release-sha');
const artifactDigest = args.get('--artifact-digest');
const pendingStateHash = args.get('--pending-state-hash');
const requiredScoreReceiptId = args.get('--required-score-receipt-id');
const inheritedLockFd = Number(args.get('--deployment-lock-fd'));
if (inheritedLockFd !== 9) {
  console.error('promotion did not receive inherited deployment lock fd 9');
  process.exit(1);
}
const lockPath = path.join(
  path.dirname(fs.realpathSync(destinationPath)),
  'deploy-promotion.lock',
);
const lockPathInfo = fs.statSync(lockPath, { bigint: true });
const lockFdInfo = fs.fstatSync(inheritedLockFd, { bigint: true });
if (
  lockPathInfo.dev !== lockFdInfo.dev ||
  lockPathInfo.ino !== lockFdInfo.ino
) {
  console.error('promotion inherited deployment lock fd does not match lock path');
  process.exit(1);
}
const source = new DatabaseSync(sourcePath, { readOnly: true });
const destination = new DatabaseSync(destinationPath);
try {
  const value = source.prepare('SELECT value FROM deployment_state').get().value;
  destination.prepare('UPDATE deployment_state SET value=?').run(value);
} finally {
  destination.close();
  source.close();
}
function digest(target) {
  return createHash('sha256').update(fs.readFileSync(target)).digest('hex');
}
function identity(target) {
  const info = fs.statSync(target, { bigint: true });
  return {
    path: target,
    realPath: fs.realpathSync(target),
    device: String(info.dev),
    inode: String(info.ino),
    sizeBytes: Number(info.size),
    linkCount: Number(info.nlink),
  };
}
function canonicalJson(value) {
  if (
    value === null ||
    typeof value === 'string' ||
    typeof value === 'number' ||
    typeof value === 'boolean'
  ) return JSON.stringify(value);
  if (Array.isArray(value)) {
    return '[' + value.map((entry) => canonicalJson(entry)).join(',') + ']';
  }
  return '{' + Object.keys(value).sort().map((key) =>
    JSON.stringify(key) + ':' + canonicalJson(value[key])
  ).join(',') + '}';
}
const promotionReceipt = {
  promotionId: 'c'.repeat(64),
  contentHash: 'd'.repeat(64),
};
const githubCatalogProof = {
  schemaVersion: 1,
  source: 'independent_github_graphql',
  repository: 'openclaw/openclaw',
  observedAt: '2026-07-05T12:00:00.000Z',
  configurationSource: {
    kind: 'installer-runtime-env',
    path: 'fixture-runtime-env',
  },
  remoteCatalog: {
    digest: 'e'.repeat(64),
    totalCount: 1,
    nodeCount: 1,
    publishedCount: 1,
    draftCount: 0,
    pageCount: 1,
    pagesFetched: 2,
    sweepCount: 2,
    sweepPageCounts: [1, 1],
    exhausted: true,
    stabilized: true,
    sourceOrder: 'CREATED_AT_DESC',
  },
  activeCatalog: {
    digest: 'f'.repeat(64),
    releaseCount: 1,
    stableCount: 1,
    prereleaseCount: 0,
    tags: ['v-test'],
    latestStable: {
      nodeId: 'RE_v_test',
      tag: 'v-test',
      tagCommitOid: 'a'.repeat(40),
      publishedAt: '2026-07-03T00:00:00.000Z',
    },
  },
  exactIdentityMatch: true,
};
const promotionAuthorizationPayload = {
  schemaVersion: 1,
  phase: 'applied',
  sourceDatabase: {
    applicationId: 0,
    userVersion: 0,
    logicalContentDigest: digest(sourcePath),
    schemaDigest: '1'.repeat(64),
  },
  installedDatabase: {
    logicalContentDigest: digest(destinationPath),
    schemaDigest: '5'.repeat(64),
    physicalSha256: digest(destinationPath),
  },
  validationReport: {
    schemaVersion: 1,
    generatedAt: '2026-07-05T12:00:00.000Z',
    status: 'validated',
    contentHash: '2'.repeat(64),
  },
  evaluationReceipt: {
    evaluationId: '3'.repeat(64),
    contentHash: '4'.repeat(64),
    evaluatedAt: '2026-07-05T12:00:00.000Z',
    status: 'validated',
  },
  promotionReceipt,
  githubReleaseCatalog: {
    schemaVersion: 1,
    source: 'independent_github_graphql',
    repository: githubCatalogProof.repository,
    observedAt: githubCatalogProof.observedAt,
    remoteCatalogDigest: githubCatalogProof.remoteCatalog.digest,
    activeCatalogDigest: githubCatalogProof.activeCatalog.digest,
    activeReleaseCount: githubCatalogProof.activeCatalog.releaseCount,
    activeReleaseTags: githubCatalogProof.activeCatalog.tags,
    exactIdentityMatch: true,
  },
};
const promotionAuthorization = {
  ...promotionAuthorizationPayload,
  contentHash: createHash('sha256')
    .update(
      'quality-db-promotion-authorization-v1\\0' +
        canonicalJson(promotionAuthorizationPayload),
    )
    .digest('hex'),
};
const report = {
  mode: 'apply',
  applied: true,
  backupPath,
  deploymentTransaction: {
    schemaVersion: 1,
    transactionId,
    releaseName,
    releaseSha,
    artifactDigest,
    pendingStateHash,
    requiredScoreReceiptId,
    lockHeldByInstaller: true,
    pendingDeploymentAuthorization: { verified: true },
    sourceAuthorization: {
      schemaVersion: 1,
      runId: 'run-test',
      receiptId: requiredScoreReceiptId,
      receiptStatus: 'success',
      codeRevision: releaseSha,
      verified: true,
    },
  },
  deploymentLock: {
    path: lockPath,
    timeoutSeconds: 7,
    sharedWithInstaller: true,
    inheritedFromInstaller: true,
    transactionId,
    proof: {
      schemaVersion: 1,
      method: 'linux-proc-fdinfo-flock',
      fd: inheritedLockFd,
      path: lockPath,
      device: String(lockFdInfo.dev),
      inode: String(lockFdInfo.ino),
      lockType: 'exclusive',
      verified: true,
    },
  },
  source: {
    file: identity(sourcePath),
    database: { logicalContentDigest: digest(sourcePath) },
  },
  destination: {
    file: identity(destinationPath),
    database: {
      logicalContentDigest: digest(destinationPath),
      schemaDigest: '5'.repeat(64),
    },
  },
  githubReleaseCatalog: {
    source: githubCatalogProof,
    beforeSwap: githubCatalogProof,
    exactAcrossCompletedStages: true,
  },
  promotionAuthorization,
  staged: {
    canonicalPromotionReceipt: promotionReceipt,
  },
  rollbackBackup: {
    externallyPrepared: true,
    verifiedAgainstPrePromotionDestination: true,
    file: identity(backupPath),
    database: { logicalContentDigest: digest(backupPath) },
  },
};
if (process.env.RADAR_TEST_PROMOTION_OMIT_GITHUB_PROOF === '1') {
  delete report.githubReleaseCatalog;
  delete report.promotionAuthorization;
}
if (process.env.RADAR_TEST_PROMOTION_BAD_LOCK_PROOF === '1') {
  report.deploymentLock.proof.inode = '0';
}
const serializedReport = JSON.stringify(report);
if (process.env.RADAR_TEST_PROMOTION_MUTATE_BACKUP_AFTER_REPORT === '1') {
  fs.appendFileSync(backupPath, 'tampered-after-report');
}
if (
  process.env.RADAR_TEST_PROMOTION_MUTATE_DESTINATION_AFTER_REPORT === '1'
) {
  const mutatedDestination = new DatabaseSync(destinationPath);
  try {
    mutatedDestination
      .prepare('UPDATE deployment_state SET value=?')
      .run('post-promoter-mutation');
  } finally {
    mutatedDestination.close();
  }
}
process.stdout.write(serializedReport);
`);
  const promotion = join(bin, 'promote-quality-db');
  writeExecutable(promotion, `#!/usr/bin/env bash
set -euo pipefail
exec "$RADAR_INSTALL_NODE_BIN" "$RADAR_TEST_PROMOTION_RUNTIME" "$@"
`);
  const npm = join(bin, 'npm');
  writeExecutable(npm, `#!/usr/bin/env bash
set -euo pipefail
prefix=
script=
while [ "$#" -gt 0 ]; do
  case "$1" in
    --prefix)
      prefix="\${2:?missing npm prefix}"
      shift 2
      ;;
    --silent)
      shift
      ;;
    run)
      shift
      script="\${1:?missing npm script}"
      shift
      ;;
    --)
      shift
      break
      ;;
    *)
      echo "unexpected fixture npm argument: $1" >&2
      exit 1
      ;;
  esac
done
[ "$script" = "promote:quality-db" ]
[ -n "$prefix" ]
npm_lifecycle_event=promote:quality-db \
npm_lifecycle_script='sh scripts/run-promote-quality-db.sh' \
npm_package_json="$prefix/package.json" \
npm_node_execpath="$RADAR_INSTALL_NODE_BIN" \
npm_execpath="$0" \
PATH="$prefix/node_modules/.bin:$PATH" \
  exec /bin/sh "$prefix/scripts/run-promote-quality-db.sh" "$@"
`);

  const baseEnv = {
    ...process.env,
    NODE_NO_WARNINGS: '1',
    RADAR_INSTALL_BASE: base,
    RADAR_INSTALL_NODE_BIN: process.execPath,
    RADAR_INSTALL_NPM_BIN: npm,
    RADAR_INSTALL_SYSTEMCTL_BIN: systemctl,
    RADAR_INSTALL_CURL_BIN: curl,
    RADAR_INSTALL_FLOCK_BIN: flock,
    RADAR_INSTALL_JOURNALCTL_BIN: journalctl,
    RADAR_INSTALL_LSOF_BIN: join(bin, 'lsof'),
    RADAR_INSTALL_GETFACL_BIN: join(bin, 'getfacl'),
    RADAR_INSTALL_GETFATTR_BIN: join(bin, 'getfattr'),
    RADAR_INSTALL_RUNTIME_USER: runtimeUser,
    RADAR_INSTALL_RUNTIME_GROUP: runtimeGroup,
    RADAR_INSTALL_RELEASE_OWNER: runtimeUser,
    RADAR_INSTALL_RELEASE_GROUP: runtimeGroup,
    RADAR_INSTALL_SHARED_ENV_OWNER: runtimeUser,
    RADAR_INSTALL_SHARED_ENV_GROUP: runtimeGroup,
    RADAR_INSTALL_SHARED_ENV_MODE: '640',
    RADAR_INSTALL_ALLOW_OWNER_RUNTIME_MATCH: '1',
    RADAR_INSTALL_READINESS_ATTEMPTS: '2',
    RADAR_INSTALL_READINESS_SLEEP_SECONDS: '0',
    RADAR_INSTALL_LOCK_TIMEOUT_SECONDS: '7',
    RADAR_INSTALL_DISABLE_WATCHDOG: '1',
    RADAR_INSTALL_TEST_MODE: '1',
    RADAR_INSTALL_TEST_NONCE: testFaultNonce,
    RADAR_INSTALL_ALLOW_CODE_ONLY_ACTIVATION: '1',
    RADAR_INSTALL_VERIFIER_KEY_PATH: verifierKeyPath,
    RADAR_INSTALL_PROMOTION_BIN: promotion,
    RADAR_TEST_INSTALLER_PATH: installerFixturePath,
    RADAR_TEST_RECONCILE_LOG: reconcileLog,
    RADAR_TEST_SERVICE_LOG: serviceLog,
    RADAR_TEST_CURL_LOG: curlLog,
    RADAR_TEST_FLOCK_LOG: flockLog,
    RADAR_TEST_RESTART_FAILURE_MARKER: restartFailureMarker,
    RADAR_TEST_DB_PATH: databasePath,
    RADAR_TEST_PROMOTION_LOG: promotionLog,
    RADAR_TEST_PROMOTION_RUNTIME: promotionRuntime,
    RADAR_TEST_REQUIRED_SCORE_RECEIPT_ID: scoreReceiptId,
  };
  const transactionIds = new Map<ReleaseFixture, string>();

  function verifierAttestation(
    release: ReleaseFixture,
    transactionId: string,
    attestationVerificationId = verificationId,
  ) {
    const transitions = readdirSync(pending)
      .filter((entry) => /^phase-transition-[0-9]{4}\.json$/.test(entry))
      .sort();
    assert.ok(transitions.length > 0, 'missing phase transition');
    const transition = transitions
      .map((entry) =>
        JSON.parse(readFileSync(join(pending, entry), 'utf8'))
      )
      .find((entry) => entry.phase === 'activated');
    assert.ok(transition, 'missing activated phase transition');
    const payload = {
      schemaVersion: 1,
      verificationId: attestationVerificationId,
      transactionId,
      pendingStateHash: readFileSync(
        join(pending, 'pending_state_hash'),
        'utf8',
      ).trim(),
      releaseName: release.releaseName,
      releaseSha: release.githubSha,
      artifactDigest: release.digest,
      deadlineEpoch: Number(
        readFileSync(join(pending, 'deadline_epoch'), 'utf8').trim(),
      ),
      phaseTransitionHash: transition.contentHash,
    };
    return createHmac('sha256', verifierKey)
      .update(
        `installer-verifier-attestation-v1\0${JSON.stringify(payload)}`,
      )
      .digest('hex');
  }

  function run(
    action:
      | 'activate'
      | 'authorize'
      | 'status'
      | 'commit'
      | 'rollback'
      | 'reconcile'
      | 'watchdog',
    args: string[],
    env: Record<string, string> = {},
    cwd = root,
  ) {
    return spawnSync('bash', [installerFixturePath, action, ...args], {
      cwd,
      env: { ...baseEnv, ...env },
      encoding: 'utf8',
    });
  }

  function installDetachedRelease(releaseName: string) {
    const releasePath = join(releases, releaseName);
    createRuntimePayload(releasePath, 'previous');
    const digest = releaseDigest(releasePath);
    writeFileSync(
      join(releasePath, 'public', 'release-manifest.json'),
      `${JSON.stringify({
        schemaVersion: 3,
        releaseName,
        githubSha,
        runtimeCodeRevision: githubSha,
        artifactDigest: digest,
        installerProtocol: 4,
        controlPlane: legacyReleaseControlPlane(releasePath),
      }, null, 2)}\n`,
    );
    return releasePath;
  }

  return {
    dir,
    base,
    shared,
    sharedEnv,
    databasePath,
    qualityDatabasePath,
    releases,
    current,
    pending,
    createTarball(
      label: string,
      releaseName: string,
      options: TarballOptions = {},
    ): ReleaseFixture {
      const payload = join(dir, `${label}-payload`);
      const tarball = join(dir, `${label}.tar.gz`);
      createRuntimePayload(payload, options.payloadMarker ?? label);
      if (options.omitApi) {
        rmSync(join(payload, 'dist', 'routes', 'api.js'));
      }
      for (const link of options.symlinks ?? []) {
        const target = join(payload, link.path);
        mkdirSync(dirname(target), { recursive: true });
        symlinkSync(link.target, target);
      }
      const digest = releaseDigest(payload);
      const manifest = {
        schemaVersion: 4,
        releaseName,
        githubSha,
        runtimeCodeRevision: githubSha,
        artifactDigest: digest,
        installerProtocol: 5,
        controlPlane: releaseControlPlane(payload),
        ...(options.extraManifestKey ? { unexpected: true } : {}),
      };
      writeFileSync(
        join(payload, 'public', 'release-manifest.json'),
        `${JSON.stringify(manifest, null, 2)}\n`,
      );
      if (options.mutateAfterManifest) {
        writeFileSync(join(payload, 'build.txt'), 'changed after signing\n');
      }
      if (options.mutateControlPlaneAfterManifest) {
        writeFileSync(
          join(payload, 'ops', 'viralo', 'openclaw-release-radar-reconcile.timer'),
          '[Timer]\nOnBootSec=1s\n',
        );
      }
      const result = spawnSync('tar', ['-C', payload, '-czf', tarball, '.'], {
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, result.stderr);
      const release: ReleaseFixture = {
        sourceTarball: tarball,
        get tarball() {
          const transactionId = transactionIds.get(release);
          if (transactionId) {
            const owned = join(
              shared,
              'deploy-artifacts',
              `${transactionId}.tar.gz`,
            );
            if (existsSync(owned)) return owned;
          }
          return tarball;
        },
        releaseName,
        releasePath: join(releases, releaseName),
        githubSha,
        digest,
      };
      return release;
    },
    createRawTarball(
      label: string,
      releaseName: string,
      entries: RawTarEntry[],
    ): ReleaseFixture {
      const tarball = join(dir, `${label}.tar.gz`);
      writeRawTarball(tarball, entries);
      return {
        sourceTarball: tarball,
        tarball,
        releaseName,
        releasePath: join(releases, releaseName),
        githubSha,
        digest: `sha256:${createHash('sha256')
          .update(`raw-archive:${label}`)
          .digest('hex')}`,
      };
    },
    installPreviousRelease(releaseName: string) {
      const releasePath = installDetachedRelease(releaseName);
      symlinkSync(releasePath, current);
      return releasePath;
    },
    installDetachedRelease,
    run,
    activate(release: ReleaseFixture, env: Record<string, string> = {}) {
      const transactionId = randomUUID();
      const result = run('activate', [
        release.sourceTarball,
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
      transactionIds.set(release, transactionId);
      return result;
    },
    activateWithTransactionId(
      release: ReleaseFixture,
      transactionId: string,
      env: Record<string, string> = {},
    ) {
      const result = run('activate', [
        release.sourceTarball,
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
      transactionIds.set(release, transactionId);
      return result;
    },
    activateWithPromotion(
      release: ReleaseFixture,
      env: Record<string, string> = {},
    ) {
      const transactionId = randomUUID();
      const result = run('activate', [
        release.sourceTarball,
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
        qualityDatabasePath,
        scoreReceiptId,
      ], {
        RADAR_INSTALL_ALLOW_CODE_ONLY_ACTIVATION: '0',
        ...env,
      });
      transactionIds.set(release, transactionId);
      return result;
    },
    authorize(release: ReleaseFixture, env: Record<string, string> = {}) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return run('authorize', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
        verificationId,
        verifierAttestation(release, transactionId),
      ], env);
    },
    authorizeAs(
      release: ReleaseFixture,
      attestationVerificationId: string,
      attestation?: string,
      env: Record<string, string> = {},
    ) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return run('authorize', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
        attestationVerificationId,
        attestation ??
          verifierAttestation(
            release,
            transactionId,
            attestationVerificationId,
          ),
      ], env);
    },
    status(release: ReleaseFixture, env: Record<string, string> = {}) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return run('status', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
    },
    commit(release: ReleaseFixture, env: Record<string, string> = {}) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      if (
        existsSync(pending) &&
        !existsSync(join(pending, 'verification-authorization.json'))
      ) {
        const authorized = run('authorize', [
          release.releaseName,
          release.githubSha,
          release.digest,
          transactionId,
          verificationId,
          verifierAttestation(release, transactionId),
        ], env);
        assert.equal(authorized.status, 0, authorized.stderr);
      }
      return run('commit', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
    },
    commitWithoutAuthorization(
      release: ReleaseFixture,
      env: Record<string, string> = {},
    ) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return run('commit', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
    },
    rollback(release: ReleaseFixture, env: Record<string, string> = {}) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return run('rollback', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
      ], env);
    },
    watchdog(
      release: ReleaseFixture,
      transactionId: string,
      pendingStateHash: string,
      deadlineEpoch: string,
      env: Record<string, string> = {},
    ) {
      return run('watchdog', [
        release.releaseName,
        release.githubSha,
        release.digest,
        transactionId,
        pendingStateHash,
        deadlineEpoch,
      ], env);
    },
    reconcile(
      options: { boot?: boolean; env?: Record<string, string> } = {},
    ) {
      return run(
        'reconcile',
        options.boot ? ['--boot'] : [],
        options.env ?? {},
      );
    },
    serviceActions() {
      return logLines(serviceLog);
    },
    curlCalls() {
      return logLines(curlLog);
    },
    flockCalls() {
      return logLines(flockLog);
    },
    bootReconcileResults() {
      return logLines(reconcileLog);
    },
    promotionCalls() {
      return logLines(promotionLog);
    },
    databaseState() {
      const db = new DatabaseSync(databasePath, { readOnly: true });
      try {
        return String(
          db.prepare('SELECT value FROM deployment_state').get()?.value,
        );
      } finally {
        db.close();
      }
    },
    snapshotPath(release: ReleaseFixture) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return join(
        shared,
        'deploy-backups',
        `${release.releaseName}-${transactionId}`,
        'pre-migration.sqlite',
      );
    },
    snapshotMetadataPath(release: ReleaseFixture) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return join(
        shared,
        'deploy-backups',
        `${release.releaseName}-${transactionId}`,
        'pre-migration.sqlite.metadata.json',
      );
    },
    transactionId(release: ReleaseFixture) {
      const transactionId = transactionIds.get(release);
      assert.ok(transactionId, `missing transaction ID for ${release.releaseName}`);
      return transactionId;
    },
    verifyStartupAuthorization(release: ReleaseFixture) {
      return verifyProductionStartupAuthorization({
        releaseRoot: release.releasePath,
        releaseRevision: release.githubSha,
        databasePath,
        expectedOwnerUid: statSync(dir).uid,
      });
    },
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function createRuntimePayload(path: string, marker: string) {
  rmSync(path, { recursive: true, force: true });
  mkdirSync(join(path, 'dist', 'routes'), { recursive: true });
  mkdirSync(join(path, 'dist', 'lib'), { recursive: true });
  mkdirSync(join(path, 'node_modules', 'express'), { recursive: true });
  mkdirSync(join(path, 'node_modules', 'dotenv'), { recursive: true });
  mkdirSync(join(path, 'public'), { recursive: true });
  mkdirSync(join(path, 'ops', 'viralo', 'openclaw-release-radar.service.d'), {
    recursive: true,
  });
  writeFileSync(join(path, 'dist', 'index.js'), 'module.exports = {};\n');
  writeFileSync(
    join(path, 'dist', 'routes', 'api.js'),
    `module.exports.api = { stack: [
  { route: { path: '/live' } },
  { route: { path: '/health' } },
  { route: { path: '/validation/opportunities' } },
] };\n`,
  );
  writeFileSync(
    join(path, 'dist', 'lib', 'releaseValidationOpportunityStatus.js'),
    'module.exports = {};\n',
  );
  writeFileSync(
    join(path, 'dist', 'lib', 'startupAuthorization.js'),
    'module.exports = {};\n',
  );
  writeFileSync(
    join(path, 'node_modules', 'express', 'package.json'),
    '{"name":"express"}\n',
  );
  writeFileSync(
    join(path, 'node_modules', 'dotenv', 'package.json'),
    '{"name":"dotenv"}\n',
  );
  const promotionRuntime = join(path, 'promotion-runtime');
  mkdirSync(join(promotionRuntime, 'scripts', 'validation'), {
    recursive: true,
  });
  mkdirSync(join(promotionRuntime, 'src', 'lib'), { recursive: true });
  mkdirSync(join(promotionRuntime, 'node_modules', 'tsx', 'dist'), {
    recursive: true,
  });
  mkdirSync(join(promotionRuntime, 'node_modules', '.bin'), {
    recursive: true,
  });
  mkdirSync(join(promotionRuntime, 'node_modules', 'dotenv'), {
    recursive: true,
  });
  mkdirSync(join(promotionRuntime, 'node_modules', 'esbuild'), {
    recursive: true,
  });
  writeFileSync(
    join(promotionRuntime, 'package.json'),
    readFileSync(join(root, 'ops', 'promotion-runtime', 'package.json')),
  );
  writeFileSync(
    join(promotionRuntime, 'scripts', 'promote-quality-db.mjs'),
    '// Installer fixture promotion entrypoint.\n',
  );
  writeFileSync(
    join(promotionRuntime, 'scripts', 'run-promote-quality-db.sh'),
    readFileSync(join(root, 'scripts', 'run-promote-quality-db.sh')),
  );
  writeFileSync(
    join(
      promotionRuntime,
      'scripts',
      'validation',
      'record-promotion.mjs',
    ),
    '// Installer fixture recorder path.\n',
  );
  writeFileSync(
    join(promotionRuntime, 'src', 'lib', 'db.ts'),
    '// Installer fixture database module path.\n',
  );
  writeFileSync(
    join(promotionRuntime, 'node_modules', 'tsx', 'package.json'),
    '{"name":"tsx"}\n',
  );
  writeFileSync(
    join(promotionRuntime, 'node_modules', 'tsx', 'dist', 'cli.mjs'),
    `import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const [entrypoint, ...args] = process.argv.slice(2);
const expectedEntrypoint = fileURLToPath(
  new URL('../../../scripts/promote-quality-db.mjs', import.meta.url),
);
if (!entrypoint || resolve(entrypoint) !== expectedEntrypoint) {
  throw new Error('unexpected fixture promotion entrypoint');
}
const runtime = process.env.RADAR_TEST_PROMOTION_RUNTIME;
if (!runtime) throw new Error('missing fixture promotion runtime');
process.argv = [process.execPath, entrypoint, ...args];
createRequire(import.meta.url)(runtime);
`,
  );
  writeExecutable(
    join(promotionRuntime, 'node_modules', '.bin', 'tsx'),
    `#!/usr/bin/env sh
exec "$RADAR_INSTALL_NODE_BIN" \
  "$(dirname "$0")/../tsx/dist/cli.mjs" \
  "$@"
`,
  );
  writeFileSync(
    join(promotionRuntime, 'node_modules', 'dotenv', 'package.json'),
    '{"name":"dotenv"}\n',
  );
  writeFileSync(
    join(promotionRuntime, 'node_modules', 'esbuild', 'package.json'),
    '{"name":"esbuild"}\n',
  );
  for (const relativePath of [
    'ops/viralo/openclaw-release-radar-install-release.sh',
    'ops/viralo/openclaw-release-radar.service',
    'ops/viralo/openclaw-release-radar-reconcile-boot.service',
    'ops/viralo/openclaw-release-radar-reconcile.service',
    'ops/viralo/openclaw-release-radar-reconcile.timer',
    'ops/viralo/openclaw-release-radar.service.d/10-deploy-reconcile.conf',
  ]) {
    const target = join(path, relativePath);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, readFileSync(join(root, relativePath)));
  }
  chmodSync(
    join(path, 'ops', 'viralo', 'openclaw-release-radar-install-release.sh'),
    0o755,
  );
  writeFileSync(join(path, 'build.txt'), `${marker}\n`);
}

function writeRawTarball(path: string, entries: RawTarEntry[]) {
  const blocks: Buffer[] = [];
  const writeString = (
    target: Buffer,
    offset: number,
    length: number,
    value: string,
  ) => {
    const encoded = Buffer.from(value);
    assert.ok(encoded.length <= length, `tar field is too long: ${value}`);
    encoded.copy(target, offset);
  };
  const writeOctal = (
    target: Buffer,
    offset: number,
    length: number,
    value: number,
  ) => {
    const encoded = value.toString(8).padStart(length - 1, '0');
    assert.ok(encoded.length < length, `tar number is too large: ${value}`);
    writeString(target, offset, length - 1, encoded);
    target[offset + length - 1] = 0;
  };

  for (const entry of entries) {
    const data = entry.type === 'file'
      ? Buffer.isBuffer(entry.data)
        ? entry.data
        : Buffer.from(entry.data ?? '')
      : Buffer.alloc(0);
    const header = Buffer.alloc(512);
    writeString(header, 0, 100, entry.name);
    writeOctal(header, 100, 8, entry.type === 'directory' ? 0o755 : 0o644);
    writeOctal(header, 108, 8, 0);
    writeOctal(header, 116, 8, 0);
    writeOctal(header, 124, 12, data.length);
    writeOctal(header, 136, 12, 1);
    header.fill(0x20, 148, 156);
    header[156] = {
      file: '0',
      directory: '5',
      symlink: '2',
      hardlink: '1',
    }[entry.type].charCodeAt(0);
    if (entry.linkName) writeString(header, 157, 100, entry.linkName);
    writeString(header, 257, 6, 'ustar');
    writeString(header, 263, 2, '00');
    let checksum = 0;
    for (const byte of header) checksum += byte;
    writeString(header, 148, 6, checksum.toString(8).padStart(6, '0'));
    header[154] = 0;
    header[155] = 0x20;
    blocks.push(header);
    if (data.length > 0) {
      blocks.push(data);
      const padding = (512 - (data.length % 512)) % 512;
      if (padding > 0) blocks.push(Buffer.alloc(padding));
    }
  }
  blocks.push(Buffer.alloc(1024));
  writeFileSync(path, gzipSync(Buffer.concat(blocks)));
}

function releaseControlPlane(path: string) {
  const entry = (relativePath: string) => ({
    path: relativePath,
    sha256: createHash('sha256')
      .update(readFileSync(join(path, relativePath)))
      .digest('hex'),
  });
  return {
    installer: entry(
      'ops/viralo/openclaw-release-radar-install-release.sh',
    ),
    applicationService: entry(
      'ops/viralo/openclaw-release-radar.service',
    ),
    reconcileBootService: entry(
      'ops/viralo/openclaw-release-radar-reconcile-boot.service',
    ),
    reconcileService: entry(
      'ops/viralo/openclaw-release-radar-reconcile.service',
    ),
    reconcileTimer: entry(
      'ops/viralo/openclaw-release-radar-reconcile.timer',
    ),
    serviceDropIn: entry(
      'ops/viralo/openclaw-release-radar.service.d/10-deploy-reconcile.conf',
    ),
  };
}

function legacyReleaseControlPlane(path: string) {
  const {
    applicationService: _applicationService,
    ...legacyControlPlane
  } = releaseControlPlane(path);
  return legacyControlPlane;
}

function releaseDigest(path: string) {
  const excluded = new Set(['.env', 'public/release-manifest.json']);
  const hash = createHash('sha256');

  function visit(relative: string) {
    const absolute = join(path, relative);
    const entries = readdirSync(absolute, { withFileTypes: true })
      .sort((left, right) => left.name < right.name ? -1 : left.name > right.name ? 1 : 0);
    for (const entry of entries) {
      const child = relative ? join(relative, entry.name) : entry.name;
      if (excluded.has(child)) continue;
      const childPath = join(path, child);
      const info = lstatSync(childPath);
      if (info.isDirectory()) {
        hash.update(`D\0${child}\0`);
        visit(child);
      } else if (info.isSymbolicLink()) {
        hash.update(`L\0${child}\0${readlinkSync(childPath)}\0`);
      } else if (info.isFile()) {
        hash.update(`F\0${child}\0${info.size}\0`);
        hash.update(readFileSync(childPath));
        hash.update('\0');
      } else {
        throw new Error(`unsupported fixture entry: ${child}`);
      }
    }
  }

  visit('');
  return `sha256:${hash.digest('hex')}`;
}

function readInstallerPendingFields(path: string) {
  return Object.fromEntries(
    INSTALLER_PENDING_STATE_FIELDS.map((field) => [
      field,
      readFileSync(join(path, field), 'utf8').trim(),
    ]),
  );
}

function logLines(path: string) {
  if (!existsSync(path)) return [];
  return readFileSync(path, 'utf8').trim().split('\n').filter(Boolean);
}

function finalizedStatePaths(base: string) {
  return readdirSync(base)
    .filter((entry) => entry.startsWith('.pending-deploy.finalized-'))
    .map((entry) => join(base, entry));
}

function completionStatePaths(shared: string) {
  const root = join(shared, 'deploy-completions');
  if (!existsSync(root)) return [];
  return readdirSync(root).map((entry) => join(root, entry));
}

function authorizationPayload(
  record: StartupAuthorizationRecord,
): StartupAuthorizationPayload {
  const { contentHash: _contentHash, ...payload } = record;
  return payload;
}

function createStartupAuthorizationFixture(name: string) {
  const dir = mkdtempSync(join(tmpdir(), `radar-startup-auth-${name}-`));
  const base = join(dir, 'radar');
  const releases = join(base, 'releases');
  const releaseName = 'release-current';
  const releaseRoot = join(releases, releaseName);
  const shared = join(base, 'shared');
  const authorizationDirectory = join(shared, 'startup-authorization');
  const authorizationPath = join(authorizationDirectory, 'active.json');
  const databasePath = join(shared, 'radar.db');
  const pendingPath = join(base, '.pending-deploy');
  const transactionId = randomUUID();
  const releaseRevision = 'a'.repeat(40);
  const artifactDigest = `sha256:${'b'.repeat(64)}`;
  const pendingStateHash = 'c'.repeat(64);
  const ownerUid = statSync(dir).uid;

  mkdirSync(releaseRoot, { recursive: true });
  mkdirSync(authorizationDirectory, { recursive: true });
  chmodSync(authorizationDirectory, 0o750);
  writeFileSync(databasePath, 'authorized database bytes\n');
  symlinkSync(releaseRoot, join(base, 'current'));

  function databaseIdentity() {
    const info = statSync(databasePath, { bigint: true });
    return {
      realPath: realpathSync(databasePath),
      device: String(info.dev),
      inode: String(info.ino),
      logicalContentDigest: 'd'.repeat(64),
      schemaDigest: 'e'.repeat(64),
      physicalSha256: createHash('sha256')
        .update(readFileSync(databasePath))
        .digest('hex'),
    };
  }

  function payload(
    lifecycle: StartupAuthorizationPayload['lifecycle'],
    state: StartupAuthorizationPayload['state'],
  ): StartupAuthorizationPayload {
    return {
      schemaVersion: 1,
      lifecycle,
      release: {
        name: releaseName,
        sha: releaseRevision,
        artifactDigest,
        realPath: realpathSync(releaseRoot),
      },
      database: databaseIdentity(),
      scoreReceipt: {
        receiptId: scoreReceiptId,
      },
      promotionReceipt: {
        promotionId: 'f'.repeat(64),
        contentHash: '1'.repeat(64),
      },
      promotionBinding: {
        contentHash: '2'.repeat(64),
        promotionAuthorizationContentHash: '3'.repeat(64),
        reportSha256: '4'.repeat(64),
      },
      transaction: {
        transactionId,
        pendingStateHash,
      },
      state,
      recordedAt: '2026-07-07T12:00:00.000Z',
    };
  }

  function record(payloadValue: StartupAuthorizationPayload):
    StartupAuthorizationRecord {
    return {
      ...payloadValue,
      contentHash: startupAuthorizationContentHash(payloadValue),
    };
  }

  function pendingAuthorization(): StartupAuthorizationRecord {
    mkdirSync(pendingPath, { recursive: true });
    return record(payload('pending-activation', {
      kind: 'pending-activation',
      path: pendingPath,
      phase: 'activated',
      phaseTransitionHash: '5'.repeat(64),
    }));
  }

  function writeRawAuthorization(value: StartupAuthorizationRecord) {
    writeFileSync(
      authorizationPath,
      `${JSON.stringify(value, null, 2)}\n`,
    );
    chmodSync(authorizationPath, 0o640);
  }

  return {
    databasePath,
    releaseRevision,
    pendingAuthorization,
    writePendingAuthorization() {
      writeRawAuthorization(pendingAuthorization());
    },
    writeCommittedAuthorization() {
      rmSync(pendingPath, { recursive: true, force: true });
      const completionPath = join(
        shared,
        'deploy-completions',
        `committed-${releaseName}-${transactionId}`,
      );
      mkdirSync(completionPath, { recursive: true });
      chmodSync(dirname(completionPath), 0o750);
      chmodSync(completionPath, 0o750);
      const finalizationPayload = {
        schemaVersion: 1,
        outcome: 'committed',
        pendingStateHash,
        transactionId,
        releaseName,
        releaseSha: releaseRevision,
        artifactDigest,
      };
      const finalization = {
        ...finalizationPayload,
        contentHash: createHash('sha256')
          .update(
            `installer-finalization-v1\0${JSON.stringify(finalizationPayload)}`,
          )
          .digest('hex'),
      };
      const finalizationPath = join(completionPath, 'finalization.json');
      writeFileSync(
        finalizationPath,
        `${JSON.stringify(finalization, null, 2)}\n`,
      );
      chmodSync(finalizationPath, 0o640);
      writeRawAuthorization(record(payload('committed-completion', {
        kind: 'committed-completion',
        path: completionPath,
        outcome: 'committed',
        finalizationContentHash: finalization.contentHash,
      })));
    },
    readAuthorization() {
      return JSON.parse(
        readFileSync(authorizationPath, 'utf8'),
      ) as StartupAuthorizationRecord;
    },
    writeRawAuthorization,
    verify() {
      return verifyProductionStartupAuthorization({
        releaseRoot,
        releaseRevision,
        databasePath,
        expectedOwnerUid: ownerUid,
      });
    },
    cleanup() {
      rmSync(dir, { recursive: true, force: true });
    },
  };
}

function waitForCondition(
  condition: () => boolean,
  timeoutMs: number,
  message: string | (() => string),
) {
  const startedAt = Date.now();
  const waitBuffer = new Int32Array(new SharedArrayBuffer(4));
  while (!condition()) {
    if (Date.now() - startedAt >= timeoutMs) {
      assert.fail(typeof message === 'function' ? message() : message);
    }
    Atomics.wait(waitBuffer, 0, 0, 50);
  }
}

function deploymentLogContents(shared: string) {
  const logRoot = join(shared, 'deploy-logs');
  if (!existsSync(logRoot)) return '<deployment log directory is absent>';
  return readdirSync(logRoot)
    .sort()
    .map((entry) => {
      const path = join(logRoot, entry);
      return `--- ${entry} ---\n${readFileSync(path, 'utf8')}`;
    })
    .join('\n');
}

function writeExecutable(path: string, contents: string) {
  writeFileSync(path, contents);
  chmodSync(path, 0o755);
}

function commandOutput(command: string, args: string[]) {
  const result = spawnSync(command, args, { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return result.stdout.trim();
}
