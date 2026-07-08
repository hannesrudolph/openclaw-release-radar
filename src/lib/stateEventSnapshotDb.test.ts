import { after, describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { fileURLToPath } from 'node:url';
import {
  ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
  canonicalStateEventActorIdentity,
  canonicalStateEventCloserIdentity,
  canonicalStateEventSourceIdentity,
  issueStateEventSweepDigest,
  issueStateEventStabilizationIdentity,
  issueStateEventSweepIdentity,
  issueStateEventsDigest,
  normalizeIssueStateEvents,
  type NormalizedIssueStateEvent,
} from './stateEventSnapshot.ts';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-state-snapshot-${name}-`)), 'radar.db');
}

const assignedWorkerDatabasePath =
  process.env.RADAR_TEST_WORKER_DB_PATH?.trim() || null;
const inheritedDotenvPath =
  process.env.DOTENV_CONFIG_PATH?.trim() || null;
const ownedDotenvDir = inheritedDotenvPath === null
  ? mkdtempSync(join(tmpdir(), 'radar-state-snapshot-env-'))
  : null;

if (assignedWorkerDatabasePath) {
  assert.equal(
    process.env.DB_PATH,
    assignedWorkerDatabasePath,
    'guarded tests must use their assigned private database',
  );
}
if (inheritedDotenvPath === null) {
  const emptyDotenvPath = join(ownedDotenvDir!, 'empty.env');
  writeFileSync(emptyDotenvPath, '');
  process.env.DOTENV_CONFIG_PATH = emptyDotenvPath;
}

let workerDb: typeof import('./db.ts') | null = null;

async function freshDb(name: string) {
  if (assignedWorkerDatabasePath) {
    if (!workerDb) {
      workerDb = await import(
        `./db.ts?state-snapshot-worker-${Date.now()}-${Math.random()}`
      );
    }
    resetDatabase(workerDb.db);
    let active = true;
    return {
      db: workerDb,
      cleanup() {
        if (!active) return;
        resetDatabase(workerDb!.db);
        active = false;
      },
    };
  }

  const path = dbPath(name);
  process.env.DB_PATH = path;
  process.env.RADAR_DB_BOOTSTRAP_MODE = 'fresh';
  process.env.RADAR_DB_READ_ONLY = '0';
  const db = await import(`./db.ts?state-snapshot-${name}-${Date.now()}-${Math.random()}`);
  let active = true;
  return {
    db,
    cleanup() {
      if (!active) return;
      db.db.close();
      rmSync(dirname(path), { recursive: true, force: true });
      active = false;
    },
  };
}

function resetDatabase(database: DatabaseSync): void {
  const tables = (database.prepare(`
    SELECT name
    FROM sqlite_master
    WHERE type='table'
      AND name NOT LIKE 'sqlite_%'
      AND name <> 'score_api_source_epoch'
    ORDER BY name
  `).all() as Array<{ name: string }>).map((row) => row.name);
  const appendOnlyTriggers = database.prepare(`
    SELECT name, sql
    FROM sqlite_master
    WHERE type='trigger'
      AND sql LIKE '% is append-only%'
    ORDER BY name
  `).all() as Array<{ name: string; sql: string }>;
  database.exec('PRAGMA foreign_keys=OFF');
  try {
    database.exec('BEGIN');
    for (const trigger of appendOnlyTriggers) {
      database.exec(`DROP TRIGGER "${trigger.name.replaceAll('"', '""')}"`);
    }
    for (const table of tables) {
      database.exec(`DELETE FROM "${table.replaceAll('"', '""')}"`);
    }
    database.exec('DELETE FROM sqlite_sequence');
    for (const trigger of appendOnlyTriggers) database.exec(trigger.sql);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  } finally {
    database.exec('PRAGMA foreign_keys=ON');
  }
}

after(() => {
  workerDb?.db.close();
  if (ownedDotenvDir) {
    rmSync(ownedDotenvDir, { recursive: true, force: true });
  }
});

function seedTestReleaseCatalog(
  db: typeof import('./db.ts'),
  releases: Array<{ tag: string; publishedAt: string }>,
): void {
  const rows = releases.map(({ tag, publishedAt }) => ({
    node_id: `RELEASE-node-${tag}`,
    catalog_tag_commit_oid: createHash('sha1')
      .update(`state-event-release:${tag}`)
      .digest('hex'),
    tag,
    name: tag,
    published_at: publishedAt,
    created_at: publishedAt,
    updated_at: publishedAt,
    html_url: `https://example.test/releases/${encodeURIComponent(tag)}`,
    prerelease: false,
    body: '',
  }));
  db.replaceActiveReleaseCatalog(rows, {
    capture: { source: 'test_fixture' },
  });
  for (const release of rows) {
    db.upsertReleaseCommit({
      tag: release.tag,
      tag_commit_oid: release.catalog_tag_commit_oid,
      committed_at: release.published_at,
    });
  }
}

function mutateBehindTrigger(
  database: DatabaseSync,
  triggerName: string,
  action: () => void,
): void {
  const trigger = database.prepare(`
    SELECT sql
    FROM sqlite_schema
    WHERE type='trigger' AND name=?
  `).get(triggerName) as { sql?: string } | undefined;
  assert.equal(typeof trigger?.sql, 'string');

  database.exec('BEGIN IMMEDIATE');
  try {
    database.exec(`DROP TRIGGER "${triggerName.replaceAll('"', '""')}"`);
    action();
    database.exec(trigger!.sql!);
    database.exec('COMMIT');
  } catch (error) {
    database.exec('ROLLBACK');
    throw error;
  }
}

function closureEvent(issueNumber: number, eventId: string, closedAt: string) {
  return {
    issue_number: issueNumber,
    issue_node_id: `ISSUE-node-${issueNumber}`,
    event_id: eventId,
    closed_at: closedAt,
    connection_ordinal: 0,
    actor_node_id: 'ACTOR-maintainer',
    actor_login: 'maintainer',
    actor_type: 'User',
    state_reason: 'COMPLETED',
    closer_type: 'PullRequest',
    closer_number: 42,
    closer_node_id: `PR-node-${eventId}`,
    closer_oid: 'a'.repeat(40),
    raw_json: JSON.stringify({
      id: eventId,
      __typename: 'ClosedEvent',
      actor: { id: 'ACTOR-maintainer', __typename: 'User', login: 'maintainer' },
      closer: { id: `PR-node-${eventId}`, __typename: 'PullRequest', number: 42 },
    }),
  };
}

function reopenEvent(issueNumber: number, eventId: string, reopenedAt: string) {
  return {
    issue_number: issueNumber,
    issue_node_id: `ISSUE-node-${issueNumber}`,
    event_id: eventId,
    reopened_at: reopenedAt,
    connection_ordinal: 1,
    actor_node_id: 'ACTOR-reporter',
    actor_login: 'reporter',
    actor_type: 'User',
    raw_json: JSON.stringify({
      id: eventId,
      __typename: 'ReopenedEvent',
      actor: { id: 'ACTOR-reporter', __typename: 'User', login: 'reporter' },
    }),
  };
}

function normalizedClosureEvent(
  close: ReturnType<typeof closureEvent>,
): NormalizedIssueStateEvent {
  return {
    eventId: close.event_id,
    eventNodeType: 'ClosedEvent',
    type: 'closed',
    occurredAt: close.closed_at,
    connectionOrdinal: close.connection_ordinal,
    actorNodeId: close.actor_node_id,
    actorLogin: close.actor_login,
    actorType: close.actor_type,
    stateReason: close.state_reason,
    closerNodeId: close.closer_node_id,
    closerType: close.closer_type,
    closerNumber: close.closer_number,
    closerOid: close.closer_oid,
  };
}

function normalizedReopenEvent(
  reopen: ReturnType<typeof reopenEvent>,
): NormalizedIssueStateEvent {
  return {
    eventId: reopen.event_id,
    eventNodeType: 'ReopenedEvent',
    type: 'reopened',
    occurredAt: reopen.reopened_at,
    connectionOrdinal: reopen.connection_ordinal,
    actorNodeId: reopen.actor_node_id,
    actorLogin: reopen.actor_login,
    actorType: reopen.actor_type,
    stateReason: null,
    closerNodeId: null,
    closerType: null,
    closerNumber: null,
    closerOid: null,
  };
}

function normalizedEvents(
  closures: Array<ReturnType<typeof closureEvent>>,
  reopens: Array<ReturnType<typeof reopenEvent>>,
): NormalizedIssueStateEvent[] {
  return normalizeIssueStateEvents([
    ...closures.map(normalizedClosureEvent),
    ...reopens.map(normalizedReopenEvent),
  ]);
}

function stabilizedSnapshotFields(input: {
  repositoryNodeId?: string;
  issueNumber: number;
  issueState: 'open' | 'closed';
  issueUpdatedAt: string;
  events: readonly NormalizedIssueStateEvent[];
}) {
  const repositoryNodeId = input.repositoryNodeId ?? 'REPO-node-openclaw';
  const issueNodeId = `ISSUE-node-${input.issueNumber}`;
  const issueNodeType = 'Issue' as const;
  const sweep = {
    repositoryNodeId,
    issueNumber: input.issueNumber,
    issueNodeId,
    issueNodeType,
    issueState: input.issueState,
    issueUpdatedAt: input.issueUpdatedAt,
    totalCount: input.events.length,
    events: input.events,
  };
  const firstSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 1,
  });
  const secondSweep = issueStateEventSweepIdentity({
    ...sweep,
    sweepOrdinal: 2,
  });
  return {
    repository_node_id: repositoryNodeId,
    issue_node_id: issueNodeId,
    issue_node_type: issueNodeType,
    events_digest: issueStateEventsDigest(input.events, {
      repositoryNodeId,
      issueNodeId,
      issueNodeType,
    }),
    authority_digest: secondSweep.sweepDigest,
    stabilization: issueStateEventStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    ),
  };
}

describe('issue state event snapshots', { concurrency: false }, () => {
  it('binds issue, event, actor, actor-type, and closer node identities into digests', () => {
    const events: NormalizedIssueStateEvent[] = [
      {
        eventId: 'EVENT-close-identity',
        eventNodeType: 'ClosedEvent',
        type: 'closed',
        occurredAt: '2026-06-01T00:00:00Z',
        connectionOrdinal: 0,
        actorNodeId: 'ACTOR-maintainer',
        actorLogin: 'maintainer',
        actorType: 'User',
        stateReason: 'COMPLETED',
        closerNodeId: 'PR-node-42',
        closerType: 'PullRequest',
        closerNumber: 42,
        closerOid: 'a'.repeat(40),
      },
      {
        eventId: 'EVENT-reopen-identity',
        eventNodeType: 'ReopenedEvent',
        type: 'reopened',
        occurredAt: '2026-06-02T00:00:00Z',
        connectionOrdinal: 1,
        actorNodeId: 'ACTOR-release-bot',
        actorLogin: 'release-bot',
        actorType: 'Bot',
        stateReason: null,
        closerNodeId: null,
        closerType: null,
        closerNumber: null,
        closerOid: null,
      },
    ];
    const issueIdentity = {
      repositoryNodeId: 'REPO-node-openclaw',
      issueNodeId: 'ISSUE-node-1',
      issueNodeType: 'Issue',
    };
    const baseline = issueStateEventsDigest(events, issueIdentity);

    for (const variant of [
      {
        events,
        identity: {
          repositoryNodeId: 'REPO-node-other',
          issueNodeId: 'ISSUE-node-1',
          issueNodeType: 'Issue',
        },
      },
      {
        events,
        identity: {
          repositoryNodeId: 'REPO-node-openclaw',
          issueNodeId: 'ISSUE-node-other',
          issueNodeType: 'Issue',
        },
      },
      {
        events: events.map((event, index) => index === 0
          ? { ...event, eventId: 'EVENT-close-other' }
          : event),
        identity: issueIdentity,
      },
      {
        events: events.map((event, index) => index === 0
          ? { ...event, actorNodeId: 'ACTOR-other-maintainer' }
          : event),
        identity: issueIdentity,
      },
      {
        events: events.map((event, index) => index === 0
          ? { ...event, actorType: 'Bot' }
          : event),
        identity: issueIdentity,
      },
      {
        events: events.map((event, index) => index === 0
          ? { ...event, closerNodeId: 'PR-node-other' }
          : event),
        identity: issueIdentity,
      },
    ]) {
      assert.notEqual(
        issueStateEventsDigest(variant.events, variant.identity),
        baseline,
      );
    }

    assert.deepEqual(canonicalStateEventSourceIdentity(events[0]), {
      source: 'github',
      nodeType: 'ClosedEvent',
      nodeId: 'EVENT-close-identity',
    });
    assert.deepEqual(canonicalStateEventActorIdentity(events[1]), {
      source: 'github',
      nodeType: 'Bot',
      nodeId: 'ACTOR-release-bot',
    });
    assert.deepEqual(canonicalStateEventCloserIdentity(events[0]), {
      source: 'github',
      nodeType: 'PullRequest',
      nodeId: 'PR-node-42',
    });
  });

  it('keeps null and legacy actors display-only while rejecting partial or conflicting identities', () => {
    const legacy: NormalizedIssueStateEvent = {
      eventId: 'EVENT-legacy-close',
      type: 'closed',
      occurredAt: '2026-06-01T00:00:00Z',
      actorLogin: 'renamed-maintainer',
      stateReason: 'COMPLETED',
      closerType: null,
      closerNumber: null,
      closerOid: null,
    };
    const missingActor = {
      ...legacy,
      eventId: 'EVENT-null-actor',
      actorLogin: null,
    };
    assert.equal(canonicalStateEventActorIdentity(legacy), null);
    assert.equal(canonicalStateEventSourceIdentity(legacy), null);
    assert.equal(canonicalStateEventActorIdentity(missingActor), null);
    assert.notEqual(
      issueStateEventsDigest([legacy]),
      issueStateEventsDigest([missingActor]),
    );

    assert.throws(
      () => normalizeIssueStateEvents([{
        ...legacy,
        actorNodeId: 'ACTOR-maintainer',
      }]),
      /actor node ID requires a canonical actor type/,
    );
    assert.throws(
      () => normalizeIssueStateEvents([{
        ...legacy,
        closerNodeId: 'PR-node-42',
      }]),
      /closer node ID requires a canonical closer type/,
    );
    assert.throws(
      () => normalizeIssueStateEvents([{
        ...legacy,
        actorNodeId: 'NODE-conflict',
        actorType: 'User',
        closerNodeId: 'NODE-conflict',
        closerType: 'PullRequest',
      }]),
      /conflicting actor and closer node ID NODE-conflict/,
    );
    assert.throws(
      () => normalizeIssueStateEvents([{
        ...legacy,
        eventId: 'EVENT-reopen-conflict',
        type: 'reopened',
        stateReason: 'COMPLETED',
      }]),
      /contains closer-only evidence/,
    );
  });

  it('keeps equal-time ordering deterministic and sweep tokens identity-bound', () => {
    const events: NormalizedIssueStateEvent[] = [
      {
        eventId: 'EVENT-z-close',
        eventNodeType: 'ClosedEvent',
        type: 'closed',
        occurredAt: '2026-06-01T03:00:00Z',
        connectionOrdinal: 0,
        actorNodeId: 'ACTOR-maintainer',
        actorLogin: 'maintainer',
        actorType: 'User',
        stateReason: 'COMPLETED',
        closerNodeId: 'COMMIT-node-z',
        closerType: 'Commit',
        closerNumber: null,
        closerOid: null,
      },
      {
        eventId: 'EVENT-a-reopen',
        eventNodeType: 'ReopenedEvent',
        type: 'reopened',
        occurredAt: '2026-06-01T03:00:00Z',
        connectionOrdinal: 1,
        actorNodeId: 'ACTOR-reporter',
        actorLogin: 'renamed-reporter',
        actorType: 'User',
        stateReason: null,
        closerNodeId: null,
        closerType: null,
        closerNumber: null,
        closerOid: null,
      },
    ];
    assert.deepEqual(
      normalizeIssueStateEvents([...events].reverse()).map((event) => event.eventId),
      ['EVENT-z-close', 'EVENT-a-reopen'],
    );
    assert.equal(
      issueStateEventsDigest(events, {
        issueNodeId: 'ISSUE-node-1',
        issueNodeType: 'Issue',
      }),
      issueStateEventsDigest([...events].reverse(), {
        issueNodeId: 'ISSUE-node-1',
        issueNodeType: 'Issue',
      }),
    );

    const sweep = {
      repositoryNodeId: 'REPO-node-openclaw',
      issueNumber: 1,
      issueNodeId: 'ISSUE-node-1',
      issueNodeType: 'Issue',
      issueState: 'open' as const,
      issueUpdatedAt: '2026-06-02T00:00:00Z',
      totalCount: 2,
      events,
    };
    const baseline = issueStateEventSweepDigest(sweep);
    assert.equal(issueStateEventSweepDigest(sweep), baseline);
    assert.notEqual(
      issueStateEventSweepDigest({
        ...sweep,
        issueUpdatedAt: '2026-06-02T00:00:01Z',
      }),
      baseline,
    );
    assert.notEqual(
      issueStateEventSweepDigest({
        ...sweep,
        issueNodeId: 'ISSUE-node-other',
      }),
      baseline,
    );
    assert.throws(
      () => issueStateEventSweepDigest({ ...sweep, totalCount: 3 }),
      /count mismatch/,
    );

    const firstSweep = issueStateEventSweepIdentity({
      ...sweep,
      sweepOrdinal: 1,
    });
    const secondSweep = issueStateEventSweepIdentity({
      ...sweep,
      sweepOrdinal: 2,
    });
    const stabilization = issueStateEventStabilizationIdentity(
      firstSweep,
      secondSweep,
      2,
    );
    assert.equal(stabilization.firstSweep.sweepOrdinal, 1);
    assert.equal(stabilization.secondSweep.sweepOrdinal, 2);
    assert.match(stabilization.identityDigest, /^[0-9a-f]{64}$/);

    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        repositoryNodeId: undefined as unknown as string,
      }),
      /requires a canonical repository node ID/,
    );
    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        issueNodeId: '',
      }),
      /issue node ID must be a non-empty canonical string/,
    );
    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        issueNodeType: 'PullRequest',
      }),
      /requires issue node type Issue/,
    );
    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        events: events.map((event, index) => index === 0
          ? { ...event, eventNodeType: undefined }
          : event),
      }),
      /requires node type ClosedEvent/,
    );
    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        events: events.map((event, index) => index === 0
          ? { ...event, actorNodeId: null }
          : event),
      }),
      /requires a canonical actor identity/,
    );
    assert.throws(
      () => issueStateEventSweepIdentity({
        ...sweep,
        sweepOrdinal: 1,
        events: events.map((event, index) => index === 0
          ? { ...event, closerNodeId: null }
          : event),
      }),
      /requires a canonical closer identity/,
    );
  });

  it('migrates legacy snapshot rows to explicit unstabilized provenance', async () => {
    const path = assignedWorkerDatabasePath
      ? join(
          mkdtempSync(
            join(dirname(assignedWorkerDatabasePath), 'legacy-migration-'),
          ),
          'radar.db',
        )
      : dbPath('migration');
    const dir = dirname(path);
    if (assignedWorkerDatabasePath) {
      assert.equal(
        workerDb,
        null,
        'legacy migration must not initialize the shared worker database',
      );
    } else {
      process.env.DB_PATH = path;
    }
    const legacy = new DatabaseSync(path);
    legacy.exec(`
      CREATE TABLE issue_state_event_snapshots (
        issue_number INTEGER PRIMARY KEY,
        schema_version INTEGER NOT NULL,
        issue_state TEXT NOT NULL,
        issue_updated_at TEXT NOT NULL,
        total_count INTEGER NOT NULL,
        fetched_count INTEGER NOT NULL,
        events_digest TEXT NOT NULL,
        events_json TEXT NOT NULL,
        revision INTEGER NOT NULL DEFAULT 1,
        fetched_at TEXT NOT NULL,
        verified_at TEXT NOT NULL
      );
    `);
    legacy.prepare(`
      INSERT INTO issue_state_event_snapshots (
        issue_number, schema_version, issue_state, issue_updated_at,
        total_count, fetched_count, events_digest, events_json,
        revision, fetched_at, verified_at
      )
      VALUES (990001, 1, 'open', '2026-06-01T00:00:00Z', 0, 0, ?, '[]', 1, ?, ?)
    `).run(
      issueStateEventsDigest([]),
      '2026-06-01T00:00:01Z',
      '2026-06-01T00:00:01Z',
    );
    legacy.close();

    if (assignedWorkerDatabasePath) {
      const result = spawnSync(process.execPath, [
        '--import=tsx',
        '--input-type=module',
        '-e',
        [
          `const migrated = (await import('./src/lib/db.ts')).default;`,
          `const row = migrated.getIssueStateEventSnapshot(990001);`,
          `const columns = migrated.db.prepare(`,
          `  'PRAGMA table_info(issue_state_event_snapshots)',`,
          `).all().map((column) => column.name);`,
          `const reusable = migrated.validateIssueStateEventSnapshot(990001).reusable;`,
          `migrated.db.close();`,
          `console.log(JSON.stringify({ row, columns, reusable }));`,
        ].join('\n'),
      ], {
        cwd: join(dirname(fileURLToPath(import.meta.url)), '..', '..'),
        env: {
          ...process.env,
          DB_PATH: path,
          RADAR_DB_BOOTSTRAP_MODE: 'existing',
          RADAR_DB_READ_ONLY: '0',
        },
        encoding: 'utf8',
      });
      assert.equal(result.status, 0, `${result.stdout}\n${result.stderr}`);
      const probe = JSON.parse(result.stdout.trim()) as {
        row: { sweep_count: number; stabilized: number };
        columns: string[];
        reusable: boolean;
      };
      assert.equal(probe.row.sweep_count, 0);
      assert.equal(probe.row.stabilized, 0);
      assert.equal(probe.reusable, false);
      assert.equal(probe.columns.includes('sweep_count'), true);
      assert.equal(probe.columns.includes('stabilized'), true);
      rmSync(dir, { recursive: true, force: true });
      return;
    }

    process.env.RADAR_DB_BOOTSTRAP_MODE = 'existing';
    process.env.RADAR_DB_READ_ONLY = '0';
    const migrated = await import(
      `./db.ts?state-snapshot-migration-${Date.now()}-${Math.random()}`
    );
    try {
      const row = migrated.getIssueStateEventSnapshot(990001);
      assert.equal(row?.sweep_count, 0);
      assert.equal(row?.stabilized, 0);
      assert.equal(migrated.validateIssueStateEventSnapshot(990001).reusable, false);
      const columns = migrated.db.prepare('PRAGMA table_info(issue_state_event_snapshots)').all() as Array<{
        name: string;
      }>;
      assert.equal(columns.some((column) => column.name === 'sweep_count'), true);
      assert.equal(columns.some((column) => column.name === 'stabilized'), true);
    } finally {
      migrated.db.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('normalizes timestamps by epoch and preserves connection order for equal instants', () => {
    const events = normalizeIssueStateEvents([
      {
        eventId: 'z-close',
        type: 'closed',
        occurredAt: '2026-06-01T01:00:00-02:00',
        connectionOrdinal: 0,
        actorLogin: 'maintainer',
        stateReason: 'COMPLETED',
        closerType: null,
        closerNumber: null,
        closerOid: null,
      },
      {
        eventId: 'a-reopen',
        type: 'reopened',
        occurredAt: '2026-06-01T03:00:00Z',
        connectionOrdinal: 1,
        actorLogin: 'reporter',
        stateReason: null,
        closerType: null,
        closerNumber: null,
        closerOid: null,
      },
    ]);

    assert.deepEqual(events.map((event) => event.eventId), ['z-close', 'a-reopen']);
    assert.deepEqual(events.map((event) => event.occurredAt), [
      '2026-06-01T03:00:00.000Z',
      '2026-06-01T03:00:00.000Z',
    ]);
    assert.equal(
      issueStateEventsDigest(events),
      issueStateEventsDigest(events.map((event) => ({
        ...event,
        occurredAt: '2026-05-31T21:00:00-06:00',
      }))),
    );
    assert.throws(
      () => normalizeIssueStateEvents(events.map((event) => ({
        ...event,
        connectionOrdinal: 0,
      }))),
      /duplicate connection ordinal 0/,
    );
    assert.throws(
      () => normalizeIssueStateEvents([
        { ...events[0], connectionOrdinal: 1 },
        { ...events[1], connectionOrdinal: 2 },
      ]),
      /non-contiguous connection ordinal 1; expected 0/,
    );
    assert.throws(
      () => normalizeIssueStateEvents([
        {
          ...events[0],
          occurredAt: '2026-06-01T04:00:00Z',
          connectionOrdinal: 0,
        },
        {
          ...events[1],
          occurredAt: '2026-06-01T03:00:00Z',
          connectionOrdinal: 1,
        },
      ]),
      /out of chronological connection order/,
    );
  });

  it('atomically replaces state event projections and preserves semantic revisions on no-op verification', async () => {
    const { db, cleanup } = await freshDb('replace');
    try {
      const close = closureEvent(1, 'close-1', '2026-06-01T00:00:00Z');
      const reopen = reopenEvent(1, 'reopen-1', '2026-06-02T00:00:00Z');
      const events = normalizedEvents([close], [reopen]);
      const input = {
        issue_number: 1,
        schema_version: ISSUE_STATE_EVENT_SNAPSHOT_SCHEMA_VERSION,
        issue_state: 'open' as const,
        issue_updated_at: '2026-06-02T00:00:00Z',
        total_count: 2,
        fetched_count: 2,
        sweep_count: 2,
        stabilized: true,
        closure_events: [close],
        reopen_events: [reopen],
        ...stabilizedSnapshotFields({
          issueNumber: 1,
          issueState: 'open',
          issueUpdatedAt: '2026-06-02T00:00:00Z',
          events,
        }),
      };

      db.replaceIssueStateEventSnapshot(input);
      const first = db.getIssueStateEventSnapshot(1);
      assert.equal(first?.revision, 1);
      assert.equal(first?.sweep_count, 2);
      assert.equal(first?.stabilized, 1);
      assert.equal(db.db.prepare('SELECT COUNT(*) AS count FROM issue_closure_events').get().count, 1);
      assert.equal(db.db.prepare('SELECT COUNT(*) AS count FROM issue_reopen_events').get().count, 1);

      db.replaceIssueStateEventSnapshot(input);
      const second = db.getIssueStateEventSnapshot(1);
      assert.equal(second?.revision, 1);
      assert.equal(second?.fetched_at, first?.fetched_at);

      const closeOnlyEvents = normalizedEvents([close], []);
      db.replaceIssueStateEventSnapshot({
        ...input,
        issue_state: 'closed',
        issue_updated_at: '2026-06-03T00:00:00Z',
        total_count: 1,
        fetched_count: 1,
        reopen_events: [],
        ...stabilizedSnapshotFields({
          issueNumber: 1,
          issueState: 'closed',
          issueUpdatedAt: '2026-06-03T00:00:00Z',
          events: closeOnlyEvents,
        }),
      });
      const replaced = db.getIssueStateEventSnapshot(1);
      assert.equal(replaced?.revision, 2);
      assert.equal(db.db.prepare('SELECT COUNT(*) AS count FROM issue_reopen_events').get().count, 0);
    } finally {
      cleanup();
    }
  });

  it('rejects incomplete or digest-mismatched snapshots before changing projections', async () => {
    const { db, cleanup } = await freshDb('reject');
    try {
      const issueNumber = 2;
      const close = closureEvent(issueNumber, 'close-2', '2026-06-01T00:00:00Z');
      const events = normalizedEvents([close], []);
      const proof = stabilizedSnapshotFields({
        issueNumber,
        issueState: 'closed',
        issueUpdatedAt: '2026-06-01T00:00:00Z',
        events,
      });
      assert.throws(
        () => db.replaceIssueStateEventSnapshot({
          ...proof,
          issue_number: issueNumber,
          issue_state: 'closed',
          issue_updated_at: '2026-06-01T00:00:00Z',
          total_count: 2,
          fetched_count: 1,
          events_digest: '0'.repeat(64),
          sweep_count: 2,
          stabilized: true,
          closure_events: [close],
          reopen_events: [],
        }),
        /snapshot is incomplete/,
      );
      assert.throws(
        () => db.replaceIssueStateEventSnapshot({
          ...proof,
          issue_number: issueNumber,
          issue_state: 'closed',
          issue_updated_at: '2026-06-01T00:00:00Z',
          total_count: 1,
          fetched_count: 1,
          events_digest: '0'.repeat(64),
          sweep_count: 2,
          stabilized: true,
          closure_events: [close],
          reopen_events: [],
        }),
        /digest mismatch/,
      );
      assert.throws(
        () => db.replaceIssueStateEventSnapshot({
          ...proof,
          issue_number: issueNumber,
          issue_state: 'closed',
          issue_updated_at: '2026-06-01T00:00:00Z',
          total_count: 1,
          fetched_count: 1,
          sweep_count: 1,
          stabilized: false,
          closure_events: [close],
          reopen_events: [],
        }),
        /snapshot is not stabilized/,
      );
      assert.equal(db.getIssueStateEventSnapshot(issueNumber), undefined);
      assert.equal(
        db.db.prepare('SELECT COUNT(*) AS count FROM issue_closure_events WHERE issue_number=?')
          .get(issueNumber).count,
        0,
      );
    } finally {
      cleanup();
    }
  });

  it('invalidates a stored snapshot when its repository identity is mutated', async () => {
    const { db, cleanup } = await freshDb('repository-mutation');
    try {
      const issueNumber = 3;
      const close = closureEvent(issueNumber, 'close-3', '2026-06-01T00:00:00Z');
      const events = normalizedEvents([close], []);
      db.replaceIssueStateEventSnapshot({
        issue_number: issueNumber,
        issue_state: 'closed',
        issue_updated_at: '2026-06-01T00:00:00Z',
        total_count: 1,
        fetched_count: 1,
        sweep_count: 2,
        stabilized: true,
        closure_events: [close],
        reopen_events: [],
        ...stabilizedSnapshotFields({
          issueNumber,
          issueState: 'closed',
          issueUpdatedAt: '2026-06-01T00:00:00Z',
          events,
        }),
      });
      assert.equal(db.validateIssueStateEventSnapshot(issueNumber).reusable, true);

      mutateBehindTrigger(
        db.db,
        'issue_state_event_snapshots_repository_node_id_immutable',
        () => {
          db.db.prepare(`
            UPDATE issue_state_event_snapshots
            SET repository_node_id='REPO-node-other'
            WHERE issue_number=?
          `).run(issueNumber);
        },
      );

      const validation = db.validateIssueStateEventSnapshot(issueNumber);
      assert.equal(validation.snapshotValid, false);
      assert.equal(validation.reusable, false);
    } finally {
      cleanup();
    }
  });

  it('fails closed when an open issue has a close event but no verified reopen snapshot', async () => {
    const { db, cleanup } = await freshDb('missing-reopen');
    try {
      seedTestReleaseCatalog(db, [{
        tag: 'v-state',
        publishedAt: '2026-06-01T00:00:00Z',
      }]);
      db.upsertIssue({
        number: 9202,
        state: 'open',
        title: 'open after a missing reopen event',
        author: 'reporter',
        html_url: 'https://example.test/issues/9202',
        created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-06-02T00:00:00Z',
        closed_at: null,
        comments: 0,
        labels: '[]',
        is_bot: 0,
      });
      db.upsertIssueClosureEvent(closureEvent(9202, 'close-9202', '2026-05-02T00:00:00Z'));

      const report = db.releaseIssueStateSnapshotIntegrity('v-state');
      assert.equal(report.candidateIssueCount, 1);
      assert.equal(report.missingSnapshotCount, 1);
      assert.match(db.formatReleaseIssueStateSnapshotIntegrityFailure(report), /missing=1/);
    } finally {
      cleanup();
    }
  });

  it('detects full projection tampering and repairs unchanged or corrupted snapshots', async () => {
    const { db, cleanup } = await freshDb('projection-repair');
    try {
      const issueNumber = 9301;
      seedTestReleaseCatalog(db, [{
        tag: 'v-projection',
        publishedAt: '2026-06-01T00:00:00Z',
      }]);
      db.upsertIssue({
        number: issueNumber,
        state: 'closed',
        title: 'projection parity',
        author: 'reporter',
        html_url: `https://example.test/issues/${issueNumber}`,
        created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-06-04T00:00:00Z',
        closed_at: '2026-06-04T00:00:00Z',
        comments: 0,
        labels: '[]',
        is_bot: 0,
      });
      const firstClose = {
        ...closureEvent(issueNumber, 'close-first', '2026-06-02T00:00:00Z'),
        connection_ordinal: 0,
      };
      const reopen = {
        ...reopenEvent(issueNumber, 'reopen-middle', '2026-06-03T00:00:00Z'),
        connection_ordinal: 1,
      };
      const finalClose = {
        ...closureEvent(issueNumber, 'close-final', '2026-06-04T00:00:00Z'),
        connection_ordinal: 2,
      };
      const events = normalizedEvents([firstClose, finalClose], [reopen]);
      const input = {
        issue_number: issueNumber,
        issue_state: 'closed' as const,
        issue_updated_at: '2026-06-04T00:00:00Z',
        total_count: 3,
        fetched_count: 3,
        sweep_count: 2,
        stabilized: true,
        closure_events: [firstClose, finalClose],
        reopen_events: [reopen],
        ...stabilizedSnapshotFields({
          issueNumber,
          issueState: 'closed',
          issueUpdatedAt: '2026-06-04T00:00:00Z',
          events,
        }),
      };

      db.replaceIssueStateEventSnapshot(input);
      const originalSnapshot = db.getIssueStateEventSnapshot(issueNumber)!;
      const untouchedProjection = db.db.prepare(`
        SELECT fetched_at
        FROM issue_closure_events
        WHERE event_id='close-final'
      `).get() as { fetched_at: string };
      db.db.prepare(`
        UPDATE issue_closure_events
        SET closed_at='2026-06-03T00:00:00Z',
            actor_login='attacker',
            closer_number=999,
            closer_oid='tampered'
        WHERE event_id='close-first'
      `).run();
      db.db.prepare(`
        UPDATE issue_reopen_events
        SET reopened_at='2026-06-02T00:00:00Z'
        WHERE event_id='reopen-middle'
      `).run();
      assert.equal(db.validateIssueStateEventSnapshot(issueNumber).snapshotValid, true);
      assert.equal(db.validateIssueStateEventSnapshot(issueNumber).projectionMatches, false);
      const tamperedReport = db.releaseIssueStateSnapshotIntegrity('v-projection');
      assert.equal(tamperedReport.projectionMismatchCount, 1);
      assert.equal(tamperedReport.latestStateMismatchCount, 0);

      db.replaceIssueStateEventSnapshot(input);
      const repairedSnapshot = db.getIssueStateEventSnapshot(issueNumber)!;
      assert.equal(db.validateIssueStateEventSnapshot(issueNumber).reusable, true);
      assert.equal(repairedSnapshot.revision, originalSnapshot.revision);
      assert.equal(repairedSnapshot.fetched_at, originalSnapshot.fetched_at);
      const repairedClose = db.db.prepare(`
        SELECT closed_at, actor_login, closer_number, closer_oid
        FROM issue_closure_events
        WHERE event_id='close-first'
      `).get() as any;
      assert.equal(repairedClose.closed_at, '2026-06-02T00:00:00.000Z');
      assert.equal(repairedClose.actor_login, 'maintainer');
      assert.equal(repairedClose.closer_number, 42);
      assert.equal(repairedClose.closer_oid, 'a'.repeat(40));
      assert.equal(
        (db.db.prepare(`
          SELECT reopened_at
          FROM issue_reopen_events
          WHERE event_id='reopen-middle'
        `).get() as any).reopened_at,
        '2026-06-03T00:00:00.000Z',
      );
      assert.equal(
        (db.db.prepare(`
          SELECT fetched_at
          FROM issue_closure_events
          WHERE event_id='close-final'
        `).get() as any).fetched_at,
        untouchedProjection.fetched_at,
      );

      db.db.prepare(`
        UPDATE issue_state_event_snapshots
        SET events_json='[]', sweep_count=1, stabilized=0
        WHERE issue_number=?
      `).run(issueNumber);
      assert.equal(db.issueStateEventSnapshotIsReusable(issueNumber), false);
      db.replaceIssueStateEventSnapshot(input);
      assert.equal(db.issueStateEventSnapshotIsReusable(issueNumber), true);
      assert.equal(db.getIssueStateEventSnapshot(issueNumber)?.events_json, JSON.stringify(events));
    } finally {
      cleanup();
    }
  });
});

describe('release closure dependency snapshots', { concurrency: false }, () => {
  it('binds transitive issue revisions and rejects persistence after dependency drift', async () => {
    const { db, cleanup } = await freshDb('closure-dependencies');
    try {
      seedTestReleaseCatalog(db, [{
        tag: 'v1',
        publishedAt: '2026-06-01T00:00:00Z',
      }]);
      for (const issueNumber of [9501, 9502, 9503]) {
        db.upsertIssue({
          number: issueNumber,
          state: 'closed',
          title: `issue ${issueNumber}`,
          author: 'reporter',
          html_url: `https://example.test/issues/${issueNumber}`,
          created_at: '2026-05-01T00:00:00Z',
          updated_at: '2026-06-01T00:00:00Z',
          closed_at: '2026-06-02T00:00:00Z',
          comments: 0,
          labels: '[]',
          is_bot: 0,
        });
      }

      const identity = db.releaseClosureDependencyIdentity('v1', [9501, 9502, 9503]);
      db.replaceReleaseClosureDependencySnapshot(identity);
      assert.equal(db.getReleaseClosureDependencySnapshot('v1')?.dependency_digest, identity.digest);
      assert.equal(db.releaseClosureProofIntegrity('v1').dependencySnapshotMismatchCount, 0);

      db.upsertIssue({
        number: 9502,
        state: 'closed',
        title: 'changed transitive issue',
        author: 'reporter',
        html_url: 'https://example.test/issues/9502',
        created_at: '2026-05-01T00:00:00Z',
        updated_at: '2026-06-03T00:00:00Z',
        closed_at: '2026-06-02T00:00:00Z',
        comments: 0,
        labels: '[]',
        is_bot: 0,
      });
      const changed = db.releaseClosureDependencyIdentity('v1', [9501, 9502, 9503]);
      assert.notEqual(changed.digest, identity.digest);
      const integrity = db.releaseClosureProofIntegrity('v1');
      assert.equal(integrity.dependencySnapshotMismatchCount, 1);
      assert.ok(integrity.staleCount >= 1);
      assert.throws(
        () => db.replaceReleaseClosureDependencySnapshot(identity),
        /dependencies changed before snapshot persistence/,
      );

      seedTestReleaseCatalog(db, [
        {
          tag: 'v2',
          publishedAt: '2026-06-10T00:00:00Z',
        },
        {
          tag: 'v1',
          publishedAt: '2026-06-01T00:00:00Z',
        },
      ]);
      db.upsertIssueClosureProof({
        release_tag: 'v1',
        issue_number: 9501,
        status: 'fixed_in_release',
        summary: 'same semantic proof',
        evidence_json: '{}',
      });
      const beforeObservationTimeChange = db.releaseClosureDependencyIdentity('v2', [9501]);
      db.db.prepare(`
        UPDATE issue_closure_proofs
        SET checked_at='2035-01-01T00:00:00Z'
        WHERE release_tag='v1' AND issue_number=9501
      `).run();
      const afterObservationTimeChange = db.releaseClosureDependencyIdentity('v2', [9501]);
      assert.equal(afterObservationTimeChange.digest, beforeObservationTimeChange.digest);
    } finally {
      cleanup();
    }
  });
});
