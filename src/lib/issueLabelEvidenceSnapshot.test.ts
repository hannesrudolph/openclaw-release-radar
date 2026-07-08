import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import type {
  GhIssueLabelEvidenceSnapshot,
  GhIssueLabelEvent,
} from './github.ts';
import {
  buildIssueLabelEvidenceSnapshot,
  issueLabelEvidenceSnapshotProblems,
  type IssueLabelEvidenceSnapshot,
} from './issueLabelEvidenceSnapshot.ts';

function event(
  eventId: string,
  overrides: Partial<GhIssueLabelEvent> = {},
): GhIssueLabelEvent {
  const action = overrides.action ?? 'labeled';
  const labelName = overrides.labelName ?? 'bug';
  const labelNodeId = overrides.labelNodeId ?? 'LABEL-node-bug';
  const actorLogin =
    overrides.actorLogin === undefined ? 'maintainer' : overrides.actorLogin;
  const actorNodeId = actorLogin == null
    ? null
    : overrides.actorNodeId ?? 'ACTOR-node-maintainer';
  const actorType = actorLogin == null
    ? null
    : overrides.actorType ?? 'User';
  const createdAt = overrides.createdAt ?? '2026-07-04T01:00:00.000Z';
  return {
    issueNumber: 42,
    issueNodeId: 'ISSUE-node-42',
    issueNodeType: 'Issue',
    eventId,
    action,
    labelNodeId,
    labelName,
    actorNodeId,
    actorLogin,
    actorType,
    createdAt,
    raw: {
      id: eventId,
      __typename: action === 'labeled' ? 'LabeledEvent' : 'UnlabeledEvent',
      createdAt,
      actor: actorLogin == null
        ? null
        : {
            id: actorNodeId,
            __typename: actorType,
            login: actorLogin,
          },
      label: {
        id: labelNodeId,
        name: labelName,
      },
    },
    ...overrides,
  };
}

function input(
  events: GhIssueLabelEvent[] = [
    event('LABEL-EVENT-1'),
    event('LABEL-EVENT-2', {
      action: 'unlabeled',
      actorNodeId: null,
      actorLogin: null,
      actorType: null,
      createdAt: '2026-07-04T02:00:00.000Z',
    }),
  ],
): GhIssueLabelEvidenceSnapshot {
  return {
    schemaVersion: 2,
    repository: 'OpenClaw/OpenClaw',
    repositoryNodeId: 'REPO-node-openclaw',
    issueNumber: 42,
    issueNodeId: 'ISSUE-node-42',
    issueNodeType: 'Issue',
    capturedAt: '2026-07-04T03:00:00.000Z',
    issueUpdatedAt: '2026-07-04T02:30:00.000Z',
    totalCount: events.length,
    fetchedCount: events.length,
    pageCount: 1,
    sweepCount: 2,
    stabilized: true,
    events,
  };
}

describe('issue label evidence snapshots', () => {
  it('builds deeply immutable evidence bound to repository, issue, label, and actor identities', () => {
    const snapshot = buildIssueLabelEvidenceSnapshot(input());

    assert.equal(snapshot.repository, 'openclaw/openclaw');
    assert.equal(snapshot.repositoryNodeId, 'REPO-node-openclaw');
    assert.equal(snapshot.issueNodeId, 'ISSUE-node-42');
    assert.equal(snapshot.rows[0].labelNodeId, 'LABEL-node-bug');
    assert.equal(snapshot.rows[0].actorNodeId, 'ACTOR-node-maintainer');
    assert.equal(snapshot.rows[1].actorNodeId, null);
    assert.match(snapshot.snapshotId, /^issue-label-evidence:v2:[0-9a-f]{64}$/);
    assert.match(snapshot.rowsContentHash, /^[0-9a-f]{64}$/);
    assert.match(snapshot.contentHash, /^[0-9a-f]{64}$/);
    assert.deepEqual(issueLabelEvidenceSnapshotProblems(snapshot), []);
    assert.equal(Object.isFrozen(snapshot), true);
    assert.equal(Object.isFrozen(snapshot.rows), true);
    assert.equal(Object.isFrozen(snapshot.rows[0]), true);
  });

  it('changes immutable hashes when authority identity or raw evidence changes', () => {
    const baseline = buildIssueLabelEvidenceSnapshot(input());
    const changedActor = buildIssueLabelEvidenceSnapshot(input([
      event('LABEL-EVENT-1', { actorNodeId: 'ACTOR-node-other' }),
      input().events[1],
    ]));
    const changedLabel = buildIssueLabelEvidenceSnapshot(input([
      event('LABEL-EVENT-1', { labelNodeId: 'LABEL-node-security' }),
      input().events[1],
    ]));
    const changedRaw = buildIssueLabelEvidenceSnapshot(input([
      event('LABEL-EVENT-1', {
        raw: {
          id: 'LABEL-EVENT-1',
          __typename: 'LabeledEvent',
          createdAt: '2026-07-04T01:00:00.000Z',
          actor: {
            id: 'ACTOR-node-maintainer',
            __typename: 'User',
            login: 'maintainer',
          },
          label: {
            id: 'LABEL-node-bug',
            name: 'bug',
          },
          sourceMutation: true,
        },
      }),
      input().events[1],
    ]));

    assert.notEqual(changedActor.contentHash, baseline.contentHash);
    assert.notEqual(changedLabel.contentHash, baseline.contentHash);
    assert.notEqual(changedRaw.contentHash, baseline.contentHash);
    assert.notEqual(changedActor.rows[0].contentHash, baseline.rows[0].contentHash);
    assert.notEqual(changedLabel.rows[0].contentHash, baseline.rows[0].contentHash);
    assert.notEqual(changedRaw.rows[0].contentHash, baseline.rows[0].contentHash);
  });

  it('rejects incomplete counts, duplicate event IDs, mismatched issues, and partial actors', () => {
    assert.throws(
      () => buildIssueLabelEvidenceSnapshot({
        ...input(),
        fetchedCount: 1,
      }),
      /fetch the complete timeline count/,
    );
    assert.throws(
      () => buildIssueLabelEvidenceSnapshot(input([
        event('LABEL-EVENT-duplicate'),
        event('LABEL-EVENT-duplicate'),
      ])),
      /duplicate event node ID LABEL-EVENT-duplicate/,
    );
    assert.throws(
      () => buildIssueLabelEvidenceSnapshot(input([
        event('LABEL-EVENT-other-issue', {
          issueNodeId: 'ISSUE-node-other',
        }),
      ])),
      /does not match snapshot issue identity/,
    );
    assert.throws(
      () => buildIssueLabelEvidenceSnapshot(input([
        event('LABEL-EVENT-partial-actor', {
          actorNodeId: null,
          actorLogin: 'maintainer',
          actorType: 'User',
        }),
      ])),
      /actor identity is incomplete/,
    );
  });

  it('detects metadata and row tampering during verification', () => {
    const original = buildIssueLabelEvidenceSnapshot(input());
    const tampered = JSON.parse(
      JSON.stringify(original),
    ) as IssueLabelEvidenceSnapshot;
    (tampered as { contentHash: string }).contentHash = 'f'.repeat(64);

    assert.deepEqual(
      issueLabelEvidenceSnapshotProblems(tampered),
      ['issue label evidence immutable metadata does not match its rows'],
    );
  });
});
