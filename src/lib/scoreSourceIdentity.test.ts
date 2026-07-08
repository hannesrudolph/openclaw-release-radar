import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  SCORE_SOURCE_IDENTITY_SCHEMA_VERSION,
  currentEffectiveScoringConfig,
  scoreEffectiveScoringConfigDigest,
  scoreSourceIdentityForDb,
  scoreSourceIdentityManifestDigest,
  scoreSourceIdentityManifestProblems,
  type ScoreEffectiveScoringConfig,
  type ScoreSourceIdentityDatabase,
  type ScoreSourceIdentityStatement,
} from './scoreSourceIdentity.ts';

function selectedColumns(sql: string): string[] {
  const match = sql.match(/^SELECT (.+?) FROM "[^"]+"/);
  if (!match) throw new Error(`Unexpected score identity SQL: ${sql}`);
  return [...match[1].matchAll(/"([^"]+)"/g)].map((column) => column[1]);
}

function selectedTable(sql: string): string {
  const match = sql.match(/ FROM "([^"]+)"/);
  if (!match) throw new Error(`Unexpected score identity SQL: ${sql}`);
  return match[1];
}

function rowFor(columns: string[], index: number): Record<string, unknown> {
  return Object.fromEntries(columns.map((column) => [
    column,
    column === 'number' || column === 'issue_number' ? index + 1 : null,
  ]));
}

function emptyDatabase(): ScoreSourceIdentityDatabase {
  return {
    prepare(): ScoreSourceIdentityStatement {
      return { all: () => [] };
    },
  };
}

function effectiveScoringConfig(
  overrides: Partial<ScoreEffectiveScoringConfig> = {},
): ScoreEffectiveScoringConfig {
  const baseline = currentEffectiveScoringConfig();
  return {
    ...baseline,
    ...overrides,
    repository: {
      ...baseline.repository,
      ...overrides.repository,
    },
    recommendation: {
      ...baseline.recommendation,
      ...overrides.recommendation,
    },
  };
}

describe('score source identity streaming', () => {
  it('streams a large source table with at most one generated row retained by the adapter', () => {
    const issueRows = 50_000;
    let activeRows = 0;
    let maxActiveRows = 0;
    let allCalls = 0;
    const database: ScoreSourceIdentityDatabase = {
      prepare(sql: string): ScoreSourceIdentityStatement {
        const table = selectedTable(sql);
        const columns = selectedColumns(sql);
        return {
          *iterate() {
            if (table !== 'issues') return;
            for (let index = 0; index < issueRows; index++) {
              activeRows++;
              maxActiveRows = Math.max(maxActiveRows, activeRows);
              yield rowFor(columns, index);
              activeRows--;
            }
          },
          all() {
            allCalls++;
            throw new Error('streaming adapter must not call all()');
          },
        };
      },
    };

    const identity = scoreSourceIdentityForDb(database);
    const issues = identity.sources.find((source) => source.source === 'issues');

    assert.equal(issues?.count, issueRows);
    assert.equal(identity.rowCount, issueRows);
    assert.equal(allCalls, 0);
    assert.equal(maxActiveRows, 1);
    assert.equal(activeRows, 0);
  });

  it('retains deterministic hashes for legacy all-only adapters', () => {
    const makeDatabase = (mode: 'iterate' | 'all'): ScoreSourceIdentityDatabase => ({
      prepare(sql: string): ScoreSourceIdentityStatement {
        const table = selectedTable(sql);
        const columns = selectedColumns(sql);
        const rows = table === 'issues'
          ? Array.from({ length: 3 }, (_, index) => rowFor(columns, index))
          : [];
        return mode === 'iterate'
          ? { iterate: () => rows.values() }
          : { all: () => rows };
      },
    });

    assert.deepEqual(
      scoreSourceIdentityForDb(makeDatabase('all')),
      scoreSourceIdentityForDb(makeDatabase('iterate')),
    );
  });

  it('includes connection ordinals in closure and reopen source projections', () => {
    const selected = new Map<string, string[]>();
    const database: ScoreSourceIdentityDatabase = {
      prepare(sql: string): ScoreSourceIdentityStatement {
        selected.set(selectedTable(sql), selectedColumns(sql));
        return { all: () => [] };
      },
    };

    scoreSourceIdentityForDb(database);

    assert.ok(selected.get('issue_closure_events')?.includes('connection_ordinal'));
    assert.ok(selected.get('issue_reopen_events')?.includes('connection_ordinal'));
  });

  it('binds canonical issue author identity used by score and profile evidence', () => {
    const selected = new Map<string, string[]>();
    const database = (authorNodeId: string, authorType: string) => ({
      prepare(sql: string): ScoreSourceIdentityStatement {
        const table = selectedTable(sql);
        const columns = selectedColumns(sql);
        selected.set(table, columns);
        if (table !== 'issues') return { all: () => [] };
        return {
          all: () => [Object.fromEntries(columns.map((column) => [
            column,
            column === 'number'
              ? 1
              : column === 'author_node_id'
                ? authorNodeId
                : column === 'author_type'
                  ? authorType
                  : null,
          ]))],
        };
      },
    });

    const baseline = scoreSourceIdentityForDb(database('U_reporter', 'User'));
    const changedNode = scoreSourceIdentityForDb(database('U_other', 'User'));
    const changedType = scoreSourceIdentityForDb(database('U_reporter', 'Bot'));

    assert.ok(selected.get('issues')?.includes('author_node_id'));
    assert.ok(selected.get('issues')?.includes('author_type'));
    assert.notEqual(baseline.digest, changedNode.digest);
    assert.notEqual(baseline.digest, changedType.digest);
  });

  it('binds label actor types and raw v2 authority evidence while excluding derived authority outputs', () => {
    const selected = new Map<string, string[]>();
    const database: ScoreSourceIdentityDatabase = {
      prepare(sql: string): ScoreSourceIdentityStatement {
        selected.set(selectedTable(sql), selectedColumns(sql));
        return { all: () => [] };
      },
    };
    const empty = scoreSourceIdentityForDb(database);
    assert.equal(empty.sourceCount, 32);
    assert.ok(selected.get('issue_label_events')?.includes('actor_type'));
    const rawAuthoritySources = [
      'issue_label_evidence_snapshots',
      'issue_label_evidence_rows',
      'repository_collaborator_permission_snapshots_v2',
      'repository_collaborator_permission_rows_v2',
      'signed_maintainer_roster_snapshots',
      'signed_maintainer_roster_entries',
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
      'closure_claim_extraction_receipts',
      'closure_claim_extraction_receipt_members',
    ] as const;
    for (const table of rawAuthoritySources) assert.equal(selected.has(table), true);
    for (const column of [
      'purpose',
      'sequence',
      'prior_digest',
      'keyring_digest',
      'signature_verified_at',
    ]) {
      assert.ok(
        selected.get('signed_maintainer_roster_snapshots')?.includes(column),
        `signed roster snapshot source identity must include ${column}`,
      );
    }
    assert.ok(
      selected
        .get('signed_maintainer_roster_entries')
        ?.includes('actor_association'),
    );
    for (const derivedTable of [
      'score_authority_resolution_runs',
      'score_authority_resolution_rows',
      'release_score_audit_history_v2_seals',
    ]) {
      assert.equal(selected.has(derivedTable), false);
    }

    const sourceDigest = (
      table: string,
      row: Record<string, unknown>,
    ): string | undefined => scoreSourceIdentityForDb({
      prepare(sql: string): ScoreSourceIdentityStatement {
        const selectedSource = selectedTable(sql);
        const columns = selectedColumns(sql);
        if (selectedSource !== table) return { all: () => [] };
        return {
          all: () => [Object.fromEntries(columns.map((column) => [
            column,
            row[column] ?? null,
          ]))],
        };
      },
    }).sources.find((source) => source.source === table)?.digest;

    assert.notEqual(
      sourceDigest('issue_label_events', {
        event_id: 'label-1',
        actor_type: 'User',
      }),
      sourceDigest('issue_label_events', {
        event_id: 'label-1',
        actor_type: null,
      }),
    );
    for (const [table, key] of [
      ['issue_label_evidence_snapshots', 'rows_content_hash'],
      ['issue_label_evidence_rows', 'raw_json'],
      ['repository_collaborator_permission_snapshots_v2', 'raw_json'],
      ['repository_collaborator_permission_rows_v2', 'permission'],
      ['signed_maintainer_roster_snapshots', 'signature'],
      ['signed_maintainer_roster_snapshots', 'keyring_digest'],
      ['signed_maintainer_roster_snapshots', 'signature_verified_at'],
      ['signed_maintainer_roster_entries', 'effective_until'],
      ['signed_maintainer_roster_entries', 'actor_association'],
      ['closure_claim_source_snapshots', 'canonical_source_json'],
      ['closure_claim_candidates', 'canonical_candidate_json'],
      ['closure_claim_extraction_receipts', 'canonical_receipt_json'],
      ['closure_claim_extraction_receipt_members', 'candidate_content_hash'],
    ] as const) {
      assert.notEqual(
        sourceDigest(table, { snapshot_id: 'snapshot-1', [key]: 'first' }),
        sourceDigest(table, { snapshot_id: 'snapshot-1', [key]: 'second' }),
        `${table}.${key} must change its source digest`,
      );
    }
  });

  it('changes event source digests when ordinal, actor, or closer provenance changes', () => {
    const identityFor = (overrides: Record<string, unknown>) =>
      scoreSourceIdentityForDb({
        prepare(sql: string): ScoreSourceIdentityStatement {
          const table = selectedTable(sql);
          const columns = selectedColumns(sql);
          const row = Object.fromEntries(columns.map((column) => [column, null]));
          if (table === 'issue_closure_events') {
            Object.assign(row, {
              issue_number: 1,
              event_id: 'closed-1',
              closed_at: '2026-07-01T00:00:00Z',
              connection_ordinal: 0,
              actor_login: 'maintainer',
              closer_type: 'PullRequest',
              closer_number: 42,
              ...overrides,
            });
            return { all: () => [row] };
          }
          return { all: () => [] };
        },
      });
    const baseline = identityFor({});
    const sourceDigest = (identity: typeof baseline) =>
      identity.sources.find((source) => source.source === 'issue_closure_events')?.digest;

    assert.notEqual(sourceDigest(identityFor({ connection_ordinal: 1 })), sourceDigest(baseline));
    assert.notEqual(sourceDigest(identityFor({ actor_login: 'attacker' })), sourceDigest(baseline));
    assert.notEqual(sourceDigest(identityFor({ closer_number: 99 })), sourceDigest(baseline));
  });

  it('binds the manifest digest to code revision and effective scoring config', () => {
    const baseline = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'revision-a',
      effectiveScoringConfig: effectiveScoringConfig(),
    });
    const codeChanged = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'revision-b',
      effectiveScoringConfig: effectiveScoringConfig(),
    });
    const limitChanged = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'revision-a',
      effectiveScoringConfig: effectiveScoringConfig({
        monitoredReleaseLimit: baseline.effectiveScoringConfig.monitoredReleaseLimit + 1,
      }),
    });
    const repositoryChanged = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'revision-a',
      effectiveScoringConfig: effectiveScoringConfig({
        repository: {
          ...baseline.effectiveScoringConfig.repository,
          repo: `${baseline.effectiveScoringConfig.repository.repo}-fork`,
        },
      }),
    });

    assert.deepEqual(codeChanged.sources, baseline.sources);
    assert.deepEqual(limitChanged.sources, baseline.sources);
    assert.notEqual(codeChanged.digest, baseline.digest);
    assert.notEqual(limitChanged.digest, baseline.digest);
    assert.notEqual(repositoryChanged.digest, baseline.digest);
    assert.notEqual(
      limitChanged.effectiveScoringConfigDigest,
      baseline.effectiveScoringConfigDigest,
    );
    assert.deepEqual(Object.keys(baseline.effectiveScoringConfig).sort(), [
      'monitoredReleaseLimit',
      'recommendation',
      'repository',
      'schemaVersion',
    ]);
  });

  it('canonicalizes effective scoring configuration independently of key order', () => {
    const baseline = effectiveScoringConfig();
    const reordered = {
      recommendation: {
        recencyTolerance: baseline.recommendation.recencyTolerance,
        threshold: baseline.recommendation.threshold,
        policyCode: baseline.recommendation.policyCode,
      },
      monitoredReleaseLimit: baseline.monitoredReleaseLimit,
      repository: {
        repo: baseline.repository.repo,
        owner: baseline.repository.owner,
      },
      schemaVersion: baseline.schemaVersion,
    } as ScoreEffectiveScoringConfig;

    assert.equal(
      scoreEffectiveScoringConfigDigest(reordered),
      scoreEffectiveScoringConfigDigest(baseline),
    );
    assert.deepEqual(
      scoreSourceIdentityForDb(emptyDatabase(), {
        codeRevision: 'canonical-revision',
        effectiveScoringConfig: reordered,
      }),
      scoreSourceIdentityForDb(emptyDatabase(), {
        codeRevision: 'canonical-revision',
        effectiveScoringConfig: baseline,
      }),
    );
  });

  it('rejects tampered runtime provenance in current schema manifests', () => {
    const identity = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'runtime-revision',
      effectiveScoringConfig: effectiveScoringConfig(),
    });
    assert.deepEqual(scoreSourceIdentityManifestProblems(identity), []);
    assert.match(
      scoreSourceIdentityManifestProblems({
        ...identity,
        effectiveScoringConfigDigest: '0'.repeat(64),
      }).join('\n'),
      /effectiveScoringConfigDigest does not match/,
    );
    assert.match(
      scoreSourceIdentityManifestProblems({
        ...identity,
        codeRevision: ' invalid revision ',
      }).join('\n'),
      /codeRevision must be a normalized/,
    );
  });

  it('semantically validates legacy schema 5 through 16 manifests while keeping schema 17 current', () => {
    const empty = scoreSourceIdentityForDb(emptyDatabase(), {
      codeRevision: 'current-revision',
      effectiveScoringConfig: effectiveScoringConfig(),
    });
    assert.equal(empty.schemaVersion, SCORE_SOURCE_IDENTITY_SCHEMA_VERSION);
    assert.deepEqual(scoreSourceIdentityManifestProblems(empty), []);

    const {
      codeRevision: _codeRevision,
      effectiveScoringConfig: _effectiveScoringConfig,
      effectiveScoringConfigDigest: _effectiveScoringConfigDigest,
      ...legacyBase
    } = empty;
    const legacyAuthoritySourceNames = [
      'repository_collaborator_permission_snapshots',
      'repository_collaborator_permission_rows',
      'approved_maintainer_roster_snapshots',
      'approved_maintainer_roster_entries',
    ] as const;
    const rawAuthoritySources = new Set([
      'issue_label_evidence_snapshots',
      'issue_label_evidence_rows',
      'repository_collaborator_permission_snapshots_v2',
      'repository_collaborator_permission_rows_v2',
      'signed_maintainer_roster_snapshots',
      'signed_maintainer_roster_entries',
      'closure_claim_source_snapshots',
      'closure_claim_candidates',
      'closure_claim_extraction_receipts',
      'closure_claim_extraction_receipt_members',
    ]);
    const withoutArtifactReceipts = empty.sources.filter(
      (source) => source.source !== 'release_artifact_receipts',
    );
    const withoutAdvisoryV2 = withoutArtifactReceipts.filter(
      (source) =>
        source.source !== 'advisory_snapshot_v2' &&
        source.source !== 'advisory_snapshot_v2_history' &&
        source.source !== 'advisory_snapshot_v2_rows',
    );
    const legacyBaseSources = withoutAdvisoryV2.filter(
      (source) => !rawAuthoritySources.has(source.source),
    );
    for (const schemaVersion of [5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16]) {
      const sources = schemaVersion === 16
        ? [...withoutArtifactReceipts]
        : schemaVersion >= 14
        ? [...withoutAdvisoryV2]
        : schemaVersion === 13
        ? withoutAdvisoryV2.filter(
            (source) =>
              source.source !== 'closure_claim_extraction_receipts' &&
              source.source !== 'closure_claim_extraction_receipt_members',
          )
        : schemaVersion >= 10
        ? withoutAdvisoryV2.filter(
            (source) =>
              source.source !== 'closure_claim_source_snapshots' &&
              source.source !== 'closure_claim_extraction_receipts' &&
              source.source !== 'closure_claim_extraction_receipt_members',
          )
        : [...legacyBaseSources];
      if (schemaVersion === 9) {
        const insertionIndex =
          sources.findIndex((source) => source.source === 'issue_label_events') + 1;
        sources.splice(
          insertionIndex,
          0,
          ...legacyAuthoritySourceNames.map((source) => ({
            source,
            count: 0,
            digest: '0'.repeat(64),
          })),
        );
      }
      if (schemaVersion < 7) {
        const advisorySnapshotIndex =
          sources.findIndex((source) => source.source === 'advisory_snapshot');
        sources.splice(advisorySnapshotIndex, 1);
      }
      const runtime = schemaVersion >= 8
        ? {
            codeRevision: empty.codeRevision,
            effectiveScoringConfig: empty.effectiveScoringConfig,
            effectiveScoringConfigDigest: empty.effectiveScoringConfigDigest,
          }
        : {};
      const legacy = {
        ...legacyBase,
        ...runtime,
        schemaVersion,
        rowCount: sources.reduce((sum, source) => sum + source.count, 0),
        sourceCount: sources.length,
        digest: scoreSourceIdentityManifestDigest(
          sources as any,
          schemaVersion,
          schemaVersion >= 8
            ? {
                codeRevision: empty.codeRevision,
                effectiveScoringConfig: empty.effectiveScoringConfig,
                effectiveScoringConfigDigest: empty.effectiveScoringConfigDigest,
              }
            : undefined,
        ),
        sources,
      };
      assert.deepEqual(scoreSourceIdentityManifestProblems(legacy), []);
      assert.match(
        scoreSourceIdentityManifestProblems({
          ...legacy,
          digest: '0'.repeat(64),
        }).join('\n'),
        /digest does not match/,
      );
    }
  });
});
