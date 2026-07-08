import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';
import {
  APPEND_ONLY_TRIGGER_SPECS,
  IMMUTABLE_LEDGER_TABLES,
  REQUIRED_APPEND_ONLY_TRIGGERS,
  appendOnlyTriggerShape,
  unconditionalAbortTriggerShape,
  undeclaredAppendOnlyTriggerShapes,
} from '../../scripts/lib/database-schema-manifest.mjs';

function triggerRow(
  name: string,
  table: string,
  event: 'UPDATE' | 'DELETE',
  message: string,
) {
  return {
    name,
    tbl_name: table,
    sql: `
      CREATE TRIGGER ${name}
      BEFORE ${event} ON ${table}
      BEGIN
        SELECT RAISE(ABORT, '${message.replaceAll("'", "''")}');
      END
    `,
  };
}

describe('database schema manifest', () => {
  it('defines one immutable UPDATE and DELETE guard per canonical table', () => {
    assert.equal(IMMUTABLE_LEDGER_TABLES.length, 56);
    assert.equal(APPEND_ONLY_TRIGGER_SPECS.length, 112);
    assert.equal(REQUIRED_APPEND_ONLY_TRIGGERS.length, 112);
    assert.equal(new Set(IMMUTABLE_LEDGER_TABLES).size, 56);
    assert.equal(
      new Set(APPEND_ONLY_TRIGGER_SPECS.map(({ name }) => name)).size,
      112,
    );
    for (const table of IMMUTABLE_LEDGER_TABLES) {
      assert.deepEqual(
        APPEND_ONLY_TRIGGER_SPECS
          .filter((spec) => spec.table === table)
          .map((spec) => spec.event)
          .sort(),
        ['DELETE', 'UPDATE'],
      );
    }
  });

  it('requires release catalog capture receipt guards', () => {
    const table = 'release_catalog_capture_receipts';
    assert.ok(IMMUTABLE_LEDGER_TABLES.includes(table));
    assert.deepEqual(
      REQUIRED_APPEND_ONLY_TRIGGERS.filter(([, triggerTable]) =>
        triggerTable === table),
      [
        ['release_catalog_capture_receipts_no_update', table, 'UPDATE'],
        ['release_catalog_capture_receipts_no_delete', table, 'DELETE'],
      ],
    );
  });

  it('strictly parses canonical unconditional abort guards', () => {
    const row = triggerRow(
      'example_no_update',
      'example',
      'UPDATE',
      'example is append-only',
    );
    assert.deepEqual(unconditionalAbortTriggerShape(row), {
      name: 'example_no_update',
      table: 'example',
      event: 'UPDATE',
      message: 'example is append-only',
    });
    assert.deepEqual(appendOnlyTriggerShape(row), {
      name: 'example_no_update',
      table: 'example',
      event: 'UPDATE',
      message: 'example is append-only',
    });
  });

  it('rejects conditional, column-scoped, and multi-statement trigger SQL', () => {
    for (const sql of [
      `
        CREATE TRIGGER example_no_update
        BEFORE UPDATE OF value ON example
        BEGIN
          SELECT RAISE(ABORT, 'example is append-only');
        END
      `,
      `
        CREATE TRIGGER example_no_update
        BEFORE UPDATE ON example
        WHEN 0
        BEGIN
          SELECT RAISE(ABORT, 'example is append-only');
        END
      `,
      `
        CREATE TRIGGER example_no_update
        BEFORE UPDATE ON example
        BEGIN
          SELECT RAISE(ABORT, 'example is append-only');
          SELECT 1;
        END
      `,
    ]) {
      assert.equal(unconditionalAbortTriggerShape({
        name: 'example_no_update',
        tbl_name: 'example',
        sql,
      }), null);
    }
  });

  it('finds undeclared guard pairs without flagging singleton or conditional guards', () => {
    const undeclared = [
      triggerRow(
        'unknown_block_update',
        'unknown_ledger',
        'UPDATE',
        'updates are forbidden',
      ),
      triggerRow(
        'unknown_block_delete',
        'unknown_ledger',
        'DELETE',
        'deletes are forbidden',
      ),
      triggerRow(
        'mutable_singleton_no_delete',
        'mutable_singleton',
        'DELETE',
        'singleton cannot be deleted',
      ),
      {
        name: 'mutable_singleton_revision_guard',
        tbl_name: 'mutable_singleton',
        sql: `
          CREATE TRIGGER mutable_singleton_revision_guard
          BEFORE UPDATE ON mutable_singleton
          WHEN NEW.revision <> OLD.revision + 1
          BEGIN
            SELECT RAISE(ABORT, 'revision must advance once');
          END
        `,
      },
    ];
    assert.deepEqual(
      undeclaredAppendOnlyTriggerShapes(undeclared).map(({ name }) => name),
      ['unknown_block_update', 'unknown_block_delete'],
    );
  });
});
