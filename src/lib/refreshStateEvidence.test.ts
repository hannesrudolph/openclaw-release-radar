import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';

function dbPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), `radar-refresh-state-${name}-`)), 'radar.db');
}

describe('refresh state evidence persistence', () => {
  it('persists commit references fetched with issue state evidence', async () => {
    const path = dbPath('commit-reference');
    process.env.DB_PATH = path;
    process.env.REFRESH_MINUTES = '0';
    const refresh = await import(`./refresh.ts?refresh-state-${Date.now()}-${Math.random()}`);
    const db = await import('./db.ts');
    try {
      refresh.__refreshTest.persistIssueStateEvidence({
        issueNumber: 123,
        closureEvents: [],
        reopenEvents: [],
        prLinks: [],
        pullRequests: [],
        commitReferences: [{
          issueNumber: 123,
          eventId: 'ref-123',
          commitOid: 'a'.repeat(40),
          commitMessageHeadline: 'fix gateway delivery',
          commitRepositoryOwner: 'openclaw',
          commitRepositoryName: 'openclaw',
          commitRepositoryNameWithOwner: 'openclaw/openclaw',
          isCrossRepository: false,
          isDirectReference: true,
          referencedAt: '2026-06-30T00:00:00Z',
          actorLogin: 'maintainer',
          raw: { id: 'ref-123' },
        }],
      });

      const row = db.db.prepare(`SELECT * FROM issue_commit_references WHERE event_id=?`).get('ref-123') as any;
      assert.equal(row.issue_number, 123);
      assert.equal(row.commit_oid, 'a'.repeat(40));
      assert.equal(row.commit_message_headline, 'fix gateway delivery');
      assert.equal(row.commit_repository_name_with_owner, 'openclaw/openclaw');
      assert.equal(row.is_cross_repository, 0);
      assert.equal(row.is_direct_reference, 1);
      assert.equal(row.referenced_at, '2026-06-30T00:00:00Z');
      assert.ok(Date.parse(row.fetched_at));
    } finally {
      try { db.db.close(); } catch { /* already closed */ }
      rmSync(dirname(path), { recursive: true, force: true });
    }
  });
});
