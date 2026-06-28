import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { releaseLabelCutoff } from './labelCutoff.ts';

describe('releaseLabelCutoff', () => {
  it('uses stable-to-stable hours, not beta/next-release hours', () => {
    const cutoff = releaseLabelCutoff({
      published_at: '2026-06-01T00:00:00Z',
      hours_to_next_stable: 240,
    });
    assert.equal(cutoff, '2026-06-11T00:00:00.000Z');
  });

  it('uses score time for latest releases without a stable successor', () => {
    assert.equal(releaseLabelCutoff({
      published_at: '2026-06-01T00:00:00Z',
      hours_to_next_stable: null,
    }, Date.parse('2026-06-28T12:00:00Z')), '2026-06-28T12:00:00.000Z');
  });

  it('returns null for latest releases when score time is unavailable', () => {
    assert.equal(releaseLabelCutoff({
      published_at: '2026-06-01T00:00:00Z',
      hours_to_next_stable: null,
    }), null);
  });

  it('returns null for malformed release timestamps', () => {
    assert.equal(releaseLabelCutoff({
      published_at: 'not-a-date',
      hours_to_next_stable: 24,
    }), null);
  });
});
