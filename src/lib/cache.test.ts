import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { getCached, invalidateCache, setCached } from './cache.ts';

describe('public API cache', () => {
  it('returns cached data only for the matching freshness key', () => {
    invalidateCache();
    const payload = { updatedAt: 't1' };
    setCached(payload, 't1');

    assert.equal(getCached('t1'), payload);
    assert.equal(getCached('t2'), null);
    assert.equal(getCached(null), null);
  });

  it('can cache null-key data explicitly', () => {
    invalidateCache();
    const payload = { updatedAt: null };
    setCached(payload, null);

    assert.equal(getCached(null), payload);
    assert.equal(getCached('t1'), null);
  });
});
