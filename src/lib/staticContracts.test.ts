import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { REC_THRESHOLD } from './score.ts';

const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

describe('static scoring/UI contracts', () => {
  it('does not hardcode a stale recommendation threshold in UI text', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.doesNotMatch(html, /newest eligible\s*(?:≥|>=)\s*7/i);
    assert.equal(REC_THRESHOLD, 5.5);
  });

  it('homepage install command only uses server-recommended releases', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /function pickRecommendedRelease\(rows\)[\s\S]*?rows\.find\(\(r\) => r\.recommended\) \?\? null;/);
    assert.doesNotMatch(html, /rows\.find\(\(r\) => r\.status === 'eligible' && r\.finalScore != null\)/);
  });

  it('score color helper keeps weak scores below caution threshold', () => {
    const html = readFileSync(join(root, 'public/index.html'), 'utf8');
    assert.match(html, /if \(n >= 5\.5\) return 'var\(--warn\)'/);
    assert.doesNotMatch(html, /if \(n >= 5\) return 'var\(--warn\)'/);
  });

  it('legacy public snapshot import requires explicit overwrite flag before loading app DB', () => {
    const script = readFileSync(join(root, 'scripts/import-public-snapshot.mjs'), 'utf8');
    assert.match(script, /--allow-overwrite-local-releases/);
    assert.doesNotMatch(script, /^import \{ db, setMeta \} from '\.\.\/src\/lib\/db\.ts';/m);
    assert.match(script, /await import\('\.\.\/src\/lib\/db\.ts'\)/);
  });
});
