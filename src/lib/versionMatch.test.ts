import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { compareVersions, isRangeParseable, matchesRange, firstPatchedVersion, stableDistance } from './versionMatch.ts';

describe('compareVersions', () => {
  it('component-wise numeric compare', () => {
    assert.equal(compareVersions('1.2.3', '1.2.3'), 0);
    assert.equal(compareVersions('1.2.3', '1.2.4'), -1);
    assert.equal(compareVersions('1.2.4', '1.2.3'), 1);
    assert.equal(compareVersions('2.0.0', '1.99.99'), 1);
  });

  it('CalVer (openclaw-style)', () => {
    assert.equal(compareVersions('2026.5.20', '2026.5.19'), 1);
    assert.equal(compareVersions('2026.5.3', '2026.5.20'), -1);
    assert.equal(compareVersions('2026.4.23', '2026.5.3'), -1);
  });

  it('strips leading v', () => {
    assert.equal(compareVersions('v1.2.3', '1.2.3'), 0);
    assert.equal(compareVersions('v2026.5.20', 'v2026.5.19'), 1);
  });

  it('different component count: missing parts treated as 0', () => {
    assert.equal(compareVersions('1.2', '1.2.0'), 0);
    assert.equal(compareVersions('2', '1.99.99'), 1);
  });

  it('prerelease tags rank below the base version', () => {
    assert.equal(compareVersions('1.2.3-alpha', '1.2.3'), -1);
    assert.equal(compareVersions('1.2.3', '1.2.3-beta'), 1);
    assert.equal(compareVersions('1.2.3-alpha', '1.2.3-beta'), -1);
  });
});

describe('matchesRange', () => {
  it('exact match without operator', () => {
    assert.equal(matchesRange('1.2.3', '1.2.3'), true);
    assert.equal(matchesRange('1.2.4', '1.2.3'), false);
  });

  it('strict less than', () => {
    assert.equal(matchesRange('1.2.2', '< 1.2.3'), true);
    assert.equal(matchesRange('1.2.3', '< 1.2.3'), false);
    assert.equal(matchesRange('1.2.4', '< 1.2.3'), false);
  });

  it('less or equal', () => {
    assert.equal(matchesRange('1.2.3', '<= 1.2.3'), true);
    assert.equal(matchesRange('1.2.4', '<= 1.2.3'), false);
  });

  it('strict greater + greater-or-equal', () => {
    assert.equal(matchesRange('1.2.4', '> 1.2.3'), true);
    assert.equal(matchesRange('1.2.3', '>= 1.2.3'), true);
    assert.equal(matchesRange('1.2.2', '>= 1.2.3'), false);
  });

  it('handles missing whitespace around operator', () => {
    assert.equal(matchesRange('2026.4.22', '<=2026.4.21'), false);
    assert.equal(matchesRange('2026.4.21', '<=2026.4.21'), true);
    assert.equal(matchesRange('2026.5.3', '<2026.4.23'), false);
    assert.equal(matchesRange('2026.4.22', '<2026.4.23'), true);
  });

  it('comma-separated AND range', () => {
    assert.equal(matchesRange('1.5.0', '>= 1.0.0, < 2.0.0'), true);
    assert.equal(matchesRange('2.0.0', '>= 1.0.0, < 2.0.0'), false);
    assert.equal(matchesRange('0.9.9', '>= 1.0.0, < 2.0.0'), false);
  });

  it('space-separated AND range (GitHub form)', () => {
    assert.equal(matchesRange('2026.4.12', '>= 2026.4.10 < 2026.4.14'), true);
    assert.equal(matchesRange('2026.4.14', '>= 2026.4.10 < 2026.4.14'), false);
    assert.equal(matchesRange('2026.4.9', '>= 2026.4.10 < 2026.4.14'), false);
  });

  it('openclaw real-world advisory ranges', () => {
    // From actual GHSA-r39h-4c2p-3jxp: "<2026.4.23"
    assert.equal(matchesRange('2026.4.22', '<2026.4.23'), true);
    assert.equal(matchesRange('2026.4.23', '<2026.4.23'), false);
    assert.equal(matchesRange('2026.5.20', '<2026.4.23'), false);
    // All our monitored 5.X releases are NOT vulnerable to 4.x-patched CVEs.
    for (const tag of ['2026.5.3', '2026.5.7', '2026.5.18', '2026.5.20']) {
      assert.equal(matchesRange(tag, '<2026.4.23'), false, `${tag} must not match <2026.4.23`);
    }
  });

  it('returns false on null / empty range', () => {
    assert.equal(matchesRange('1.2.3', null), false);
    assert.equal(matchesRange('1.2.3', ''), false);
    assert.equal(matchesRange('1.2.3', '   '), false);
  });

  it('returns false on malformed range while exposing parse failure', () => {
    assert.equal(matchesRange('1.2.3', '^1.0.0'), false);
    assert.equal(matchesRange('1.2.3', '~1.2.0'), false);
    assert.equal(isRangeParseable('^1.0.0'), false);
    assert.equal(isRangeParseable('~1.2.0'), false);
    assert.equal(isRangeParseable('>= 1.0.0, < 2.0.0'), true);
    assert.equal(isRangeParseable('>= 1.0.0 < 2.0.0'), true);
  });
});

describe('firstPatchedVersion', () => {
  it('bare version', () => {
    assert.equal(firstPatchedVersion('2026.4.23'), '2026.4.23');
  });
  it('takes the >= clause', () => {
    assert.equal(firstPatchedVersion('>= 2026.4.14'), '2026.4.14');
    assert.equal(firstPatchedVersion('>= 2026.4.10 < 2026.5'), '2026.4.10');
  });
  it('null / empty → null', () => {
    assert.equal(firstPatchedVersion(null), null);
    assert.equal(firstPatchedVersion(''), null);
  });
});

describe('stableDistance', () => {
  const stables = ['v2026.5.27', 'v2026.5.26', 'v2026.5.22', 'v2026.5.20']; // newest first

  it('0 for the newest still-affected version (right before the patch)', () => {
    // patched in 5.27 → nothing sits between 5.26 and the patch
    assert.equal(stableDistance('v2026.5.26', '2026.5.27', stables), 0);
  });

  it('counts stables between the version and the patch', () => {
    assert.equal(stableDistance('v2026.5.22', '2026.5.27', stables), 1); // 5.26 between
    assert.equal(stableDistance('v2026.5.20', '2026.5.27', stables), 2); // 5.22, 5.26 between
  });

  it('uses the patch from a >= range', () => {
    assert.equal(stableDistance('v2026.5.22', '>= 2026.5.27', stables), 1);
  });

  it('0 when the patch is unparseable (conservative full weight)', () => {
    assert.equal(stableDistance('v2026.5.20', null, stables), 0);
  });
});
