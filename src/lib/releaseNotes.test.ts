import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import {
  parseReleaseNotes,
  computeBetaCount,
  computeHoursToNextRelease,
  computeAggregateBreaking,
} from './releaseNotes.ts';

describe('parseReleaseNotes', () => {
  it('returns zeros for null / empty / whitespace body', () => {
    for (const body of [null, undefined, '', '   ', '\n\n']) {
      const r = parseReleaseNotes(body);
      assert.equal(r.breakingCount, 0);
      assert.equal(r.fixesCount, 0);
      assert.equal(r.changesCount, 0);
      assert.equal(r.highlightsCount, 0);
      assert.equal(r.prRefsCount, 0);
    }
  });

  it('counts bullets only within their section', () => {
    const body = [
      '## 2026.5.22',
      '',
      '### Changes',
      '- one',
      '- two',
      '- three',
      '',
      '### Fixes',
      '- a',
      '- b',
      '',
      '### Highlights',
      '- highlighted thing',
      '',
      '### Breaking',
      '- broke something',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.changesCount, 3);
    assert.equal(r.fixesCount, 2);
    assert.equal(r.highlightsCount, 1);
    assert.equal(r.breakingCount, 1);
  });

  it('ignores nested sub-bullets (they modify the parent, not new items)', () => {
    const body = [
      '### Fixes',
      '- top-level fix',
      '  - sub-detail',
      '  - another sub-detail',
      '- another top-level fix',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 2);
  });

  it('handles missing sections by reporting zero', () => {
    const body = '### Fixes\n- only fixes here';
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 1);
    assert.equal(r.changesCount, 0);
    assert.equal(r.breakingCount, 0);
    assert.equal(r.highlightsCount, 0);
  });

  it('is case-insensitive on section names', () => {
    const body = '### BREAKING\n- x\n### fixes\n- y';
    const r = parseReleaseNotes(body);
    assert.equal(r.breakingCount, 1);
    assert.equal(r.fixesCount, 1);
  });

  it('ignores unknown sections without crashing', () => {
    const body = '### Random Stuff\n- a\n- b\n### Fixes\n- real fix';
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 1);
  });

  it('dedupes PR refs across bullets', () => {
    const body = [
      '### Changes',
      '- one (#12345)',
      '- two (#67890)',
      '### Fixes',
      '- repeat of (#12345) in a different section',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.prRefsCount, 2);
  });

  it('counts PR refs with 2+ digits, ignores single-digit "#1"', () => {
    const body = '### Changes\n- top #1 priority\n- fix (#42) and #999';
    const r = parseReleaseNotes(body);
    assert.equal(r.prRefsCount, 2); // 42 and 999, not 1
  });

  it('counts PR refs anywhere in body, not just inside sections', () => {
    const body = 'preamble #11111\n### Fixes\n- something (#22222)';
    const r = parseReleaseNotes(body);
    assert.equal(r.prRefsCount, 2);
  });

  it('handles Windows-style CRLF line endings', () => {
    const body = '### Fixes\r\n- a\r\n- b\r\n### Changes\r\n- c';
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 2);
    assert.equal(r.changesCount, 1);
  });

  it('survives malformed bullets (no space after dash)', () => {
    const body = '### Fixes\n-no-space\n- real fix';
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 1);
  });

  it('recognises h4 sections (####) the same as h3', () => {
    // openclaw v2026.5.18 wraps everything in `### Detailed ... Changes` and
    // puts the real buckets at h4 level.
    const body = [
      '### Detailed 2026.5.18 Changes',
      '',
      '#### Changes',
      '- change one',
      '- change two',
      '',
      '#### Fixes',
      '- fix one',
      '- fix two',
      '- fix three',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.changesCount, 2);
    assert.equal(r.fixesCount, 3);
  });

  it('treats h3 and h4 buckets with the same name as one bucket (totals merge)', () => {
    // Hypothetical: ### Fixes (early bullets) + #### Fixes deeper.
    // We count all fix-bullets — easier to explain than counting only the
    // first-occurrence level.
    const body = [
      '### Fixes',
      '- early fix',
      '',
      '### Detailed list',
      '#### Fixes',
      '- detailed fix one',
      '- detailed fix two',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 3);
  });

  it('ignores h2 (## …) and h5+ headings', () => {
    const body = [
      '## 2026.5.22',
      '- not a section bullet (no h3/h4 yet)',
      '##### Sub-sub-section',
      '- also ignored',
      '### Fixes',
      '- real fix',
    ].join('\n');
    const r = parseReleaseNotes(body);
    assert.equal(r.fixesCount, 1);
  });
});

describe('computeBetaCount', () => {
  const releases = [
    { tag: 'v2026.5.19',         published_at: '2026-05-20T20:20:53Z', prerelease: false },
    { tag: 'v2026.5.19-beta.2',  published_at: '2026-05-19T21:12:37Z', prerelease: true  },
    { tag: 'v2026.5.19-alpha.1', published_at: '2026-05-20T00:50:52Z', prerelease: true  },
    { tag: 'v2026.5.19-beta.1',  published_at: '2026-05-18T22:58:13Z', prerelease: true  },
    { tag: 'v2026.5.18',         published_at: '2026-05-18T18:54:22Z', prerelease: false },
    { tag: 'v2026.5.18-beta.1',  published_at: '2026-05-18T16:13:00Z', prerelease: true  },
  ];

  it('counts prereleases between this stable and the previous stable', () => {
    assert.equal(computeBetaCount(releases, 'v2026.5.19'), 3);
    assert.equal(computeBetaCount(releases, 'v2026.5.18'), 1);
  });

  it('returns 0 when the target is itself a prerelease', () => {
    assert.equal(computeBetaCount(releases, 'v2026.5.19-beta.1'), 0);
  });

  it('returns 0 when the target is not in the list', () => {
    assert.equal(computeBetaCount(releases, 'v9999.0.0'), 0);
  });
});

describe('computeHoursToNextRelease', () => {
  const releases = [
    { tag: 'newest', published_at: '2026-05-24T01:12:56Z' },
    { tag: 'mid',    published_at: '2026-05-24T00:12:56Z' }, // 1h before newest
    { tag: 'old',    published_at: '2026-05-23T01:12:56Z' }, // 23h before mid
  ];

  it('returns hours from this release to the next newer one', () => {
    assert.equal(computeHoursToNextRelease(releases, 'mid'), 1);
    assert.equal(computeHoursToNextRelease(releases, 'old'), 23);
  });

  it('returns null for the newest release (no successor)', () => {
    assert.equal(computeHoursToNextRelease(releases, 'newest'), null);
  });

  it('returns null when the target is unknown', () => {
    assert.equal(computeHoursToNextRelease(releases, '???'), null);
  });

  it('returns null when timestamps are missing', () => {
    const r = [
      { tag: 'a', published_at: null },
      { tag: 'b', published_at: '2026-01-01T00:00:00Z' },
    ];
    assert.equal(computeHoursToNextRelease(r, 'b'), null);
  });
});

describe('computeAggregateBreaking', () => {
  // Fixture mirrors a realistic openclaw window: two stables, each preceded by a
  // beta chain of varying length. breakingCount per row simulates the post-parse
  // state (some bullets in betas, none in stables — the exact blind spot we
  // close).
  //
  //  newest                              older
  //  ┌──────────── v5.19 chain ─────────┐  ┌────── v5.18 chain ─────┐
  //  v5.19    beta.2    beta.1    alpha.1    v5.18    beta.1
  //  own=0    own=2     own=0     own=1      own=0    own=0
  //
  // Expected aggregate for v5.19 = 0 (own) + 2 + 0 + 1 = 3
  // Expected aggregate for v5.18 = 0 (own) + 0 = 0
  const releases = [
    { tag: 'v2026.5.19',         published_at: '2026-05-20T20:20:53Z', prerelease: false, breakingCount: 0 },
    { tag: 'v2026.5.19-beta.2',  published_at: '2026-05-19T21:12:37Z', prerelease: true,  breakingCount: 2 },
    { tag: 'v2026.5.19-alpha.1', published_at: '2026-05-20T00:50:52Z', prerelease: true,  breakingCount: 0 },
    { tag: 'v2026.5.19-beta.1',  published_at: '2026-05-18T22:58:13Z', prerelease: true,  breakingCount: 1 },
    { tag: 'v2026.5.18',         published_at: '2026-05-18T18:54:22Z', prerelease: false, breakingCount: 0 },
    { tag: 'v2026.5.18-beta.1',  published_at: '2026-05-18T16:13:00Z', prerelease: true,  breakingCount: 0 },
  ];

  it('sums own + every preceding beta until the next stable boundary', () => {
    // The exact "BlueBubbles" scenario: stable's own body says nothing, but its
    // beta chain documents the breaking change.
    assert.equal(computeAggregateBreaking(releases, 'v2026.5.19'), 3);
  });

  it('returns just own count when the preceding chain has no breaking bullets', () => {
    assert.equal(computeAggregateBreaking(releases, 'v2026.5.18'), 0);
  });

  it('stops at the next stable boundary — does not bleed into older chains', () => {
    // Inject a fresh stable with own=0 followed by a single beta=4, then the
    // already-defined v5.18 chain. Aggregate for the new stable must be 4,
    // NOT 4 + everything below.
    const r = [
      { tag: 'fresh',         published_at: '2026-05-25T00:00:00Z', prerelease: false, breakingCount: 0 },
      { tag: 'fresh-beta.1',  published_at: '2026-05-24T23:00:00Z', prerelease: true,  breakingCount: 4 },
      ...releases, // v5.19 chain with breaking=3 underneath
    ];
    assert.equal(computeAggregateBreaking(r, 'fresh'), 4);
  });

  it('returns own breakingCount for a prerelease target (no forward walk)', () => {
    // Policy is symmetric with computeBetaCount: prerelease aggregates are not
    // meaningful — the prerelease IS one of the bullets, not the rollup. We
    // return its own count so callers can still distinguish "this beta had a
    // breaking change" from "this beta had none".
    assert.equal(computeAggregateBreaking(releases, 'v2026.5.19-beta.2'), 2);
    assert.equal(computeAggregateBreaking(releases, 'v2026.5.19-alpha.1'), 0);
  });

  it('returns 0 when the target tag is not in the list', () => {
    assert.equal(computeAggregateBreaking(releases, 'v9999.0.0'), 0);
  });

  it('handles multiple stables each with their own chain — only nearest chain counts per target', () => {
    // Three stables each preceded by two betas. Each stable should report only
    // its own chain's sum, no cross-contamination.
    const r = [
      { tag: 'S3',  published_at: '2026-06-03T00:00:00Z', prerelease: false, breakingCount: 1 },
      { tag: 'b3a', published_at: '2026-06-02T00:00:00Z', prerelease: true,  breakingCount: 2 },
      { tag: 'b3b', published_at: '2026-06-01T00:00:00Z', prerelease: true,  breakingCount: 0 },
      { tag: 'S2',  published_at: '2026-05-30T00:00:00Z', prerelease: false, breakingCount: 0 },
      { tag: 'b2a', published_at: '2026-05-29T00:00:00Z', prerelease: true,  breakingCount: 5 },
      { tag: 'b2b', published_at: '2026-05-28T00:00:00Z', prerelease: true,  breakingCount: 0 },
      { tag: 'S1',  published_at: '2026-05-25T00:00:00Z', prerelease: false, breakingCount: 7 },
      { tag: 'b1a', published_at: '2026-05-24T00:00:00Z', prerelease: true,  breakingCount: 3 },
      { tag: 'b1b', published_at: '2026-05-23T00:00:00Z', prerelease: true,  breakingCount: 0 },
    ];
    assert.equal(computeAggregateBreaking(r, 'S3'), 1 + 2 + 0);  // own + b3a + b3b
    assert.equal(computeAggregateBreaking(r, 'S2'), 0 + 5 + 0);  // own + b2a + b2b
    assert.equal(computeAggregateBreaking(r, 'S1'), 7 + 3 + 0);  // own + b1a + b1b
  });
});
