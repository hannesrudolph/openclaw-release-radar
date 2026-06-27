# Scoring Model

Current model: `evidence-v10-evidence-report`

The score answers one question:

> Should a user install this OpenClaw stable release right now?

It is not a raw issue count. The model combines hard gates, release survival, issue provenance, community breadth, fix reachability, release checks, and package artifact verification. Every score is written to `release_score_audits` with JSON inputs, components, issue evidence, and gate evidence.

## Hard Gates

These override the normal 0-10 score:

- `wait`: release is younger than the settle window.
- `skip-cve`: medium-or-higher advisory affects the release.
- `skip-hotfix`: release was superseded quickly or by a hotfix successor.

## Score Components

The normal score starts from a base value, then applies bounded components:

- `verifiedDebt`: release-local field/community-confirmed blocker risk.
- `carryoverDebt`: inherited source/static/current open risk. This is capped.
- `staleDebt`: low-confidence, stale, needs-info, or weak evidence risk. This is heavily capped.
- `coverage`: penalty if raw issues exist but classification coverage is incomplete.
- `survival`: reward for standing as latest/current stable without hotfix replacement.
- `shakeout`: small reward for beta/prerelease bake time.
- `regression`: reach-weighted balance of field-visible opened vs fixed bugs.
- `breaking`: release-note breaking-change penalty.
- `releaseVerification`: capped confidence from release commit checks.
- `artifactVerification`: capped confidence from npm package integrity plus release evidence report verification.

## Issue Evidence Rules

Issue evidence is cluster-aware:

- Duplicate clusters are deduplicated.
- Independent human reporters increase field/community confidence.
- Unique human commenters increase field/community confidence.
- Reactions only provide a small weight lift; they never make a source-only issue verified.
- Bot-only activity does not establish field evidence.
- Raw comment volume alone does not establish field evidence.

The model deliberately separates:

- field-confirmed breakage
- source/static risk
- weak or stale issue evidence
- closed issues not counted for this release
- reachable fixes

## Label Timing

Current labels can be misleading because labels may be added or removed after a release. The model persists GitHub `LabeledEvent` and `UnlabeledEvent` timeline items in `issue_label_events`.

When scoring a historical release, it reconstructs the label set at that release's cutoff time. For the latest release, the cutoff is current time, so current labels are used.

Audit rows include both effective labels and current labels where relevant.

## Release Fix Credit

A closed issue does not automatically count as fixed for a release.

Fix credit requires:

- GitHub closure reason is `COMPLETED`.
- The final GitHub close event is the `COMPLETED` close. Older close events do not count after reopen/reclose.
- Closing PR is linked through GitHub closure/reference evidence or a high-confidence same-repo closure/fix proof comment.
- PR is merged.
- PR merge commit is reachable from the release tag commit.

Closed issues without a merged linked PR reachable from the release tag remain visible in audit evidence, but they do not reduce release risk.

Broad PR mentions in comments are stored for audit context, but they do not reduce release risk. Comment-derived fix credit requires explicit closure/fix wording such as a maintainer/bot note identifying the merged PR that closed or fixed the report.

The closure proof analyzer classifies every closed issue that is not counted as a fix for the scored release into one of these buckets:

- `fixed_in_release`: merged closing PR is reachable from this release tag.
- `fixed_after_release`: merged closing PR exists, but is not reachable from this release tag.
- `duplicate_to_open_canonical`: closure moved the report to a canonical issue that remains open.
- `duplicate_to_closed_canonical`: closure moved the report to a canonical issue that is also closed.
- `canonical_cycle_or_self_reference`: canonical reference loops back to the same issue or repeats.
- `duplicate_or_superseded`: closure comments or state show the issue moved under another tracker.
- `already_present_claim`: closure comment claims the behavior is already implemented, but no linked merged PR is reachable from the scored release tag.
- `main_only_claim`: closure comment claims the fix exists on current main, but indicates the scored release may not contain it.
- `no_code_proof`: closure exists, but no linked merged PR is reachable from the scored release tag.
- `no_timeline_event`: issue has `closed_at`, but no fetched GitHub close event.
- `non_bug_neutral`: closed item is not negative bug evidence.
- `not_planned`: closure reason or comment says the issue was not planned/actionable.

Only `fixed_in_release` receives fix credit. Other buckets preserve the closure context in the audit, but they do not reduce release risk for this tag.

The API exposes a coherent `releaseFixCredit` object:

- `countedClosedCount`: closed issues counted as release fixes.
- `notCountedClosedCount`: closed issues in the release window not counted as release fixes.
- `analyzedClosedCount`: total closed issues analyzed for the release window.

The invariant is `countedClosedCount + notCountedClosedCount = analyzedClosedCount`.

After closure proof analysis, the same `closureProof` and `releaseFixCredit` payload is persisted back into `release_score_audits.gate_evidence_json` and exposed through `/review` and `/comparison`.

Refresh recomputes closure proof automatically for monitored releases. The manual command below reruns the same proof pass for a specific tag when debugging.

Run the audit invariant verifier after refreshes:

```bash
npm run verify:release-audit
npm run ui:smoke
```

## Release Checks

The model reads the release tag commit's GitHub `statusCheckRollup`.

- Successful checks add a small capped confidence bump.
- Pending checks add a small penalty.
- Failed checks add a larger penalty.
- Missing check data is neutral.

The audit payload stores check state, counts, and check contexts.

## Artifact Verification

Release notes are parsed for:

- npm package URL
- registry tarball URL
- package integrity
- release SHA
- full release CI report URL

The model verifies npm registry metadata against the release notes:

- registry version
- tarball URL
- integrity

It also checks whether the linked release evidence report exists and is non-empty. A verified npm artifact adds confidence. A missing linked evidence report offsets part of that confidence instead of being treated like an npm integrity mismatch.

For `v2026.6.10`, npm metadata matches the release notes and release SHA, but the linked release evidence report currently returns `404`, so artifact confidence is partial.

## Current `v2026.6.10` Snapshot

As of the latest local refresh:

- Score: `7.5`
- Band: `ok`
- Model: `evidence-v10-evidence-report`
- Reason: `latest - stood 3.7d with no hotfix, 518 source/carryover risk, net-opening field-visible bugs, 4 release checks passed, npm artifact verified, release evidence report missing, 2 betas baked`

Key component values:

- `verifiedDebt`: `0`
- `carryoverDebt`: `-0.6`
- `staleDebt`: `-0.2`
- `survival`: `0.4`
- `shakeout`: `0.4`
- `regression`: `-0.3`
- `releaseVerification`: `0.3`
- `artifactVerification`: `0.1`

## Validation Commands

Use these before trusting a scoring change:

```bash
npm test
npm run typecheck
npm run build
npx tsx scripts/verify-new-scoring.mjs
npm run analyze:closure-proofs -- v2026.6.10
curl http://127.0.0.1:8787/api/releases/v2026.6.10/review | jq
```
