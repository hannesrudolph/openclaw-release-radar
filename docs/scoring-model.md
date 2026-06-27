# Scoring Model

Current model: `evidence-v10-evidence-report`

The score answers one question:

> Should a user install this OpenClaw stable release right now?

It is not a raw issue count. The model combines hard gates, release survival, issue provenance, community breadth, fix reachability, release checks, and package artifact verification. Every score is written to `release_score_audits` with JSON inputs, components, issue evidence, and gate evidence.

Refresh and `npm run verify:score` both use the shared `releaseScoring` DB scoring pass. The verifier opens the database in read-only/query-only mode, recomputes the same install inputs and audit payloads from stored evidence, then fails if persisted release rows or score-audit rows drift. The same pass also writes the structured `components.explanation` payload used by the UI's "Why not 10?" panel, including prose plus machine-readable reason codes, metrics, buckets, and supporting issue references.

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

When scoring a historical release, it reconstructs the label set at that release's cutoff time. If no label timeline events were fetched for an issue at a historical cutoff, the scorer does not fall back to current labels; it scores that issue without label-derived overrides and records the missing timeline coverage in `gateEvidence.labelTimeline`. For the latest release, there is no historical cutoff yet, so current labels are used.

Audit rows include both effective labels and current labels where relevant, plus `labelSource` and `labelTimelineEventCount` for issue evidence.

## Release Fix Credit

A closed issue does not automatically count as fixed for a release.

Fix credit requires:

- GitHub closure reason is `COMPLETED`.
- The final GitHub close event is the `COMPLETED` close. Older close events do not count after reopen/reclose.
- A hard code proof exists:
  - closing PR is linked through GitHub closure/reference evidence or a high-confidence same-repo closure/fix proof comment, the PR is merged, and the PR merge commit is reachable from the release tag commit; or
  - a high-confidence closure/canonical comment names a fix/source commit, and that commit is reachable from the release tag commit.

Closed issues without a reachable merged PR or reachable named fix/source commit remain visible in audit evidence, but they do not reduce release risk.

Broad PR/commit mentions in comments are stored for audit context, but they do not reduce release risk. Comment-derived fix credit requires explicit closure/fix/provenance wording such as a maintainer/bot note identifying the merged PR or fix/source commit that closed, fixed, or proves the reported behavior is present in the release source.

The closure proof analyzer classifies every closed issue that is not counted as a fix for the scored release into one of these buckets:

- `fixed_in_release`: merged closing PR or named fix/source commit is reachable from this release tag.
- `fixed_after_release`: merged closing PR or named fix/source commit exists, but is not reachable from this release tag.
- `duplicate_to_open_canonical`: closure moved the report to a canonical issue that remains open.
- `duplicate_to_closed_canonical`: closure moved the report to a canonical issue that is also closed.
- `canonical_cycle_or_self_reference`: canonical reference loops back to the same issue or repeats.
- `duplicate_or_superseded`: closure comments or state show the issue moved under another tracker.
- `already_present_claim`: closure comment claims the behavior is already implemented, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
- `main_only_claim`: closure comment claims the fix exists on current main, but indicates the scored release may not contain it.
- `reporter_replaced`: reporter refiled, reopened, or replaced the issue under another issue number.
- `reporter_withdrawn`: reporter withdrew the report, asked maintainers to ignore it, or closed it for privacy/non-fix reasons.
- `reporter_self_closed`: reporter self-closed the issue without linked release fix proof or ongoing failure context.
- `no_code_proof`: closure exists, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
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

The release audit verifier checks both aggregate counts and proof shape, including full 40-character commit IDs, reachable/not-reachable commit arrays, and consistency between commit proof rows and their summary booleans.

Run the audit invariant verifier after refreshes:

```bash
npm run verify:local
npm run verify:live
npm run verify:score
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

## Inspecting Current Evidence

Do not hardcode a "current" score in docs. The current recommendation changes as GitHub issues, labels, releases, advisories, and package metadata change.

Use the live local API instead:

```bash
curl -s http://127.0.0.1:8787/api/public \
  | jq '.releases[0] | {tag, score, band, status, recommended, reason, explanation}'

curl -s http://127.0.0.1:8787/api/releases/v2026.6.10/review \
  | jq '{score: .local.score, explanation: .local.components.explanation, fix: .local.gateEvidence.fixProvenance.releaseFixCredit}'
```

`components.explanation` is the stable "Why not 10?" contract:

- `schemaVersion`: explanation contract version. Current value: `1`.
- `positives`: human-readable favorable evidence lines.
- `positiveDetails`: machine-readable entries aligned 1:1 with `positives`.
- `limits`: human-readable limiting evidence lines.
- `limitDetails`: machine-readable entries aligned 1:1 with `limits`.
- `verdict`: install-facing interpretation of the score.

Each detail entry has a stable `code`, matching `text`, and may include `metrics`, `buckets`, and `issueRefs`.

## Validation Commands

Use these before trusting a scoring change:

```bash
npm test
npm run typecheck
npm run build
npm run verify:ci
npm run verify:scripts
npm run verify:local
npm run verify:live
npm run analyze:closure-proofs -- v2026.6.10
curl http://127.0.0.1:8787/api/releases/v2026.6.10/review | jq
```
