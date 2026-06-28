# Scoring Model

Current model: `evidence-v13-effective-closure-risk`

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
- `closureRisk`: closed issue evidence that is not credited as fixed in this release and remains unresolved for this tag. This is capped and does not score non-bug, reporter-withdrawn, or concretely non-actionable closures.
- `coverage`: penalty if raw issues exist but classification coverage is incomplete.
- `survival`: reward for standing as latest/current stable without hotfix replacement.
- `shakeout`: small reward for beta/prerelease bake time.
- `regression`: reach-weighted balance of field-visible opened vs fixed bugs.
- `breaking`: release-note breaking-change penalty.
- `releaseVerification`: capped confidence from release commit checks.
- `artifactVerification`: capped confidence from npm package integrity plus release evidence report verification.

Still-open release-local reports are not counted again in the opened-vs-fixed regression balance; they already score as active open debt. The regression component uses field-visible reports opened during the release window that are no longer open, plus verified fixes, so a single unresolved report does not lower the score twice.

When unresolved closed-release risk is heavy, the model also applies a score ceiling of `7.9`. This prevents CI/artifact/survival bonuses from making a release look `solid` while many closed-window issues are known not to be fixed in the tag, moved to open canonicals, or still unsupported by release proof.

## Issue Evidence Rules

Issue evidence is cluster-aware:

- Duplicate clusters are deduplicated globally across debt tiers.
- A duplicate cluster only counts as release-local when every report in that cluster is release-local; fresh duplicate reports can add field breadth to an older bug, but they do not turn that older carryover bug into a new release-local blocker.
- Independent human reporters increase field/community confidence.
- Unique human commenters increase field/community confidence. Refresh cursor-paginates issue comments until exhausted, so commenter counts and comment-derived fix proof are not capped to the most recent page.
- Reactions only provide a small weight lift; they never make a source-only issue verified.
- Bot-only activity does not establish field evidence.
- Raw comment volume alone does not establish field evidence.
- `impact:security` alone is treated as a noisy keyword-stamped label; security/design dampening requires the explicit `security` label or other direct evidence.

The model deliberately separates:

- field-confirmed breakage
- source/static risk
- weak or stale issue evidence
- incomplete classification coverage
- unresolved closed issues not counted for this release
- reachable fixes

Issue evidence stores both `rawClassification` from the persisted classifier row and effective `classification` after deterministic title/label overrides. When those differ, `classificationDiff` records the changed fields so reviewers can see whether a score came from the LLM row or a rule-based override.

Debt evidence also records `installImpactClass` and `installImpactMultiplier`, so damped provider/security/product-debt risks are auditable in the score explanation instead of being hidden inside the final weight.

If raw attributed issues exist without current classifications, the score explanation includes `incomplete_classification_coverage` with raw/classified counts, the missing count, the evidence-coverage ratio, the capped penalty, and example unclassified issue references when available. This makes coverage penalties explicit instead of hiding them inside the final score.

## Issue Open Intervals

Release attribution is based on issue open intervals, not a single created-to-final-closed span.

The initial open interval starts at `issues.created_at` and ends at the first fetched GitHub close event after creation. Each fetched `ReopenedEvent` starts another open interval, ending at the next fetched close event. If timeline evidence is missing, the scorer falls back to `issues.closed_at` rather than treating sparse history as open forever.

An issue is attributed to a release only when one of those open intervals overlaps the release's stable-to-stable reign window. This prevents reports that were already closed before a release from counting against that release merely because they were reopened later.

## Label Timing

Current labels can be misleading because labels may be added or removed after a release. The model persists GitHub `LabeledEvent` and `UnlabeledEvent` timeline items in `issue_label_events`.

Refresh fetches label timelines for every issue that overlaps the monitored release window, even if the issue no longer has current labels. Label timeline GraphQL connections are cursor-paginated until exhausted.

When scoring a historical release, it reconstructs the label set at that release's cutoff time. If no label timeline events were fetched for an issue at a historical cutoff, the scorer does not fall back to current labels; it scores that issue without label-derived overrides and records the missing timeline coverage in `gateEvidence.labelTimeline`.

For the latest release, the cutoff is the exact score timestamp. Refresh and `backfill:issue-state-events` persist current-label snapshots in `issue_label_snapshots`; when a latest-release issue lacks label timeline events, the scorer uses the newest snapshot at or before the score timestamp. This keeps the latest score audit reproducible instead of letting later label edits mutate past evidence.

Audit rows include both effective labels and current labels where relevant, plus `labelSource` and `labelTimelineEventCount` for issue evidence. `gateEvidence.labelTimeline` separates `current`, `timeline`, `snapshot`, and `missing_timeline` sources.
`gateEvidence.labelTimeline.schemaVersion` is the label-timeline coverage contract version. Current value: `1`.
`gateEvidence.schemaVersion` is the top-level gate evidence contract version. Current value: `1`.

## Release Fix Credit

A closed issue does not automatically count as fixed for a release.

Fix credit requires:

- GitHub closure reason is `COMPLETED`.
- The final GitHub close event is the `COMPLETED` close. Older close events do not count after reopen/reclose.
- A hard code proof exists:
  - closing PR is linked through GitHub closure/reference evidence or a high-confidence same-repo closure/fix proof comment, the PR is merged, and the PR merge commit is reachable from the release tag commit; or
  - a high-confidence closure/canonical comment names a fix/source commit, and that commit is reachable from the release tag commit; or
  - when no stronger PR, closure-commit, or trusted-comment commit proof exists, a same-repo direct GitHub `ReferencedEvent` commit with fix-shaped wording is reachable from the release tag commit.

Closed issues without a reachable merged PR or reachable named fix/source commit remain visible in audit evidence, but they do not reduce release risk.

Reachability has three states: `reachable`, `not_reachable`, and `unknown`. `not_reachable` is only used when Git can prove exact non-ancestry with `merge-base --is-ancestor` exit status `1`. Missing release commits, missing PR merge commits, unavailable objects, and Git errors are stored as `unknown`; they never receive fix credit and remain auditable instead of being collapsed into proof that the fix is absent.

Broad PR/commit mentions in comments are stored for audit context, but they do not reduce release risk. Comment-derived fix credit requires explicit closure/fix/provenance wording from a trusted source, such as a maintainer or the known ClawSweeper reviewer account, identifying the merged PR or fix/source commit that closed, fixed, or proves the reported behavior is present in the release source.

GitHub `ReferencedEvent` commit references are stored separately from closure events. Fork/cross-repository references are audit context only. Same-repo direct references are used only as fallback commit proof, and only when the commit headline is fix-shaped and the reference happened no later than the final close timestamp tolerance.

The closure proof analyzer classifies every closed issue that is not counted as a fix for the scored release into one of these buckets:

- `fixed_in_release`: merged closing PR or named fix/source commit is reachable from this release tag.
- `fixed_after_release`: merged closing PR or named fix/source commit exists, but is not reachable from this release tag.
- `fixed_in_later_release`: merged closing PR or named fix/source commit is not reachable from this release tag, but is reachable from a later scored stable release.
- `fixed_not_in_scored_releases`: merged closing PR or named fix/source commit exists, but no scored stable release currently contains it.
- `fixed_after_latest_release`: merged closing PR or named fix/source commit exists after the latest scored stable release, so no scored stable can contain it yet.
- `fixed_skipped_by_later_releases`: merged closing PR or named fix/source commit predates at least one later scored stable release, but no scored stable contains it.
- `duplicate_to_fixed_in_release`: closure moved the report to a canonical issue or canonical fix/source commit that is reachable from this release tag.
- `duplicate_to_open_canonical`: closure moved the report to a canonical issue that remains open.
- `duplicate_to_closed_canonical`: closure moved the report to a canonical issue that is also closed.
- `duplicate_to_non_actionable_canonical`: closure moved the report to a canonical issue that closed as non-actionable or non-bug evidence.
- `duplicate_to_known_not_in_release_canonical`: closure moved the report to a canonical issue whose terminal proof is known not to be in this release tag.
- `duplicate_to_open_pr_canonical`: closure moved the report to a canonical issue that is closed, but its terminal proof still points to open PR/canonical risk.
- `duplicate_to_unverified_closed_canonical`: closure moved the report to a canonical issue that is closed, but terminal proof does not establish release resolution.
- `duplicate_to_closed_canonical_missing_proof`: closure moved the report to a canonical issue that is closed, but the audit has no terminal closure proof for the canonical issue.
- `duplicate_to_fixed_after_release`: closure moved the report to a canonical issue whose fix proof is not reachable from this release tag, including terminal canonical proof found in a later release audit.
- `superseded_to_open_pr`: trusted close-time closure context moved the report to a referenced PR that remains open and unmerged.
- `duplicate_with_open_pr_context`: the issue is closed as duplicate/superseded and related open PR references exist, but no trusted close-time closure note marks those PRs as canonical.
- `canonical_cycle_or_self_reference`: canonical reference loops back to the same issue or repeats.
- `duplicate_or_superseded`: closure comments or state show the issue moved under another tracker.
- `already_present_claim`: closure comment claims the behavior is already implemented, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
- `admin_not_planned_unverified`: a negative report was closed with GitHub `NOT_PLANNED`, but no reachable release fix proof or concrete close-time non-actionable rationale was found.
- `not_planned_with_release_fix_proof`: a negative report was closed with GitHub `NOT_PLANNED`, but trusted release-reachable fix proof exists. It resolves closure risk without direct GitHub fix-credit.
- `not_planned_fixed_after_release`: a negative report was closed with GitHub `NOT_PLANNED`, and trusted fix proof exists only after the scored release tag.
- `not_planned_with_open_pr_context`: a negative report was closed with GitHub `NOT_PLANNED` while related open PR context still exists.
- `not_planned_linked_pr_not_merged`: a negative report was closed with GitHub `NOT_PLANNED` and a linked closing PR is not merged or has unknown merge state.
- `not_planned_related_pr_without_release_fix`: a negative report was closed with GitHub `NOT_PLANNED` and related PR references exist, but none is release-fix proof for the scored tag.
- `main_only_claim`: closure comment claims the fix exists on current main, but indicates the scored release may not contain it.
- `reporter_replaced`: reporter refiled, reopened, or replaced the issue under another issue number.
- `reporter_withdrawn`: reporter withdrew the report, asked maintainers to ignore it, or closed it for privacy/non-fix reasons.
- `reporter_self_closed`: reporter self-closed the issue without linked release fix proof or ongoing failure context.
- `no_code_proof`: closure exists, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
- `linked_closing_pr_reachability_unknown`: a merged GitHub closing PR link exists, but release-tag reachability is missing or unknown.
- `linked_closing_pr_not_merged`: a GitHub closing PR link exists, but the PR is not merged or its merge state is unknown.
- `linked_closing_pr_open`: a GitHub closing PR link exists and that PR is still open.
- `linked_closing_pr_closed_unmerged`: a GitHub closing PR link exists, but that PR closed without merging.
- `related_pr_without_release_fix`: related PR references exist, but none is linked as reachable release-fix proof for the scored tag.
- `closed_without_release_fix_proof`: no linked PR or fix/source commit proof was found for the closure.
- `no_timeline_event`: issue has `closed_at`, but no fetched GitHub close event.
- `non_bug_fixed_in_release`: non-negative item has release-reachable fix proof; it remains audit-visible but is not scored as bug fix credit.
- `non_bug_fixed_after_release`: non-negative item has fix proof that is not reachable from this release tag.
- `non_bug_fixed_in_later_release`: non-negative item has fix proof reachable from a later scored stable release.
- `non_bug_fixed_not_in_scored_releases`: non-negative item has fix proof that is not reachable from any scored stable release.
- `non_bug_fixed_after_latest_release`: non-negative item has fix proof after the latest scored stable release.
- `non_bug_fixed_skipped_by_later_releases`: non-negative item has fix proof that predates later scored stable releases but is not reachable from them.
- `non_bug_linked_without_merge`: non-negative item has a linked closing PR, but it is not merged or merge state is unknown.
- `non_bug_linked_pr_open`: non-negative item has an open linked closing PR.
- `non_bug_linked_pr_closed_unmerged`: non-negative item has a linked closing PR that closed without merging.
- `non_bug_duplicate_to_fixed_in_release`: non-negative duplicate/superseded item points to canonical release-fix proof.
- `non_bug_duplicate_to_open_canonical`: non-negative duplicate/superseded item points to an open canonical issue.
- `non_bug_duplicate_to_closed_canonical`: non-negative duplicate/superseded item points to a closed canonical issue with terminal proof that is not release-fix credit.
- `non_bug_duplicate_to_closed_canonical_missing_proof`: non-negative duplicate/superseded item points to a closed canonical issue whose terminal closure proof is missing.
- `non_bug_duplicate_to_fixed_after_release`: non-negative duplicate/superseded item points to canonical fix proof that is not reachable from this release tag.
- `non_bug_superseded_to_open_pr`: non-negative duplicate/superseded item points to an open, unmerged PR.
- `non_bug_duplicate_with_open_pr_context`: non-negative duplicate/superseded item has related open PR context that is not marked canonical.
- `non_bug_duplicate_or_superseded`: non-negative item was closed as duplicate/superseded, but no canonical issue or PR target was resolved.
- `non_bug_not_actionable`: non-negative item was closed with concrete non-actionable, out-of-scope, or out-of-repository rationale.
- `non_bug_neutral`: closed item is not negative bug evidence.
- `not_planned`: close-time rationale says the issue is expected, by design, outside the tracked source/repository boundary, or otherwise concretely non-actionable for this release.

Only `fixed_in_release` receives direct fix credit. `duplicate_to_fixed_in_release` is treated as resolved release risk, but it remains separate so duplicate reports do not inflate direct fix counts. Other buckets preserve the closure context in the audit, but they do not reduce release risk for this tag.

The closure proof payload also rolls status buckets into risk dispositions:

- `credited_release_fix`: hard proof that the release tag contains the fix.
- `resolved_by_canonical_release_fix`: duplicate/superseded report whose canonical fix is proven reachable from the release tag.
- `resolved_by_release_fix_proof`: trusted release-reachable proof exists, but the GitHub closure shape was not direct fix-credit.
- `known_not_in_release`: a PR/commit or closure note indicates the fix is on main or after this tag, so it is not proof for this release.
- `open_canonical_risk`: the report was moved to an open canonical issue/trusted PR, or it has related open PR context that proves the work is not resolved in the scored release.
- `unsupported_closure_claim`: an already-present, duplicate, superseded, admin-not-planned, or closed-canonical claim that lacks reachable release code proof.
- `neutral_or_non_actionable`: not-scored closure evidence such as non-bug reports, concrete non-actionable rationale, reporter replacement, withdrawal, or self-closure.
- `missing_evidence`: missing closure timeline/proof evidence.

`unresolvedForReleaseCount` is the sum of `known_not_in_release`, `open_canonical_risk`, `unsupported_closure_claim`, and `missing_evidence`. It deliberately excludes direct fixes, duplicate reports resolved by canonical release fixes, not-planned closures resolved by trusted release proof, and not-scored/non-actionable closures so the UI does not imply every non-credited closure is a broken user report. Admin `NOT_PLANNED` closures without trusted rationale or proof are not in that not-scored bucket; they remain `unsupported_closure_claim`. The scorer converts the unresolved set into `unresolvedClosureRiskWeight` with the same effective classification path used by open-debt scoring: historical label reconstruction, deterministic title/label overrides, then disposition weight times severity, functionality, scope, and affected-user reach. Known-not-in-release counts as 1.0, open canonical risk as 1.2, unsupported closure/admin claim as 0.8, and missing proof evidence as 1.5 before issue severity/reach weighting. The resulting `closureRisk` score component is capped at a 0.5 point penalty.

The API exposes a coherent `releaseFixCredit` object:

- `countedClosedCount`: closed issues counted as release fixes.
- `notCountedClosedCount`: closed issues in the release window not counted as release fixes.
- `analyzedClosedCount`: total closed issues analyzed for the release window.

The invariant is `countedClosedCount + notCountedClosedCount = analyzedClosedCount`.

After closure proof analysis, the same `closureProof` and `releaseFixCredit` payload is persisted back into `release_score_audits.gate_evidence_json` and exposed through `/review` and `/comparison`.

Closure proof examples are selected after risk weighting and sorted by descending `riskWeight`. They expose raw classification, effective classification, classification diffs, effective labels, and per-issue risk weight so reviewers can see which deterministic overrides affected closure-risk scoring.

Refresh recomputes closure proof automatically for monitored releases. The manual command below reruns the same proof pass for a specific tag when debugging.

For historical scored releases, `npm run backfill:closed-windows -- --all` classifies raw closed-window issues that are missing current classification rows, then reruns closure evidence, PR reachability, closure proof, and score persistence.

The release audit verifier checks both aggregate counts and proof shape, including full 40-character commit IDs, reachable/not-reachable commit arrays, and consistency between commit proof rows and their summary booleans.

Run the audit invariant verifier after refreshes:

```bash
npm run verify:local
npm run verify:live
npm run verify:score
npm run verify:release-audit
npm run ui:smoke
```

`verify:local` and `verify:live` run score and release-audit checks in `--all` mode, covering every scored stable release rather than only the newest display window.

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

If the markdown evidence report link is missing but the release notes include a successful GitHub Actions `full release validation` run with a non-expired artifact, the scorer treats that action artifact as fallback release evidence. The original report URL and fallback action URL remain exposed in `gateEvidence.artifactVerification`.
`gateEvidence.releaseChecks.schemaVersion` and `gateEvidence.artifactVerification.schemaVersion` are the release-check and artifact-verification contract versions. Current value: `1`.

## Inspecting Current Evidence

Do not hardcode a "current" score in docs. The current recommendation changes as GitHub issues, labels, releases, advisories, and package metadata change.

Use the live local API instead:

```bash
curl -s http://127.0.0.1:8787/api/public \
  | jq '.releases[0] | {tag, score, band, status, recommended, reason, explanation}'

curl -s http://127.0.0.1:8787/api/releases/v2026.6.10/review \
  | jq '{score: .local.score, explanation: .local.components.explanation, fix: .local.gateEvidence.fixProvenance.releaseFixCredit}'
```

`/api/public` exposes top-level `schemaVersion` for the public payload contract. Current value: `1`.

`components.explanation` is the stable "Why not 10?" contract:

- `schemaVersion`: explanation contract version. Current value: `1`.
- `positives`: human-readable favorable evidence lines.
- `positiveDetails`: machine-readable entries aligned 1:1 with `positives`.
- `limits`: human-readable limiting evidence lines.
- `limitDetails`: machine-readable entries aligned 1:1 with `limits`.
- `verdict`: install-facing interpretation of the score.

Each detail entry has a stable `code`, matching `text`, and may include `metrics`, `buckets`, and `issueRefs`.

`/api/releases/:tag/review` exposes `local.input.schemaVersion` and `local.components.schemaVersion`. Current value: `1`.
`/api/releases/:tag/review` exposes `local.schemaVersion`; `/api/public` and `/api/releases` expose `scoreAudit.schemaVersion`. Current value: `1`.
`/api/releases/:tag/review` also exposes `local.issueEvidence.schemaVersion`. Current value: `1`.
The internal `/api/comparison` payload, upstream row, and delta objects also expose `schemaVersion`. Current value: `1`.
The `/api/status`, `/api/config`, `/api/releases` rows, `/api/releases/history` rows, and `/api/public` release rows also expose `schemaVersion`. Current value: `1`.

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
