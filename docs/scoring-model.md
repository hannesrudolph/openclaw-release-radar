# Scoring Model

Current model: `evidence-v14-closure-risk-ceilings`

The score answers one question:

> Should a user install this OpenClaw stable release right now?

It is not a raw issue count. The model combines hard gates, release survival, issue provenance, community breadth, fix reachability, release checks, and package artifact verification. Every score is written to `release_score_audits` with JSON inputs, components, issue evidence, and gate evidence.

Refresh and `npm run verify:score` both use the shared `releaseScoring` DB scoring pass. The verifier opens the database in read-only/query-only mode, recomputes the same install inputs and audit payloads from stored evidence, then fails if persisted release rows or score-audit rows drift. Score persistence writes release summary rows and `release_score_audits` inside one transaction, so a failed write cannot leave mixed old/new score state. The same pass also writes the structured `components.explanation` payload used by the UI's "Why not 10?" panel, including prose plus machine-readable reason codes, metrics, buckets, supporting issue references, and a `scoreLedger` that shows the base score, every component adjustment, caps, and final score arithmetic.

## Hard Gates

These override the normal 0-10 score:

- `wait`: release is younger than the settle window.
- `skip-cve`: medium-or-higher advisory affects the release.
- `skip-hotfix`: release was superseded quickly or by a hotfix successor.

Advisory version ranges are score-critical. Score writers refuse malformed or unsupported `vulnerable_version_range` strings instead of treating them as non-matches, because a false non-match could hide a `skip-cve` gate. A single GHSA can contain multiple vulnerable package ranges; refresh stores each vulnerability range as its own advisory row keyed by GHSA, package, ecosystem, and range so every range participates in skip/CVE scoring and advisory display.

## Score Components

The normal score starts from a base value, then applies bounded components:

- `verifiedDebt`: release-local field/community-confirmed blocker risk.
- `carryoverDebt` internally, displayed as open unconfirmed issue risk: open negative issue debt overlapping the release that is inherited, source-only/static, or otherwise not proven release-local blocker evidence. This is capped.
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

When unresolved closed-release risk is meaningful, the model also applies score ceilings. Moderate unresolved closure risk caps very high scores at `8.4`; substantial unresolved closure risk, by weight or issue count, caps at `7.9` so the release cannot display as `solid` while many closed-window issues are known not to be fixed in the tag, moved to open canonicals, or still unsupported by release proof.

## Issue Evidence Rules

Issue evidence is cluster-aware:

- Duplicate clusters are deduplicated globally across debt tiers.
- A duplicate cluster only counts as release-local when every report in that cluster is release-local; fresh duplicate reports can add field breadth to an older bug, but they do not turn that older open unconfirmed risk item into a new release-local blocker.
- Independent human reporters increase field/community confidence.
- Unique human commenters increase field/community confidence. Refresh cursor-paginates issue comments until exhausted, so commenter counts and comment-derived fix proof are not capped to the most recent page.
- Reactions only provide a small weight lift; they never make a source-only issue verified.
- Bot-only activity does not establish field evidence.
- Raw comment volume alone does not establish field evidence.
- `impact:security` alone is treated as a noisy keyword-stamped label; security/design dampening requires the explicit `security` label or other direct evidence.

The model deliberately separates:

- field-confirmed breakage
- open unconfirmed issue risk
- weak or stale issue evidence
- incomplete classification coverage
- unresolved closed issues not counted for this release
- reachable fixes

Issue evidence stores both `rawClassification` from the persisted classifier row and effective `classification` after deterministic title/label overrides. When those differ, `classificationDiff` records the changed fields so reviewers can see whether a score came from the LLM row or a rule-based override. Open-debt rows can also expose `debtClassification` and `debtClassificationDiff` when debt scoring uses a risk-only bug-evidence hint that differs from the display classification.

Debt evidence also records `installImpactClass`, `installImpactMultiplier`, and issue-ref scoring reasons, so damped provider/security/product-debt risks and open unconfirmed examples are auditable in the score explanation instead of being hidden inside the final weight. Stale or weak rows with concrete bug evidence, such as source-only/static repro plus impact labels, remain capped as `staleDebt`; they are not promoted to verified field-blocker debt.

If raw attributed issues exist without current classifications, the score explanation includes `incomplete_classification_coverage` with raw/classified counts, the missing count, the evidence-coverage ratio, the capped penalty, and example unclassified issue references when available. This makes coverage penalties explicit instead of hiding them inside the final score.

## Issue Open Intervals

Release attribution is based on issue open intervals, not a single created-to-final-closed span.

The initial open interval starts at `issues.created_at` and ends at the first fetched GitHub close event after creation. Each fetched `ReopenedEvent` starts another open interval, ending at the next fetched close event. If timeline evidence is missing, the scorer falls back to `issues.closed_at` rather than treating sparse history as open forever.

An issue is attributed to a release only when one of those open intervals overlaps the release's stable-to-stable reign window. This prevents reports that were already closed before a release from counting against that release merely because they were reopened later.

Score persistence refuses ambiguous open-interval evidence. If a fetched reopen event has no preceding close event for that issue, the scorer cannot prove where the earlier open interval ended, so `persistReleaseScoreRun` refuses to write release rows or score audits until timeline evidence is complete. Score persistence also refuses ambiguous stable release windows when stable releases have missing or duplicate `published_at` timestamps.

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

The scoring query that supplies verified fixes is proof-row-only: it credits only `issue_closure_proofs.status = fixed_in_release` for the scored release tag. Raw linked PR reachability, closure comments, and commit references are inputs to closure-proof analysis; they are not a direct fallback path to scoring credit when the proof row is missing.

Closed-window fix credit is final-close based. If an issue closes during one stable's reign, reopens, and finally closes during a later stable's reign, only the later final close is analyzed for release fix credit. The earlier close is treated as a failed or superseded resolution attempt, not as a stable fix.

Reachability has three states: `reachable`, `not_reachable`, and `unknown`. `not_reachable` is only used when Git can prove exact non-ancestry with `merge-base --is-ancestor` exit status `1`. Missing release commits, missing PR merge commits, unavailable objects, and Git errors are stored as `unknown`; they never receive fix credit and remain auditable instead of being collapsed into proof that the fix is absent. Each persisted reachability row stores schema-versioned evidence with a known reason, the release tag commit, the checked PR merge/fix commit, base ref, and command diagnostics when a Git command determines the result.

Broad PR/commit mentions in comments are stored for audit context, but they do not reduce release risk. Comment-derived fix credit requires explicit closure/fix/provenance wording from a trusted source, such as a maintainer or the known ClawSweeper reviewer account, identifying the merged PR or fix/source commit that closed, fixed, or proves the reported behavior is present in the release source.

GitHub `ReferencedEvent` commit references are stored separately from closure events. Fork/cross-repository references and same-repo direct references are audit context only; they do not create release fix credit by themselves, even when the commit headline is fix-shaped. Trusted close-time comments may name abbreviated commit hashes, but the proof analyzer accepts them only after the local OpenClaw git clone resolves the prefix uniquely to a full 40-character commit SHA.

Every same-repo merged PR stored in closure proof `linkedPrs` carries release-tag reachability metadata: `reachabilityStatus`, `reachabilityMethod`, `tagCommitOid`, `mergeCommitOid`, and `reachabilityEvidence`. This makes each proof row self-auditing instead of requiring reviewers to cross-reference `release_pr_reachability` manually. Merged PRs from external repositories are marked `external_repo_unchecked` with `external_repository_not_checked_against_openclaw_release_tag`; they remain visible as context but are not release inclusion proof.

Named direct fix/source commit proof also fails closed on git infrastructure errors. Missing release commit evidence, release commit fetch failures, candidate commit fetch infrastructure failures, and merge-base errors abort closure proof persistence so transient git failures cannot downgrade a reachable fix into unknown proof without durable failure provenance. A named SHA that GitHub explicitly reports as not present in the repository remains non-crediting `commit_unavailable` evidence instead of blocking the whole release.

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
- `duplicate_with_release_fix_proof`: the issue is closed as duplicate/superseded, but trusted closure-comment fix proof is reachable from this release tag. It resolves closure risk without direct GitHub fix-credit.
- `superseded_to_open_pr`: trusted close-time closure context moved the report to a referenced PR that remains open and unmerged.
- `duplicate_with_open_pr_context`: the issue is closed as duplicate/superseded and related open PR references exist, but no trusted close-time closure note marks those PRs as canonical.
- `duplicate_related_closed_unmerged_pr_context`: the issue is closed as duplicate/superseded and related PR context exists, but the referenced PRs closed without merging.
- `duplicate_related_merged_pr_not_reachable_context`: the issue is closed as duplicate/superseded and related merged PR work exists, but that PR is not reachable from this release tag.
- `duplicate_related_merged_pr_reachable_context_without_fix_credit`: the issue is closed as duplicate/superseded and related PR work is reachable from this release tag, but no trusted closing/fix proof is credited for this issue.
- `duplicate_related_merged_pr_reachability_unknown`: the issue is closed as duplicate/superseded and related merged PR work exists, but release-tag reachability is unknown.
- `duplicate_related_pr_without_release_fix`: the issue is closed as duplicate/superseded and related PR references exist, but none is trusted release-fix proof for this issue.
- `canonical_cycle_or_self_reference`: canonical reference loops back to the same issue or repeats.
- `duplicate_or_superseded`: closure comments or state show the issue moved under another tracker.
- `already_present_claim`: closure comment claims the behavior is already implemented, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
- `admin_not_planned_unverified`: a negative report was closed with GitHub `NOT_PLANNED`, but no reachable release fix proof or concrete close-time non-actionable rationale was found.
- `admin_not_planned_no_context`: a negative report was closed with GitHub `NOT_PLANNED`, but the audit found no trusted close-time rationale comment at all.
- `not_planned_with_release_fix_proof`: a negative report was closed with GitHub `NOT_PLANNED`, but trusted release-reachable fix proof exists. It resolves closure risk without direct GitHub fix-credit.
- `not_planned_fixed_after_release`: a negative report was closed with GitHub `NOT_PLANNED`, and trusted fix proof exists only after the scored release tag.
- `not_planned_with_open_pr_context`: a negative report was closed with GitHub `NOT_PLANNED` while related open PR context still exists.
- `not_planned_linked_pr_not_merged`: a negative report was closed with GitHub `NOT_PLANNED` and a linked closing PR is not merged or has unknown merge state.
- `not_planned_related_closed_unmerged_pr_context`: a negative report was closed with GitHub `NOT_PLANNED` and related PR context closed without merging.
- `not_planned_related_merged_pr_not_reachable_context`: a negative report was closed with GitHub `NOT_PLANNED` and related merged PR work is not reachable from the scored tag.
- `not_planned_related_merged_pr_reachable_context_without_fix_credit`: a negative report was closed with GitHub `NOT_PLANNED`; related PR work is reachable from the scored tag, but no trusted closing/fix proof is credited for the issue.
- `not_planned_related_merged_pr_reachability_unknown`: a negative report was closed with GitHub `NOT_PLANNED` and related merged PR reachability is unknown.
- `not_planned_related_pr_without_release_fix`: a negative report was closed with GitHub `NOT_PLANNED` and related PR references exist, but none is release-fix proof for the scored tag.
- `main_only_claim`: closure comment claims the fix exists on current main, but indicates the scored release may not contain it.
- `reporter_replaced`: reporter refiled, reopened, or replaced the issue under another issue number.
- `reporter_withdrawn`: reporter withdrew the report, asked maintainers to ignore it, or closed it for privacy/non-fix reasons.
- `reporter_self_closed`: reporter self-closed the issue without linked release fix proof or ongoing failure context.
- `insufficient_info`: closure explains that requested reproduction detail, logs, or trace evidence never arrived. It remains unresolved proof debt rather than a release fix.
- `no_code_proof`: closure exists, but no linked merged PR or named fix/source commit is reachable from the scored release tag.
- `linked_closing_pr_reachability_unknown`: a merged GitHub closing PR link exists, but release-tag reachability is missing or unknown.
- `linked_closing_pr_not_merged`: a GitHub closing PR link exists, but the PR is not merged or its merge state is unknown.
- `linked_closing_pr_open`: a GitHub closing PR link exists and that PR is still open.
- `linked_closing_pr_closed_unmerged`: a GitHub closing PR link exists, but that PR closed without merging.
- `external_repo_closing_pr_unscored`: GitHub closure points to a merged PR in another repository; OpenClaw release inclusion is not proven by the release tag.
- `related_open_pr_context`: related PR context remains open.
- `related_closed_unmerged_pr_context`: related PR context exists, but the referenced PRs closed without merging.
- `related_merged_pr_not_reachable_context`: related merged PR work exists, but is not reachable from the scored tag.
- `related_merged_pr_reachable_context_without_fix_credit`: related PR work is reachable from the scored tag, but no trusted closing/fix proof is credited for the issue.
- `related_merged_pr_reachability_unknown`: related merged PR work exists, but release-tag reachability is unknown.
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
- `non_bug_duplicate_related_closed_unmerged_pr_context`: non-negative duplicate/superseded item has related PR context that closed without merging.
- `non_bug_duplicate_related_merged_pr_not_reachable_context`: non-negative duplicate/superseded item has related merged PR context that is not reachable from this release tag.
- `non_bug_duplicate_related_merged_pr_reachable_context_without_fix_credit`: non-negative duplicate/superseded item has related reachable PR context but no direct fix credit.
- `non_bug_duplicate_related_merged_pr_reachability_unknown`: non-negative duplicate/superseded item has related merged PR context with unknown release reachability.
- `non_bug_duplicate_related_pr_without_release_fix`: non-negative duplicate/superseded item has related PR references that are not release-fix proof.
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

`unresolvedForReleaseCount` is the sum of `known_not_in_release`, `open_canonical_risk`, `unsupported_closure_claim`, and `missing_evidence`. It deliberately excludes direct fixes, duplicate reports resolved by canonical release fixes, not-planned closures resolved by trusted release proof, and not-scored/non-actionable closures so the UI does not imply every non-credited closure is a broken user report. Admin `NOT_PLANNED` closures without trusted rationale or proof are not in that not-scored bucket; they remain `unsupported_closure_claim`. The scorer converts the unresolved set into `unresolvedClosureRiskWeight` with the same effective classification path used by open-debt scoring: historical label reconstruction, deterministic title/label overrides, a risk-only bug-evidence hint, then disposition weight times severity, functionality, scope, and affected-user reach. Neutral/stale/enhancement-shaped rows are treated as negative risk when concrete bug evidence is present, such as source-only repro plus impact labels, data-loss labels, explicit bug/regression labels, affected-version evidence, or bug-shaped titles. This prevents a manual/bot close or stale label from becoming zero-risk solely because the display classification is neutral. Known-not-in-release counts as 1.0, open canonical risk as 1.2, unsupported closure/admin claim as 0.8, and missing proof evidence as 1.5 before issue severity/reach weighting. The resulting `closureRisk` score component is capped at a 0.5 point penalty. Separately, if `unresolvedClosureRiskWeight` is at least 40 or `unresolvedForReleaseCount` is at least 50, the final eligible score is capped at 8.4; if the weight is at least 60 or the count is at least 75, the cap is 7.9.

The API exposes a coherent `releaseFixCredit` object:

- `countedClosedCount`: closed issues counted as release fixes.
- `notCountedClosedCount`: final-closed issues in the release window not counted as release fixes.
- `analyzedClosedCount`: total final-closed issues analyzed for the release window.

The invariant is `countedClosedCount + notCountedClosedCount = analyzedClosedCount`.

After closure proof analysis, the same `closureProof` and `releaseFixCredit` payload is included in the next `release_score_audits.gate_evidence_json` written by score persistence and exposed through `/review` and `/comparison`. Proof rows are staged before replacement, and replacing `issue_closure_proofs` happens inside one DB transaction. Refresh and closed-window backfill run closure proof analysis with score-audit payload persistence disabled, then write the proof payload only as part of the final score transaction; a failed later evidence step cannot attach fresh proof payloads to stale scores. Manual single-release proof commands keep score-audit payload persistence enabled for inspection/debugging, and malformed existing audit gate evidence aborts that manual write. Releases with zero proof rows persist an explicit zero-count closure-proof payload instead of leaving a stale previous payload in place. A scored audit must also have `input.unresolvedClosureIssueCount` and `input.unresolvedClosureRiskWeight` matching `closureProof.riskSummary`; if proof analysis changes closure risk, score persistence must run again before the audit is considered valid.

Closure proof evidence must cover every raw closed issue in the release window before scores can be persisted or verified. The guard rejects missing proof rows, extra proof rows outside the release window, and proof rows older than their dependency evidence, including issue rows, classifications, labels, closure/reopen events, PR links, commit references, PR metadata, and release PR reachability.

Closure proof examples are selected after risk weighting and sorted by descending `riskWeight`. They expose raw classification, effective classification, classification diffs, effective labels, current labels, label source/cutoff provenance, per-issue risk weight, and human-readable labels for machine risk enums so reviewers can see which deterministic overrides affected closure-risk scoring without decoding internal names.

Each release review also exposes `dataFreshness`. `scoredAt` is when the score/audit payload was computed. `issueUpdatedAtMax` is the newest GitHub issue `updated_at` value included in the release issue universe. `issueUpdatedAgeHoursAtScore` makes that semantic GitHub gap explicit, while `issue_fetches` records when those issue rows were last fetched/written locally. Each source exposes `count`, `nullCount`, `maxAt`, and age-at-score data; populated freshness sources must not have null timestamps, otherwise doctor treats the score as not fully auditable. A freshly computed score can still be based on issue rows, labels, or source metadata fetched earlier. The review UI shows this as `Source freshness`, and the API includes per-source timestamps for release-row metadata/artifact checks, issue rows, local issue fetches, classifications, label events/snapshots, closure proof, closure events, PR links, PR metadata, and release reachability.

Refresh records the latest issue-pagination crawl in `meta.issue_crawl_last_run`, including pages fetched, stop reason, whether issue backfill was complete, truncated comment scans seen during the crawl, release-metadata/artifact/release-check/advisory/monitored-release evidence refresh failures, and whether score persistence happened after that crawl. If release metadata cannot be fetched, refresh writes an `evidence_failure` crawl record with zero issue pages and refuses score persistence. Refresh also refuses to score if the fetched release window lacks enough stable releases or the older stable boundary needed to compute monitored-release beta, breaking-change, hotfix, and stable-window context. If issue pagination stops at `MAX_ISSUE_PAGES`, refresh refuses to persist scores from that incomplete crawl. If issue-page comments, label timelines, or fix evidence fail mid-crawl, refresh records `stopReason: "evidence_failure"`, persists failure examples, and refuses score persistence before any partial issue page is written as if it were complete. Truncated comment scans are treated as score-blocking incomplete evidence because commenter breadth and comment-derived proof would otherwise be undercounted. Once page evidence is fetched cleanly, refresh writes the page's issue rows, label events/snapshots, and state evidence in one transaction; issue-page write failures are recorded as `issue-page-write`, rolled back, and score-blocking. Page classifications are also staged in memory and written in one transaction only if every pending issue on that page classifies cleanly; classification write failures are recorded as `issue-classification-write` and block scoring. If artifact verification, release commit checks, advisories, closure evidence, PR reachability, or closure-proof refresh fails, refresh records `evidenceRefreshFailures` and refuses to persist scores until those evidence passes complete cleanly. Closure-proof refresh can update `issue_closure_proofs`, but refresh does not patch existing `release_score_audits`; the refreshed proof payload is attached only if score persistence succeeds. `npm run doctor -- --fail-on-warnings` surfaces missing crawl metadata on scored DBs, recorded page-cap stops, truncated comment scans, evidence refresh failures, durable `ingestion_evidence_failures` rows newer than the latest score, and source evidence newer than the latest score so a score cannot quietly look fresh after incomplete evidence ingestion.

Every score write also records `meta.score_persistence_last_run` in the same transaction as release rows and `release_score_audits`. The record captures the writer source, scope, release tags, recommended tag, model/prompt versions, score timestamps, and issue-crawl coordinates used by that writer. Doctor fails if current score rows drift from this provenance, including the exact release-tag set, model version, and prompt version, so manual score writes such as `populate-db` or `backfill:closed-windows` are auditable instead of silently replacing refresh-produced scores.

GraphQL nested evidence connections are treated as required provenance, not optional decoration. Missing `nodes`, null nodes, missing `pageInfo`, or a `hasNextPage` page without `endCursor` fails ingestion for score-affecting release pages, issue pages, issue labels, comments, label timelines, fix evidence, release check contexts, and advisory pages instead of being interpreted as empty evidence.

`ingestion_evidence_failures` is append-only provenance for score-blocking fetch failures. It records the refresh run id, source, scope, optional release/issue/PR coordinates, message, context JSON, and occurrence timestamp so failed evidence pulls remain auditable even when refresh exits before it can complete normal crawl metadata.

GitHub partial responses for missing issue aliases are recovered only when a caller provides an explicit missing-alias reporter. During refresh, each skipped alias is recorded as a score-blocking ingestion evidence failure, and scoring is refused rather than treating that issue's comments, labels, or fix evidence as empty. Other callers fail closed on the GraphQL error.

Refresh recomputes closure proof automatically for monitored releases. The refresh path writes proof rows with score-audit payload persistence disabled and relies on the subsequent score transaction to attach the matching proof payload. The manual proof commands rerun the same proof pass for a specific tag when debugging. They require the release to exist locally, require clean ingestion metadata before writing, and record score-blocking `ingestion_evidence_failures` rows when the proof/reachability pipeline aborts.

PR reachability is staged before replacement. `checkReleasePrReachability` fetches the release commit, fetches and validates each candidate PR merge commit, builds the full replacement row set in memory, validates row evidence shape, then replaces `release_pr_reachability` for that tag inside one DB transaction. Run-level git evidence failures abort before deleting old reachability rows; refresh records them as score-blocking evidence failures, and the standalone reachability command records a durable `ingestion_evidence_failures` row before exiting.

PR reachability evidence must cover the current merged linked-PR candidate set before scores can be persisted or verified. For each scored release, the guard requires every current same-repo merged linked PR to have a reachability row, rejects extra rows outside that candidate set, rejects rows older than current PR metadata, and rejects reachable/not-reachable rows whose merge commit or base ref no longer matches current PR metadata. Link-row refetches alone do not force reachability stale; new or removed linked PR candidates are covered by the missing/extra row checks.

Closure evidence refresh also stages comment-derived PR lookups before replacing link rows. Raw closure evidence and comment-link replacement delete and insert their affected link rows inside DB transactions, so failed PR detail fetches do not first wipe prior link evidence. Trusted closure-comment PR mentions fail closed when GitHub cannot resolve the named PR; missing PR metadata is treated as incomplete provenance, not absence of a fix candidate.

`backfill:issue-state-events` fetches all GitHub fix/state evidence before writing label snapshots, closure events, reopen events, PR links, or PR rows. After fetch succeeds, it writes the full snapshot/event/PR batch in one DB transaction. Missing aliases, fetch failures, or write failures are recorded in `ingestion_evidence_failures` and abort or roll back the write so manual state backfills cannot leave partial evidence while appearing clean.

For historical scored releases, `npm run backfill:closed-windows -- --all` classifies raw closed-window issues that are missing current classification rows, stages every classification result in memory, writes the staged classification set in one DB transaction, then reruns closure evidence, PR reachability, closure proof, and score persistence. During that backfill, closure proof writes side-table proof rows but does not patch existing score audits until the final score persistence transaction. Fetch, classification, classification-write, closure-evidence, reachability, or closure-proof failures are recorded in `ingestion_evidence_failures` with release context where applicable and abort without leaving partial closed-window classification writes or fresh proof payloads attached to stale score audits. Manual score writers share the same clean-ingestion guard: before writing scores, they refuse dirty ingestion metadata such as missing/malformed `issue_crawl_last_run`, page-cap or evidence-failure stop reasons, recorded evidence/classification failures, durable ingestion failure rows newer than the latest score, or any durable score-blocking ingestion failure before the first score.

The release audit verifier checks both aggregate counts and proof shape, including full 40-character commit IDs, reachable/not-reachable commit arrays, and consistency between commit proof rows and their summary booleans.

Run the audit invariant verifier after refreshes:

```bash
npm run verify:local
npm run verify:live
npm run verify:score
npm run verify:release-audit
npm run ui:smoke
```

`verify:local` and `verify:live` run score and release-audit checks in `--all` mode, covering every scored stable release rather than only the newest display window. `verify:live` also runs browser smoke checks across desktop and mobile viewports so API-correct data cannot ship with an unreadable or horizontally overflowing UI.

## Release Checks

The model reads the release tag commit's GitHub `statusCheckRollup`.

- Successful checks add a small capped confidence bump.
- Pending checks add a small penalty.
- Failed checks add a larger penalty.
- Missing check data is neutral.

The audit payload stores check state, complete check counts, `contextCount`, `shownContextCount`, `contextsTruncated`, and a capped example list of check contexts.

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
`gateEvidence.releaseChecks.schemaVersion` is the release-check contract version. Current value: `2`. `gateEvidence.artifactVerification.schemaVersion` is the artifact-verification contract version. Current value: `1`.

## Inspecting Current Evidence

Do not hardcode a "current" score in docs. The current recommendation changes as GitHub issues, labels, releases, advisories, and package metadata change.

Use the live local API instead:

```bash
curl -s http://127.0.0.1:8787/api/public \
  | jq '.releases[0] | {tag, score, band, status, recommended, reason, explanation}'

curl -s http://127.0.0.1:8787/api/releases/v2026.6.10/review \
  | jq '{score: .local.score, explanation: .local.components.explanation, fix: .local.gateEvidence.fixProvenance.releaseFixCredit}'
```

`/api/public` exposes top-level `schemaVersion` for the public payload contract. Current value: `4`.

`components.explanation` is the stable "Why not 10?" contract:

- `schemaVersion`: explanation contract version. Current value: `1`.
- `scoreLedger`: ordered score math rows (`base`, evidence penalties, survival/shakeout/release/artifact bonuses), cap rows such as heavy closure-risk ceiling and hotfix ceiling, subtotal before caps, score after caps, and final rounded score. The audit verifier treats ledger row keys, labels, order, cap keys, and cap order as part of the contract.
- `positives`: human-readable favorable evidence lines.
- `positiveDetails`: machine-readable entries aligned 1:1 with `positives`.
- `limits`: human-readable limiting evidence lines.
- `limitDetails`: machine-readable entries aligned 1:1 with `limits`.
- `verdict`: install-facing interpretation of the score.

Each detail entry has a stable `code`, mandatory canonical `label`, matching `text`, and may include `metrics`, `buckets`, and `issueRefs`.

`/api/releases/:tag/review` exposes `local.input.schemaVersion` and `local.components.schemaVersion`. Current value: `1`.
`/api/releases/:tag/review` exposes `local.schemaVersion`; `/api/public` and `/api/releases` expose `scoreAudit.schemaVersion`. Current value: `1`.
`/api/releases/:tag/review` also exposes `local.issueEvidence.schemaVersion`. Current value: `1`.
The internal `/api/comparison` payload, upstream row, and delta objects also expose `schemaVersion`. Current value: `1`.
Comparison snapshots are internal calibration artifacts. They are validated before insertion, stored outside local score/audit rows, and must not be used as local audit-backed score evidence.
The `/api/status` and `/api/config` payloads also expose `schemaVersion`. Current value: `1`.
The `/api/releases/history` rows expose `schemaVersion`. Current value: `2`.
The `/api/public` payload and `/api/public` release rows expose `schemaVersion`. Current value: `4`. Public release `profileEvidence.schemaVersion` current value: `1`; it is derived from audited issue-evidence rows, not from capped public issue summaries. `/api/releases` rows expose `schemaVersion`. Current value: `2`.

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
