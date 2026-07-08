# Scoring Model

Current model: `evidence-v30-tooling-exclusion`

The 0-10 value is an ordinal policy/stability assessment. It ranks releases under the current audited policy; it is not a probability, percentage, or claim that a release is issue-free.

The assessment answers one question:

> Should a user install this OpenClaw stable release right now?

It is not a raw issue count. The model combines hard gates, release survival, issue provenance, semantic human confirmation, fix reachability, release checks, and package artifact verification. Every assessment is written to `release_score_audits` with JSON inputs, components, issue evidence, gate evidence, and a separate score-source identity manifest.

Recommendation selection ranks audited assessments with bounded recency preference. Eligible releases must score at least `7.0`. The newest candidate is selected only when it is within `0.5` points of the strongest eligible assessment; otherwise the materially stronger assessment is selected. Tolerance comparison uses fixed decimal units, so `7.8` is correctly within `0.5` of `8.3`. Each audit persists a structured `recommendationDecision` with the policy, threshold, tolerance, ranks, selected tag, and human-readable reason. Persistence and API compatibility checks recompute the complete run policy, require zero or one selected row as appropriate, require the selected tag to be a candidate, and require every row's decision copies to agree.

Refresh and `npm run verify:score` both use the shared `releaseScoring` DB scoring pass. The verifier opens the database in read-only/query-only mode, recomputes the same install inputs, audit payloads, and source identity from stored evidence, then fails if persisted release rows or score-audit rows drift. Refresh preflights prospective forecast slots before the score transaction. Score persistence then writes release summary rows, current `release_score_audits`, and immutable `release_score_audit_history` atomically; a short post-score transaction binds commit timing, appends any new schema-v4 forecasts, and appends the success receipt. The same pass also writes the structured `components.explanation` payload used by the UI's assessment-details panel, including prose plus machine-readable reason codes, metrics, buckets, supporting issue references, a validated `recommendationDecision`, and a `scoreLedger` that shows the base score, every component adjustment, caps, and final score arithmetic.

The release and current-audit tables are mutable presentation state; they may be replaced only by a complete verified score write. Score history, refresh attempts and stage events, terminal receipts, forecasts, outcomes, observation batches, advisory snapshots, and issue-catalog snapshots are immutable append-only ledgers. A current assessment is publishable only when its mutable rows exactly match the sealed immutable history tip and the receipt/source contracts authorize that tip.

## Hard Gates

These override the normal 0-10 score:

- `wait`: release is younger than the settle window.
- `skip-cve`: medium-or-higher advisory affects the release.
- `skip-hotfix`: release was superseded quickly or by a hotfix successor.

Advisory version ranges are score-critical. The supported grammar is exact versions and `<`, `<=`, `>`, `>=`, or `=` clauses joined by commas or whitespace. Parsing rejects unsupported operators, empty or trailing comma segments, multiple bare versions, contradictory exact versions, impossible lower/upper intersections, and every other range that can never match. Version comparison follows SemVer prerelease precedence component by component: numeric identifiers compare numerically and sort before nonnumeric identifiers. Score writers refuse malformed or unsupported `vulnerable_version_range` values instead of treating them as non-matches, because a false non-match could hide a `skip-cve` gate.

GitHub's `firstPatchedVersion` is authoritative patch metadata. If GitHub returns no first patched version, refresh stores `null`; it never derives a patch from the vulnerable range. A malformed patch identifier or a claimed patch that still satisfies the vulnerable range blocks advisory replacement and score persistence.

A single GHSA can contain multiple vulnerable package ranges. Refresh stores each vulnerability range as its own advisory row for audit, but overlapping matching rows for the same GHSA/package contribute only one strongest advisory load and one API advisory total. Any matching medium-or-higher range still activates `skip-cve`.

Advisory ingestion cursor-paginates package-bound GraphQL security vulnerabilities to `totalCount` and captures repository-advisory REST evidence separately. New compound-v2 snapshots declare authority policy `graphql_global_with_complete_repository_fallback` schema 1, and that policy is bound into the source, catalog, and score hashes. Unmarked historical v2 snapshots reconstruct under the original strict reconciliation policy. Current GraphQL rows are authoritative whenever a GHSA exists in the package-global catalog. A complete, valid repository row is a fallback authority only for repository-owned GHSAs absent from that global catalog. The repository observation retains each advisory `updated_at`, and snapshot construction independently recomputes the canonical REST content digest over advisory metadata and every package/range row before any fallback can become score authority. Historical REST metadata, range, patch, or state differences remain immutable audit evidence and cannot override a current GraphQL row; reconciliation reports them as `divergent`, while malformed repository-only fallback evidence, declared reconciliation tampering, source corruption, or incomplete required pagination remains `blocked`. Duplicate or overlapping GraphQL identities, incomplete GraphQL pagination, and incomplete REST pagination when repository-only fallback rows are required fail closed. Every scoreable compound snapshot is appended to the immutable v2 header/row ledger before scoring. Staging does not move the active pointer. Activation and the legacy score projection occur only inside the score/forecast/success-receipt transaction, and the receipt exact-binds the snapshot metadata, source/catalog/score hashes, ledger hash, projection digest, and row counts. Source identity reads the selected active metadata pointer rather than the ledger tip.

The review API publishes the same advisory-v2 audit projection independently
reconstructed by the release-audit reader. The projection requires an intact
v2 ledger and active score projection, a valid operation receipt ledger, and
exactly one successful receipt whose binding and publication timing match the
active snapshot. It exposes the complete active metadata, metadata digest,
content and score-projection hashes, row counts, authorizing receipt/run and
semantic receipt identity, plus authorized and staged snapshot IDs. Any
integrity, active-projection, operation-ledger, or authorization problem fails
closed. Legacy snapshot metadata and history are reported separately for
compatibility and do not contribute failures to a valid v2 publication.

When advisory rows or audit compatibility change after a score was written, API surfaces return explicit `status: "stale"`, suppress the score and recommendation, and expose the prior persisted status only as `diagnosticStatus`. Current per-range advisory evidence remains visible for diagnosis, but the old `eligible` or skip state is not presented as current install advice.

## Release Catalog

Release windows are selected from an exhaustive, stabilized catalog rather than from a bounded "latest releases" page. Refresh cursor-paginates the complete GitHub `repository.releases` connection, validates `totalCount`, IDs, tags, nodes, and pagination metadata, and repeats complete sweeps until two consecutive canonical catalog digests match. A catalog that changes across all three allowed sweeps fails closed.

GitHub returns the connection in `created_at` order. Only after the complete catalog stabilizes does refresh sort all releases by `published_at`, reject missing or duplicate stable publication timestamps, select the monitored stable window, and select its immediate older stable predecessor. This prevents a late-published release with an older creation timestamp from being omitted or assigned to the wrong stable window.

## Issue Catalog Completeness

Exhaustive issue runs use deterministic `CREATED_AT ASC` order. The first response freezes an as-of boundary at its starting `totalCount`; the first sweep records the terminal immutable node ID, issue number, and `createdAt`, and every sweep collects exactly that first-N universe. Newly created issues appended after the boundary are excluded and recorded as post-boundary growth. A count decrease below N, duplicate node IDs or issue numbers, missing first-N identities, terminal-watermark drift, repeated or missing cursors, or inability to collect exactly N rows fails closed.

Stabilization compares a canonical membership digest over immutable node ID, issue number, and `createdAt` across two complete sweeps against the same frozen boundary. Mutable remote content has a separate content digest and does not invalidate membership; the last accepted sweep supplies the persisted metadata. The accepted catalog creates `meta.issue_crawl_exhaustive_baseline` with repository identity, explicit as-of boundary, boundary and observed counts, post-boundary growth, membership/content digests, and page/sweep counts.

Every score-producing refresh repeats the exhaustive `CREATED_AT ASC` path. Issues created after the frozen first-N boundary are recorded as post-boundary growth and enter the next exhaustive snapshot; they do not force an in-progress run to restart. The legacy `UPDATED_AT DESC` incremental code remains non-authoritative compatibility code and cannot persist a score.

## Score Components

The normal score starts from a base value, then applies bounded components:

- `verifiedDebt`: release-local field/community-confirmed blocker risk.
- `carryoverDebt` is a legacy machine identifier retained for compatibility. Publicly it is inherited issue context: issue groups linked to the release because they predate its window. They remain visible for audit but contribute zero score points and never apply a score ceiling.
- `staleDebt`: low-confidence, stale, needs-info, weak, source/static-only, or otherwise unconfirmed evidence risk. This is heavily capped.
- `closureRisk`: unresolved closed-issue evidence selected by the exclusive risk ledger when it is the strongest adverse representation of its alias group. This is capped and does not score non-bug, reporter-withdrawn, or concretely non-actionable closures.
- `coverage`: penalty if raw issues exist but classification coverage is incomplete.
- `survival`: reward for standing as latest/current stable without hotfix replacement.
- `shakeout`: small reward for beta/prerelease bake time.
- `regression`: exclusive deduplicated reach-weighted opened-report risk versus first-containing verified fixes.
- `breaking`: release-note breaking-change penalty.
- `releaseVerification`: capped confidence from release commit checks.
- `artifactVerification`: capped confidence from npm package integrity plus release evidence report verification.

The functionality taxonomy distinguishes runtime paths (`core`, `integration`, and `provider`) from non-runtime work. `tooling` covers test infrastructure, CI, builds, linting, formatting, fixtures, harnesses, and developer tooling. Tooling issues carry zero issue weight, do not enter felt opened/closed load, and cannot qualify as default-path impact. Deterministic title correction requires an explicit tooling subject and is vetoed when the title identifies a runtime failure target; CI, test, or build context alone cannot zero a gateway, channel, provider, request, response, authentication, or message-delivery failure. The review issue-evidence API accepts `functionality=tooling` for audit rows that are present; zero-weight open tooling issues do not enter score-evidence tiers.

Each canonical/classifier alias group elects exactly one score-affecting adverse contribution across verified debt, stale debt, closure risk, and regression. Carryover groups remain visible alongside that ledger as audit-only context. This preserves exclusive numerical accounting while preventing inherited backlog volume from being treated as release instability. Release-unresolved issues remain debt even when their current global state later becomes closed. Resolved, neutral, and contained-in-tag groups receive no regression penalty; a contained fix receives positive regression credit only when it is also proven first-containing.

When unresolved closed-release risk is meaningful, the model also applies score ceilings. The numeric closure penalty remains exclusive with verified debt, stale debt, and regression, but the ceiling uses a separate deduplicated affirmative closure-risk weight computed before that channel election. This prevents a verified or stale debt representative from erasing a known-not-in-release, open-canonical, or unsupported-closure ceiling for the same alias group. Moderate affirmative weight caps very high scores at `8.4`; substantial affirmative weight caps at `7.9`. `missing_evidence` is never included in the ceiling weight. Raw report volume does not trigger a ceiling, and canonical issues or duplicate clusters contribute one maximum-weight affirmative group.

## ScoreLedgerV2

`components.explanation.scoreLedger` is a required, non-null `ScoreLedgerV2` for every score status, including `wait`, `skip-cve`, and `skip-hotfix`. The ledger is deep-frozen when constructed and carries a canonical SHA-256 digest. Score persistence and audit serialization both reject it unless semantic replay from the persisted score input reproduces the exact ledger, confidence tuple, evidence binding, and digest.

The ordered `operations` array is authoritative score arithmetic. Every operation records a stable `formulaCode`, typed operands with units, raw and bounded points, explicit bounds, running `before`/`after` values, whether it applied, any predicate result, the complete evidence-manifest keys it consumed, and a digest of those manifests. The derivation records:

- exact predicates for advisory exposure, the 24-hour settle threshold, the non-latest hotfix condition or `<6` hour successor gap, and closure-risk thresholds at weights `40` and `60`;
- every bounded component adjustment;
- the explicit `0..10` range clamp;
- closure ceilings at `8.4` or `7.9` and the hotfix ceiling at `4.9`;
- final one-decimal rounding.

The advisory-gate path records `4.9 * (1 - min(1, cveLoad / 30))`, its `0..4.9` clamp, one-decimal rounding, and the selected minimum against a complete no-advisory counterfactual. The legacy `cveGate` and `cveLoad` machine identifiers retain both arithmetic paths and bind the decision to the exhaustive advisory identity manifest.

Evidence previews are presentation only. Each evidence channel has a separate canonically ordered exhaustive manifest of `{kind, identity, digest}` references, a manifest digest, and a bundle digest. Previews retain at most 25 references by default and record their limit, total count, and truncation state; persistence validation compares them with the corresponding manifest prefix, so evidence after the 25th item remains score-authoritative.

`aliasElection` stores every canonical/classifier alias group, all candidate channels, the elected exclusive channel and weight, channel totals, and its own digest. Audit replay reconstructs the election and requires its exhaustive manifest to match, preventing debt, stale debt, closure risk, or regression from being silently duplicated or reassigned.

For numeric scores, `gapToTen.items` is a signed, ordered decomposition of the same operations. Its item sum must equal both `gapToTen.total` and exactly `10 - finalScore`; null-score gates mark the gap as not applicable. The legacy `rows`, `caps`, `subtotalBeforeCaps`, and `scoreAfterCaps` fields remain a presentation projection for current clients and are not authoritative score math.

## Issue Evidence Rules

Issue evidence uses per-issue proof with cluster-level weight deduplication:

- Classifier duplicate clusters and canonical proof aliases are unified by deterministic union-find grouping across debt, regression, closure risk, issue drilldowns, and profile evidence.
- Group representatives preserve the strongest adverse contribution rather than preferring a nominally stronger tier with a smaller effective penalty.
- LLM `duplicateCluster` may deduplicate weight only. It cannot establish field confirmation, increase reporter breadth, transfer exact-version locality, or promote another member of a mixed group.
- Hard release-local blocker debt requires an exact literal version in the persisted issue title, issue body, or complete cached comment text. The evidence records its source and snippet; comment evidence also records comment ID, URL, and author. Creation timing and classifier-only `affects_version` output remain auditable context but cannot promote a report into verified blocker debt.
- Issue state is release scoped. A report fixed in a later stable remains debt for older affected tags that do not contain the proven fix; its current global closed state cannot rewrite those releases as unbroken or move it into a second regression/closure penalty.
- Independent semantic reproduction comments establish human confirmation only when they make a concrete first-person or deployment-backed adverse claim, such as reproducing the failure, hitting the same failure signature, identifying another affected channel, or reporting a production data point. Vague "same problem" discussion, successful-workaround confirmation, and incidental "me too" text do not qualify. The author must be a non-bot other than the original reporter. `CONTRIBUTOR` reports and comments count as human evidence.
- `confirmationReasons` exposes the exact qualifying comment or label-event evidence. Source-only and `needs-live-repro` findings require independent human reproduction; labels alone cannot confirm them.
- Active `P0`, `P1`, `beta-blocker`, and `regression` labels can affect severity or confirmation only when their latest applicable label event at the release cutoff was applied by a non-bot actor. Bot-applied priority labels remain auditable but do not raise severity. Snapshot-only labels have no actor proof and cannot confirm. `P1` hard confirmation still requires a human-applied regression event and bug-shaped labels.
- `affectedUsers` is derived only from explicit population or configuration scope in issue/comment text. Prompt version 10 requires exact `{source_id, excerpt}` citations in `evidence.affected_users` for `many`, `some`, or `few`; `unknown` requires an empty citation array. Reporter identities, duplicate reports, comment volume, commenter counts, reactions, "+1", "me too", and reproduction volume are excluded from the classifier prompt as affected-user evidence.
- Raw comment counts, commenter counts, contributor counts, reporter counts, and reactions are retained for audit but do not change affected-user reach, debt, or regression weights.
- Human discussion affects scoring only through explicit semantic confirmation already recorded in `confirmationReasons`.
- Bot-only activity does not establish field evidence.
- Raw comment volume alone does not establish field evidence.
- `impact:security` alone is treated as a noisy keyword-stamped label; security/design dampening requires the explicit `security` label or other direct evidence.

The model deliberately separates:

- field-confirmed breakage
- inherited/carryover issue context
- weak or stale issue evidence
- incomplete classification coverage
- unresolved closed issues not counted for this release
- reachable fixes

Prompt version 10 requires every classification enum, rationale, and the exact `evidence` object keyed by all score-affecting fields. Known affected-user scope requires at least one exact `{source_id, excerpt}` citation from the included issue title, body, or comments; `unknown` requires an empty citation array. The model does not output `confidence` or `hasWorkaround`: the caller derives confidence deterministically from verified citation quality and derives `hasWorkaround` from `workaroundStatus`. Eligible citation-only grounding defects may be normalized by canonicalizing citations while preserving every model-selected classification value; provenance records the original and effective evidence plus normalization diagnostics. Missing, extra, invalid, inconsistent, non-JSON, or non-normalizable grounding output remains unscoreable and follows the bounded retry/rejection path. For every rejected mandatory field, the retry payload enumerates the exact values and source excerpts accepted by the deterministic validator; the replacement must choose from that list and keep mandatory citation identities distinct. Repeated unsupported values must change their evidence or value. A narrowly worded feature is not `niche` unless the cited text limits impact to a specialized or non-default population or setup. Every raw attempt remains in the classifier ledger. The response model and service tier must exactly match the request.

The classifier persists the exact validated model JSON before any deterministic label or title override. Raw rows are tagged `classification_origin=raw_model` and include response/request provenance, exact raw output, response ID, prompt-template hash, exact per-issue prompt hash, and raw-output hash. Legacy or manually written rows are tagged `legacy_or_manual`, keep `rawClassification=null`, and expose their values as `storedClassification`; they are never relabeled as raw. Deterministic label/title overrides run only while scoring or building proof with release-cutoff labels. `classificationDiff` records differences between the stored classification and the effective classification.

Issue-evidence schema v3 widens functionality to include `tooling` and retains schema v2's uncapped `evidenceCounts` beside the capped example arrays. Validation and audit tooling use those totals to detect truncated field/debt/fix evidence rather than comparing one capped list with another.

Debt evidence also records `installImpactClass`, `installImpactMultiplier`, and issue-ref scoring reasons, so damped provider/security/product-debt risks and inherited/carryover examples are auditable in the score explanation instead of being hidden inside the final weight. Stale or weak rows with concrete bug evidence, such as source-only/static repro plus impact labels, remain capped as `staleDebt`; they are not promoted to verified field-blocker debt.

If raw attributed issues exist without current classifications, the score explanation includes `incomplete_classification_coverage` with raw/classified counts, the missing count, the evidence-coverage ratio, the capped penalty, and example unclassified issue references when available. This makes coverage penalties explicit instead of hiding them inside the final score.

## Issue Open Intervals

Release attribution is based on issue open intervals, not a single created-to-final-closed span.

The initial open interval starts at `issues.created_at` and ends at the first fetched GitHub close event after creation. Each fetched `ReopenedEvent` starts another open interval, ending at the next fetched close event. If timeline evidence is missing, the scorer falls back to `issues.closed_at` rather than treating sparse history as open forever.

An issue is attributed to a release only when one of those open intervals overlaps the release's stable-to-stable reign window. This prevents reports that were already closed before a release from counting against that release merely because they were reopened later.

State-event evidence is stored as a verified counted and stabilized snapshot per issue. Fix-evidence batching is preserved, but each bounded attempt freezes separate first-response boundaries for the close/reopen, closed-by PR, and reference connections. Both sweeps request only the remaining rows needed to collect each frozen first-N prefix in deterministic connection order. Ordered identity and score-content digests must match across sweeps; state events additionally require contiguous connection ordinals and chronological connection order. A later append may increase `totalCount` without invalidating the prefix, and each connection snapshot records the frozen count, largest observed count, post-boundary growth, terminal first-N identity, and identity/content digests. Counts below the boundary, missing or duplicate first-N identities, terminal-identity drift, malformed cursors, count mismatches, or changed score-affecting event content fail closed. Mutable PR title, state, merge, and branch metadata does not participate in append-only stabilization and is refreshed through the dedicated PR metadata path. Each `issue_state_event_snapshots` row binds the accepted first-N state-event count, equal fetched count, normalized close/reopen event JSON, digest, projected `issue_closure_events` / `issue_reopen_events` rows, complete sweep count, and explicit stabilization flag. Legacy rows migrate with zero sweeps and `stabilized=0`, so they cannot be reused until refreshed. Missing or unstabilized snapshots, malformed equal-time identities, unstable ordering/content, digest drift, projection drift, or disagreement with the issue's current state blocks scoring.

GitHub `ClosedEvent.closer` is nullable for actor-attributed manual or administrative closes. Those events remain authoritative when the event and actor node identities are canonical; the closer fields remain null and create no direct PR or commit fix proof. A partially populated closer identity, or closer number/OID details without a canonical closer node ID and type, still fails closed.

`FULL_ISSUE_BACKFILL` is retained only as a compatibility and audit marker. Every score-producing refresh uses the same exhaustive catalog path and must establish complete required evidence before persistence.

After the two matching `CREATED_AT ASC` catalog sweeps, refresh writes an append-only staged catalog header and one immutable row per first-N issue before evidence processing starts. The header binds repository identity, source order, frozen terminal boundary, counts, capture time, membership/content digests, row-schema digest, aggregate row hash, and the prior snapshot hash; each row binds source ordinal, node ID, and the complete fetched metadata payload. A failed evidence/classification page therefore leaves a verified catalog that a later full backfill or prompt sweep can resume for up to `ISSUE_CATALOG_SNAPSHOT_MAX_AGE_HOURS` (default `24`) without repeating the network catalog scan.

Resume validates the complete snapshot chain, current row schema, canonical payloads, row count, row and aggregate hashes, membership/content digests, repository, and age. Required score-overlap rows still fetch current full issue metadata plus comments, labels, and state evidence; drift is reconciled before persistence. Rows created after the frozen boundary remain outside the staged as-of catalog and are collected by the next exhaustive refresh. Catalog staging alone never establishes `issue_crawl_exhaustive_baseline` or `backfill_completed_at`; every staged page must complete evidence and classification first.

Score persistence refuses ambiguous open-interval evidence. If a fetched reopen event has no preceding close event for that issue, the scorer cannot prove where the earlier open interval ended, so `persistReleaseScoreRun` refuses to write release rows or score audits until timeline evidence is complete. Score persistence also refuses ambiguous stable release windows when stable releases have missing or duplicate `published_at` timestamps.

`missing_evidence` closure rows never contribute closure-risk points and never apply the `8.4` or `7.9` closure ceiling. A negative closure row with otherwise score-affecting severity, functionality, scope, and reach makes the analysis incomplete instead. Persistence fails with explicit release, issue-number, and closure-status diagnostics until the missing proof is resolved. Known-not-in-release, open-canonical, and unsupported closure evidence retain their calibrated numerical treatment.

## Label Timing

Current labels can be misleading because labels may be added or removed after a release. The model persists GitHub `LabeledEvent` and `UnlabeledEvent` timeline items in `issue_label_events`.

Refresh fetches label timelines for every issue that overlaps the monitored release window, even if the issue no longer has current labels. Current-label and label-timeline GraphQL connections include `totalCount`, reject null nodes, duplicates, count drift, terminal count mismatches, and cursor anomalies, and paginate to exhaustion. Label timelines require two consecutive canonical sweeps over event ID, action, label, actor, and timestamp. Duplicate label event IDs are rejected across a batch, and an existing persisted event ID cannot be overwritten with different provenance.

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
  - a high-confidence closure/canonical comment names a fix/source commit, and that commit is reachable from the release tag commit.

Closed issues without a reachable merged PR or reachable named fix/source commit remain visible in audit evidence, but they do not reduce release risk.

The scoring query that supplies verified fixes is proof-row-only: it credits only `issue_closure_proofs.status = fixed_in_release` for the scored release tag. Raw linked PR reachability, closure comments, and commit references are inputs to closure-proof analysis; they are not a direct fallback path to scoring credit when the proof row is missing.

Closed-window fix credit is final-close based. If an issue closes during one stable's reign, reopens, and finally closes during a later stable's reign, only the later final close is analyzed for release fix credit. The earlier close is treated as a failed or superseded resolution attempt, not as a stable fix.

Reachability has three states: `reachable`, `not_reachable`, and `unknown`. `not_reachable` is only used when Git can prove exact non-ancestry with `merge-base --is-ancestor` exit status `1`. Missing release commits, missing PR merge commits, unavailable objects, and Git errors are stored as `unknown`; they never receive fix credit and remain auditable instead of being collapsed into proof that the fix is absent. Each persisted reachability row stores schema-versioned evidence with a known reason, the release tag commit, the checked PR merge/fix commit, base ref, and command diagnostics when a Git command determines the result.

Broad PR/commit mentions in comments are stored for audit context, but they do not reduce release risk. Comment-derived fix credit requires explicit closure/fix/provenance wording from a trusted source, such as a maintainer or the known ClawSweeper reviewer account, identifying the merged PR or fix/source commit that closed, fixed, or proves the reported behavior is present in the release source.

Comment proof uses the current body's effective timestamp: `updated_at` when the comment was edited after creation, otherwise `created_at`. That effective timestamp must fall inside the final closure window, and any edit after final closure is rejected. This allows a maintainer to append an auditable close rationale to an older review comment while preventing post-close edits from retroactively creating proof. Score-changing closure rationale is accepted only from an owner/member/collaborator, the issue reporter, the final closure actor, or the known ClawSweeper reviewer account. Language that keeps this issue open is never closure rationale; language saying distinct or separate reports remain open does not invalidate an otherwise explicit closure. A reopened issue cannot inherit PR/comment proof from an earlier close cycle. Canonical duplicate edges use the same trusted-author and close-window rules at every hop. When a closure names multiple canonical targets, every relevant branch must resolve before fixed credit is granted; an open or unresolved branch keeps the closure unresolved.

Closure-comment provenance is durable and directly reviewable. Matching comments persist their GitHub database ID, issue number, URL, author, timestamps, and capped snippet in closure proof evidence. Comment-derived PR links persist the source comment ID/URL beside the PR reference, and direct commit proof exposes a canonical commit URL plus source issue/comment context. If GitHub reports a referenced PR as missing, the reference is retained as `metadataMissing` evidence linked to the source comment instead of aborting the entire release; missing PR metadata never earns fix credit.

Because release PR reachability uses a global merged-PR candidate set, refresh first discovers canonical and comment-derived candidates across every monitored release, refreshes mutable PR metadata, and computes one complete reachability matrix. The matrix also includes the stable immediately before the monitored window as a proof boundary, without scoring or exposing that release.

Canonical closure resolution is transitive. Discovery follows trusted canonical edges at every hop, fetches terminal canonical issues that sit outside the source release window when required, and includes source issues, every reachable canonical issue, and terminal evidence-only issues in the analysis set. After proof construction, `release_closure_dependency_snapshots` stores that exact sorted issue set plus an analyzer version, row count, and digest over the release/commit, issue, classification, comment, state, label, closure/reopen, PR/commit link, PR metadata, reachability, and cross-release proof rows. Any dependency-set or digest change makes the proof stale and blocks score persistence until it is rebuilt.

Containment and bonus credit are separate decisions. A closure proof can be `fixed_in_release` because code is reachable from the target tag while still receiving no regression fix bonus. Each contained fix gets a persisted target/predecessor decision:

- `credited`: every trusted merged PR identity in the final closure proof has strict valid evidence, is `reachable` in the target, and is explicitly `not_reachable` in the immediate stable predecessor.
- `withheld`: target proof is missing, invalid, unknown, or not reachable; predecessor proof is missing, invalid, unknown, or already reachable; another trusted PR is already in the predecessor; or only direct-commit proof exists without a strict predecessor comparison.

Therefore `containedFixedCount` may be greater than `countedClosedCount`, and `containedNotCreditedCount` records that difference. Missing or unknown predecessor evidence never establishes first-containing credit. Proof construction and the final cross-release canonical stabilization pass reuse the same dependency snapshot and in-memory Git reachability cache. Score persistence is refused if any release still has missing, extra, stale, or mismatched reachability rows.

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
- `duplicate_to_non_actionable_canonical`: closure moved the report to a canonical issue that closed as non-actionable or non-bug evidence. A canonical terminal `not_planned` proof only qualifies when the terminal proof carries concrete non-actionable rationale; bare not-planned terminal proof remains unresolved closed-canonical risk.
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
- `not_planned_direct_fix_commit_reachability_unknown`: a negative report was closed with GitHub `NOT_PLANNED`, and trusted direct fix/source commit proof exists, but release-tag reachability for that commit is missing or unknown.
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
- `direct_fix_commit_reachability_unknown`: trusted direct fix/source commit proof exists, but release-tag reachability for that commit is missing or unknown.
- `closed_without_release_fix_proof`: no linked PR or fix/source commit proof was found for the closure.
- `no_timeline_event`: issue has `closed_at`, but no fetched GitHub close event.
- `non_bug_fixed_in_release`: non-negative item has release-reachable fix proof; it remains audit-visible but is not scored as bug fix credit.
- `non_bug_fixed_after_release`: non-negative item has fix proof that is not reachable from this release tag.
- `non_bug_direct_fix_commit_reachability_unknown`: non-negative item has trusted direct fix/source commit proof, but release-tag reachability for that commit is missing or unknown.
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

Those are effective scoring and presentation dispositions, not an unconditional projection of raw analyzer status. Raw closure text and raw closure-proof status remain diagnostic evidence. A status whose favorable treatment depends on a human claim is neutral only when the score-authority ledger contains the matching authorized immutable closure-claim candidate. `reporter_replaced`, `reporter_withdrawn`, and `reporter_self_closed` require the corresponding reporter-action claim. `not_planned` requires an authorized concrete non-actionable closure-rationale or reporter-action claim. `duplicate_to_non_actionable_canonical` requires both an authorized duplicate/superseded claim on the source issue and an authorized non-actionable claim on the canonical issue. When required authority is absent, the effective disposition is `unsupported_closure_claim`; it remains adverse, receives the normal positive closure-risk weight, and is counted and filtered under that effective disposition by the review API.

Raw prose saying that a release is not affected is also diagnostic only. Excluding an issue from release-local field evidence, debt, profile evidence, or score inputs requires an authorized immutable `release_local:not_affected` closure claim whose normalized release tag exactly matches the scored tag. The scorer records every such score-affecting claim in the authority subject ledger. Score construction resolves current immutable candidates and receipts; score-linked profile and closure-review reads replay the exact authority run sealed with that publication and reject a stored resolution that no longer matches its immutable candidate identity. This keeps the score, public profile evidence, closure review rows, effective dispositions, counts, filters, and risk weights on one authority policy without reinterpreting mutable raw text after publication.

Raw closure-proof status counts retain `known_not_in_release`, `open_canonical_risk`, `unsupported_closure_claim`, and `missing_evidence`, while weighted aggregation excludes zero-weight missing evidence, direct fixes, canonical release fixes, trusted release proof, and non-actionable closures. The scorer converts affirmative rows into deduplicated weighted candidates with the same effective historical classification path used by debt. The exclusive risk ledger then retains only closure groups elected for numeric closure-risk scoring, so `input.unresolvedClosureIssueCount` and `input.unresolvedClosureRiskWeight` describe the exclusive penalty contribution. Separately, `input.affirmativeClosureRiskCeilingWeight` records the complete deduplicated affirmative closure risk before channel election and drives the `8.4`/`7.9` ceilings at weights 40/60. `missing_evidence` is excluded from that field and instead makes analysis incomplete.

The API exposes a coherent `releaseFixCredit` object:

- `countedClosedCount`: closed issues counted as release fixes.
- `notCountedClosedCount`: final-closed issues in the release window not counted as release fixes.
- `analyzedClosedCount`: total final-closed issues analyzed for the release window.

The invariant is `countedClosedCount + notCountedClosedCount = analyzedClosedCount`.

After closure proof analysis, the same complete `closureProof` and `releaseFixCredit` payload is included in the next `release_score_audits.gate_evidence_json` written by score persistence and exposed through `/review`. The widened closure-proof payload is schema v2; the release-fix-credit payload remains schema v1. Proof rows are staged before replacement, and replacing `issue_closure_proofs` happens inside one DB transaction. Closure-proof analysis is side-table-only by default. Refresh and a full monitored closed-window backfill attach proof payloads and source identity only in the final complete-window score transaction. One-tag manual proof commands remain explicitly staged-only, so they can repair analyzer-v8 evidence without replacing unrelated score/audit rows or recording a misleading score failure. Releases with zero proof rows persist an explicit zero-count closure-proof payload instead of leaving a stale previous payload in place. The scored input stores the exclusive closure contribution after cross-channel deduplication; the raw closure proof summary remains available for provenance.

Closure authority comes from exactly one normalized close event: the latest event by parsed timestamp, then by `connection_ordinal` for equal timestamps. The selected event must exactly match `issues.closed_at`; nearby close events are never aggregated for state reason, actor, PR, or commit credit. Contributor comments are trusted for rationale and PR/commit proof only when that contributor is the selected final closure actor. Cross-release fallback proof is usable only when its row has the current closure-proof analyzer version and its release dependency snapshot still matches current evidence. Direct closure-proof patching of an existing current audit is disabled; production writers must rebuild and seal the complete score run.

Closure proof evidence must cover every raw closed issue in the release window before scores can be persisted or verified. The guard rejects missing proof rows, extra proof rows outside the release window, and proof rows older than their dependency evidence, including issue rows, classifications, labels, closure/reopen events, PR links, commit references, PR metadata, and release PR reachability.

Closure proof examples are selected after risk weighting and sorted by descending `riskWeight`. They expose raw classification, effective classification, classification diffs, effective labels, current labels, label source/cutoff provenance, per-issue risk weight, and human-readable labels for machine risk enums so reviewers can see which deterministic overrides affected closure-risk scoring without decoding internal names.

Each release review also exposes `dataFreshness`. `scoredAt` is when the score/audit payload was computed. `issueUpdatedAtMax` is the newest GitHub issue `updated_at` value included in the release issue universe. `issueUpdatedAgeHoursAtScore` makes that semantic GitHub gap explicit, while `issue_fetches` records when those issue rows were last fetched/written locally. Issue rows persist the full GitHub body. `issue_comment_snapshots` records fetched comment counts, latest comment update time, a digest, the matching issue `updated_at`, and a complete cached comment payload. Missing, malformed, incomplete, or stale comment payloads fail scoring closed because comment text participates in human confirmation and exact-version locality.

Every score run computes source identity schema v17 over explicit ordered columns from 32 sources: release and commit metadata; advisories and their legacy/current stabilized snapshots and rows; issues, classifications, verified comments, label events and stabilized label evidence; collaborator-permission and signed-maintainer authority evidence; closure-claim source snapshots, candidates, extraction receipts, and receipt membership; closure proofs, close/reopen events, and stabilized state snapshots; PR links, commit references, PR metadata, release reachability; release closure dependency snapshots; and the release artifact receipt projection. Issue rows bind canonical issue and author node identity plus author type. Closure and reopen identities include connection ordinal plus canonical issue, event, and actor identity; closure identities also include canonical closer identity, state reason, raw payload, and fetch time. State snapshots bind issue identity, event authority digest, complete stabilization proof, and projection rows. PR inputs bind PR and repository node identity and raw evidence. Schema v17 also binds the code revision and effective scoring configuration. Semantic manifest validation retains immutable schema v5-v16 history while current score production remains schema v17. Comparison tables, validation ledgers, derived authority runs, and score-output columns remain excluded. Score construction streams each ordered SQLite statement with `Statement.iterate()` so peak memory is independent of source-table size, computes identity before and after analysis, and persistence recomputes it inside the write transaction.

Refresh records issue crawl schema v4 in `meta.issue_crawl_last_run`, including repository identity, crawl mode, frozen boundary and observed counts, post-boundary growth, fetched and unique counts, page/sweep counts, membership/content digests, stability state, last requested and next cursors, stop reason, the embedded exhaustive baseline schema v2, pagination schema v2, metadata-only issues observed, required comment-snapshot issues requested, truncated required-comment scans, evidence failures, and whether score persistence happened after that crawl. Complete and prompt sweeps persist basic remote metadata for every accepted first-N issue, but fetch comments, label timelines, and state evidence only for issues whose lifetimes can overlap monitored release windows. Later closure reconciliation fetches complete comments and state evidence for every direct or transitive closure dependency, including canonical issues outside those windows. A required comment failure records the requirement and issue coordinates in durable provenance and blocks scoring; a metadata-only row does not require a comment request. The default issue cap is 4,096 pages and the GraphQL connection guard is 8,192 pages; either guard fails closed before truncation can be scored.

If release metadata cannot be fetched, refresh writes `stopReason: "evidence_failure"` and refuses scoring. It also refuses when the fetched release window lacks enough stable releases. Crawl metadata retains release-metadata/artifact/release-check/advisory/monitored-release evidence refresh failures. If artifact verification, release commit checks, advisories, closure evidence, PR reachability, or closure-proof refresh fails, score persistence remains blocked. Truncated comment scans are treated as score-blocking incomplete evidence for every issue whose comments are required.

Closure-proof refresh does not patch existing `release_score_audits`; matching proof payloads are attached only by the final score transaction after all evidence succeeds.

During refresh, issue-page write failures are recorded as `issue-page-write`, rolled back, and score-blocking. Page classifications are also staged in memory and written in one transaction before the page is accepted.

The shared refresh/write lease has a five-minute TTL with a one-minute heartbeat. Refresh, manual proof commands, comment/state backfills, closed-window backfills, and standalone reachability writes use that same renewable lease. State backfill also validates staged issue evidence revisions before its transaction; standalone commands perform post-commit lease checks so a lost lease is detected and reported with the correct commit state. A crashed holder therefore stops blocking recovery after at most five minutes, while `SIGINT` and `SIGTERM` release a live holder before closing the server and database.

Refresh operation provenance is durable and separate from mutable status fields. Once the lease is acquired, refresh computes one dirty-aware code revision and `refresh_operation_attempts` immediately records it with the immutable run ID, operation/trigger, start time, lease holder/expiry, and secret-free effective configuration before any network request. The same revision is passed through score persistence, forecast capture, and receipt creation. `refresh_operation_stage_events` is an append-only per-run SHA-256 chain containing started/completed/failed lifecycle events with timestamps, durations, optional counts, and bounded failure details; no new event may follow a terminal receipt, and non-abandoned terminal runs must close every started stage. `refresh_capture_receipts` is a globally hash-chained terminal ledger with exactly one success, failure, or abandoned result per attempt. A new lease holder appends `abandoned` receipts for expired unterminated attempts; it never edits those attempt rows. After score construction, refresh performs a new complete stabilized release-catalog fetch and refuses publication unless its remote digest/counts exactly match the initial catalog and its publication-ordered projection exactly matches the active local catalog and latest stable identity.

Operators can inspect that ledger without mutating it. `/api/status` schema v1
exposes the active run ID when this process is refreshing, the latest attempt and
terminal receipt, the latest success and failure receipt/run IDs, and the receipt
that currently authorizes or rejects the score tip. Authorization status is
`authorized`, `unauthorized`, `missing`, `not_required`, or `unavailable`.
`GET /api/receipts?limit=` and `GET /api/receipts/:receiptId` schema v1 execute in
one stable SQLite read transaction and return normalized attempt metadata, ordered
stage events, explicit success/failure/abandoned terminal payloads, content-chain
hashes, score-history run/hash links, forecast decision IDs, and receipt-ledger
verification. Detail lookup accepts either the receipt ID or run ID. The list limit
defaults to 10 and is strictly bounded to 1-25; list/detail stage arrays and JSON
payloads have separate hard caps with explicit truncation flags. Attempt effective
configuration and lease-holder IDs are omitted, and all stored strings, nested
credential-like fields, and verification diagnostics are redacted and bounded
before serialization. Receipt and status responses use `Cache-Control: no-store`.

SQLite indexes `issues(created_at)` and `issues(closed_at)` support the measured release-window range predicates used by opened/closed issue queries. Doctor verifies both index definitions and checks `EXPLAIN QUERY PLAN` output for the corresponding range scans.

Every score write also records `meta.score_persistence_last_run` schema v2 in the same transaction as release rows and `release_score_audits`. The record captures the writer source, scope, release tags, recommended tag, model/prompt versions, score timestamps, issue-crawl coordinates/digest, score-source identity schema/digest/counts, the sealed history run ID/tip, the startup code revision, forecast preflight plan, and refresh catalog attestation/receipt requirements. Each current audit is appended to `release_score_audit_history` under an ingestion-linked, retry-idempotent run ID; the complete canonically ordered row set is then sealed in `release_score_audit_history_runs` and linked to the previous run seal before a validation forecast may reference it. History rows and run seals have no cascade-delete relationship to current release rows, and SQLite triggers reject updates/deletes. API publication is actionable only when the mutable current audit exactly matches its row in that recorded run, the run is the valid current tip, the history manifest is semantically valid, no score-affecting negative `missing_evidence` remains, and a refresh-written tip has a non-bypassable success receipt. Authorization validates the attempt and full stage/receipt chains, code revision, catalog attestation, authoritative issue/advisory digests, exact forecast eligibility/capture set, and score-history link. `auditDigest` binds the sealed run/content identity and exact history row. Doctor applies the same current-tip receipt requirement and still fails on drift in the exact release-tag set, model version, prompt version, or source identity.

Successor startup recovers an unactionable failed, abandoned, or receiptless score tip only after any receiptless attempt has an immutable `abandoned` receipt. It may restore the newest earlier successful refresh publication only when every later history publication forms an ordered suffix with an exactly aligned history-v2 seal, linked authority run, matching publication timestamp, refresh attempt, and terminal `failure` or `abandoned` receipt. Successful or non-refresh publications cannot be skipped. Recovery metadata uses `publicationRecovery.schemaVersion = 3` and stores restored identities, latest displaced aliases, every ordered displaced publication binding, `displacedPublicationCount`, and a domain-separated SHA-256 `displacedPublicationDigest`. Standalone authority records are excluded from the publication suffix, while linked authority runs must remain ordered in the authority chain. The API, doctor, and sealed-publication reader recompute the suffix and reject count, digest, binding, receipt-ledger, history-chain, authority-chain, or history-v2-chain drift.

Before score durability, refresh inspects every non-expired revision-aware capture slot. A semantically equivalent existing schema-v4 row is reserved as `already_captured`; a conflicting or legacy v1-v3 row aborts before a new score tip exists. The score/history transaction then completes. Its injectable wall/monotonic clock records integer-millisecond `commitNotBefore` and monotonic-normalized `commitNotAfter` bounds; a backward wall clock is normalized by elapsed monotonic time, while a regressing/invalid monotonic clock fails closed after score durability. Forecast eligibility uses `commitNotAfter`, never the history timestamp. A separate short transaction binds the commit timing into score metadata, appends eligible empty-slot forecasts, and appends the success receipt. The receipt links the score-history run/content hash, exact release tags and recommendation decisions, authoritative issue/advisory metadata digests, schema-v4 catalog attestation, and exact `eligible_and_captured`, `already_captured`, or `not_eligible` decision sets. If that transaction fails, no forecast or success receipt is retained; failure provenance and a failure receipt are appended separately, while the already committed score remains semantically blocked after restart.

Score persistence atomically replaces the monitored score window. Manual writers derive that complete window from `score_persistence_last_run.releaseTags` when it exists, retaining audited null-score `wait` releases; a CLI `--tags` or `--limit` selection is only an evidence-mutation scope and is never used as a partial replacement window. Releases outside a valid complete run retain release metadata but have score outputs cleared and their old score-audit rows deleted before the new monitored rows are written. Historical release metadata therefore remains available without mixing stale source identities into the current audited score set.

GraphQL nested evidence connections are treated as required provenance, not optional decoration. Missing `nodes`, null nodes, missing `pageInfo`, or a `hasNextPage` page without `endCursor` fails ingestion for score-affecting release pages, issue pages, issue labels, comments, label timelines, fix evidence, release check contexts, and advisory pages instead of being interpreted as empty evidence.

`ingestion_evidence_failures` is append-only provenance for score-blocking fetch failures. It records the refresh run id, source, scope, optional release/issue/PR coordinates, message, context JSON, and occurrence timestamp so failed evidence pulls remain auditable even when refresh exits before it can complete normal crawl metadata. Manual command scopes are canonical hashes of the exact release/issue set. A successful stage supersedes only rows matching the exact source, scope, release, issue, and PR tuple; skipped proof, reachability, or score stages do not supersede those failures.

GitHub partial responses for missing issue aliases are recovered only when a caller provides an explicit missing-alias reporter. During refresh, each skipped alias is recorded as a score-blocking ingestion evidence failure, and scoring is refused rather than treating that issue's comments, labels, or fix evidence as empty. Other callers fail closed on the GraphQL error.

Refresh recomputes closure proof automatically for monitored releases. The refresh path writes proof rows with score-audit payload persistence disabled and relies on the subsequent score transaction to attach the matching proof payload. The one-tag manual provenance commands rerun the same analyzer-v8 proof pass for a specific tag, keep proof writes side-table-only, validate crawl schema/baseline before mutation, and return an explicit staged-only result. They do not attempt a partial score replacement. A successful rerun clears only its exact prior failure tuple; a full monitored `backfill:closed-windows -- --all` run rebuilds converged proofs and performs the complete score commit.

PR reachability is staged before replacement. Refresh queries the global candidate set once, checks the persisted matrix for exact candidate/tag/commit freshness and evidence semantics, probes only required Git objects instead of inventorying the entire object database, fetches each missing object through a serialized retry-safe lane, and runs read-only `merge-base --is-ancestor` checks with bounded local concurrency and command time/output limits. Every release row set is prepared deterministically before one atomic replacement transaction. A valid unchanged matrix is reused without touching `checked_at`. Run-level Git evidence failures abort before deleting old reachability rows; refresh records them as score-blocking evidence failures, and the standalone reachability command records a durable `ingestion_evidence_failures` row before exiting.

PR reachability evidence must cover the current merged linked-PR candidate set before scores can be persisted or verified. For each scored release, the guard requires every current same-repo merged linked PR to have a reachability row, rejects extra rows outside that candidate set, rejects rows older than current PR metadata, and rejects rows whose release-tag commit, merge commit, base ref, status, or schema-versioned evidence no longer matches current release/PR evidence. Link-row refetches alone do not force reachability stale; new or removed linked PR candidates are covered by the missing/extra row checks.

Closure evidence refresh also stages comment-derived PR lookups before replacing link rows. A per-issue refresh state binds raw evidence to the issue `updated_at`, validated comment digest, and evidence schema version. Unchanged complete dependencies reuse existing raw evidence; any issue update, incomplete comment payload, digest mismatch, or schema change forces a refetch. Raw closure evidence and comment-link replacement delete and insert their affected link rows inside DB transactions, so failed PR detail fetches do not first wipe prior link evidence. Trusted closure-comment PR mentions fail closed when GitHub cannot resolve the named PR; missing PR metadata is treated as incomplete provenance, not absence of a fix candidate.

`backfill:issue-state-events` holds the shared renewable lease and fetches all GitHub fix/state evidence before writing label snapshots, closure events, reopen events, PR links, or PR rows. After fetch succeeds, it checks the staged issue/comment/state/classification revisions and writes the full snapshot/event/PR batch in one DB transaction. Missing aliases, fetch failures, races, or write failures are recorded in `ingestion_evidence_failures`. Exact successful chunks/writes supersede only matching failures, and a post-commit lease/recovery failure reports that the evidence was committed instead of claiming rollback.

For historical audited releases, `npm run backfill:closed-windows -- --all` validates crawl schema v4 and the exhaustive baseline schema v2 before its first evidence mutation, classifies raw closed-window issues that are missing current classification rows, stages every classification result in memory, writes the staged classification set in one DB transaction, then reruns closure evidence, PR reachability, and closure proof. Because rebuilding an older release can change cross-release dependencies of a newer release analyzed earlier in the pass, the backfill repeats proof construction to the same bounded fixed point used by refresh. Score persistence is allowed only when the selected proof scope covers every release in the complete persisted monitored window, including audited null-score waits. Scoped `--tags`/`--limit`, `--skip-proof`, and `--skip-score` runs return staged-only and leave every score/audit row untouched. Stage recovery is exact, so skipped stages cannot clear proof, reachability, or score failures. Manual score writers share the same clean-ingestion guard: before writing scores, they refuse missing or malformed issue crawl schema v4, an invalid or repository-mismatched exhaustive baseline schema v2, boundary/count/growth/cursor/digest inconsistencies, a partial crawl mislabeled complete, page-cap or evidence-failure stop reasons, recorded evidence/classification failures, durable ingestion failure rows newer than the latest score, or any durable score-blocking ingestion failure before the first score.

The release audit verifier checks both aggregate counts and proof shape, including full 40-character commit IDs, reachable/not-reachable commit arrays, and consistency between commit proof rows and their summary booleans.

Run the audit invariant verifier after refreshes:

```bash
npm run verify:local
npm run verify:live
npm run verify:score
npm run verify:release-audit
npm run ui:smoke
```

`verify:local` and `verify:live` run score and release-audit checks in `--all` mode, covering every scored stable release rather than only the newest display window. `verify:live` first requires HTTP `200` liveness with `status: "live"` and HTTP `200` semantic readiness with `status: "ready"` and every check `ok`, before doctor or any other API/UI verification. Its browser smoke always covers recommendation, stale-analysis isolation, non-overlapping release rows, desktop, and mobile behavior. Advisory-gated, eligible non-recommended, and fix-credit link examples are optional dataset coverage and are reported as passed or skipped with an explicit reason.

Quality DB promotion repeats the production gates against the final staged database before any swap: doctor with warnings fatal, full score recomputation with `--all`, full release-audit invariants with `--all`, and exact replay of the latest immutable prospective-validation evaluation receipt. The latest receipt must recompute to the same evaluation ID/content hash and have status `validated`; insufficient, failed, missing, older, or drifted evaluations cannot pass. Promotion records a production receipt bound to that exact evaluation plus source and destination logical database digests. Calibration receipts are retained as evidence but cannot authorize production. A dry-run creates the receipt only in its disposable stage and cannot authorize a later apply.

Promotion merges append-only refresh attempts and stage events by exact identity, preserves the destination capture-receipt chain as the promoted prefix, appends source-only receipts with valid new chain links, and rechecks the full receipt ledger. It also re-snapshots the live source after staging and at the final swap boundary to reject inode or logical-content drift, and checks holders plus active refresh leases before success and around automatic rollback. This rejects internally consistent obsolete-model or wrong-arithmetic candidates while retaining history-extension tip reconciliation and automatic rollback behavior.

## Release Checks

The model reads the release tag commit's GitHub `statusCheckRollup`.

- Successful checks add a small capped confidence bump.
- Pending checks add a small penalty.
- Failed checks add a larger penalty.
- Missing check data is neutral.

The audit payload stores check state, complete check counts, `contextCount`, `shownContextCount`, `contextsTruncated`, and a capped example list of check contexts. Before applying the cap, contexts are ordered deterministically with failed/error/action-required checks first, pending checks next, successful checks after them, and neutral or unknown checks last. Adverse contexts therefore displace successful examples at the cap. If aggregate counts or state are adverse but the stored context payload contains no matching adverse context, successful-only links are suppressed instead of presenting contradictory evidence beside a score penalty.

## Artifact Verification

Release notes are parsed for:

- npm package URL
- registry tarball URL
- package integrity
- release SHA
- full release CI report URL

The model downloads the npm tarball and verifies the retained registry evidence against the release notes:

- registry version
- canonical tarball URL
- exact SRI digest over the downloaded tarball bytes
- tarball byte count and supported digests
- registry `gitHead`
- release integrity, tarball URL, and release SHA binding
- release tag commit identity

It also checks whether the linked release evidence report exists and is non-empty. A verified npm artifact adds confidence. A missing linked evidence report offsets part of that confidence instead of being treated like an npm integrity mismatch.

If the markdown evidence report link is missing but the release notes include a successful GitHub Actions `full release validation` run with a non-expired artifact, the scorer treats that action artifact as fallback release evidence. The original report URL and fallback action URL remain exposed in `gateEvidence.artifactVerification`.

Every persisted artifact gate carries the canonical release, release metadata,
artifact evidence, evidence-report result, `runId`, `observedAt`,
`observationId`, `receiptId`, `evidenceIdentity`, `evidenceReportIdentity`,
the receipt and observation content hashes, and both ledger predecessor hashes.
The score-audit verifier rebuilds the schema-v2 receipt and observation,
replays the artifact facts, checks the release tag/OID/SHA bindings, and
requires every flat compatibility field to match the nested immutable proof.
Missing, partial, malformed, non-replayable, or score-input-divergent proof
invalidates the score audit. Artifact confidence is awarded only when the
current release commit binding is explicitly proven true.

`gateEvidence.releaseChecks.schemaVersion` is the release-check contract version. Current value: `2`. `gateEvidence.artifactVerification.schemaVersion` is the artifact-verification contract version. Current value: `2`.

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

`components.explanation` is the stable assessment-details contract:

- `schemaVersion`: explanation contract version. Current value: `5`.
- closure proof PR references retain repository, source, merge/reachability metadata, and source-comment links where available.
- `scoreLedger`: required immutable `ScoreLedgerV2`. Its ordered operations, exhaustive evidence manifests, alias election, advisory counterfactual, predicates, clamps, caps, rounding, digest, and exact `gapToTen` reconciliation are authoritative. `rows` and `caps` are compatibility projections only.
- Compatibility validation covers ledger row keys, labels, order, cap keys, and cap order; a display renderer must not silently reorder or relabel those projections.
- `positives`: human-readable favorable evidence lines.
- `positiveDetails`: machine-readable entries aligned 1:1 with `positives`.
- `limits`: legacy human-readable detail lines. Public renderers must not place zero-impact entries under score-lowering or score-limiting headings.
- `limitDetails`: machine-readable entries aligned 1:1 with `limits`. Entries with `metrics.scoreAffecting: false` are context only; inherited carryover context must be rendered separately from score-affecting limits.
- `verdict`: install-facing interpretation of the score.
- `recommendationDecision`: validated recommendation policy, threshold, recency tolerance, selected/highest-scoring releases and scores, ranks, score deltas, and decision reason.

The issue-evidence tier `verifiedFixed` is presented as **Contained release fixes**. Containment proves the fix is in the tag; only the subset with strict target/predecessor proof is first-containing and credited in regression. The `openedFeltSerious` drilldown contains the exact exclusive representatives and weights used by the regression component, so its counts match persisted explanation metrics instead of re-running a broader opened-issue filter.

Each detail entry has a stable `code`, mandatory canonical `label`, matching `text`, and may include `metrics`, `buckets`, and `issueRefs`.

`/api/releases/:tag/review` exposes `local.input.schemaVersion` (current value: `2`) and `local.components.schemaVersion` (current value: `1`).
`/api/releases/:tag/review` exposes `local.schemaVersion`. Current value: `1`. `/api/public` and `/api/releases` expose `scoreAudit.schemaVersion`. Current value: `2`.
`/api/releases/:tag/review` also exposes `local.issueEvidence.schemaVersion`. Current value: `3`.
The internal `/api/comparison` payload, upstream row, and delta objects also expose `schemaVersion`. Current value: `1`.
Comparison snapshots are internal calibration artifacts. They are validated before insertion, stored outside local score/audit rows and source identity, and must not be used as local audit-backed evidence or shown in product UX. Calibration snapshot names, source URLs, rendered text, deltas, and upstream identities are internal-only data and never become product copy, recommendation inputs, or score-source identity.
The `/api/status`, `/api/config`, and `/api/receipts` list/detail payloads expose
`schemaVersion` `1`.
Receipt list/detail responses also expose `validationProof`, a time-aware summary
of canonical proof integrity, active epochs/cohorts, current evaluation,
production promotion, latest calibration promotion, and production
authorization. Production authorization requires one active proof epoch, a
current `validated` evaluation, and a production promotion receipt bound to its
exact evaluation ID and content hash.
The `/api/releases/history` rows expose `schemaVersion`. Current value: `2`.
The `/api/public` payload and `/api/public` release rows expose `schemaVersion`. Current value: `4`. Public release `profileEvidence.schemaVersion` current value: `2`; it is derived from the full release issue-evidence projection, not from capped public issue summaries. `/api/releases` rows expose `schemaVersion`. Current value: `2`.
The `/api/releases/:tag/review/issues` issue-evidence audit payload and `/api/releases/:tag/review/closure-proofs` closure-proof audit payload expose top-level `schemaVersion`. Current value: `2` for both.
When a public or review release is bound to a sealed score publication, profile evidence and closure-proof pagination use that publication's exact authority run. Audited profile evidence uses `sourceMode: "sealed_score_replay"` and carries a content-hashed publication binding over the profile-row digest, audit digest, authority run ID/content hash, history-v2 seal, score source identity digest, score model version, and prompt version. Unscored or stale profile evidence uses `sourceMode: "current_diagnostic_evidence"` and cannot claim a publication binding. The raw closure-proof `status` remains visible for diagnosis, while `riskDisposition`, risk weights, aggregate disposition counts, and disposition filtering use the authority-adjusted effective disposition.

## Prospective Validation

Validation is prospective only. `first_verified_after_3h` is bounded to release age `[3h,6h)` and `first_verified_after_24h` to `[24h,30h)`. Integer-millisecond start is inclusive and end is exclusive. A first score observed at 25 hours records only the 24-hour opportunity; it never backfills the missed 3-hour decision. New forecast writes accept only decision schema v4, which persists observed time/age, both opportunity bounds, score commit bounds, sealed history run/hash, and final catalog attestation. History and forecast timestamps may differ. Legacy v1-v3 forecasts remain immutable and readable but are excluded from observation, current-stratum selection, and evaluation regardless of timing.

Each forecast retains the complete candidate audit snapshots, selected tag, recommendation decision, model/prompt/policy versions, source identity, history run ID/content hash, commit timing, catalog attestation, and code revision. The catalog attestation is covered by the forecast content hash and records initial/final remote digests, counts and sweep metadata, `finalObservedAt`, projected/local active catalog digest/count, latest stable node/tag/`publishedAt`, and `scoreBuiltAt`. New captures require a normalized deterministic revision: a validated build/provider identity is preferred, while local runs derive a Git identity that includes a digest of tracked and untracked dirty state. Offline/manual score writers do not capture forecasts. The nullable schema and null-series index remain only so legacy rows stay readable; null revisions never count as the current stratum.

The revision-aware unique series key is a capture slot. Preflight validates an occupied v4 row against its own immutable history and compares its score/recommendation/evidence semantics with the pending run while excluding attempt-specific timestamps and run IDs. Equivalent occupancy returns `already_captured` with the existing decision ID and no new row. Any semantic difference, corrupt prior row, or occupied legacy slot aborts before score persistence. Empty eligible slots return `inserted`. A crash after score commit but before the final transaction leaves no retrospective forecast; the current score tip remains unauthorized until a matching success receipt exists. Current monitoring and evaluation require the same normalized concrete revision and never infer one from legacy ledger rows. Source digests remain provenance only and never form the business key. Startup migration preserves existing forecast IDs, hashes, chain links, and outcome references.

`npm run validation:observe` considers two outcomes independently:

- `field_regression_72h`: issues first created after the forecast and inside the 72-hour window, evaluated from complete raw issue/comment/label/fix evidence. A validating adverse outcome requires exact selected-version linkage in the title, body, or an unedited in-horizon comment plus either a non-bot human confirmation comment/human-applied adverse label or trusted later fix/hotfix proof. Exact issue, comment, label-event, PR, and commit references are persisted. Score buckets and classifier output are only a non-validating proxy.
- `security_30d`: medium-or-higher advisories published after the forecast and inside the 30-day window, matched against the earliest post-horizon compound advisory v2 projection authorized by a hash-valid successful atomic publication receipt.

An outcome is appended only for a schema-v4 forecast recorded inside its bounded opportunity when a complete post-horizon crawl, score persistence record, source identity, matching sealed score-history audit, and any required immutable advisory snapshot exist. New security observations never consume raw legacy advisory tables, the mutable active projection, or intact-but-unreceipted staged v2 rows. The operation receipt ledger must verify before any v2 authorization is trusted; malformed bindings, duplicate authorizations, missing snapshots, and invalid publication timing fail closed. Security payloads retain the snapshot schema and ID, source/catalog/score hashes, ledger and projection digests, complete metadata, and authorizing receipt/run identity. Legacy schema-1 snapshot evidence remains available only to replay already-recorded historical outcomes. New outcomes can be written only through one atomic observation-batch commit; the standalone outcome writer is disabled. At commit, the v2 receipt must still match every current forecast decision ID and content hash, and every inserted outcome must carry the receipt's current score-source digest. Legacy v1-v3 and timing-invalid v4 forecasts are reported as excluded before observation and never receive new immutable outcome rows. A complete exact-version crawl through the horizon with zero independent adverse evidence yields `observed-safe`, including for an older selected release. Missing comments, incomplete crawl metadata, malformed/future timestamps, or incomplete proof coverage remain censored. Field observations have a 24-hour grace period; security observations have seven days. Later knowledge cannot backfill a missed observation window. V2 receipts wrap their canonical result set with exact forecast inputs and inserted-outcome references; evaluation unwraps that envelope, and the ledger may never regress to v1 after the first v2 receipt.

Evaluation is decision-level. It retains native, older-selection, adverse, and parallel-model decisions before dependence analysis. By-model metrics are computed from each model's own cases, paired comparisons use the same latest release/opportunity/horizon where available, and a separate maximum-non-overlapping sensitivity is reported. Release-cluster percentile bootstrap intervals account for repeated decisions on one release; validation is refused when unique-release count or power is inadequate.

The production minimums are 20 decision cases, 20 unique release clusters, and 20 each of recommended, withheld, adverse, and safe cases. Sample sufficiency is necessary but never sufficient. The current model/prompt/revision stratum must also meet: recommendation precision 95% cluster-bootstrap lower bound `>=0.70`, false-safe upper bound `<=0.30`, accuracy lower bound `>=0.60`, and safe-vs-adverse AUC lower bound `>=0.65`. Once the sample is otherwise sufficient, a missing or non-finite AUC fails validation rather than being treated as passing. Score bins are labeled empirical discrimination, not probability calibration. `validated` exits `0`, `insufficient` exits `2`, and `measurable_but_failed` exits `1`; ledger or fatal evidence failures also fail with exit `1`.

The canonical proof ledger is epoch-scoped. Each epoch fixes the policy,
cohorts, authenticated first-seen catalog order, immutable development/holdout
assignments, every required opportunity-by-horizon obligation, forecasts,
outcomes, and exact-set observation batches. A release first seen after a cell
closed is retained as `late_missed`; a release or cohort is never silently
removed to improve the denominator. Epoch retirement is effective only at its
recorded retirement time, so historical evaluation retries continue to resolve
against the epoch that was active then.

`npm run validation:evaluate` is read-only. Use `npm run
validation:evaluate -- --record` after the final candidate writes to append the
immutable evaluation receipt. `--evaluated-at <ISO timestamp>` makes scheduling
and retries deterministic. `--require-recorded --evaluated-at <ISO timestamp>`
is the promotion replay mode: it performs no write and requires the exact
receipt to already exist. Evaluation and promotion receipt inserts are
idempotent by canonical identity and reject conflicting reuse.

`npm run validation:snapshot -- --output <file>` can atomically export the forecast ledger for review. It does not create forecasts or reconstruct historical decisions.

## Validation Commands

Normal iteration is `npm run test:preflight` only when the installer changed, `npm run test:focus -- <manifest-test-file> [--name <pattern>]`, optional `npm run test:focus -- --authoritative <manifest-test-file> [--name <pattern>]`, then `npm run verify:ci`.

```bash
# Run only when the installer changed.
npm run test:preflight
npm run test:focus -- src/lib/example.test.ts
# Optional focused validation through the authoritative sandbox and audit path.
npm run test:focus -- --authoritative src/lib/example.test.ts
npm run verify:ci
npm run verify:local
npm run verify:live
npm run analyze:closure-proofs -- v2026.6.10
npm run validation:snapshot
npm run validation:opportunities -- --db-path /path/to/radar.db
npm run validation:observe
npm run validation:evaluate
npm run validation:evaluate -- --record
curl http://127.0.0.1:8787/api/releases/v2026.6.10/review | jq
```

Run the full gate once, after implementation stabilizes and before push or deploy: choose either `npm test -- --full` or `npm run test:baseline -- --full`, not both.

Baseline acceptance is separate: review the generated candidate, then run `npm run test:baseline:accept`.

`verify:ci` is the portable typecheck, script-syntax, and build gate. The
deployment workflow runs `verify:authoritative-ci` on macOS, which runs
`test:safety` and forces fresh full non-accepted candidate generation with
`npm run test:baseline -- --full --rerun`. Validation runs are serialized.
Full test runs require the explicit `--full` flag, and each entrypoint rejects unsupported forwarded arguments. `npm test -- --full` uses one worker, enforces a bounded timeout for
every test, caps isolated worker/SQLite footprints, and forbids `VACUUM` in
tests. Raw VM disk operations are outside this repository workflow. Repository
work must not attach, mount, inspect, or mutate raw VM disks. Use named npm
lifecycle commands for database work; the exact app runtimes are `tsx watch
src/index.ts` for development and `NODE_ENV=production node dist/index.js` for
production. Eval,
print, stdin, and custom import scripts must use an explicit fresh private
`DB_PATH` and an empty `DOTENV_CONFIG_PATH`, never the configured live database.
