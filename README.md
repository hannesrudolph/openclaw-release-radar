# OpenClaw Release Radar

OpenClaw Release Radar is a small dashboard that answers:

> Which OpenClaw stable release should I install right now?

It watches `openclaw/openclaw`, pulls releases, issues, comments, and advisory data from GitHub GraphQL, classifies issue impact with OpenAI, stores the result in SQLite, and serves a local web UI plus JSON API.

The score is a triage aid, not a guarantee. Inspect `/api/releases/:tag/review` before acting on a recommendation.

Recommendations require an eligible score of at least `7.0`. The policy prefers the newest release only when it is within `0.5` points of the strongest eligible score; otherwise it selects the materially higher-confidence release. The exact decision and score comparison are persisted in each release audit.

The API fails closed unless the mutable current audit exactly matches its row in the sealed history run recorded by `score_persistence_last_run`, that run is the valid current history tip, and the audit also matches the current model, prompt, explanation schema, release tuple, recommendation decision, and score-source identity. The UI then shows `Analysis is stale` and withholds install/update commands. A valid numeric score from the authoritative release snapshot remains visible for review even when public enrichment, status authorization, or another release is non-actionable; recommendation flags and install/update commands still fail closed. If the authoritative release snapshot itself is unavailable or invalid, retained release metadata is diagnostic only and its scores are cleared. `auditDigest` identifies the sealed history row and run, not mutable current JSON.

![OpenClaw Release Radar screenshot](docs/screenshot.png)

## Current Status

This is now maintained from:

```text
https://github.com/hannesrudolph/openclaw-release-radar
```

It is intended to be deployed under your own domain. The old `isitstable.iclaw.digital` / `radar.iclaw.digital` references are not part of this setup.

## Quick Start

Requirements:

- Node.js `>=22.16`
- npm
- Git
- GitHub token
- OpenAI API key

Install dependencies:

```bash
npm install
```

Create local config:

```bash
cp .env.example .env
```

`.env` is for local development and isolated quality-database work. Production uses `/opt/openclaw-release-radar/shared/.env`; do not promote or copy a local `.env` into that location. The installer validates the production file separately and creates a release-specific runtime environment containing the verified code revision.

dotenv is non-overriding: every variable inherited from the launching shell wins over the matching `.env` value, for all settings, not only credentials. Check exported `DB_PATH`, model, revision, refresh, and server variables when an `.env` edit appears to have no effect.

Edit `.env`:

```bash
GITHUB_OWNER=openclaw
GITHUB_REPO=openclaw
OPENCLAW_REPO_URL=https://github.com/openclaw/openclaw.git

OPENAI_MODEL=gpt-5.5
OPENAI_REASONING_EFFORT=medium
OPENAI_SERVICE_TIER=priority
OPENAI_REQUEST_TIMEOUT_MS=300000
OPENAI_MAX_ATTEMPTS=5

PORT=8787
DB_PATH=./data/radar-quality.db
REFRESH_ON_STARTUP=false
REFRESH_MINUTES=0
RELEASES_LIMIT=10
FULL_ISSUE_BACKFILL=false
MAX_ISSUE_PAGES=4096
GITHUB_ISSUE_PAGE_SIZE=25
ISSUE_CATALOG_SNAPSHOT_MAX_AGE_HOURS=24
CLASSIFY_CONCURRENCY=5
GITHUB_GRAPHQL_CONCURRENCY=2
GITHUB_GRAPHQL_MIN_START_SPACING_MS=250
RELEASE_NETWORK_CONCURRENCY=4
CLOSURE_EVIDENCE_CONCURRENCY=3
CLOSURE_PROOF_CONCURRENCY=4
GIT_REACHABILITY_CONCURRENCY=16
GIT_CACHE_MAX_PACKS=64
GIT_CACHE_MAX_SIZE_MIB=2048
GIT_CACHE_MAINTENANCE_TIMEOUT_MS=300000
OPEN_PR_REFRESH_MINUTES=15
CLOSED_PR_REFRESH_MINUTES=1440
COMPARISON_API_ENABLED=false
```

Secrets can live in your shell/global environment instead of `.env`:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_github_token
export OC_OPENAI_API_KEY=sk-your_openai_key
```

The app also accepts the conventional names `GITHUB_TOKEN` and `OPENAI_API_KEY` if you prefer those.

Classification requests use `gpt-5.5` and explicitly send `reasoning_effort: "medium"` and `service_tier: "priority"` by default. OpenAI calls the fast API processing tier `priority`; override these settings only if you intentionally want a different model, latency, or reasoning tradeoff. Transport retries use bounded jitter and honor longer `Retry-After` deadlines. Model-correctable citation-grounding failures retry within the same `OPENAI_MAX_ATTEMPTS` budget with bounded deterministic validator feedback; schema, identity, usage, configuration, and duplicate-source failures remain terminal. Every attempt records the hash of its exact serialized request, while the run retains the initial request hash. The response model must match exactly, except that an unversioned request may resolve to the same model plus a `-YYYY-MM-DD` suffix. Any other returned model or any returned service-tier mismatch is a hard classification failure; the response is not accepted as evidence, and incomplete classification coverage blocks score persistence.

Choose an explicit quality database and the exact raw commit SHA that will be deployed. The checkout must represent that SHA; do not use the auto-derived `git:<sha>` or dirty-worktree revision for deployable quality data.

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
```

Build a fresh quality database. The main file and its `-wal`, `-shm`, and
`-journal` sidecars must all be absent. This command writes only the explicit
quality DB:

```bash
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB"
```

If the process is interrupted after creating the database, preserve the whole
SQLite family and resume the same quality DB explicitly:

```bash
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB" --resume-existing
```

The resume flag is never inferred from existing files or inherited
environment. Admission runs under the repository writer lock, rejects
`data/radar.db` and every path/inode alias of its SQLite family, and requires
the main DB plus any present sidecars to be regular non-symlink files. Use the
same explicit form for a later intentional refresh of an existing quality DB.
Do not prefix this command with `DB_PATH`; any inherited `DB_PATH` is treated as
a configured application database and is protected from quality refresh.

Validate the same DB read-only:

```bash
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local
```

Only after the refresh and read-only validation succeed, start a read-only preview of that same DB:

```bash
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" \
RADAR_DB_READ_ONLY=1 REFRESH_ON_STARTUP=false REFRESH_MINUTES=0 PORT=8787 \
  npm run dev
```

Open `http://127.0.0.1:8787`. The successful refresh result includes `runId` and `receiptId`.

Every refresh exhausts the complete GitHub release connection and repeats complete sweeps until two consecutive canonical catalog digests match. GitHub supplies that connection in `created_at` order, but release selection is performed only after stabilization and is ordered by `published_at`. After score construction and immediately before publication, refresh fetches and validates a second complete stabilized catalog. The initial and final remote digests/counts, projected active-catalog digest/count, and latest stable tag/publication time must agree exactly. Missing or duplicate stable publication timestamps, catalog drift, an incomplete catalog, or a catalog that does not stabilize blocks score persistence.

Every score-producing issue crawl is exhaustive and uses deterministic `CREATED_AT ASC` order. `FULL_ISSUE_BACKFILL` remains only as a compatibility/audit marker and does not select a cheaper incremental path. The first response freezes an as-of boundary from its `totalCount`; the sweep records the immutable terminal issue node ID, number, and `createdAt`, then collects exactly that first-N universe. Issues created after the boundary remain outside that accepted snapshot. Later `totalCount` growth is recorded as post-boundary growth, while a decrease below the frozen count, duplicate or missing immutable identities, terminal-watermark drift, cursor anomalies, or failure to collect exactly N rows blocks scoring.

Exhaustive stabilization compares a membership digest over immutable node ID, issue number, and `createdAt` across two complete sweeps against the same frozen boundary. Mutable title, body, state, labels, comments, and `updatedAt` are recorded in a separate content digest and do not invalidate membership; the last accepted sweep supplies the persisted issue metadata. `meta.issue_crawl_exhaustive_baseline` stores the repository identity, explicit as-of boundary, observed count and post-boundary growth, membership/content digests, and page/sweep counts.

After catalog stabilization and before any per-page evidence work, refresh atomically appends an immutable `issue_catalog_snapshots` header plus one `issue_catalog_snapshot_rows` row per issue. The ledger stores the node ID, complete fetched issue metadata, source ordinal, frozen boundary, counts, capture time, membership/content digests, row-schema digest, per-row hashes, aggregate row hash, and a chained header hash. Exhaustive page processing always reloads and consumes this persisted snapshot rather than the in-memory network result.

If a run fails after catalog acceptance but before every evidence/classification page succeeds, a later refresh may reuse the newest staged exhaustive snapshot when its repository identity, schema, hashes, digests, row count, required fields, and age all validate. `ISSUE_CATALOG_SNAPSHOT_MAX_AGE_HOURS` defaults to `24`; stale or incompatible snapshots trigger a new exhaustive network catalog scan. Issues created after the frozen first-N boundary are intentionally excluded from that as-of snapshot, recorded as post-boundary growth, and covered by the next exhaustive refresh. The published score remains explicitly bound to the accepted snapshot rather than claiming coverage beyond it. A staged snapshot never sets `backfill_completed_at` or `meta.issue_crawl_exhaustive_baseline`; those become complete only after every staged page finishes evidence refresh and classification successfully.

The current score-producing path never uses the legacy `UPDATED_AT DESC` early-stop crawl. Before score commit, refresh requires exhaustive stabilized crawl metadata and validates repository identity, boundary counts, cursors, membership/content digests, snapshot consumption, and final catalog attestation; doctor and release-audit verification apply the same contract. The final remote issue pass rechecks immutable first-N membership only. Its `contentDigest` field remains the digest of the consumed snapshot whose score-relevant rows were reconciled, not a claim that every unrelated mutable issue field stayed unchanged for the duration of the run. The default issue cap is 4,096 pages and the lower-level GraphQL connection guard defaults to 8,192 pages.

Full sweeps persist basic GitHub metadata for every issue but fetch score-blocking comments, current full issue metadata, label timelines, and state evidence only for issues that overlap monitored releases. Staged rows in that required set are compared with the fresh full metadata batch; any title/body/state/label/comment/reaction/timestamp drift is reconciled with the comment and state snapshots before persistence. Current-label connections are counted to exhaustion and reject null nodes, duplicate label names, count drift, terminal count mismatches, and cursor anomalies. Label timelines apply the same counted pagination checks and require two consecutive canonical sweeps to match event ID, action, label, actor, and timestamp; duplicate event IDs are rejected across the whole batch and persisted event IDs are immutable. Each fix-evidence chunk freezes independent first-response boundaries for close/reopen events, closed-by PR refs, and reference/commit events. Both sweeps collect exactly those first N rows in connection order and compare ordered immutable identities plus all score-affecting event content. Later appends are allowed, recorded as post-boundary growth, and deferred to the next exhaustive refresh; a count decrease below the boundary, missing or duplicate first-N identities, terminal-identity drift, cursor anomalies, non-contiguous state ordinals, malformed equal-time ordering, or changed score evidence fails closed. Mutable PR title/state/merge metadata is excluded from append-only stabilization and remains on the separate PR refresh path. Persisted state snapshots record the complete sweep count and stabilization flag; legacy single-sweep rows remain unusable until refreshed. Closure reconciliation separately fetches and verifies complete comments for every direct or transitive closure dependency, including terminal canonical issues outside the monitored window. Failures in either required set remain durable score-blocking provenance; metadata-only rows do not create comment-fetch failures. A later exhaustive refresh may reuse classifications and evidence only when their complete identities and digests still validate, but operators should budget every score-producing refresh as exhaustive rather than incremental. Every run prints `[refresh:timing]` stage timings.

`REFRESH_ON_STARTUP=false` disables startup refresh writes. `REFRESH_MINUTES=0` disables periodic refreshes. Normal startup still opens SQLite writable so it can enable WAL and run schema migrations. For genuinely read-only inspection of an already-migrated DB, start with `RADAR_DB_READ_ONLY=1 REFRESH_ON_STARTUP=false REFRESH_MINUTES=0`. Changing `FULL_ISSUE_BACKFILL` does not reduce or expand the current score-producing crawl. `GITHUB_ISSUE_PAGE_SIZE` defaults to 25 so fully expanded issue queries stay below GitHub secondary-rate limits; raising it trades fewer requests for substantially heavier queries. If the crawl reaches `MAX_ISSUE_PAGES` before exhausting GitHub pagination, the exhaustive crawl remains incomplete, refresh records the page-cap stop in doctor metadata, and scoring is refused.

GitHub GraphQL requests share one bounded limiter. The default allows two requests in flight with 250 ms between starts, honors full server `Retry-After` / rate-reset deadlines, uses a 60-second fallback for headerless secondary limits, times out request and body reads, and rejects repeated cursors or overlong nested pagination. Release artifact/check work, closure evidence, closure dependency discovery, and local Git ancestry checks have separate bounded concurrency controls. Raising GitHub concurrency aggressively is usually slower because secondary-rate-limit cooldowns dominate. A renewable SQLite lease prevents separate server/CLI processes from refreshing the same DB concurrently. The lease expires after five minutes and renews every minute, so a crashed holder recovers quickly; `SIGINT` and `SIGTERM` release the active lease, stop refresh scheduling, close the HTTP server, and close SQLite.

Immediately after acquiring that lease and before network work, refresh resolves one deterministic code revision and commits it in an immutable `refresh_operation_attempts` row with the run/operation/trigger, start time, lease holder, and an allowlisted effective config that excludes API credentials. For a deployable quality DB, `RADAR_CODE_REVISION` must be the exact raw deployment commit SHA, with no `git:` prefix, and the same value must be used by refresh, read-only preview, validation observation, and evaluation. The revision is passed through score persistence, forecast capture, and the terminal receipt; it is never recomputed mid-attempt. `refresh_operation_stage_events` records an append-only per-run hash chain, rejects new events after a terminal receipt, and requires every non-abandoned terminal run to close its started stages. The globally chained `refresh_capture_receipts` ledger records success, failure, or lease-expiry abandonment.

Before score durability, refresh preflights every non-expired forecast capture slot for the attested latest release, model, prompt, opportunity, and startup revision. An empty eligible slot may be captured after commit. A semantically equivalent existing schema-v4 slot yields `already_captured` with no new forecast row; a conflicting or legacy v1-v3 slot blocks the score commit. The score/current-audit/history transaction then commits and records monotonic-normalized `commitNotBefore`/`commitNotAfter` bounds. One short final transaction binds those bounds into score metadata, appends any new forecasts, and appends the success receipt. The receipt records exact `eligible_and_captured`, `already_captured`, or `not_eligible` decision sets. Any post-score failure receives a failure receipt, and `/api/status`, `/api/health`, and doctor continue to treat that current score tip as failed after restart.

Build a fresh quality database separately from the serving database:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
rm -f "$QUALITY_DB" "$QUALITY_DB-wal" "$QUALITY_DB-shm" "$QUALITY_DB-journal"
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local
```

Every later score-producing refresh of that DB uses the same exhaustive path,
must use the raw deployment SHA for the candidate being evaluated, and must opt
into the existing database explicitly:

```bash
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB" --resume-existing
```

Reachability checks maintain a bare Git cache at `.cache/openclaw.git`. `OPENCLAW_REPO_URL` must identify the same repository as `GITHUB_OWNER` / `GITHUB_REPO`. For a private target, configure Git credentials that allow the bare clone and fetches to read that URL. Probe commands keep Git auto-GC and automatic maintenance disabled. Before probing, the app runs bounded explicit `repack` and `prune` maintenance only when `git count-objects` reaches `GIT_CACHE_MAX_PACKS` or `GIT_CACHE_MAX_SIZE_MIB`; `GIT_CACHE_MAINTENANCE_TIMEOUT_MS` bounds each inspection and maintenance command.

## Internal Calibration Snapshot

During model calibration, you can capture an external rendered UI snapshot as a temporary internal benchmark:

```bash
npm run scrape:upstream
```

The snapshot is stored separately from local model data after validating the rendered release rows. It is internal calibration evidence only: it must not appear in product UX, overwrite local scores, or enter score-source identity. Review endpoints do not expose upstream comparison fields. `/api/comparison` remains disabled unless an operator explicitly sets `COMPARISON_API_ENABLED=true`.

## Current Rows and Immutable Ledgers

`releases` and `release_score_audits` are mutable current-state rows used to serve the latest verified assessment. They are actionable only when they exactly match the current sealed `release_score_audit_history` run and its `score_persistence_last_run` pointer. Historical score runs, refresh attempts, stage events, capture receipts, forecasts, observations, advisory snapshots, and issue-catalog snapshots are immutable append-only ledgers. Operators must append a new verified run rather than edit or delete ledger history.

When a successor refresh encounters a failed, abandoned, or formerly receiptless score publication, it clears the unactionable mutable tip and may restore the newest earlier successful refresh publication. Restoration fails closed unless every later immutable history publication is an ordered refresh publication with an exactly aligned history-v2 seal, linked authority run, matching timestamp, operation attempt, and terminal `failure` or `abandoned` receipt; a successful or non-refresh publication may never be skipped. `score_persistence_last_run.publicationRecovery` schema v3 records the restored publication identities, the latest displaced aliases, and the complete ordered `displacedPublications` suffix with its count and SHA-256 digest. Standalone authority-chain records that are not linked to a history publication are not treated as displaced publications, but linked authority runs must preserve chain order. Any later ledger or recovery-metadata drift makes the restored score unactionable.

## Tokens

### GitHub

`GITHUB_PERSONAL_ACCESS_TOKEN` or `GITHUB_TOKEN` is required because the app uses GitHub GraphQL.

For the public `openclaw/openclaw` repo, a classic token with `public_repo` is enough. For a private target repo, use a token that can read that repo.

If you already use the GitHub CLI:

```bash
gh auth status
gh auth token
```

Export the token globally as `GITHUB_PERSONAL_ACCESS_TOKEN`, or put it in `.env` as `GITHUB_TOKEN`.

### OpenAI

`OC_OPENAI_API_KEY` or `OPENAI_API_KEY` is required for issue classification. Without it, GitHub data can be fetched but release scoring will fail.

## Verify It Works

Process liveness only:

```bash
curl -f http://127.0.0.1:8787/api/live
```

Semantic deployment readiness:

```bash
curl -f http://127.0.0.1:8787/api/health
```

`/api/live` does not read SQLite. It only proves that the HTTP process can answer the lightweight route and may return `200` while the scored data is stale, invalid, or unavailable. Never use it as a deployment or recommendation-readiness gate. `/api/health` is the semantic gate: it reads the serving database and returns `200` with `status: "ready"` only when every scored or audited recommendation candidate has a valid sealed audit publication, current model/prompt and score-source identity, complete score-affecting closure evidence, and current closure-proof dependency integrity, while the aggregate recommendation run is valid, stable release windows are unambiguous, and no active score-blocking ingestion failure exists. A refresh-written current history tip additionally requires a hash-valid success receipt whose attempt, stage chain, code revision, catalog attestation, authoritative crawl/advisory digests, exact forecast set, and score-history link all validate. `operationReceiptRequired` cannot disable this check. This includes an older selected release: stale audit, negative `missing_evidence`, or closure evidence on that candidate blocks readiness even when the newest tag is current. A not-ready or unavailable result returns `503` with `ok: false`, structured per-release check diagnostics, and bounded failure details. Historical status is labeled `diagnosticStatus`, `diagnosticScoredAt`, and `diagnosticPreviouslyRecommended`; the health payload does not expose actionable `score` or `recommended` fields.

Refresh status:

```bash
curl http://127.0.0.1:8787/api/status
```

Main public payload:

```bash
curl http://127.0.0.1:8787/api/public
```

Top-level `schemaVersion` is the public payload contract version. Current value: `4`.

Score review:

```bash
curl http://127.0.0.1:8787/api/releases/v2026.6.10/review
```

Release audit invariant check:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
export API_BASE=http://127.0.0.1:8787

# Read-only DB validation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run doctor
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run doctor -- --api-base "$API_BASE"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:release-audit
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:release-audit -- --api-base "$API_BASE"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:live

# API/browser validation only; this script does not open SQLite.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" API_BASE="$API_BASE" \
  npm run ui:smoke
```

`npm run doctor` is a read-only SQLite health report. It prints DB path/size, table counts, latest scored stable, recommendation count, score-write provenance, classification coverage, source freshness, closure-proof coverage, closure-evidence/comment-cache reuse, PR reachability counts, comparison snapshot state, warnings, and failures. It also verifies the `issues(created_at)` and `issues(closed_at)` indexes and confirms measured release-window range plans use them. It checks every scored stable release row against its matching `release_score_audits` row and the exact current sealed-history row, validates history seals/tips and semantic source manifests, and rejects forecasts that carry or reference invalid provenance. It verifies attempt hashes, complete stage chains, terminality, receipt hashes, and the current score tip's non-bypassable success receipt, including code revision, score-history link, catalog attestation, authoritative issue/advisory digests, recommendation, and exact inserted/already-captured/empty forecast sets. Prospective advisory validation separately reports authorized and staged v2 snapshots; it trusts only exact-bound successful receipts after the full operation ledger verifies. Receiptless staged rows remain auditable but cannot become outcome evidence. Legacy forecast schemas v1-v3 remain immutable and readable but are excluded from current evaluation. State-event projection checks compare full ordinal, actor, state-reason, and closer identity rather than counts alone. It also validates issue crawl schema v4 and its embedded/stored exhaustive baseline schema v2 against `meta.issue_crawl_exhaustive_baseline`; pagination metadata is schema v2. Current score-producing crawls must be frozen-boundary, counted, membership-stable, content-digested, repository-bound, exhaustive, and stabilized; historical incremental metadata remains auditable but is not the current score-producing path. It checks page-cap stops, truncated required-comment scans, issue classification failures, release-metadata/artifact/release-check/advisory/monitored-release evidence refresh failures, durable `ingestion_evidence_failures` rows recorded after the latest score, malformed freshness timestamps, issue comment snapshot freshness, and source rows that changed after the latest score. Use `--api-base http://127.0.0.1:8787` to also check the running local server. Add `--fail-on-warnings` when stale evidence warnings should fail the command.

`verify:local` starts with `npm run doctor -- --fail-on-warnings`. `verify:live` first requires `/api/live` to return HTTP `200` with `status: "live"` and `/api/health` to return HTTP `200` with `status: "ready"` and every semantic check marked `ok`; only then does it run doctor, score, release-audit, and UI checks. Both commands use `--all` internally, so they check every scored stable release and fail if a scored release lacks a score audit, the latest evidence is stale, or the latest crawl recorded classification/evidence failures that could affect the current score. Release metadata, release-window context, artifact verification, release commit checks, and security advisories are score-affecting evidence; refresh records failures for those sources and refuses score persistence instead of falling back to stale rows.

Advisory ingestion stores every vulnerable package range for a GHSA as a separate row, keyed by advisory/package/range. Scores and advisory badges evaluate all rows, so a multi-range GHSA cannot hide exposure by overwriting one range with another.

Score writers also enforce complete classification coverage, complete score-affecting closure evidence, unambiguous stable release windows, verified state-event snapshot coverage, unambiguous issue open intervals, and a stable source snapshot before updating release rows or score audits. Score construction runs inside one SQLite read transaction, streams explicit ordered columns from the 32 score-input sources through SHA-256 before and after analysis, then verifies the same identity again inside the score-write transaction. It does not materialize whole source tables in memory. Issue rows bind canonical issue and author node identity plus author type. Closure and reopen source rows include `connection_ordinal` plus canonical issue and actor identity; closure rows bind the canonical closer resource when GitHub supplies one. Actor-attributed manual or administrative closes legitimately retain a null `ClosedEvent.closer`; they preserve the close reason and actor provenance but create no direct PR/commit fix proof. Partial closer identities still fail closed. PR rows bind PR and repository node identity plus raw source evidence. If any release has `classifiedIssueCount !== rawIssueCount`, `analysisCompleteness.complete` is false, a score-affecting negative closure row is `missing_evidence`, a stable release has a missing/duplicate `published_at`, a required state snapshot is missing or inconsistent, a fetched reopen event has no preceding close event, or any source row changes during analysis or before persistence, persistence and `verify:score` refuse the run with explicit diagnostics. The exported `currentScoreCompletenessDiagnostic` is the canonical completeness check for verifier/API/doctor consumers. `missing_evidence` contributes zero points and cannot cap the score. The exclusive ledger prevents duplicate numeric penalties, while `input.affirmativeClosureRiskCeilingWeight` separately preserves deduplicated known-not-in-release, open-canonical, and unsupported-closure ceilings even when verified or stale debt wins the alias channel. Inherited/carryover issue groups remain visible in audits but contribute zero points. Prompt version 9 requires exact `{source_id, excerpt}` citations for affected-user scope; reporter/comment/reaction volume never changes `affectedUsers`, debt, or regression weight. Every successful audit stores source identity schema v17 in `source_identity_json`, including per-source digests, release artifact receipts, the effective scoring configuration, the code revision, and the combined database identity. Semantic validation retains immutable schema v5-v16 history while current score production remains schema v17. `score_persistence_last_run` schema v2 records that digest plus writer source, scope, release tags, score timestamps, recommended tag, model/prompt versions, and issue-crawl coordinates.

The score transaction replaces the monitored score window atomically. Stable releases that fall outside the configured monitored set keep their release metadata, but their score outputs and `release_score_audits` rows are cleared before the new monitored audits are written. This prevents an old audit with a previous source identity from remaining mixed into the current score run.

GitHub GraphQL ingestion also fails closed on malformed nested evidence connections. Missing `nodes`, null nodes, missing `pageInfo`, or `hasNextPage` without `endCursor` on issue labels, comments, label timelines, fix evidence, release check contexts, release pages, issue pages, or advisory pages is treated as an ingestion failure, not as empty evidence.

Closure-proof review rows preserve exact GitHub evidence links. Matching closure comments and non-actionable rationale include the comment database ID and URL; comment-derived PR links retain their source-comment URL; commit proof exposes the full commit URL, source issue, author, timestamp, and reachability result. A deleted or mistyped PR reference remains visible as `metadataMissing` evidence and receives no fix credit unless separate reachable proof exists.

Refresh separates network discovery from proof calculation. It expands canonical issue references transitively, including terminal canonical issues outside the source release window, then stores one `release_closure_dependency_snapshots` digest over the complete issue set and every proof-affecting row. Proof construction runs from that stable snapshot; a final local stabilization pass resolves cross-release canonical proof references without refetching GitHub or recomputing cached Git ancestry. Any issue-set, row-count, analyzer-version, or digest drift invalidates the proof and blocks scoring.

`fixed_in_release` means code proof is contained in the target tag; it does not by itself earn the regression fix bonus. Each contained fix receives a strict target/predecessor decision. Bonus credit requires a trusted merged PR whose evidence is valid, `reachable` in the target, and explicitly `not_reachable` in the immediate stable predecessor. Missing, unknown, invalid, or already-reachable predecessor evidence withholds the bonus, so `containedFixedCount` may exceed `countedClosedCount`.

Score-blocking ingestion failures are appended to `ingestion_evidence_failures` with run/source/scope/message context as soon as they happen. If issue-page comments, label timelines, or fix evidence fail before normal crawl metadata can be completed, refresh writes `stopReason: "evidence_failure"`, persists the failure examples, and refuses score persistence.

When GitHub returns a partial GraphQL response because an issue alias cannot be resolved, batch helpers recover only when the caller provides an explicit missing-alias reporter. Refresh records the skipped alias as a durable score-blocking evidence failure. Other callers fail closed instead of silently treating comments, labels, or fix evidence as empty.

Audit freshness follows the newest audited stable release, including null-score `wait` rows. Recommendation counts still require a numeric score, so wait/gated audits do not become install candidates.

Scoring rules and evidence sources are documented in [docs/scoring-model.md](docs/scoring-model.md).

A healthy `/api/status` response has:

```json
{
  "schemaVersion": 1,
  "refreshing": false,
  "activeRunId": null,
  "latestAttemptRunId": "2026-07-04T10:00:00.000Z:12345:...",
  "latestTerminalReceiptId": "...",
  "latestTerminalReceiptStatus": "success",
  "latestSuccessReceiptId": "...",
  "latestSuccessRunId": "2026-07-04T10:00:00.000Z:12345:...",
  "latestFailureReceiptId": null,
  "latestFailureRunId": null,
  "currentScoreRunId": "2026-07-04T10:00:00.000Z:12345:...",
  "currentScoreReceiptId": "...",
  "currentScoreReceiptStatus": "success",
  "currentScoreAuthorizationStatus": "authorized",
  "lastError": null
}
```

`activeRunId` is populated only while this process is refreshing and has committed
its immutable attempt row. `currentScoreAuthorizationStatus` is one of
`authorized`, `unauthorized`, `missing`, `not_required`, or `unavailable`.

A healthy completed refresh also records `meta.issue_crawl_last_run`, which `npm run doctor` reports under `ingestion.issueCrawl`:

```json
{
  "ingestion": {
    "issueCrawl": {
      "schemaVersion": 4,
      "repository": "openclaw/openclaw",
      "stopReason": "exhausted",
      "crawlMode": "exhaustive",
      "pagination": {
        "completeness": "exhaustive_stable",
        "boundaryTotalCount": 41234,
        "observedTotalCount": 41234,
        "postBoundaryGrowthCount": 0,
        "fetchedCount": 41234,
        "uniqueCount": 41234,
        "stabilized": true,
        "membershipDigest": "...",
        "contentDigest": "..."
      },
      "baseline": {
        "repository": "openclaw/openclaw",
        "asOfBoundary": {
          "totalCount": 41234,
          "terminalIssue": {
            "nodeId": "...",
            "issueNumber": 41234,
            "createdAt": "..."
          },
          "membershipDigest": "..."
        },
        "postBoundaryGrowthCount": 0,
        "contentDigest": "...",
        "identity": "..."
      },
      "classificationFailures": [],
      "evidenceRefreshFailures": [],
      "scorePersisted": true
    }
  }
}
```

## API

| Endpoint | Purpose |
| --- | --- |
| `/api/live` | Lightweight HTTP process liveness only; does not read the database and is not a readiness gate |
| `/api/health` | Semantic deployment/readiness gate; returns `200` only with `status: "ready"` and otherwise returns `503` |
| `/api/status` | Refresh state, latest attempt/terminal/success/failure receipt IDs, active run ID, and current-score receipt authorization |
| `/api/receipts?limit=10` | Newest terminal refresh receipts with normalized attempts, ordered stages, bounded/redacted payloads, hash IDs, history/forecast links, and ledger verification |
| `/api/receipts/:receiptId` | One terminal receipt by receipt ID or run ID |
| `/api/validation/opportunities` | Read-only current model/prompt/revision validation-opportunity status |
| `/api/releases` | Dashboard release data; each row includes `auditLinks` for review, issue evidence, closure proofs, and PR reachability |
| `/api/releases/history` | Cross-release score trend using the current audited row for each release; each row includes `scoredAt`, `scoreAudit`, `dataFreshness`, and `auditLinks`; this is not the per-run append-only score ledger |
| `/api/public` | Main install recommendation payload; each release row includes `auditLinks` for audit drill-down |
| `/api/releases/:tag/review` | Local score audit for one release; no upstream comparison fields; includes `local.sourceProvenance` with the persisted score-source identity, score/audit timestamp alignment, receipt-authorized compound-advisory v2 publication, freshness sources, and publication-bound raw-row links |
| `/api/releases/:tag/review/issues` | Paginated current-DB issue-evidence rows for one release; supports exact `issue`/`number`, comma-separated `tier`, `impact`, `state`, `sentiment`, `severity`, `functionality`, `scope`, `affectedUsers`, `fieldConfirmed`, `minWeight`, `maxWeight`, `sort`, `direction`, `summaryOnly`, plus `limit` and `cursor`; includes `sourceMode`, `scoredAt`, `dataFreshness`, `tierInfo`, `summaryByTier`, `filteredSummary`, `filteredCountsByTier`, `filteredSummaryByTier`, and `totals` |
| `/api/releases/:tag/review/closure-proofs` | Paginated current-DB closure-proof rows for one release; supports exact `issue`/`number`, validated `status`, audit enum `riskDisposition`, `limit`, and `cursor`; includes `sourceMode`, `scoredAt`, `dataFreshness`, human-readable risk labels, filtered/unfiltered status counts, and filtered/unfiltered risk-disposition counts |
| `/api/releases/:tag/review/reachability` | Paginated current-DB PR reachability rows for one release; supports `status`, `pr`, `limit`, and `cursor`; includes `sourceMode`, `scoredAt`, `dataFreshness`, and filtered/unfiltered status counts |

Score-bearing, recommendation, review, history, comparison, health, validation-status, refresh-status, and receipt-history responses use `Cache-Control: no-store`. Static files keep the normal Express cache policy.

`local.sourceProvenance.advisorySnapshot` is the public advisory publication
audit. It identifies the active immutable v2 snapshot, complete metadata and
metadata digest, ledger and score-projection hashes, row counts, active
projection verification, the exact authorizing receipt/run and semantic
receipt identity, and all authorized versus staged snapshot IDs. Integrity,
operation-ledger, and receipt-authorization failures are reported separately
and make `verified` false. Legacy advisory snapshot diagnostics remain
compatibility evidence only and cannot invalidate an otherwise intact,
receipt-authorized v2 publication.

Receipt reads are operator-facing and read-only:

```bash
curl 'http://127.0.0.1:8787/api/receipts?limit=10'
curl 'http://127.0.0.1:8787/api/receipts/<receipt-or-run-id>'
```

The list limit defaults to `10` and must be between `1` and `25`. List records
include at most 50 ordered stage events and an 8,000-character payload budget;
detail records include at most 250 stages and a 32,000-character payload budget.
Responses report truncation and JSON parse status. Attempt effective configuration
and lease-holder IDs are never returned. Stored payloads, counts, details, operation
labels, and verification diagnostics are defensively redacted for credentials and
bounded before serialization. The terminal outcome remains explicit as `success`,
`failure`, or `abandoned`, and `links` exposes the sealed score-history run/hash and
forecast decision IDs when the receipt contains them. Each response is assembled
inside one stable SQLite read transaction and includes `readEpoch` plus full-ledger
verification status.

The structured score explanation appears at these paths:

- `/api/releases`: `release.explanation`
- `/api/public`: `release.explanation`
- `/api/releases/:tag/review`: `local.components.explanation`

That structured `explanation` object contains:

- `schemaVersion`: explanation contract version. Current value: `5`. Closure proof references include linked PR source/reachability/merge metadata and source-comment URLs where available; issue references also expose exact release-local evidence and release-scoped state.
- `scoreLedger`: canonical score math rows with stable row keys/labels, subtotal, cap rows, score after caps, and final rounded score.
- `positives` / `limits`: human-readable evidence lines for the UI.
- `positiveDetails` / `limitDetails`: matching machine-readable entries with stable reason `code`, mandatory canonical `label`, optional `metrics`, `buckets` / `riskBuckets`, and `issueRefs`.
- `verdict`: install-facing interpretation of the score.
- `recommendationDecision`: the validated policy decision, threshold, recency tolerance, selected/highest-scoring tags and scores, ranks, deltas, and decision reason.

The `/api/releases/:tag/review` `local.input` and `local.components` objects also expose `schemaVersion`. Current input value: `2`; current components value: `1`.
The `/api/releases/:tag/review` `local` audit object exposes `schemaVersion`. Current value: `1`. `/api/public` and `/api/releases` `scoreAudit` summaries expose `schemaVersion`. Current value: `2`.
The `/api/releases/:tag/review` `local.issueEvidence` object also exposes `schemaVersion`. Current value: `2`.
The `/api/releases/:tag/review` `local.gateEvidence` object also exposes `schemaVersion`. Current value: `1`.
The `/api/releases/:tag/review` `local.gateEvidence.labelTimeline` object also exposes `schemaVersion`. Current value: `1`.
The `/api/releases/:tag/review` `local.gateEvidence.releaseChecks` object exposes `schemaVersion`. Current value: `2`. `local.gateEvidence.artifactVerification.schemaVersion` current value: `2`. Artifact gates retain the complete replayable receipt and observation proof: canonical release identity, release metadata, byte-level npm artifact evidence, release-evidence report verification, run/timestamp, immutable identities, content hashes, and ledger predecessor hashes. Proof-bearing fields are all null when no observation exists and otherwise must replay exactly and agree with the flat compatibility fields and score input.
The internal `/api/comparison` payload, upstream row, and delta objects also expose `schemaVersion`. Current value: `1`.
The `/api/status`, `/api/config`, and `/api/receipts` list/detail payloads expose
`schemaVersion` `1`.
Both `/api/receipts` and `/api/receipts/:receiptId` include `validationProof`.
It reports proof-ledger integrity, the active epoch/cohort IDs, immutable row
counts, the current evaluation ID/hash/status, the current production promotion
ID/hash and database bindings, the latest calibration promotion, and
`productionAuthorized`. Production authorization is true only when the current
active epoch has one exact `validated` evaluation and a production promotion
receipt bound to that same evaluation ID and content hash.
The `/api/releases/history` rows expose `schemaVersion`. Current value: `2`.
The `/api/public` payload and `/api/public` release rows expose `schemaVersion`. Current value: `4`. Public release `profileEvidence.schemaVersion` current value: `2`; it is derived from the full release issue-evidence projection, not from capped public issue summaries. `sealed_score_replay` rows bind the profile-row digest to the exact audit digest, immutable authority run, history-v2 seal, score source identity, model version, and prompt version. Unscored or stale rows use `current_diagnostic_evidence` and carry no sealed publication binding. `/api/releases` rows expose `schemaVersion`. Current value: `2`.

## Development Commands

Normal iteration is `npm run test:preflight` only when the installer changed, `npm run test:focus -- <manifest-test-file> [--name <pattern>]`, optional `npm run test:focus -- --authoritative <manifest-test-file> [--name <pattern>]`, then `npm run verify:ci`.

```bash
# Run only when the installer changed.
npm run test:preflight
npm run test:focus -- src/lib/example.test.ts
npm run test:focus -- src/lib/example.test.ts --name "specific test name"
# Optional focused validation through the authoritative sandbox and audit path.
npm run test:focus -- --authoritative src/lib/example.test.ts
npm run verify:ci

export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
export API_BASE=http://127.0.0.1:8787

# Read-only DB validation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run verify:local
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run verify:live
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run doctor
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run verify:score -- --all
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run verify:release-audit -- --all
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" API_BASE="$API_BASE" npm run ui:smoke

# DB-writing maintenance; each command targets only the explicit quality DB.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run analyze:closure-proofs -- <tag>
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run backfill:issue-comment-snapshots -- --all-scored
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run backfill:issue-state-events -- --limit 10
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run backfill:closed-windows -- --all
RADAR_CODE_REVISION="$DEPLOY_SHA" npm run refresh:quality -- --db-path "$QUALITY_DB" --resume-existing

# Read-only validation snapshot; --output writes only the requested JSON file.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run validation:snapshot
# Read-only validation opportunity status.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run validation:opportunities
# DB-writing validation outcome observation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run validation:observe
# Read-only validation evaluation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run validation:evaluate
# DB-writing validation evaluation receipt.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run validation:evaluate -- --record

npm run promote:quality-db -- --help
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
REFRESH_ON_STARTUP=false REFRESH_MINUTES=0 npm run dev
```

Run the full gate once, after implementation stabilizes and before push or deploy: choose either `npm test -- --full` or `npm run test:baseline -- --full`, not both.

`npm test -- --full` verifies the full suite against the accepted baseline. `npm run test:baseline -- --full` generates a full baseline candidate for review.

Baseline acceptance is separate: review the generated candidate, then run `npm run test:baseline:accept`.

`npm run verify:ci` is portable CI validation: typecheck, script syntax checks, and build. The deploy workflow separately runs `npm run verify:authoritative-ci` on macOS. That command runs `npm run test:safety` and forces fresh full candidate generation with `npm run test:baseline -- --full --rerun` without accepting or rewriting the checked-in trust root.

`npm run verify:scripts` syntax-checks every `.mjs` maintenance/validation script and every `.mjs` or `.cjs` test harness file.

Use `npm run test:preflight` only when the installer changed. It
materializes every quoted heredoc into private files, rejects shell
here-strings that would require Bash temp files, checks the transformed script
with `bash -n`, and verifies installer protocol `5`.

Use `npm run test:focus -- <manifest-test-file> [--name <pattern>]` while
iterating. It accepts exactly one file from `test/test-manifest.json`, holds the
suite and database-writer locks, uses a fresh private database and empty dotenv,
and runs one test worker. Add `--authoritative` before the file only when the
affected path needs the real Seatbelt profile, database guard, private installer
fixture, and audit contract.

Validation is serialized. Full test runs require the explicit `--full` flag, and each entrypoint rejects unsupported forwarded arguments. `npm test -- --full` holds one
authoritative suite lock, runs with exactly one worker, applies a non-disableable
bounded timeout to every individual test, limits temporary SQLite and worker
footprints, and forbids `VACUUM` inside isolated tests. On macOS, the detached
watchdog samples cumulative bytes written by the owned test process group and
terminates that group after 4 GiB by default, even when repeated SQLite page
rewrites keep the final files small. The process-write budget may be lowered,
but the non-disableable 4096 MiB ceiling cannot be raised. Whole-system
disk-transfer sampling is pressure telemetry only and never terminates
repository processes because it includes unrelated VM, APFS, and application
traffic. Process-write accounting is sampled rather than a kernel lifetime
audit: it is designed to stop sustained multi-GiB churn, while the file, SQLite,
footprint, timeout, and free-space guards remain necessary for short-lived
processes that could exit between samples.
Promotion tests inject bounded fixture snapshots while the production
promotion command continues to use verified `VACUUM INTO` snapshots. Raw VM
disk operations are not part of this repository workflow; do not attach,
mount, inspect, or mutate VM disks during repository work.

Use named npm lifecycle commands for database operations. The supported app
runtimes are `npm run dev` (`tsx watch src/index.ts`) for local development and
`npm start` (`NODE_ENV=production node dist/index.js`) for an installer-authorized
production release. Any eval, print, stdin, or custom import script that loads
repository modules must instead use an explicit fresh private `DB_PATH` and an
empty `DOTENV_CONFIG_PATH`; it must not open the configured live database. Do
not invoke the refresh pipeline through eval. Use `npm run refresh:quality --
--db-path <path>` for a fresh SQLite family, or add `--resume-existing` after
the path to resume an interrupted or intentionally retained quality DB. The
guard refuses `data/radar.db` and aliases of its complete SQLite family,
validates fresh/resume admission while holding the writer lock, preserves
existing sidecars, and disables automatic refresh. Every
writable database import also holds a per-database initialization lock until
bootstrap and migration finish, so separate processes cannot interleave schema
work before the SQLite lease is available.

`npm run verify:local` is read-only. Run it with explicit `DB_PATH`, `RADAR_CODE_REVISION`, and `RADAR_DB_READ_ONLY=1`; it runs the health doctor in `--fail-on-warnings` mode and checks persisted score/audit consistency for every scored stable release.

`npm run verify:live` is read-only against the explicit `DB_PATH` and requires the local server at `http://127.0.0.1:8787`. It verifies liveness and semantic readiness before any other API/UI checks, runs doctor in `--fail-on-warnings` mode, checks API/UI contracts for every scored stable release, and runs desktop/mobile browser layout smoke checks. Recommendation, stale-analysis isolation, non-overlapping release rows, desktop layout, and mobile layout are mandatory. CVE-gated, eligible non-recommended, and fix-credit link examples are reported as explicit optional coverage and are skipped with a reason when the deployed dataset has no matching release. The web UI renders authoritative release rows from `/api/releases` first; score history, public issue enrichment, and per-release review payloads load afterward behind snapshot guards. History can enrich a row only when score, status, recommendation, `scoredAt`, score-audit identity, stale-audit state, and freshness all match the authoritative release snapshot. Any release/public/review failure converts retained rows to non-actionable diagnostics and removes update/copy controls until a complete retry succeeds.

`npm run doctor`, `npm run verify:score`, and `npm run verify:release-audit` are read-only and must name the inspected database through `DB_PATH`. Doctor emits a JSON health report covering current score/audit parity, sealed score-history runs, forecast/outcome chains, advisory and issue-catalog snapshot row counts and hashes, issue-catalog hash-chain/schema integrity, advisory package/key identity, orphan rows, evidence freshness, and closure/reachability coverage. A valid staged issue catalog older than its resume window is reported as `stale` but is not a health failure; row/hash/schema corruption is fatal. Immutable historical rows that are structurally valid but predate stricter semantic contracts are retained under `legacyFindings`; they remain auditable but do not make `--fail-on-warnings` reject an otherwise valid current tip. Add `-- --api-base http://127.0.0.1:8787` when you want doctor or release-audit validation to compare the running server with the DB; add `-- --fail-on-warnings` when operational warnings such as stale current evidence should return a failing exit code. `npm run ui:smoke` is API/browser-only and does not open SQLite, but operator examples still carry `DB_PATH` so the target dataset remains explicit.

Score persistence preflights prospective capture slots before writing and seals immutable `release_score_audit_history` before final capture. The 3-hour opportunity is valid only at release age `[3h,6h)` and the 24-hour opportunity only at `[24h,30h)`, evaluated with integer milliseconds, inclusive start, and exclusive end; a late first observation never backfills an earlier opportunity. New writes accept only forecast decision schema v4. It uses `commitNotAfter` as `recorded_at`, binds the distinct history timestamp by sealed run ID/content hash, stores both commit bounds, and includes a content-hashed `catalogAttestation` with the initial/final remote sweep metadata, final observation time, projected/local active catalog identity, latest stable identity, and score-build time. Offline/manual score writers never append forecasts, and refresh capture without valid attestation fails. Every new capture uses the one normalized deterministic revision established at attempt startup. The revision-aware series key is a capture slot: a semantically equivalent existing v4 capture is reported as `already_captured`, while payload drift or an occupied legacy slot blocks score durability. Legacy schemas v1-v3 and null-revision rows remain immutable and readable but never count as current or evaluable.

`npm run validation:snapshot` and `npm run validation:opportunities` are read-only against the explicit `DB_PATH`. Snapshot prints the immutable forecast ledger and writes only the requested JSON output file when `--output` is supplied. Opportunities reports exact UTC opening and exclusive-closing times for the latest stable, distinguishes current model/prompt/revision captures from old strata, and identifies upcoming, open, captured, and missed windows. Add `--check` for monitoring exit codes: `0` all captured, `2` upcoming, `3` capture window open, `4` missed with no open window, and `1` malformed or ambiguous state. Opportunities disables startup/periodic refresh and never writes forecasts or backdates missed opportunities.

`npm run validation:observe` is DB-writing and must target the explicit quality `DB_PATH` with the same exact raw `RADAR_CODE_REVISION` used for refresh and preview. It first excludes every v1-v3 forecast and every timing-invalid v4 forecast, so legacy decisions never acquire new immutable outcome rows. For eligible v4 forecasts it derives field outcomes from independent raw post-forecast evidence, not `openedFeltSerious`, `verifiedDebt`, or other score buckets. A validating adverse field outcome requires complete post-horizon issue/comment coverage, exact selected-version title/body/comment linkage, and either a non-bot human confirmation comment or label actor, or trusted later fix/hotfix proof. Exact evidence URLs/IDs and the outcome source class are persisted. Classifier bucket outcomes are reported only as `classifier_score_bucket_proxy` and cannot satisfy validation. A complete exact-version crawl with zero independent adverse evidence yields `observed-safe`, including for an older selected release; incomplete evidence remains censored. Security outcomes require the earliest post-horizon compound advisory v2 projection authorized by a successful atomic refresh receipt. The payload records the complete v2 metadata and source/catalog/score/ledger/projection hashes plus the authorizing receipt and run. Raw legacy tables, the mutable active projection, and receiptless staged snapshots cannot satisfy a new security observation; legacy snapshots remain available only to verify already-recorded historical outcomes.

Observe is batch-atomic. It computes every decision/horizon result and intended outcome row without writes, validates the existing forecast/outcome and observation-batch ledgers plus the complete proposed extension, then opens one `BEGIN IMMEDIATE` transaction. That transaction rechecks the score-source identity, the exact sorted forecast decision-ID/content-hash set, the outcome tip, and the receipt tip before inserting all new outcomes and one immutable `release_validation_observation_batches` receipt. Every inserted outcome must carry the same score-source digest as its receipt. Any conflict or error rolls back the whole batch. The v2 receipt stores the batch ID, observation time, code revision, current source-identity digest, exact forecast inputs, forecast and status counts, canonical exact decision/horizon results, exact inserted-outcome references, the outcome-chain bounds, the previous batch hash, and its own content hash. Once a ledger contains a v2 receipt it cannot append a legacy v1 receipt. Receipt and outcome chains are verified before and after commit, both batch updates and deletes are blocked by append-only triggers, and standalone outcome inserts are disabled so new outcomes cannot bypass a receipt.

Use `DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" npm run validation:observe -- --batch-id <stable-id>` when a scheduler needs retry-safe execution. This form writes the explicit quality DB. An exact rerun returns the existing equivalent receipt; reusing that ID with a different observation time, code revision, source identity, forecast count, result set, or outcome set fails as a conflict. `--observed-at <ISO timestamp>` is available for deterministic operations and tests; omit it for the current time.

`npm run validation:evaluate` is read-only by default and must use the explicit quality `DB_PATH` plus the same exact raw `RADAR_CODE_REVISION` used by refresh, preview, and observation. It retains every forecast decision before overlap analysis, computes by-model metrics without allowing another model to prune its cases, pairs models on matching release/opportunity/horizon cases, and reports non-overlapping sensitivity plus release-cluster bootstrap uncertainty. Score bins are empirical discrimination summaries, not probability calibration. Validation requires minimum unique-release and class counts plus all documented quality gates: 95% cluster-bootstrap recommendation precision lower bound `>=0.70`, false-safe upper bound `<=0.30`, accuracy lower bound `>=0.60`, and safe-vs-adverse AUC lower bound `>=0.65` when both classes are measurable. Status is `validated`, `insufficient`, or `measurable_but_failed`; exit codes are `0`, `2`, and `1` respectively. Sample sufficiency alone never returns success.

With `--record`, evaluation becomes DB-writing. A production candidate must run it against the explicit quality DB after its final observation and scoring writes, with the same raw deployment SHA. The command appends one immutable canonical evaluation receipt that binds the active proof epoch, every active cohort, the exact required opportunity-by-horizon cells, observation batches, outcomes, complete metrics, status, evaluation time, and content hash. An exact retry is idempotent; the same evaluation time with different content is rejected. `--evaluated-at <ISO timestamp>` is available for deterministic scheduling.

`DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run validation:evaluate -- --require-recorded --evaluated-at <ISO timestamp>` is the read-only replay gate used by promotion. It succeeds only when recomputation produces the exact already-recorded evaluation ID and content hash. Promotion always uses the latest recorded receipt and requires its status to be `validated`; `insufficient`, `measurable_but_failed`, a missing receipt, an older receipt, or any recomputation drift blocks promotion.

## Operator Workflow

Automatic refresh stays disabled during calibration. A fresh installation and a
production promotion are different workflows:

- A fresh local installation can build, verify, and serve a new quality DB
  immediately. It does not need a promotion receipt.
- Production promotion remains blocked until prospective validation has
  accumulated the documented minimum cohort and produced a recorded
  `validated` evaluation. A new DB cannot manufacture that historical evidence.

### Fresh Local Installation

Build a private quality DB outside `data/radar.db`, verify it, and serve that
same file directly:

```bash
export QUALITY_ROOT="$PWD/.codex-local/quality-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 700 "$QUALITY_ROOT"
export QUALITY_DB="$QUALITY_ROOT/radar.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"

RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB"

DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local

DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" PORT=8787 \
RADAR_DB_READ_ONLY=1 REFRESH_ON_STARTUP=false REFRESH_MINUTES=0 \
  npm run dev
```

Open `http://127.0.0.1:8787`. Keep `DB_PATH` pointed at this verified file for
local use. Do not copy or promote it over `data/radar.db`.

### Production Promotion

Use this workflow only after `validation:evaluate -- --record` returns
`validated` for the exact model, prompt, code revision, active proof epoch, and
prospective cohort. The production minimum is 20 decision cases, 20 unique
release clusters, and 20 cases in each required outcome class; a freshly
created database will normally report `insufficient` until those observations
have accumulated over real future releases.

Complete every DB-writing candidate step and DB-only evaluation against the
existing separate candidate DB before starting or restarting its immutable
read-only reader on port `8788`. Stop any existing candidate reader before the
first command:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export PRIMARY_DB="$PWD/data/radar.db"
export CANDIDATE_URL=http://127.0.0.1:8788
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"

# DB-writing exhaustive refresh of the explicit quality DB.
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB" --resume-existing

# Read-only DB validation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local

# Read-only score verification before recording the evaluation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:score -- --all

# Final candidate DB write: record the evaluation receipt.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" \
  npm run validation:evaluate -- --record

# Promotion dry-run writes only disposable staging.
RADAR_CODE_REVISION="$DEPLOY_SHA" npm run --silent promote:quality-db -- \
  --source "$QUALITY_DB" --destination "$PRIMARY_DB" --dry-run

# Immutable candidate reader. Start or restart it only after every command above
# completes, then keep this terminal running for the API/UI checks below.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" PORT=8788 \
RADAR_DB_READ_ONLY=1 REFRESH_ON_STARTUP=false REFRESH_MINUTES=0 \
  npm run dev
```

In another terminal, export the same values. Do not substitute a different revision:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export PRIMARY_DB="$PWD/data/radar.db"
export CANDIDATE_URL=http://127.0.0.1:8788
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"

# Reader-backed DB/API validation.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run doctor -- --fail-on-warnings --api-base "$CANDIDATE_URL"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:release-audit -- --all --api-base "$CANDIDATE_URL"

# API/browser-only validation; the script does not open SQLite.
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" \
API_BASE="$CANDIDATE_URL" npm run ui:smoke
```

If any later candidate DB write is required, stop the immutable reader first,
complete the write and evaluation, restart the reader, and rerun every API/UI
check against the newly opened database state.

The dry-run above is read-only with respect to the source and destination and
may inspect their activity; a live destination requires explicit `--dry-run`.
Its report marks activity observations as non-durable and never authorizes a
later apply. After the reader-backed API/UI checks pass, stop the production and
candidate servers, verify both complete SQLite families (the main file plus
`-wal`, `-shm`, and `-journal`) have no holders or active refresh leases, then
apply. Apply always performs fresh source and destination activity checks
regardless of any earlier report:

```bash
export RADAR_DEPLOY_LOCK_PATH=/opt/openclaw-release-radar/shared/deploy-promotion.lock
RADAR_CODE_REVISION="$DEPLOY_SHA" npm run --silent promote:quality-db -- \
  --source "$QUALITY_DB" --destination "$PRIMARY_DB" --apply \
  | tee ./promotion-report.json
export BACKUP_PATH="$(jq -r '.backupPath' ./promotion-report.json)"
test -f "$BACKUP_PATH"
```

Promotion snapshots the source with `VACUUM INTO`, records holders across the complete source and destination SQLite families (main, `-wal`, `-shm`, and `-journal`) plus active and stale lease rows in the report, strips every `refresh_leases` row from the staged database, and reports the captured/stripped/remaining counts. Apply refuses an active or malformed source lease, any live holder on either SQLite family, or corresponding destination activity before staging can hide it. After staging it revalidates the source before the awaited independent GitHub catalog check, then repeats the full source family, holder, lease, and logical-identity revalidation after that check; only synchronous boundary checks remain before the atomic swap. Replacement or content drift aborts. Expired source lease rows are reported as stale and removed only from the staged install; the source database is not modified.

Before any swap, the source and final staged DB must pass doctor with `--fail-on-warnings`, full score recomputation with `verify-new-scoring --all`, full release-audit invariants with `--all`, and an exact replay of the latest immutable prospective-validation evaluation receipt. Only status `validated` is promotable. `Insufficient`, `measurable_but_failed`, malformed or semantically invalid ledgers, hidden failed models, a missing or stale evaluation receipt, or any ID/hash mismatch are rejected. Calibration promotion receipts never authorize production. The staged database receives a production promotion receipt bound to the exact evaluation ID/content hash plus the source and destination logical database digests. Dry-run reports this receipt only from its disposable stage and explicitly cannot authorize a later apply; apply records it in the installed database.

An internally consistent obsolete model or wrong score arithmetic is also rejected. Destination-only `ingestion_evidence_failures`, `comparison_snapshots`, and `comparison_releases` are merged exactly; primary-key conflicts or changes during staging abort instead of dropping or rewriting evidence. `issue_state_event_snapshots` and `release_closure_dependency_snapshots` are score inputs, so they are not merged into the verified quality DB. Promotion requires their canonical source columns, primary keys, and indexes even when an older destination does not have the tables, and aborts if either destination table changes while staging. A successful install keeps the source snapshots while the rollback backup retains the destination snapshots.

Exhaustive issue-catalog snapshots are resumable operational data owned by the promoted source database. Promotion verifies their append-only tables as immutable source ledgers and installs the source snapshot chain exactly; it does not merge older destination staging rows, whose repository/age context may no longer match the promoted quality run. The rollback backup retains the prior destination chain.

Immutable advisory, forecast, validation-opportunity enrollment, outcome, validation-observation batch, issue-catalog consumption, and history ledgers remain fail-closed. Promotion requires every destination row in those ledgers to exist exactly in the verified source snapshot; destination-only evidence aborts promotion instead of being dropped. Their update/delete triggers are checked as unconditional append-only guards, and their complete row identities are included in source, destination, staged, and promotion-doctor digests. Promotion requires both revision-aware partial forecast-series unique indexes and rejects identities that omit `code_revision`. Existing forecast rows, hashes, and outcome links are preserved during migration. Refresh operation attempts and stage events are merged only when duplicate identities are exact. The destination capture-receipt chain remains the exact prefix of the promoted ledger; source-only receipts are appended in source order with new chain links, then the complete attempt/stage/receipt ledger is rechecked for hashes and foreign keys. `operationReceiptMerge.receipts.identityMappings` records each source receipt's run/receipt IDs, original and merged chain hashes, and matching semantic-identity digests so rehashing is explicitly auditable. Any destination operation-receipt change during staging aborts. When the destination has a valid sealed score-history extension, promotion preserves it and updates only `score_persistence_last_run.historyRunId` and `historyRunContentHash` to the merged history tip.

Before swapping, apply checkpoints the destination, requires any `-wal` or `-journal` contents recreated by read-only doctor/identity inspection to be empty, clears the resulting `-wal`, `-shm`, and `-journal` sidecars, verifies the logical contents and inode again, and preserves owner, group, mode, ACLs, and extended attributes on both the installed database and rollback backup. It checks holders across both complete SQLite families and active refresh leases before final success and around rollback, including after the backup has been restored. The backup path is `PRIMARY_DB.pre-promotion-<UTC>.bak` and is returned as `backupPath`. A post-swap failure attempts rollback automatically and retains that independent backup. Apply holds `RADAR_DEPLOY_LOCK_PATH` for the complete operation; its default is `/opt/openclaw-release-radar/shared/deploy-promotion.lock`, exactly the same `flock` lock used by release activation, commit, rollback, and watchdog recovery.

For an operator-requested rollback after a successful promotion, stop the
service, verify the main DB and its `-wal`, `-shm`, and `-journal` sidecars have
no holders, and restore atomically from the reported backup:

```bash
export ROLLBACK_SHA="<exact-raw-SHA-of-restored-release>"
node -e "const { DatabaseSync } = require('node:sqlite'); const db = new DatabaseSync(process.argv[1]); db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close()" "$PRIMARY_DB"
rm -f "$PRIMARY_DB-wal" "$PRIMARY_DB-shm" "$PRIMARY_DB-journal"
FAILED_DB="${PRIMARY_DB}.failed-$(date -u +%Y%m%dT%H%M%SZ)"
RESTORE_DB="${PRIMARY_DB}.restore"
rm -f "$RESTORE_DB" "$RESTORE_DB-wal" "$RESTORE_DB-shm" "$RESTORE_DB-journal"
mv "$PRIMARY_DB" "$FAILED_DB"
cp -a "$BACKUP_PATH" "$RESTORE_DB"
mv "$RESTORE_DB" "$PRIMARY_DB"
DB_PATH="$PRIMARY_DB" RADAR_CODE_REVISION="$ROLLBACK_SHA" RADAR_DB_READ_ONLY=1 \
  npm run doctor -- --fail-on-warnings
sudo systemctl restart openclaw-release-radar.service
curl --fail http://127.0.0.1:8787/api/health
```

Do not copy or replace a live SQLite family (the main file plus `-wal`, `-shm`,
and `-journal`). Restore the database while the service is stopped, then restart
the old code and require semantic readiness before declaring rollback complete.

`npm run backfill:issue-comment-snapshots -- --all-scored` fetches comments for the current audited release issue universe, including audited null-score `wait` releases, and writes `issue_comment_snapshots` rows with total/fetched comment counts, latest comment update time, a digest, matching issue `updated_at`, and the validated comment cache used by closure analysis. The command holds the shared renewable write lease, detects staged revision races, and supersedes only a prior failure with the exact same release/issue scope after the snapshot transaction succeeds. Run the explicit read-only `DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 npm run verify:local` form afterward; if snapshots are newer than the current score, run the full monitored closed-window backfill.

`npm run backfill:issue-state-events -- --limit 10` fetches close/reopen timeline evidence and snapshots current labels for the current audited issue universe, including audited null-score `wait` releases, so release attribution uses issue open intervals and latest-release scores have reproducible label evidence. It holds the shared renewable write lease, fetches all GitHub state evidence before writing, requires two consecutive exhaustive canonical state-event sweeps per chunk, verifies that local issue/snapshot/classification revisions did not change while work was staged, then writes snapshots, closure/reopen events, PR links, and PR rows in one transaction. Successful chunks and writes supersede only failures with the exact same source and issue scope. Fetch failures, stabilization failures, missing issue aliases, races, or write failures are recorded in `ingestion_evidence_failures`; post-commit failures are reported as post-commit instead of claiming the transaction rolled back.

`npm run check:release-pr-reachability -- <tag>` rebuilds PR merge-commit reachability for one release tag under the shared renewable write lease. It stages the full replacement set before writing, then swaps rows in one transaction; git evidence failures leave the previous rows intact and are recorded as score-blocking `ingestion_evidence_failures`. A successful post-commit lease check supersedes only the exact prior source/scope/release failure tuple.

`npm run backfill:closed-windows -- --all` first validates issue crawl schema v4 and the stored exhaustive baseline schema v2, then classifies raw closed-window issues missing current classification rows, stages all classification results before writing them in one transaction, reruns closure evidence, reachability, and closure proof for audited stable releases, and recomputes cross-release proof dependencies to a bounded fixed point. Score persistence uses the complete release set from `score_persistence_last_run`, including audited null-score `wait` releases. A scoped `--tags` or smaller `--limit` run, `--skip-proof`, or `--skip-score` returns an explicit `staged-only` score result and does not clear or replace any score/audit rows. A full score commit is attempted only when the refreshed proof scope covers every monitored release. Each successful stage supersedes only its exact prior source/scope/release/issue failure; skipped proof, reachability, and score stages never clear their failures.

`npm run dev` runs TypeScript directly with watch mode.

`npm start` runs the compiled app from `dist/` with `NODE_ENV=production`; it
requires the installer-managed release layout and startup authorization. Use
`npm run dev` for a local preview.

Refresh computes closure proof automatically. During refresh and closed-window backfill, closure proof updates side-table proof rows but leaves `release_score_audits` unchanged until a complete monitored-window score write succeeds, so a failed evidence pass cannot attach fresh proof payloads to stale scores. `npm run analyze:closure-proofs -- <tag>` reruns closure evidence, PR reachability, and analyzer-v8 proof for that tag under the shared lease, then returns `score.status: "staged-only"` without recording a misleading score failure or replacing unrelated scores/audits. A successful rerun supersedes only its own exact prior failure tuple. Run `npm run backfill:closed-windows -- --all` to rebuild all monitored proofs and commit the complete score window.

`npm run ingest:fix-provenance -- <tag>` is kept as a compatibility alias and now runs the same guarded closure-proof/reachability pipeline.

All three write-capable single-release commands require an explicit tag and fail before loading database writers when it is omitted; none infers a default or latest release.

## Local Data

The application fallback is:

```text
./data/radar.db
```

Operator workflows in this README do not rely on that fallback; they name a separate quality DB explicitly.

To reset local data:

```bash
rm -f ./data/*.db ./data/*.db-* ./data/*.db-wal ./data/*.db-shm ./data/*.db-journal
```

This also deletes durable refresh attempts/stage events/capture receipts, append-only score history, prospective forecasts, outcomes, and advisory snapshots. Export any validation ledger you need before wiping:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run validation:snapshot -- --output ./release-validation-forecasts.json
```

This reads the explicit DB and writes only the requested JSON export.

Then rebuild that separate quality DB. Do not start a server against it while
the full refresh is writing:

```bash
export QUALITY_DB="$PWD/data/radar-quality.db"
export DEPLOY_SHA="$(git rev-parse --verify HEAD)"
test -z "$(git status --porcelain)"
RADAR_CODE_REVISION="$DEPLOY_SHA" \
RELEASES_LIMIT=10 CLASSIFY_CONCURRENCY=5 \
  npm run refresh:quality -- --db-path "$QUALITY_DB"
DB_PATH="$QUALITY_DB" RADAR_CODE_REVISION="$DEPLOY_SHA" RADAR_DB_READ_ONLY=1 \
  npm run verify:local
```

The refresh is exhaustive and may spend additional OpenAI API credits.

## Deployment

The included GitHub Actions workflow deploys `main` over SSH.
Before pushing `main` or starting a deployment, complete the single full gate
described under Development Commands after implementation has stabilized.

Set these GitHub Actions repository variables:

```text
DEPLOY_HEALTH_URL=https://your-domain.example/api/health
DEPLOY_MAX_SCORE_AGE_HOURS=24
DEPLOY_MAX_REFRESH_AGE_HOURS=24
DEPLOY_QUALITY_DB_PATH=/absolute/server/path/to/verified-quality.db
DEPLOY_REQUIRED_PROMOTION_RECEIPT_ID=<current promoted score receipt ID>
```

`DEPLOY_QUALITY_DB_PATH` and `DEPLOY_REQUIRED_PROMOTION_RECEIPT_ID` are mandatory and deliberately have no defaults. The path must identify the separately built and fully verified quality database on the deployment server. The receipt ID must be that database's exact current successful score receipt. Deployment refuses a different receipt, an unverified or failed receipt, a receipt whose attempt or terminal payload revision differs from the release SHA, a non-validated prospective evaluation, or score/refresh data older than the configured limits.

Set these SSH secrets:

```text
DEPLOY_SSH_HOST
DEPLOY_SSH_PORT
DEPLOY_SSH_USER
DEPLOY_SSH_KEY
DEPLOY_SSH_KNOWN_HOSTS
DEPLOY_VERIFIER_HMAC_KEY
```

`DEPLOY_VERIFIER_HMAC_KEY` must contain at least 32 bytes. Install the exact same value on the server before the first deployment:

```bash
sudo install -d -o root -g root -m 0700 /etc/openclaw-release-radar
umask 077
printf '%s\n' "$DEPLOY_VERIFIER_HMAC_KEY" |
  sudo tee /etc/openclaw-release-radar/deploy-verifier.key >/dev/null
sudo chown root:root /etc/openclaw-release-radar/deploy-verifier.key
sudo chmod 0600 /etc/openclaw-release-radar/deploy-verifier.key
```

The workflow compares the SHA-256 key ID without transmitting the key to the server. A missing key, unsafe owner/mode, mismatched key ID, invalid HMAC, reused verifier identity, or conflicting verifier identity fails deployment.

Provision the base application service once before enabling automated deploys.
The workflow installs and verifies the reconciliation units and service drop-in;
it deliberately refuses to invent or replace the base service. The default
deployment contract also requires Node 24 at `/opt/node-v24/bin/node`, npm at
`/opt/node-v24/bin/npm`, and the Linux `lsof`, `getfacl`, and `getfattr`
commands.

```bash
sudo install -d -o root -g root -m 0755 \
  /opt/openclaw-release-radar \
  /opt/openclaw-release-radar/releases
sudo install -d -o root -g www-data -m 0750 \
  /opt/openclaw-release-radar/shared

sudo tee /etc/systemd/system/openclaw-release-radar.service >/dev/null <<'UNIT'
[Unit]
Description=OpenClaw Release Radar
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/opt/openclaw-release-radar/current
Environment=NODE_ENV=production
ExecStart=/opt/node-v24/bin/node /opt/openclaw-release-radar/current/dist/index.js
Restart=on-failure
RestartSec=5
UMask=0027

[Install]
WantedBy=multi-user.target
UNIT
sudo systemctl daemon-reload
sudo systemctl enable openclaw-release-radar.service
```

The workflow pins third-party actions by commit SHA, builds and verifies the app, installs Chromium through the existing Playwright development dependency, and stages the complete compiled `dist` tree with production-only `node_modules`. The artifact also includes the versioned installer and a self-contained production-only promotion runtime. Its schema-4 manifest embeds installer protocol `5`, the GitHub SHA, the same `runtimeCodeRevision`, a digest over the non-manifest payload, and exact SHA-256 bindings for the installer, application service, boot reconciler, reconciler service, reconciliation timer, and service drop-in. The installer verifies those files inside the artifact, and both installer and workflow require the served manifest to match the same complete object. Before upload, the workflow requires the installed server-side script to complete a protocol `5` handshake:

```text
/usr/local/bin/openclaw-release-radar-install-release
```

That installer expects shared runtime config at:

```text
/opt/openclaw-release-radar/shared/.env
```

Production `shared/.env` must be a regular non-symlink file owned by `root:www-data` with mode `0640` (override the expected owner/group/mode only through the installer service environment). It must set an absolute `DB_PATH` outside `releases/`, use `PORT=8787` for the default deployment probes, explicitly keep `REFRESH_ON_STARTUP=false` and `REFRESH_MINUTES=0`, and omit `RADAR_CODE_REVISION`/`CODE_REVISION`. The installer creates `shared/runtime-env/<release>.env`, copies the shared settings, and appends the exact raw manifest/GitHub deployment SHA as `RADAR_CODE_REVISION`, with no `git:` prefix. Readiness requires `/api/validation/opportunities` to report that exact revision.

The installer performs no server-side dependency installation or network package fetch. The serving application does not contain `tsx`; database promotion runs only from the verified `promotion-runtime` bundled in the release artifact. The workflow uploads to a transaction-specific `/tmp/<release>-<transaction-id>.tar.gz` path. After writing and fsyncing activation intent, the installer requires a same-filesystem atomic rename into `shared/deploy-artifacts/<transaction-id>.tar.gz`, changes ownership to the release owner with mode `0600`, and binds the compressed byte digest and size into the intent and pending-state hashes. Recovery and cleanup accept only that exact transaction-owned path and fail closed if the file is replaced, linked, symlinked, or changed. An interruption before adoption leaves the external upload untouched.

The installer extracts into a fresh staging directory, rejects unsafe archive paths, verifies the manifest, control-plane hashes, payload digest, installer protocol, runtime contents, production environment, database location, and semantic readiness, and smoke-loads the compiled API with the production Node runtime before changing live state. It owns release code as `root:root`, removes group/other write bits, and keeps runtime-writable locations separate under `shared/` (`deploy-artifacts`, `install-smoke`, runtime envs, deployment backups, logs, and immutable deployment completion receipts). The `www-data` runtime must not own release code. Existing same-name releases are never deleted: identical contents may be reused, while different contents fail closed. Watchdog logs are created with unique names inside a validated non-symlink, root-owned directory rather than by following a predictable log path.

Immediately before promotion, activation stops the old service and creates a consistent SQLite `backup()` snapshot at `shared/deploy-backups/<release>-<transaction-id>/pre-migration.sqlite`. It publishes one hash-bound pending transaction containing the transaction ID, release/SHA/artifact identity, exact production and quality database paths, rollback snapshot path and physical digest, required score receipt, previous `current` target, and installer-created artifact ownership. The bundled promotion runtime then inherits the already-held deployment lock. The installer accepts the promotion report only when it exact-binds that pending transaction, source receipt and code revision, quality/production/rollback database identities, production promotion receipt, and the unchanged rollback-backup digest.

Activation atomically replaces the `current` symlink only after promotion succeeds, then requires exact local health, served manifest, API code provenance, status receipt, and receipt verification before handing control back to the workflow. On failed activation or explicit pending rollback, the installer stops the candidate, atomically restores the pre-promotion snapshot while clearing `-wal`, `-shm`, and `-journal` sidecars, switches `current` back, restores and restarts the prior release when one exists, and waits for semantic readiness. Old code is never restarted against the promoted candidate database.

External verification uses protocol-4 HMAC authorization. The attestation binds the workflow run/attempt, transaction ID, pending-state hash, release identity, deadline, and the immutable `activated` phase-transition hash. The installer first fsyncs `verification-authorization.json`, then appends and fsyncs the `verified` phase transition. A lost response is idempotently recoverable: when the current phase is already `verified`, authorization is revalidated against that transition's `previousHash`, which must be the original `activated` hash. Conflicting verification identities and any authorization or phase-chain tampering fail closed.

Commit and rollback are crash-recoverable transactions. Before the active pending directory is renamed, the installer writes and fsyncs a content-hashed finalization record bound to the pending-state hash, outcome, transaction ID, release name, SHA, and artifact digest. Cleanup runs only while holding the deployment lock. It verifies that `current` agrees with the recorded committed or rolled-back outcome, removes installer-owned recovery artifacts, and moves the finalized state into `shared/deploy-completions/` only after every cleanup step succeeds. A SIGKILL before rename, after rename, or during cleanup remains retryable. Malformed records, changed hashes, symlinked fields, multiple active finalization markers, conflicting outcomes, or contradictory live state fail closed without deleting recovery evidence.

The control plane installs:

```text
openclaw-release-radar-reconcile-boot.service
openclaw-release-radar-reconcile.service
openclaw-release-radar-reconcile.timer
openclaw-release-radar.service.d/10-deploy-reconcile.conf
```

The application service `Requires=` the boot reconciler and starts only after it succeeds. Boot reconciliation rolls back an unverified transaction, but preserves a durably verified transaction without starting network-dependent readiness checks. The enabled five-minute timer later rechecks readiness and commits it. The timer also rolls back an expired unverified transaction.

All installer actions and `promote:quality-db --apply` serialize on `/opt/openclaw-release-radar/shared/deploy-promotion.lock` by default. Keep `RADAR_DEPLOY_LOCK_PATH` identical in the installer service environment and the promotion shell.
Installer-owned promotion does not trust a lock environment flag: it runs the
declared npm lifecycle with the already-locked file descriptor inherited as FD
9, and rejects the promotion report unless its device, inode, path, and
exclusive-lock proof match the installer transaction.

After local activation, both installer and workflow require `/api/health` to be `ready` with every check passing, the served manifest to match the exact release, and API revision provenance to match the GitHub SHA. The workflow additionally verifies `/api/status` plus `/api/receipts/<id>` against `DEPLOY_REQUIRED_PROMOTION_RECEIPT_ID`, then runs the full Playwright UI smoke. `/api/live` is intentionally insufficient. `commit` and `rollback` are idempotent for the exact release identity: a lost SSH response can be retried and is resolved from the authenticated active-finalization state or immutable completion receipt. After a failed commit step, the workflow retries commit first and rolls back only when no durable commit can be recovered.

Installer status is transaction-scoped:

```bash
sudo /usr/local/bin/openclaw-release-radar-install-release status \
  <release-name> <github-sha> sha256:<artifact-digest> <transaction-id>
```

It reports `preparing`, `pending_verification`, `verified`, `commit_decided`, `rollback_decided`, `committed`, `rolled_back`, or `not_found`. Pending responses include the deadline, pending-state hash, phase, phase-transition hash, authorization state, and verifier identity where applicable.

To roll back a release that is still pending workflow commit:

```bash
sudo /usr/local/bin/openclaw-release-radar-install-release rollback \
  release-<sha> <sha> sha256:<artifact-digest> <transaction-id>
curl --fail http://127.0.0.1:8787/api/health
```

Focused local coverage for the deployment transaction:

```bash
# Required when installer code or protocol handling changed.
npm run test:preflight
npm run test:focus -- src/lib/installRelease.test.ts
npm run test:focus -- src/lib/promoteQualityDb.test.ts
npm run verify:ci
```

Add `--authoritative` before either manifest file when that focused case must
exercise the real Seatbelt, database-guard, private-fixture, and audit path.

## Git Remote Setup

This repo should push only to your fork:

```text
origin   https://github.com/hannesrudolph/openclaw-release-radar.git
```

If you keep the original project as a reference remote, make it fetch-only:

```bash
git remote set-url --push upstream DISABLED
```

Current recommended shape:

```text
origin   https://github.com/hannesrudolph/openclaw-release-radar.git (fetch)
origin   https://github.com/hannesrudolph/openclaw-release-radar.git (push)
upstream https://github.com/iClawApp/openclaw-release-radar (fetch)
upstream DISABLED (push)
```

## License

MIT
