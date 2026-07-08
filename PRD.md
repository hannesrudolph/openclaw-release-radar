# Release Radar Quality Convergence

## Objective

Make release analysis, measurement, evidence provenance, scoring, refresh, validation,
deployment, and public presentation first-class and auditable.

## Acceptance Criteria

1. **Complete, immutable evidence**
   - GitHub release, issue, comment, label, state-event, advisory, closure-proof, and
     reachability ingestion is paginated, identity-bound, and completeness-checked.
   - Unknown or missing evidence fails closed and never silently becomes fix credit or
     a favorable score.

2. **Defensible scoring**
   - Numeric scores and recommendation decisions derive only from verified evidence,
     deterministic policy, and immutable source identities.
   - Classification authority, aliasing, label overrides, advisory handling, release
     linkage, and carryover treatment have adversarial coverage.
   - Public explanations are human-readable and match the exact score ledger.

3. **Prospective measurement**
   - Forecast cohorts, opportunity denominators, holdouts, horizons, attrition,
     censoring, and outcome observations are immutable and hash-chain verified.
   - Validation cannot pass until every required opportunity-by-horizon cell meets its
     documented sample and quality thresholds.

4. **Atomic publication**
   - A refresh publishes score rows, sealed history, forecasts, recommendation
     decisions, and its terminal success receipt in one lease-fenced transaction.
   - Failed, abandoned, or receiptless refreshes cannot expose a partial score and
     restore the last sealed actionable publication where applicable.

5. **Robust execution**
   - GitHub, OpenAI, npm, and git work supports bounded concurrency, cancellation,
     timeout cleanup, sibling failure handling, and durable partial classification work
     without publishing an incomplete score.
   - Automatic background refresh remains disabled during calibration.

6. **Coherent API and UI**
   - Score-bearing API responses use one explicit snapshot and never mix partial refresh
     data, retained diagnostics, or comparison artifacts into actionable output.
   - Hard refresh, loading, stale, error, retry, active-refresh, mobile, and accessibility
     states are covered by smoke tests.
   - Upstream comparison remains an internal calibration artifact and is absent from the
     primary product UI.

7. **Verified release**
   - The isolated full test suite, typecheck, script verification, build, safety guard,
     quality-database checks, guarded refresh, API verification, and UI smoke tests pass.
   - The live database is untouched until a separately verified quality database is
     promoted through the guarded installer.
   - Commit and push occur only after every preceding criterion has authoritative evidence.

## Boundaries

- Do not use `data/radar.db` for integration work.
- Do not commit, push, deploy, or promote a database before final verification.
- Preserve immutable evidence ledgers and existing user changes.
- Prefer correctness, provenance, and release linkage over runtime.
