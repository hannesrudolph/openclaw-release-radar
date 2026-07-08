# Agent Guidance

## Parallel Agent Usage

For this repository, aggressively use parallel subagents for substantial work.

- The user has explicitly authorized using up to 50 subagents when the task benefits from parallel exploration or implementation.
- Treat 50 as an absolute ceiling, not a target. Scale workers to current host pressure and expected output volume.
- Prefer spawning multiple focused agents for independent questions, such as ingestion correctness, scoring design, UI comparison, deployment, tests, data validation, API shape, and schema migration.
- Keep each agent task narrow, concrete, and non-overlapping.
- For code-editing workers, assign clear file ownership and tell each worker that other changes may be happening in parallel.
- For read-only exploration, use many explorers rather than one broad explorer when the questions are separable.
- Do not use subagents for trivial single-file edits or quick command checks.

## Current Project Priorities

- Treat scoring quality, issue/release linkage, and evidence provenance as more important than speed.
- Do not trust a release score unless issue pagination, release linkage, and classification coverage are auditable.
- Keep upstream comparison data separate from local model data.
- Avoid automatic background refreshes while the scoring model is being calibrated.

## Database Safety

- Never import `src/lib/db.ts` from an ad hoc command unless `DB_PATH` points to a fresh private temporary database and `DOTENV_CONFIG_PATH` points to an empty file.
- Treat transitive imports as database access: modules such as release scoring, public summaries, doctor/audit helpers, and verifier scripts may reach `src/lib/db.ts` even when the requested function appears pure.
- Every eval, print, stdin, or custom script that imports repository modules must use an explicit fresh private `DB_PATH` and an empty `DOTENV_CONFIG_PATH`.
- Access to a configured live database is supported only through named npm lifecycle commands or the exact app runtimes declared in `package.json`: `tsx watch src/index.ts` for development and `NODE_ENV=production node dist/index.js` for production.
- Writable ad hoc repository imports are globally serialized by a process lock. Do not bypass or remove that lock to gain parallelism.
- Every writable SQLite import also holds a per-database initialization lock through bootstrap and schema migration.
- Use `npm run refresh:quality -- --db-path <path>` instead of invoking `refresh()` through `tsx -e`.
- Prefer the guarded focused runner during implementation for code paths that open SQLite; reserve the full runners for the single full gate described below.
- Do not open or migrate `data/radar.db` during implementation or test work. Promote a separately verified quality database only through the guarded installer.

## Local Resource Safety

- Do not run overlapping full test suites, guarded refreshes, or database-heavy verification jobs.
- Validation is serialized. Full test runs require the explicit `--full` flag, and each entrypoint rejects unsupported forwarded arguments.
- Normal iteration is `npm run test:preflight` only when the installer changed, `npm run test:focus -- <manifest-test-file> [--name <pattern>]`, optional `npm run test:focus -- --authoritative <manifest-test-file> [--name <pattern>]`, then `npm run verify:ci`.
- `npm run test:preflight` checks installer syntax, quoted heredocs, shell here-strings, and protocol handling before any dynamic installer run.
- Both focused forms run one manifest file under the suite and database-writer locks with a fresh private database and empty dotenv. The authoritative form also exercises the real Seatbelt profile, database guard, private installer fixture, and audit contract.
- Run the full gate once, after implementation stabilizes and before push or deploy: choose either `npm test -- --full` or `npm run test:baseline -- --full`, not both.
- Baseline acceptance is separate: review the generated candidate, then run `npm run test:baseline:accept`.
- `npm run verify:authoritative-ci` runs `npm run test:safety` and forces fresh full candidate generation with `npm run test:baseline -- --full --rerun`; it never accepts the candidate.
- For performance work, benchmark the same focused authoritative case before and after each change. Do not rerun the full installer matrix between small edits.
- Subagents must not run tests, builds, typechecks, refreshes, or other database-writing validation. Return implementation work to the parent, which runs validation serially.
- Do not bypass the authoritative suite lock with overlapping direct `npx tsx --test` commands. A focused direct test is allowed only as the sole validation process, with a fresh private `DB_PATH` and empty `DOTENV_CONFIG_PATH`.
- Parallel agents may inspect and edit disjoint files, but database-writing validation must fan in and run serially.
- Before a substantial worker wave or validation run, inspect host load, `apfsd`, virtualization CPU/RSS, and active Codex/Node writers.
- Normalize macOS process CPU percentages against the machine's logical-core count. On this 16-core host, `305%` is roughly three busy cores and is not elevated pressure by itself.
- Do not defer work for aggregate CPU alone. Defer executable validation only for overlapping repository-owned writers, active APFS pressure, real memory/pageout pressure, insufficient free space, or another measured resource limit that threatens correctness.
- On macOS, whole-system disk transfer is pressure telemetry only because it includes unrelated VM, APFS, and application traffic. Enforce repository-owned suite, worker, SQLite, and free-space limits; do not kill repository processes from an unattributed host-wide counter.
- Raw VM disk operations are not part of this repository workflow. Do not attach, mount, inspect, or mutate VM disks during repository work.
- Keep worker and command output bounded. Return concise findings and targeted diffs instead of emitting large files, full test logs, or repository-wide diffs into the Codex session ledger.
