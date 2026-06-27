# Agent Guidance

## Parallel Agent Usage

For this repository, aggressively use parallel subagents for substantial work.

- The user has explicitly authorized using up to 50 subagents when the task benefits from parallel exploration or implementation.
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
