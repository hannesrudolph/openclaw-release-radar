# OpenClaw Release Radar

Stability monitor for [`openclaw/openclaw`](https://github.com/openclaw/openclaw).
Polls GitHub issues every 20 minutes, classifies each via LLM across 7 dimensions
(sentiment, severity, scope, functionality, affected users, workaround, duplicate cluster),
and scores every release on a 0–10 stability scale.

Inspired by `agent-watch`; this is a slim Node/Express port for a single repo.

## How scoring works

Methodology is ported from
[`agent-watch`'s release-stability-evaluation](https://github.com/davideuler/agent-watch/blob/main/release-stability-evaluation.md)
with deliberate recalibration (softer weights, log-curve at the heavy end,
bot dampening). Values below are the source of truth — match `src/lib/score.ts`.

### 1. Grace period for new releases

Releases younger than **3 hours** are pinned to a neutral **5.0** with state
`analyzing` — there is no useful signal yet.

### 2. Per-issue risk weight

For every issue with `sentiment = "negative"` attributed (by the LLM, via
explicit `affectsVersion`) to the release:

```
raw = recency × discussionBoost × duplicateBoost × confidence
    × SEVERITY × SCOPE × FUNCTIONALITY × USER_SHARE × WORKAROUND
    × botFactor

weight = min(raw, PER_ISSUE_CAP)        // PER_ISSUE_CAP = 4
```

| Factor                | Values → Weights                                              |
| --------------------- | ------------------------------------------------------------- |
| **SEVERITY**          | critical 2.2 · high 1.4 · medium 0.7 · low 0.25               |
| **SCOPE**             | broad 1.5 · moderate 1.0 · niche 0.4                          |
| **FUNCTIONALITY**     | core 1.3 · provider 0.65 · integration 0.4 · docs 0.1         |
| **USER_SHARE**        | many 1.3 · some 0.85 · few 0.35 · unknown 0.65                |
| **WORKAROUND**        | none 1.0 · unknown 0.85 · partial 0.65 · confirmed 0.35       |
| **recency**           | `0.55 + 0.45 × exp(−ageDays / 45)` (half-life 45 d)           |
| **discussionBoost**   | `1 + min(1.4, log10(1 + comments) × 0.45)`                    |
| **duplicateBoost**    | `1 + log2(clusterSize) × 0.28` (1× if no cluster)             |
| **confidence**        | LLM 0–1, floored at 0.2                                       |
| **botFactor**         | 0.3 if `is_bot` (matches `dependabot`, `*[bot]`, …); else 1.0 |

Bot-authored issues are still counted, just dampened — they tend to over-report
(one human bug → many bot pings) and would otherwise inflate volume.

### 3. Core-serious vs other split

Each negative is bucketed:

* **core-serious** = `functionality == core` AND `severity ∈ {critical, high}`
* **other** = everything else

Positive issues form a budget:

```
posBudget = 0.7 × Σ positiveWeight
```

The budget cancels *other* negatives first, then any residual cancels
*core-serious* negatives.

### 4. Score formula

```
coreScore = 10 − log2(1 + effectiveCore) × 1.5      // RISK_LOG_FACTOR = 1.5
otherDrop = 1.5 × (1 − exp(−effectiveOther / 3.5))  // OTHER_DROP_MAX = 1.5
baseScore = clamp(coreScore − otherDrop, 1.0, 10)
```

The log curve (vs `agent-watch`'s sigmoid) keeps separation at the very-bad
end — two releases with risk 25 vs 35 stay distinguishable instead of both
flooring to 1.

Calibration target:

| risk | score | grade            |
| ---- | ----- | ---------------- |
| 0    | 10    | STABLE           |
| 2.5  | 7.3   | MOSTLY STABLE    |
| 6    | 5.8   | MIXED            |
| 12   | 4.5   | RISKY            |
| 20   | 3.4   | RISKY / UNSTABLE |
| 30   | 2.6   | UNSTABLE         |
| 50   | 1.5   | UNSTABLE         |

### 5. Peer-median floor

If this release's `weightedNegSum` is at or below the project's own median
(across all rated releases with negative signal, min 3 such releases) AND
`baseScore < 5.5`, it is floored to **5.5**. Prevents an
average-or-better release from looking catastrophic on the absolute scale.

### 6. Insufficient signal

* Empty issue set → neutral **5.0**, state `insufficient`.
* Only neutral/positive issues → neutral **5.0**, state `insufficient`.
  (Without this guard, "no negatives" would score a perfect 10, which would
  conflate "good release" with "we don't have evidence".)

### Attribution

Only issues with an explicit, LLM-extracted `affectsVersion` count toward
that version's score. Unattributed negative issues are deliberately dropped
rather than charged against the latest release — same model as `agent-watch`.

## Setup

Requires **Node ≥ 22.5** (uses the built-in `node:sqlite` module — no native build, no prebuilds, zero compile steps).

```bash
cp .env.example .env
# fill in OPENAI_API_KEY; optionally GITHUB_TOKEN to raise rate limits
npm install
npm run dev
```

Open <http://localhost:8787>.

### Env vars

| var | default | notes |
| --- | --- | --- |
| `GITHUB_OWNER` | `openclaw` | |
| `GITHUB_REPO`  | `openclaw` | |
| `GITHUB_TOKEN` | (empty)    | optional PAT — 60 req/h → 5000 req/h |
| `OPENAI_API_KEY` | — | required |
| `OPENAI_MODEL` | `gpt-4o-mini` | |
| `PORT` | `8787` | |
| `DB_PATH` | `./data/radar.db` | SQLite file |
| `REFRESH_CRON` | `*/20 * * * *` | every 20 minutes |
| `RELEASES_LIMIT` | `10` | how many releases to score |

## API

| method | path | purpose |
| --- | --- | --- |
| `GET`  | `/api/health` | repo info |
| `GET`  | `/api/status` | refresh state |
| `GET`  | `/api/releases` | scored releases |
| `GET`  | `/api/release/:tag` | release + classified issues |
| `GET`  | `/api/unversioned` | issues with no detected version |
| `POST` | `/api/refresh` | force a refresh (blocks if one is running) |

## Production

```bash
npm run build
node dist/index.js
```

Run behind a reverse proxy (nginx/Caddy). State is a single SQLite file in `./data/` —
back that directory up.

### GitHub Actions deploy

The repo includes `.github/workflows/deploy-radar.yml`.

Recommended usage:

* deploy automatically on push to `main`
* optional manual re-run via **Actions → Deploy radar.iclaw.digital**

Required GitHub secrets:

* `DEPLOY_SSH_HOST`
* `DEPLOY_SSH_PORT`
* `DEPLOY_SSH_USER`
* `DEPLOY_SSH_KEY`

What the workflow does:

1. builds the app in CI
2. packages a tarball with `dist/`, `public/`, and package manifests
3. uploads the tarball to `viralo` over SSH
4. invokes `/usr/local/bin/openclaw-release-radar-install-release`
5. verifies `https://radar.iclaw.digital/api/health`

The workflow assumes:

* release root: `/opt/openclaw-release-radar`
* shared env: `/opt/openclaw-release-radar/shared/.env`
* shared data: `/opt/openclaw-release-radar/shared/data/`
* current symlink: `/opt/openclaw-release-radar/current`
* service name: `openclaw-release-radar.service`
* release installer: `/usr/local/bin/openclaw-release-radar-install-release`
* runtime secrets stay server-side and are not part of the tarball

## Cost (gpt-4o-mini)

* ~5–15 changed issues per refresh → ~2k tokens each
* ~$0.10–0.30 / month
* GitHub API: free tier covers it; PAT optional

## License

MIT
