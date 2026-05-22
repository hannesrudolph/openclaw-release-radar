# OpenClaw Release Radar

Stability monitor for [`openclaw/openclaw`](https://github.com/openclaw/openclaw).
Polls GitHub issues every 20 minutes, classifies each via LLM across 7 dimensions
(sentiment, severity, scope, functionality, affected users, workaround, duplicate cluster),
and scores every release on a 0–10 stability scale.

Inspired by `agent-watch`; this is a slim Node/Express port for a single repo.

## How scoring works

Each negative issue gets a weight:

```
weight = recency × discussionBoost × duplicateBoost × confidence
       × SEVERITY × SCOPE × FUNCTIONALITY × USER_SHARE × WORKAROUND
```

Positive issues cancel negative ones (non-core first, then core).
Final formula:

```
baseScore = 10 / (1 + (riskIndex / 4.2) ^ 1.35)
```

* recency: exponential decay, half-life 45 days
* discussionBoost: log-scaled by comment count
* duplicateBoost: log2 of cluster size — same root cause across N issues amplifies
* SEVERITY: critical 3.0 · high 2.0 · medium 1.0 · low 0.4
* SCOPE: broad 1.6 · moderate 1.0 · niche 0.5
* FUNCTIONALITY: core 1.5 · integration 1.0 · provider 0.8 · docs 0.2
* USER_SHARE: many 1.4 · some 1.0 · few 0.6 · unknown 0.8
* WORKAROUND: yes 0.6 · no 1.0

Unversioned negative issues are charged against the latest release.

## Setup

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
| `ISSUES_LIMIT` | `80` | how many recent issues per refresh |
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

## Cost (gpt-4o-mini)

* ~5–15 changed issues per refresh → ~2k tokens each
* ~$0.10–0.30 / month
* GitHub API: free tier covers it; PAT optional

## License

MIT
