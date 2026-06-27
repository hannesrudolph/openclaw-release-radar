# OpenClaw Release Radar

OpenClaw Release Radar is a small dashboard that answers:

> Which OpenClaw stable release should I install right now?

It watches `openclaw/openclaw`, pulls releases, issues, comments, and advisory data from GitHub GraphQL, classifies issue impact with OpenAI, stores the result in SQLite, and serves a local web UI plus JSON API.

![OpenClaw Release Radar screenshot](docs/screenshot.png)

## Current Status

This is now maintained from:

```text
https://github.com/hannesrudolph/openclaw-release-radar
```

It is intended to be deployed under your own domain. The old `isitstable.iclaw.digital` / `radar.iclaw.digital` references are not part of this setup.

## Quick Start

Requirements:

- Node.js `>=22.5`
- npm
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

Edit `.env`:

```bash
GITHUB_OWNER=openclaw
GITHUB_REPO=openclaw

OPENAI_MODEL=gpt-5.5

PORT=8787
DB_PATH=./data/radar.db
REFRESH_MINUTES=0
RELEASES_LIMIT=10
FULL_ISSUE_BACKFILL=false
MAX_ISSUE_PAGES=500
```

Secrets can live in your shell/global environment instead of `.env`:

```bash
GITHUB_PERSONAL_ACCESS_TOKEN=ghp_your_github_token
OC_OPENAI_API_KEY=sk-your_openai_key
```

The app also accepts the conventional names `GITHUB_TOKEN` and `OPENAI_API_KEY` if you prefer those.

Run the app:

```bash
npm run dev
```

Open:

```text
http://127.0.0.1:8787
```

The first refresh can take a few minutes because it backfills GitHub data and classifies issues. Later refreshes only process changed issues.

`REFRESH_MINUTES=0` disables automatic refreshes. Set `FULL_ISSUE_BACKFILL=true` when you need a complete issue-history pass; this is intentionally expensive.

## Internal Calibration Snapshot

During model calibration, you can capture an external rendered UI snapshot as a temporary internal benchmark:

```bash
npm run scrape:upstream
```

The snapshot is stored separately from local model data. It is for internal review only, is not shown in the product UI, and does not overwrite local release scores.

The older public JSON snapshot importer is still available as a one-off utility:

```bash
npm run import:public-snapshot -- https://isitstable.iclaw.digital/api/public
```

Do not use that importer as a benchmark source; it writes into the local release table. Prefer `scrape:upstream`.

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

Health check:

```bash
curl http://127.0.0.1:8787/api/health
```

Refresh status:

```bash
curl http://127.0.0.1:8787/api/status
```

Main public payload:

```bash
curl http://127.0.0.1:8787/api/public
```

Score review:

```bash
curl http://127.0.0.1:8787/api/releases/v2026.6.10/review
```

Scoring rules and evidence sources are documented in [docs/scoring-model.md](docs/scoring-model.md).

A healthy completed refresh has:

```json
{
  "refreshing": false,
  "lastError": null
}
```

## API

| Endpoint | Purpose |
| --- | --- |
| `/api/health` | Basic process and target repo check |
| `/api/status` | Refresh state and last error |
| `/api/releases` | Dashboard release data |
| `/api/releases/history` | Score history |
| `/api/public` | Main install recommendation payload |

## Development Commands

```bash
npm run typecheck
npm test
npm run build
npm start
```

`npm run dev` runs TypeScript directly with watch mode.

`npm start` runs the compiled app from `dist/`.

## Local Data

The SQLite database defaults to:

```text
./data/radar.db
```

To reset local data:

```bash
rm -f ./data/radar.db ./data/radar.db-shm ./data/radar.db-wal
```

Then restart:

```bash
npm run dev
```

This forces a fresh backfill and may spend additional OpenAI API credits.

## Deployment

The included GitHub Actions workflow deploys `main` over SSH.

Set this repo variable or secret to your real domain:

```text
DEPLOY_HEALTH_URL=https://your-domain.example/api/health
```

Set these SSH secrets:

```text
DEPLOY_SSH_HOST
DEPLOY_SSH_PORT
DEPLOY_SSH_USER
DEPLOY_SSH_KEY
```

The workflow builds the app, uploads a tarball, and calls this server-side installer:

```text
/usr/local/bin/openclaw-release-radar-install-release
```

That installer expects shared runtime config at:

```text
/opt/openclaw-release-radar/shared/.env
```

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
