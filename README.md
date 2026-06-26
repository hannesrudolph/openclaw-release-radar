# OpenClaw Release Radar

Release Radar answers one question: **which OpenClaw stable release should I install right now?**

It watches a GitHub repository, pulls releases, issues, comments, and security advisory data through GitHub GraphQL, classifies issue impact with OpenAI, stores the results in SQLite, and serves a small dashboard plus JSON API.

Live instance: https://radar.iclaw.digital/

Default tracked source repo: `openclaw/openclaw`

![OpenClaw Release Radar](docs/screenshot.png)

## What You Need

- Node.js `>=22.5`
- npm
- A GitHub token for GraphQL reads
- An OpenAI API key for issue classification

The app writes its local database to `./data/radar.db` by default.

## 1. Install

```bash
git clone https://github.com/hannesrudolph/openclaw-release-radar.git
cd openclaw-release-radar
npm install
```

If you already have the repo checked out, just run:

```bash
npm install
```

## 2. Create `.env`

```bash
cp .env.example .env
```

Edit `.env` and fill in these required values:

```bash
GITHUB_OWNER=openclaw
GITHUB_REPO=openclaw
GITHUB_TOKEN=ghp_your_token_here

OPENAI_API_KEY=sk-your_key_here
OPENAI_MODEL=gpt-4o-mini

PORT=8787
DB_PATH=./data/radar.db
REFRESH_MINUTES=30
RELEASES_LIMIT=10
```

`GITHUB_OWNER` and `GITHUB_REPO` are the repo being analyzed. They are not this dashboard repo unless you intentionally point the radar at itself.

## 3. Get A GitHub Token

The GraphQL API requires authenticated requests.

For the default public `openclaw/openclaw` target, a classic GitHub personal access token with `public_repo` is enough. If you point the radar at a private repo, use a token that can read that repo.

Quick local option if `gh` is already logged in:

```bash
gh auth status
gh auth token
```

Paste that token into `.env` as `GITHUB_TOKEN`.

## 4. Get An OpenAI Key

Create an API key in your OpenAI account and set:

```bash
OPENAI_API_KEY=sk-your_key_here
```

The first refresh can classify many issues and may take a few minutes. It can also spend OpenAI API credits. Later refreshes reuse cached classifications and only process changed issues.

## 5. Run Locally

```bash
npm run dev
```

Expected startup output looks like:

```text
[radar] listening on http://127.0.0.1:8787
[radar] watching openclaw/openclaw
[refresh] every 30 min
```

Open:

```text
http://127.0.0.1:8787
```

The first page load may show empty or stale-looking data while the startup refresh is running. Check status with:

```bash
curl http://127.0.0.1:8787/api/status
```

When `refreshing` is `false` and `lastError` is `null`, the latest refresh completed.

## Useful API Endpoints

```bash
curl http://127.0.0.1:8787/api/health
curl http://127.0.0.1:8787/api/status
curl http://127.0.0.1:8787/api/releases
curl http://127.0.0.1:8787/api/public
```

`/api/public` is the main machine-readable answer for "which release should I install?"

## Build And Run Production Mode

```bash
npm run typecheck
npm test
npm run build
npm start
```

`npm start` runs the compiled app from `dist/`.

## Configuration

| Variable | Required | Default | Meaning |
| --- | --- | --- | --- |
| `GITHUB_OWNER` | yes | `openclaw` | GitHub owner/org to analyze |
| `GITHUB_REPO` | yes | `openclaw` | GitHub repo to analyze |
| `GITHUB_TOKEN` | yes | none | Token used for GitHub GraphQL reads |
| `OPENAI_API_KEY` | yes | none | Key used for issue classification |
| `OPENAI_MODEL` | yes | `gpt-4o-mini` | OpenAI model used for classification |
| `PORT` | no | `8787` | Local HTTP port |
| `DB_PATH` | no | `./data/radar.db` | SQLite database path |
| `REFRESH_MINUTES` | no | `30` | Automatic refresh interval, 1 to 600 |
| `RELEASES_LIMIT` | no | `10` | Number of stable releases to score |

## Troubleshooting

### `GITHUB_TOKEN is required`

You did not set `GITHUB_TOKEN` in `.env`, or the process was started from a shell that cannot see it.

### GitHub GraphQL errors

Check that the token is valid:

```bash
gh auth status
```

Then verify the target repo exists:

```bash
set -a
source .env
set +a
gh repo view "$GITHUB_OWNER/$GITHUB_REPO"
```

### `OPENAI_API_KEY is not set`

Set `OPENAI_API_KEY` in `.env`. The app can fetch GitHub data without it, but classification will fail and releases will not score correctly.

### The dashboard is empty

Check refresh state:

```bash
curl http://127.0.0.1:8787/api/status
```

If `refreshing` is `true`, wait. If `lastError` has a value, fix that error and restart `npm run dev`.

### Reset local data

Stop the server and remove the SQLite DB:

```bash
rm -f ./data/radar.db ./data/radar.db-shm ./data/radar.db-wal
```

Start the app again:

```bash
npm run dev
```

This forces a fresh backfill and may trigger more OpenAI classification work.

## Deploy Notes

The included GitHub Actions workflow deploys `main` to `radar.iclaw.digital`. It expects SSH deploy secrets to be configured in GitHub Actions and runs:

```bash
npm ci
npm run typecheck
npm run build
```

Local development does not require the deploy workflow.

## License

MIT
