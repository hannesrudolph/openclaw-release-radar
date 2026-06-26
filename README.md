# OpenClaw Release Radar

**Should I install this openclaw stable?** — live at **[radar.iclaw.digital](https://radar.iclaw.digital/)**

Scores each release from GitHub issues: which one to pick, known CVEs, and what integrations it still breaks (Discord, Telegram, MCP, …).

[![OpenClaw Release Radar](docs/screenshot.png)](https://radar.iclaw.digital/)

Source repo: [openclaw/openclaw](https://github.com/openclaw/openclaw)

## Run locally

Node ≥ 22.5.

```bash
cp .env.example .env   # OPENAI_API_KEY and GITHUB_TOKEN required
npm install
npm run dev            # http://localhost:8787
```

## API

`GET /api/releases` · [full JSON](https://radar.iclaw.digital/api/public)

## License

MIT
