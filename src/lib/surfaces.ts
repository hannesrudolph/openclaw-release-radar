// Map an issue title to a specific product surface (channel / provider) so the UI can
// show WHAT a release breaks ("Discord", "Ollama"), not just an abstract score.
//
// Why titles and not labels: openclaw barely uses surface labels (observed on 4 of
// 2395 open issues), so the issue title is the only reliable signal. This is a
// heuristic — it nails the named channels/providers users care about and lumps the
// rest as "unnamed" (the caller just shows the top named ones + "+N more").
//
// `icon` is the filename stem under public/icons/<icon>.svg. '_generic' is a neutral
// mark used when we have no (open-source) brand icon for that surface.

export interface Surface {
  re: RegExp;
  label: string;
  icon: string;
}

// Order matters — first match wins. Channels first, then providers; specific names
// before generic ones.
export const SURFACES: Surface[] = [
  // ── channels ──
  { re: /\bdiscord\b/i,            label: 'Discord',    icon: 'discord' },
  { re: /\btelegram\b/i,           label: 'Telegram',   icon: 'telegram' },
  { re: /\bslack\b/i,              label: 'Slack',      icon: 'slack' },
  { re: /\bwhatsapp\b/i,           label: 'WhatsApp',   icon: 'whatsapp' },
  { re: /\b(wechat|weixin)\b/i,    label: 'WeChat',     icon: 'wechat' },
  { re: /\bmattermost\b/i,         label: 'Mattermost', icon: 'mattermost' },
  { re: /\b(feishu|lark)\b/i,      label: 'Feishu',     icon: 'feishu' },
  { re: /\btiktok\b/i,             label: 'TikTok',     icon: 'tiktok' },
  { re: /\b(kakao|kakaotalk)\b/i,  label: 'KakaoTalk',  icon: 'kakaotalk' },
  { re: /\bline bot\b|\bline channel\b/i, label: 'LINE', icon: 'line' },
  { re: /\bimessage\b/i,           label: 'iMessage',   icon: 'imessage' },
  { re: /\bwebchat\b/i,            label: 'WebChat',    icon: 'webchat' },
  // (Signal intentionally omitted — "signal" collides with signal handlers / SIGTERM)
  // ── openclaw UI / extensions ──
  { re: /\bcontrol[- ]ui\b/i,       label: 'Control UI', icon: 'control-ui' },
  { re: /\bdashboard\b/i,          label: 'Dashboard',  icon: 'dashboard' },
  // ── providers ──
  { re: /\bollama\b/i,             label: 'Ollama',     icon: 'ollama' },
  { re: /\b(llama\.cpp|llama)\b/i, label: 'Llama',      icon: 'llama' },
  // Codex MUST precede OpenAI: the `openai-codex` provider (ChatGPT sign-in / OAuth)
  // is a distinct surface from plain `openai` (API key), and many titles mention both
  // ("Codex OAuth falls back to direct OpenAI API"). First-match-wins, so without this
  // ordering ~31% of Codex issues leak into the OpenAI bucket.
  { re: /\b(openai-codex|codex)\b/i, label: 'Codex',    icon: 'codex' },
  { re: /\bopenai\b/i,             label: 'OpenAI',     icon: 'openai' },
  { re: /\b(anthropic|claude)\b/i, label: 'Claude',     icon: 'claude' },
  { re: /\bgemini\b/i,             label: 'Gemini',     icon: 'gemini' },
  { re: /\bdeepseek\b/i,           label: 'DeepSeek',   icon: 'deepseek' },
  { re: /\bmistral\b/i,            label: 'Mistral',    icon: 'mistral' },
  { re: /\bqwen\b/i,               label: 'Qwen',       icon: 'qwen' },
  { re: /\bminimax\b/i,            label: 'MiniMax',    icon: 'minimax' },
  { re: /\bbedrock\b/i,            label: 'Bedrock',    icon: 'bedrock' },
  { re: /\b(xai|grok)\b/i,         label: 'xAI',        icon: 'xai' },
  { re: /\bmcp\b/i,                label: 'MCP',        icon: 'mcp' },
];

export interface BrokenSurface {
  label: string;
  icon: string;
  count: number;
}

export function surfaceOf(title: string): Surface | null {
  for (const s of SURFACES) if (s.re.test(title)) return s;
  return null;
}

// Tally named surfaces across a set of (already filtered to visible/open) issue
// titles, most-broken first. Unnamed titles are skipped.
export function topBrokenSurfaces(titles: string[]): BrokenSurface[] {
  const byLabel = new Map<string, BrokenSurface>();
  for (const t of titles) {
    const s = surfaceOf(t);
    if (!s) continue;
    const cur = byLabel.get(s.label);
    if (cur) cur.count++;
    else byLabel.set(s.label, { label: s.label, icon: s.icon, count: 1 });
  }
  return [...byLabel.values()].sort((a, b) => b.count - a.count);
}
