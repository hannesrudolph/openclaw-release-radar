import { describe, it } from 'node:test';
import { strict as assert } from 'node:assert';
import { surfaceOf, topBrokenSurfaces } from './surfaces.ts';

describe('surfaceOf', () => {
  it('names channels and providers from a title', () => {
    assert.equal(surfaceOf('Discord DMs silently dropped')?.label, 'Discord');
    assert.equal(surfaceOf('Ollama proxy loopback timeout')?.label, 'Ollama');
    assert.equal(surfaceOf('[Bug] Claude tool call 500')?.label, 'Claude');
  });
  it('maps OpenClaw UI surfaces to dedicated icons', () => {
    assert.equal(surfaceOf('WebChat session dropped')?.icon, 'webchat');
    assert.equal(surfaceOf('control-ui panel blank')?.icon, 'control-ui');
    assert.equal(surfaceOf('dashboard widgets missing')?.icon, 'dashboard');
  });
  it('maps Feishu to its icon', () => {
    const f = surfaceOf('Feishu interactive card parse error');
    assert.equal(f?.label, 'Feishu');
    assert.equal(f?.icon, 'feishu');
  });
  it('maps MCP, Codex, xAI and iMessage to dedicated icons', () => {
    assert.equal(surfaceOf('MCP server handshake timeout')?.icon, 'mcp');
    assert.equal(surfaceOf('Codex CLI auth loop')?.icon, 'codex');
    assert.equal(surfaceOf('Grok API rate limit')?.icon, 'xai');
    assert.equal(surfaceOf('iMessage bridge disconnect')?.icon, 'imessage');
  });
  it('prefers Ollama over Llama when both could match', () => {
    assert.equal(surfaceOf('Ollama model pull fails')?.label, 'Ollama');
    assert.equal(surfaceOf('llama.cpp server OOM')?.label, 'Llama');
  });
  it('returns null when no surface is named', () => {
    assert.equal(surfaceOf('Gateway boot race condition'), null);
  });
});

describe('topBrokenSurfaces', () => {
  it('tallies and sorts most-broken first, skipping unnamed', () => {
    const out = topBrokenSurfaces([
      'Discord A', 'Discord B', 'Telegram C', 'gateway internal D', 'Discord E',
    ]);
    assert.deepEqual(out, [
      { label: 'Discord', icon: 'discord', count: 3 },
      { label: 'Telegram', icon: 'telegram', count: 1 },
    ]);
  });
});
