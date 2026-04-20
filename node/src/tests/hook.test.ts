// End-to-end test: attacker-style spawn via @modelcontextprotocol/sdk must be
// blocked by our child_process hook.

import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { installHooks, JailBlocked } from '../hook.js';
import child_process from 'node:child_process';

installHooks();

function freshJail(): string {
  const home = mkdtempSync(path.join(tmpdir(), 'mcp-jail-node-'));
  process.env['HOME'] = home;
  const r = spawnSync('mcp-jail', ['init'], { encoding: 'utf8' });
  assert.equal(r.status, 0, `init failed: ${r.stderr}`);
  return path.join(home, '.mcp-jail');
}

function latestPendingFingerprint(jailRoot: string): string {
  const pending = path.join(jailRoot, 'pending.jsonl');
  const content = readFileSync(pending, 'utf8');
  const lines = content.trim().split('\n');
  return JSON.parse(lines[lines.length - 1]!).fingerprint as string;
}

test('unapproved MCP-shaped spawn is blocked before exec', () => {
  freshJail();
  const marker = path.join(tmpdir(), `node-rce-${Date.now()}`);
  if (existsSync(marker)) rmSync(marker);

  assert.throws(
    () => {
      // Shape: the MCP SDK's spawn call. We use child_process.spawn directly
      // because the SDK's StdioClientTransport calls this underneath.
      child_process.spawn('/usr/bin/touch', [marker]);
    },
    (err: unknown) => {
      assert.ok(err instanceof JailBlocked, `expected JailBlocked, got ${String(err)}`);
      return true;
    },
  );

  assert.equal(existsSync(marker), false, 'marker must not exist — spawn must be prevented');
});

test('approved spawn is wrapped in sandbox-exec and succeeds', (t) => {
  if (process.platform !== 'darwin') {
    t.skip('macOS sandbox only');
    return;
  }
  const jailRoot = freshJail();
  const tmp = mkdtempSync(path.join(tmpdir(), 'mcp-jail-node-scope-'));
  const marker = path.join(tmp, 'ok');

  // First call seeds pending and throws.
  assert.throws(() => child_process.spawn('/usr/bin/touch', [marker]), JailBlocked);

  const fp = latestPendingFingerprint(jailRoot).slice(0, 12);
  const r = spawnSync('mcp-jail', ['approve', fp, '--id', 'node-touch', '--fs-write', tmp], {
    encoding: 'utf8',
  });
  assert.equal(r.status, 0, r.stderr);

  const proc = child_process.spawn('/usr/bin/touch', [marker]);
  return new Promise<void>((resolve, reject) => {
    proc.on('exit', (code) => {
      try {
        assert.equal(code, 0, `touch rc=${code}`);
        assert.ok(existsSync(marker), 'marker should exist after approved spawn');
        resolve();
      } catch (e) {
        reject(e);
      }
    });
    proc.on('error', reject);
  });
});

test('dangerous flag approval is refused by CLI', () => {
  freshJail();
  const tmp = mkdtempSync(path.join(tmpdir(), 'mcp-jail-node-dangerous-'));
  const marker = path.join(tmp, 'rce');
  assert.throws(
    () => child_process.spawn('/usr/bin/node', ['-e', `require('fs').writeFileSync(${JSON.stringify(marker)}, '')`]),
    JailBlocked,
  );

  const fp = latestPendingFingerprint(path.join(process.env['HOME']!, '.mcp-jail')).slice(0, 12);
  const r = spawnSync('mcp-jail', ['approve', fp, '--id', 'node-dangerous'], { encoding: 'utf8' });
  assert.notEqual(r.status, 0, 'CLI must refuse -e approval without --dangerous');
  assert.ok(/dangerous|interpreter-eval/i.test(r.stderr), `bad stderr: ${r.stderr}`);
});
