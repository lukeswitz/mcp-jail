// Bridge to the Rust CLI: JSON request on stdin -> JSON decision on stdout.

import { spawnSync } from 'node:child_process';
import { existsSync, accessSync, constants } from 'node:fs';
import { delimiter, join } from 'node:path';

export interface Decision {
  allow: boolean;
  reason: string;
  fingerprint: string;
  wrapped_argv: string[] | null;
  env_allow: string[];
  sandbox: Record<string, unknown>;
  raw: Record<string, unknown>;
}

export interface EvaluateInput {
  command: string;
  argv: readonly string[];
  env: Readonly<Record<string, string | undefined>>;
  cwd: string;
  source_config?: string | undefined;
}

const CLI_ENV = 'MCP_JAIL_CLI';
const TIMEOUT_MS = 10_000;

function resolveCli(): string | null {
  const explicit = process.env[CLI_ENV];
  if (explicit && existsSync(explicit)) {
    try {
      accessSync(explicit, constants.X_OK);
      return explicit;
    } catch {
      // fall through to PATH lookup
    }
  }
  const pathEnv = process.env['PATH'] ?? '';
  for (const dir of pathEnv.split(delimiter)) {
    if (!dir) continue;
    const candidate = join(dir, 'mcp-jail');
    if (existsSync(candidate)) {
      try {
        accessSync(candidate, constants.X_OK);
        return candidate;
      } catch {
        // keep looking
      }
    }
  }
  return null;
}

export function evaluate(input: EvaluateInput): Decision {
  const cli = resolveCli();
  if (cli === null) {
    return deny('mcp-jail CLI not found in PATH; install from https://github.com/lukeswitz/mcp-jail');
  }

  const payload = JSON.stringify({
    command: input.command,
    argv: [...input.argv],
    env: sanitizeEnv(input.env),
    cwd: input.cwd,
    source_config: input.source_config ?? null,
  });

  const result = spawnSync(cli, ['check'], {
    input: payload,
    encoding: 'utf8',
    timeout: TIMEOUT_MS,
  });

  if (result.error !== undefined && result.error !== null) {
    return deny(`mcp-jail CLI failed: ${String(result.error)}`);
  }

  let raw: Record<string, unknown>;
  try {
    raw = JSON.parse(result.stdout) as Record<string, unknown>;
  } catch {
    return deny(`mcp-jail CLI produced invalid JSON: ${result.stdout}`);
  }

  return {
    allow: raw['decision'] === 'allow',
    reason: typeof raw['reason'] === 'string' ? (raw['reason'] as string) : '',
    fingerprint: typeof raw['fingerprint'] === 'string' ? (raw['fingerprint'] as string) : '',
    wrapped_argv: Array.isArray(raw['wrapped_argv']) ? (raw['wrapped_argv'] as string[]) : null,
    env_allow: Array.isArray(raw['env_allow']) ? (raw['env_allow'] as string[]) : [],
    sandbox: (raw['sandbox'] as Record<string, unknown> | undefined) ?? {},
    raw,
  };
}

function sanitizeEnv(env: Readonly<Record<string, string | undefined>>): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(env)) {
    if (typeof v === 'string') out[k] = v;
  }
  return out;
}

function deny(reason: string): Decision {
  return {
    allow: false,
    reason,
    fingerprint: '',
    wrapped_argv: null,
    env_allow: [],
    sandbox: {},
    raw: {},
  };
}
