// Monkey-patch child_process.spawn. Only intervene when argv looks like an
// MCP server spawn (string[] args, no shell:true); everything else passes
// through. Also marks StdioClientTransport's prototype so our guard isn't
// double-applied if the SDK is pre-loaded.

import { JailBlocked as JailBlockedError } from './errors.js';
import { evaluate } from './cli.js';
import child_process from 'node:child_process';
import Module from 'node:module';
import process from 'node:process';

export { JailBlockedError as JailBlocked };

let installed = false;
const PASSTHROUGH_ENV = 'MCP_JAIL_PASSTHROUGH';

export function installHooks(): void {
  if (installed) return;
  installed = true;
  patchChildProcess();
  patchModuleResolution();
}

type SpawnFn = typeof child_process.spawn;

function patchChildProcess(): void {
  const original: SpawnFn = child_process.spawn.bind(child_process);
  const wrapped: SpawnFn = ((...rawArgs: unknown[]) => {
    const parsed = parseSpawnArgs(rawArgs);
    if (parsed === null) {
      return (original as (...a: unknown[]) => child_process.ChildProcess)(...rawArgs);
    }
    const { command, args, options } = parsed;

    const envObj = (options.env ?? process.env) as Record<string, string | undefined>;
    if (envObj[PASSTHROUGH_ENV] === '1') {
      const cleaned: Record<string, string | undefined> = { ...envObj };
      delete cleaned[PASSTHROUGH_ENV];
      const newOpts = { ...options, env: cleaned };
      return (original as (...a: unknown[]) => child_process.ChildProcess)(command, args, newOpts);
    }

    if (!Array.isArray(args) || options.shell === true) {
      return (original as (...a: unknown[]) => child_process.ChildProcess)(...rawArgs);
    }

    const cwd = typeof options.cwd === 'string' ? options.cwd : process.cwd();

    const decision = evaluate({
      command,
      argv: [command, ...args],
      env: envObj,
      cwd,
    });

    if (!decision.allow) {
      throw new JailBlockedError(decision.reason, decision.fingerprint, [command, ...args]);
    }

    const wrappedArgv = decision.wrapped_argv ?? [command, ...args];
    const newCommand = wrappedArgv[0] ?? command;
    const newArgs = wrappedArgv.slice(1);
    const filteredEnv = filterEnv(envObj, decision.env_allow);
    filteredEnv[PASSTHROUGH_ENV] = '1';

    return (original as (...a: unknown[]) => child_process.ChildProcess)(
      newCommand,
      newArgs,
      { ...options, env: filteredEnv },
    );
  }) as unknown as SpawnFn;

  Object.defineProperty(wrapped, '__mcp_jail_patched__', { value: true });
  (child_process as { spawn: SpawnFn }).spawn = wrapped;
}

interface SpawnArgs {
  command: string;
  args: string[];
  options: child_process.SpawnOptions;
}

function parseSpawnArgs(a: readonly unknown[]): SpawnArgs | null {
  if (a.length === 0) return null;
  const command = a[0];
  if (typeof command !== 'string') return null;
  let args: string[] = [];
  let options: child_process.SpawnOptions = {};
  if (a.length >= 2 && Array.isArray(a[1])) {
    args = a[1] as string[];
    if (a.length >= 3 && typeof a[2] === 'object' && a[2] !== null) {
      options = a[2] as child_process.SpawnOptions;
    }
  } else if (a.length >= 2 && typeof a[1] === 'object' && a[1] !== null) {
    options = a[1] as child_process.SpawnOptions;
  }
  return { command, args, options };
}

function filterEnv(
  env: Readonly<Record<string, string | undefined>>,
  keep: readonly string[],
): Record<string, string> {
  const out: Record<string, string> = {};
  const essentials = [
    'PATH', 'HOME', 'USER', 'LOGNAME', 'TMPDIR', 'SHELL', 'LANG', 'LC_ALL',
    'SSH_AUTH_SOCK', 'DISPLAY', 'XAUTHORITY',
  ];
  for (const k of keep) {
    const v = env[k];
    if (typeof v === 'string') out[k] = v;
  }
  for (const k of essentials) {
    if (!(k in out)) {
      const v = env[k];
      if (typeof v === 'string') out[k] = v;
    }
  }
  return out;
}

function patchModuleResolution(): void {
  // child_process.spawn is the load-bearing hook; this just marks an
  // already-loaded SDK to avoid double-patching.
  for (const key of Object.keys(require.cache ?? {})) {
    if (key.includes('@modelcontextprotocol/sdk') && key.endsWith('stdio.js')) {
      try {
        tryPatchStdio(require.cache[key]?.exports);
      } catch {
        // noop
      }
    }
  }
}

function tryPatchStdio(mod: unknown): void {
  if (mod === null || mod === undefined) return;
  const m = mod as { StdioClientTransport?: new (...a: unknown[]) => { start: () => Promise<void> } };
  const Transport = m.StdioClientTransport;
  if (typeof Transport !== 'function') return;
  const proto = Transport.prototype as unknown as { __mcp_jail_patched__?: boolean };
  if (proto.__mcp_jail_patched__ === true) return;
  proto.__mcp_jail_patched__ = true;
}

import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
void Module;
