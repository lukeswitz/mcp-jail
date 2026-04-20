# mcp-jail

Allow-list + sandbox guard for Anthropic's Model Context Protocol (MCP) STDIO transport.
Closes the supply-chain RCE class disclosed by OX Security in April 2026 (10 CVEs,
150M+ SDK downloads, 200K+ public servers) — without patching the upstream SDK and
without editing your MCP client configs.

The tool hooks the exact function every vulnerable path calls:
`StdioServerParameters(command, args)` → `subprocess.spawn`. Every invocation,
approved or not, passes the same five checks:

1. Canonicalize `{command, argv, env subset, cwd}`
2. SHA-256 fingerprint must match a user-signed entry in `~/.mcp-jail/allow.toml`
3. Reject interpreter-eval flags (`-c`, `-e`, `/c`, `-Command`) unless `dangerous = true`
4. Cross-check the source config file hasn't been tampered with since approval
5. Spawn inside an OS-native sandbox (sandbox-exec / bwrap+seccomp / Job Object)

Signatures are *permission*, not *exemption*. Sandbox + argv-sanity still run.

## Layout

```
cli/           Rust CLI (init / approve / list / revoke / logs / verify)
python/        PyPI package: .pth activator + SDK hook
node/          npm package: --require hook (v1)
sandbox/       Per-OS sandbox profile templates
tests/e2e/     CVE-replay harnesses (LiteLLM, Flowise, DocsGPT patterns)
docs/          Threat model, CVE→check mapping, quickstart
```

## Status

v0 — building the smallest end-to-end path: Rust CLI + Python interposer + macOS sandbox.
See `docs/2026-04-20-mcp-jail-design.md` for the full design.
