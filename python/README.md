# mcp-jail — Python interposer

Python side of [mcp-jail](https://github.com/lukeswitz/mcp-jail): a local
policy shim that blocks the MCP STDIO RCE class disclosed by OX Security
in April 2026 (10 CVEs, 150M+ SDK downloads).

This package installs a `.pth` activator that patches
`mcp.client.stdio._create_platform_compatible_process` and
`anyio.open_process` at interpreter start. Every MCP server spawn is
fingerprinted, argv-sanity-checked, and run inside an OS sandbox. The
`.pth` ships inside the wheel, so `pip install mcp-jail` into any
virtualenv automatically activates the guard for that interpreter.

## Install

```bash
pip install mcp-jail
mcp-jail init       # requires the mcp-jail CLI (Rust binary), see main repo
```

For the one-shot installer that sets up binary + pip + npm together:

```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```

Full documentation, CVE coverage matrix, threat model, and usage:
<https://github.com/lukeswitz/mcp-jail>.

## License

Apache-2.0.
