<div align=center>

# mcp-jail

[![ci](https://github.com/lukeswitz/mcp-jail/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/ci.yml) [![release](https://github.com/lukeswitz/mcp-jail/actions/workflows/release.yml/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/release.yml) [![Pre-release](https://img.shields.io/github/v/release/lukeswitz/mcp-jail?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/mcp-jail/releases) [![CodeQL](https://github.com/lukeswitz/mcp-jail/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/github-code-scanning/codeql)

**Stops MCP servers from running commands they shouldn't.**

</div>

Your MCP client (Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI, Copilot…) trusts whatever is in its config file. A poisoned config — from a prompt injection, a shady marketplace entry, or a vulnerable web app — gets arbitrary code execution on your machine. Anthropic called it "expected behavior" and won't patch it.

mcp-jail sits in front of every MCP server and only lets through the ones you've approved. Servers run inside a small OS sandbox so even approved ones can't wander off into your SSH keys or AWS credentials.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```

That's it. The installer scans your existing MCP clients, asks once before making changes, protects what's there, and sets up a background watchdog that pings you if anything goes wrong. Restart your MCP client.

## What happens after install

- **Your existing servers keep working.** They just run sandboxed now.
- **A new server tries to start** (you installed one, or something rewrote your config behind your back): a small native dialog pops up showing the command and where it came from. Click **Approve** and the server starts. Click **Deny** (or let the 60-second timeout elapse) and it stays blocked.
- **Headless / no GUI** (SSH, server, notifications off): approval fails closed. `mcp-jail` writes an actionable message to the MCP client's log telling you exactly what to type in a terminal.
- **Something breaks** (mcp-jail gets deleted, signatures don't match, config tampered): the background watchdog pops a notification with the fix. No silent failures.

You don't normally need the CLI. It's there if you want it.

## Uninstall

```bash
mcp-jail unwrap     # restore your original configs
```

Or delete the binary and reinstall later — your configs are backed up.

## Platforms

macOS (Apple Silicon + Intel), Linux (x86_64 + arm64), Windows (x86_64).

---

<details>
<summary><b>CVE coverage</b> — the 10 MCP RCEs disclosed April 2026</summary>

OX Security disclosed 10 RCE CVEs across the MCP ecosystem (LiteLLM, Agent Zero, Upsonic, Langchain-Chatchat, Fay, Bisheng/Jaaz, GPT Researcher, DocsGPT, Flowise, Windsurf). All 10 exploit the same sink: a config gets written with attacker-controlled `{command, args}` and the MCP client runs it.

mcp-jail blocks that sink.

| CVE | Product | Attack shape | Without mcp-jail | With mcp-jail |
|---|---|---|---|---|
| 2026-30623 | LiteLLM | `node -e …` | RCE | blocked |
| 2026-30624 | Agent Zero | `python3 -c …` | RCE | blocked |
| 2026-30625 | Upsonic | plain `tee` | RCE | blocked |
| 2026-30617 | Langchain-Chatchat | `perl -e …` | RCE | blocked |
| 2026-30618 | Fay Framework | plain `cp` | RCE | blocked |
| 2026-33224 | Bisheng / Jaaz | `ruby -e …` | RCE | blocked |
| 2025-65720 | GPT Researcher | plain `ln -s` | RCE | blocked |
| 2026-26015 | DocsGPT | plain `touch` | RCE | blocked |
| 2026-40933 | Flowise | `awk BEGIN{…}` | RCE | blocked |
| 2026-30615 | Windsurf | approved argv, one arg mutated | RCE | blocked |

Test harness: [`tests/cve-repro/sweep.sh`](tests/cve-repro/sweep.sh).

</details>

<details>
<summary><b>How it works</b> — one paragraph</summary>

Every MCP server is identified by a SHA-256 of its exact command line. mcp-jail keeps a signed allow-list of ones you've approved. When your MCP client tries to start a server, mcp-jail checks the fingerprint against that list. Match → run inside a sandbox (macOS `sandbox-exec`, Linux `bwrap`+seccomp, Windows Job Object) with no access to your SSH keys, cloud creds, or browser cookies by default. No match → refused. Argv with interpreter-eval flags like `python -c …` or `bash -c …` is refused on first sight — those are the shapes attackers use to smuggle commands past allow-lists.

</details>

<details>
<summary><b>CLI reference</b> — if you want it</summary>

```
mcp-jail approve              walk pending blocked servers, one at a time
mcp-jail list                 show approved + pending
mcp-jail revoke <id>          drop an approval
mcp-jail doctor               health check
mcp-jail status               one-liner for shell prompts
mcp-jail logs                 audit log (every allow/deny)
mcp-jail wrap                 re-scan configs (new MCP client installed?)
mcp-jail unwrap               restore original configs
mcp-jail upgrade              upgrade in place
mcp-jail sentry <cmd>         manage the background watchdog
```

The installer runs the right things for you. `mcp-jail approve` is the one you'll actually use.

Kill switch for experimentation: set `MCP_JAIL_NOTIFY=0` to silence notifications, or `MCP_JAIL_NO_SENTRY=1` during install to skip the watchdog.

</details>

<details>
<summary><b>From source</b></summary>

```bash
git clone https://github.com/lukeswitz/mcp-jail && cd mcp-jail
cargo install --path cli --locked
mcp-jail init && mcp-jail wrap && mcp-jail sentry install
```

Installer env overrides: `MCP_JAIL_VERSION=v0.2.1` to pin, `MCP_JAIL_PREFIX=$HOME/.local` to install without sudo.

Prebuilt binaries on [Releases](https://github.com/lukeswitz/mcp-jail/releases): `aarch64-apple-darwin`, `x86_64-apple-darwin`, `x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, each with a `.sha256` sidecar.

</details>

<details>
<summary><b>FAQ</b></summary>

**Does this slow my MCP servers down?** No. The fingerprint check is a hash lookup. The sandbox is the OS's own — same overhead as any sandboxed process.

**Will it break my existing setup?** The installer shows you the plan and asks before touching anything. Every config is backed up. Run `mcp-jail unwrap` to revert.

**I got a "mcp-jail blocked" notification — is that a virus?** No, it's the guard doing its job. Something tried to start an MCP server you haven't approved. Open a terminal, run `mcp-jail approve`, and decide.

**The notification says mcp-jail is missing.** Something deleted the binary. Run the install command again. Your approvals and configs are intact.

**I approved a server and now I don't trust it.** `mcp-jail revoke <id>`. The sandbox also limits damage by default — no access to `~/.ssh`, `~/.aws`, `~/.gcp`, `~/.azure`, Keychain, or browser cookies regardless of approval.

**Will MCP ship a real fix?** If/when it does, `mcp-jail` becomes obsolete — which is the correct outcome. Until then, this is the local mitigation.

**macOS network scoping is weird.** Apple's `sandbox-exec` only lets us express "block / localhost-only / allow all" for outbound network. Linux can do per-host; Windows can too. Live with the macOS limitation or run servers in a Linux VM.

</details>

<details>
<summary><b>Security disclosure</b></summary>

Found a bypass? File a GitHub security advisory on this repo. Reproducing an OX CVE that mcp-jail *doesn't* block counts.

</details>

<details>
<summary><b>Disclaimer</b></summary>

Provided as-is. See [LICENSE](LICENSE). This is defense-in-depth against a specific class of RCE, not a total security solution. Don't skip patches, code review, or common sense because you installed a sandbox. v0.2, no independent audit — don't rely on it alone for high-value production systems. You're responsible for the legality of whatever you wrap.

</details>

## Credits

CVEs discovered and disclosed by the **OX Security** research team (Moshe Siman Tov Bustan, Mustafa Naamnih, Nir Zadok, Roni Bar), April 2026.

Not affiliated with Anthropic, OX Security, the Model Context Protocol org, or any of the products referenced.

## License

[MIT](LICENSE)

## References

- [OX Security — Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
- [OX Security — CVE advisory](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
- [The Hacker News coverage](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [MCP transports spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
