# mcp-jail

[![ci](https://github.com/lukeswitz/mcp-jail/actions/workflows/ci.yml/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/ci.yml) [![release](https://github.com/lukeswitz/mcp-jail/actions/workflows/release.yml/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/release.yml) [![Pre-release](https://img.shields.io/github/v/release/lukeswitz/mcp-jail?include_prereleases&label=pre-release&color=orange)](https://github.com/lukeswitz/mcp-jail/releases) [![GitHub code size in bytes](https://img.shields.io/github/languages/code-size/lukeswitz/mcp-jail)](https://github.com/lukeswitz/mcp-jail/tree/main/mcp-jail/) [![CodeQL](https://github.com/lukeswitz/mcp-jail/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/lukeswitz/mcp-jail/actions/workflows/github-code-scanning/codeql)
</div>

> Blocks the MCP STDIO RCE class disclosed by OX Security in April 2026.

Works with Claude Code, Claude Desktop, Cursor, Windsurf, Gemini CLI, and any other MCP client.

## The attack

MCP's STDIO transport takes a `{command, args}` from a config file and
spawns it as a subprocess. Validation happens *after* the process has
already run. If an attacker controls the config — via prompt injection,
a malicious marketplace entry, or a vulnerable web app that accepts
user-supplied MCP configs — they have arbitrary code execution on your
machine. 

**Anthropic marked the behavior "expected" and declined to patch.**

## The "fix"

Install `mcp-jail`. It rewrites every MCP entry in your client configs
to route through itself. Before any spawn:

1. **Canonicalise** `{command, argv}` and SHA-256 fingerprint it.
2. **Match** the fingerprint against a signed allow-list.
3. **Refuse** interpreter-eval flags (`-c`, `-e`, `/c`, `-Command`) unless explicitly approved.
4. **Run inside an OS sandbox** (`sandbox-exec` on macOS, `bwrap`+seccomp on Linux, Job Object on Windows).

If any check fails, the spawn never happens.

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```

Detects macOS / Linux / Windows (WSL/git-bash), downloads the signed
binary, verifies SHA-256, runs `mcp-jail init`, and offers to wrap your
MCP client configs. Re-run to upgrade. Or `mcp-jail upgrade` from the CLI.

<details>
<summary>Manual / from source</summary>

Binaries: [Releases](https://github.com/lukeswitz/mcp-jail/releases) —
`aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`, each with a `.sha256` sidecar.

```bash
cargo install --path cli
mcp-jail init
```

Installer env overrides:
- `MCP_JAIL_VERSION=v0.1.2` — pin a release
- `MCP_JAIL_PREFIX=$HOME/.local` — install without sudo

</details>

## How to use it

Run the installer. That's it.

```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```

The installer:

1. Downloads the signed binary and verifies SHA-256.
2. Finds every MCP server already in your client configs (Claude Code,
   Claude Desktop, Cursor, Windsurf, Gemini CLI, Copilot).
3. Shows you the plan, asks `Apply now? [y/N]`, backs up each file.
4. Interactively configures each server's sandbox, one prompt per entry,
   with smart defaults: loopback-only for local bridges, host-restricted
   for SSH/curl/etc. (detected host pre-filled), block otherwise. Enter
   through the prompt accepts the defaults. Servers with interpreter-eval
   flags (`python -c`, `bash --rcfile`, etc.) are flagged for manual
   review — they skip auto-approval.
5. Done. Restart your MCP client. Existing servers run sandboxed
   automatically. No further action.

Non-interactive flags for scripts:
- `mcp-jail wrap --yes` — accept all defaults silently
- `mcp-jail wrap --yes --strict` — lock everything to deny-everywhere
- `mcp-jail wrap --no-auto-approve` — approve each on first spawn instead

When a new server appears later — installed fresh, rewritten by a
prompt-injected agent, pulled from a marketplace — mcp-jail blocks it
on first launch and prints a one-liner: `mcp-jail approve <fp> --id <name>`.
Copy-paste, done.

<details>
<summary>Scoping an approval (optional)</summary>

By default the sandbox denies writes (except `/tmp`, `/var/folders`),
scopes network per-server (loopback / host-restricted / all / block),
and blocks reads of **your operator credentials only** — `~/.ssh`,
`~/.aws`, `~/.gcp`, `~/.azure`, Keychain, browser cookies, etc. Target
data stored under `~/targets`, `~/loot`, or anywhere outside those
specific dirs stays readable. Grant more only if a server needs it:

```bash
mcp-jail approve <fp> --id my-server \
  --fs-read  "$HOME/work" \
  --fs-write "$HOME/work/.cache" \
  --net      localhost
```

| Flag | Effect |
|---|---|
| `--id NAME` | Human-friendly id |
| `--dangerous` | Permit `-c` / `-e` / `/c` in argv |
| `--fs-read PATH` | Read access |
| `--fs-write PATH` | Write access |
| `--fs-read-secret PATH` | Specific file inside an otherwise-denied secret dir (e.g. `$HOME/.ssh/mcp_ed25519` for SSH-wrapped MCPs) |
| `--net DOMAIN\|IP` | Outbound network. macOS collapses to deny / localhost-only / all-outbound; Linux & Windows scope per host |
| `--env NAME` | Include an env var in the fingerprint (off by default) |

</details>

<details>
<summary>All commands</summary>

```
mcp-jail init                 generate key, bootstrap state
mcp-jail wrap [--yes|--strict]  rewrite MCP entries + configure per-server sandbox
mcp-jail unwrap               revert wrapping, restore originals
mcp-jail list                 approved + pending (auto-prunes stale pending rows)
mcp-jail approve <fp>         sign a pending fingerprint
mcp-jail revoke <id>          remove an approval
mcp-jail logs                 audit log, hash-chain verified
mcp-jail verify               signatures + chain + sandbox helper self-check
mcp-jail doctor               full health check: state, sigs, wrap coverage,
                              pending, PATH shadowing, update availability
mcp-jail upgrade              re-run the installer
```

`mcp-jail exec` is the internal subcommand wrapped configs invoke — it
is hidden from `--help` because you never run it directly.

Kill switch: `MCP_JAIL_DISABLE=1` — honoured by future in-process hook
extensions; does not affect the config-wrap enforcement path.

</details>

---

## OX CVE class — sink-level defense

All 10 OX CVEs are the same vulnerability class with different entry
points. Nine (LiteLLM, Agent Zero, Upsonic, Langchain-Chatchat, Fay,
Bisheng/Jaaz, GPT Researcher, DocsGPT, Flowise) are "vulnerable product
API writes attacker-controlled `{command, args}` JSON, MCP client
execve's it." Windsurf (CVE-2026-30615) is the mutation variant — client
config is rewritten between approval and spawn. Every one terminates at
the same spawn sink.

`mcp-jail` guards that sink: fingerprint + sandbox between the client
and the OS. A refused sink means the whole class is refused, independent
of which product's API was the entry point.

**Scope note (honest).** OX has not published per-CVE PoC payloads; the
public advisories describe the class generically. The sweep here does
NOT reproduce each CVE's exploit at its vulnerable product endpoint —
that would require standing up each product (LiteLLM, Flowise, etc.)
and running a per-product HTTP exploit. Instead it tests the guard at
the shared sink with a deliberately varied set of attacker argv shapes
(interpreter-eval via node/python/perl/ruby, plain-binary invocation,
and argv mutation of an approved entry). End-to-end per-product repros
are tracked as follow-up work.

Harness: [`tests/cve-repro/sweep.sh`](tests/cve-repro/sweep.sh).

| OX CVE | Product | Delivery (OX family) | Attacker argv shape exercised | Unguarded | Guarded |
|---|---|---|---|---|---|
| 2026-30623 | LiteLLM            | 1 (vuln API) | `node -e …`     | RCE-CONFIRMED | blocked (unknown fingerprint, exit 126) |
| 2026-30624 | Agent Zero         | 1 (vuln API) | `python3 -c …`  | RCE-CONFIRMED | blocked |
| 2026-30625 | Upsonic            | 1 (vuln API) | plain binary `tee` | RCE-CONFIRMED | blocked |
| 2026-30617 | Langchain-Chatchat | 1 (vuln API) | `perl -e …`     | RCE-CONFIRMED | blocked |
| 2026-30618 | Fay Framework      | 1 (vuln API) | plain binary `cp` | RCE-CONFIRMED | blocked |
| 2026-33224 | Bisheng / Jaaz     | 1 (vuln API) | `ruby -e …`     | RCE-CONFIRMED | blocked |
| 2025-65720 | GPT Researcher     | 1 (vuln API) | plain binary `ln -s` | RCE-CONFIRMED | blocked |
| 2026-26015 | DocsGPT            | 1 (vuln API) | plain binary `touch` | RCE-CONFIRMED | blocked |
| 2026-40933 | Flowise            | 1 (vuln API) | `awk BEGIN{…}`  | RCE-CONFIRMED | blocked |
| 2026-30615 | Windsurf           | 3 (config mutation) | approved argv, one arg mutated | mutation applies | blocked (fingerprint mismatch) |

Secondary defense (OX family 2): `mcp-jail approve` refuses to sign an
argv containing `-c`/`-e`/`--eval`/etc. without `--dangerous`. The sweep
exercises this path and requires the refusal.

<details>
<summary>Run the sweep yourself</summary>

```bash
tests/cve-repro/sweep.sh --unguarded-only   # confirms the 9 attacker argvs are live RCE vectors
tests/cve-repro/sweep.sh                     # full: baseline + guarded, expects 10/10 blocked
```

Per-product end-to-end repros (stand up each vulnerable product in a
container, POST the attacker JSON to its vuln endpoint, confirm mcp-jail
blocks the downstream spawn) are tracked as a follow-up.

</details>

<details>
<summary>How the four OX delivery families map to the four checks</summary>

| Family | Description | Check |
|---|---|---|
| 1 | Unauth/auth command injection via an app's MCP config endpoint | 2 — fingerprint mismatch |
| 2 | Hardening bypass: allow-list inspects program name, attacker smuggles via `python -c` / `bash -c` / `node -e` | 3 — argv sanity refusal |
| 3 | Zero-click prompt injection rewrites the client's MCP config JSON between approval and spawn | 2 — mutated argv has no signed entry |
| 4 | Malicious marketplace entry installs a new `{command, args}` | 2 — new argv has no signed entry |

</details>

---

## Status

v0.1 — macOS arm64 + x86_64, Linux x86_64 + aarch64, Windows x86_64.
One static binary, no runtime deps.

Tested end-to-end against real MCP servers in two environments: a
host-local Python MCP, an SSH-tunneled CLI MCP on a VM, and an
SSH-tunneled Java MCP on a VM. All three round-trip MCP tool calls
correctly under the sandbox.

---

<details>
<summary>FAQ</summary>

**Why isn't this fix in the MCP spec?** Because the paper's finding is
architectural: STDIO's bootstrap mechanism is "client spawns an
arbitrary command and uses stdio as the transport." Anthropic declined
to change it. `mcp-jail` enforces locally what the protocol doesn't.
If MCP ever ships a v2 STDIO with signed manifests, this tool becomes
obsolete — the correct long-term outcome.

**What about servers you already approved turning malicious?** The
sandbox bounds the damage — operator-credential dirs (`~/.ssh`, `~/.aws`,
Keychain, etc.) are blocked, network scope is whatever you granted at
wrap time (default loopback for local bridges, host-restricted for SSH),
writes are scoped to `/tmp`. It does not eliminate the damage. Audit
log gives you forensics.

**macOS per-host egress scoping?** `sandbox-exec` can't express it —
`remote ip/tcp` accept only `*` or `localhost` for host. `--net`
collapses to deny / localhost-only / all-outbound. Proper per-host is
Linux/bwrap+nftables and Windows Filtering Platform.

**Audit chain says "broken" — is that bad?** Only if you didn't cause
it. Initial setup / testing will seed before `init` and break the chain
by design. Reset: delete `~/.mcp-jail/audit.jsonl`. In steady state it
should stay intact.

</details>

<details>
<summary>Security disclosure</summary>

Found a bypass? Report privately via GitHub security advisory on this
repository. If you reproduce an OX CVE that `mcp-jail` *doesn't* block,
that's a valid report.

</details>

<details>
<summary>Disclaimer + limitations</summary>

> **`mcp-jail` IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,**
> EXPRESS OR IMPLIED. SEE [LICENSE](LICENSE) FOR THE FULL TERMS.

- Defence-in-depth against a specific class of MCP STDIO RCE, not a comprehensive security solution. Does not replace OS hardening, code review of servers you install, or keeping upstream software patched.
- The sandbox bounds blast radius; it cannot prevent abuse by a server you have consciously approved and granted broad scopes to. Read the argv before signing.
- The operator-credential deny list (`~/.ssh`, `~/.aws`, Keychain, etc.) is a *heuristic* — scoped to your local host only, not to target data. Add paths if you store credentials elsewhere; override a specific denied file with `--fs-read-secret` when an MCP genuinely needs it.
- v0.1, no independent security audit. Do not rely on it alone for production or high-value systems.
- CVEs attributed to OX Security's public disclosure. Reproduction scripts exercise the vulnerable sink, not every code path of every vulnerable app.
- **Authorised use only.** The sandbox does not make offensive actions legal. If you wrap an MCP server that scans, exploits, or acts against systems, you are responsible for having written authorisation from the system owner.

</details>

---

## Credits

The 10 CVEs were discovered and publicly disclosed by the **OX Security
research team** (Moshe Siman Tov Bustan, Mustafa Naamnih, Nir Zadok,
Roni Bar) in April 2026. `mcp-jail` implements a local mitigation for
the vulnerability class they identified.

Not developed, endorsed, or affiliated with Anthropic PBC, OX Security,
the Model Context Protocol organization, or any of the vulnerable
projects referenced. All product names, logos, and brands are property
of their respective owners.

## License

[LICENSE](LICENSE).

## References

- [OX Security — Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
- [OX Security — Full CVE advisory](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
- [The Hacker News coverage](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [MCP transports spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
