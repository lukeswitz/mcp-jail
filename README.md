# mcp-jail

> A local policy shim that blocks the MCP STDIO RCE class disclosed by OX
> Security in April 2026 — **10 CVEs, 150M+ SDK downloads, 200K+ public
> servers**. With `mcp-jail` installed, none of those 10 CVEs produce RCE
> on your machine.

## The attack

The MCP SDK's STDIO transport spawns a subprocess from an in-memory
`{command, args, env, cwd}` tuple and validates whether the child speaks
MCP *after* it has already run. Any path that reaches `stdio_client()` with
attacker-controlled args is arbitrary-code execution on the host.

Anthropic marked the behaviour "expected" and declined to patch.

## The fix

`mcp-jail` wraps every MCP server launch with four checks. If any fail,
the process is never spawned.

1. **Canonicalise** the spawn request (`command`, `argv`, declared env keys).
2. **Match** its SHA-256 fingerprint against a user-signed allow-list.
3. **Reject interpreter-eval flags** (`-c`, `-e`, `/c`, `-Command`) unless explicitly approved with `--dangerous`.
4. **Run inside an OS sandbox** (`sandbox-exec` on macOS, `bwrap`+seccomp on Linux, Job Object on Windows — v1.1).

Signatures are **permission**, not **exemption**: checks 3 and 4 fire on every spawn, approved or not.

## Install

One command. Detects macOS / Linux / Windows (WSL), downloads the signed
binary, installs the Python + Node interposers if those runtimes are
present, runs `mcp-jail init`.

```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```

Re-run the same command any time to upgrade. Or from the CLI:

```bash
mcp-jail upgrade
```

<details>
<summary><b>Manual install / from source / per-platform</b></summary>

**Per-platform binary** — see [Releases](https://github.com/lukeswitz/mcp-jail/releases)
for `aarch64-apple-darwin`, `x86_64-apple-darwin`,
`x86_64-unknown-linux-gnu`, `aarch64-unknown-linux-gnu`,
`x86_64-pc-windows-msvc`. Every asset has a `.sha256` sidecar.

```bash
pip install --user mcp-jail       # Python interposer
npm install -g mcp-jail           # Node interposer (optional)
mcp-jail init
```

**From source:**
```bash
cargo install --path cli
pip install --user ./python
cd node && npm install && npm run build && npm link
mcp-jail init
```

**Environment overrides** for the installer:
- `MCP_JAIL_VERSION=v0.1.2` — pin a specific release
- `MCP_JAIL_PREFIX=$HOME/.local` — install binary without sudo

</details>

## How to use it

Three steps. None involve hand-editing JSON.

**1. Install.**
```bash
curl -fsSL https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh | bash
```
The installer also scans your MCP client configs (Claude Code, Claude
Desktop, Cursor, Windsurf, Gemini CLI, Copilot) and offers to wrap every
server entry for you. Say yes; it backs up each file first.

If you skipped that step or want to re-run it later:
```bash
mcp-jail wrap           # interactive: shows plan, asks to confirm
mcp-jail wrap --yes     # non-interactive
mcp-jail unwrap         # revert, restoring originals
```

**2. Start your MCP client normally.** The first time each MCP server
launches, mcp-jail blocks it and prints a fingerprint like:
```
mcp-jail: blocked new server
  id:           binary_ninja_mcp
  argv:         /…/python3 /…/bridge.py
  fingerprint:  8a1eec5348c1
  hint:         mcp-jail approve 8a1eec5348c1
```

**3. Approve it once.** Copy the fingerprint from the error and run:
```bash
mcp-jail approve 8a1eec5348c1 --id binary_ninja_mcp
```
That server now runs sandboxed from then on. No further approvals unless
the argv changes (which would be exactly the attack we're blocking).

Then tell your MCP client to reconnect (`/mcp` in Claude Code, restart
otherwise). That's it.

<details>
<summary><b>Scoping an approval more tightly (optional)</b></summary>

By default an approved server runs in a sandbox with default-deny writes
and default-deny network — it can read most of the filesystem (SIP
binaries need it) but can't touch `~/.ssh`, `~/.aws`, Keychain, or
browser cookies. If a server needs more, grant it explicitly at approve
time:

```bash
mcp-jail approve <fp> --id my-server \
  --fs-read  "$HOME/work" \
  --fs-write "$HOME/work/.cache" \
  --net      localhost
```

| Flag | Effect |
|---|---|
| `--id NAME` | Human-friendly id shown in `list` / audit log |
| `--source-config PATH` | Record origin config file (audit only; the argv fingerprint already catches malicious rewrites) |
| `--dangerous` | Permit interpreter-eval flags in argv (`-c`, `-e`, `/c`) |
| `--fs-read PATH` | Grant read access to a path |
| `--fs-write PATH` | Grant write access to a path |
| `--fs-read-secret PATH` | Grant read inside an otherwise-denied secret dir (e.g. `$HOME/.ssh/mcp_ed25519` for an SSH-wrapped MCP) |
| `--net DOMAIN\|IP` | Permit outbound network. macOS collapses to deny / localhost-only / all-outbound; Linux / Windows scope per host |
| `--env NAME` | Include an env var in the fingerprint (off by default — volatile keys like `TMPDIR` would otherwise flip the hash) |

</details>

<details>
<summary><b>Other commands</b></summary>

```
mcp-jail list            # approved servers + pending blocks
mcp-jail revoke <id>     # remove an approval
mcp-jail logs            # audit log, hash-chain verified
mcp-jail verify          # signatures + chain + sandbox helper
mcp-jail wrap --dry-run  # preview what would be wrapped
mcp-jail unwrap          # restore original configs
mcp-jail upgrade         # re-run the install script
```

Kill switch: `MCP_JAIL_DISABLE=1 <your-mcp-client>` unloads the Python
`.pth` and Node `--import` hooks for that process. Does not bypass a
signed allow-list.

</details>

---

## OX CVE coverage — all 10 reproduced and blocked

Every CVE's vulnerable call pattern was executed against the real MCP
Python SDK (or real Node `child_process.spawn`). The payload is a
harmless `touch /tmp/pwned_<slug>`. Harness:
[`tests/cve-repro/sweep.py`](tests/cve-repro/sweep.py),
[`tests/cve-repro/flowise_repro.js`](tests/cve-repro/flowise_repro.js).

| OX CVE | Product | Unguarded | Guarded |
|---|---|---|---|
| 2026-30623 | LiteLLM | RCE | **blocked** |
| 2026-30624 | Agent Zero | RCE | **blocked** |
| 2026-30625 | Upsonic | RCE | **blocked** |
| 2026-30617 | Langchain-Chatchat | RCE | **blocked** |
| 2026-30618 | Fay Framework | RCE | **blocked** |
| 2026-33224 | Bisheng / Jaaz | RCE | **blocked** |
| 2025-65720 | GPT Researcher | RCE | **blocked** |
| 2026-26015 | DocsGPT | RCE | **blocked** |
| 2026-40933 | Flowise (Node) | RCE | **blocked** |
| 2026-30615 | Windsurf (family 3) | RCE via config mutation | **blocked** |

<details>
<summary><b>Verbatim sweep output</b></summary>

```
=== sweep (UNGUARDED) ===
  CVE-2026-30623    LiteLLM                 exc=None  marker=True
  CVE-2026-30624    Agent Zero              exc=None  marker=True
  CVE-2026-30625    Upsonic                 exc=None  marker=True
  CVE-2026-30617    Langchain-Chatchat      exc=None  marker=True
  CVE-2026-30618    Fay Framework           exc=None  marker=True
  CVE-2026-33224    Bisheng/Jaaz            exc=None  marker=True
  CVE-2025-65720    GPT Researcher          exc=None  marker=True
  CVE-2026-26015    DocsGPT                 exc=None  marker=True
unguarded: 8/8 CVEs produced a marker (RCE confirmed)

=== sweep (GUARDED) ===
  CVE-2026-30623    LiteLLM                 exc=JailBlocked  marker=False
  CVE-2026-30624    Agent Zero              exc=JailBlocked  marker=False
  CVE-2026-30625    Upsonic                 exc=JailBlocked  marker=False
  CVE-2026-30617    Langchain-Chatchat      exc=JailBlocked  marker=False
  CVE-2026-30618    Fay Framework           exc=JailBlocked  marker=False
  CVE-2026-33224    Bisheng/Jaaz            exc=JailBlocked  marker=False
  CVE-2025-65720    GPT Researcher          exc=JailBlocked  marker=False
  CVE-2026-26015    DocsGPT                 exc=JailBlocked  marker=False
  CVE-2026-30615    Windsurf (family 3)     baseline_ok=True  argv_blocked=True  marker=False
guarded:   9/9 blocked; 0 leaked
```

Flowise (the tenth CVE, Node-side) is exercised by `flowise_repro.js`:
unguarded = marker created, guarded = `JailBlocked`, no marker.

</details>

<details>
<summary><b>How the four OX delivery families map to the four checks</b></summary>

| Family | Description | Check that blocks it |
|---|---|---|
| 1 | Unauth/auth command injection via an app's MCP config endpoint (LiteLLM, Agent Zero, Upsonic, Langchain-Chatchat, Fay, Bisheng, GPT Researcher) | 2 — fingerprint mismatch |
| 2 | Hardening bypass: allow-list inspects program name, attacker smuggles payload via `python -c` / `bash -c` / `node -e` / `cmd /c` | 3 — argv sanity refusal |
| 3 | Zero-click prompt injection rewrites the client's MCP config JSON between approval and spawn (Windsurf, rejected Claude Code / Cursor / Gemini-CLI / Copilot disclosures) | 2 — mutated command or args produce a new argv → fingerprint mismatch |
| 4 | Malicious marketplace entry installs a new `{command, args}` into a signed-looking directory (9 of 11 marketplaces accepted OX's PoC) | 2 — new argv has no signed entry |

</details>

---

## Tests

| Layer | Passing |
|---|---|
| Rust CLI unit | 3/3 |
| Python E2E | 8/8 |
| Node E2E | 3/3 |
| CVE reproduction | **10/10** |
| Real-world smoke | 3/3 — local + VM |

<details>
<summary><b>What each layer actually exercises</b></summary>

- **Rust CLI unit** — fingerprint determinism, argv-mutation sensitivity, dangerous-flag detection.
- **Python E2E** — against the real `mcp` + `anyio` packages: unapproved `StdioServerParameters` spawn blocked before `execve`; `python -c` refused at approve time without `--dangerous`; approved server runs inside `sandbox-exec`; `~/.ssh` denied even for approved entries; family-3 mutated argv blocked; family-3 *unrelated* config writes do NOT false-positive; family-4 id-reuse blocked; family-4 fresh-marketplace-install blocked.
- **Node E2E** — same invariants through `child_process.spawn`, the syscall every Node MCP host lands on.
- **Real-world smoke** — validated on the host AND across SSH into a VM: a local-Python MCP server, an SSH-tunneled CLI MCP server on the VM, and an SSH→JVM MCP server on the VM all start under the sandbox, round-trip MCP JSON-RPC calls correctly (`url_encode`, `hmac_compute`, `generate_random_string`, `get_entry_points`, `list_sections`, `execute_command`, and server-side errors all pass through intact), and every invocation is recorded as `allow` in the hash-chained audit log.

</details>

---

## Design summary

Shape: one static Rust binary, one PyPI package, one npm package, one shared allow-list.

**Shared state (`~/.mcp-jail/`):**
- `allow.toml` — id, fingerprint, env subset, sandbox scopes, signed_at, ed25519 signature
- `key.ed25519` (`chmod 600`) + `key.ed25519.pub`
- `audit.jsonl` — hash-chained append-only decision log
- `sandbox/<id>.sb` — per-id rendered sandbox profile

**Two enforcement layers:**

1. **Config wrap (preferred, language-agnostic):** client config entries rewritten to call `mcp-jail exec …`. The CLI evaluates, then `execve`s the sandbox-wrapped argv in-place. Works with any client regardless of language or env inheritance.
2. **SDK interposer (defense in depth):** Python `.pth` + Node `--import` hooks patch `mcp.client.stdio._create_platform_compatible_process`, `anyio.open_process`, and `child_process.spawn` at interpreter start. Any MCP consumer running inside that runtime gets the guard whether or not its config was wrapped.

9 of 10 published CVEs are server-side Python (the SDK hook catches those even without config-wrapping); the config wrap additionally handles Claude Desktop-style launch and anything statically linked. Both idempotent.

---

## Layout

```
cli/              Rust binary: init / approve / list / revoke / logs / verify / check / exec
python/           PyPI package: .pth activator + mcp.client.stdio + anyio.open_process hooks
node/             npm package:  --import hook patching child_process.spawn
tests/e2e/        pytest + Node node:test suite
tests/cve-repro/  per-CVE reproduction scripts (all 10)
.github/          ci.yml (tests on mac/linux arm/x86) + release.yml (5-target binary + wheel + npm tarball, signed)
```

---

<details>
<summary><b>FAQ</b></summary>

**Why isn't this fix in the MCP spec?** Because the paper's finding is
architectural: MCP STDIO's bootstrap mechanism is "client spawns an
arbitrary command and uses stdio as the transport." Anthropic declined
to change it. `mcp-jail` enforces locally what the protocol doesn't
require. If MCP ever ships a v2 STDIO with signed manifests, this tool
becomes obsolete — the correct long-term outcome.

**What about servers you already approved turning malicious?** The
sandbox bounds the damage (no `~/.ssh`, `~/.aws`, Keychain; default-deny
network; write-scoped). It does not eliminate it. Audit log gives you
the forensics.

**Statically-compiled MCP consumers that bypass the Python/Node hooks?**
Wrap them via `mcp-jail exec` in the client config — that path works
regardless of language. A Rust-crate interposer is on the roadmap for
consumers that can't be config-wrapped.

**HTTP/SSE transports?** None of the 10 CVEs use them. Separate egress
policy planned for v1.2.

**macOS per-host network scoping?** `sandbox-exec` can't express it —
`remote ip/tcp` only accept `*` or `localhost` as host. Our `--net`
flag records intent and expands to deny / localhost-only / all-outbound
on macOS. Proper per-host scoping is Linux/bwrap + nftables (v1.1) and
Windows Filtering Platform (v1.2).

**Audit chain says "broken" — is that bad?** Only if you didn't cause
it. During initial setup / testing the log will seed before and after
`init`, breaking the chain by design. To reset: `trash ~/.mcp-jail/audit.jsonl`.
In steady state it should stay intact; any break after that warrants
investigation.

</details>

<details>
<summary><b>Security disclosure</b></summary>

Found a bypass, an unsafe default, or a way the guard fails open? Please
report privately via GitHub security advisory on this repository rather
than a public issue. If you reproduce an OX CVE that `mcp-jail`
*doesn't* block, that's a valid report.

</details>

<details>
<summary><b>Disclaimer + limitations</b></summary>

> **`mcp-jail` IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND**,
> EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
> MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.
> IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
> CLAIM, DAMAGES, OR OTHER LIABILITY ARISING FROM THE USE OF THIS
> SOFTWARE. See [LICENSE](LICENSE) for the full terms.

**Security tool limitations — please read:**

- `mcp-jail` is defence-in-depth against a specific class of MCP STDIO RCE, not a comprehensive security solution. It does not replace OS hardening, code review of servers you install, or keeping upstream software patched.
- The sandbox bounds blast radius but cannot prevent abuse by a server you have consciously approved and granted broad scopes to. Read the argv before signing.
- Default-deny of `~/.ssh`, `~/.aws`, Keychain, network is a *heuristic* list. It will not cover every credential store on every machine. If you store secrets elsewhere, add them before relying on it.
- `mcp-jail` is v0.1 with no independent security audit. Do not rely on it alone to defend a production or high-value system.
- CVEs referenced here are attributed to OX Security's public disclosure. Reproduction scripts exercise the vulnerable sink, not every code path of every vulnerable app; see [tests/cve-repro/sweep.py](tests/cve-repro/sweep.py) for exactly what is exercised.
- **Authorised use only.** The sandbox does not make offensive actions legal. If you wrap an MCP server that performs network scanning, exploitation, or any action against systems, you are responsible for having written authorisation from the system owner.

</details>

---

## Credits

The 10 CVEs enumerated above were discovered, coordinated, and publicly
disclosed by the **OX Security research team** (Moshe Siman Tov Bustan,
Mustafa Naamnih, Nir Zadok, Roni Bar) in April 2026. `mcp-jail`
implements a local mitigation for the vulnerability class they
identified; their work is the reason this tool exists.

`mcp-jail` is not developed, endorsed, or affiliated with Anthropic PBC,
OX Security, the Model Context Protocol organization, or any of the
vulnerable projects referenced. All product names, logos, and brands are
property of their respective owners.

## License

Apache License 2.0 — see [LICENSE](LICENSE).

## References

- [OX Security — Mother of All AI Supply Chains](https://www.ox.security/blog/the-mother-of-all-ai-supply-chains-critical-systemic-vulnerability-at-the-core-of-the-mcp/)
- [OX Security — Full CVE advisory](https://www.ox.security/blog/mcp-supply-chain-advisory-rce-vulnerabilities-across-the-ai-ecosystem)
- [The Hacker News coverage](https://thehackernews.com/2026/04/anthropic-mcp-design-vulnerability.html)
- [MCP transports spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports)
