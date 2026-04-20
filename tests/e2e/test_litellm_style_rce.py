"""End-to-end replay of the OX/LiteLLM CVE class (CVE-2026-30623 et al).

The pattern across 9 of 10 OX CVEs: attacker-controlled JSON reaches a
server that constructs `StdioServerParameters(command, args)` and hands it
to `stdio_client()`, which spawns the command. The child runs before the
MCP handshake validates the server — RCE.

We simulate the unsafe handler locally, then verify mcp-jail blocks the
unapproved spawn, approves it, and re-runs it inside the sandbox.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

import mcp_jail
from mcp_jail._guard import JailBlocked


PAYLOAD_MARKER = "pwned_by_litellm_style_rce"


def _run_cli(*args: str) -> subprocess.CompletedProcess:
    cli = shutil.which("mcp-jail")
    assert cli is not None, "mcp-jail binary must be on PATH"
    return subprocess.run(
        [cli, *args], capture_output=True, check=False, text=True
    )


def _latest_pending_fp(jail_root: Path) -> str:
    lines = (jail_root / "pending.jsonl").read_text().strip().splitlines()
    return json.loads(lines[-1])["fingerprint"]


def _unsafe_handler(user_command: str, user_args: list[str]) -> int:
    """Mirror of LiteLLM/Flowise/etc. `create_mcp_server` handler.

    Returns the child's exit code. This is the shape of the code the attacker
    reaches; our interposer must refuse the spawn without any patch here.
    """
    from mcp import StdioServerParameters
    from mcp.client.stdio import _create_platform_compatible_process

    params = StdioServerParameters(
        command=user_command, args=user_args, env=os.environ.copy(), cwd=os.getcwd()
    )

    async def _run() -> int:
        proc = await _create_platform_compatible_process(
            params.command, params.args, params.env or {}, sys.stderr, params.cwd
        )
        return await proc.wait()

    return asyncio.run(_run())


@pytest.fixture(autouse=True)
def _install_hooks() -> None:
    mcp_jail.install_hooks()


@pytest.fixture()
def fresh_jail(monkeypatch, tmp_path) -> Path:
    jail_home = tmp_path / "home"
    jail_home.mkdir()
    monkeypatch.setenv("HOME", str(jail_home))
    # Run init against the new HOME so allow/audit live under tmp.
    r = _run_cli("init")
    assert r.returncode == 0, r.stderr
    return jail_home / ".mcp-jail"


def test_unapproved_rce_is_blocked(fresh_jail, tmp_path):
    """The exact payload shape from the OX advisory: `touch <file>` as args."""
    marker = tmp_path / "rce.marker"
    assert not marker.exists()

    with pytest.raises(JailBlocked) as ei:
        _unsafe_handler("/usr/bin/touch", [str(marker)])

    assert not marker.exists(), "mcp-jail failed to prevent the spawn"
    assert "unknown fingerprint" in ei.value.reason


def test_dangerous_flag_rejected_even_after_approval(fresh_jail, tmp_path):
    """After approving `python3`, an argv with `-c` must still be refused
    (unless the user explicitly signed with --dangerous)."""
    marker = tmp_path / "rce2.marker"

    # First attempt: deny. This seeds a pending entry.
    with pytest.raises(JailBlocked):
        _unsafe_handler("/usr/bin/python3", ["-c", f"open('{marker}', 'w').close()"])

    # User mistakenly approves the fingerprint without --dangerous. CLI must refuse.
    fp = _latest_pending_fp(fresh_jail)
    r = _run_cli("approve", fp[:12], "--id", "python3-unsafe")
    assert r.returncode != 0, "CLI must refuse -c approval without --dangerous"
    assert "interpreter-eval" in r.stderr or "dangerous" in r.stderr


def test_approved_server_runs_inside_sandbox(fresh_jail, tmp_path):
    """Approve a benign server argv, confirm next spawn goes through sandbox-exec
    (on macOS) and produces the expected output."""
    if sys.platform != "darwin":
        pytest.skip("macOS sandbox integration")

    marker = tmp_path / "allowed.marker"

    # First call seeds pending.
    with pytest.raises(JailBlocked):
        _unsafe_handler("/usr/bin/touch", [str(marker)])

    fp = _latest_pending_fp(fresh_jail)
    r = _run_cli(
        "approve",
        fp[:12],
        "--id",
        "touch-allowed",
        "--fs-write",
        str(tmp_path),
    )
    assert r.returncode == 0, r.stderr

    # Second call should be allowed and wrapped in sandbox-exec.
    rc = _unsafe_handler("/usr/bin/touch", [str(marker)])
    assert rc == 0, f"approved+sandboxed touch failed rc={rc}"
    assert marker.exists(), "approved + sandboxed touch should have created the file"


def test_approved_server_cannot_read_ssh_dir(fresh_jail, tmp_path):
    """The sandbox profile denies ~/.ssh reads even for approved servers."""
    if sys.platform != "darwin":
        pytest.skip("macOS sandbox integration")

    ssh_dir = Path(os.environ["HOME"]) / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    secret = ssh_dir / "id_rsa_fake"
    secret.write_text("PRIVATE KEY DO NOT LEAK\n")

    # Seed + approve `/bin/cat` for this argv.
    out = tempfile.NamedTemporaryFile(delete=False)
    with pytest.raises(JailBlocked):
        _unsafe_handler("/bin/cat", [str(secret)])

    fp = _latest_pending_fp(fresh_jail)
    r = _run_cli("approve", fp[:12], "--id", "cat-ssh", "--fs-read", str(tmp_path))
    assert r.returncode == 0, r.stderr

    rc = _unsafe_handler("/bin/cat", [str(secret)])
    assert rc != 0, "sandbox should deny reads under ~/.ssh"
