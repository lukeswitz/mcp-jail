"""Family 4 — malicious MCP marketplace install.

OX showed 9 of 11 marketplaces accept a malicious PoC without review. The
delivery shape: an attacker publishes an MCP entry in a trusted-looking
directory; on install, the user's client config gains a new `{command,
args}` or an existing entry is replaced. Either way, the next spawn runs
an attacker-controlled argv.

Our defense is the same as family 1: fingerprint mismatch. The test
models a worse variant — the attacker re-uses an existing *id* (e.g.
`github-mcp`) but swaps the argv. The ID collision must not grant the
new argv the trust of the old one.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import mcp_jail
from mcp_jail._guard import JailBlocked


def _cli(*args: str) -> subprocess.CompletedProcess:
    binary = shutil.which("mcp-jail")
    assert binary is not None
    return subprocess.run([binary, *args], capture_output=True, text=True, check=False)


def _pending_fp(root: Path) -> str:
    lines = (root / "pending.jsonl").read_text().strip().splitlines()
    return json.loads(lines[-1])["fingerprint"]


def _spawn(command: str, args: list[str]) -> int:
    from mcp import StdioServerParameters
    from mcp.client.stdio import _create_platform_compatible_process

    params = StdioServerParameters(
        command=command, args=args, env=os.environ.copy(), cwd=os.getcwd()
    )

    async def run() -> int:
        proc = await _create_platform_compatible_process(
            params.command, params.args, params.env or {}, sys.stderr, params.cwd
        )
        return await proc.wait()

    return asyncio.run(run())


@pytest.fixture(autouse=True)
def _hooks() -> None:
    mcp_jail.install_hooks()


@pytest.fixture()
def jail(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    r = _cli("init")
    assert r.returncode == 0, r.stderr
    return home / ".mcp-jail"


def test_id_reuse_with_different_argv_is_blocked(jail, tmp_path):
    """Approve argv A under id=`legit-server`. An attacker-installed entry
    under the same id with argv B must not be permitted to spawn."""
    marker_legit = tmp_path / "legit"
    marker_evil = tmp_path / "evil"

    # 1. User approves the benign server.
    with pytest.raises(JailBlocked):
        _spawn("/usr/bin/touch", [str(marker_legit)])
    fp_legit = _pending_fp(jail)[:12]
    r = _cli(
        "approve", fp_legit,
        "--id", "legit-server",
        "--fs-write", str(tmp_path),
    )
    assert r.returncode == 0, r.stderr

    # Baseline: legit argv runs fine.
    assert _spawn("/usr/bin/touch", [str(marker_legit)]) == 0
    assert marker_legit.exists()

    # 2. Attacker installs a new MCP entry with the same id but a different
    # command -- the marketplace attack shape. The next spawn must refuse.
    # (In a real client config the attacker only controls the JSON; we
    # exercise the same path by invoking spawn with the attacker's argv.)
    with pytest.raises(JailBlocked) as ei:
        _spawn("/usr/bin/touch", [str(marker_evil)])
    assert not marker_evil.exists(), "different argv must not run on id reuse"
    assert "unknown fingerprint" in ei.value.reason


def test_new_marketplace_entry_blocked_until_explicit_approval(jail, tmp_path):
    """Direct analog of `mcp-jail install` flow: an entry that has never
    been approved must not spawn, even if the user already approved a
    *different* entry."""
    existing = tmp_path / "existing"
    attacker = tmp_path / "attacker"

    # User has one other server approved.
    with pytest.raises(JailBlocked):
        _spawn("/usr/bin/touch", [str(existing)])
    fp = _pending_fp(jail)[:12]
    r = _cli("approve", fp, "--id", "existing", "--fs-write", str(tmp_path))
    assert r.returncode == 0

    # A new, fresh argv from a marketplace install must still be refused.
    with pytest.raises(JailBlocked):
        _spawn("/usr/bin/python3", [str(attacker)])
    assert not attacker.exists()
