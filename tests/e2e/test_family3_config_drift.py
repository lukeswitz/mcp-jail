"""Family 3 — zero-click prompt-injection edits the MCP config file.

The realistic attack: an attacker (or prompt-injected agent) rewrites
mcpServers.<id>.command or .args in the client config. The next time the
client spawns that MCP, it reads the new argv and passes it to the SDK.

Defense: the new argv has no signed allow-list entry → fingerprint
mismatch → blocked. Same mechanism as family 1; mutating argv via the
config is just another path to the same sink.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest


def _cli(*args: str, **kw) -> subprocess.CompletedProcess:
    binary = shutil.which("mcp-jail")
    assert binary is not None
    return subprocess.run(
        [binary, *args], capture_output=True, text=True, check=False, **kw
    )


def _pending_fp(root: Path) -> str:
    lines = (root / "pending.jsonl").read_text().strip().splitlines()
    return json.loads(lines[-1])["fingerprint"]


def _spawn_from_config(cfg: Path, server_id: str) -> subprocess.CompletedProcess:
    """Mimic the client's read-config-then-spawn flow."""
    d = json.loads(cfg.read_text())
    entry = d["mcpServers"][server_id]
    argv = [entry["command"], *entry.get("args", [])]
    return _cli(
        "exec",
        "--id", server_id,
        "--source-config", str(cfg),
        "--",
        *argv,
    )


@pytest.fixture()
def scenario(monkeypatch, tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    r = _cli("init")
    assert r.returncode == 0, r.stderr
    cfg = tmp_path / "client_config.json"
    cfg.write_text(json.dumps({
        "mcpServers": {
            "srv": {
                "command": "/usr/bin/touch",
                "args": [str(tmp_path / "legit")],
            }
        }
    }))
    return {"jail_root": home / ".mcp-jail", "config": cfg, "tmp": tmp_path}


def test_config_mutation_to_new_argv_is_blocked(scenario):
    jail_root = scenario["jail_root"]
    cfg = scenario["config"]
    tmp = scenario["tmp"]

    # 1. First spawn from the legit config → pending.
    r = _spawn_from_config(cfg, "srv")
    assert r.returncode != 0
    fp = _pending_fp(jail_root)[:12]
    r = _cli(
        "approve", fp,
        "--id", "srv",
        "--source-config", str(cfg),
        "--fs-write", str(tmp),
    )
    assert r.returncode == 0, r.stderr

    # 2. Baseline: legit argv runs fine.
    r = _spawn_from_config(cfg, "srv")
    assert r.returncode == 0, r.stderr
    assert (tmp / "legit").exists()

    # 3. Prompt injection rewrites args to an attacker-chosen target.
    d = json.loads(cfg.read_text())
    d["mcpServers"]["srv"]["args"] = [str(tmp / "pwned")]
    cfg.write_text(json.dumps(d))

    # 4. Next spawn reads the mutated argv and must be refused.
    r = _spawn_from_config(cfg, "srv")
    assert r.returncode != 0, "mutated args must be refused"
    assert "unknown fingerprint" in r.stderr, r.stderr
    assert not (tmp / "pwned").exists(), "mutated argv must not spawn"


def test_config_writes_that_dont_touch_argv_are_not_false_positives(scenario):
    """A client writing unrelated state (session, project list, timestamps)
    to the same config file must not cause deny on subsequent spawns. This
    is what tripped Claude Code in live deployment."""
    jail_root = scenario["jail_root"]
    cfg = scenario["config"]
    tmp = scenario["tmp"]

    r = _spawn_from_config(cfg, "srv")
    assert r.returncode != 0
    fp = _pending_fp(jail_root)[:12]
    r = _cli(
        "approve", fp,
        "--id", "srv",
        "--source-config", str(cfg),
        "--fs-write", str(tmp),
    )
    assert r.returncode == 0, r.stderr

    # The client writes unrelated state back to the config.
    d = json.loads(cfg.read_text())
    d["lastSession"] = "2026-04-20T17:07:18"
    d["projects"] = {"/tmp/foo": {}}
    cfg.write_text(json.dumps(d))

    # Spawn must still succeed — argv unchanged.
    r = _spawn_from_config(cfg, "srv")
    assert r.returncode == 0, f"legit argv after unrelated config write must pass: {r.stderr}"
