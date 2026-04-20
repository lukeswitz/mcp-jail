"""Bridge to the Rust CLI: JSON request on stdin -> JSON decision on stdout."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence


CLI_ENV = "MCP_JAIL_CLI"
_TIMEOUT_SEC = 10.0


@dataclass
class Decision:
    allow: bool
    reason: str
    fingerprint: str
    wrapped_argv: Optional[List[str]]
    env_allow: List[str]
    sandbox: Dict[str, Any]
    raw: Dict[str, Any]


def resolve_cli() -> Optional[str]:
    env = os.environ.get(CLI_ENV)
    if env and os.path.isfile(env) and os.access(env, os.X_OK):
        return env
    return shutil.which("mcp-jail")


def check(
    *,
    command: str,
    argv: Sequence[str],
    env: Dict[str, str],
    cwd: str,
    source_config: Optional[str] = None,
) -> Decision:
    cli = resolve_cli()
    if cli is None:
        return Decision(
            allow=False,
            reason="mcp-jail CLI not found in PATH; install from https://github.com/mcp-jail/mcp-jail",
            fingerprint="",
            wrapped_argv=None,
            env_allow=[],
            sandbox={},
            raw={},
        )

    payload = json.dumps(
        {
            "command": command,
            "argv": list(argv),
            "env": dict(env),
            "cwd": cwd,
            "source_config": source_config,
        }
    ).encode()

    try:
        proc = subprocess.run(  # noqa: S603 -- cli path already validated
            [cli, "check"],
            input=payload,
            capture_output=True,
            check=False,
            timeout=_TIMEOUT_SEC,
        )
    except subprocess.TimeoutExpired:
        return Decision(
            allow=False,
            reason="mcp-jail CLI timed out",
            fingerprint="",
            wrapped_argv=None,
            env_allow=[],
            sandbox={},
            raw={},
        )

    try:
        raw = json.loads(proc.stdout.decode(errors="replace"))
    except json.JSONDecodeError:
        return Decision(
            allow=False,
            reason=f"mcp-jail CLI produced invalid JSON: {proc.stdout!r}",
            fingerprint="",
            wrapped_argv=None,
            env_allow=[],
            sandbox={},
            raw={},
        )

    return Decision(
        allow=raw.get("decision") == "allow",
        reason=raw.get("reason", ""),
        fingerprint=raw.get("fingerprint", ""),
        wrapped_argv=raw.get("wrapped_argv"),
        env_allow=raw.get("env_allow", []) or [],
        sandbox=raw.get("sandbox", {}) or {},
        raw=raw,
    )
