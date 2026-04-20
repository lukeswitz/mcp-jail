"""Import-time interposers patching mcp.client.stdio and anyio.open_process.
Each wrapper shells out to `mcp-jail check`, then either raises JailBlocked
or calls through with the sandbox-wrapped argv and filtered env."""

from __future__ import annotations

import importlib.abc
import importlib.util
import os
import sys
import threading
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from . import _cli

_INSTALLED = False
_LOCK = threading.Lock()


class JailBlocked(OSError):
    """Raised when mcp-jail refuses to spawn an MCP server process."""

    def __init__(self, reason: str, fingerprint: str, argv: Sequence[str]) -> None:
        super().__init__(reason)
        self.reason = reason
        self.fingerprint = fingerprint
        self.argv = list(argv)

    def __str__(self) -> str:  # pragma: no cover -- trivial
        hint = f"  mcp-jail approve {self.fingerprint[:12]}" if self.fingerprint else ""
        return (
            f"mcp-jail blocked spawn: {self.reason}\n"
            f"  argv: {self.argv!r}\n"
            f"{hint}"
        )


def install_hooks() -> None:
    """Idempotent. Safe to call from .pth activator and from user code."""
    global _INSTALLED
    with _LOCK:
        if _INSTALLED:
            return
        _install_import_hook()
        _INSTALLED = True


def _evaluate(
    command: str,
    argv: Sequence[str],
    env: Optional[Dict[str, str]],
    cwd: Optional[str],
) -> Tuple[List[str], Dict[str, str]]:
    """Return (wrapped_argv, filtered_env). Raises JailBlocked on deny."""
    effective_env = dict(env if env is not None else os.environ)
    effective_cwd = os.path.abspath(cwd) if cwd else os.getcwd()

    decision = _cli.check(
        command=command,
        argv=list(argv),
        env=effective_env,
        cwd=effective_cwd,
    )

    if not decision.allow:
        raise JailBlocked(decision.reason, decision.fingerprint, argv)

    wrapped = decision.wrapped_argv or list(argv)
    filtered: Dict[str, str] = {}
    for key in decision.env_allow:
        if key in effective_env:
            filtered[key] = effective_env[key]
    for essential in (
        "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SHELL", "LANG", "LC_ALL",
        "SSH_AUTH_SOCK", "DISPLAY", "XAUTHORITY",
    ):
        if essential in effective_env and essential not in filtered:
            filtered[essential] = effective_env[essential]
    return wrapped, filtered


def _patch_mcp_client_stdio(mod: Any) -> None:
    target_name = "_create_platform_compatible_process"
    original = getattr(mod, target_name, None)
    if original is None or getattr(original, "__mcp_jail_patched__", False):
        return

    async def wrapper(command: str, args: Sequence[str], env: Dict[str, str], errlog: Any, cwd: Optional[str]) -> Any:
        wrapped, filtered_env = _evaluate(
            command=command,
            argv=[command, *list(args)],
            env=env,
            cwd=cwd,
        )
        # argv[0] is now the sandbox helper; unpack for the (command, args) API.
        new_command = wrapped[0]
        new_args = wrapped[1:]
        filtered_env = dict(filtered_env)
        filtered_env["MCP_JAIL_PASSTHROUGH"] = "1"
        return await original(new_command, new_args, filtered_env, errlog, cwd)

    wrapper.__mcp_jail_patched__ = True  # type: ignore[attr-defined]
    setattr(mod, target_name, wrapper)


def _patch_anyio(mod: Any) -> None:
    target_name = "open_process"
    original = getattr(mod, target_name, None)
    if original is None or getattr(original, "__mcp_jail_patched__", False):
        return

    async def wrapper(command: Any, *a: Any, **kw: Any) -> Any:
        # Only intervene on list/tuple argv form (the MCP SDK's shape).
        # Bare-string commands are shell pipelines and pass through.
        if not isinstance(command, (list, tuple)):
            return await original(command, *a, **kw)
        if not command:
            return await original(command, *a, **kw)

        # Inner passthrough when the outer hook already evaluated.
        env_kw = kw.get("env") or {}
        if env_kw.get("MCP_JAIL_PASSTHROUGH") == "1":
            clean = {k: v for k, v in env_kw.items() if k != "MCP_JAIL_PASSTHROUGH"}
            kw["env"] = clean
            return await original(command, *a, **kw)

        argv = list(command)
        env = kw.get("env")
        cwd = kw.get("cwd")
        wrapped, filtered_env = _evaluate(
            command=argv[0],
            argv=argv,
            env=env,
            cwd=cwd,
        )
        kw["env"] = filtered_env
        return await original(wrapped, *a, **kw)

    wrapper.__mcp_jail_patched__ = True  # type: ignore[attr-defined]
    setattr(mod, target_name, wrapper)


_PATCHERS: Dict[str, Callable[[Any], None]] = {
    "mcp.client.stdio": _patch_mcp_client_stdio,
    "anyio": _patch_anyio,
}


class _PostImportHook(importlib.abc.Loader, importlib.abc.MetaPathFinder):
    """Defers to real finders, patches target modules on first load."""

    def find_spec(self, fullname: str, path: Any = None, target: Any = None) -> Optional[importlib.util.ModuleSpec]:
        if fullname not in _PATCHERS:
            return None
        for finder in sys.meta_path:
            if finder is self:
                continue
            try:
                spec = finder.find_spec(fullname, path, target)
            except (AttributeError, ImportError):
                continue
            if spec is None:
                continue
            original_loader = spec.loader
            spec.loader = _WrappingLoader(original_loader, _PATCHERS[fullname])
            return spec
        return None


class _WrappingLoader(importlib.abc.Loader):
    def __init__(self, inner: Any, patcher: Callable[[Any], None]) -> None:
        self._inner = inner
        self._patcher = patcher

    def create_module(self, spec: importlib.util.ModuleSpec) -> Any:
        if hasattr(self._inner, "create_module"):
            return self._inner.create_module(spec)
        return None

    def exec_module(self, module: Any) -> None:
        self._inner.exec_module(module)
        try:
            self._patcher(module)
        except Exception:
            pass


def _install_import_hook() -> None:
    # Patch modules already imported before the hook installed.
    for fullname, patcher in _PATCHERS.items():
        mod = sys.modules.get(fullname)
        if mod is not None:
            try:
                patcher(mod)
            except Exception:
                pass
    hook = _PostImportHook()
    if not any(isinstance(f, _PostImportHook) for f in sys.meta_path):
        sys.meta_path.insert(0, hook)
