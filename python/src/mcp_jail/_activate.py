"""Loaded by the .pth activator at interpreter start. Idempotent."""

import os

if os.environ.get("MCP_JAIL_DISABLE") != "1":
    try:
        from ._guard import install_hooks
        install_hooks()
    except Exception:
        # Must never brick interpreter startup.
        pass
