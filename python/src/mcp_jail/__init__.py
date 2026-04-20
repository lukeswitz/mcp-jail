"""mcp-jail: Python interposer for the MCP STDIO transport."""

from ._guard import JailBlocked, install_hooks  # noqa: F401

__all__ = ["JailBlocked", "install_hooks"]
__version__ = "0.1.0"
