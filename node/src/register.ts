// Entry point for `--import mcp-jail/register`; installs hooks at startup.

import { installHooks } from './hook.js';

if (process.env['MCP_JAIL_DISABLE'] !== '1') {
  installHooks();
}
