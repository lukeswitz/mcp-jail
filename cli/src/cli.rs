use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mcp-jail", version, about = "Allow-list + sandbox guard for MCP STDIO")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Initialize ~/.mcp-jail, generate key, install Python .pth activator.
    Init(InitArgs),
    /// Interactively approve a pending fingerprint (or a fresh argv).
    Approve(ApproveArgs),
    /// Show approved servers + recent pending blocks.
    List,
    /// Remove an approved entry.
    Revoke(RevokeArgs),
    /// Inspect audit log with hash-chain verification.
    Logs(LogsArgs),
    /// Self-check: keys, activators, hooks present.
    Verify,
    /// INTERNAL: evaluate a spawn request; returns JSON decision on stdout.
    /// Used by language interposers. Reads the canonical request on stdin.
    Check,
    /// Evaluate, sandbox-wrap, and `execv` the given argv. The preferred way
    /// to guard an MCP client: rewrite each config entry from
    ///   {"command": "uvx", "args": ["some-server"]}
    /// to
    ///   {"command": "mcp-jail",
    ///    "args": ["exec", "--id", "some-server", "--", "uvx", "some-server"]}
    /// Works with any client regardless of language or inheritance model.
    Exec(ExecArgs),
    /// Re-run the install script to upgrade binary, Python, and Node packages.
    /// Equivalent to: curl -fsSL https://raw.githubusercontent.com/mcp-jail/mcp-jail/main/install.sh | bash
    Upgrade,
    /// Scan known MCP client configs and rewrite every entry to route
    /// through `mcp-jail exec`. Backs up each file it modifies.
    Wrap(WrapArgs),
    /// Remove mcp-jail wrapping from known MCP client configs, restoring
    /// the original `command`/`args`. Useful for full uninstall.
    Unwrap(WrapArgs),
}

#[derive(Parser)]
pub struct WrapArgs {
    /// Apply changes without asking for confirmation.
    #[arg(long)]
    pub yes: bool,
    /// Print what would change without modifying files.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
}

#[derive(Parser)]
pub struct ExecArgs {
    /// Optional stable id to surface in audit/list output.
    #[arg(long)]
    pub id: Option<String>,
    /// Path to the MCP client config that contains this entry (for
    /// source-config cross-check on CVE family 3).
    #[arg(long = "source-config")]
    pub source_config: Option<String>,
    /// The command and its args to execute under the jail.
    #[arg(last = true, required = true)]
    pub argv: Vec<String>,
}

#[derive(Parser)]
pub struct InitArgs {
    /// Non-interactive; accept defaults.
    #[arg(long)]
    pub yes: bool,
}

#[derive(Parser)]
pub struct ApproveArgs {
    /// Fingerprint prefix (min 6 hex chars) to approve from pending log.
    pub fingerprint: Option<String>,
    /// Optional human-friendly id; otherwise derived from argv[0].
    #[arg(long)]
    pub id: Option<String>,
    /// Grant interpreter-eval flags (`-c`, `-e`, `/c`). Default: deny.
    #[arg(long)]
    pub dangerous: bool,
    /// Allow network egress to domain. Repeatable.
    #[arg(long = "net", value_name = "DOMAIN")]
    pub net: Vec<String>,
    /// Allow read access to path. Repeatable.
    #[arg(long = "fs-read", value_name = "PATH")]
    pub fs_read: Vec<String>,
    /// Allow read access to a specific file inside an otherwise-denied
    /// secret directory (~/.ssh/ssh_host_key, specific AWS profile, etc.).
    /// Emitted AFTER the built-in secret denies so it wins. Requires
    /// explicit path — broad grants under ~/.ssh must be intentional.
    #[arg(long = "fs-read-secret", value_name = "PATH")]
    pub fs_read_secret: Vec<String>,
    /// Allow write access to path. Repeatable.
    #[arg(long = "fs-write", value_name = "PATH")]
    pub fs_write: Vec<String>,
    /// Allow inherit of env var. Repeatable.
    #[arg(long = "env", value_name = "NAME")]
    pub env: Vec<String>,
    /// Bind this approval to a specific config file; future spawns must resolve from it.
    #[arg(long = "source-config")]
    pub source_config: Option<String>,
}

#[derive(Parser)]
pub struct RevokeArgs {
    pub id: String,
}

#[derive(Parser)]
pub struct LogsArgs {
    #[arg(long, default_value = "50")]
    pub limit: usize,
}
