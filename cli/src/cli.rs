use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(name = "mcp-jail", version, about = "Allow-list + sandbox guard for MCP STDIO")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Subcommand)]
pub enum Command {
    /// Generate signing key and initialize the allow-list (run once after install).
    Init(InitArgs),
    /// Scan your MCP client configs and route every server through mcp-jail.
    Wrap(WrapArgs),
    /// Undo `wrap` — restore original MCP client configs.
    Unwrap(WrapArgs),
    /// Approve a blocked server by its fingerprint.
    Approve(ApproveArgs),
    /// Show approved servers and pending fingerprints awaiting approval.
    List,
    /// Remove an approval.
    Revoke(RevokeArgs),
    /// Show the audit log (every allow/deny decision).
    Logs(LogsArgs),
    /// Self-check: key present, signatures valid, sandbox helper available.
    Verify,
    /// Re-run the install script to upgrade mcp-jail.
    Upgrade,
    /// Run a command under mcp-jail (used by wrapped configs; you don't run this yourself).
    Exec(ExecArgs),
    #[command(hide = true)]
    Check,
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
