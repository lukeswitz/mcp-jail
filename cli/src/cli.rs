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
    /// Drop entries from the pending queue. Default: all. Use flags to scope.
    Prune(PruneArgs),
    /// One-line summary — print "N pending" if any, else silent. Drop-in
    /// for shell prompts (`PROMPT_COMMAND`/`precmd`) and status bars.
    Status,
    /// Show the audit log (every allow/deny decision).
    Logs(LogsArgs),
    /// Self-check: key present, signatures valid, sandbox helper available.
    Verify,
    /// Re-run the install script to upgrade mcp-jail.
    Upgrade,
    /// Health check: state dir, key, signatures, sandbox helper, pending approvals, version check.
    Doctor(DoctorArgs),
    /// Install, uninstall, or check the platform-native integrity
    /// watchdog that alerts when mcp-jail is missing, tampered, or
    /// unhealthy. Uses launchd (macOS) / systemd (Linux).
    Sentry(SentryArgs),
    #[command(hide = true)]
    Exec(ExecArgs),
    #[command(hide = true)]
    Check,
}

#[derive(Parser)]
pub struct DoctorArgs {
    /// Fire a desktop notification on the first problem/warning in
    /// addition to printing to stdout. Intended for unattended
    /// invocations from the sentry watchdog.
    #[arg(long)]
    pub notify: bool,
    /// Exit 0 even when problems are found. For monitoring contexts
    /// that treat non-zero exits as hard failures but still want the
    /// notification side effect.
    #[arg(long = "soft-fail")]
    pub soft_fail: bool,
}

#[derive(Parser)]
pub struct SentryArgs {
    #[command(subcommand)]
    pub action: SentryAction,
}

#[derive(Subcommand)]
pub enum SentryAction {
    /// Install and load the integrity watchdog. Runs `mcp-jail doctor
    /// --notify` every 5 minutes and on filesystem events against the
    /// mcp-jail binary itself (launchd `WatchPaths` / systemd `.path`).
    /// A shell wrapper fires a platform notification directly if the
    /// binary is gone — solving the dead-man's-switch problem.
    Install,
    /// Unload and remove the watchdog.
    Uninstall,
    /// Report whether the watchdog is installed and loaded.
    Status,
}

#[derive(Parser)]
pub struct WrapArgs {
    /// Apply changes without asking for confirmation.
    #[arg(long)]
    pub yes: bool,
    /// Print what would change without modifying files.
    #[arg(long = "dry-run")]
    pub dry_run: bool,
    /// Don't auto-approve existing servers; make the user approve each one
    /// interactively on first spawn. Default is to trust what's already in
    /// your config (you ran the installer; you own those entries), skip
    /// servers with dangerous argv flags, and sign everything else with
    /// the default sandbox profile.
    #[arg(long = "no-auto-approve")]
    pub no_auto_approve: bool,
    /// Force strict defaults (net BLOCKED, fs_write=/tmp) on every server
    /// instead of prompting. Use `--yes --strict` to silently lock down.
    #[arg(long)]
    pub strict: bool,
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
pub struct PruneArgs {
    /// Drop every pending entry. Default when no other flag is given.
    #[arg(long)]
    pub all: bool,
    /// Drop pending entries older than N days.
    #[arg(long = "older-than", value_name = "DAYS")]
    pub older_than: Option<i64>,
    /// Drop the pending entry matching this fingerprint prefix.
    #[arg(long = "fp", value_name = "HEX")]
    pub fingerprint: Option<String>,
}

#[derive(Parser)]
pub struct LogsArgs {
    #[arg(long, default_value = "50")]
    pub limit: usize,
}
