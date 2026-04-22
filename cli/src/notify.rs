//! Best-effort desktop notifications + persistent alert log when mcp-jail
//! blocks an MCP spawn.
//!
//! Desktop notifications from a subprocess of an MCP client are unreliable
//! on macOS (bundle-id / notification-permission issues), so we ALWAYS also
//! append to `~/.mcp-jail/alerts.log` — a single tail-able file the user
//! can watch or read in `mcp-jail list`. If the log write fails we fall
//! back to best-effort desktop notifications only.
//!
//! Disable desktop notifications with `MCP_JAIL_NOTIFY=0` in the env.

use std::io::Write;
use std::path::Path;

pub fn blocked_spawn(argv: &[String], fingerprint: &str) {
    let short_cmd = argv
        .first()
        .and_then(|s| Path::new(s).file_name().and_then(|n| n.to_str()))
        .or_else(|| argv.first().map(String::as_str))
        .unwrap_or("unknown");
    let fp_prefix = &fingerprint[..12.min(fingerprint.len())];

    // Always persist — this is what the user will actually see.
    let _ = append_alert_log(argv, fingerprint);

    if std::env::var("MCP_JAIL_NOTIFY").as_deref() == Ok("0") {
        return;
    }

    #[cfg(target_os = "macos")]
    mac_notify(short_cmd, fp_prefix);

    #[cfg(all(unix, not(target_os = "macos")))]
    linux_notify(short_cmd, fp_prefix);

    #[cfg(not(unix))]
    {
        let _ = (short_cmd, fp_prefix);
    }
}

const ALERT_LOG_MAX_BYTES: u64 = 1_048_576;
const ALERT_LOG_ARGV_MAX: usize = 512;

fn append_alert_log(argv: &[String], fingerprint: &str) -> std::io::Result<()> {
    let Some(home) = dirs::home_dir() else {
        return Ok(());
    };
    let dir = home.join(".mcp-jail");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("alerts.log");

    // Rotate if oversized. Single-generation rotation is fine — this log
    // is a heads-up aid, not a forensic record (that's audit.jsonl).
    if let Ok(meta) = std::fs::metadata(&path)
        && meta.len() > ALERT_LOG_MAX_BYTES
    {
        let _ = std::fs::rename(&path, dir.join("alerts.log.1"));
    }

    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    let ts = chrono::Utc::now().to_rfc3339();
    let fp12 = &fingerprint[..12.min(fingerprint.len())];
    let mut joined = argv.join(" ");
    if joined.len() > ALERT_LOG_ARGV_MAX {
        joined.truncate(ALERT_LOG_ARGV_MAX);
        joined.push('…');
    }
    writeln!(f, "{ts}  BLOCKED  fp={fp12}  argv={joined}")
}

#[cfg(target_os = "macos")]
fn mac_notify(short_cmd: &str, fp_prefix: &str) {
    let title = format!("mcp-jail blocked: {}", short_cmd.replace('"', "'"));
    let body = format!("Run `mcp-jail approve` to review (fp {fp_prefix})");

    // When spawned as a subprocess of an MCP host (Claude Code, Cursor,
    // etc.), this process lives OUTSIDE the user's Aqua GUI session. The
    // Notification Center APIs silently refuse to post from there. Fix:
    // re-enter the GUI session via `launchctl asuser $UID` before
    // launching the notifier. This works from both session types.
    let uid = format!("{}", unsafe { libc::getuid() });

    // Prefer terminal-notifier if installed. The real action is the
    // `display alert` modal fired by prompt::ask; this banner is just a
    // passive heads-up so the user notices if the modal is off-screen.
    let tn = which("terminal-notifier");
    if let Some(tn_path) = tn {
        let _ = std::process::Command::new("launchctl")
            .args([
                "asuser",
                &uid,
                &tn_path,
                "-title", &title,
                "-message", &body,
                "-sound", "Funk",
                "-group", "mcp-jail",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        return;
    }

    let script = format!(
        "display notification \"{body}\" with title \"{title}\" sound name \"Funk\"",
        body = body.replace('"', "'"),
        title = title.replace('"', "'"),
    );
    let _ = std::process::Command::new("launchctl")
        .args(["asuser", &uid, "/usr/bin/osascript", "-e", &script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}

#[cfg(target_os = "macos")]
fn which(cmd: &str) -> Option<String> {
    let path = std::env::var("PATH").ok()?;
    for dir in path.split(':').chain(["/opt/homebrew/bin", "/usr/local/bin"]) {
        let p = std::path::Path::new(dir).join(cmd);
        if p.is_file() {
            return p.to_str().map(str::to_owned);
        }
    }
    None
}

pub fn health_alert(problems: usize, warnings: usize) {
    if std::env::var("MCP_JAIL_NOTIFY").as_deref() == Ok("0") {
        return;
    }
    let title = if problems > 0 { "mcp-jail unhealthy" } else { "mcp-jail warnings" };
    let body = format!(
        "{problems} problem(s), {warnings} warning(s). Run `mcp-jail doctor` for details."
    );

    #[cfg(target_os = "macos")]
    {
        let uid = format!("{}", unsafe { libc::getuid() });
        if let Some(tn_path) = which("terminal-notifier") {
            let _ = std::process::Command::new("launchctl")
                .args([
                    "asuser", &uid, &tn_path,
                    "-title", title,
                    "-message", &body,
                    "-sound", "Funk",
                    "-group", "mcp-jail-health",
                ])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        } else {
            let script = format!(
                "display notification \"{body}\" with title \"{title}\" sound name \"Funk\"",
                body = body.replace('"', "'"),
                title = title.replace('"', "'"),
            );
            let _ = std::process::Command::new("launchctl")
                .args(["asuser", &uid, "/usr/bin/osascript", "-e", &script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
        }
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let urgency = if problems > 0 { "critical" } else { "normal" };
        let _ = std::process::Command::new("notify-send")
            .args(["-a", "mcp-jail", "-u", urgency, title, &body])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    #[cfg(not(unix))]
    {
        let _ = (title, body);
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
fn linux_notify(short_cmd: &str, fp_prefix: &str) {
    let title = format!("mcp-jail blocked: {short_cmd}");
    let body = format!("Run `mcp-jail approve` to review (fp {fp_prefix})");
    let _ = std::process::Command::new("notify-send")
        .args(["-a", "mcp-jail", "-u", "normal", &title, &body])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
}
