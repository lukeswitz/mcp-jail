//! Best-effort desktop notifications when mcp-jail blocks an MCP spawn.
//!
//! Fires once per brand-new pending fingerprint so the user doesn't have
//! to monitor `mcp-jail list` or their MCP client's log. Fully fire-and-
//! forget: any failure (osascript missing, user disabled notifications,
//! non-mac host) is silently swallowed because the guard's primary job
//! (refuse the spawn) has already succeeded by the time we get here.
//!
//! Disable with `MCP_JAIL_NOTIFY=0` in the env.

use std::path::Path;

pub fn blocked_spawn(argv: &[String], fingerprint: &str) {
    if std::env::var("MCP_JAIL_NOTIFY").as_deref() == Ok("0") {
        return;
    }
    let short_cmd = argv
        .first()
        .and_then(|s| Path::new(s).file_name().and_then(|n| n.to_str()))
        .or_else(|| argv.first().map(String::as_str))
        .unwrap_or("unknown");
    let fp_prefix = &fingerprint[..12.min(fingerprint.len())];

    #[cfg(target_os = "macos")]
    mac_notify(short_cmd, fp_prefix);

    // Linux / BSD: best-effort notify-send if present.
    #[cfg(all(unix, not(target_os = "macos")))]
    linux_notify(short_cmd, fp_prefix);

    #[cfg(not(unix))]
    {
        let _ = (short_cmd, fp_prefix);
    }
}

#[cfg(target_os = "macos")]
fn mac_notify(short_cmd: &str, fp_prefix: &str) {
    // Escape quotes so `display notification` doesn't blow up on weird argv.
    let title = format!("mcp-jail blocked: {}", short_cmd.replace('"', "'"));
    let body = format!("Run `mcp-jail approve` to review (fp {fp_prefix})");
    let script = format!(
        "display notification \"{body}\" with title \"{title}\" sound name \"Funk\"",
        body = body.replace('"', "'"),
        title = title.replace('"', "'"),
    );
    let _ = std::process::Command::new("osascript")
        .args(["-e", &script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();
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
        let script = format!(
            "display notification \"{body}\" with title \"{title}\" sound name \"Funk\"",
            body = body.replace('"', "'"),
            title = title.replace('"', "'"),
        );
        let _ = std::process::Command::new("osascript")
            .args(["-e", &script])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
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
