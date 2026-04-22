//! Best-effort clipboard copy. Silently no-ops if no tool is available.

use std::io::Write;
use std::process::{Command, Stdio};

pub fn copy(text: &str) -> bool {
    if std::env::var("MCP_JAIL_CLIPBOARD").as_deref() == Ok("0") {
        return false;
    }
    for (cmd, args) in candidates() {
        if try_pipe(cmd, args, text) {
            return true;
        }
    }
    false
}

#[cfg(target_os = "macos")]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("pbcopy", &[])]
}

#[cfg(all(unix, not(target_os = "macos")))]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    vec![
        ("wl-copy", &[]),
        ("xclip", &["-selection", "clipboard"]),
        ("xsel", &["--clipboard", "--input"]),
    ]
}

#[cfg(target_os = "windows")]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    vec![("clip", &[])]
}

#[cfg(not(any(unix, target_os = "windows")))]
fn candidates() -> Vec<(&'static str, &'static [&'static str])> {
    vec![]
}

fn try_pipe(cmd: &str, args: &[&str], text: &str) -> bool {
    let child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
    let Ok(mut child) = child else { return false };
    if let Some(mut stdin) = child.stdin.take()
        && stdin.write_all(text.as_bytes()).is_err()
    {
        let _ = child.wait();
        return false;
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}
