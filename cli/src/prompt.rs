//! Native approve/deny modal shown when mcp-jail blocks an unknown spawn.

use std::process::Command;

#[cfg(unix)]
const TIMEOUT_SECS: u64 = 60;

pub enum Decision {
    Approve,
    Deny,
    #[allow(dead_code)]
    Timeout,
    NoGui,
}

pub fn ask(argv: &[String], source_config: Option<&str>) -> Decision {
    if std::env::var("MCP_JAIL_PROMPT").as_deref() == Ok("0") {
        return Decision::NoGui;
    }
    let cmd_str = truncate(&argv.join(" "), 400);
    let src = source_config.unwrap_or("(unknown)");

    #[cfg(target_os = "macos")]
    {
        macos::ask(&cmd_str, src)
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        linux::ask(&cmd_str, src)
    }
    #[cfg(target_os = "windows")]
    {
        windows::ask(&cmd_str, src)
    }
    #[cfg(not(any(unix, target_os = "windows")))]
    {
        let _ = (cmd_str, src);
        Decision::NoGui
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut t: String = s.chars().take(max).collect();
        t.push('…');
        t
    }
}

fn body(cmd_str: &str, source: &str) -> String {
    format!(
        "Command:\n{cmd_str}\n\n\
         Source:\n{source}\n\n\
         Approve lets it run with a default sandbox. \
         Tune later with `mcp-jail list` and `mcp-jail approve --help`."
    )
}

#[cfg(target_os = "macos")]
mod macos {
    use super::*;

    pub fn ask(cmd_str: &str, source: &str) -> Decision {
        let message = super::body(cmd_str, source)
            .replace('\\', "\\\\")
            .replace('"', "\\\"");

        // tell System Events so the modal comes to the foreground even when
        // we're spawned as a background subprocess of an MCP client.
        let script = format!(
            "tell application \"System Events\" to activate\n\
             display alert \"mcp-jail: new MCP server\" message \"{message}\" \
             buttons {{\"Deny\", \"Approve\"}} default button \"Deny\" cancel button \"Deny\" \
             as critical giving up after {TIMEOUT_SECS}"
        );

        // Re-enter user's Aqua GUI session via `launchctl asuser` so the
        // modal actually renders when spawned from an MCP host subprocess.
        let uid = format!("{}", unsafe { libc::getuid() });
        let Ok(out) = Command::new("launchctl")
            .args(["asuser", &uid, "/usr/bin/osascript", "-e", &script])
            .output()
        else {
            return Decision::NoGui;
        };
        let stdout = String::from_utf8_lossy(&out.stdout);
        let stderr = String::from_utf8_lossy(&out.stderr);

        if stdout.contains("gave up:true") {
            return Decision::Timeout;
        }
        if stdout.contains("button returned:Approve") {
            return Decision::Approve;
        }
        if stdout.contains("button returned:Deny") {
            return Decision::Deny;
        }
        if stderr.contains("User canceled") {
            return Decision::Deny;
        }
        Decision::NoGui
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;

    pub fn ask(cmd_str: &str, source: &str) -> Decision {
        let body = super::body(cmd_str, source);
        for tool in ["zenity", "kdialog"] {
            if let Some(d) = try_tool(tool, &body) {
                return d;
            }
        }
        Decision::NoGui
    }

    fn try_tool(name: &str, body: &str) -> Option<Decision> {
        let st = match name {
            "zenity" => Command::new("zenity")
                .args([
                    "--question",
                    "--title=mcp-jail",
                    "--ok-label=Approve",
                    "--cancel-label=Deny",
                    "--default-cancel",
                    &format!("--timeout={TIMEOUT_SECS}"),
                    &format!("--text={body}"),
                ])
                .status(),
            "kdialog" => Command::new("kdialog")
                .args([
                    "--title",
                    "mcp-jail",
                    "--yesno",
                    body,
                    "--yes-label",
                    "Approve",
                    "--no-label",
                    "Deny",
                ])
                .status(),
            _ => return None,
        };
        let st = st.ok()?;
        Some(match st.code() {
            Some(0) => Decision::Approve,
            Some(5) => Decision::Timeout,
            _ => Decision::Deny,
        })
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;

    pub fn ask(cmd_str: &str, source: &str) -> Decision {
        let body = super::body(cmd_str, source).replace('"', "`\"").replace('`', "``");
        let ps = format!(
            r#"Add-Type -AssemblyName System.Windows.Forms | Out-Null
$r = [System.Windows.Forms.MessageBox]::Show("{body}","mcp-jail","YesNo","Warning","Button2")
if ($r -eq [System.Windows.Forms.DialogResult]::Yes) {{ exit 0 }} else {{ exit 1 }}"#,
        );
        let Ok(st) = Command::new("powershell")
            .args(["-NoProfile", "-NonInteractive", "-Command", &ps])
            .status()
        else {
            return Decision::NoGui;
        };
        match st.code() {
            Some(0) => Decision::Approve,
            _ => Decision::Deny,
        }
    }
}
