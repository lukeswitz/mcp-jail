//! Platform-native integrity watchdog. Runs `mcp-jail doctor --notify`
//! on a timer and on filesystem events against the binary itself. Shell
//! wrapper fires a direct platform notification if the binary is gone.

use anyhow::{anyhow, bail, Context, Result};
use std::path::PathBuf;

use crate::cli::SentryAction;

const SERVICE_LABEL: &str = "com.lukeswitz.mcp-jail.sentry";
const CHECK_INTERVAL_SECS: u32 = 300;

pub fn dispatch(action: SentryAction) -> Result<()> {
    match action {
        SentryAction::Install => install(),
        SentryAction::Uninstall => uninstall(),
        SentryAction::Status => status(),
    }
}

fn current_exe() -> Result<PathBuf> {
    let p = std::env::current_exe().context("resolve current_exe")?;
    Ok(std::fs::canonicalize(&p).unwrap_or(p))
}

#[cfg(target_os = "macos")]
fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;")
}

#[cfg(target_os = "macos")]
fn install() -> Result<()> {
    mac::install()
}
#[cfg(all(unix, not(target_os = "macos")))]
fn install() -> Result<()> {
    linux::install()
}
#[cfg(target_os = "windows")]
fn install() -> Result<()> {
    windows::install()
}
#[cfg(not(any(target_os = "macos", target_os = "windows", all(unix, not(target_os = "macos")))))]
fn install() -> Result<()> {
    bail!("mcp-jail sentry: unsupported platform")
}

#[cfg(target_os = "macos")]
fn uninstall() -> Result<()> {
    mac::uninstall()
}
#[cfg(all(unix, not(target_os = "macos")))]
fn uninstall() -> Result<()> {
    linux::uninstall()
}
#[cfg(target_os = "windows")]
fn uninstall() -> Result<()> {
    windows::uninstall()
}
#[cfg(not(any(target_os = "macos", target_os = "windows", all(unix, not(target_os = "macos")))))]
fn uninstall() -> Result<()> {
    bail!("mcp-jail sentry: unsupported platform")
}

#[cfg(target_os = "macos")]
fn status() -> Result<()> {
    mac::status()
}
#[cfg(all(unix, not(target_os = "macos")))]
fn status() -> Result<()> {
    linux::status()
}
#[cfg(target_os = "windows")]
fn status() -> Result<()> {
    windows::status()
}
#[cfg(not(any(target_os = "macos", target_os = "windows", all(unix, not(target_os = "macos")))))]
fn status() -> Result<()> {
    println!("sentry: not supported on this platform");
    Ok(())
}

#[cfg(target_os = "macos")]
mod mac {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn home() -> Result<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| anyhow!("HOME unset"))
    }

    fn plist_path() -> Result<PathBuf> {
        Ok(home()?.join("Library/LaunchAgents").join(format!("{SERVICE_LABEL}.plist")))
    }

    fn log_dir() -> Result<PathBuf> {
        Ok(home()?.join(".mcp-jail").join("sentry"))
    }

    fn build_plist(jail_path: &str, log_dir_str: &str) -> String {
        let script = format!(
            "JAIL='{jail}'; \
             if [ ! -x \"$JAIL\" ]; then \
               /usr/bin/osascript -e 'display notification \"mcp-jail binary missing at {jail}. Recover: mcp-jail upgrade\" with title \"mcp-jail INTEGRITY FAILURE\" sound name \"Funk\"' >/dev/null 2>&1; \
               exit 1; \
             fi; \
             \"$JAIL\" doctor --notify --soft-fail >/dev/null 2>&1",
            jail = jail_path.replace('\'', "'\\''"),
        );
        format!(
            r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/bash</string>
    <string>-c</string>
    <string>{script}</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>StartInterval</key><integer>{interval}</integer>
  <key>WatchPaths</key>
  <array>
    <string>{jail}</string>
  </array>
  <key>StandardOutPath</key><string>{log_dir}/stdout.log</string>
  <key>StandardErrorPath</key><string>{log_dir}/stderr.log</string>
  <key>EnvironmentVariables</key>
  <dict>
    <key>PATH</key><string>/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin</string>
  </dict>
</dict>
</plist>
"#,
            label = xml_escape(SERVICE_LABEL),
            script = xml_escape(&script),
            interval = CHECK_INTERVAL_SECS,
            jail = xml_escape(jail_path),
            log_dir = xml_escape(log_dir_str),
        )
    }

    pub fn install() -> Result<()> {
        let exe = super::current_exe()?;
        let exe_str = exe.to_str().ok_or_else(|| anyhow!("non-UTF8 mcp-jail path"))?;
        let logs = log_dir()?;
        fs::create_dir_all(&logs).with_context(|| format!("create {}", logs.display()))?;
        let logs_str = logs.to_str().ok_or_else(|| anyhow!("non-UTF8 log dir"))?;

        let plist = build_plist(exe_str, logs_str);
        let target = plist_path()?;
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        fs::write(&target, plist).with_context(|| format!("write {}", target.display()))?;
        let target_str = target.to_str().ok_or_else(|| anyhow!("non-UTF8 plist path"))?;

        let _ = Command::new("launchctl").args(["unload", target_str]).status();
        let st = Command::new("launchctl")
            .args(["load", "-w", target_str])
            .status()
            .context("launchctl load")?;
        if !st.success() {
            bail!("launchctl load failed for {}", target.display());
        }

        println!("sentry installed at {}", target.display());
        println!("  watches: {exe_str}");
        println!("  interval: every {CHECK_INTERVAL_SECS}s + instant on file events");
        println!("  logs: {}", logs.display());
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let target = plist_path()?;
        if !target.exists() {
            println!("sentry not installed");
            return Ok(());
        }
        if let Some(s) = target.to_str() {
            let _ = Command::new("launchctl").args(["unload", s]).status();
        }
        fs::remove_file(&target).with_context(|| format!("remove {}", target.display()))?;
        println!("sentry uninstalled");
        Ok(())
    }

    pub fn status() -> Result<()> {
        let target = plist_path()?;
        if !target.exists() {
            println!("sentry: NOT installed (run `mcp-jail sentry install`)");
            return Ok(());
        }
        let out = Command::new("launchctl")
            .args(["list", SERVICE_LABEL])
            .output()
            .context("launchctl list")?;
        if out.status.success() {
            println!("sentry: installed and loaded");
            println!("  plist: {}", target.display());
        } else {
            println!(
                "sentry: plist present but NOT loaded ({}) — re-run `mcp-jail sentry install`",
                target.display()
            );
        }
        Ok(())
    }
}

#[cfg(all(unix, not(target_os = "macos")))]
mod linux {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    fn home() -> Result<PathBuf> {
        std::env::var_os("HOME").map(PathBuf::from).ok_or_else(|| anyhow!("HOME unset"))
    }

    fn unit_dir() -> Result<PathBuf> {
        Ok(home()?.join(".config/systemd/user"))
    }
    fn log_dir() -> Result<PathBuf> {
        Ok(home()?.join(".mcp-jail").join("sentry"))
    }
    fn service_name() -> String { format!("{SERVICE_LABEL}.service") }
    fn timer_name() -> String { format!("{SERVICE_LABEL}.timer") }
    fn path_name() -> String { format!("{SERVICE_LABEL}.path") }

    fn build_service(jail_path: &str, log_dir_str: &str) -> String {
        let script = format!(
            "JAIL='{jail}'; \
             if [ ! -x \"$JAIL\" ]; then \
               notify-send -a mcp-jail -u critical \"mcp-jail INTEGRITY FAILURE\" \"Binary missing at {jail}. Recover: mcp-jail upgrade\" || true; \
               exit 1; \
             fi; \
             \"$JAIL\" doctor --notify --soft-fail >/dev/null 2>&1",
            jail = jail_path.replace('\'', "'\\''"),
        );
        format!(
            "[Unit]\nDescription=mcp-jail integrity watchdog\n\n\
             [Service]\nType=oneshot\nExecStart=/bin/bash -c '{script}'\n\
             StandardOutput=append:{log}/stdout.log\nStandardError=append:{log}/stderr.log\n",
            script = script.replace('\'', "'\\''"),
            log = log_dir_str,
        )
    }

    fn build_timer() -> String {
        format!(
            "[Unit]\nDescription=mcp-jail sentry periodic check\n\n\
             [Timer]\nOnBootSec=60\nOnUnitActiveSec={interval}\nUnit={svc}\n\n\
             [Install]\nWantedBy=timers.target\n",
            interval = CHECK_INTERVAL_SECS,
            svc = service_name(),
        )
    }

    fn build_path(jail_path: &str) -> String {
        format!(
            "[Unit]\nDescription=mcp-jail sentry file-event trigger\n\n\
             [Path]\nPathModified={jail}\nUnit={svc}\n\n\
             [Install]\nWantedBy=paths.target\n",
            jail = jail_path,
            svc = service_name(),
        )
    }

    pub fn install() -> Result<()> {
        let exe = super::current_exe()?;
        let exe_str = exe.to_str().ok_or_else(|| anyhow!("non-UTF8 mcp-jail path"))?;
        let logs = log_dir()?;
        fs::create_dir_all(&logs).with_context(|| format!("create {}", logs.display()))?;
        let logs_str = logs.to_str().ok_or_else(|| anyhow!("non-UTF8 log dir"))?;
        let d = unit_dir()?;
        fs::create_dir_all(&d).with_context(|| format!("create {}", d.display()))?;

        fs::write(d.join(service_name()), build_service(exe_str, logs_str))?;
        fs::write(d.join(timer_name()), build_timer())?;
        fs::write(d.join(path_name()), build_path(exe_str))?;

        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        for unit in [timer_name(), path_name()] {
            let st = Command::new("systemctl")
                .args(["--user", "enable", "--now", &unit])
                .status()
                .context("systemctl enable --now")?;
            if !st.success() {
                bail!("systemctl enable --now {unit} failed");
            }
        }

        println!("sentry installed ({})", d.display());
        println!("  watches: {exe_str}");
        println!("  interval: every {CHECK_INTERVAL_SECS}s + instant on file events");
        println!("  logs: {}", logs.display());
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let d = unit_dir()?;
        if !d.join(service_name()).exists() && !d.join(timer_name()).exists() {
            println!("sentry not installed");
            return Ok(());
        }
        for unit in [timer_name(), path_name()] {
            let _ = Command::new("systemctl")
                .args(["--user", "disable", "--now", &unit])
                .status();
        }
        for name in [service_name(), timer_name(), path_name()] {
            let p = d.join(&name);
            if p.exists() {
                let _ = fs::remove_file(&p);
            }
        }
        let _ = Command::new("systemctl").args(["--user", "daemon-reload"]).status();
        println!("sentry uninstalled");
        Ok(())
    }

    pub fn status() -> Result<()> {
        let d = unit_dir()?;
        if !d.join(service_name()).exists() {
            println!("sentry: NOT installed (run `mcp-jail sentry install`)");
            return Ok(());
        }
        let out = Command::new("systemctl")
            .args(["--user", "is-active", &timer_name()])
            .output()
            .context("systemctl is-active")?;
        let state = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("sentry: timer is {state} ({})", d.display());
        Ok(())
    }
}

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::process::Command;

    const TASK_PERIODIC: &str = "mcp-jail-sentry";
    const TASK_WATCHER: &str = "mcp-jail-sentry-watcher";

    fn script_dir() -> Result<PathBuf> {
        let base = std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .ok_or_else(|| anyhow!("APPDATA unset"))?;
        Ok(base.join("mcp-jail").join("sentry"))
    }

    fn ps_escape(s: &str) -> String {
        s.replace('`', "``").replace('"', "`\"").replace('$', "`$")
    }

    fn check_script(jail_path: &str) -> String {
        // BurntToast falls back to balloon-tip if unavailable, keeping
        // the integrity alert visible even on minimal Windows installs.
        format!(
            r#"$ErrorActionPreference = 'Continue'
$jail = "{jail}"
function Show-Alert($title, $body) {{
    try {{
        if (Get-Module -ListAvailable -Name BurntToast) {{
            Import-Module BurntToast -ErrorAction Stop
            New-BurntToastNotification -Text $title,$body | Out-Null
            return
        }}
    }} catch {{}}
    try {{
        Add-Type -AssemblyName System.Windows.Forms -ErrorAction Stop
        $n = New-Object System.Windows.Forms.NotifyIcon
        $n.Icon = [System.Drawing.SystemIcons]::Warning
        $n.BalloonTipTitle = $title
        $n.BalloonTipText = $body
        $n.Visible = $true
        $n.ShowBalloonTip(5000)
        Start-Sleep -Seconds 6
        $n.Dispose()
    }} catch {{
        Write-EventLog -LogName Application -Source 'mcp-jail' -EntryType Error -EventId 1001 -Message "$title`n$body" -ErrorAction SilentlyContinue
    }}
}}
if (-not (Test-Path -LiteralPath $jail)) {{
    Show-Alert 'mcp-jail INTEGRITY FAILURE' "Binary missing at $jail. Recover: mcp-jail upgrade"
    exit 1
}}
& $jail doctor --notify --soft-fail *> $null
"#,
            jail = ps_escape(jail_path),
        )
    }

    fn watcher_script(jail_path: &str, check_path: &str) -> String {
        let dir = std::path::Path::new(jail_path)
            .parent()
            .map(|p| p.to_string_lossy().into_owned())
            .unwrap_or_default();
        let file = std::path::Path::new(jail_path)
            .file_name()
            .map(|f| f.to_string_lossy().into_owned())
            .unwrap_or_default();
        format!(
            r#"$ErrorActionPreference = 'Continue'
$watcher = New-Object System.IO.FileSystemWatcher
$watcher.Path = "{dir}"
$watcher.Filter = "{file}"
$watcher.IncludeSubdirectories = $false
$watcher.EnableRaisingEvents = $true
$action = {{ & powershell -ExecutionPolicy Bypass -File "{check}" | Out-Null }}
Register-ObjectEvent $watcher Changed -Action $action | Out-Null
Register-ObjectEvent $watcher Deleted -Action $action | Out-Null
Register-ObjectEvent $watcher Renamed -Action $action | Out-Null
while ($true) {{ Start-Sleep -Seconds 3600 }}
"#,
            dir = ps_escape(&dir),
            file = ps_escape(&file),
            check = ps_escape(check_path),
        )
    }

    fn schtasks(args: &[&str]) -> Result<()> {
        let st = Command::new("schtasks").args(args).status().context("schtasks")?;
        if !st.success() {
            bail!("schtasks {:?} failed", args);
        }
        Ok(())
    }

    fn task_exists(name: &str) -> bool {
        Command::new("schtasks")
            .args(["/Query", "/TN", name])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    pub fn install() -> Result<()> {
        let exe = super::current_exe()?;
        let exe_str = exe.to_str().ok_or_else(|| anyhow!("non-UTF8 mcp-jail path"))?;
        let d = script_dir()?;
        fs::create_dir_all(&d).with_context(|| format!("create {}", d.display()))?;
        let check_ps1 = d.join("check.ps1");
        let watcher_ps1 = d.join("watcher.ps1");
        fs::write(&check_ps1, check_script(exe_str))?;
        fs::write(&watcher_ps1, watcher_script(exe_str, check_ps1.to_str().unwrap_or_default()))?;

        let check_str = check_ps1.to_str().ok_or_else(|| anyhow!("non-UTF8 path"))?;
        let watcher_str = watcher_ps1.to_str().ok_or_else(|| anyhow!("non-UTF8 path"))?;
        let tr_check = format!("powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{check_str}\"");
        let tr_watcher =
            format!("powershell -ExecutionPolicy Bypass -WindowStyle Hidden -File \"{watcher_str}\"");

        if task_exists(TASK_PERIODIC) {
            let _ = schtasks(&["/Delete", "/TN", TASK_PERIODIC, "/F"]);
        }
        if task_exists(TASK_WATCHER) {
            let _ = schtasks(&["/Delete", "/TN", TASK_WATCHER, "/F"]);
        }

        schtasks(&[
            "/Create", "/TN", TASK_PERIODIC, "/SC", "MINUTE", "/MO", "5", "/TR", &tr_check, "/F",
        ])?;
        schtasks(&[
            "/Create", "/TN", TASK_WATCHER, "/SC", "ONLOGON", "/TR", &tr_watcher, "/F",
        ])?;
        let _ = schtasks(&["/Run", "/TN", TASK_WATCHER]);

        println!("sentry installed");
        println!("  periodic task: {TASK_PERIODIC} (every 5 min)");
        println!("  watcher task:  {TASK_WATCHER} (on-logon, FileSystemWatcher)");
        println!("  scripts: {}", d.display());
        Ok(())
    }

    pub fn uninstall() -> Result<()> {
        let mut removed = 0usize;
        for t in [TASK_PERIODIC, TASK_WATCHER] {
            if task_exists(t) && schtasks(&["/Delete", "/TN", t, "/F"]).is_ok() {
                removed += 1;
            }
        }
        if removed == 0 {
            println!("sentry not installed");
        } else {
            println!("sentry uninstalled");
        }
        Ok(())
    }

    pub fn status() -> Result<()> {
        let p = task_exists(TASK_PERIODIC);
        let w = task_exists(TASK_WATCHER);
        match (p, w) {
            (true, true) => println!("sentry: both tasks installed"),
            (true, false) => println!("sentry: periodic installed, watcher MISSING — re-run install"),
            (false, true) => println!("sentry: watcher installed, periodic MISSING — re-run install"),
            (false, false) => println!("sentry: NOT installed (run `mcp-jail sentry install`)"),
        }
        Ok(())
    }
}
