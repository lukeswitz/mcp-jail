
use crate::store::{AllowEntry, Sandbox};
#[allow(unused_imports)]
use anyhow::{anyhow, Result};
use std::path::{Path, PathBuf};

pub fn profile_dir(root: &Path) -> PathBuf {
    root.join("sandbox")
}

pub fn write_profile(root: &Path, entry: &AllowEntry) -> Result<PathBuf> {
    std::fs::create_dir_all(profile_dir(root))?;
    let path = profile_dir(root).join(format!("{}.sb", entry.id));
    if cfg!(target_os = "macos") {
        std::fs::write(&path, macos_profile(&entry.sandbox))?;
    } else if cfg!(target_os = "linux") {
        std::fs::write(&path, "# bwrap args live in allow entry\n")?;
    }
    Ok(path)
}

#[cfg(target_os = "macos")]
pub fn wrap_argv(profile: &Path, command: &str, argv: &[String]) -> Result<Vec<String>> {
    let mut out = vec![
        "/usr/bin/sandbox-exec".to_owned(),
        "-f".to_owned(),
        profile.display().to_string(),
        command.to_owned(),
    ];
    out.extend(argv.iter().skip(1).cloned());
    Ok(out)
}

#[cfg(target_os = "linux")]
pub fn wrap_argv(_profile: &Path, command: &str, argv: &[String]) -> Result<Vec<String>> {
    let mut out = vec![
        "bwrap".to_owned(),
        "--unshare-all".to_owned(),
        "--die-with-parent".to_owned(),
        "--ro-bind".to_owned(),
        "/usr".to_owned(),
        "/usr".to_owned(),
        "--ro-bind".to_owned(),
        "/lib".to_owned(),
        "/lib".to_owned(),
        "--ro-bind".to_owned(),
        "/lib64".to_owned(),
        "/lib64".to_owned(),
        "--ro-bind".to_owned(),
        "/etc".to_owned(),
        "/etc".to_owned(),
        "--proc".to_owned(),
        "/proc".to_owned(),
        "--dev".to_owned(),
        "/dev".to_owned(),
        "--".to_owned(),
        command.to_owned(),
    ];
    out.extend(argv.iter().skip(1).cloned());
    Ok(out)
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
pub fn wrap_argv(_profile: &Path, command: &str, argv: &[String]) -> Result<Vec<String>> {
    let mut out = vec![command.to_owned()];
    out.extend(argv.iter().skip(1).cloned());
    Ok(out)
}

#[must_use]
pub fn macos_profile(scope: &Sandbox) -> String {
    let mut s = String::new();
    s.push_str("(version 1)\n(allow default)\n");

    s.push_str("(deny file-write*)\n");
    s.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
    s.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
    s.push_str("(allow file-write* (subpath \"/dev\"))\n");
    s.push_str("(allow file-write-data file-read-data (literal \"/dev/null\") (literal \"/dev/zero\") (literal \"/dev/random\") (literal \"/dev/urandom\") (literal \"/dev/tty\") (literal \"/dev/dtracehelper\"))\n");

    for p in &scope.fs_read {
        s.push_str(&format!("(allow file-read* (subpath \"{}\"))\n", escape_sb(p)));
    }
    for p in &scope.fs_write {
        s.push_str(&format!(
            "(allow file-write* (subpath \"{}\"))\n",
            escape_sb(p),
        ));
        s.push_str(&format!(
            "(allow file-read* (subpath \"{}\"))\n",
            escape_sb(p),
        ));
    }

    let home_raw = std::env::var("HOME").unwrap_or_else(|_| "/".to_owned());
    let home = std::fs::canonicalize(&home_raw)
        .map(|p| p.display().to_string())
        .unwrap_or(home_raw);

    s.push_str(&format!(
        "(deny file-write* (subpath \"{}/.mcp-jail\"))\n",
        escape_sb(&home),
    ));
    s.push_str(&format!(
        "(deny file-read* (literal \"{}/.mcp-jail/key.ed25519\"))\n",
        escape_sb(&home),
    ));

    for secret in [
        ".ssh",
        ".aws",
        ".netrc",
        "Library/Keychains",
        "Library/Application Support/1Password",
        "Library/Cookies",
    ] {
        s.push_str(&format!(
            "(deny file-read* (subpath \"{}/{secret}\"))\n",
            escape_sb(&home),
        ));
    }

    for p in &scope.fs_read_secret {
        s.push_str(&format!("(allow file-read* (literal \"{}\"))\n", escape_sb(p)));
        s.push_str(&format!(
            "(allow file-read-metadata (subpath \"{}\"))\n",
            escape_sb(p),
        ));
    }

    s.push_str("(deny network*)\n");
    if !scope.net.is_empty() {
        let only_loopback = scope.net.iter().all(|d| is_loopback(d));
        s.push_str("(allow network-outbound (remote ip \"localhost:*\"))\n");
        s.push_str("(allow network-bind (local ip \"localhost:*\"))\n");
        if !only_loopback {
            s.push_str("(allow network-outbound (remote ip \"*:*\"))\n");
            s.push_str("(allow network-outbound (remote tcp \"*:*\"))\n");
            s.push_str("(allow network-outbound (remote udp \"*:*\"))\n");
        }
    }
    s
}

fn is_loopback(s: &str) -> bool {
    if s == "localhost" {
        return true;
    }
    match s.parse::<std::net::IpAddr>() {
        Ok(addr) => addr.is_loopback(),
        Err(_) => false,
    }
}

fn escape_sb(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

pub fn ensure_helper() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        if !Path::new("/usr/bin/sandbox-exec").exists() {
            return Err(anyhow!("/usr/bin/sandbox-exec missing"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        if which("bwrap").is_none() {
            return Err(anyhow!("bwrap not in PATH; install via `sudo apt install bubblewrap`"));
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn which(bin: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|d| d.join(bin))
            .find(|p| p.is_file())
    })
}
