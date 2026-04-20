//! Auto-wrap known MCP client configs so every `mcpServers.*` entry routes
//! through `mcp-jail exec --id X --source-config P -- <orig argv>`.
//!
//! Walks a fixed list of well-known config paths, parses each as JSON,
//! recursively finds every `mcpServers` object, and rewraps its entries.
//! Preserves the original under `_mcp_jail_original`. Backs up each file
//! it writes to with a timestamped `.bak-<unix>` sibling.

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use std::path::PathBuf;

use crate::canonical::home;

const MARKER: &str = "_mcp_jail_original";

fn known_config_paths() -> Vec<PathBuf> {
    let h = home();
    // `mut` is used by cfg-gated push() blocks on macOS/Windows below.
    #[allow(unused_mut)]
    let mut out = vec![
        h.join(".claude.json"),
        h.join(".cursor").join("mcp.json"),
        h.join(".codeium").join("windsurf").join("mcp_config.json"),
        h.join(".config").join("gemini-cli").join("settings.json"),
        h.join(".config").join("github-copilot").join("mcp.json"),
    ];
    #[cfg(target_os = "macos")]
    out.push(
        h.join("Library")
            .join("Application Support")
            .join("Claude")
            .join("claude_desktop_config.json"),
    );
    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        out.push(
            PathBuf::from(appdata)
                .join("Claude")
                .join("claude_desktop_config.json"),
        );
    }
    out
}

fn current_binary_path() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "mcp-jail".to_owned())
}

fn rewrap_entry(id: &str, entry: &mut Map<String, Value>, source_config: &str, bin: &str) -> bool {
    // Idempotency: presence of the MARKER key is the only reliable signal
    // that this entry is already wrapped. Binary-path comparison breaks
    // when `mcp-jail` is moved or reinstalled to a different prefix.
    if entry.contains_key(MARKER) {
        return false;
    }
    let orig_cmd = match entry.get("command").and_then(Value::as_str) {
        Some(s) => s.to_owned(),
        None => return false,
    };
    let orig_args: Vec<Value> = entry
        .get("args")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    let mut new_args: Vec<Value> = vec![
        Value::String("exec".into()),
        Value::String("--id".into()),
        Value::String(id.to_owned()),
        Value::String("--source-config".into()),
        Value::String(source_config.to_owned()),
        Value::String("--".into()),
        Value::String(orig_cmd.clone()),
    ];
    new_args.extend(orig_args.clone());

    let mut original = Map::new();
    original.insert("command".into(), Value::String(orig_cmd));
    original.insert("args".into(), Value::Array(orig_args));
    entry.insert(MARKER.into(), Value::Object(original));
    entry.insert("command".into(), Value::String(bin.to_owned()));
    entry.insert("args".into(), Value::Array(new_args));
    true
}

fn unwrap_entry(entry: &mut Map<String, Value>) -> bool {
    let Some(Value::Object(orig)) = entry.remove(MARKER) else {
        return false;
    };
    if let Some(cmd) = orig.get("command").and_then(Value::as_str) {
        entry.insert("command".into(), Value::String(cmd.to_owned()));
    }
    if let Some(args) = orig.get("args") {
        entry.insert("args".into(), args.clone());
    } else {
        entry.remove("args");
    }
    true
}

fn walk_and_apply(
    value: &mut Value,
    source_config: &str,
    bin: &str,
    unwrapping: bool,
) -> usize {
    let mut changes = 0;
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(servers)) = map.get_mut("mcpServers") {
                let ids: Vec<String> = servers.keys().cloned().collect();
                for id in ids {
                    if let Some(Value::Object(entry)) = servers.get_mut(&id) {
                        let applied = if unwrapping {
                            unwrap_entry(entry)
                        } else {
                            rewrap_entry(&id, entry, source_config, bin)
                        };
                        if applied {
                            changes += 1;
                        }
                    }
                }
            }
            for (_, v) in map.iter_mut() {
                changes += walk_and_apply(v, source_config, bin, unwrapping);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                changes += walk_and_apply(v, source_config, bin, unwrapping);
            }
        }
        _ => {}
    }
    changes
}

fn backup_path(path: &std::path::Path) -> PathBuf {
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let fname = format!(
        "{}.bak-{ts}",
        path.file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("config.json")
    );
    path.with_file_name(fname)
}

pub struct Change {
    pub path: PathBuf,
    pub touched: usize,
}

pub fn scan_and_apply(dry_run: bool, unwrapping: bool) -> Result<Vec<Change>> {
    let bin = current_binary_path();
    let mut out = Vec::new();
    for cfg in known_config_paths() {
        if !cfg.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&cfg)
            .with_context(|| format!("read {}", cfg.display()))?;
        let mut doc: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => continue, // not our JSON
        };
        let source_config = cfg.display().to_string();
        let touched = walk_and_apply(&mut doc, &source_config, &bin, unwrapping);
        if touched == 0 {
            continue;
        }
        if !dry_run {
            let bak = backup_path(&cfg);
            std::fs::copy(&cfg, &bak)
                .with_context(|| format!("backup {}", cfg.display()))?;
            let serialized = serde_json::to_string_pretty(&doc)?;
            std::fs::write(&cfg, serialized)
                .with_context(|| format!("write {}", cfg.display()))?;
        }
        out.push(Change { path: cfg, touched });
    }
    Ok(out)
}

pub fn prompt_yes(message: &str) -> bool {
    use std::io::{BufRead, Write};
    print!("{message} [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return false;
    }
    matches!(line.trim(), "y" | "Y" | "yes" | "YES")
}
