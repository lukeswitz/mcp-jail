
use anyhow::{anyhow, Context, Result};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::path::PathBuf;

use crate::canonical::home;
use crate::store::{ensure_key, Paths};

const MARKER: &str = "_mcp_jail_original";

/// Signed registry entry: written when `mcp-jail wrap` rewrites a config
/// entry, and consulted (with strict signature verification) when
/// `mcp-jail unwrap` is asked to restore the same entry. Prevents an
/// attacker with write access to the MCP client config from pre-seeding
/// a forged `_mcp_jail_original` object that points at an attacker
/// command — on unwrap we refuse to honor markers without a matching
/// signed registry record.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WrapRecord {
    pub ts: chrono::DateTime<chrono::Utc>,
    pub config_path: String,
    pub entry_key: String,
    pub original_command: String,
    pub original_args: Vec<String>,
    pub signature: String,
}

fn registry_path() -> PathBuf {
    home().join(".mcp-jail").join("wraps.jsonl")
}

fn wrap_record_canonical_bytes(r: &WrapRecord) -> Result<Vec<u8>> {
    let mut clone = r.clone();
    clone.signature.clear();
    let doc = serde_json::json!({
        "ts": clone.ts.to_rfc3339(),
        "config_path": clone.config_path,
        "entry_key": clone.entry_key,
        "original_command": clone.original_command,
        "original_args": clone.original_args,
    });
    let mut bytes = serde_json::to_vec(&doc)?;
    bytes.extend_from_slice(b"wrap-registry-v1");
    Ok(bytes)
}

fn append_wrap_record(
    config_path: &str,
    entry_key: &str,
    original_command: &str,
    original_args: &[String],
) -> Result<()> {
    let paths = Paths::default();
    paths.ensure()?;
    let key = ensure_key(&paths)?;
    let mut rec = WrapRecord {
        ts: chrono::Utc::now(),
        config_path: config_path.to_owned(),
        entry_key: entry_key.to_owned(),
        original_command: original_command.to_owned(),
        original_args: original_args.to_vec(),
        signature: String::new(),
    };
    let msg = wrap_record_canonical_bytes(&rec)?;
    rec.signature = hex::encode(key.sign(&Sha256::digest(&msg)).to_bytes());

    let path = registry_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)?;
    use std::io::Write;
    writeln!(f, "{}", serde_json::to_string(&rec)?)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = f.set_permissions(std::fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

fn load_wrap_records() -> Vec<WrapRecord> {
    let path = registry_path();
    let Ok(s) = std::fs::read_to_string(&path) else {
        return vec![];
    };
    s.lines()
        .filter_map(|l| serde_json::from_str::<WrapRecord>(l).ok())
        .collect()
}

/// Find a signed registry record matching this config/entry whose
/// recorded `original_*` is byte-identical to the marker's payload.
/// Signatures are verified with the mcp-jail pubkey. If either no
/// record exists, or all matching records fail signature verification,
/// returns `None` — the caller MUST refuse to restore.
fn find_verified_record(
    config_path: &str,
    entry_key: &str,
    marker_cmd: &str,
    marker_args: &[String],
) -> Option<WrapRecord> {
    let paths = Paths::default();
    let pubkey_hex = std::fs::read_to_string(&paths.pubkey).ok()?;
    let pubkey_raw = hex::decode(pubkey_hex.trim()).ok()?;
    let pubkey_arr: [u8; 32] = pubkey_raw.as_slice().try_into().ok()?;
    let pubkey = ed25519_dalek::VerifyingKey::from_bytes(&pubkey_arr).ok()?;

    for rec in load_wrap_records().into_iter().rev() {
        if rec.config_path != config_path || rec.entry_key != entry_key {
            continue;
        }
        if rec.original_command != marker_cmd || rec.original_args != marker_args {
            continue;
        }
        let Ok(msg) = wrap_record_canonical_bytes(&rec) else { continue };
        let Ok(sig_raw) = hex::decode(&rec.signature) else { continue };
        let Ok(sig_arr): std::result::Result<[u8; 64], _> = sig_raw.as_slice().try_into() else { continue };
        let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);
        if pubkey.verify(&Sha256::digest(&msg), &sig).is_ok() {
            return Some(rec);
        }
    }
    None
}

/// Verify that a proposed unwrap is backed by a signed registry entry.
/// Public so commands.rs can also call it ahead of time if it wants to.
pub fn unwrap_authorized(
    config_path: &str,
    entry_key: &str,
    marker_cmd: &str,
    marker_args: &[String],
) -> bool {
    find_verified_record(config_path, entry_key, marker_cmd, marker_args).is_some()
}

/// Error surfaced when unwrap refuses to restore a marker that has no
/// matching signed registry entry (forgery suspected).
pub const FORGED_MARKER_MSG: &str =
    "refusing to restore _mcp_jail_original: no matching signed entry in ~/.mcp-jail/wraps.jsonl. \
     Either this config was not wrapped by mcp-jail or the registry was deleted. \
     Re-run `mcp-jail wrap` to re-sign, or delete the marker manually after review.";

fn known_config_paths() -> Vec<PathBuf> {
    let h = home();
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

fn rewrap_entry(
    id: &str,
    entry: &mut Map<String, Value>,
    source_config: &str,
    bin: &str,
    dry_run: bool,
) -> bool {
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
    original.insert("command".into(), Value::String(orig_cmd.clone()));
    original.insert("args".into(), Value::Array(orig_args.clone()));
    entry.insert(MARKER.into(), Value::Object(original));
    entry.insert("command".into(), Value::String(bin.to_owned()));
    entry.insert("args".into(), Value::Array(new_args));

    if !dry_run {
        let args_strs: Vec<String> = orig_args
            .iter()
            .filter_map(|v| v.as_str().map(str::to_owned))
            .collect();
        let _ = append_wrap_record(source_config, id, &orig_cmd, &args_strs);
    }
    true
}

/// Returns `Ok(true)` on successful restore, `Ok(false)` when no marker
/// was present (nothing to do), or `Err(FORGED_MARKER_MSG)` when a
/// marker exists but no matching signed registry record vouches for
/// its payload.
fn unwrap_entry(
    entry: &mut Map<String, Value>,
    config_path: &str,
    entry_key: &str,
) -> Result<bool> {
    let Some(Value::Object(orig)) = entry.get(MARKER).cloned() else {
        return Ok(false);
    };
    let marker_cmd = orig.get("command").and_then(Value::as_str).unwrap_or("");
    let marker_args: Vec<String> = orig
        .get("args")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();

    if !unwrap_authorized(config_path, entry_key, marker_cmd, &marker_args) {
        return Err(anyhow!(FORGED_MARKER_MSG));
    }

    entry.remove(MARKER);
    entry.insert("command".into(), Value::String(marker_cmd.to_owned()));
    entry.insert(
        "args".into(),
        Value::Array(
            marker_args
                .into_iter()
                .map(Value::String)
                .collect(),
        ),
    );
    Ok(true)
}

fn walk_and_apply(
    value: &mut Value,
    source_config: &str,
    bin: &str,
    unwrapping: bool,
    dry_run: bool,
    collect: &mut Vec<WrappedEntry>,
    forgeries: &mut Vec<String>,
) -> usize {
    let mut changes = 0;
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(servers)) = map.get_mut("mcpServers") {
                let ids: Vec<String> = servers.keys().cloned().collect();
                for id in ids {
                    if let Some(Value::Object(entry)) = servers.get_mut(&id) {
                        if unwrapping {
                            match unwrap_entry(entry, source_config, &id) {
                                Ok(true) => changes += 1,
                                Ok(false) => {}
                                Err(e) => {
                                    forgeries.push(format!(
                                        "{source_config}#{id}: {e}"
                                    ));
                                }
                            }
                        } else {
                            let orig_cmd = entry
                                .get("command")
                                .and_then(Value::as_str)
                                .map(str::to_owned);
                            let orig_args: Vec<String> = entry
                                .get("args")
                                .and_then(Value::as_array)
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|v| v.as_str().map(str::to_owned))
                                        .collect()
                                })
                                .unwrap_or_default();
                            if rewrap_entry(&id, entry, source_config, bin, dry_run) {
                                if let Some(cmd) = orig_cmd {
                                    collect.push(WrappedEntry {
                                        id: id.clone(),
                                        command: cmd,
                                        args: orig_args,
                                        source_config: source_config.to_owned(),
                                    });
                                }
                                changes += 1;
                            }
                        }
                    }
                }
            }
            for (_, v) in map.iter_mut() {
                changes += walk_and_apply(
                    v, source_config, bin, unwrapping, dry_run, collect, forgeries,
                );
            }
        }
        Value::Array(arr) => {
            for v in arr {
                changes += walk_and_apply(
                    v, source_config, bin, unwrapping, dry_run, collect, forgeries,
                );
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
    pub wrapped: Vec<WrappedEntry>,
}

#[derive(Clone)]
pub struct WrappedEntry {
    pub id: String,
    pub command: String,
    pub args: Vec<String>,
    pub source_config: String,
}

pub fn scan_and_apply(dry_run: bool, unwrapping: bool) -> Result<Vec<Change>> {
    let (out, forgeries) = scan_and_apply_inner(dry_run, unwrapping)?;
    if !forgeries.is_empty() {
        for f in &forgeries {
            eprintln!("mcp-jail: {f}");
        }
        return Err(anyhow!(
            "{} unverified _mcp_jail_original marker(s) detected — refusing to unwrap. \
             Review the config(s) above and remove the markers manually if safe.",
            forgeries.len()
        ));
    }
    Ok(out)
}

fn scan_and_apply_inner(dry_run: bool, unwrapping: bool) -> Result<(Vec<Change>, Vec<String>)> {
    let bin = current_binary_path();
    let mut out = Vec::new();
    let mut forgeries: Vec<String> = Vec::new();
    for cfg in known_config_paths() {
        if !cfg.is_file() {
            continue;
        }
        let raw = std::fs::read_to_string(&cfg)
            .with_context(|| format!("read {}", cfg.display()))?;
        let mut doc: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let source_config = cfg.display().to_string();
        let mut wrapped = Vec::new();
        let touched = walk_and_apply(
            &mut doc,
            &source_config,
            &bin,
            unwrapping,
            dry_run,
            &mut wrapped,
            &mut forgeries,
        );
        if touched == 0 {
            continue;
        }
        if !dry_run {
            let bak = backup_path(&cfg);
            std::fs::copy(&cfg, &bak)
                .with_context(|| format!("backup {}", cfg.display()))?;
            let serialized = serde_json::to_string_pretty(&doc)?;
            let tmp = cfg.with_extension("json.mcp-jail-tmp");
            std::fs::write(&tmp, &serialized)
                .with_context(|| format!("write {}", tmp.display()))?;
            std::fs::rename(&tmp, &cfg)
                .with_context(|| format!("atomic rename onto {}", cfg.display()))?;
        }
        out.push(Change { path: cfg, touched, wrapped });
    }
    Ok((out, forgeries))
}

/// Scan known config files for entries that are ALREADY wrapped and return
/// the `WrappedEntry` representation read back from each `_mcp_jail_original`
/// marker. Used to reconcile the allow-list against the on-disk wrap state.
pub fn scan_already_wrapped() -> Result<Vec<WrappedEntry>> {
    let mut out = Vec::new();
    for cfg in known_config_paths() {
        if !cfg.is_file() {
            continue;
        }
        let raw = match std::fs::read_to_string(&cfg) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let doc: Value = match serde_json::from_str(&raw) {
            Ok(v) => v,
            Err(_) => continue,
        };
        collect_wrapped(&doc, &cfg.display().to_string(), &mut out);
    }
    Ok(out)
}

fn collect_wrapped(value: &Value, source_config: &str, out: &mut Vec<WrappedEntry>) {
    match value {
        Value::Object(map) => {
            if let Some(Value::Object(servers)) = map.get("mcpServers") {
                for (id, entry) in servers {
                    let Value::Object(entry) = entry else { continue };
                    let Some(Value::Object(orig)) = entry.get(MARKER) else { continue };
                    let Some(cmd) = orig.get("command").and_then(Value::as_str) else { continue };
                    let args: Vec<String> = orig
                        .get("args")
                        .and_then(Value::as_array)
                        .map(|a| {
                            a.iter()
                                .filter_map(|v| v.as_str().map(str::to_owned))
                                .collect()
                        })
                        .unwrap_or_default();
                    out.push(WrappedEntry {
                        id: id.clone(),
                        command: cmd.to_owned(),
                        args,
                        source_config: source_config.to_owned(),
                    });
                }
            }
            for (_, v) in map {
                collect_wrapped(v, source_config, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_wrapped(v, source_config, out);
            }
        }
        _ => {}
    }
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
