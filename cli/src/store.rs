
use crate::canonical::{home, SpawnRequest};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey, SIGNATURE_LENGTH};
use fs2::FileExt;
use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AllowList {
    #[serde(default)]
    pub entries: Vec<AllowEntry>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AllowEntry {
    pub id: String,
    pub fingerprint: String,
    pub argv: Vec<String>,
    pub command: String,
    pub cwd: String,
    #[serde(default)]
    pub env_subset: Vec<String>,
    #[serde(default)]
    pub dangerous: bool,
    #[serde(default)]
    pub source_config: Option<SourceConfig>,
    #[serde(default)]
    pub sandbox: Sandbox,
    /// Content-hash bindings for argv[1..] elements that resolved to a
    /// regular file at approve time. Refuses exec if any file's hash no
    /// longer matches — defeats TOCTOU on script paths like
    /// `python3 /opt/server.py`.
    #[serde(default)]
    pub argv_file_hashes: Vec<ArgvFileHash>,
    pub signed_at: DateTime<Utc>,
    pub signature: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ArgvFileHash {
    pub index: usize,
    pub sha256: String,
    pub size: u64,
    pub mtime_ns: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SourceConfig {
    pub path: String,
    pub hash: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct Sandbox {
    #[serde(default)]
    pub net: Vec<String>,
    #[serde(default)]
    pub fs_read: Vec<String>,
    #[serde(default)]
    pub fs_write: Vec<String>,
    #[serde(default)]
    pub fs_read_secret: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PendingEntry {
    /// First time this fingerprint was seen.
    pub ts: DateTime<Utc>,
    pub fingerprint: String,
    pub request: SpawnRequest,
    pub reason: String,
    /// Most recent time this fingerprint was blocked. Optional for
    /// backward compatibility with pre-0.x records that lacked it.
    #[serde(default)]
    pub last_seen: Option<DateTime<Utc>>,
    /// How many blocked attempts share this fingerprint. Optional for
    /// backward compatibility.
    #[serde(default)]
    pub hit_count: Option<u32>,
}

/// Pending entries older than this are silently pruned on every `list`
/// / `exec` call. Keeps the queue from ballooning under sweep tests or
/// an over-eager client that keeps retrying a blocked launch.
pub const PENDING_MAX_AGE_DAYS: i64 = 7;

/// Hard cap on the pending queue. An adversarial MCP client could spam
/// distinct fingerprints to push legitimate entries out or balloon disk
/// usage. When the cap is hit, the oldest entries (by `last_seen` or
/// `ts`) are evicted to make room.
pub const PENDING_MAX_ENTRIES: usize = 10_000;

pub struct Paths {
    pub root: PathBuf,
    pub allow: PathBuf,
    pub pending: PathBuf,
    pub audit: PathBuf,
    pub key: PathBuf,
    pub pubkey: PathBuf,
}

impl Paths {
    #[must_use]
    pub fn default() -> Self {
        let root = home().join(".mcp-jail");
        Self {
            allow: root.join("allow.toml"),
            pending: root.join("pending.jsonl"),
            audit: root.join("audit.jsonl"),
            key: root.join("key.ed25519"),
            pubkey: root.join("key.ed25519.pub"),
            root,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        std::fs::create_dir_all(&self.root)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(0o700);
            std::fs::set_permissions(&self.root, perms)?;
        }
        Ok(())
    }
}

pub fn load_allow(paths: &Paths) -> Result<AllowList> {
    if !paths.allow.exists() {
        return Ok(AllowList::default());
    }
    let f = File::open(&paths.allow).context("open allow.toml")?;
    f.lock_shared().ok();
    let mut s = String::new();
    (&f).read_to_string(&mut s)?;
    f.unlock().ok();
    Ok(toml::from_str(&s)?)
}

pub fn save_allow(paths: &Paths, allow: &AllowList) -> Result<()> {
    let s = toml::to_string_pretty(allow)?;
    let tmp = paths.allow.with_extension("toml.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    f.lock_exclusive()?;
    f.write_all(s.as_bytes())?;
    f.sync_all()?;
    f.unlock().ok();
    std::fs::rename(&tmp, &paths.allow)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&paths.allow, perms)?;
    }
    Ok(())
}

/// Upsert a pending entry: if an entry with the same fingerprint already
/// exists, bump its `last_seen` + `hit_count`; otherwise append. Always
/// writes the file back with mode 0600 so leaked env-var redaction is
/// backed by strict filesystem permissions.
///
/// Returns `true` when the fingerprint was new to the queue. Callers use
/// that signal to fire a desktop notification only the first time, so
/// retries from a misbehaving MCP client don't spam the user.
pub fn upsert_pending(paths: &Paths, mut entry: PendingEntry) -> Result<bool> {
    let mut all = load_pending(paths).unwrap_or_default();
    let now = entry.ts;
    if let Some(existing) = all.iter_mut().find(|p| p.fingerprint == entry.fingerprint) {
        existing.last_seen = Some(now);
        existing.hit_count = Some(existing.hit_count.unwrap_or(1).saturating_add(1));
        existing.reason = entry.reason;
        save_pending(paths, &all)?;
        Ok(false)
    } else {
        entry.last_seen = Some(now);
        entry.hit_count = Some(1);
        all.push(entry);
        // Enforce hard cap. Evict oldest-by-last_seen until under cap.
        // Cheap because we only re-sort when over cap.
        if all.len() > PENDING_MAX_ENTRIES {
            all.sort_by(|a, b| {
                let a_ts = a.last_seen.unwrap_or(a.ts);
                let b_ts = b.last_seen.unwrap_or(b.ts);
                b_ts.cmp(&a_ts) // newest first
            });
            all.truncate(PENDING_MAX_ENTRIES);
        }
        save_pending(paths, &all)?;
        Ok(true)
    }
}

pub fn load_pending(paths: &Paths) -> Result<Vec<PendingEntry>> {
    if !paths.pending.exists() {
        return Ok(vec![]);
    }
    let s = std::fs::read_to_string(&paths.pending)?;
    Ok(s.lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect())
}

pub fn save_pending(paths: &Paths, entries: &[PendingEntry]) -> Result<()> {
    let tmp = paths.pending.with_extension("jsonl.tmp");
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&tmp)?;
    f.lock_exclusive()?;
    for e in entries {
        writeln!(f, "{}", serde_json::to_string(e)?)?;
    }
    f.sync_all()?;
    f.unlock().ok();
    std::fs::rename(&tmp, &paths.pending)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // 0600: pending is write-only state; even with env redaction we
        // don't want argv/cwd readable by other users on shared hosts.
        let perms = std::fs::Permissions::from_mode(0o600);
        std::fs::set_permissions(&paths.pending, perms)?;
    }
    Ok(())
}

/// Drop pending entries older than `PENDING_MAX_AGE_DAYS` and persist.
/// Returns the number of entries removed. Cheap no-op when nothing is stale.
pub fn auto_prune_pending(paths: &Paths) -> Result<usize> {
    let all = load_pending(paths).unwrap_or_default();
    if all.is_empty() {
        return Ok(0);
    }
    let cutoff = Utc::now() - chrono::Duration::days(PENDING_MAX_AGE_DAYS);
    let before = all.len();
    let kept: Vec<_> = all
        .into_iter()
        .filter(|p| p.last_seen.unwrap_or(p.ts) >= cutoff)
        .collect();
    let pruned = before - kept.len();
    if pruned > 0 {
        save_pending(paths, &kept)?;
    }
    Ok(pruned)
}

pub fn clear_pending_for(paths: &Paths, fingerprint: &str) -> Result<()> {
    let all = load_pending(paths)?;
    let kept: Vec<_> = all
        .into_iter()
        .filter(|p| p.fingerprint != fingerprint)
        .collect();
    save_pending(paths, &kept)
}

pub fn ensure_key(paths: &Paths) -> Result<SigningKey> {
    if paths.key.exists() {
        let mut buf = [0u8; 32];
        let mut f = File::open(&paths.key)?;
        f.read_exact(&mut buf)?;
        return Ok(SigningKey::from_bytes(&buf));
    }
    let key = SigningKey::generate(&mut OsRng);
    let mut f = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(&paths.key)?;
    f.write_all(&key.to_bytes())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&paths.key, std::fs::Permissions::from_mode(0o600))?;
    }
    std::fs::write(&paths.pubkey, hex::encode(key.verifying_key().to_bytes()))?;
    Ok(key)
}

pub fn sign_entry(key: &SigningKey, entry: &mut AllowEntry) -> Result<()> {
    entry.signature.clear();
    let bytes = canonical_entry_bytes(entry)?;
    let sig = key.sign(&bytes);
    entry.signature = hex::encode(sig.to_bytes());
    Ok(())
}

pub fn verify_entry(pubkey: &VerifyingKey, entry: &AllowEntry) -> Result<()> {
    let mut clone = entry.clone();
    clone.signature.clear();
    let bytes = canonical_entry_bytes(&clone)?;
    let raw = hex::decode(&entry.signature).context("signature hex")?;
    let arr: [u8; SIGNATURE_LENGTH] = raw
        .as_slice()
        .try_into()
        .context("signature length")?;
    let sig = ed25519_dalek::Signature::from_bytes(&arr);
    pubkey.verify(&bytes, &sig).context("bad signature")?;
    Ok(())
}

fn canonical_entry_bytes(entry: &AllowEntry) -> Result<Vec<u8>> {
    let mut map: BTreeMap<&str, serde_json::Value> = BTreeMap::new();
    map.insert("id", serde_json::Value::String(entry.id.clone()));
    map.insert(
        "fingerprint",
        serde_json::Value::String(entry.fingerprint.clone()),
    );
    map.insert("argv", serde_json::to_value(&entry.argv)?);
    map.insert(
        "command",
        serde_json::Value::String(entry.command.clone()),
    );
    map.insert("cwd", serde_json::Value::String(entry.cwd.clone()));
    map.insert("env_subset", serde_json::to_value(&entry.env_subset)?);
    map.insert("dangerous", serde_json::Value::Bool(entry.dangerous));
    map.insert(
        "source_config",
        serde_json::to_value(&entry.source_config)?,
    );
    map.insert("sandbox", serde_json::to_value(&entry.sandbox)?);
    map.insert(
        "argv_file_hashes",
        serde_json::to_value(&entry.argv_file_hashes)?,
    );
    map.insert(
        "signed_at",
        serde_json::Value::String(entry.signed_at.to_rfc3339()),
    );
    Ok(serde_json::to_vec(&map)?)
}

