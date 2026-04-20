
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
    pub signed_at: DateTime<Utc>,
    pub signature: String,
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
    pub ts: DateTime<Utc>,
    pub fingerprint: String,
    pub request: SpawnRequest,
    pub reason: String,
}

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

pub fn append_pending(paths: &Paths, entry: &PendingEntry) -> Result<()> {
    let mut f = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&paths.pending)?;
    f.lock_exclusive()?;
    let line = serde_json::to_string(entry)?;
    writeln!(f, "{line}")?;
    f.unlock().ok();
    Ok(())
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
    Ok(())
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
        "signed_at",
        serde_json::Value::String(entry.signed_at.to_rfc3339()),
    );
    Ok(serde_json::to_vec(&map)?)
}

