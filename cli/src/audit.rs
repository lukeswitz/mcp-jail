//! Append-only, hash-chained JSONL audit log.

use anyhow::Result;
use chrono::{DateTime, Utc};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Record {
    pub ts: DateTime<Utc>,
    pub prev_hash: String,
    pub decision: String,
    pub fingerprint: String,
    pub id: Option<String>,
    pub reason: String,
    pub pid: u32,
    pub this_hash: String,
}

pub fn append(path: &Path, mut rec: Record) -> Result<()> {
    let prev = last_hash(path)?.unwrap_or_else(|| "0".repeat(64));
    rec.prev_hash = prev;
    let mut digest_input = serde_json::to_vec(&rec)?;
    digest_input.extend_from_slice(b"chain");
    let digest = Sha256::digest(&digest_input);
    rec.this_hash = hex::encode(digest);

    let mut f = OpenOptions::new().create(true).append(true).open(path)?;
    f.lock_exclusive()?;
    writeln!(f, "{}", serde_json::to_string(&rec)?)?;
    f.unlock().ok();
    Ok(())
}

pub fn read_last(path: &Path, n: usize) -> Result<Vec<Record>> {
    if !path.exists() {
        return Ok(vec![]);
    }
    let f = File::open(path)?;
    let recs: Vec<Record> = BufReader::new(f)
        .lines()
        .map_while(Result::ok)
        .filter_map(|l| serde_json::from_str(&l).ok())
        .collect();
    let len = recs.len();
    Ok(recs.into_iter().skip(len.saturating_sub(n)).collect())
}

pub fn verify_chain(path: &Path) -> Result<bool> {
    if !path.exists() {
        return Ok(true);
    }
    let f = File::open(path)?;
    let mut prev = "0".repeat(64);
    for line in BufReader::new(f).lines() {
        let l = line?;
        let r: Record = serde_json::from_str(&l)?;
        if r.prev_hash != prev {
            return Ok(false);
        }
        prev = r.this_hash.clone();
    }
    Ok(true)
}

fn last_hash(path: &Path) -> Result<Option<String>> {
    if !path.exists() {
        return Ok(None);
    }
    let f = File::open(path)?;
    let mut last: Option<Record> = None;
    for line in BufReader::new(f).lines() {
        let l = line?;
        if let Ok(r) = serde_json::from_str::<Record>(&l) {
            last = Some(r);
        }
    }
    Ok(last.map(|r| r.this_hash))
}
