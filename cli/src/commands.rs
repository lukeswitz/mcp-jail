//! Command dispatch for the `mcp-jail` CLI.

use crate::audit;
use crate::canonical::{find_dangerous_flag, hash_file, SpawnRequest};
use crate::cli::{ApproveArgs, Command, ExecArgs, InitArgs, LogsArgs, RevokeArgs, WrapArgs};
use crate::wrap;
use crate::errors::JailError;
use crate::sandbox;
use crate::store::{
    append_pending, clear_pending_for, ensure_key, load_allow, load_pending, save_allow,
    sign_entry, verify_entry, AllowEntry, AllowList, PendingEntry, Paths, Sandbox, SourceConfig,
};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use ed25519_dalek::VerifyingKey;
use std::io::Read;
use std::path::PathBuf;
use std::process;

pub fn dispatch(cmd: Command) -> Result<()> {
    match cmd {
        Command::Init(a) => cmd_init(a),
        Command::Approve(a) => cmd_approve(a),
        Command::List => cmd_list(),
        Command::Revoke(a) => cmd_revoke(a),
        Command::Logs(a) => cmd_logs(a),
        Command::Verify => cmd_verify(),
        Command::Check => cmd_check(),
        Command::Exec(a) => cmd_exec(a),
        Command::Upgrade => cmd_upgrade(),
        Command::Wrap(a) => cmd_wrap(a, false),
        Command::Unwrap(a) => cmd_wrap(a, true),
    }
}

fn cmd_wrap(a: WrapArgs, unwrapping: bool) -> Result<()> {
    let verb = if unwrapping { "unwrap" } else { "wrap" };
    let proposed = wrap::scan_and_apply(true, unwrapping)?;
    if proposed.is_empty() {
        println!("mcp-jail: no {verb}-able entries found in known client configs.");
        return Ok(());
    }
    println!("mcp-jail: {verb} plan — {} file(s)", proposed.len());
    for c in &proposed {
        println!("  {}  ({} entries)", c.path.display(), c.touched);
    }
    if a.dry_run {
        println!("(dry-run; no files changed)");
        return Ok(());
    }
    if !a.yes && !wrap::prompt_yes("Apply changes? backups will be written next to each file.") {
        println!("aborted.");
        return Ok(());
    }
    let applied = wrap::scan_and_apply(false, unwrapping)?;
    for c in &applied {
        println!("  {} {} ({} entries)", verb, c.path.display(), c.touched);
    }
    println!("done. start your MCP client; first spawn of each server will block with a fingerprint — approve once.");
    Ok(())
}

fn cmd_upgrade() -> Result<()> {
    let url =
        "https://raw.githubusercontent.com/lukeswitz/mcp-jail/main/install.sh";
    let status = std::process::Command::new("sh")
        .arg("-c")
        .arg(format!("curl -fsSL {url} | bash"))
        .status()
        .context("failed to spawn upgrade shell")?;
    if !status.success() {
        return Err(anyhow!("upgrade script exited {status}"));
    }
    Ok(())
}

fn cmd_init(_a: InitArgs) -> Result<()> {
    let paths = Paths::default();
    paths.ensure()?;
    let _key = ensure_key(&paths)?;
    sandbox::ensure_helper().ok(); // non-fatal; warn only
    println!("mcp-jail: initialized at {}", paths.root.display());
    println!("  key:     {}", paths.pubkey.display());
    println!("  allow:   {}", paths.allow.display());
    println!("  audit:   {}", paths.audit.display());
    Ok(())
}

fn cmd_approve(a: ApproveArgs) -> Result<()> {
    let paths = Paths::default();
    paths.ensure()?;
    let key = ensure_key(&paths)?;

    // Load the pending entry matching the fingerprint prefix.
    let fp = a
        .fingerprint
        .ok_or_else(|| anyhow!("provide a fingerprint prefix (>=6 hex chars)"))?;
    if fp.len() < 6 {
        return Err(anyhow!("fingerprint prefix must be >=6 chars"));
    }
    let pendings = load_pending(&paths)?;
    let pending = pendings
        .iter()
        .rev() // latest first
        .find(|p| p.fingerprint.starts_with(&fp))
        .cloned()
        .ok_or_else(|| anyhow!("no pending entry matching `{fp}`"))?;

    if !a.dangerous {
        if let Some(flag) = find_dangerous_flag(&pending.request.argv) {
            return Err(anyhow!(
                "argv contains interpreter-eval flag `{flag}`; re-run with --dangerous to allow"
            ));
        }
    }

    let id = a
        .id
        .unwrap_or_else(|| derive_id(&pending.request.argv, &pending.fingerprint));

    // Env keys do not participate in the fingerprint unless the user opts
    // in per-key with --env. Avoids volatile keys (TMPDIR, `_`) causing drift.
    let env_subset = a.env.clone();

    let source_config = match a.source_config.or(pending.request.source_config.clone()) {
        Some(p) => {
            let h = hash_file(std::path::Path::new(&p))
                .ok_or_else(|| anyhow!("cannot read source config {p}"))?;
            Some(SourceConfig { path: p, hash: h })
        }
        None => None,
    };

    let mut entry = AllowEntry {
        id: id.clone(),
        fingerprint: pending.request.fingerprint(&env_subset),
        argv: pending.request.argv.clone(),
        command: pending.request.command.clone(),
        cwd: pending.request.cwd.clone(),
        env_subset,
        dangerous: a.dangerous,
        source_config,
        sandbox: Sandbox {
            net: a.net,
            fs_read: a.fs_read,
            fs_write: a.fs_write,
            fs_read_secret: a.fs_read_secret,
        },
        signed_at: Utc::now(),
        signature: String::new(),
    };
    sign_entry(&key, &mut entry)?;
    sandbox::write_profile(&paths.root, &entry)?;

    let mut allow = load_allow(&paths)?;
    allow.entries.retain(|e| e.id != entry.id);
    allow.entries.push(entry.clone());
    save_allow(&paths, &allow)?;
    clear_pending_for(&paths, &pending.fingerprint)?;

    audit::append(
        &paths.audit,
        audit::Record {
            ts: Utc::now(),
            prev_hash: String::new(),
            decision: "approve".to_owned(),
            fingerprint: entry.fingerprint.clone(),
            id: Some(entry.id.clone()),
            reason: "user approval".to_owned(),
            pid: process::id(),
            this_hash: String::new(),
        },
    )?;

    println!("approved {} ({})", entry.id, entry.fingerprint);
    Ok(())
}

fn cmd_list() -> Result<()> {
    let paths = Paths::default();
    let allow = load_allow(&paths)?;
    println!("# approved");
    for e in &allow.entries {
        println!(
            "  {:<24} {}  dangerous={} net={:?} fs_read={:?} fs_write={:?}",
            e.id,
            &e.fingerprint[..12],
            e.dangerous,
            e.sandbox.net,
            e.sandbox.fs_read,
            e.sandbox.fs_write,
        );
    }
    let pending = load_pending(&paths)?;
    if !pending.is_empty() {
        println!("# pending");
        for p in pending.iter().rev().take(20) {
            println!(
                "  {}  {}  argv={:?}",
                p.ts.format("%Y-%m-%d %H:%M:%S"),
                &p.fingerprint[..12],
                p.request.argv
            );
        }
    }
    Ok(())
}

fn cmd_revoke(a: RevokeArgs) -> Result<()> {
    let paths = Paths::default();
    let mut allow = load_allow(&paths)?;
    let before = allow.entries.len();
    allow.entries.retain(|e| e.id != a.id);
    if allow.entries.len() == before {
        return Err(anyhow!("no entry with id `{}`", a.id));
    }
    save_allow(&paths, &allow)?;
    audit::append(
        &paths.audit,
        audit::Record {
            ts: Utc::now(),
            prev_hash: String::new(),
            decision: "revoke".to_owned(),
            fingerprint: String::new(),
            id: Some(a.id.clone()),
            reason: "user revoke".to_owned(),
            pid: process::id(),
            this_hash: String::new(),
        },
    )?;
    println!("revoked {}", a.id);
    Ok(())
}

fn cmd_logs(a: LogsArgs) -> Result<()> {
    let paths = Paths::default();
    let recs = audit::read_last(&paths.audit, a.limit)?;
    let chain_ok = audit::verify_chain(&paths.audit)?;
    for r in recs {
        println!(
            "{} {:<7} {:<20} fp={} reason={}",
            r.ts.format("%Y-%m-%dT%H:%M:%S"),
            r.decision,
            r.id.unwrap_or_default(),
            &r.fingerprint.chars().take(12).collect::<String>(),
            r.reason,
        );
    }
    if !chain_ok {
        eprintln!("!! audit chain broken");
    }
    Ok(())
}

fn cmd_verify() -> Result<()> {
    let paths = Paths::default();
    paths.ensure()?;
    let pubkey_hex = std::fs::read_to_string(&paths.pubkey)
        .context("missing pubkey; run `mcp-jail init`")?;
    let pubkey_raw = hex::decode(pubkey_hex.trim())?;
    let pubkey_arr: [u8; 32] = pubkey_raw.as_slice().try_into().context("pubkey length")?;
    let pubkey = VerifyingKey::from_bytes(&pubkey_arr)?;
    let allow = load_allow(&paths)?;
    let mut bad = 0;
    for e in &allow.entries {
        if verify_entry(&pubkey, e).is_err() {
            println!("BAD signature: {}", e.id);
            bad += 1;
        }
    }
    println!("entries={}  bad_sigs={}", allow.entries.len(), bad);
    if !audit::verify_chain(&paths.audit)? {
        println!("AUDIT chain broken");
    } else {
        println!("audit chain OK");
    }
    match sandbox::ensure_helper() {
        Ok(()) => println!("sandbox helper OK"),
        Err(e) => println!("sandbox helper MISSING: {e}"),
    }
    if bad > 0 {
        return Err(anyhow!("{bad} entries with bad signatures"));
    }
    Ok(())
}

/// Stdin JSON: { "command": "...", "argv": [...], "env": {...}, "cwd": "..." }
/// Stdout JSON: { "decision": "allow"|"deny", "reason": "...",
///                "wrapped_argv": [...]|null,
///                "env_allow": [...], "fingerprint": "..." }
fn cmd_check() -> Result<()> {
    let paths = Paths::default();
    paths.ensure()?;
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s)?;
    let req: SpawnRequest = serde_json::from_str(&s).context("invalid check payload")?;

    let allow = load_allow(&paths)?;
    let fp_full = req.fingerprint_full();

    let decision = evaluate(&allow, &req);
    match decision {
        Ok(entry) => {
            let profile = sandbox::write_profile(&paths.root, entry)?;
            let wrapped = sandbox::wrap_argv(&profile, &entry.command, &entry.argv)?;
            audit::append(
                &paths.audit,
                audit::Record {
                    ts: Utc::now(),
                    prev_hash: String::new(),
                    decision: "allow".to_owned(),
                    fingerprint: entry.fingerprint.clone(),
                    id: Some(entry.id.clone()),
                    reason: "matched signed entry".to_owned(),
                    pid: process::id(),
                    this_hash: String::new(),
                },
            )?;
            let out = serde_json::json!({
                "decision": "allow",
                "id": entry.id,
                "fingerprint": entry.fingerprint,
                "wrapped_argv": wrapped,
                "env_allow": entry.env_subset,
                "sandbox": entry.sandbox,
            });
            println!("{out}");
            Ok(())
        }
        Err(reason) => {
            append_pending(
                &paths,
                &PendingEntry {
                    ts: Utc::now(),
                    fingerprint: fp_full.clone(),
                    request: req.clone(),
                    reason: reason.clone(),
                },
            )?;
            audit::append(
                &paths.audit,
                audit::Record {
                    ts: Utc::now(),
                    prev_hash: String::new(),
                    decision: "deny".to_owned(),
                    fingerprint: fp_full.clone(),
                    id: None,
                    reason: reason.clone(),
                    pid: process::id(),
                    this_hash: String::new(),
                },
            )?;
            let out = serde_json::json!({
                "decision": "deny",
                "reason": reason,
                "fingerprint": fp_full,
                "hint": format!("mcp-jail approve {}", &fp_full[..12]),
                "argv": req.argv,
                "command": req.command,
            });
            println!("{out}");
            Ok(())
        }
    }
}

fn evaluate<'a>(allow: &'a AllowList, req: &SpawnRequest) -> Result<&'a AllowEntry, String> {
    for entry in &allow.entries {
        let fp = req.fingerprint(&entry.env_subset);
        if fp != entry.fingerprint {
            continue;
        }
        // Argv sanity — still runs on approved entries.
        if !entry.dangerous {
            if let Some(flag) = find_dangerous_flag(&req.argv) {
                return Err(JailError::DangerousFlag(flag).to_string());
            }
        }
        // NOTE: we intentionally do NOT hash the source config file for
        // enforcement. Family-3 attacks (prompt-injection rewrites config)
        // work by mutating command/args, which already flips the argv
        // fingerprint above. Hashing the whole config additionally trips on
        // unrelated writes the client itself makes (Claude Code updates
        // session state on its own JSON file) — false positives in the live
        // deployment with no added defense. source_config remains in the
        // entry for audit/intent.
        return Ok(entry);
    }
    Err(JailError::UnknownFingerprint(req.fingerprint_full()).to_string())
}

fn derive_id(argv: &[String], fingerprint: &str) -> String {
    let base = argv
        .iter()
        .skip(1)
        .find(|a| !a.starts_with('-'))
        .cloned()
        .unwrap_or_else(|| {
            PathBuf::from(argv.first().cloned().unwrap_or_default())
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "server".to_owned())
        });
    format!("{}-{}", sanitize_id(&base), &fingerprint[..6])
}

fn sanitize_id(s: &str) -> String {
    s.chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect()
}

fn cmd_exec(a: ExecArgs) -> Result<()> {
    use crate::canonical::SpawnRequest;
    use std::collections::BTreeMap;

    let paths = Paths::default();
    paths.ensure()?;

    let argv = a.argv;
    if argv.is_empty() {
        return Err(anyhow!("`exec --` requires at least one argument"));
    }
    let command = argv[0].clone();
    let cwd = std::env::current_dir()?
        .to_str()
        .ok_or_else(|| anyhow!("cwd not utf-8"))?
        .to_owned();

    let env: BTreeMap<String, String> = std::env::vars().collect();

    let req = SpawnRequest {
        command: command.clone(),
        argv: argv.clone(),
        env,
        cwd,
        source_config: a.source_config.clone(),
    };

    let allow = load_allow(&paths)?;
    match evaluate(&allow, &req) {
        Ok(entry) => {
            let profile = sandbox::write_profile(&paths.root, entry)?;
            let wrapped =
                sandbox::wrap_argv(&profile, &entry.command, &entry.argv)?;
            audit::append(
                &paths.audit,
                audit::Record {
                    ts: Utc::now(),
                    prev_hash: String::new(),
                    decision: "allow".to_owned(),
                    fingerprint: entry.fingerprint.clone(),
                    id: Some(entry.id.clone()),
                    reason: "exec".to_owned(),
                    pid: process::id(),
                    this_hash: String::new(),
                },
            )?;
            exec_or_die(&wrapped, &entry.env_subset)?;
            unreachable!()
        }
        Err(reason) => {
            let fp = req.fingerprint_full();
            append_pending(
                &paths,
                &crate::store::PendingEntry {
                    ts: Utc::now(),
                    fingerprint: fp.clone(),
                    request: req.clone(),
                    reason: reason.clone(),
                },
            )?;
            audit::append(
                &paths.audit,
                audit::Record {
                    ts: Utc::now(),
                    prev_hash: String::new(),
                    decision: "deny".to_owned(),
                    fingerprint: fp.clone(),
                    id: a.id.clone(),
                    reason: reason.clone(),
                    pid: process::id(),
                    this_hash: String::new(),
                },
            )?;
            eprintln!("mcp-jail: blocked exec of {:?}", argv);
            eprintln!("  reason: {reason}");
            eprintln!("  hint:   mcp-jail approve {}", &fp[..12]);
            std::process::exit(126);
        }
    }
}

#[cfg(unix)]
fn exec_or_die(wrapped: &[String], env_subset: &[String]) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let filtered_env: Vec<(String, String)> = {
        let mut out = Vec::new();
        let declared: std::collections::HashSet<&str> =
            env_subset.iter().map(String::as_str).collect();
        let essentials = [
            "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SHELL", "LANG", "LC_ALL",
            "SSH_AUTH_SOCK", "DISPLAY", "XAUTHORITY",
        ];
        for (k, v) in std::env::vars() {
            if declared.contains(k.as_str()) || essentials.contains(&k.as_str()) {
                out.push((k, v));
            }
        }
        out
    };

    let c_argv: Vec<CString> = wrapped
        .iter()
        .map(|s| CString::new(s.as_bytes()).unwrap_or_default())
        .collect();
    let c_envp: Vec<CString> = filtered_env
        .iter()
        .map(|(k, v)| {
            let kv = format!("{k}={v}");
            CString::new(kv.as_bytes()).unwrap_or_default()
        })
        .collect();

    let mut argv_ptrs: Vec<*const libc::c_char> =
        c_argv.iter().map(|s| s.as_ptr()).collect();
    argv_ptrs.push(std::ptr::null());
    let mut envp_ptrs: Vec<*const libc::c_char> =
        c_envp.iter().map(|s| s.as_ptr()).collect();
    envp_ptrs.push(std::ptr::null());

    let program = CString::new(std::ffi::OsStr::new(&wrapped[0]).as_bytes())
        .map_err(|_| anyhow!("program path has NUL"))?;

    // SAFETY: pointer arrays live to the end of this frame; execve only
    // returns on failure.
    unsafe {
        libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    Err(anyhow!("execve({}) failed: {err}", wrapped[0]))
}

#[cfg(not(unix))]
fn exec_or_die(wrapped: &[String], env_subset: &[String]) -> Result<()> {
    // Windows has no execve analogue. Spawn the child, inherit stdio,
    // wait, and propagate the exit code so the parent acts like the
    // child replaced it (close enough for Claude Code's MCP spawn path).
    use std::collections::HashSet;
    let declared: HashSet<&str> = env_subset.iter().map(String::as_str).collect();
    let essentials = [
        "PATH", "HOME", "USER", "LOGNAME", "TMPDIR", "SHELL", "LANG", "LC_ALL",
        "SSH_AUTH_SOCK", "DISPLAY", "XAUTHORITY",
        "USERPROFILE", "APPDATA", "LOCALAPPDATA", "SYSTEMROOT", "TEMP", "TMP",
    ];
    let mut cmd = std::process::Command::new(&wrapped[0]);
    cmd.args(&wrapped[1..]);
    cmd.env_clear();
    for (k, v) in std::env::vars() {
        if declared.contains(k.as_str()) || essentials.contains(&k.as_str()) {
            cmd.env(k, v);
        }
    }
    let status = cmd.status().context("spawn wrapped child")?;
    std::process::exit(status.code().unwrap_or(1));
}

