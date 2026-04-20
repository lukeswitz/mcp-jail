
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
        Command::Doctor => cmd_doctor(),
    }
}

fn cmd_doctor() -> Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    let mut problems = 0usize;
    let mut warnings = 0usize;
    let ok = |msg: &str| println!("  \x1b[32m✓\x1b[0m {msg}");
    let warn_line = |msg: &str| println!("  \x1b[33m⚠\x1b[0m {msg}");
    let err_line = |msg: &str| println!("  \x1b[31m✗\x1b[0m {msg}");

    println!("mcp-jail doctor\n");

    let paths = Paths::default();

    if !paths.root.is_dir() {
        err_line(&format!(
            "state dir missing: {} — run `mcp-jail init`",
            paths.root.display()
        ));
        problems += 1;
    } else {
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&paths.root)
                .ok()
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            if mode != 0o700 {
                warn_line(&format!(
                    "state dir {} mode is {:o}; should be 700",
                    paths.root.display(),
                    mode
                ));
                warnings += 1;
            } else {
                ok(&format!("state dir {} (mode 700)", paths.root.display()));
            }
        }
    }

    if !paths.key.is_file() {
        err_line("private key missing — run `mcp-jail init`");
        problems += 1;
    } else {
        #[cfg(unix)]
        {
            let mode = std::fs::metadata(&paths.key)
                .ok()
                .map(|m| m.permissions().mode() & 0o777)
                .unwrap_or(0);
            let size = std::fs::metadata(&paths.key).ok().map(|m| m.len()).unwrap_or(0);
            if mode != 0o600 {
                err_line(&format!("private key mode {:o}; must be 600", mode));
                problems += 1;
            } else if size != 32 {
                err_line(&format!("private key size {size} bytes; expected 32 (ed25519)"));
                problems += 1;
            } else {
                ok("private key (32 bytes, mode 600)");
            }
        }
    }

    let pubkey = match load_pubkey() {
        Ok(k) => {
            ok("public key loaded");
            Some(k)
        }
        Err(e) => {
            err_line(&format!("public key unloadable: {e}"));
            problems += 1;
            None
        }
    };

    let allow = match load_allow(&paths) {
        Ok(a) => a,
        Err(e) => {
            err_line(&format!("allow.toml unreadable: {e}"));
            problems += 1;
            AllowList::default()
        }
    };
    if let Some(pk) = &pubkey {
        let mut bad = 0;
        for e in &allow.entries {
            if verify_entry(pk, e).is_err() {
                bad += 1;
            }
        }
        if bad == 0 {
            ok(&format!(
                "{} approved entries, all signatures valid",
                allow.entries.len()
            ));
        } else {
            err_line(&format!(
                "{bad} of {} approved entries have INVALID signatures (tampered allow-list?)",
                allow.entries.len()
            ));
            problems += 1;
        }
    }

    match audit::verify_chain(&paths.audit) {
        Ok(true) => ok("audit log hash-chain intact"),
        Ok(false) => {
            warn_line("audit log hash-chain broken (tampered or test-seeded)");
            warnings += 1;
        }
        Err(e) => {
            warn_line(&format!("audit log unreadable: {e}"));
            warnings += 1;
        }
    }

    match sandbox::ensure_helper() {
        Ok(()) => ok("sandbox helper available"),
        Err(e) => {
            err_line(&format!("sandbox helper missing: {e}"));
            problems += 1;
        }
    }

    match wrap::scan_and_apply(true, false) {
        Ok(plan) if plan.is_empty() => ok("all known MCP client configs are wrapped"),
        Ok(plan) => {
            let total: usize = plan.iter().map(|c| c.touched).sum();
            warn_line(&format!(
                "{total} MCP server entr{} across {} config file(s) NOT wrapped — run `mcp-jail wrap`",
                if total == 1 { "y" } else { "ies" },
                plan.len()
            ));
            warnings += 1;
        }
        Err(e) => {
            warn_line(&format!("config scan failed: {e}"));
            warnings += 1;
        }
    }

    let pending = load_pending(&paths).unwrap_or_default();
    if pending.is_empty() {
        ok("no pending approvals");
    } else {
        warn_line(&format!(
            "{} pending fingerprint(s) awaiting approval — run `mcp-jail list`",
            pending.len()
        ));
        warnings += 1;
    }

    let current = env!("CARGO_PKG_VERSION");
    match fetch_latest_version() {
        Some(latest) if latest == current => {
            ok(&format!("mcp-jail v{current} is up to date"));
        }
        Some(latest) => {
            warn_line(&format!(
                "update available: v{current} installed, v{latest} is latest — run `mcp-jail upgrade`"
            ));
            warnings += 1;
        }
        None => {
            ok(&format!(
                "mcp-jail v{current} (online version check skipped)"
            ));
        }
    }

    println!();
    if problems == 0 && warnings == 0 {
        println!("\x1b[32mAll healthy.\x1b[0m");
    } else if problems == 0 {
        println!("\x1b[33m{warnings} warning(s).\x1b[0m OK to use; see above.");
    } else {
        println!(
            "\x1b[31m{problems} problem(s), {warnings} warning(s).\x1b[0m"
        );
        return Err(anyhow!("{problems} health check(s) failed"));
    }
    Ok(())
}

fn fetch_latest_version() -> Option<String> {
    let out = std::process::Command::new("curl")
        .args([
            "-fsSL",
            "--max-time",
            "3",
            "https://api.github.com/repos/lukeswitz/mcp-jail/releases/latest",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let body = String::from_utf8_lossy(&out.stdout);
    let tag = body.split("\"tag_name\"").nth(1)?;
    let start = tag.find('"')? + 1;
    let rest = &tag[start..];
    let end = rest.find('"')?;
    Some(rest[..end].trim_start_matches('v').to_owned())
}

fn cmd_wrap(a: WrapArgs, unwrapping: bool) -> Result<()> {
    let verb = if unwrapping { "unwrap" } else { "wrap" };

    let proposed = wrap::scan_and_apply(true, unwrapping)?;
    if proposed.is_empty() {
        if unwrapping {
            println!("No mcp-jail-wrapped entries found. Nothing to undo.");
        } else {
            println!(
                "All your MCP client configs are already routed through mcp-jail.\n\
                 Nothing to change. You're protected."
            );
        }
        return Ok(());
    }

    let total: usize = proposed.iter().map(|c| c.touched).sum();
    let entry_word = if total == 1 { "entry" } else { "entries" };
    let file_word = if proposed.len() == 1 { "file" } else { "files" };

    println!();
    if unwrapping {
        println!("mcp-jail found {total} wrapped {entry_word} across {} {file_word} it can restore:", proposed.len());
    } else {
        println!(
            "mcp-jail found {total} MCP server {entry_word} across {} {file_word}.",
            proposed.len()
        );
        println!("It will route each one through itself so every launch is checked.");
        println!();
        println!("Files that will be modified:");
    }
    for c in &proposed {
        let entry_label = if c.touched == 1 { "entry" } else { "entries" };
        println!("  • {} ({} {entry_label})", c.path.display(), c.touched);
    }
    if !unwrapping {
        println!();
        println!("Each file gets a timestamped backup next to it before any change.");
        println!("`mcp-jail unwrap` later puts everything back exactly as it was.");
    }

    if a.dry_run {
        println!("\n(dry-run — nothing written)");
        return Ok(());
    }

    if !a.yes {
        println!();
        let q = if unwrapping {
            "Restore original configs?"
        } else {
            "Apply now?"
        };
        if !wrap::prompt_yes(q) {
            println!("Cancelled — nothing changed.");
            return Ok(());
        }
    }

    let applied = wrap::scan_and_apply(false, unwrapping)?;
    println!();
    for c in &applied {
        let entry_label = if c.touched == 1 { "entry" } else { "entries" };
        println!("  ✓ {} — {} {entry_label} {verb}ped", c.path.display(), c.touched);
    }

    if unwrapping {
        println!();
        println!("Done. Your MCP clients spawn their servers directly again.");
        return Ok(());
    }

    let mut auto_signed = 0usize;
    let mut manual_needed: Vec<String> = Vec::new();
    if !a.no_auto_approve {
        let paths = Paths::default();
        paths.ensure()?;
        let key = ensure_key(&paths)?;
        let mut allow = load_allow(&paths)?;
        for change in &applied {
            for w in &change.wrapped {
                let mut argv = vec![w.command.clone()];
                argv.extend(w.args.iter().cloned());
                if let Some(flag) = find_dangerous_flag(&argv) {
                    manual_needed.push(format!("{} (uses `{}`)", w.id, flag));
                    continue;
                }
                let req = SpawnRequest {
                    command: w.command.clone(),
                    argv: argv.clone(),
                    env: std::collections::BTreeMap::new(),
                    cwd: String::new(),
                    source_config: Some(w.source_config.clone()),
                };
                let fingerprint = req.fingerprint(&[]);
                allow.entries.retain(|e| e.id != w.id);
                let mut entry = AllowEntry {
                    id: w.id.clone(),
                    fingerprint,
                    argv,
                    command: w.command.clone(),
                    cwd: String::new(),
                    env_subset: Vec::new(),
                    dangerous: false,
                    source_config: Some(SourceConfig {
                        path: w.source_config.clone(),
                        hash: String::new(),
                    }),
                    sandbox: Sandbox::default(),
                    signed_at: Utc::now(),
                    signature: String::new(),
                };
                sign_entry(&key, &mut entry)?;
                sandbox::write_profile(&paths.root, &entry)?;
                allow.entries.push(entry);
                auto_signed += 1;
            }
        }
        save_allow(&paths, &allow)?;
    }

    println!();
    println!("Done. Your MCP client configs are protected by mcp-jail.");
    if auto_signed > 0 {
        let word = if auto_signed == 1 { "server" } else { "servers" };
        println!(
            "Auto-approved {auto_signed} pre-existing {word} — they will just work\n\
             when you restart your MCP client. No further action needed."
        );
    }
    if !manual_needed.is_empty() {
        println!();
        println!("The following server(s) use interpreter-eval flags and were NOT");
        println!("auto-approved — review the argv and approve manually if you trust them:");
        for m in &manual_needed {
            println!("  • {m}");
        }
        println!("Run `mcp-jail approve <fp> --id <name> --dangerous` to allow.");
    }
    if auto_signed == 0 && manual_needed.is_empty() {
        println!();
        println!("Restart your MCP client. The first time each server launches,");
        println!("mcp-jail prints a `mcp-jail approve …` line — run it once.");
    }
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
    sandbox::ensure_helper().ok();
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

    let fp = a
        .fingerprint
        .ok_or_else(|| anyhow!("provide a fingerprint prefix (>=6 hex chars)"))?;
    if fp.len() < 6 {
        return Err(anyhow!("fingerprint prefix must be >=6 chars"));
    }
    let pendings = load_pending(&paths)?;
    let pending = pendings
        .iter()
        .rev()
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
    let pubkey = load_pubkey().map_err(|e| format!("mcp-jail not initialized: {e}"))?;
    for entry in &allow.entries {
        let fp = req.fingerprint(&entry.env_subset);
        if fp != entry.fingerprint {
            continue;
        }
        if verify_entry(&pubkey, entry).is_err() {
            return Err(format!(
                "entry `{}` has an invalid signature — tampered allow-list?",
                entry.id
            ));
        }
        if !entry.dangerous {
            if let Some(flag) = find_dangerous_flag(&req.argv) {
                return Err(JailError::DangerousFlag(flag).to_string());
            }
        }
        return Ok(entry);
    }
    Err(JailError::UnknownFingerprint(req.fingerprint_full()).to_string())
}

fn load_pubkey() -> Result<ed25519_dalek::VerifyingKey> {
    let paths = Paths::default();
    let hex_str = std::fs::read_to_string(&paths.pubkey)
        .context("missing pubkey; run `mcp-jail init`")?;
    let raw = hex::decode(hex_str.trim())?;
    let arr: [u8; 32] = raw.as_slice().try_into().context("pubkey length")?;
    Ok(ed25519_dalek::VerifyingKey::from_bytes(&arr)?)
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

    unsafe {
        libc::execve(program.as_ptr(), argv_ptrs.as_ptr(), envp_ptrs.as_ptr());
    }
    let err = std::io::Error::last_os_error();
    Err(anyhow!("execve({}) failed: {err}", wrapped[0]))
}

#[cfg(not(unix))]
fn exec_or_die(wrapped: &[String], env_subset: &[String]) -> Result<()> {
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

