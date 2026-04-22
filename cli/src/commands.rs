
use crate::audit;
use crate::canonical::{find_dangerous_flag, hash_file, SpawnRequest};
use crate::cli::{
    ApproveArgs, Command, DoctorArgs, ExecArgs, InitArgs, LogsArgs, PruneArgs, RevokeArgs,
    SentryArgs, WrapArgs,
};
use crate::wrap;
use crate::errors::JailError;
use crate::sandbox;
use crate::sentry;
use crate::store::{
    self, auto_prune_pending, clear_pending_for, ensure_key, load_allow, load_pending, save_allow,
    sign_entry, upsert_pending, verify_entry, AllowEntry, AllowList, PendingEntry, Paths, Sandbox,
    SourceConfig,
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
        Command::Prune(a) => cmd_prune(a),
        Command::Status => cmd_status(),
        Command::Logs(a) => cmd_logs(a),
        Command::Verify => cmd_verify(),
        Command::Check => cmd_check(),
        Command::Exec(a) => cmd_exec(a),
        Command::Upgrade => cmd_upgrade(),
        Command::Wrap(a) => cmd_wrap(a, false),
        Command::Unwrap(a) => cmd_wrap(a, true),
        Command::Doctor(a) => cmd_doctor(a),
        Command::Sentry(a) => cmd_sentry(a),
    }
}

fn cmd_sentry(a: SentryArgs) -> Result<()> {
    sentry::dispatch(a.action)
}

fn cmd_doctor(args: DoctorArgs) -> Result<()> {
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

    match check_path_shadowing() {
        Ok(0) => ok("single mcp-jail binary on PATH"),
        Ok(n) => {
            warn_line(&format!(
                "{n} extra mcp-jail binar{} on PATH — shadows may cause `wrap`/`list` drift",
                if n == 1 { "y" } else { "ies" }
            ));
            if let Ok(list) = collect_path_binaries() {
                for p in list {
                    warn_line(&format!("  {}", p.display()));
                }
            }
            warnings += 1;
        }
        Err(e) => {
            warn_line(&format!("PATH shadow check skipped: {e}"));
            warnings += 1;
        }
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
        return Ok(());
    }

    if problems == 0 {
        println!("\x1b[33m{warnings} warning(s).\x1b[0m OK to use; see above.");
    } else {
        println!("\x1b[31m{problems} problem(s), {warnings} warning(s).\x1b[0m");
    }

    if args.notify {
        crate::notify::health_alert(problems, warnings);
    }

    if problems > 0 && !args.soft_fail {
        return Err(anyhow!("{problems} health check(s) failed"));
    }
    Ok(())
}

fn collect_path_binaries() -> Result<Vec<PathBuf>> {
    let path = std::env::var_os("PATH").ok_or_else(|| anyhow!("PATH unset"))?;
    let exe_name = if cfg!(windows) { "mcp-jail.exe" } else { "mcp-jail" };
    let mut seen: Vec<PathBuf> = Vec::new();
    for dir in std::env::split_paths(&path) {
        let candidate = dir.join(exe_name);
        let Ok(meta) = std::fs::metadata(&candidate) else { continue };
        if !meta.is_file() {
            continue;
        }
        let canonical = std::fs::canonicalize(&candidate).unwrap_or(candidate);
        if !seen.iter().any(|p| p == &canonical) {
            seen.push(canonical);
        }
    }
    Ok(seen)
}

fn check_path_shadowing() -> Result<usize> {
    let bins = collect_path_binaries()?;
    Ok(bins.len().saturating_sub(1))
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

#[derive(Default)]
struct ReconcileReport {
    signed: usize,
    missing_manual: Vec<String>,
}

#[derive(Clone, Copy)]
enum PromptMode {
    /// Prompt user per server (TTY-only).
    Ask,
    /// No prompting; infer "trusted" sandbox (net allowed for ssh/curl/etc,
    /// host-restricted when detectable).
    Trusted,
    /// No prompting; strict defaults (net BLOCKED, fs_write=/tmp).
    Strict,
}

fn detect_ssh_host(argv: &[String]) -> Option<String> {
    let base = std::path::Path::new(argv.first()?)
        .file_name()?
        .to_str()?;
    if !matches!(base, "ssh" | "scp" | "mosh") {
        return None;
    }
    let mut i = 1;
    while i < argv.len() {
        let a = &argv[i];
        if a == "-o" || a == "-i" || a == "-p" || a == "-l" || a == "-F" || a == "-J" {
            i += 2;
            continue;
        }
        if a.starts_with('-') {
            i += 1;
            continue;
        }
        let host = a.rsplit('@').next().unwrap_or(a).to_owned();
        if !host.is_empty() {
            return Some(host);
        }
        break;
    }
    None
}

fn detect_url_host(argv: &[String]) -> Option<String> {
    for a in argv.iter().skip(1) {
        if let Some(rest) = a.strip_prefix("https://").or_else(|| a.strip_prefix("http://")) {
            let host = rest.split(['/', ':']).next()?.to_owned();
            if !host.is_empty() {
                return Some(host);
            }
        }
    }
    None
}

fn trusted_sandbox_for(argv: &[String]) -> Sandbox {
    let mut sb = Sandbox::default();
    if needs_network(argv) {
        if let Some(h) = detect_ssh_host(argv).or_else(|| detect_url_host(argv)) {
            sb.net.push(h);
        } else {
            sb.net.push("*".into());
        }
    } else {
        sb.net.push("127.0.0.1".into());
    }
    if is_ssh_command(argv)
        && let Ok(home) = std::env::var("HOME")
    {
        for f in ["id_ed25519", "id_rsa", "id_ecdsa", "id_dsa", "config", "known_hosts"] {
            sb.fs_read_secret.push(format!("{home}/.ssh/{f}"));
        }
    }
    sb
}

fn is_ssh_command(argv: &[String]) -> bool {
    argv.first()
        .map(|c| {
            std::path::Path::new(c)
                .file_name()
                .map(|s| s.to_string_lossy().to_lowercase() == "ssh")
                .unwrap_or(false)
        })
        .unwrap_or(false)
}

fn prompt_line(msg: &str, default: &str) -> String {
    use std::io::{BufRead, Write};
    print!("{msg} [{default}] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    if std::io::stdin().lock().read_line(&mut line).is_err() {
        return default.to_owned();
    }
    let trimmed = line.trim();
    if trimmed.is_empty() {
        default.to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn ask_sandbox(w: &wrap::WrappedEntry, argv: &[String]) -> Option<Sandbox> {
    println!();
    println!("── \x1b[1m{}\x1b[0m", w.id);
    println!("   cmd: {}", format_argv(argv));
    let suggested_host = detect_ssh_host(argv).or_else(|| detect_url_host(argv));
    let net_hint = needs_network(argv);
    let (hint, default_choice) = match (net_hint, &suggested_host) {
        (true, Some(h)) => (format!("reaches remote host {h}"), "h"),
        (true, None) => ("network-dependent (no host detected)".into(), "a"),
        (false, _) => ("local command — most MCPs talk to 127.0.0.1".into(), "l"),
    };
    println!("   → {hint}");
    println!("   network policy:");
    println!("     [l]oopback only (127.0.0.1)   — safe default for local bridges");
    if suggested_host.is_some() {
        println!(
            "     [h]ost-restricted             — allow only {}",
            suggested_host.as_deref().unwrap_or("")
        );
    }
    println!("     [a]ll outbound                — no restriction");
    println!("     [b]lock                       — no network at all");
    println!("     [s]kip                        — don't add this server");
    let ans = prompt_line("   choice", default_choice);
    let mut sb = Sandbox::default();
    match ans.chars().next().unwrap_or('l') {
        'l' | 'L' => sb.net.push("127.0.0.1".into()),
        'h' | 'H' => {
            let host_default = suggested_host.clone().unwrap_or_default();
            let h = if host_default.is_empty() {
                prompt_line("   host", "")
            } else {
                prompt_line("   host", &host_default)
            };
            if !h.is_empty() {
                sb.net.push(h);
            }
        }
        'a' | 'A' => sb.net.push("*".into()),
        's' | 'S' => return None,
        _ => {}
    }
    Some(sb)
}

fn resolve_prompt_mode(a: &WrapArgs) -> PromptMode {
    if a.strict {
        return PromptMode::Strict;
    }
    if a.yes {
        return PromptMode::Trusted;
    }
    // Interactive only if STDIN is a TTY; otherwise fall back to Trusted so
    // installer pipelines don't break MCP servers on first launch.
    use std::io::IsTerminal;
    if std::io::stdin().is_terminal() {
        PromptMode::Ask
    } else {
        PromptMode::Trusted
    }
}

fn choose_sandbox(w: &wrap::WrappedEntry, argv: &[String], mode: PromptMode) -> Option<Sandbox> {
    match mode {
        PromptMode::Strict => Some(Sandbox::default()),
        PromptMode::Trusted => Some(trusted_sandbox_for(argv)),
        PromptMode::Ask => ask_sandbox(w, argv),
    }
}

fn approve_wrapped(
    wrapped: &[wrap::WrappedEntry],
    only_missing: bool,
    mode: PromptMode,
) -> Result<ReconcileReport> {
    let mut report = ReconcileReport::default();
    if wrapped.is_empty() {
        return Ok(report);
    }
    let paths = Paths::default();
    paths.ensure()?;
    let key = ensure_key(&paths)?;
    let mut allow = load_allow(&paths)?;
    let mut dirty = false;
    for w in wrapped {
        let mut argv = vec![w.command.clone()];
        argv.extend(w.args.iter().cloned());
        if let Some(flag) = find_dangerous_flag(&argv) {
            let already_ok = allow.entries.iter().any(|e| e.id == w.id);
            if !(only_missing && already_ok) {
                report.missing_manual.push(format!("{} (uses `{}`)", w.id, flag));
            }
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
        if only_missing {
            let vk = key.verifying_key();
            let have = allow.entries.iter().any(|e| {
                e.id == w.id && e.fingerprint == fingerprint && verify_entry(&vk, e).is_ok()
            });
            if have {
                continue;
            }
        }
        let Some(sandbox) = choose_sandbox(w, &argv, mode) else {
            continue;
        };
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
            sandbox,
            signed_at: Utc::now(),
            signature: String::new(),
        };
        sign_entry(&key, &mut entry)?;
        sandbox::write_profile(&paths.root, &entry)?;
        allow.entries.push(entry);
        report.signed += 1;
        dirty = true;
    }
    if dirty {
        save_allow(&paths, &allow)?;
    }
    Ok(report)
}

fn reconcile_allow_list(wrapped: &[wrap::WrappedEntry]) -> Result<ReconcileReport> {
    // Reconcile uses strict defaults — never prompts. Users can re-run
    // `mcp-jail wrap` interactively to redo sandbox choices.
    approve_wrapped(wrapped, true, PromptMode::Strict)
}

fn cmd_wrap(a: WrapArgs, unwrapping: bool) -> Result<()> {
    let verb = if unwrapping { "unwrap" } else { "wrap" };

    let proposed = wrap::scan_and_apply(true, unwrapping)?;
    if proposed.is_empty() {
        if unwrapping {
            println!("No mcp-jail-wrapped entries found. Nothing to undo.");
            return Ok(());
        }
        let existing = wrap::scan_already_wrapped()?;
        if existing.is_empty() {
            println!(
                "No MCP servers found in any known client config.\n\
                 Install/configure an MCP client first, then re-run `mcp-jail wrap`."
            );
            return Ok(());
        }
        let reconciled = if a.no_auto_approve {
            ReconcileReport::default()
        } else {
            reconcile_allow_list(&existing)?
        };
        println!(
            "All {} MCP server entr{} in your client configs are already routed through mcp-jail.",
            existing.len(),
            if existing.len() == 1 { "y" } else { "ies" }
        );
        if reconciled.signed == 0 && reconciled.missing_manual.is_empty() {
            println!("Allow-list is in sync — nothing to do.");
        } else {
            if reconciled.signed > 0 {
                let word = if reconciled.signed == 1 { "server" } else { "servers" };
                println!(
                    "Re-approved {} wrapped {word} that were missing from the allow-list.",
                    reconciled.signed
                );
            }
            if !reconciled.missing_manual.is_empty() {
                println!();
                println!("The following wrapped server(s) use interpreter-eval flags and were NOT");
                println!("auto-approved — review argv and approve manually if you trust them:");
                for m in &reconciled.missing_manual {
                    println!("  • {m}");
                }
                println!("Run `mcp-jail approve <fp> --id <name> --dangerous` to allow.");
            }
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

    let report = if a.no_auto_approve {
        ReconcileReport::default()
    } else {
        let all: Vec<wrap::WrappedEntry> = applied
            .iter()
            .flat_map(|c| c.wrapped.iter().cloned())
            .collect();
        let mode = resolve_prompt_mode(&a);
        if matches!(mode, PromptMode::Ask) {
            println!();
            println!("Configuring sandbox for each server.");
            println!("Press Enter to accept the bracketed default. Choose [b]lock if unsure —");
            println!("you can grant more later with `mcp-jail approve`.");
        }
        approve_wrapped(&all, /* only_missing */ false, mode)?
    };
    let auto_signed = report.signed;
    let manual_needed = report.missing_manual;

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

    // No fp supplied → walk every pending entry one at a time on the TTY.
    // Makes "quick approval" a single command with no fingerprint-pasting.
    let fp = match a.fingerprint {
        Some(f) => f,
        None => return cmd_approve_interactive(&paths, &key),
    };
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

    if !a.dangerous
        && let Some(flag) = find_dangerous_flag(&pending.request.argv)
    {
        return Err(anyhow!(
            "argv contains interpreter-eval flag `{flag}`; re-run with --dangerous to allow"
        ));
    }

    // `--env NAME` at approve time would need the captured env VALUE to
    // recompute a matching fingerprint. As of this build, values are
    // redacted from `pending.jsonl` for security, so --env via pending
    // would silently sign a mismatching fingerprint. Force the operator
    // to bind env vars through `mcp-jail wrap` (which captures values
    // directly) instead.
    if !a.env.is_empty() {
        return Err(anyhow!(
            "--env is not supported on pending approvals (env values are redacted \
             from pending.jsonl for security). Re-run `mcp-jail wrap` to bind env \
             vars for an auto-discovered server, or edit allow.toml manually."
        ));
    }

    let id = a
        .id
        .unwrap_or_else(|| derive_id(&pending.request.argv, &pending.fingerprint));

    let env_subset: Vec<String> = Vec::new();

    let source_config = match a.source_config.or(pending.request.source_config.clone()) {
        Some(p) => {
            let h = hash_file(std::path::Path::new(&p))
                .ok_or_else(|| anyhow!("cannot read source config {p}"))?;
            Some(SourceConfig { path: p, hash: h })
        }
        None => None,
    };

    // Recompute the fingerprint with an EMPTY env_subset to match what
    // `evaluate()` will compute at spawn time (runtime also uses
    // entry.env_subset, which is empty here). We don't reuse the stored
    // pending.fingerprint because that one was computed via
    // `fingerprint_full` (every env key), which wouldn't match runtime.
    // `fingerprint(&[])` needs no env values — unaffected by redaction.
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

/// Walk every pending entry on the TTY: show argv, ask A/s/d/q. Approving
/// picks a sensible sandbox (trusted-defaults for network-looking commands
/// else loopback-only). Skipping leaves the entry for later. Deleting drops
/// it. Refuses interpreter-eval argvs without `--dangerous` (operator must
/// intentionally re-run with a fingerprint + `--dangerous` for those).
fn cmd_approve_interactive(paths: &Paths, key: &ed25519_dalek::SigningKey) -> Result<()> {
    use std::io::{BufRead, IsTerminal, Write};

    let pending = load_pending(paths)?;
    if pending.is_empty() {
        println!("No pending approvals.");
        return Ok(());
    }
    if !std::io::stdin().is_terminal() {
        eprintln!(
            "{} pending — run `mcp-jail approve` from a terminal to review interactively.",
            pending.len()
        );
        for p in &pending {
            eprintln!("  fp={}  argv={}", &p.fingerprint[..12], format_argv(&p.request.argv));
        }
        return Ok(());
    }

    let mut allow = load_allow(paths)?;
    let mut approved = 0usize;
    let mut skipped = 0usize;
    let mut deleted = 0usize;
    let total = pending.len();

    println!("{total} pending approval(s). Press Enter to approve each, or type s/d/q.");
    println!();

    for (idx, p) in pending.iter().enumerate() {
        println!("── \x1b[1m[{}/{total}]\x1b[0m  fp={}", idx + 1, &p.fingerprint[..12]);
        println!("   cmd: {}", format_argv(&p.request.argv));
        let hits = p.hit_count.unwrap_or(1);
        if hits > 1 {
            println!("   ({hits} blocked attempts, last seen {})",
                p.last_seen.unwrap_or(p.ts).format("%Y-%m-%d %H:%M:%S"));
        }
        if let Some(flag) = find_dangerous_flag(&p.request.argv) {
            println!("   \x1b[33m⚠  argv uses interpreter-eval flag `{flag}`.\x1b[0m");
            println!("   \x1b[33m   Skipping — re-run with: mcp-jail approve {} --dangerous\x1b[0m",
                &p.fingerprint[..12]);
            skipped += 1;
            println!();
            continue;
        }

        print!("   [A]pprove / [s]kip / [d]elete / [q]uit > ");
        std::io::stdout().flush().ok();
        let mut line = String::new();
        if std::io::stdin().lock().read_line(&mut line).is_err() {
            break;
        }
        match line.trim().chars().next().unwrap_or('a').to_ascii_lowercase() {
            'q' => break,
            's' => { skipped += 1; }
            'd' => {
                store::clear_pending_for(paths, &p.fingerprint).ok();
                deleted += 1;
            }
            _ => {
                let id = derive_id(&p.request.argv, &p.fingerprint);
                let sandbox = trusted_sandbox_for(&p.request.argv);
                let source_config = p.request.source_config.as_deref().and_then(|path| {
                    hash_file(std::path::Path::new(path)).map(|hash| SourceConfig {
                        path: path.to_owned(),
                        hash,
                    })
                });
                let mut entry = AllowEntry {
                    id: id.clone(),
                    fingerprint: p.request.fingerprint(&[]),
                    argv: p.request.argv.clone(),
                    command: p.request.command.clone(),
                    cwd: p.request.cwd.clone(),
                    env_subset: Vec::new(),
                    dangerous: false,
                    source_config,
                    sandbox,
                    signed_at: Utc::now(),
                    signature: String::new(),
                };
                sign_entry(key, &mut entry)?;
                sandbox::write_profile(&paths.root, &entry)?;
                allow.entries.retain(|e| e.id != entry.id);
                allow.entries.push(entry.clone());
                save_allow(paths, &allow)?;
                store::clear_pending_for(paths, &p.fingerprint).ok();
                audit::append(
                    &paths.audit,
                    audit::Record {
                        ts: Utc::now(),
                        prev_hash: String::new(),
                        decision: "approve".to_owned(),
                        fingerprint: entry.fingerprint.clone(),
                        id: Some(entry.id.clone()),
                        reason: "interactive approval".to_owned(),
                        pid: process::id(),
                        this_hash: String::new(),
                    },
                )?;
                println!("   ✓ approved as `{id}`");
                approved += 1;
            }
        }
        println!();
    }

    println!("Done. {approved} approved, {skipped} skipped, {deleted} deleted.");
    Ok(())
}

fn needs_network(argv: &[String]) -> bool {
    let Some(cmd) = argv.first() else { return false };
    let base = std::path::Path::new(cmd)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(cmd);
    matches!(
        base,
        "ssh" | "scp" | "curl" | "wget" | "rsync" | "mosh" | "nc" | "ncat" | "socat"
    )
}

fn shorten_home(s: &str) -> String {
    if let Some(home) = dirs::home_dir().and_then(|p| p.to_str().map(str::to_owned))
        && let Some(rest) = s.strip_prefix(&home)
    {
        return format!("~{rest}");
    }
    s.to_owned()
}

fn format_argv(argv: &[String]) -> String {
    argv.iter()
        .map(|a| {
            let s = shorten_home(a);
            if s.contains(' ') { format!("\"{s}\"") } else { s }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn format_net(items: &[String]) -> String {
    if items.is_empty() {
        "net:      BLOCKED (no egress)".into()
    } else {
        format!("net:      allow {}", items.join(", "))
    }
}

fn format_fs_read(items: &[String], secrets: &[String]) -> String {
    let mut extra: Vec<String> = items.iter().map(|s| shorten_home(s)).collect();
    extra.extend(secrets.iter().map(|s| format!("{} (override)", shorten_home(s))));
    if extra.is_empty() {
        "fs_read:  default — host creds blocked (~/.ssh, ~/.aws, Keychains)".into()
    } else {
        format!(
            "fs_read:  default + grants: {}",
            extra.join(", ")
        )
    }
}

fn format_fs_write(items: &[String]) -> String {
    if items.is_empty() {
        "fs_write: /tmp, /var/folders only".into()
    } else {
        let extra: Vec<String> = items.iter().map(|s| shorten_home(s)).collect();
        format!("fs_write: /tmp + {}", extra.join(", "))
    }
}

fn format_dangerous(d: bool) -> &'static str {
    if d {
        "dangerous-flags: ALLOWED (-c / -e / /c)"
    } else {
        "dangerous-flags: blocked"
    }
}

fn cmd_list() -> Result<()> {
    let paths = Paths::default();
    let allow = load_allow(&paths)?;

    // Auto-prune anything older than PENDING_MAX_AGE_DAYS so the queue
    // doesn't accumulate attack-replay cruft. Then drop entries that
    // match a signed approval (argv was later allow-listed).
    let age_pruned = auto_prune_pending(&paths)?;
    let mut pending = load_pending(&paths)?;
    let before = pending.len();
    pending.retain(|p| {
        !allow
            .entries
            .iter()
            .any(|e| e.argv == p.request.argv && e.command == p.request.command)
    });
    let approve_pruned = before - pending.len();
    if approve_pruned > 0 {
        store::save_pending(&paths, &pending)?;
    }
    let pruned = age_pruned + approve_pruned;

    println!("# approved ({})", allow.entries.len());
    if allow.entries.is_empty() {
        println!("  (none — run `mcp-jail wrap` to populate)");
    }
    for e in &allow.entries {
        let src = e
            .source_config
            .as_ref()
            .map(|s| shorten_home(&s.path))
            .unwrap_or_else(|| "(none)".into());
        println!("  {}  fp={}", e.id, &e.fingerprint[..12]);
        println!("    cmd: {}", format_argv(&e.argv));
        println!("    src: {src}");
        println!("    {}", format_net(&e.sandbox.net));
        println!("    {}", format_fs_read(&e.sandbox.fs_read, &e.sandbox.fs_read_secret));
        println!("    {}", format_fs_write(&e.sandbox.fs_write));
        println!("    {}", format_dangerous(e.dangerous));
        if needs_network(&e.argv) && e.sandbox.net.is_empty() {
            println!(
                "    \x1b[33m⚠  this command looks network-dependent but net is BLOCKED;\x1b[0m"
            );
            println!(
                "    \x1b[33m   grant with: mcp-jail approve {} --id {} --net <host>\x1b[0m",
                &e.fingerprint[..12],
                e.id,
            );
        }
    }

    println!();
    println!("Baselines applied to every entry (not about target/pentest data — only YOUR host):");
    println!("  • fs_read  — all paths OK except: ~/.ssh ~/.aws ~/.gcp ~/.azure ~/.config/{{gh,gcloud,op}}");
    println!("               ~/.gnupg ~/.password-store ~/.docker ~/.kube shell histories,");
    println!("               Library/Keychains, 1Password/Bitwarden, browser storage, /etc/shadow, /etc/ssh");
    println!("  • fs_write — denied everywhere except /tmp, /private/var/folders (scratch)");
    println!("  • net      — per-entry policy shown above");
    println!();
    println!("Target files at ~/targets, ~/loot, etc. are NOT blocked. Override a specific");
    println!("secret path if you truly need it: mcp-jail approve <fp> --id <name> --fs-read-secret <path>");

    if !pending.is_empty() {
        // Sort newest-last-seen first so interesting attempts surface.
        let mut sorted = pending.clone();
        sorted.sort_by(|a, b| {
            let a_ts = a.last_seen.unwrap_or(a.ts);
            let b_ts = b.last_seen.unwrap_or(b.ts);
            b_ts.cmp(&a_ts)
        });
        let shown = 20usize;
        println!();
        println!("# pending ({})", pending.len());
        for p in sorted.iter().take(shown) {
            let hits = p.hit_count.unwrap_or(1);
            let last = p.last_seen.unwrap_or(p.ts);
            let hits_suffix = if hits > 1 {
                format!("  ({hits} hits, last {})", last.format("%Y-%m-%d %H:%M:%S"))
            } else {
                format!("  ({})", p.ts.format("%Y-%m-%d %H:%M:%S"))
            };
            println!("  fp={}{hits_suffix}", &p.fingerprint[..12]);
            println!("    argv: {}", format_argv(&p.request.argv));
        }
        if pending.len() > shown {
            println!("  … {} more — `mcp-jail prune --all` to clear the queue",
                pending.len() - shown);
        }
        println!();
        println!("Approve legitimate entries: mcp-jail approve <fp-prefix> --id <name>");
        println!("Clear attack-replay cruft:  mcp-jail prune --all");
        if pruned > 0 {
            println!("(auto-pruned {pruned} stale entr{} this run)",
                if pruned == 1 { "y" } else { "ies" });
        }
    } else if pruned > 0 {
        println!();
        println!("(pruned {pruned} stale pending entr{})",
            if pruned == 1 { "y" } else { "ies" });
    }
    Ok(())
}

/// Terse one-liner, safe to call from a shell prompt hook. Silent when
/// nothing is pending so prompts stay clean. When pending entries exist,
/// prints a yellow warning line and exits non-zero so status-bar widgets
/// can color themselves red.
fn cmd_status() -> Result<()> {
    let paths = Paths::default();
    let _ = auto_prune_pending(&paths);
    let pending = load_pending(&paths).unwrap_or_default();
    if pending.is_empty() {
        return Ok(());
    }
    let word = if pending.len() == 1 { "server" } else { "servers" };
    eprintln!(
        "\x1b[33m⚠  {} MCP {word} awaiting mcp-jail approval — run `mcp-jail approve`\x1b[0m",
        pending.len()
    );
    std::process::exit(2);
}

fn cmd_prune(a: PruneArgs) -> Result<()> {
    let paths = Paths::default();
    let all = load_pending(&paths).unwrap_or_default();
    if all.is_empty() {
        println!("pending queue is empty");
        return Ok(());
    }
    let before = all.len();

    // Scope: --fp > --older-than > --all (or default-all).
    let kept: Vec<PendingEntry> = if let Some(prefix) = a.fingerprint.as_deref() {
        if prefix.len() < 6 {
            return Err(anyhow!("--fp prefix must be >=6 hex chars"));
        }
        all.into_iter()
            .filter(|p| !p.fingerprint.starts_with(prefix))
            .collect()
    } else if let Some(days) = a.older_than {
        if days < 0 {
            return Err(anyhow!("--older-than must be >= 0"));
        }
        let cutoff = Utc::now() - chrono::Duration::days(days);
        all.into_iter()
            .filter(|p| p.last_seen.unwrap_or(p.ts) >= cutoff)
            .collect()
    } else {
        // Default: wipe everything. `--all` is explicit-but-redundant.
        let _ = a.all;
        Vec::new()
    };

    let pruned = before - kept.len();
    store::save_pending(&paths, &kept)?;
    println!("pruned {pruned} pending entr{}, {} remaining",
        if pruned == 1 { "y" } else { "ies" },
        kept.len());
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
            let mut persisted = req.clone();
            persisted.redact_env();
            let is_new = upsert_pending(
                &paths,
                PendingEntry {
                    ts: Utc::now(),
                    fingerprint: fp_full.clone(),
                    request: persisted,
                    reason: reason.clone(),
                    last_seen: None,
                    hit_count: None,
                },
            )?;
            if is_new {
                crate::notify::blocked_spawn(&req.argv, &fp_full);
            }
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
        if !entry.dangerous
            && let Some(flag) = find_dangerous_flag(&req.argv)
        {
            return Err(JailError::DangerousFlag(flag).to_string());
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

    let argv = a.argv.clone();
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
            let dangerous = find_dangerous_flag(&argv).is_some();

            let mut persisted = req.clone();
            persisted.redact_env();
            let is_new = upsert_pending(
                &paths,
                crate::store::PendingEntry {
                    ts: Utc::now(),
                    fingerprint: fp.clone(),
                    request: persisted,
                    reason: reason.clone(),
                    last_seen: None,
                    hit_count: None,
                },
            )?;
            if is_new {
                crate::notify::blocked_spawn(&argv, &fp);
            }

            if !dangerous {
                match crate::prompt::ask(&argv, a.source_config.as_deref()) {
                    crate::prompt::Decision::Approve => {
                        return approve_and_exec(&paths, &req, &a);
                    }
                    crate::prompt::Decision::Deny
                    | crate::prompt::Decision::Timeout
                    | crate::prompt::Decision::NoGui => {}
                }
            }

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

            let fp12 = &fp[..12];
            let src = a.source_config.as_deref().unwrap_or("(unknown)");
            eprintln!("mcp-jail: blocked new MCP server");
            eprintln!("  command:     {}", argv.join(" "));
            eprintln!("  source:      {src}");
            eprintln!("  fingerprint: {fp12}");
            eprintln!();
            if dangerous {
                eprintln!("Argv uses an interpreter-eval flag (`-c`, `-e`, `/c`).");
                eprintln!("Manual approval required:");
                eprintln!("  mcp-jail approve {fp12} --dangerous  (and add sandbox flags)");
            } else {
                eprintln!("Approve this server (walks pending one at a time):");
                eprintln!("  mcp-jail approve");
            }
            eprintln!();
            eprintln!("Review or tune:");
            eprintln!("  mcp-jail list");
            eprintln!("  mcp-jail approve --help");
            std::process::exit(126);
        }
    }
}

fn approve_and_exec(
    paths: &Paths,
    req: &SpawnRequest,
    a: &ExecArgs,
) -> Result<()> {
    let key = ensure_key(paths)?;
    let fp = req.fingerprint(&[]);
    let id = a.id.clone().unwrap_or_else(|| derive_id(&req.argv, &fp));
    let sandbox = trusted_sandbox_for(&req.argv);
    let source_config = a
        .source_config
        .clone()
        .or_else(|| req.source_config.clone())
        .map(|p| SourceConfig {
            path: p,
            hash: String::new(),
        });
    let mut entry = AllowEntry {
        id,
        fingerprint: fp,
        argv: req.argv.clone(),
        command: req.command.clone(),
        cwd: String::new(),
        env_subset: Vec::new(),
        dangerous: false,
        source_config,
        sandbox,
        signed_at: Utc::now(),
        signature: String::new(),
    };
    sign_entry(&key, &mut entry)?;

    let mut allow = load_allow(paths)?;
    allow.entries.retain(|e| e.id != entry.id);
    allow.entries.push(entry.clone());
    save_allow(paths, &allow)?;
    clear_pending_for(paths, &entry.fingerprint)?;

    audit::append(
        &paths.audit,
        audit::Record {
            ts: Utc::now(),
            prev_hash: String::new(),
            decision: "approve".to_owned(),
            fingerprint: entry.fingerprint.clone(),
            id: Some(entry.id.clone()),
            reason: "user approved via modal".to_owned(),
            pid: process::id(),
            this_hash: String::new(),
        },
    )?;

    let profile = sandbox::write_profile(&paths.root, &entry)?;
    let wrapped = sandbox::wrap_argv(&profile, &entry.command, &entry.argv)?;
    audit::append(
        &paths.audit,
        audit::Record {
            ts: Utc::now(),
            prev_hash: String::new(),
            decision: "allow".to_owned(),
            fingerprint: entry.fingerprint.clone(),
            id: Some(entry.id.clone()),
            reason: "modal-approved, first exec".to_owned(),
            pid: process::id(),
            this_hash: String::new(),
        },
    )?;
    exec_or_die(&wrapped, &entry.env_subset)?;
    unreachable!()
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

