
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SpawnRequest {
    pub command: String,
    pub argv: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub cwd: String,
    #[serde(default)]
    pub source_config: Option<String>,
}

impl SpawnRequest {
    /// Replace every env value with an empty string, keeping only the keys.
    /// Called before a SpawnRequest is persisted to `pending.jsonl` so that
    /// secrets (OPENAI_API_KEY, SSH agent sockets, etc.) captured from the
    /// spawning process never hit disk. Fingerprints are computed BEFORE
    /// this runs and stored separately on the PendingEntry, so redaction
    /// does not affect matching.
    pub fn redact_env(&mut self) {
        for v in self.env.values_mut() {
            v.clear();
        }
    }

    #[must_use]
    pub fn fingerprint(&self, env_subset: &[String]) -> String {
        let mut env: BTreeMap<&str, &str> = BTreeMap::new();
        for k in env_subset {
            if let Some(v) = self.env.get(k) {
                env.insert(k.as_str(), v.as_str());
            }
        }
        let doc = serde_json::json!({
            "command": resolve_command(&self.command),
            "argv": self.argv,
            "env": env,
        });
        let bytes = serde_json::to_vec(&doc).unwrap_or_default();
        let digest = Sha256::digest(&bytes);
        hex::encode(digest)
    }

    #[must_use]
    pub fn fingerprint_full(&self) -> String {
        let keys: Vec<String> = self.env.keys().cloned().collect();
        self.fingerprint(&keys)
    }
}

fn resolve_command(cmd: &str) -> String {
    let p = Path::new(cmd);
    if p.is_absolute() {
        return std::fs::canonicalize(p)
            .map(|p| p.display().to_string())
            .unwrap_or_else(|_| cmd.to_owned());
    }
    if let Some(path_env) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path_env) {
            let candidate = dir.join(p);
            if candidate.is_file() {
                return std::fs::canonicalize(&candidate)
                    .map(|p| p.display().to_string())
                    .unwrap_or_else(|_| candidate.display().to_string());
            }
        }
    }
    cmd.to_owned()
}

pub const DANGEROUS_FLAGS: &[&str] = &[
    "-c",
    "-C",
    "--command",
    "-e",
    "-E",
    "--eval",
    "--exec",
    "/c",
    "/C",
    "-Command",
    "-EncodedCommand",
    "-EncodedArguments",
    "-m",
    "--module",
    "-r",
    "--require",
    "--import",
    "-p",
    "--print",
    "--rcfile",
    "--init-file",
    "-f",
    "--file",
];

/// Short flags known to accept an inline value concatenated right after
/// the flag letter (POSIX `-c CODE` also accepted as `-cCODE`). Any
/// short flag NOT in this table refuses to match its greedy-prefix form
/// so benign flags like `find -exec` aren't misread as `-e` + `xec`.
const INLINE_VALUE_SHORTS: &[&str] = &[
    "-c", "-C", "-e", "-E", "-m", "-r", "-p", "-f",
];

fn argv0_basename(argv: &[String]) -> String {
    let Some(first) = argv.first() else {
        return String::new();
    };
    Path::new(first)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(first.as_str())
        .to_ascii_lowercase()
}

/// Interpreter-aware check for eval-class argv. Runs the existing
/// DANGEROUS_FLAGS prefix match FIRST (with the safer short-flag rule),
/// then applies a per-binary rule. Returns a stable string identifying
/// the matched rule.
#[must_use]
pub fn find_dangerous_flag(argv: &[String]) -> Option<String> {
    // 1. Generic flag table.
    for a in argv.iter().skip(1) {
        if DANGEROUS_FLAGS.iter().any(|f| a == *f) {
            return Some(a.clone());
        }
        for f in DANGEROUS_FLAGS {
            if !a.starts_with(f) || a.len() <= f.len() {
                continue;
            }
            let is_short_flag = f.len() == 2 && f.starts_with('-') && !f.starts_with("--");
            let next = a.as_bytes()[f.len()];
            if next == b'=' {
                return Some((*f).to_owned());
            }
            if is_short_flag && INLINE_VALUE_SHORTS.contains(f) {
                // Known short flag that accepts an inline value. `-cPAYLOAD`
                // is a smuggling vector; `find -exec` is benign because
                // `-e` is NOT in INLINE_VALUE_SHORTS actually — wait,
                // `-e` IS here. Refine: only flag if the next char is
                // non-alpha OR the payload looks like code (contains a
                // character that could not start a long-flag name).
                // For `find -exec`: argv element is `-exec`. We WOULD
                // flag `-e` here. Mitigate by requiring that the
                // interpreter for this argv plausibly accepts inline
                // code (see per-binary rule below which runs first when
                // argv[0] is a known interpreter). For a random argv[0]
                // like /usr/bin/find, we don't want this to trip.
                //
                // Resolution: only apply short-flag inline-value match
                // when argv[0] is a known code-eval binary.
                let base = argv0_basename(argv);
                if is_code_eval_binary(&base) {
                    return Some((*f).to_owned());
                }
            }
        }
    }

    // 2. Per-binary deep inspection.
    let base = argv0_basename(argv);
    if let Some(r) = interpreter_rule(&base, argv) {
        return Some(r);
    }
    None
}

fn is_code_eval_binary(base: &str) -> bool {
    matches!(
        base,
        "python" | "python2" | "python3"
        | "node" | "nodejs" | "bun" | "deno"
        | "ruby" | "perl"
        | "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "mksh"
        | "pwsh" | "powershell"
    ) || base.starts_with("python3.")
}

fn interpreter_rule(base: &str, argv: &[String]) -> Option<String> {
    let rest: &[String] = argv.get(1..).unwrap_or(&[]);

    // Shells: -s, -i, bare `-`, or no positional script argument at all
    // (all args begin with '-' or there ARE no args → reads stdin, and
    // an MCP host's stdin is attacker-controlled).
    if matches!(base, "sh" | "bash" | "zsh" | "dash" | "ksh" | "ash" | "mksh") {
        for a in rest {
            if a == "-s" || a == "-i" || a == "-" {
                return Some(format!("{base} {a}"));
            }
        }
        let has_script = rest.iter().any(|a| !a.starts_with('-'));
        if !has_script {
            return Some(format!("{base} (no script arg → reads stdin)"));
        }
    }

    // Python: decompose combined short flags (-Ic / -Ec / -Sc) and
    // detect `-m` anywhere. Long-form and plain `-c`/`-m` are caught by
    // the generic table above.
    if base == "python" || base == "python2" || base == "python3" || base.starts_with("python3.") {
        for a in rest {
            if let Some(body) = a.strip_prefix('-')
                && !a.starts_with("--")
                && body.chars().all(|c| c.is_ascii_alphabetic())
                && (body.contains('c') || body.contains('m'))
            {
                return Some(format!("python {a} (combined -c/-m)"));
            }
        }
    }

    // Perl: -x / -X (loads script embedded in another file; eval-class).
    if base == "perl" {
        for a in rest {
            if a == "-x" || a == "-X" {
                return Some(format!("perl {a}"));
            }
        }
    }

    // Node / Bun: dangerous loader flags.
    if matches!(base, "node" | "nodejs" | "bun") {
        for a in rest {
            let key = a.split('=').next().unwrap_or(a);
            if matches!(
                key,
                "--loader"
                | "--experimental-loader"
                | "--import-map"
                | "--experimental-vm-modules"
                | "--inspect-brk"
            ) {
                return Some(format!("{base} {key}"));
            }
        }
    }

    // Deno: `eval`, `repl`, `run` subcommands.
    if base == "deno"
        && let Some(first_nonflag) = rest.iter().find(|a| !a.starts_with('-'))
        && matches!(first_nonflag.as_str(), "eval" | "repl" | "run")
    {
        return Some(format!("deno {first_nonflag}"));
    }

    // awk / gawk / mawk / nawk: without `-f FILE` the program is inline.
    if matches!(base, "awk" | "gawk" | "mawk" | "nawk") {
        let mut has_f = false;
        let mut i = 0;
        while i < rest.len() {
            let a = &rest[i];
            if a == "-f" || a == "--file" {
                has_f = true;
                break;
            }
            if a.starts_with("-f") || a.starts_with("--file=") {
                has_f = true;
                break;
            }
            i += 1;
        }
        if !has_f {
            return Some(format!("{base} (inline program; no -f)"));
        }
    }

    // env -S / --split-string: smuggles a whole new argv.
    if base == "env" {
        for a in rest {
            if a == "-S" || a == "--split-string" || a.starts_with("-S") || a.starts_with("--split-string=") {
                return Some("env -S (splits string into argv)".to_owned());
            }
        }
    }

    None
}

#[must_use]
pub fn hash_file(path: &Path) -> Option<String> {
    let bytes = std::fs::read(path).ok()?;
    Some(hex::encode(Sha256::digest(&bytes)))
}

/// Stat + hash a regular file, returning `(sha256_hex, size_bytes,
/// mtime_ns)`. Used to bind argv[1..] paths to their content at approve
/// time so a later content swap is refused at exec. Returns `None` for
/// non-regular or unreadable paths — those are treated as "not a file"
/// positionals.
#[must_use]
pub fn hash_stat_file(path: &Path) -> Option<(String, u64, i128)> {
    let meta = std::fs::metadata(path).ok()?;
    if !meta.is_file() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let hash = hex::encode(Sha256::digest(&bytes));
    let size = meta.len();
    // mtime_ns as i128 — plenty of range, signed to survive weird clocks.
    let mtime_ns: i128 = meta
        .modified()
        .ok()
        .and_then(|t| {
            t.duration_since(std::time::SystemTime::UNIX_EPOCH)
                .map(|d| i128::from(d.as_nanos() as u64))
                .ok()
        })
        .unwrap_or(0);
    Some((hash, size, mtime_ns))
}

/// Reject strings that would corrupt TOML/JSON serialization or break
/// out of a sandbox-profile literal. Mirrors `sandbox::validate_sb_token`
/// but with `(`/`)` allowed (harmless outside sandbox tokens) and a
/// single descriptive error. Used on argv, env values, cwd, and every
/// user-supplied --fs-read/--fs-write/--env/--net string before it is
/// persisted or signed.
pub fn validate_no_control(s: &str, field: &str) -> anyhow::Result<()> {
    for b in s.as_bytes() {
        if *b < 0x20 && *b != b'\t' {
            return Err(anyhow::anyhow!(
                "{field} contains forbidden control byte 0x{:02x}; refusing",
                b
            ));
        }
        if *b == 0x7f {
            return Err(anyhow::anyhow!(
                "{field} contains DEL (0x7f); refusing"
            ));
        }
    }
    Ok(())
}

#[must_use]
pub fn home() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(argv: &[&str]) -> SpawnRequest {
        SpawnRequest {
            command: argv[0].to_owned(),
            argv: argv.iter().map(|s| (*s).to_owned()).collect(),
            env: BTreeMap::new(),
            cwd: "/tmp".to_owned(),
            source_config: None,
        }
    }

    #[test]
    fn fingerprint_is_stable() {
        let r1 = req(&["/bin/echo", "hello"]);
        let r2 = req(&["/bin/echo", "hello"]);
        assert_eq!(r1.fingerprint(&[]), r2.fingerprint(&[]));
    }

    #[test]
    fn fingerprint_sensitive_to_argv() {
        let r1 = req(&["/bin/echo", "hello"]);
        let r2 = req(&["/bin/echo", "world"]);
        assert_ne!(r1.fingerprint(&[]), r2.fingerprint(&[]));
    }

    #[test]
    fn detects_dangerous_flag() {
        assert_eq!(
            find_dangerous_flag(&["python".to_owned(), "-c".to_owned(), "print(1)".to_owned()])
                .as_deref(),
            Some("-c")
        );
        assert_eq!(
            find_dangerous_flag(&["node".to_owned(), "--eval=1+1".to_owned()]).as_deref(),
            Some("--eval")
        );
        assert_eq!(
            find_dangerous_flag(&["uvx".to_owned(), "server".to_owned()]),
            None
        );
    }

    #[test]
    fn detects_concatenated_short_flags() {
        // -c followed by inline code, no separator — bypass of naive checks.
        assert_eq!(
            find_dangerous_flag(&["python3".to_owned(), "-cprint(1)".to_owned()]).as_deref(),
            Some("-c")
        );
        assert_eq!(
            find_dangerous_flag(&["node".to_owned(), "-econsole.log(1)".to_owned()]).as_deref(),
            Some("-e")
        );
        assert_eq!(
            find_dangerous_flag(&["python3".to_owned(), "-mhttp.server".to_owned()]).as_deref(),
            Some("-m")
        );
        assert_eq!(
            find_dangerous_flag(&["ruby".to_owned(), "-rnet/http".to_owned()]).as_deref(),
            Some("-r")
        );
    }

    #[test]
    fn ignores_unrelated_short_prefixes() {
        // `--command` is a long flag; bare `--command-foo` is not eval.
        assert_eq!(
            find_dangerous_flag(&["rustc".to_owned(), "--crate-name=foo".to_owned()]),
            None
        );
        // `-p` is listed (node --print); but `-pretty` isn't a valid node flag.
        // We still flag it because single-dash short flags bind greedily to any
        // suffix. Acceptable false-positive (user can --dangerous).
    }
}
