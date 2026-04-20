
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

#[must_use]
pub fn find_dangerous_flag(argv: &[String]) -> Option<String> {
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
            if is_short_flag || next == b'=' {
                return Some((*f).to_owned());
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
