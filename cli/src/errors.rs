use thiserror::Error;

#[derive(Error, Debug)]
pub enum JailError {
    #[error("unknown fingerprint {0}; run `mcp-jail approve {0}` after review")]
    UnknownFingerprint(String),
    #[error("argv contains interpreter-eval flag `{0}`; approve with --dangerous to allow")]
    DangerousFlag(String),
    #[error("source config at {path} changed since approval (hash {actual} != expected {expected})")]
    ConfigDrift {
        path: String,
        expected: String,
        actual: String,
    },
    #[error("sandbox helper unavailable for this platform")]
    #[allow(dead_code)]
    NoSandbox,
}
