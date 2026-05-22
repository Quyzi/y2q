//! Contract test for Tier-2 daemon-gated stub commands: every stub must exit
//! with code 64 and, in --json mode, emit `{"error":"not_yet_supported",...}`.

use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_y2q");

/// (args) tuples — one representative invocation per stub command.
const STUB_INVOCATIONS: &[&[&str]] = &[
    &["tag", "set", "local/b/k", "k=v"],
    &["attribute", "set", "local/b/k", "k=v"],
    &["version", "enable", "local/b"],
    &["undo", "local/b/k"],
    &["retention", "info", "local/b/k"],
    &["legalhold", "info", "local/b/k"],
    &["share", "download", "local/b/k"],
    &["anonymous", "get", "local/b"],
    &["cors", "get", "local/b"],
    &["quota", "info", "local/b"],
    &["inventory", "ls", "local/b"],
    &["ilm", "rule", "ls", "local/b"],
    &["encrypt", "info", "local/b"],
    &["event", "ls", "local/b"],
    &["batch", "ls", "local"],
];

#[test]
fn stubs_exit_64() {
    for args in STUB_INVOCATIONS {
        let out = Command::new(BIN)
            .args(*args)
            .output()
            .expect("run y2q stub");
        assert_eq!(
            out.status.code(),
            Some(64),
            "command {args:?} should exit 64, got {:?}",
            out.status.code()
        );
    }
}

#[test]
fn stubs_emit_json_error() {
    for args in STUB_INVOCATIONS {
        let mut full = vec!["--json"];
        full.extend_from_slice(args);
        let out = Command::new(BIN)
            .args(&full)
            .output()
            .expect("run y2q stub --json");
        let stdout = String::from_utf8_lossy(&out.stdout);
        let v: serde_json::Value = serde_json::from_str(stdout.trim())
            .unwrap_or_else(|e| panic!("command {args:?} stdout not JSON ({e}): {stdout:?}"));
        assert_eq!(
            v["error"], "not_yet_supported",
            "command {args:?} should report not_yet_supported"
        );
        assert!(
            v["command"].is_string() && v["gate"].is_string(),
            "command {args:?} JSON missing command/gate fields: {v}"
        );
    }
}
