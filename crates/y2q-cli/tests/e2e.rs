//! End-to-end harness: spawns a real `y2qd` (the locally built, and under
//! `cargo llvm-cov` instrumented, binary) over plaintext HTTP against
//! throwaway temp directories, then drives the `y2q` CLI as subprocesses.
//!
//! Because both binaries are the local build, `LLVM_PROFILE_FILE` is inherited
//! by the spawned processes and their coverage is collected — this is what
//! exercises the network/IO code paths (CLI `cmd/*`, `y2q-client`, and the
//! `y2qd` handlers/storage) that no unit test can reach.
//!
//! The whole flow lives in one `#[test]` so the server is started once.

use std::io::{BufRead, BufReader, Read};
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the `y2qd` binary, in the same dir as the `y2q` bin Cargo hands us.
fn y2qd_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_y2q"))
        .parent()
        .expect("bin dir")
        .join("y2qd")
}

/// Ensure the `y2qd` binary exists, building it if necessary. `y2qd` lives in a
/// different package and is not built as a dependency of this crate's tests, so
/// neither `cargo test` nor `cargo llvm-cov --workspace` produce the standalone
/// binary. Building it here via the inherited `CARGO`/`RUSTFLAGS`/`CARGO_TARGET_DIR`
/// environment places it next to `y2q` — and, under `cargo llvm-cov`, builds it
/// with the same coverage instrumentation so its profile is collected too.
fn ensure_y2qd() -> Option<PathBuf> {
    let bin = y2qd_path();
    if bin.exists() {
        return Some(bin);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "-p", "y2qd"])
        .status()
        .ok()?;
    if status.success() && bin.exists() {
        Some(bin)
    } else {
        None
    }
}

fn y2q_bin() -> &'static str {
    env!("CARGO_BIN_EXE_y2q")
}

/// Path to the `y2q-warp` binary (sibling of `y2q`), building on demand. Like
/// `y2qd`, it lives in another package and isn't built for this crate's tests.
fn ensure_warp() -> Option<PathBuf> {
    let bin = PathBuf::from(env!("CARGO_BIN_EXE_y2q"))
        .parent()
        .expect("bin dir")
        .join("y2q-warp");
    if bin.exists() {
        return Some(bin);
    }
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let status = Command::new(cargo)
        .args(["build", "-p", "y2q-warp"])
        .status()
        .ok()?;
    (status.success() && bin.exists()).then_some(bin)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

struct Server {
    child: Child,
    port: u16,
    cfg_home: PathBuf,
    base: PathBuf,
    password: String,
    tls: bool,
}

impl Drop for Server {
    fn drop(&mut self) {
        // Stop with SIGTERM (not SIGKILL) so actix shuts down gracefully and the
        // instrumented binary flushes its coverage profile on normal exit.
        let pid = self.child.id();
        let _ = Command::new("kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status();
        // Give it a moment to exit cleanly, then ensure it's reaped.
        for _ in 0..40 {
            match self.child.try_wait() {
                Ok(Some(_)) => break,
                _ => std::thread::sleep(Duration::from_millis(50)),
            }
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

impl Server {
    /// Run `y2q <args>` against this server with an isolated config home.
    fn y2q(&self, args: &[&str]) -> std::process::Output {
        Command::new(y2q_bin())
            .env("XDG_CONFIG_HOME", &self.cfg_home)
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .expect("spawn y2q")
    }

    /// Run `y2q-warp <args>` against this server's config home.
    fn warp(&self, warp_bin: &PathBuf, args: &[&str]) -> std::process::Output {
        Command::new(warp_bin)
            .env("XDG_CONFIG_HOME", &self.cfg_home)
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .expect("spawn y2q-warp")
    }

    /// Run `y2q <args>` feeding `input` on stdin (for `pipe`).
    fn y2q_stdin(&self, args: &[&str], input: &[u8]) -> std::process::Output {
        use std::io::Write;
        let mut child = Command::new(y2q_bin())
            .env("XDG_CONFIG_HOME", &self.cfg_home)
            .env("NO_COLOR", "1")
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn y2q");
        child.stdin.take().unwrap().write_all(input).unwrap();
        child.wait_with_output().expect("wait y2q")
    }

    /// Run `y2q <args>`, asserting success and surfacing stderr on failure.
    fn ok(&self, args: &[&str]) {
        let out = self.y2q(args);
        if !out.status.success() {
            panic!(
                "`y2q {}` failed (status {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
                args.join(" "),
                out.status.code(),
                String::from_utf8_lossy(&out.stdout),
                String::from_utf8_lossy(&out.stderr),
            );
        }
    }

    fn url(&self) -> String {
        let scheme = if self.tls { "https" } else { "http" };
        format!("{scheme}://127.0.0.1:{}", self.port)
    }
}

/// Generate a throwaway self-signed cert+key into `dir` via the system openssl.
/// Returns `None` if openssl is unavailable (test then skips the TLS path).
fn gen_self_signed(dir: &std::path::Path) -> Option<(PathBuf, PathBuf)> {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=localhost",
            "-keyout",
            key.to_str().unwrap(),
            "-out",
            cert.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .ok()?;
    (status.success() && cert.exists() && key.exists()).then_some((cert, key))
}

fn start_server() -> Option<Server> {
    start_server_tls(None)
}

/// Start a daemon. When `tls` is `Some((cert, key))`, serve HTTPS with those
/// PEM files and PQ-kex requirement relaxed (the throwaway cert is classical).
fn start_server_tls(tls: Option<(PathBuf, PathBuf)>) -> Option<Server> {
    let Some(bin) = ensure_y2qd() else {
        eprintln!("skipping e2e: could not locate or build the y2qd binary");
        return None;
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("y2q-e2e-{}-{}", std::process::id(), nanos));
    let data = base.join("data");
    let keys = base.join("keys");
    let cfg_home = base.join("cfg");
    for d in [&data, &keys, &cfg_home] {
        std::fs::create_dir_all(d).unwrap();
    }

    let port = free_port();
    let mut cmd = Command::new(&bin);
    cmd.env("Y2QD_SERVER__HOST", "127.0.0.1")
        .env("Y2QD_SERVER__PORT", port.to_string())
        .env("Y2QD_STORAGE__BASE_PATH", &data)
        .env("Y2QD_CRYPTO__KEYSTORE_DIR", &keys)
        // Cheap KDF params so first-run + login are fast in tests.
        .env("Y2QD_CRYPTO__ARGON2__M_COST_KIB", "8")
        .env("Y2QD_CRYPTO__ARGON2__T_COST", "1")
        .env("Y2QD_CRYPTO__ARGON2__P_COST", "1")
        .env("Y2QD_AUTH__MIN_LOGIN_RESPONSE_MS", "0")
        .env("Y2QD_OBSERVABILITY__LOG_FILTER", "error")
        .env("RUST_LOG", "error")
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let is_tls = tls.is_some();
    if let Some((cert, key)) = &tls {
        cmd.env("Y2QD_SERVER__TLS__ENABLED", "true")
            .env("Y2QD_SERVER__TLS__CERT_PATH", cert)
            .env("Y2QD_SERVER__TLS__KEY_PATH", key)
            .env("Y2QD_SERVER__TLS__REQUIRE_PQ_KEX", "false");
    } else {
        cmd.env("Y2QD_SERVER__TLS__ENABLED", "false");
    }
    let mut child = cmd.spawn().expect("spawn y2qd");

    // Parse the first-run root password from stdout, then drain the rest in a
    // background thread so the daemon never blocks on a full stdout pipe.
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);
    let mut password = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap_or(0) == 0 {
            break;
        }
        if let Some(p) = line.trim().strip_prefix("password:") {
            password = p.trim().to_string();
            break;
        }
        if Instant::now() > deadline {
            break;
        }
    }
    std::thread::spawn(move || {
        let mut sink = Vec::new();
        let _ = reader.read_to_end(&mut sink);
    });

    assert!(!password.is_empty(), "failed to capture first-run password");

    // Wait for the listener to accept connections.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "y2qd did not become ready");
        std::thread::sleep(Duration::from_millis(50));
    }

    Some(Server {
        child,
        port,
        cfg_home,
        base,
        password,
        tls: is_tls,
    })
}

fn ok(out: &std::process::Output) -> bool {
    out.status.success()
}

#[test]
fn e2e_full_cli_flow() {
    let Some(server) = start_server() else {
        return;
    };

    // ── alias + login ───────────────────────────────────────────────────────
    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    server.ok(&["alias", "list"]);
    server.ok(&["alias", "export"]);

    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    // ── buckets ──────────────────────────────────────────────────────────────
    server.ok(&["mb", "test/bucket"]);
    let _ = server.y2q(&["mb", "test/bucket", "--ignore-existing"]); // idempotent
    server.ok(&["ls", "test/"]);

    // ── upload / download / inspect ───────────────────────────────────────────
    let local = server.base.join("hello.txt");
    std::fs::write(&local, b"hello post-quantum world").unwrap();
    let local_s = local.to_str().unwrap();
    server.ok(&[
        "cp",
        local_s,
        "test/bucket/hello.txt",
        "--label",
        "env=test",
    ]);
    server.ok(&["ls", "test/bucket"]);
    server.ok(&["ls", "test/bucket", "--all"]);
    server.ok(&["stat", "test/bucket/hello.txt"]);
    server.ok(&["cat", "test/bucket/hello.txt"]);
    server.ok(&["head", "test/bucket/hello.txt", "-c", "5"]);

    let dl = server.base.join("out.txt");
    server.ok(&["get", "test/bucket/hello.txt", dl.to_str().unwrap()]);
    assert_eq!(std::fs::read(&dl).unwrap(), b"hello post-quantum world");

    // ── listing analytics ─────────────────────────────────────────────────────
    server.ok(&["du", "test/"]); // alias-only -> sums every bucket (sum_prefix)
    server.ok(&["du", "test/bucket"]);
    server.ok(&["du", "test/bucket", "--depth", "1"]);
    server.ok(&["tree", "test/bucket"]);
    server.ok(&["find", "test/bucket", "--name", "*.txt"]);
    server.ok(&["find", "test/bucket", "--size", "+1"]);

    // ── label search (server-side query language) ─────────────────────────────
    // hello.txt was uploaded with label env=test.
    let s = server.y2q(&["--json", "search", "test/bucket", "--query", "env == test"]);
    assert!(
        s.status.success(),
        "search failed: {}",
        String::from_utf8_lossy(&s.stderr)
    );
    assert!(
        String::from_utf8_lossy(&s.stdout).contains("hello.txt"),
        "search did not match the labeled object: {}",
        String::from_utf8_lossy(&s.stdout)
    );
    // Cross-bucket (alias-only) with regex/prefix combiners.
    server.ok(&[
        "search",
        "test/",
        "--query",
        "env =~ \"te.*\" or env ^= prod",
    ]);
    // Non-matching query still succeeds (empty result).
    server.ok(&["search", "test/bucket", "--query", "env == nope"]);
    // Malformed query -> daemon 400 -> non-zero CLI exit.
    assert!(!ok(&server.y2q(&[
        "search",
        "test/bucket",
        "--query",
        "env =="
    ])));

    // ── tags / attributes ─────────────────────────────────────────────────────
    server.ok(&["tag", "set", "test/bucket/hello.txt", "team=infra"]);
    server.ok(&["tag", "list", "test/bucket/hello.txt"]);
    server.ok(&["attribute", "set", "test/bucket/hello.txt", "tier=hot"]);
    server.ok(&["attribute", "list", "test/bucket/hello.txt"]);
    let _ = server.y2q(&["tag", "rm", "test/bucket/hello.txt"]);

    // ── per-bucket config (quota / encrypt sidecar) ───────────────────────────
    server.ok(&["quota", "set", "test/bucket", "--size", "10m"]);
    server.ok(&["quota", "info", "test/bucket"]);
    server.ok(&["quota", "clear", "test/bucket"]);
    server.ok(&["encrypt", "set", "test/bucket", "aes256-gcm"]);
    server.ok(&["encrypt", "info", "test/bucket"]);
    server.ok(&["encrypt", "clear", "test/bucket"]);

    // ── mirror / diff (local dir tree -> remote) ──────────────────────────────
    let srcdir = server.base.join("tree");
    std::fs::create_dir_all(srcdir.join("sub")).unwrap();
    std::fs::write(srcdir.join("a.txt"), b"aaa").unwrap();
    std::fs::write(srcdir.join("sub/b.txt"), b"bbbb").unwrap();
    let _ = server.y2q(&["mirror", srcdir.to_str().unwrap(), "test/bucket/mirror"]);
    let _ = server.y2q(&["diff", srcdir.to_str().unwrap(), "test/bucket/mirror"]);
    // Re-mirror unchanged tree: every entry is identical -> skip branch in copy_one.
    let _ = server.y2q(&["mirror", srcdir.to_str().unwrap(), "test/bucket/mirror"]);
    // Introduce a change + a new file, then diff (changed + missing-remote) and
    // mirror --overwrite (checksum-differs branch).
    std::fs::write(srcdir.join("a.txt"), b"aaa-now-different-and-longer").unwrap();
    std::fs::write(srcdir.join("c.txt"), b"brand new").unwrap();
    let _ = server.y2q(&["diff", srcdir.to_str().unwrap(), "test/bucket/mirror"]);
    let _ = server.y2q(&[
        "mirror",
        srcdir.to_str().unwrap(),
        "test/bucket/mirror",
        "--overwrite",
    ]);

    // ── alias import (stdin TOML) + remove on a throwaway alias ───────────────
    let import_toml = format!("[aliases.tmp]\nurl = \"{url}\"\nusername = \"root\"\n");
    let imp = server.y2q_stdin(&["alias", "import", "--merge"], import_toml.as_bytes());
    assert!(
        imp.status.success(),
        "alias import failed: {}",
        String::from_utf8_lossy(&imp.stderr)
    );
    let _ = server.y2q(&["alias", "rm", "tmp"]);

    // ── health probes ─────────────────────────────────────────────────────────
    server.ok(&["ping", "test", "--count", "1"]);
    server.ok(&["ready", "test"]);

    // ── admin: users + locks + rebuild status ─────────────────────────────────
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "alice",
        "--password",
        "alicepw",
    ]);
    server.ok(&["admin", "user", "list", "test"]);
    let _ = server.y2q(&["admin", "user", "rm", "test", "alice"]);
    server.ok(&["admin", "locks", "list", "test", "--older-than", "5m"]);
    let _ = server.y2q(&["admin", "locks", "clear", "test", "--older-than", "1h"]);
    let _ = server.y2q(&["admin", "rebuild", "status", "test"]);

    // ── recursive + glob uploads ──────────────────────────────────────────────
    server.ok(&["cp", "-r", srcdir.to_str().unwrap(), "test/bucket/rec"]);
    let glob = format!("{}/*.txt", srcdir.to_str().unwrap());
    server.ok(&["cp", &glob, "test/bucket/globbed"]);

    // ── pipe (stdin -> object) + cat back ─────────────────────────────────────
    let piped = server.y2q_stdin(&["pipe", "test/bucket/piped.bin"], b"streamed bytes");
    assert!(
        piped.status.success(),
        "pipe failed: {}",
        String::from_utf8_lossy(&piped.stderr)
    );
    server.ok(&["cat", "test/bucket/piped.bin"]);

    // ── move remote -> local (copy + delete source) ──────────────────────────
    let moved = server.base.join("moved.bin");
    server.ok(&["mv", "test/bucket/piped.bin", moved.to_str().unwrap()]);
    assert_eq!(std::fs::read(&moved).unwrap(), b"streamed bytes");

    // ── range read via head byte count ────────────────────────────────────────
    server.ok(&["head", "test/bucket/hello.txt", "-c", "4"]);

    // ── disk-usage grouping (sum_prefix) ──────────────────────────────────────
    server.ok(&["du", "test/bucket", "--depth", "2"]);

    // ── mirror with overwrite + prune, then diff again ────────────────────────
    std::fs::write(srcdir.join("a.txt"), b"aaa-changed-longer").unwrap();
    let _ = server.y2q(&[
        "mirror",
        srcdir.to_str().unwrap(),
        "test/bucket/mirror",
        "--overwrite",
    ]);
    std::fs::remove_file(srcdir.join("sub/b.txt")).unwrap();
    let _ = server.y2q(&[
        "mirror",
        srcdir.to_str().unwrap(),
        "test/bucket/mirror",
        "--remove",
    ]);

    // ── admin: rebuild start + status ─────────────────────────────────────────
    let _ = server.y2q(&["admin", "rebuild", "start", "test"]);
    let _ = server.y2q(&["admin", "rebuild", "status", "test"]);

    // ── glob delete (covers multi-object rm path) ─────────────────────────────
    let _ = server.y2q(&["rm", "test/bucket/globbed/*", "-f"]);

    // ── change password (last auth op before teardown) ────────────────────────
    let _ = server.y2q(&["passwd", "test", "--current", &pw, "--new", "newrootpw"]);

    // ── JSON output mode ──────────────────────────────────────────────────────
    server.ok(&["--json", "ls", "test/bucket"]);
    server.ok(&["--json", "stat", "test/bucket/hello.txt"]);

    // ── y2q-warp load tool against the live daemon ────────────────────────────
    // Tiny, fast workloads: a couple of objects, 1 KiB each, ~1s. Reuses the
    // cached session token under XDG_CONFIG_HOME. Each subcommand exercises the
    // worker/ops/metrics/recorder/display/prepare/auth paths.
    if let Some(warp) = ensure_warp() {
        server.ok(&["mb", "test/warpb"]);
        let common: &[&str] = &[
            "--bucket",
            "warpb",
            "--concurrent",
            "2",
            "--duration",
            "1s",
            "--objects",
            "4",
            "--obj-size",
            "1KiB",
        ];
        let put_csv = server.base.join("put.csv.zst");
        let mut put_args = vec!["test", "put"];
        put_args.extend_from_slice(common);
        put_args.extend_from_slice(&["--output", put_csv.to_str().unwrap(), "--no-cleanup"]);
        let out = server.warp(&warp, &put_args);
        assert!(
            out.status.success(),
            "warp put failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );

        for op in ["get", "stat", "list", "delete"] {
            let mut a = vec!["test", op];
            a.extend_from_slice(common);
            a.push("--no-cleanup");
            let out = server.warp(&warp, &a);
            assert!(
                out.status.success(),
                "warp {op} failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }

        // mixed workload
        let mut mixed = vec!["test", "mixed"];
        mixed.extend_from_slice(common);
        mixed.push("--no-cleanup");
        let _ = server.warp(&warp, &mixed);

        // prepare + cleanup lifecycle
        let _ = server.warp(
            &warp,
            &[
                "test",
                "prepare",
                "--bucket",
                "warpb",
                "--objects",
                "3",
                "--obj-size",
                "1KiB",
            ],
        );
        let _ = server.warp(&warp, &["test", "cleanup", "--bucket", "warpb"]);

        // analyze the recorded CSV (no server needed)
        if put_csv.exists() {
            let out = server.warp(&warp, &["test", "analyze", put_csv.to_str().unwrap()]);
            assert!(
                out.status.success(),
                "warp analyze failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let _ = server.y2q(&["rb", "test/warpb", "--force"]);
    }

    // ── error paths (non-zero exit codes) ─────────────────────────────────────
    assert!(!ok(&server.y2q(&["stat", "test/bucket/nope"]))); // 404 -> code 3
    assert!(!ok(&server.y2q(&["stat", "unknownalias/b/k"]))); // unknown alias

    // ── delete + bucket removal ───────────────────────────────────────────────
    server.ok(&["rm", "test/bucket/hello.txt", "-f"]);
    server.ok(&["rb", "test/bucket", "--force"]);

    // ── logout ─────────────────────────────────────────────────────────────────
    server.ok(&["logout", "test"]);
}

/// HTTPS variant: exercises the rustls server config (`tls::build_server_config`)
/// and the client's rustls builder (`build_rustls_client_config`) via an
/// `--insecure` alias against a self-signed cert. Skips if openssl is absent.
#[test]
fn e2e_tls_flow() {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let certdir =
        std::env::temp_dir().join(format!("y2q-tlscert-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&certdir).unwrap();
    let Some((cert, key)) = gen_self_signed(&certdir) else {
        eprintln!("skipping TLS e2e: openssl unavailable");
        let _ = std::fs::remove_dir_all(&certdir);
        return;
    };
    let Some(server) = start_server_tls(Some((cert, key))) else {
        let _ = std::fs::remove_dir_all(&certdir);
        return;
    };

    let url = server.url(); // https://127.0.0.1:PORT
    // Self-signed -> the alias must skip certificate verification.
    server.ok(&["alias", "set", "test", &url, "--user", "root", "--insecure"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);
    server.ok(&["mb", "test/tbucket"]);

    let f = server.base.join("over-tls.txt");
    std::fs::write(&f, b"encrypted in transit too").unwrap();
    server.ok(&["cp", f.to_str().unwrap(), "test/tbucket/t.txt"]);
    server.ok(&["stat", "test/tbucket/t.txt"]);
    server.ok(&["cat", "test/tbucket/t.txt"]);
    server.ok(&["rm", "test/tbucket/t.txt", "-f"]);
    server.ok(&["rb", "test/tbucket", "--force"]);

    let _ = std::fs::remove_dir_all(&certdir);
}
