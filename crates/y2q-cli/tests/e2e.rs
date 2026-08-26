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

/// Hex-encoded 32-byte node key for the throwaway test deployment.
///
/// Fixed so a failing run reproduces, but drawn from CSPRNG output: the daemon
/// rejects key material that does not look random (see
/// `y2q_core::crypto::node_key`), so a low-diversity placeholder fails at boot.
const TEST_NODE_KEY_HEX: &str = "9f3c1d7a04b8e526cf91072d4ab6539e8c25f0716da3b48c17e69205d3fa8b41";

/// A second, unrelated key used by the rotation test as the *new* node key.
const TEST_NEW_NODE_KEY_HEX: &str =
    "2e75b0c9631fa8d405e3927b6c1af84e39d20b57e8146c3a92f5087db4e61c39";

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
        // 32 raw bytes, hex-encoded. Fixed rather than random so a failing run
        // reproduces, but it must still pass the CSPRNG shape check in
        // `crypto::node_key` — a low-diversity constant like "ab" repeated is
        // rejected at boot.
        .env("Y2QD_NODE_KEY", TEST_NODE_KEY_HEX)
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

/// Poll `child` until it exits or `timeout` elapses. Returns the exit
/// status if it exited in time, `None` if it's still running (caller must
/// then decide whether to kill it).
fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Ok(Some(status)) = child.try_wait() {
            return Some(status);
        }
        if Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Exercises `--rotate-node-key` end to end, including its crash-safety
/// story (plan Phase 4 node-key-rotation verification): a rotation
/// genuinely interrupted mid-walk (kill lands while the timed calibration
/// run proves it would still be in progress) leaves the daemon refusing to
/// boot with the "interrupted" message; resuming with the same key pair
/// completes it; every object then reads correctly under the new key and
/// the old key is rejected outright.
#[test]
fn e2e_node_key_rotation_crash_safety() {
    let Some(bin) = ensure_y2qd() else {
        eprintln!("skipping e2e: could not locate or build the y2qd binary");
        return;
    };

    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base =
        std::env::temp_dir().join(format!("y2q-rotate-e2e-{}-{}", std::process::id(), nanos));
    let data = base.join("data");
    let keys = base.join("keys");
    let cfg_home = base.join("cfg");
    let snapshot = base.join("snapshot");
    for d in [&data, &keys, &cfg_home] {
        std::fs::create_dir_all(d).unwrap();
    }

    let old_key = TEST_NODE_KEY_HEX.to_owned();
    let new_key = TEST_NEW_NODE_KEY_HEX.to_owned();
    let port = free_port();

    let apply_common_env = |cmd: &mut Command| {
        cmd.env("Y2QD_SERVER__HOST", "127.0.0.1")
            .env("Y2QD_SERVER__PORT", port.to_string())
            .env("Y2QD_SERVER__TLS__ENABLED", "false")
            .env("Y2QD_STORAGE__BASE_PATH", &data)
            .env("Y2QD_CRYPTO__KEYSTORE_DIR", &keys)
            .env("Y2QD_CRYPTO__ARGON2__M_COST_KIB", "8")
            .env("Y2QD_CRYPTO__ARGON2__T_COST", "1")
            .env("Y2QD_CRYPTO__ARGON2__P_COST", "1")
            .env("Y2QD_AUTH__MIN_LOGIN_RESPONSE_MS", "0")
            .env("Y2QD_OBSERVABILITY__LOG_FILTER", "error")
            .env("RUST_LOG", "error");
    };

    // ── Phase 1: boot normally under the old key, seed enough objects that
    // a full rotation takes measurable wall-clock time ─────────────────────
    let mut boot = Command::new(&bin);
    apply_common_env(&mut boot);
    boot.env("Y2QD_NODE_KEY", &old_key)
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    let mut child = boot.spawn().expect("spawn y2qd");
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
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(Instant::now() < deadline, "y2qd did not become ready");
        std::thread::sleep(Duration::from_millis(50));
    }

    let y2q = |args: &[&str]| -> std::process::Output {
        Command::new(y2q_bin())
            .env("XDG_CONFIG_HOME", &cfg_home)
            .env("NO_COLOR", "1")
            .args(args)
            .output()
            .expect("spawn y2q")
    };
    let url = format!("http://127.0.0.1:{port}");
    assert!(
        y2q(&["alias", "set", "test", &url, "--user", "root"])
            .status
            .success()
    );
    assert!(
        y2q(&["login", "test", "--password", &password])
            .status
            .success()
    );

    const BUCKETS: usize = 4;
    const OBJECTS_PER_BUCKET: usize = 40;
    let mut expected: Vec<(String, String)> = Vec::new(); // (object path, content)
    for b in 0..BUCKETS {
        let bucket = format!("test/rotbucket{b}");
        assert!(y2q(&["mb", &bucket]).status.success());
        for i in 0..OBJECTS_PER_BUCKET {
            let content = format!("payload for bucket {b} object {i}");
            let local = base.join(format!("seed-{b}-{i}.txt"));
            std::fs::write(&local, &content).unwrap();
            let object = format!("{bucket}/obj{i}.txt");
            let out = y2q(&["cp", local.to_str().unwrap(), &object]);
            assert!(
                out.status.success(),
                "seed cp failed: {}",
                String::from_utf8_lossy(&out.stderr)
            );
            expected.push((object, content));
        }
    }

    // Stop the daemon cleanly (SIGTERM), then snapshot the pre-rotation tree
    // so the timing-calibration rotation below can be undone.
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    for _ in 0..40 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    let copy_tree = |from: &std::path::Path, to: &std::path::Path| {
        let _ = std::fs::remove_dir_all(to);
        let status = Command::new("cp")
            .args(["-r", "-p"])
            .arg(from)
            .arg(to)
            .status()
            .expect("cp -r");
        assert!(
            status.success(),
            "cp -r {} {} failed",
            from.display(),
            to.display()
        );
    };
    std::fs::create_dir_all(&snapshot).unwrap();
    copy_tree(&data, &snapshot.join("data"));
    copy_tree(&keys, &snapshot.join("keys"));

    let rotate_cmd = || -> Command {
        let mut cmd = Command::new(&bin);
        apply_common_env(&mut cmd);
        cmd.env("Y2QD_NODE_KEY", &old_key)
            .env("Y2QD_NEW_NODE_KEY", &new_key)
            .arg("--rotate-node-key")
            .stdout(Stdio::null())
            .stderr(Stdio::piped());
        cmd
    };

    // ── Phase 2: calibrate — run one full rotation, timing it ─────────────
    let calib_start = Instant::now();
    let mut calib = rotate_cmd().spawn().expect("spawn calibration rotation");
    let calib_status = calib.wait().expect("wait calibration rotation");
    let full_duration = calib_start.elapsed();
    assert!(calib_status.success(), "calibration rotation failed");
    assert!(
        full_duration >= Duration::from_millis(5),
        "seeded {} objects rotated in {full_duration:?} — too fast to reliably interrupt mid-walk; increase OBJECTS_PER_BUCKET",
        BUCKETS * OBJECTS_PER_BUCKET
    );

    // Restore the pre-rotation tree so the real (interrupted) run starts
    // from the same old-key state the calibration run did.
    copy_tree(&snapshot.join("data"), &data);
    copy_tree(&snapshot.join("keys"), &keys);

    // ── Phase 3: interrupt a real rotation partway through ─────────────────
    let kill_after = full_duration.mul_f32(0.4).max(Duration::from_millis(2));
    let mut rot = rotate_cmd().spawn().expect("spawn rotation");
    std::thread::sleep(kill_after);
    let still_running = matches!(rot.try_wait(), Ok(None));
    assert!(
        still_running,
        "rotation already finished before the calibrated kill point — timing assumption broke; \
         increase OBJECTS_PER_BUCKET or lower the kill fraction"
    );
    let _ = Command::new("kill")
        .arg("-KILL")
        .arg(rot.id().to_string())
        .status();
    let _ = rot.wait();

    let journal_path = keys.join("node-key-rotation.json");
    assert!(
        journal_path.exists(),
        "rotation journal must survive an interruption mid-walk"
    );

    // ── Phase 4: normal boot refuses while the journal is present ──────────
    let mut refused_boot = Command::new(&bin);
    apply_common_env(&mut refused_boot);
    refused_boot
        .env("Y2QD_NODE_KEY", &old_key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut refused_child = refused_boot.spawn().expect("spawn y2qd (expect refusal)");
    let status = match wait_for_exit(&mut refused_child, Duration::from_secs(10)) {
        Some(s) => s,
        None => {
            // It didn't refuse — it's serving. That's the bug this test
            // exists to catch. Kill it before failing so the test process
            // doesn't leak a listening daemon.
            let _ = refused_child.kill();
            let _ = refused_child.wait();
            panic!(
                "daemon started successfully despite an interrupted rotation journal being present"
            );
        }
    };
    assert!(
        !status.success(),
        "boot with an interrupted rotation journal present must fail"
    );
    let stderr = {
        use std::io::Read;
        let mut s = String::new();
        refused_child
            .stderr
            .take()
            .unwrap()
            .read_to_string(&mut s)
            .ok();
        s
    };
    assert!(
        stderr.contains("interrupted"),
        "expected the interrupted-rotation message, got: {stderr}"
    );

    // ── Phase 5: resume the rotation to completion ──────────────────────────
    let mut resume = rotate_cmd();
    let resume_out = resume.output().expect("resume rotation");
    assert!(
        resume_out.status.success(),
        "resumed rotation failed: {}",
        String::from_utf8_lossy(&resume_out.stderr)
    );
    assert!(
        !journal_path.exists(),
        "journal must be deleted once the rotation completes"
    );

    // ── Phase 6: boot under the new key and verify every object ────────────
    let mut boot2 = Command::new(&bin);
    apply_common_env(&mut boot2);
    boot2
        .env("Y2QD_NODE_KEY", &new_key)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut child2 = boot2.spawn().expect("spawn y2qd under new key");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if TcpStream::connect(("127.0.0.1", port)).is_ok() {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "y2qd did not become ready under the new key"
        );
        std::thread::sleep(Duration::from_millis(50));
    }

    // A fresh daemon process starts with an empty in-memory session store —
    // the token cached from before rotation is gone. Node-key rotation
    // never touches user identity/auth, so the same password logs back in.
    assert!(
        y2q(&["login", "test", "--password", &password])
            .status
            .success()
    );

    for (object, content) in &expected {
        let dl = base.join("verify.tmp");
        let out = y2q(&["get", object, dl.to_str().unwrap()]);
        assert!(
            out.status.success(),
            "get {object} failed after rotation: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        assert_eq!(
            &std::fs::read(&dl).unwrap(),
            content.as_bytes(),
            "content mismatch for {object} after rotation"
        );
    }

    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child2.id().to_string())
        .status();
    for _ in 0..40 {
        if matches!(child2.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child2.kill();
    let _ = child2.wait();

    // ── Phase 7: the old key is rejected outright post-rotation ────────────
    let mut boot3 = Command::new(&bin);
    apply_common_env(&mut boot3);
    boot3
        .env("Y2QD_NODE_KEY", &old_key)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let mut child3 = boot3
        .spawn()
        .expect("spawn y2qd with the old key post-rotation");
    let status3 = match wait_for_exit(&mut child3, Duration::from_secs(10)) {
        Some(s) => s,
        None => {
            let _ = child3.kill();
            let _ = child3.wait();
            panic!("daemon started successfully with the OLD key after rotation completed");
        }
    };
    assert!(
        !status3.success(),
        "the old node key must be rejected after rotation"
    );

    let _ = std::fs::remove_dir_all(&base);
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

/// Exercises the phase-3 per-bucket key grant flow end to end: the owner
/// writes an object, a second user is denied (404, not 403 — visibility
/// follows the cryptographic grant) until explicitly granted `read` via
/// `acl grant`, can then decrypt it, and loses access again after `acl
/// revoke` (which also kills their live session).
#[test]
fn e2e_bucket_acl_grant_and_revoke() {
    let Some(server) = start_server() else {
        return;
    };

    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    // Owner creates a bucket and writes an object.
    server.ok(&["mb", "test/shared"]);
    let local = server.base.join("secret.txt");
    std::fs::write(&local, b"top secret payload").unwrap();
    server.ok(&["cp", local.to_str().unwrap(), "test/shared/secret.txt"]);

    // Create a second user and log them in under their own alias.
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "bob",
        "--password",
        "bob-secure-passphrase-1",
    ]);
    server.ok(&["alias", "set", "bob", &url, "--user", "bob"]);
    server.ok(&["login", "bob", "--password", "bob-secure-passphrase-1"]);

    // Before any grant, bob cannot even see the bucket — visibility follows
    // the cryptographic grant, not just role/ACL, so this is 404 not 403.
    assert!(!ok(&server.y2q(&["stat", "bob/shared/secret.txt"])));

    // Owner grants bob read access; this seals a real bucket-key grant to
    // bob's real (randomly-placed) identity slot, not just an authz-layer
    // ACL entry.
    server.ok(&["admin", "acl", "grant", "test", "shared", "bob", "read"]);

    // Bob can now list and decrypt the object using his existing session —
    // no re-login required, since the grant is resolved fresh per request.
    server.ok(&["ls", "bob/shared"]);
    let dl = server.base.join("bob_secret.txt");
    server.ok(&["get", "bob/shared/secret.txt", dl.to_str().unwrap()]);
    assert_eq!(std::fs::read(&dl).unwrap(), b"top secret payload");

    // Owner revokes bob's access. This re-seals bob's slot as a decoy and
    // drops his live sessions, so his subsequent request fails outright.
    server.ok(&["admin", "acl", "revoke", "test", "shared", "bob"]);
    assert!(!ok(&server.y2q(&["stat", "bob/shared/secret.txt"])));
}

/// Exercises the `DELETE /api/v1/users/{user}` orphan guard: deleting a
/// bucket's owner is refused with 409 (their identity is the only thing
/// that can ever grant fresh access to it), and `--force` overrides it. A
/// non-owning user deletes with no guard at all.
#[test]
fn e2e_delete_user_bucket_owner_guard() {
    let Some(server) = start_server() else {
        return;
    };

    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    // carol owns a bucket; dave is just a plain user with none.
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "carol",
        "--password",
        "carol-secure-passphrase-1",
    ]);
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "dave",
        "--password",
        "dave-secure-passphrase-1",
    ]);
    server.ok(&["alias", "set", "carol", &url, "--user", "carol"]);
    server.ok(&["login", "carol", "--password", "carol-secure-passphrase-1"]);
    server.ok(&["mb", "carol/owned"]);

    // Deleting the owner without --force is refused (409).
    let out = server.y2q(&["admin", "user", "rm", "test", "carol"]);
    assert!(
        !ok(&out),
        "deleting a bucket owner without --force should fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("only key holder"),
        "expected sole-grantee orphan-guard message, got: {stderr}"
    );

    // A non-owning user deletes cleanly, no guard triggered.
    server.ok(&["admin", "user", "rm", "test", "dave"]);

    // --force overrides the guard.
    server.ok(&["admin", "user", "rm", "test", "carol", "--force"]);

    // carol's bucket still exists (existing objects/config untouched) but
    // her identity is gone — nobody can ever grant new access to it again.
    server.ok(&["admin", "user", "list", "test"]);
}

/// Exercises rotate-key + rekey end to end (plan Phase 4 verification):
/// grant a user read access, revoke it, rotate to a fresh epoch the revoked
/// user never held, write a second object under the new epoch, rekey to
/// migrate the first object off the old epoch and prune it, and confirm the
/// bucket ends up on a single retained epoch with both objects still
/// readable by the owner.
#[test]
fn e2e_rotate_key_and_rekey() {
    let Some(server) = start_server() else {
        return;
    };

    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    server.ok(&["mb", "test/alpha"]);
    let local = server.base.join("secret.txt");
    std::fs::write(&local, b"first epoch payload").unwrap();
    server.ok(&["cp", local.to_str().unwrap(), "test/alpha/secret.txt"]);

    // Grant eve read, then revoke it — her real grant on epoch 0 is now
    // stale but still technically present until a rekey prunes it.
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "eve",
        "--password",
        "eve-secure-passphrase-1",
    ]);
    server.ok(&["admin", "acl", "grant", "test", "alpha", "eve", "read"]);
    server.ok(&["admin", "acl", "revoke", "test", "alpha", "eve"]);

    // Rotate to a fresh epoch eve never held.
    let out = server.y2q(&["--json", "admin", "rotate-key", "test", "alpha"]);
    assert!(
        ok(&out),
        "rotate-key failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let rotate: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(rotate["epoch"], 1);
    assert_eq!(rotate["key_epochs"], serde_json::json!([0, 1]));

    // A second object, written after rotation, lands on the new epoch.
    let local2 = server.base.join("after.txt");
    std::fs::write(&local2, b"second epoch payload").unwrap();
    server.ok(&["cp", local2.to_str().unwrap(), "test/alpha/after.txt"]);

    // Rekey: migrates secret.txt off epoch 0, prunes it.
    server.ok(&["admin", "rekey", "start", "test", "alpha"]);
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    loop {
        let out = server.y2q(&["--json", "admin", "rekey", "status", "test", "alpha"]);
        assert!(ok(&out), "rekey status failed");
        let status: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
        match status["state"].as_str().unwrap() {
            "completed" => break,
            "failed" => panic!("rekey failed: {status:?}"),
            _ => {
                assert!(
                    std::time::Instant::now() < deadline,
                    "rekey did not complete in time"
                );
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    // A single retained epoch survives the rekey.
    let out = server.y2q(&["--json", "admin", "acl", "get", "test", "alpha"]);
    assert!(ok(&out));
    let acl: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(acl["key_epochs"], serde_json::json!([1]));

    // Both objects still decrypt correctly for the owner.
    let dl1 = server.base.join("dl_secret.txt");
    server.ok(&["get", "test/alpha/secret.txt", dl1.to_str().unwrap()]);
    assert_eq!(std::fs::read(&dl1).unwrap(), b"first epoch payload");
    let dl2 = server.base.join("dl_after.txt");
    server.ok(&["get", "test/alpha/after.txt", dl2.to_str().unwrap()]);
    assert_eq!(std::fs::read(&dl2).unwrap(), b"second epoch payload");
}

/// Exercises `reset-identity` end to end: it restores login under a new
/// password, kills the target's live session, and scrubs their bucket
/// grants — orphaning a bucket where they were the sole grantee while
/// leaving a shared bucket's other grantee untouched.
#[test]
fn e2e_reset_identity() {
    let Some(server) = start_server() else {
        return;
    };

    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "frank",
        "--password",
        "frank-old-passphrase-1",
    ]);
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "gina",
        "--password",
        "gina-secure-passphrase-1",
    ]);
    server.ok(&["alias", "set", "frank", &url, "--user", "frank"]);
    server.ok(&["login", "frank", "--password", "frank-old-passphrase-1"]);

    // frank owns two buckets: one solo, one shared with gina (real grant).
    server.ok(&["mb", "frank/solo"]);
    server.ok(&["mb", "frank/shared"]);
    server.ok(&["admin", "acl", "grant", "frank", "shared", "gina", "read"]);

    // gina can read the shared bucket before the reset.
    let local = server.base.join("shared.txt");
    std::fs::write(&local, b"shared payload").unwrap();
    server.ok(&["cp", local.to_str().unwrap(), "frank/shared/shared.txt"]);
    server.ok(&["alias", "set", "gina", &url, "--user", "gina"]);
    server.ok(&["login", "gina", "--password", "gina-secure-passphrase-1"]);
    server.ok(&["stat", "gina/shared/shared.txt"]);

    // frank's session is live before the reset.
    server.ok(&["ls", "frank/solo"]);

    // Root resets frank's identity under a new password.
    let out = server.y2q(&[
        "--json",
        "admin",
        "reset-identity",
        "test",
        "frank",
        "--password",
        "frank-new-passphrase-2",
    ]);
    assert!(
        ok(&out),
        "reset-identity failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let resp: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    let orphaned: Vec<String> = resp["orphaned_buckets"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap().to_owned())
        .collect();
    assert_eq!(
        orphaned,
        vec!["solo".to_owned()],
        "only the sole-grantee bucket should orphan"
    );

    // frank's live session (under the old identity) is dead.
    assert!(!ok(&server.y2q(&["stat", "frank/shared/shared.txt"])));

    // The old password no longer works; the new one does.
    assert!(!ok(&server.y2q(&[
        "login",
        "frank",
        "--password",
        "frank-old-passphrase-1"
    ])));
    server.ok(&["login", "frank", "--password", "frank-new-passphrase-2"]);

    // frank's new identity holds no grant anywhere — even the shared bucket
    // he still nominally owns is now 404 to him until someone re-grants it.
    assert!(!ok(&server.y2q(&["stat", "frank/shared/shared.txt"])));

    // gina's own separate grant on the shared bucket is untouched.
    server.ok(&["stat", "gina/shared/shared.txt"]);
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

/// The end-to-end proof the whole plan exists for (plan Phase 3
/// verification): a compromised global-admin account cannot read object
/// plaintext it wasn't granted, a user with zero relationship to a bucket
/// gets 404 (not 403 - indistinguishable from the bucket not existing), a
/// `writeonly` grantee can write but not read back what they wrote, and
/// deleting a bucket's sole grantee is guarded (409) unless forced.
#[test]
fn e2e_bucket_blast_radius() {
    let Some(server) = start_server() else {
        return;
    };

    let url = server.url();
    server.ok(&["alias", "set", "test", &url, "--user", "root"]);
    let pw = server.password.clone();
    server.ok(&["login", "test", "--password", &pw]);

    // Root creates two buckets, each with a secret object.
    server.ok(&["mb", "test/alpha"]);
    server.ok(&["mb", "test/beta"]);
    let secret = server.base.join("secret.txt");
    std::fs::write(&secret, b"alpha secret payload").unwrap();
    server.ok(&["cp", secret.to_str().unwrap(), "test/alpha/secret.txt"]);
    std::fs::write(&secret, b"beta secret payload").unwrap();
    server.ok(&["cp", secret.to_str().unwrap(), "test/beta/secret.txt"]);

    // alice and carol are ordinary users; alice is granted read on alpha
    // only. carol gets nothing.
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "alice",
        "--password",
        "alice-secure-passphrase-1",
    ]);
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "carol",
        "--password",
        "carol-secure-passphrase-1",
    ]);
    server.ok(&["admin", "acl", "grant", "test", "alpha", "alice", "read"]);
    server.ok(&["alias", "set", "alice", &url, "--user", "alice"]);
    server.ok(&["login", "alice", "--password", "alice-secure-passphrase-1"]);
    server.ok(&["alias", "set", "carol", &url, "--user", "carol"]);
    server.ok(&["login", "carol", "--password", "carol-secure-passphrase-1"]);

    // alice reads what she was granted.
    let dl = server.base.join("alice_dl.txt");
    server.ok(&["get", "alice/alpha/secret.txt", dl.to_str().unwrap()]);
    assert_eq!(std::fs::read(&dl).unwrap(), b"alpha secret payload");

    // alice has zero relationship to beta -> 404, not 403: indistinguishable
    // from beta not existing.
    let out = server.y2q(&["stat", "alice/beta/secret.txt"]);
    assert!(!ok(&out), "alice must not read beta");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "expected 404 not found, got: {stderr}"
    );

    // carol has zero relationship to alpha either -> same 404.
    let out = server.y2q(&["stat", "carol/alpha/secret.txt"]);
    assert!(!ok(&out), "carol must not read alpha");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "expected 404 not found, got: {stderr}"
    );

    // dave is a global ADMIN with no bucket grant anywhere. This is the
    // core claim of the whole plan: a compromised admin account cannot
    // read data. Admin visibility still lists bucket *names* (role_is_global
    // bypasses the ACL/ownership gate for listing), but the actual GET
    // fails at the crypto layer - `authorize_bucket` lets the request
    // through on role alone, then `bucket_keys::resolve_read_key` fails
    // because dave holds no real sealed grant, surfacing as 403.
    server.ok(&[
        "admin",
        "user",
        "add",
        "test",
        "dave",
        "--role",
        "admin",
        "--password",
        "dave-secure-passphrase-1",
    ]);
    server.ok(&["alias", "set", "dave", &url, "--user", "dave"]);
    server.ok(&["login", "dave", "--password", "dave-secure-passphrase-1"]);

    let out = server.y2q(&["ls", "dave/"]);
    assert!(ok(&out), "admin must be able to list buckets");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        stdout.contains("alpha") && stdout.contains("beta"),
        "expected both bucket names, got: {stdout}"
    );

    // `stat`/HEAD never decrypts the body (only Metadata, tier-0/node-key
    // material an admin can already see) - use a real GET, the only path
    // that calls `bucket_keys::resolve_read_key`.
    let dave_dl = server.base.join("dave_dl.txt");
    let out = server.y2q(&["get", "dave/alpha/secret.txt", dave_dl.to_str().unwrap()]);
    assert!(!ok(&out), "admin must not read alpha's plaintext");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("forbidden"),
        "expected 403 forbidden, got: {stderr}"
    );

    // Even the ACL endpoint itself refuses dave: granting requires sealing
    // a new grant against the bucket wrap key, which only a real grantee
    // can recover.
    let out = server.y2q(&["admin", "acl", "grant", "dave", "alpha", "dave", "read"]);
    assert!(
        !ok(&out),
        "admin must not be able to self-grant a bucket key"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("forbidden"),
        "expected 403 forbidden, got: {stderr}"
    );

    // Root grants carol writeonly on alpha: she can write, but reading back
    // what she just wrote is refused - a writeonly grantee never gets a
    // real bucket-key grant sealed to them at all.
    server.ok(&[
        "admin",
        "acl",
        "grant",
        "test",
        "alpha",
        "carol",
        "writeonly",
    ]);
    let dropbox = server.base.join("dropbox.txt");
    std::fs::write(&dropbox, b"carol's write").unwrap();
    server.ok(&["cp", dropbox.to_str().unwrap(), "carol/alpha/dropbox.txt"]);
    let out = server.y2q(&["stat", "carol/alpha/dropbox.txt"]);
    assert!(
        !ok(&out),
        "writeonly grantee must not read back her own write"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    // HEAD responses carry no body per HTTP spec, so the client falls back
    // to the bare status text ("Forbidden") rather than the detailed JSON
    // error message - check the status code instead.
    assert!(
        stderr.contains("403"),
        "expected 403 forbidden, got: {stderr}"
    );

    // alice is the sole grantee (owner) of a bucket of her own - deleting
    // her without --force is refused, since her identity is the only
    // thing that could ever grant fresh access to it again. (Alpha itself
    // doesn't trigger this: root, the owner, is also a grants-map entry,
    // so alice alone is never "sole" there.)
    server.ok(&["mb", "alice/mine"]);
    let out = server.y2q(&["admin", "user", "rm", "test", "alice"]);
    assert!(
        !ok(&out),
        "deleting the sole grantee without --force must fail"
    );
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("only key holder"),
        "expected sole-grantee guard message, got: {stderr}"
    );
    server.ok(&["admin", "user", "rm", "test", "alice", "--force"]);
}

/// Duress separation and deniability (plan Phase 5 verification), driven
/// through `y2q_client::Y2qClient` directly rather than CLI subprocesses:
/// `persona add` deliberately has no `--password` flag (it always prompts
/// on a real TTY), which a piped-stdin subprocess can't satisfy, but the
/// server behavior under test is exactly what the client library calls.
/// The byte-shape padding invariant (item 7 of the plan's spec) is covered
/// separately by `y2q_core::crypto::user_store::tests::record_always_carries_credential_slots`
/// and `y2qd::bucket_keys::tests::grant_row_is_byte_shape_uniform_across_authorized_and_decoy_slots`.
#[tokio::test]
async fn e2e_duress_persona_deniability() {
    let Some(server) = start_server() else {
        return;
    };
    let url = server.url();

    let mk = || y2q_client::Y2qClient::new(y2q_client::ClientConfig::new(url.clone())).unwrap();

    let mut root = mk();
    let root_tok = root
        .login("root", &server.password, None)
        .await
        .expect("root login");
    root.set_token(root_tok.token);
    root.add_user("alice", "password-A", Some("user"))
        .await
        .expect("add alice");

    // 1. As alice (password A, whichever slot the server randomly chose as
    // her real identity): create real-bucket+secret.txt and
    // decoy-bucket+plausible.txt.
    let mut alice_a = mk();
    let tok_a = alice_a
        .login("alice", "password-A", None)
        .await
        .expect("alice login A");
    alice_a.set_token(tok_a.token.clone());
    let alice_a_slot = alice_a.whoami_persona().await.expect("whoami as A").slot;

    alice_a
        .create_bucket("real-bucket")
        .await
        .expect("create real-bucket");
    let real_secret: &[u8] = b"the real secret";
    alice_a
        .put_from_reader(
            "real-bucket",
            "secret.txt",
            std::io::Cursor::new(real_secret.to_vec()),
            Some(real_secret.len() as u64),
            &Default::default(),
            None,
        )
        .await
        .expect("put secret.txt");
    alice_a
        .create_bucket("decoy-bucket")
        .await
        .expect("create decoy-bucket");
    let plausible: &[u8] = b"nothing to see here";
    alice_a
        .put_from_reader(
            "decoy-bucket",
            "plausible.txt",
            std::io::Cursor::new(plausible.to_vec()),
            Some(plausible.len() as u64),
            &Default::default(),
            None,
        )
        .await
        .expect("put plausible.txt");

    // 2. Create a duress persona at any slot other than alice's own real
    // one (primary placement is randomized, so it could be any of the
    // four - the server refuses only the caller's currently-active slot),
    // password B, revoke_other_sessions baked in from the start (exercised
    // by the later silent-switch check).
    let duress_slot = (0..4u8).find(|&s| s != alice_a_slot).unwrap();
    let resp = alice_a
        .create_persona(duress_slot, "password-B", Some("user"), true)
        .await
        .expect("create duress persona");
    assert!(
        resp.warning.contains("overwritten"),
        "expected the unconditional overwrite warning, got: {}",
        resp.warning
    );

    // 3. Share only decoy-bucket with the duress slot.
    alice_a
        .grant_persona(duress_slot, &["decoy-bucket".to_owned()])
        .await
        .expect("grant decoy-bucket to duress slot");

    // A held live A-session (separate from `alice_a`, minted before B's
    // duress login below) to prove it silently becomes B's session rather
    // than dying when password B logs in.
    let mut held_a = mk();
    let held_tok = held_a
        .login("alice", "password-A", None)
        .await
        .expect("mint held A session");
    held_a.set_token(held_tok.token);
    held_a
        .whoami_persona()
        .await
        .expect("held A session works before duress login");

    // 4. Log in with password B.
    let mut alice_b = mk();
    let tok_b = alice_b
        .login("alice", "password-B", None)
        .await
        .expect("alice login B");
    alice_b.set_token(tok_b.token.clone());

    let view = alice_b.whoami_persona().await.expect("whoami as B");
    assert_eq!(view.slot, duress_slot);
    assert_eq!(view.role, "user");

    let buckets = alice_b.list_buckets().await.expect("list buckets as B");
    assert_eq!(
        buckets,
        vec!["decoy-bucket".to_owned()],
        "B must see only the decoy bucket"
    );

    let mut got = Vec::new();
    alice_b
        .get_to_writer("decoy-bucket", "plausible.txt", &mut got)
        .await
        .expect("B reads the decoy object");
    assert_eq!(got, b"nothing to see here");

    let err = alice_b
        .get_to_writer("real-bucket", "secret.txt", &mut Vec::new())
        .await
        .expect_err("B must not read real-bucket");
    assert!(
        matches!(err, y2q_client::ClientError::NotFound { .. }),
        "expected 404 (not 403 - a 403 would confirm the bucket exists), got: {err:?}"
    );

    // Duress silent switch: the held A session, live since before B's
    // login, keeps authenticating with the *same* token - no revocation,
    // no 401 - but it now silently carries B's (duress) identity: whoami
    // reports the duress slot, and its bucket access is now B's, not the
    // real A's.
    let held_view = held_a
        .whoami_persona()
        .await
        .expect("held A session must keep working - switched in place, not revoked");
    assert_eq!(
        held_view.slot, duress_slot,
        "held session must now report the duress persona's slot"
    );
    assert_eq!(held_view.role, "user");

    let held_buckets = held_a
        .list_buckets()
        .await
        .expect("held session still lists buckets");
    assert_eq!(
        held_buckets,
        vec!["decoy-bucket".to_owned()],
        "held session must now see only the decoy bucket, like B"
    );
    let err = held_a
        .get_to_writer("real-bucket", "secret.txt", &mut Vec::new())
        .await
        .expect_err("held session must no longer read real-bucket after the silent switch");
    assert!(
        matches!(err, y2q_client::ClientError::NotFound { .. }),
        "expected 404, got: {err:?}"
    );

    alice_b
        .whoami_persona()
        .await
        .expect("B's own session keeps working");

    // 5. A fresh login with password A again - the duress persona changed
    // nothing about the real one.
    let mut alice_a2 = mk();
    let tok_a2 = alice_a2
        .login("alice", "password-A", None)
        .await
        .expect("alice re-login A");
    alice_a2.set_token(tok_a2.token);
    let mut got2 = Vec::new();
    alice_a2
        .get_to_writer("real-bucket", "secret.txt", &mut got2)
        .await
        .expect("A still reads real-bucket");
    assert_eq!(got2, b"the real secret");

    // 6. Reusing password A for a different (untouched) slot is refused
    // outright.
    let untouched_slot = (0..4u8)
        .find(|&s| s != alice_a_slot && s != duress_slot)
        .unwrap();
    let err = alice_a2
        .create_persona(untouched_slot, "password-A", Some("user"), false)
        .await
        .expect_err("password reuse across slots must be refused");
    assert!(
        matches!(err, y2q_client::ClientError::Conflict { .. }),
        "expected 409 conflict, got: {err:?}"
    );
}

/// Regression: a duress persona must not be able to destroy the account's
/// real identity through `create_persona`/`delete_persona`, and the two
/// endpoints' responses must be indistinguishable whether or not the
/// targeted slot happened to be the real one — otherwise a coercer holding
/// only a duress password could enumerate the other three slots and read
/// off which one is real from whichever refuses to change.
#[tokio::test]
async fn e2e_duress_persona_cannot_destroy_primary() {
    let Some(server) = start_server() else {
        return;
    };
    let url = server.url();
    let mk = || y2q_client::Y2qClient::new(y2q_client::ClientConfig::new(url.clone())).unwrap();

    // Login budget: the `/auth/login` rate limiter allows a burst of 5
    // requests per source IP before throttling (see `rate_limit.rs`), so
    // this test is deliberately structured to use exactly 5: root, real,
    // duress, then one final "real still works" check and one "attacker
    // password fails" check — both attacks below reuse the already
    // logged-in `duress` session rather than minting fresh ones.
    let mut root = mk();
    let root_tok = root
        .login("root", &server.password, None)
        .await
        .expect("root login");
    root.set_token(root_tok.token);
    root.add_user("mallory", "password-real", Some("user"))
        .await
        .expect("add mallory");

    let mut real = mk();
    let real_tok = real
        .login("mallory", "password-real", None)
        .await
        .expect("real login");
    real.set_token(real_tok.token);
    let real_slot = real.whoami_persona().await.expect("whoami real").slot;

    // Duress persona at any other slot.
    let duress_slot = (0..4u8).find(|&s| s != real_slot).unwrap();
    real.create_persona(duress_slot, "password-duress", Some("user"), false)
        .await
        .expect("create duress persona");

    let mut duress = mk();
    let duress_tok = duress
        .login("mallory", "password-duress", None)
        .await
        .expect("duress login");
    duress.set_token(duress_tok.token);
    assert_eq!(
        duress.whoami_persona().await.expect("whoami duress").slot,
        duress_slot
    );

    // The duress persona attempts to overwrite the real slot with an
    // attacker-controlled password.
    let resp_on_real = duress
        .create_persona(real_slot, "attacker-password", Some("user"), false)
        .await
        .expect("create_persona on the real slot must still return success");

    // Same call against a genuinely untouched (non-real) slot, for
    // response-shape comparison.
    let untouched_slot = (0..4u8)
        .find(|&s| s != real_slot && s != duress_slot)
        .unwrap();
    let resp_on_untouched = duress
        .create_persona(untouched_slot, "another-password", Some("user"), false)
        .await
        .expect("create_persona on an untouched slot");

    // The warning always echoes the caller's own requested slot number
    // (which the caller already knows - not a leak), so compare the
    // message *shape*, not literal text: both must say "overwritten",
    // neither may say anything distinguishing real from decoy.
    for w in [&resp_on_real.warning, &resp_on_untouched.warning] {
        assert!(
            w.contains("overwritten") && w.contains("grants sealed to it are gone"),
            "response must not reveal whether the target was the real slot: {w}"
        );
    }

    // Now the same attack via delete_persona: targeting the real slot must
    // also silently no-op, with an identical 204 either way.
    duress
        .delete_persona(real_slot)
        .await
        .expect("delete_persona on the real slot must still return success");

    // The real password still works after both attacks; the attacker's
    // injected password does not open any persona.
    let real2 = mk();
    real2
        .login("mallory", "password-real", None)
        .await
        .expect("real password must still work - the primary slot was never touched");
    let attacker_login = mk();
    attacker_login
        .login("mallory", "attacker-password", None)
        .await
        .expect_err("the attacker's injected password must not open any persona");
}
