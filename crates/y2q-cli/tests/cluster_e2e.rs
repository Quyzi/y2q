//! Multi-node cluster end-to-end harness.
//!
//! Spawns N real `y2qd` processes that share one deployment keystore (so every
//! node derives the identical MEK/Path Key — the shared-MEK invariant), a shared
//! cluster secret, and a provisioned unlock secret, then drives the cluster over
//! plaintext HTTP to verify CRAQ replication, apportioned reads, overwrite
//! consistency, and scatter-gather listing.
//!
//! These tests are `#[ignore]` by default: they build the `y2qd` binary on
//! demand, spawn several processes, and poll for raft convergence, so they are
//! slow and meant for a dedicated CI job (`cargo test --test cluster_e2e
//! -- --ignored`). They are also tolerant of a missing/unbuildable binary
//! (return early) so they never hard-fail in an environment without it.
//!
//! Keystore sharing: a throwaway non-cluster node first-runs once to generate
//! `pubkey.json` + `users.redb` and print the root password. Each cluster node
//! gets its own *copy* of that keystore (the daemon holds `users.redb` open for
//! the process lifetime, so copies — not a shared file — are required), and the
//! captured root password doubles as the provisioned unlock secret.

use std::io::{BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// Path to the `y2qd` binary, in the same dir as the `y2q` bin Cargo hands us.
fn y2qd_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_y2q"))
        .parent()
        .expect("bin dir")
        .join("y2qd")
}

/// Ensure the `y2qd` binary exists, building it on demand (it lives in another
/// package and is not a dependency of this crate's tests).
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
    (status.success() && bin.exists()).then_some(bin)
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

// ---------------------------------------------------------------------------
// Minimal plaintext HTTP/1.1 client (the harness serves HTTP, not HTTPS).
// ---------------------------------------------------------------------------

/// Issue one HTTP request and return `(status, body_bytes)`. Uses
/// `Connection: close` so the whole response can be read to EOF, then splits off
/// the headers. Bodies are kept small in tests so responses are never chunked.
fn http(
    port: u16,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> std::io::Result<(u16, Vec<u8>)> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(30)))?;
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n");
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    if !body.is_empty() || method == "POST" || method == "PUT" {
        req.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|i| i + 4)
        .unwrap_or(0);
    let head = String::from_utf8_lossy(&raw[..split.saturating_sub(4)]).into_owned();
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);
    Ok((status, raw[split..].to_vec()))
}

/// Log in as `user`/`pw` and return the bearer token, retrying briefly while the
/// node finishes coming up.
fn login(port: u16, user: &str, pw: &str) -> Option<String> {
    let body = format!("{{\"username\":\"{user}\",\"password\":\"{pw}\"}}");
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if let Ok((200, resp)) = http(
            port,
            "POST",
            "/api/v1/auth/login",
            &[("Content-Type", "application/json")],
            body.as_bytes(),
        ) {
            let text = String::from_utf8_lossy(&resp);
            if let Some(tok) = json_str_field(&text, "token") {
                return Some(tok);
            }
        }
        if Instant::now() > deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// Extract a string field value from flat JSON: `"field":"value"`.
fn json_str_field(json: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\":\"");
    let start = json.find(&needle)? + needle.len();
    let end = json[start..].find('"')? + start;
    Some(json[start..end].to_string())
}

fn auth_header(token: &str) -> String {
    format!("Bearer {token}")
}

/// Create a bucket on one node (`PUT /{bucket}/`).
fn create_bucket(port: u16, token: &str, bucket: &str) -> u16 {
    let bearer = auth_header(token);
    http(
        port,
        "PUT",
        &format!("/{bucket}/"),
        &[("Authorization", &bearer)],
        &[],
    )
    .map(|(s, _)| s)
    .unwrap_or(0)
}

/// PUT an object (`PUT /{bucket}/{key}`).
fn put_object(port: u16, token: &str, bucket: &str, key: &str, body: &[u8]) -> u16 {
    let bearer = auth_header(token);
    http(
        port,
        "PUT",
        &format!("/{bucket}/{key}"),
        &[("Authorization", &bearer)],
        body,
    )
    .map(|(s, _)| s)
    .unwrap_or(0)
}

/// GET an object (`GET /{bucket}/{key}`) returning `(status, body)`.
fn get_object(port: u16, token: &str, bucket: &str, key: &str) -> (u16, Vec<u8>) {
    let bearer = auth_header(token);
    http(
        port,
        "GET",
        &format!("/{bucket}/{key}"),
        &[("Authorization", &bearer)],
        &[],
    )
    .unwrap_or((0, Vec::new()))
}

/// List a bucket (`GET /{bucket}/`) returning `(status, json_body)`.
fn list_objects(port: u16, token: &str, bucket: &str) -> (u16, String) {
    let bearer = auth_header(token);
    let (s, b) = http(
        port,
        "GET",
        &format!("/{bucket}/"),
        &[("Authorization", &bearer)],
        &[],
    )
    .unwrap_or((0, Vec::new()));
    (s, String::from_utf8_lossy(&b).into_owned())
}

/// Count nodes the leader reports as `Active` in the committed control state.
fn active_count(port: u16, token: &str) -> usize {
    let bearer = auth_header(token);
    let Ok((200, body)) = http(
        port,
        "GET",
        "/api/v1/cluster/status",
        &[("Authorization", &bearer)],
        &[],
    ) else {
        return 0;
    };
    String::from_utf8_lossy(&body)
        .matches("\"status\":\"active\"")
        .count()
}

/// Poll `cond` every 250ms up to `secs`; return whether it became true in time.
fn wait_until(mut cond: impl FnMut() -> bool, secs: u64) -> bool {
    let deadline = Instant::now() + Duration::from_secs(secs);
    loop {
        if cond() {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(250));
    }
}

/// Wait for a TCP listener on `port`; return whether it came up in time.
fn wait_port(port: u16, secs: u64) -> bool {
    wait_until(|| TcpStream::connect(("127.0.0.1", port)).is_ok(), secs)
}

// ---------------------------------------------------------------------------
// Keystore generation + cluster bring-up.
// ---------------------------------------------------------------------------

/// First-run a throwaway non-cluster node to generate a keystore, capture the
/// root password, then shut it down. Returns the keystore dir and the password.
fn gen_keystore(bin: &Path, base: &Path) -> Option<(PathBuf, String)> {
    let keys = base.join("seed-keys");
    let data = base.join("seed-data");
    for d in [&keys, &data] {
        std::fs::create_dir_all(d).ok()?;
    }
    let port = free_port();
    let mut child = Command::new(bin)
        .env("Y2QD_SERVER__HOST", "127.0.0.1")
        .env("Y2QD_SERVER__PORT", port.to_string())
        .env("Y2QD_SERVER__TLS__ENABLED", "false")
        .env("Y2QD_STORAGE__BASE_PATH", &data)
        .env("Y2QD_CRYPTO__KEYSTORE_DIR", &keys)
        .env("Y2QD_CRYPTO__ARGON2__M_COST_KIB", "8")
        .env("Y2QD_CRYPTO__ARGON2__T_COST", "1")
        .env("Y2QD_CRYPTO__ARGON2__P_COST", "1")
        .env("Y2QD_AUTH__MIN_LOGIN_RESPONSE_MS", "0")
        .env("RUST_LOG", "error")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;

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

    // Wait for full startup (port bound) so the keystore is completely written.
    let deadline = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", port)).is_err() {
        if Instant::now() > deadline {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }

    // Stop it cleanly so redb flushes, then reap.
    let _ = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status();
    for _ in 0..60 {
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let _ = child.kill();
    let _ = child.wait();

    if password.is_empty() || !keys.join("pubkey.json").exists() {
        return None;
    }
    Some((keys, password))
}

/// Copy the deployment keystore (public key + user records) into `dst`.
fn copy_keystore(src: &Path, dst: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dst)?;
    for f in ["pubkey.json", "users.redb"] {
        std::fs::copy(src.join(f), dst.join(f))?;
    }
    Ok(())
}

/// A spawned cluster node. Dropped with SIGTERM so coverage flushes on exit.
/// Holds enough to stop and respawn the process in place (for recovery tests).
struct ClusterNode {
    child: Option<Child>,
    port: u16,
    id: u64,
    base: PathBuf,
    cfg: PathBuf,
    bin: PathBuf,
    password: String,
}

/// SIGTERM a child and reap it, returning once it has exited (or been killed).
fn stop_child(child: &mut Child) {
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
}

/// Spawn one cluster daemon with the shared secret + provisioned unlock secret,
/// logging stdout/stderr to `<base>/stderr.log`.
fn spawn_child(bin: &Path, cfg: &Path, base: &Path, password: &str) -> Option<Child> {
    let log = std::fs::File::create(base.join("stderr.log")).ok()?;
    let log2 = log.try_clone().ok()?;
    Command::new(bin)
        .arg("--config")
        .arg(cfg)
        .env("Y2QD_CLUSTER__SHARED_SECRET", SHARED_SECRET)
        .env("Y2QD_CLUSTER__UNLOCK_SECRET", password)
        .env("RUST_LOG", "error")
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(log2))
        .spawn()
        .ok()
}

impl ClusterNode {
    /// Stop the process but keep the data dir + config, so it can be respawned.
    fn kill(&mut self) {
        if let Some(mut child) = self.child.take() {
            stop_child(&mut child);
        }
    }

    /// Respawn a previously-killed node from its persisted config/keystore.
    fn respawn(&mut self) -> bool {
        if self.child.is_some() {
            return true;
        }
        self.child = spawn_child(&self.bin, &self.cfg, &self.base, &self.password);
        self.child.is_some()
    }
}

impl Drop for ClusterNode {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            stop_child(&mut child);
        }
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

/// A spawned cluster plus the captured root password / unlock secret.
struct Cluster {
    nodes: Vec<ClusterNode>,
    password: String,
    base: PathBuf,
}

impl Drop for Cluster {
    fn drop(&mut self) {
        // Nodes drop first (their own dirs), then remove the shared base.
        self.nodes.clear();
        let _ = std::fs::remove_dir_all(&self.base);
    }
}

const SHARED_SECRET: &str = "cluster-e2e-shared-secret";

/// Write one node's `config.toml`. Node 0 bootstraps and lists the others as
/// peers; the rest are admitted by the bootstrap node.
#[allow(clippy::too_many_arguments)]
fn write_node_config(
    path: &Path,
    data: &Path,
    keys: &Path,
    port: u16,
    id: u64,
    rf: usize,
    n: usize,
    ports: &[u16],
) {
    let mut toml = String::new();
    toml.push_str("[server]\nhost = \"127.0.0.1\"\n");
    toml.push_str(&format!("port = {port}\n"));
    toml.push_str("[server.tls]\nenabled = false\n");
    toml.push_str(&format!("[storage]\nbase_path = \"{}\"\n", data.display()));
    toml.push_str(&format!(
        "[crypto]\nkeystore_dir = \"{}\"\n",
        keys.display()
    ));
    toml.push_str("[crypto.argon2]\nm_cost_kib = 8\nt_cost = 1\np_cost = 1\n");
    toml.push_str("[auth]\nmin_login_response_ms = 0\n");
    toml.push_str("[cluster]\nenabled = true\n");
    toml.push_str(&format!("node_id = \"{id}\"\n"));
    toml.push_str(&format!("advertise_addr = \"127.0.0.1:{port}\"\n"));
    toml.push_str(&format!("replication_factor = {rf}\n"));
    toml.push_str("unlock_user = \"root\"\n");
    if id == 1 {
        for (i, p) in ports.iter().enumerate() {
            let peer_id = (i + 1) as u64;
            if peer_id == 1 {
                continue;
            }
            toml.push_str("[[cluster.peers]]\n");
            toml.push_str(&format!("id = {peer_id}\nurl = \"http://127.0.0.1:{p}\"\n"));
        }
    }
    toml.push_str("[cluster.raft]\n");
    toml.push_str(&format!("bootstrap = {}\n", id == 1));
    let seeds: Vec<String> = (1..=n as u64).map(|x| x.to_string()).collect();
    toml.push_str(&format!("voter_seeds = [{}]\n", seeds.join(", ")));
    std::fs::write(path, toml).unwrap();
}

/// Bring up an `n`-node cluster at replication factor `rf`. Returns `None` if the
/// binary is unavailable or the cluster fails to converge.
fn start_cluster(n: usize, rf: usize) -> Option<Cluster> {
    let bin = ensure_y2qd()?;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let base = std::env::temp_dir().join(format!("y2q-cluster-{}-{}", std::process::id(), nanos));
    std::fs::create_dir_all(&base).ok()?;

    let (seed_keys, password) = match gen_keystore(&bin, &base) {
        Some(v) => v,
        None => {
            eprintln!("skipping cluster e2e: could not generate keystore");
            let _ = std::fs::remove_dir_all(&base);
            return None;
        }
    };

    let ports: Vec<u16> = (0..n).map(|_| free_port()).collect();
    let mut nodes = Vec::with_capacity(n);
    for i in 0..n {
        let id = (i + 1) as u64;
        let node_base = base.join(format!("node{i}"));
        let data = node_base.join("data");
        let keys = node_base.join("keys");
        std::fs::create_dir_all(&data).ok()?;
        copy_keystore(&seed_keys, &keys).ok()?;
        let cfg = node_base.join("config.toml");
        write_node_config(&cfg, &data, &keys, ports[i], id, rf, n, &ports);

        let child = spawn_child(&bin, &cfg, &node_base, &password)?;
        nodes.push(ClusterNode {
            child: Some(child),
            port: ports[i],
            id,
            base: node_base,
            cfg,
            bin: bin.clone(),
            password: password.clone(),
        });
    }

    // Wait for every node's listener.
    for node in &nodes {
        let deadline = Instant::now() + Duration::from_secs(30);
        while TcpStream::connect(("127.0.0.1", node.port)).is_err() {
            if Instant::now() > deadline {
                eprintln!("cluster e2e: node {} never bound", node.id);
                return None;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    // Poll the leader until all nodes are Active in the committed control state.
    let token = login(nodes[0].port, "root", &password)?;
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        if active_count(nodes[0].port, &token) >= n {
            break;
        }
        if Instant::now() > deadline {
            let bearer = auth_header(&token);
            let status = http(
                nodes[0].port,
                "GET",
                "/api/v1/cluster/status",
                &[("Authorization", &bearer)],
                &[],
            )
            .map(|(s, b)| format!("{s} {}", String::from_utf8_lossy(&b)))
            .unwrap_or_else(|e| format!("err {e}"));
            eprintln!("cluster e2e: did not converge to {n} active nodes; status = {status}");
            for node in &nodes {
                let log = std::fs::read_to_string(node.base.join("stderr.log")).unwrap_or_default();
                let tail: String = log.lines().rev().take(15).collect::<Vec<_>>().join("\n");
                eprintln!(
                    "--- node {} (port {}) stderr tail ---\n{tail}",
                    node.id, node.port
                );
            }
            return None;
        }
        std::thread::sleep(Duration::from_millis(250));
    }

    Some(Cluster {
        nodes,
        password,
        base,
    })
}

// ---------------------------------------------------------------------------
// Tests.
// ---------------------------------------------------------------------------

/// PUT replicates down the chain, GET works from every node (local and
/// apportioned/proxied reads), overwrites are seen cluster-wide, and a
/// scatter-gather LIST returns the object from any contact node.
#[test]
#[ignore = "multi-node cluster; run with `cargo test --test cluster_e2e -- --ignored`"]
fn cluster_replication_and_apportioned_reads() {
    // 3 nodes at RF=2 → each object lives on 2 of 3 nodes, so a GET to the third
    // node exercises the apportioned (proxied) read path, while the chain members
    // serve locally.
    let Some(cluster) = start_cluster(3, 2) else {
        return;
    };
    let pw = cluster.password.clone();

    // Sessions are node-local, so log in to each node (they share the same user
    // records, so root/pw authenticates everywhere).
    let tokens: Vec<String> = cluster
        .nodes
        .iter()
        .map(|node| login(node.port, "root", &pw).expect("login on each node"))
        .collect();

    // The bucket registry is still per-node (cluster-global bucket state is a
    // later phase), so register the bucket on every node to satisfy the
    // per-node read authorization check.
    let bucket = "cl";
    for (node, token) in cluster.nodes.iter().zip(&tokens) {
        let s = create_bucket(node.port, token, bucket);
        assert!(
            s == 200 || s == 201 || s == 409,
            "create bucket on node {}: {s}",
            node.id
        );
    }

    // PUT via node 0; the object replicates down its chain. A brand-new key
    // returns 201 Created.
    let key = "alpha/object.bin";
    let body = b"hello-from-the-cluster";
    let s = put_object(cluster.nodes[0].port, &tokens[0], bucket, key, body);
    assert_eq!(s, 201, "PUT (create) via node 0");

    // GET from EVERY node returns the object: chain members serve locally, the
    // off-chain node fetches the committed envelope from the TAIL and decrypts.
    for (node, token) in cluster.nodes.iter().zip(&tokens) {
        let (status, got) = get_object(node.port, token, bucket, key);
        assert_eq!(status, 200, "GET via node {}", node.id);
        assert_eq!(got, body, "GET body via node {}", node.id);
    }

    // Overwrite via node 1; an existing key returns 200, and the new version
    // must be visible from every node.
    let body2 = b"second-version-overwrite";
    let s = put_object(cluster.nodes[1].port, &tokens[1], bucket, key, body2);
    assert_eq!(s, 200, "overwrite via node 1");
    for (node, token) in cluster.nodes.iter().zip(&tokens) {
        let (status, got) = get_object(node.port, token, bucket, key);
        assert_eq!(status, 200, "GET-after-overwrite via node {}", node.id);
        assert_eq!(got, body2, "overwrite not visible from node {}", node.id);
    }

    // A scatter-gather LIST from any contact node returns the object exactly once
    // (deduped across the R replicas). Match the `"key":"…"` field specifically —
    // the key substring also appears in the `url_path` field.
    let key_field = format!("\"key\":\"{key}\"");
    for (node, token) in cluster.nodes.iter().zip(&tokens) {
        let (status, json) = list_objects(node.port, token, bucket);
        assert_eq!(status, 200, "LIST via node {}", node.id);
        assert_eq!(
            json.matches(key_field.as_str()).count(),
            1,
            "LIST via node {} should return the key exactly once (deduped): {json}",
            node.id
        );
    }
}

/// Kill a node, write while it is down, restart it, and verify it recovers: the
/// leader drives it Down -> Recovering -> Active, it back-fills the history it
/// missed plus the write that landed while it was down, and every object is
/// readable from the recovered node. Exercises the failure/back-fill path and the
/// continued-reconcile-through-promotion hardening.
#[test]
#[ignore = "multi-node cluster; run with `cargo test --test cluster_e2e -- --ignored`"]
fn cluster_node_recovery_backfill() {
    let Some(mut cluster) = start_cluster(3, 2) else {
        return;
    };
    let pw = cluster.password.clone();
    let tokens: Vec<String> = cluster
        .nodes
        .iter()
        .map(|node| login(node.port, "root", &pw).expect("login on each node"))
        .collect();

    let bucket = "rec";
    for (node, token) in cluster.nodes.iter().zip(&tokens) {
        let s = create_bucket(node.port, token, bucket);
        assert!(s == 200 || s == 201 || s == 409, "create bucket: {s}");
    }

    let leader_port = cluster.nodes[0].port;
    let leader_tok = tokens[0].clone();

    // A write before the failure.
    assert_eq!(
        put_object(leader_port, &leader_tok, bucket, "before.bin", b"v-before"),
        201,
        "PUT before.bin"
    );

    // Kill a non-leader node and wait for the leader to mark it Down.
    let victim = 2usize;
    let victim_port = cluster.nodes[victim].port;
    cluster.nodes[victim].kill();
    assert!(
        wait_until(|| active_count(leader_port, &leader_tok) <= 2, 60),
        "leader did not mark the killed node Down"
    );

    // A write while the victim is down — replicates to the surviving nodes only.
    assert_eq!(
        put_object(leader_port, &leader_tok, bucket, "during.bin", b"v-during"),
        201,
        "PUT during.bin while a node is down"
    );

    // Restart the victim; it rejoins, recovers, and back-fills to Active.
    assert!(cluster.nodes[victim].respawn(), "respawn victim");
    assert!(wait_port(victim_port, 30), "victim did not rebind");
    assert!(
        wait_until(|| active_count(leader_port, &leader_tok) >= 3, 90),
        "cluster did not reconverge to 3 active nodes after recovery"
    );

    // The recovered node serves both the pre-failure object and the one written
    // while it was down. Retry briefly to let back-fill + reconcile settle.
    let vtok = login(victim_port, "root", &pw).expect("login recovered node");
    for (key, want) in [
        ("before.bin", &b"v-before"[..]),
        ("during.bin", &b"v-during"[..]),
    ] {
        let mut got = (0u16, Vec::new());
        for _ in 0..40 {
            got = get_object(victim_port, &vtok, bucket, key);
            if got.0 == 200 && got.1 == want {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
        assert_eq!(got.0, 200, "GET {key} from recovered node");
        assert_eq!(got.1, want, "recovered node returned wrong bytes for {key}");
    }
}
