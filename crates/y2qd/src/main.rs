//! `y2qd` — HTTP daemon for the y2q post-quantum secure object store.
//!
//! Exposes [`y2q_core::Storage`] operations over a REST API protected by a
//! token-based authentication system. Objects are addressed by a
//! `(bucket, key)` pair extracted from the URL path. Keys may contain `/`
//! characters; the route pattern `/{bucket}/{tail}*` captures the entire
//! remainder of the path as the key.
//!
//! # Configuration
//!
//! Loaded from `config.toml` in the working directory, with environment
//! variable overrides. See [`config::Config`] for the full schema. Example:
//!
//! ```toml
//! [server]
//! host = "127.0.0.1"
//! port = 8080
//!
//! [storage]
//! base_path = "/var/lib/y2qd/objects"
//!
//! [crypto]
//! keystore_dir = "/var/lib/y2qd/keystore"
//! ```
//!
//! # First-run setup
//!
//! The daemon refuses to start without an operator-supplied node key
//! (`Y2QD_NODE_KEY` env var or `[crypto] node_key_file`; never
//! auto-generated). Given a valid node key and no `keystore.json` in
//! `[crypto] keystore_dir`, it treats this as first-run: generates a
//! `root` identity keypair, wraps its secret key under a
//! randomly-generated password, prints the password to stdout exactly
//! once, and persists the keystore verifier + user record. RECORD THIS
//! PASSWORD — losing it requires resetting everything.
//!
//! # Authentication
//!
//! All routes (objects, listing, admin) require a Bearer token. Obtain one
//! via `POST /api/v1/auth/login` with `{"username": "...", "password": "..."}`.
//!
//! # Swagger UI
//!
//! Available at `/swagger-ui/` when the server is running. The raw OpenAPI
//! JSON is served at `/api-docs/openapi.json`. By default both require
//! authentication; set `[server] unauthenticated_metrics = true` to expose
//! them without a token.
//!
//! # Metrics
//!
//! An interactive dashboard is served at `/metrics/dashboard`. Prometheus
//! scrape endpoint: `/metrics/prometheus`. Auth-gated by default.
//!
//! # Logging
//!
//! Set `RUST_LOG` to control verbosity, e.g. `RUST_LOG=y2qd=debug,actix_web=info`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

#[cfg(feature = "pyroscope")]
use pyroscope::backend::{BackendConfig, PprofConfig, pprof_backend};
#[cfg(feature = "pyroscope")]
use pyroscope::pyroscope::PyroscopeAgentBuilder;

use actix_web::{App, HttpServer, http::KeepAlive, middleware::from_fn, web};
use clap::Parser;
use metrics_exporter_prometheus::Matcher;
use metrics_rs_dashboard_actix::{DashboardInput, create_metrics_actx_scope};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;
use crate::span::Y2qRootSpanBuilder;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use y2q_core::crypto::{Argon2Params, keystore as keystore_mod, node_key};
use y2q_core::{AnyStorage, FilesystemStorage, StorageExt};

#[cfg(target_os = "linux")]
use y2q_core::{UringStorage, storage::uring::UringConfig};

mod auth;
mod authz;
mod bucket_keys;
mod cipher;
mod cli;
mod cluster;
mod config;
mod error;
mod handlers;
mod node_key_rotation;
pub(crate) mod observability;
mod rate_limit;
mod request_id;
mod span;
mod tls;
mod trace;

use crate::auth::AuthState;
use crate::trace::TraceHub;

struct IgnoreBrokenPipe<W>(W);

impl<W: std::io::Write> std::io::Write for IgnoreBrokenPipe<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.0.write(buf) {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(buf.len()),
            other => other,
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self.0.flush() {
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            other => other,
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "y2qd",
        description = "Post-quantum secure object store HTTP daemon",
        version = "0.1.0",
    ),
    paths(
        handlers::get::handle,
        handlers::put::handle,
        handlers::delete::handle,
        handlers::head::handle,
        handlers::list_buckets::handle,
        handlers::list_objects::handle,
        handlers::search::handle,
        handlers::buckets::create,
        handlers::buckets::remove,
        handlers::buckets::get_config,
        handlers::buckets::set_config,
        handlers::acl::get_acl,
        handlers::acl::set_acl,
        handlers::keys::rotate_key,
        handlers::keys::start_rekey,
        handlers::keys::rekey_status,
        handlers::tags::handle,
        handlers::rebuild::start,
        handlers::rebuild::status,
        handlers::locks::list,
        handlers::locks::clear,
        auth::handlers::login,
        auth::handlers::refresh,
        auth::handlers::logout,
        auth::handlers::change_password,
        auth::handlers::delete_user,
        auth::handlers::reset_identity,
        auth::handlers::add_user,
        auth::handlers::list_users,
        auth::handlers::set_role,
        auth::handlers::create_persona,
        auth::handlers::delete_persona,
        auth::handlers::whoami_persona,
        handlers::personas::grant_persona,
        handlers::personas::revoke_persona_grant,
    ),
    components(schemas(
        error::ErrorBody,
        handlers::list_buckets::ListBucketsResponse,
        handlers::buckets::CreateBucketResponse,
        handlers::buckets::DeleteBucketResponse,
        handlers::buckets::BucketConfigBody,
        handlers::acl::AclBody,
        handlers::keys::RotateKeyResponse,
        handlers::keys::RekeyStartResponse,
        handlers::keys::RekeyStatusResponse,
        handlers::tags::SetTagsResponse,
        handlers::list_objects::ListObjectsResponse,
        handlers::list_objects::MetadataView,
        handlers::rebuild::RebuildStartResponse,
        handlers::rebuild::RebuildStatusResponse,
        handlers::locks::StaleLockEntry,
        handlers::locks::ClearStaleLocksResponse,
        auth::handlers::LoginRequest,
        auth::handlers::TokenResponse,
        auth::handlers::ListUsersResponse,
        auth::handlers::UserView,
        auth::handlers::ResetIdentityRequest,
        auth::handlers::ResetIdentityResponse,
        auth::handlers::ChangePasswordRequest,
        auth::handlers::AddUserRequest,
        auth::handlers::SetRoleRequest,
        auth::handlers::PersonaCreateRequest,
        auth::handlers::PersonaCreateResponse,
        auth::handlers::PersonaView,
        handlers::personas::PersonaGrantBody,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "objects", description = "Object storage — read, write, and delete objects addressed by bucket/key"),
        (name = "listing", description = "Enumerate buckets and the objects within them"),
        (name = "buckets", description = "Explicit bucket lifecycle — create and delete buckets"),
        (name = "tags", description = "Mutate object labels (tags/attributes) without re-upload"),
        (name = "admin", description = "Administrative operations — secondary-index rebuild, stale-lock cleanup"),
        (name = "auth", description = "Session login/refresh/logout and password change"),
        (name = "users", description = "Add, list, and delete users authorized to log in"),
        (name = "personas", description = "Multiple passwords per user (duress personas) and self-service bucket sharing between them"),
    ),
)]
struct ApiDoc;

/// Adds a `bearer` security scheme to the generated OpenAPI document so
/// `security(("bearer" = []))` annotations on individual operations resolve.
struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};
        let components = openapi
            .components
            .get_or_insert(utoipa::openapi::Components::new());
        components.add_security_scheme(
            "bearer",
            SecurityScheme::Http(
                HttpBuilder::new()
                    .scheme(HttpAuthScheme::Bearer)
                    .bearer_format("token")
                    .build(),
            ),
        );
    }
}

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = cli::Cli::parse();

    let cfg = config::Config::load(&cli)
        .expect("failed to load config (config.toml, Y2QD_* env vars, or --set)");

    // RUST_LOG takes precedence; fall back to the config-file filter.
    let log_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| {
        EnvFilter::new(format!(
            "{},metrics_rs_dashboard_actix=warn",
            cfg.observability.log_filter
        ))
    });

    match cfg.observability.log_format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(log_filter)
            .with_writer(|| IgnoreBrokenPipe(std::io::stdout()))
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_filter)
            .with_writer(|| IgnoreBrokenPipe(std::io::stdout()))
            .init(),
    }

    tracing::info!(host = %cfg.server.host, port = cfg.server.port, "starting y2qd");

    // Offline node-key rotation short-circuits the entire normal boot
    // sequence: it acquires its own flock, walks the storage tree, and exits.
    if cli.rotate_node_key {
        let new_node_key_file = cli
            .new_node_key_file
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        return node_key_rotation::run(&cfg, new_node_key_file).await;
    }

    #[cfg(feature = "pyroscope")]
    let _pyroscope_agent = {
        let pcfg = &cfg.observability.pyroscope;
        if pcfg.enabled {
            let sample_rate = pcfg.sample_rate;
            let backend_label = match cfg.storage.backend {
                config::StorageBackend::Filesystem => "filesystem",
                config::StorageBackend::Uring => "uring",
            };
            let mut builder = PyroscopeAgentBuilder::new(
                &pcfg.server_url,
                "y2qd",
                sample_rate,
                "pyroscope-rs",
                env!("CARGO_PKG_VERSION"),
                pprof_backend(PprofConfig { sample_rate }, BackendConfig::default()),
            )
            .tags(vec![
                ("version", env!("CARGO_PKG_VERSION")),
                ("backend", backend_label),
            ]);
            if let (Some(user), Some(pass)) = (&pcfg.basic_auth_user, &pcfg.basic_auth_password) {
                builder = builder.basic_auth(user.as_str(), pass.as_str());
            }
            let agent = builder
                .build()
                .map_err(|e| std::io::Error::other(format!("pyroscope build: {e}")))?;
            let agent_running = agent
                .start()
                .map_err(|e| std::io::Error::other(format!("pyroscope start: {e}")))?;
            tracing::info!(server_url = %pcfg.server_url, sample_rate, "pyroscope profiling started");
            Some(agent_running)
        } else {
            None
        }
    };

    // Acquire daemon-wide flock on the keystore directory before doing
    // anything else — prevents two y2qd processes from racing over the
    // same keystore.
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);
    if keystore_mod::rotation_journal_exists(&keystore_dir) {
        return Err(std::io::Error::other(node_key_rotation::INTERRUPTED_MESSAGE));
    }
    let _flock = keystore_mod::acquire_lock(&keystore_dir)
        .map_err(|e| std::io::Error::other(format!("acquire keystore lock: {e}")))?;

    // Resolve the operator-supplied node key. Never auto-generated — refuses
    // to start without one. Also refuse a node_key_file that resolves inside
    // storage.base_path or keystore_dir, so a copy of the data can't carry
    // the key that protects it.
    node_key::check_node_key_location(
        &cfg.crypto.node_key_file,
        std::path::Path::new(&cfg.storage.base_path),
        &keystore_dir,
    )
    .map_err(std::io::Error::other)?;
    let nk = node_key::load_node_key(&cfg.crypto.node_key_file)
        .map_err(|e| std::io::Error::other(format!("node key: {e}")))?;
    let node_key_verifier = y2q_core::crypto::derive_node_key_verifier(&nk);
    let node_key_fingerprint = to_hex(&node_key_verifier);

    // Load or first-run the keystore.
    let argon2_for_first_run = Argon2Params::with_random_salt(
        cfg.crypto.argon2.m_cost_kib,
        cfg.crypto.argon2.t_cost,
        cfg.crypto.argon2.p_cost,
    );
    let user_store = match keystore_mod::load(&keystore_dir, &nk) {
        Ok(store) => store,
        Err(y2q_core::crypto::CryptoError::KeystoreMissing(_)) => {
            tracing::info!(
                dir = %keystore_dir.display(),
                "no keystore found; running first-run setup"
            );
            let outcome =
                keystore_mod::first_run(&keystore_dir, "root", argon2_for_first_run, &nk)
                    .map_err(|e| std::io::Error::other(format!("first-run setup: {e}")))?;
            print_first_run_password(&outcome.root_username, &outcome.root_password);
            tracing::info!(dir = %keystore_dir.display(), "keystore initialized");
            outcome.user_store
        }
        Err(e) => {
            return Err(std::io::Error::other(format!("load keystore: {e}")));
        }
    };

    // Records written before the role field default to `User` on load. Without
    // this, an upgraded deployment would have zero admins and lock everyone out
    // of the admin endpoints — so ensure at least one administrator exists.
    reconcile_admin(&user_store)?;

    tracing::info!(node_key_fingerprint = %node_key_fingerprint[..16], "node key loaded");

    let index_path = cfg
        .storage
        .index_path
        .clone()
        .unwrap_or_else(|| format!("{}/_y2q_index.redb", cfg.storage.base_path));

    let (dirty_tx, dirty_rx) = flume::unbounded::<y2q_core::DirtyEntry>();
    let flush_notify = Arc::new(tokio::sync::Notify::new());

    let storage: Arc<AnyStorage> = Arc::new(match cfg.storage.backend {
        config::StorageBackend::Filesystem => AnyStorage::Filesystem(
            FilesystemStorage::new(&cfg.storage.base_path, &index_path)
                .map_err(|e| std::io::Error::other(format!("storage init: {e}")))?
                .with_dirty_channel(dirty_tx, flush_notify.clone(), cfg.storage.sync_flush_limit),
        ),
        #[cfg(target_os = "linux")]
        config::StorageBackend::Uring => AnyStorage::Uring({
            let ur = &cfg.storage.uring;
            let uring_cfg = UringConfig {
                workers: ur.workers.unwrap_or_else(|| {
                    std::thread::available_parallelism()
                        .map(|n| n.get())
                        .unwrap_or(4)
                }),
                large_object_bytes: ur.large_object_bytes,
                sq_entries: ur.sq_entries,
                cq_entries: ur.cq_entries,
                sq_poll: ur.sq_poll,
                sq_poll_idle_ms: ur.sq_poll_idle_ms,
                sq_poll_cpu: ur.sq_poll_cpu,
                io_poll: ur.io_poll,
                single_issuer: ur.single_issuer,
                coop_taskrun: ur.coop_taskrun,
            };
            UringStorage::new(&cfg.storage.base_path, &index_path, uring_cfg)
                .map_err(|e| std::io::Error::other(format!("storage init: {e}")))?
        }),
        #[cfg(not(target_os = "linux"))]
        config::StorageBackend::Uring => {
            return Err(std::io::Error::other(
                "storage.backend = \"uring\" is only available on Linux; use \"filesystem\" on this platform",
            ));
        }
    });
    let storage_data = web::Data::new(storage);

    // Install the node key on the active backend — the daemon's own keys
    // (index, paths, object metadata) now come from the operator, not from
    // whoever logs in first. Drop the raw key immediately afterward; every
    // holder from here on is a derived, domain-separated sub-key. Cluster
    // builds also need the Control Store Key (CSK) to encrypt the Raft
    // control redb; derive it now, before the raw node key is dropped.
    let control_store_key = y2q_core::crypto::derive_control_store_key(&nk);
    storage_data.install_node_key(*nk);
    drop(nk);

    // Startup auto-rebuild: repair index consistency after any unclean
    // shutdown. Runs immediately — the node key is already installed, so
    // there is no session to wait for.
    {
        let storage_clone = Arc::clone(storage_data.as_ref());
        tokio::spawn(async move {
            if let Err(e) = storage_clone.rebuild_cache().await {
                tracing::warn!(error = %e, "startup cache rebuild failed to initiate");
            } else {
                tracing::info!("startup cache rebuild initiated");
            }
        });
    }

    let auth_state = web::Data::new(AuthState::new(
        user_store,
        cfg.auth.clone(),
        cfg.crypto.argon2.clone(),
    ));

    // Build the cluster runtime (control plane) when clustering is enabled.
    // Cluster admission is fingerprinted by the node-key verifier — every
    // node already has its own node key, so there is no unlock secret to
    // provision here.
    let cluster_runtime: Option<web::Data<cluster::ClusterRuntime>> = if cfg.cluster.enabled {
        let rt = cluster::build_runtime(
            &cfg,
            Arc::clone(storage_data.as_ref()),
            &node_key_fingerprint,
            control_store_key,
        )
        .await
        .map_err(|e| std::io::Error::other(format!("cluster startup: {e}")))?;
        let rt = web::Data::new(rt);
        // Leader-driven failure detection + re-splice loop.
        cluster::spawn_maintenance(
            rt.clone(),
            cfg.cluster.health_probe_interval_ms,
            cfg.cluster.health_fail_threshold,
        );
        // Mirror the replicated bucket + user registries into local stores on
        // every apply (a joined node inherits all bucket configs and users).
        cluster::spawn_registry_projector(rt.clone(), auth_state.clone());
        Some(rt)
    } else {
        None
    };

    // Background sweeper for expired sessions.
    {
        let auth_state = auth_state.clone();
        let interval = Duration::from_secs(cfg.auth.session_sweep_interval_seconds.max(1));
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let removed = auth_state.sessions.sweep();
                if removed > 0 {
                    tracing::debug!(removed, "swept expired sessions");
                }
            }
        });
    }

    let label_limits = web::Data::new(config::LabelLimits::from(&cfg.storage));
    let default_sync = web::Data::new(cfg.storage.default_sync);
    let encryption_params = web::Data::new(config::EncryptionParams {
        chunk_size_bytes: cfg.crypto.envelope_chunk_size_bytes,
        max_body_bytes: cfg.server.max_body_bytes as u64,
    });
    let rekey_registry = web::Data::new(handlers::keys::RekeyRegistry::new());

    // Background dirty flusher: drains best-effort PUT paths and fsyncs them.
    {
        let interval = Duration::from_secs(cfg.storage.sync_flush_interval_secs.max(1));
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {}
                    _ = flush_notify.notified() => {}
                }
                let mut dirs: HashSet<PathBuf> = HashSet::new();
                let mut files: Vec<PathBuf> = Vec::new();
                while let Ok(entry) = dirty_rx.try_recv() {
                    files.push(entry.obj_path);
                    dirs.insert(entry.parent_dir);
                }
                for path in files {
                    if let Ok(f) = tokio::fs::File::open(&path).await {
                        let _ = f.sync_data().await;
                    }
                }
                for dir in dirs {
                    if let Ok(d) = tokio::fs::File::open(&dir).await {
                        let _ = d.sync_all().await;
                    }
                }
            }
        });
    }

    let openapi = ApiDoc::openapi();

    let trace_hub = web::Data::new(Arc::new(TraceHub::new()));

    let max_body_bytes = cfg.server.max_body_bytes;
    let expose_unauthed = cfg.server.unauthenticated_metrics;
    if !expose_unauthed {
        tracing::info!(
            "metrics dashboard, prometheus scrape, and swagger UI are NOT exposed; \
             set [server] unauthenticated_metrics = true to enable them"
        );
    }

    // Extract actix knobs before the move closure captures `cfg`.
    let actix_workers = cfg.server.actix.workers;
    let actix_backlog = cfg.server.actix.backlog;
    let actix_max_connections = cfg.server.actix.max_connections;
    let actix_keep_alive = if cfg.server.actix.keep_alive_secs == 0 {
        KeepAlive::Disabled
    } else {
        KeepAlive::Timeout(Duration::from_secs(cfg.server.actix.keep_alive_secs))
    };
    let actix_req_timeout = Duration::from_secs(cfg.server.actix.client_request_timeout_secs);
    let actix_disc_timeout = Duration::from_secs(cfg.server.actix.client_disconnect_timeout_secs);
    let actix_shutdown = cfg.server.actix.shutdown_timeout_secs;

    let mut server = HttpServer::new(move || {
        // The dashboard crate installs its own Prometheus recorder on first
        // call (once per process via once_cell). Custom histogram buckets are
        // threaded through DashboardInput so the recorder is configured
        // identically across all worker threads.
        let dashboard_input = DashboardInput {
            buckets_for_metrics: vec![
                (
                    Matcher::Suffix(observability::PAYLOAD_METRIC_SUFFIX.to_string()),
                    observability::PAYLOAD_BUCKETS_BYTES,
                ),
                (
                    Matcher::Full(observability::DURATION_METRIC_NAME.to_string()),
                    observability::DURATION_BUCKETS_MILLIS,
                ),
                (
                    Matcher::Suffix(observability::STORAGE_DURATION_METRIC_SUFFIX.to_string()),
                    observability::STORAGE_DURATION_BUCKETS_MILLIS,
                ),
                (
                    Matcher::Full(observability::CLUSTER_PREPARE_HOP_DURATION.to_string()),
                    observability::DURATION_BUCKETS_MILLIS,
                ),
                (
                    Matcher::Full(observability::CLUSTER_COMMIT_DURATION.to_string()),
                    observability::DURATION_BUCKETS_MILLIS,
                ),
            ],
        };
        let dashboard_scope = create_metrics_actx_scope(&dashboard_input)
            .expect("failed to create metrics dashboard scope");
        // describe_* is idempotent; call it here so HELP/TYPE lines appear
        // in the output as soon as the recorder is installed.
        observability::describe_metrics();

        let mut app = App::new()
            .wrap(from_fn(request_id::request_id_middleware))
            .wrap(TracingLogger::<Y2qRootSpanBuilder>::new())
            .wrap(from_fn(observability::metrics_middleware))
            .wrap(from_fn(trace::trace_middleware))
            .app_data(trace_hub.clone())
            .app_data(storage_data.clone())
            .app_data(label_limits.clone())
            .app_data(default_sync.clone())
            .app_data(encryption_params.clone())
            .app_data(rekey_registry.clone())
            .app_data(auth_state.clone())
            .app_data(web::PayloadConfig::new(max_body_bytes));
        // Register cluster routes before handlers::configure so the specific
        // /internal/v1 and /api/v1/cluster paths win over the greedy object
        // route. Only present when clustering is enabled.
        if let Some(rt) = &cluster_runtime {
            app = app.app_data(rt.clone()).configure(cluster::configure);
        }
        // Swagger UI and metrics dashboard are unauthenticated (actix doesn't
        // make it easy to wrap third-party scopes with our extractor). Only
        // register them when the operator has explicitly opted in.
        if expose_unauthed {
            app = app
                .service(
                    SwaggerUi::new("/swagger-ui/{_:.*}")
                        .url("/api-docs/openapi.json", openapi.clone()),
                )
                // Dashboard scope must be registered before handlers::configure,
                // which contains the greedy /{bucket}/{tail}* pattern that would
                // otherwise capture /metrics/dashboard.
                .service(dashboard_scope);
        }
        app.configure(handlers::configure)
    });

    if let Some(w) = actix_workers {
        server = server.workers(w);
    }
    server = server
        .backlog(actix_backlog)
        .max_connections(actix_max_connections)
        .keep_alive(actix_keep_alive)
        .client_request_timeout(actix_req_timeout)
        .client_disconnect_timeout(actix_disc_timeout)
        .shutdown_timeout(actix_shutdown);

    let bind_addr = (cfg.server.host.as_str(), cfg.server.port);
    let server = if cfg.server.tls.enabled {
        let cert_path = cfg.server.tls.cert_path.as_deref().ok_or_else(|| {
            std::io::Error::other("server.tls.enabled = true but server.tls.cert_path is unset")
        })?;
        let key_path = cfg.server.tls.key_path.as_deref().ok_or_else(|| {
            std::io::Error::other("server.tls.enabled = true but server.tls.key_path is unset")
        })?;
        let client_ca = cfg.server.tls.client_ca_path.as_deref();
        let require_pq = cfg.server.tls.require_pq_kex;
        let tls_cfg = tls::build_server_config(
            std::path::Path::new(cert_path),
            std::path::Path::new(key_path),
            client_ca.map(std::path::Path::new),
            require_pq,
        )?;
        let kex_label = if require_pq {
            "X25519MLKEM768 (PQ-only)"
        } else {
            "default (PQ preferred)"
        };
        match client_ca {
            Some(ca) => tracing::info!(
                cert = cert_path,
                key = key_path,
                client_ca = ca,
                kex = kex_label,
                "TLS + mTLS enabled"
            ),
            None => tracing::info!(
                cert = cert_path,
                key = key_path,
                kex = kex_label,
                "TLS enabled"
            ),
        }
        server.bind_rustls_0_23(bind_addr, tls_cfg)?
    } else {
        tracing::warn!(
            "TLS disabled — y2qd is serving plaintext HTTP. Set [server.tls] enabled = true for production."
        );
        server.bind(bind_addr)?
    };

    let result = server.run().await;

    #[cfg(feature = "pyroscope")]
    if let Some(agent_running) = _pyroscope_agent {
        match agent_running.stop() {
            Ok(agent_ready) => agent_ready.shutdown(),
            Err(e) => tracing::warn!(error = %e, "pyroscope stop failed"),
        }
    }

    result
}

/// Guarantee at least one administrator exists after loading the user store.
///
/// User records written before the `role` field deserialize as
/// [`Role::User`](y2q_core::crypto::Role::User). On an upgraded deployment that
/// would leave zero admins and lock everyone out of the admin endpoints, so if
/// no admin is present we promote `root` (or, if absent, the earliest-created
/// user) and log a warning. A fresh first-run install already has an admin
/// `root`, so this is a no-op there.
fn reconcile_admin(user_store: &y2q_core::crypto::UserStore) -> std::io::Result<()> {
    use y2q_core::crypto::Role;
    let users = user_store
        .list()
        .map_err(|e| std::io::Error::other(format!("list users: {e}")))?;
    if users.is_empty() || users.iter().any(|u| u.role == Role::Admin) {
        return Ok(());
    }
    let target = users
        .iter()
        .find(|u| u.username == "root")
        .or_else(|| users.iter().min_by_key(|u| u.created_at))
        .map(|u| u.username.clone());
    let Some(name) = target else {
        return Ok(());
    };
    if let Some(mut rec) = user_store
        .get(&name)
        .map_err(|e| std::io::Error::other(format!("get user `{name}`: {e}")))?
    {
        rec.role = Role::Admin;
        user_store
            .upsert(&rec)
            .map_err(|e| std::io::Error::other(format!("promote `{name}` to admin: {e}")))?;
        tracing::warn!(
            user = %name,
            "no administrator found in user store; promoted existing user to admin (post-upgrade reconciliation)"
        );
    }
    Ok(())
}

/// Print the first-run root password to stdout exactly once.
///
/// Bypasses the tracing subscriber on purpose so it shows up regardless of
/// `RUST_LOG`. Operators must capture this immediately — there is no second
/// chance.
fn print_first_run_password(username: &str, password: &str) {
    println!();
    println!("===========================================================");
    println!("  y2qd first-run: ROOT PASSWORD (recorded NOWHERE — copy now)");
    println!("    username: {username}");
    println!("    password: {password}");
    println!("===========================================================");
    println!();
}

/// Lowercase-hex encode `bytes`.
fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}
