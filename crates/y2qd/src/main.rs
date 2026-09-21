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
//! # OpenAPI document
//!
//! The raw OpenAPI JSON is served at `/api-docs/openapi.json`. By default it
//! requires authentication; set `[server] unauthenticated_metrics = true` to
//! expose it without a token.
//!
//! # Metrics
//!
//! Prometheus scrape endpoint: `/metrics/prometheus`. Auth-gated by default.
//!
//! # Logging
//!
//! Set `RUST_LOG` to control verbosity, e.g. `RUST_LOG=y2qd=debug,actix_web=info`.

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use actix_web::{App, HttpServer, http::KeepAlive, middleware::from_fn, web};
use clap::Parser;
use metrics_exporter_prometheus::Matcher;
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;

use crate::config::LogFormat;
use crate::span::Y2qRootSpanBuilder;
use utoipa::OpenApi;
use y2q_core::crypto::{Argon2Params, keystore as keystore_mod, node_key};
use y2q_core::{AnyStorage, FilesystemStorage, StorageExt, secmem};

#[cfg(target_os = "linux")]
use y2q_core::{UringStorage, storage::uring::UringConfig};

mod auth;
mod authz;
mod bucket_keys;
mod cipher;
mod cli;
mod config;
mod error;
mod handlers;
mod node_key_rotation;
pub(crate) mod observability;
mod quota;
mod rate_limit;
mod request_id;
mod s3;
#[cfg(test)]
mod s3_gateway_test;
#[cfg(test)]
mod session_residency_test;
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
        s3::credentials::mint,
        s3::credentials::list,
        s3::credentials::revoke,
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
        s3::credentials::MintRequest,
        s3::credentials::MintResponse,
        s3::credentials::ListCredentialsResponse,
        s3::credentials::CredentialView,
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
        (name = "s3", description = "Temporary SigV4 credentials for the S3-compatible gateway"),
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
    let log_filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(cfg.observability.log_filter.clone()));

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

    // Harden the process before any secret is loaded — including node-key
    // rotation below, which loads key material too. Refusing to start here
    // (rather than warning) means an operator finds out about a too-low
    // RLIMIT_MEMLOCK at boot, not the first time a session identity key
    // would otherwise land in swappable, dumpable memory.
    let mem_policy = if cfg.server.allow_unprotected_memory {
        secmem::Policy::BestEffort
    } else {
        secmem::Policy::Require
    };
    secmem::harden_process(mem_policy).map_err(|e| {
        std::io::Error::other(format!(
            "refusing to start: {e}. Core dumps and swap would expose session \
             identity keys; set [server] allow_unprotected_memory = true to override."
        ))
    })?;

    // Offline node-key rotation short-circuits the entire normal boot
    // sequence: it acquires its own flock, walks the storage tree, and exits.
    if cli.rotate_node_key {
        if cli.upgrade_container_headers {
            return Err(std::io::Error::other(
                "--upgrade-container-headers cannot be combined with --rotate-node-key; \
                 rotation already rewrites every header",
            ));
        }
        let new_node_key_file = cli
            .new_node_key_file
            .as_deref()
            .and_then(|p| p.to_str())
            .unwrap_or("");
        return node_key_rotation::run(&cfg, new_node_key_file).await;
    }

    // Same shape as rotation: takes the keystore flock, rewrites headers, exits.
    if cli.upgrade_container_headers {
        return node_key_rotation::upgrade_headers(&cfg).await;
    }

    // Acquire daemon-wide flock on the keystore directory before doing
    // anything else — prevents two y2qd processes from racing over the
    // same keystore.
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);
    if keystore_mod::rotation_journal_exists(&keystore_dir) {
        return Err(std::io::Error::other(
            node_key_rotation::INTERRUPTED_MESSAGE,
        ));
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
            let outcome = keystore_mod::first_run(&keystore_dir, "root", argon2_for_first_run, &nk)
                .map_err(|e| std::io::Error::other(format!("first-run setup: {e}")))?;
            print_first_run_password(&outcome.root_username, outcome.root_password.expose());
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
    // holder from here on is a derived, domain-separated sub-key.
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

    let auth_state = web::Data::new(
        AuthState::new(user_store, cfg.auth.clone(), cfg.crypto.argon2.clone())
            .map_err(|e| std::io::Error::other(format!("failed to initialize auth state: {e}")))?,
    );

    let s3_state = web::Data::new(s3::state::S3State {
        credentials: s3::state::S3CredentialStore::new(
            auth_state.sessions.keyring(),
            cfg.s3.max_credentials_per_session,
        ),
        uploads: s3::state::MultipartRegistry::new(cfg.s3.max_uploads_per_session),
        config: cfg.s3.clone(),
    });
    // Background sweeper for expired sessions, stale S3 credentials, and
    // orphaned multipart uploads (owning session gone).
    {
        let auth_state = auth_state.clone();
        let s3_state = s3_state.clone();
        let storage_for_sweep = Arc::clone(storage_data.get_ref());
        let interval = Duration::from_secs(cfg.auth.session_sweep_interval_seconds.max(1));
        let upload_max_age = Duration::from_secs(cfg.s3.upload_max_age_secs);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(interval).await;
                let removed = auth_state.sessions.sweep();
                if removed > 0 {
                    tracing::debug!(removed, "swept expired sessions");
                }
                let removed_creds = s3_state.credentials.sweep(&auth_state.sessions);
                if removed_creds > 0 {
                    tracing::debug!(removed = removed_creds, "swept expired S3 credentials");
                }
                s3::multipart::sweep_orphaned_uploads(
                    &storage_for_sweep,
                    &s3_state.uploads,
                    &auth_state.sessions,
                    upload_max_age,
                )
                .await;
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
    let openapi_json = web::Data::new(
        openapi
            .to_json()
            .expect("generated OpenAPI document serializes"),
    );

    let trace_hub = web::Data::new(Arc::new(TraceHub::new()));

    let max_body_bytes = cfg.server.max_body_bytes;
    let expose_unauthed = cfg.server.unauthenticated_metrics;
    if !expose_unauthed {
        tracing::info!(
            "prometheus scrape and the OpenAPI document are NOT exposed; \
             set [server] unauthenticated_metrics = true to enable them"
        );
    }

    let prometheus = metrics_exporter_prometheus::PrometheusBuilder::new()
        .set_buckets_for_metric(
            Matcher::Suffix(observability::PAYLOAD_METRIC_SUFFIX.to_string()),
            observability::PAYLOAD_BUCKETS_BYTES,
        )
        .expect("payload histogram buckets are non-empty and finite")
        .set_buckets_for_metric(
            Matcher::Full(observability::DURATION_METRIC_NAME.to_string()),
            observability::DURATION_BUCKETS_MILLIS,
        )
        .expect("duration histogram buckets are non-empty and finite")
        .set_buckets_for_metric(
            Matcher::Suffix(observability::STORAGE_DURATION_METRIC_SUFFIX.to_string()),
            observability::STORAGE_DURATION_BUCKETS_MILLIS,
        )
        .expect("storage duration histogram buckets are non-empty and finite")
        .install_recorder()
        .expect("failed to install the Prometheus recorder");
    observability::describe_metrics();
    let prometheus = web::Data::new(prometheus);

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

    // Cloned before the REST `HttpServer::new` closure below moves the
    // originals in — the S3 listener (built further down, only when
    // `[s3] enabled`) shares the same underlying storage/auth/config state.
    let storage_data_s3 = storage_data.clone();
    let label_limits_s3 = label_limits.clone();
    let default_sync_s3 = default_sync.clone();
    let encryption_params_s3 = encryption_params.clone();
    let auth_state_s3 = auth_state.clone();
    let s3_state_s3 = s3_state.clone();

    let mut server = HttpServer::new(move || {
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
            .app_data(s3_state.clone())
            .app_data(web::PayloadConfig::new(max_body_bytes));
        // The OpenAPI JSON document and the Prometheus scrape endpoint are
        // unauthenticated. Only register them when the operator has
        // explicitly opted in.
        if expose_unauthed {
            app = app
                .app_data(prometheus.clone())
                .app_data(openapi_json.clone())
                .service(web::resource("/api-docs/openapi.json").route(web::get().to(
                    |doc: web::Data<String>| async move {
                        actix_web::HttpResponse::Ok()
                            .content_type("application/json")
                            .body(doc.get_ref().clone())
                    },
                )))
                // Must be registered before handlers::configure, which
                // contains the greedy /{bucket}/{tail}* pattern that would
                // otherwise capture /metrics/prometheus.
                .service(web::resource("/metrics/prometheus").route(web::get().to(
                    |h: web::Data<metrics_exporter_prometheus::PrometheusHandle>| async move {
                        actix_web::HttpResponse::Ok()
                            .content_type("text/plain; version=0.0.4; charset=utf-8")
                            .body(h.render())
                    },
                )));
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
    if !cfg.server.tls.enabled {
        if !config::host_is_loopback(&cfg.server.host) && !cfg.server.allow_insecure_bind {
            return Err(std::io::Error::other(format!(
                "refusing to bind {}:{} without TLS ([server.tls] enabled = false) on a \
                 non-loopback address — session tokens, passwords, and object plaintext \
                 would cross the network unencrypted. Enable TLS, bind a loopback \
                 address (127.0.0.1/::1), or set [server] allow_insecure_bind = true \
                 to override.",
                cfg.server.host, cfg.server.port
            )));
        }
        tracing::warn!(
            "TLS disabled — y2qd is serving plaintext HTTP. Set [server.tls] enabled = true for production."
        );
    }
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
        server.bind(bind_addr)?
    };

    if !cfg.s3.enabled {
        tracing::debug!("[s3] gateway disabled");
        return server.run().await;
    }

    let s3_bind_addr = (cfg.s3.host.as_str(), cfg.s3.port);
    if !cfg.s3.tls.enabled {
        if !config::host_is_loopback(&cfg.s3.host) && !cfg.s3.allow_insecure_bind {
            return Err(std::io::Error::other(format!(
                "refusing to bind {}:{} for the S3 gateway without TLS ([s3.tls] enabled = \
                 false) on a non-loopback address — SigV4 protects the request signature but \
                 object plaintext and minted secret access keys would cross the network \
                 unencrypted. Enable TLS, bind a loopback address, or set [s3] \
                 allow_insecure_bind = true to override.",
                cfg.s3.host, cfg.s3.port
            )));
        }
        tracing::warn!(
            "[s3] TLS disabled — the S3 gateway is serving plaintext HTTP. Set [s3.tls] enabled = true for production."
        );
    }

    let s3_max_body_bytes = max_body_bytes;
    let mut s3_server = HttpServer::new(move || {
        App::new()
            .wrap(from_fn(request_id::request_id_middleware))
            .wrap(from_fn(s3::routes::error_detail_middleware))
            .wrap(TracingLogger::<Y2qRootSpanBuilder>::new())
            .wrap(from_fn(observability::metrics_middleware))
            .wrap(from_fn(trace::trace_middleware))
            .wrap(from_fn(s3::routes::vhost_middleware))
            .app_data(storage_data_s3.clone())
            .app_data(label_limits_s3.clone())
            .app_data(default_sync_s3.clone())
            .app_data(encryption_params_s3.clone())
            .app_data(auth_state_s3.clone())
            .app_data(s3_state_s3.clone())
            .app_data(web::PayloadConfig::new(s3_max_body_bytes))
            .configure(s3::routes::configure)
    });
    if let Some(w) = actix_workers {
        s3_server = s3_server.workers(w);
    }
    s3_server = s3_server
        .backlog(actix_backlog)
        .max_connections(actix_max_connections)
        .keep_alive(actix_keep_alive)
        .client_request_timeout(actix_req_timeout)
        .client_disconnect_timeout(actix_disc_timeout)
        .shutdown_timeout(actix_shutdown);

    let s3_server = if cfg.s3.tls.enabled {
        let cert_path = cfg.s3.tls.cert_path.as_deref().ok_or_else(|| {
            std::io::Error::other("s3.tls.enabled = true but s3.tls.cert_path is unset")
        })?;
        let key_path = cfg.s3.tls.key_path.as_deref().ok_or_else(|| {
            std::io::Error::other("s3.tls.enabled = true but s3.tls.key_path is unset")
        })?;
        let client_ca = cfg.s3.tls.client_ca_path.as_deref();
        let require_pq = cfg.s3.tls.require_pq_kex;
        let tls_cfg = tls::build_server_config(
            std::path::Path::new(cert_path),
            std::path::Path::new(key_path),
            client_ca.map(std::path::Path::new),
            require_pq,
        )?;
        tracing::info!(
            host = %cfg.s3.host, port = cfg.s3.port, region = %cfg.s3.region, tls = true,
            "S3 gateway listening"
        );
        s3_server.bind_rustls_0_23(s3_bind_addr, tls_cfg)?
    } else {
        tracing::info!(
            host = %cfg.s3.host, port = cfg.s3.port, region = %cfg.s3.region, tls = false,
            "S3 gateway listening"
        );
        s3_server.bind(s3_bind_addr)?
    };

    let (rest_result, s3_result) =
        futures_util::future::try_join(server.run(), s3_server.run()).await?;
    let _: ((), ()) = (rest_result, s3_result);
    Ok(())
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
