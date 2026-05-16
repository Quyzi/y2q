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
//! On first start (no `pubkey.json` in `[crypto] keystore_dir`), the daemon
//! generates an ML-KEM-768 keypair, wraps the secret key under a
//! randomly-generated root password, prints the password to stdout exactly
//! once, and persists the public key + wrapped secret. RECORD THIS PASSWORD —
//! losing it requires resetting everything.
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

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

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
use y2q_core::crypto::{Argon2Params, derive_mek, keystore as keystore_mod};
use y2q_core::{AnyStorage, FilesystemStorage};

#[cfg(all(target_os = "linux", feature = "uring"))]
use y2q_core::{UringStorage, storage::uring::UringConfig};

mod auth;
mod cipher;
mod cli;
mod config;
mod error;
mod handlers;
pub(crate) mod observability;
mod request_id;
mod span;
mod trace;

use crate::auth::AuthState;
use crate::trace::TraceHub;

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
        handlers::rebuild::start,
        handlers::rebuild::status,
        handlers::locks::list,
        handlers::locks::clear,
        auth::handlers::login,
        auth::handlers::refresh,
        auth::handlers::logout,
        auth::handlers::change_password,
        auth::handlers::add_user,
        auth::handlers::list_users,
        auth::handlers::delete_user,
    ),
    components(schemas(
        error::ErrorBody,
        handlers::list_buckets::ListBucketsResponse,
        handlers::list_objects::ListObjectsResponse,
        handlers::list_objects::MetadataView,
        handlers::rebuild::RebuildStartResponse,
        handlers::rebuild::RebuildStatusResponse,
        handlers::locks::StaleLockEntry,
        handlers::locks::ClearStaleLocksResponse,
        auth::handlers::LoginRequest,
        auth::handlers::TokenResponse,
        auth::handlers::ChangePasswordRequest,
        auth::handlers::AddUserRequest,
        auth::handlers::ListUsersResponse,
        auth::handlers::UserView,
    )),
    modifiers(&SecurityAddon),
    tags(
        (name = "objects", description = "Object storage — read, write, and delete objects addressed by bucket/key"),
        (name = "listing", description = "Enumerate buckets and the objects within them"),
        (name = "admin", description = "Administrative operations — secondary-index rebuild, stale-lock cleanup"),
        (name = "auth", description = "Session login/refresh/logout and password change"),
        (name = "users", description = "Add, list, and delete users authorized to log in"),
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
        EnvFilter::new(format!("{},metrics_rs_dashboard_actix=warn", cfg.observability.log_filter))
    });

    match cfg.observability.log_format {
        LogFormat::Text => tracing_subscriber::fmt()
            .with_env_filter(log_filter)
            .init(),
        LogFormat::Json => tracing_subscriber::fmt()
            .json()
            .with_env_filter(log_filter)
            .init(),
    }

    tracing::info!(host = %cfg.server.host, port = cfg.server.port, "starting y2qd");

    // Acquire daemon-wide flock on the keystore directory before doing
    // anything else — prevents two y2qd processes from racing over the
    // same keystore.
    let keystore_dir = PathBuf::from(&cfg.crypto.keystore_dir);
    let _flock = keystore_mod::acquire_lock(&keystore_dir)
        .map_err(|e| std::io::Error::other(format!("acquire keystore lock: {e}")))?;

    // Load or first-run the keystore.
    let argon2_for_first_run = Argon2Params::with_random_salt(
        cfg.crypto.argon2.m_cost_kib,
        cfg.crypto.argon2.t_cost,
        cfg.crypto.argon2.p_cost,
    );
    let (public_keystore, user_store) = match keystore_mod::load(&keystore_dir) {
        Ok(pair) => pair,
        Err(y2q_core::crypto::CryptoError::KeystoreMissing(_)) => {
            tracing::info!(
                dir = %keystore_dir.display(),
                "no keystore found; running first-run setup"
            );
            let outcome = keystore_mod::first_run(&keystore_dir, "root", argon2_for_first_run)
                .map_err(|e| std::io::Error::other(format!("first-run setup: {e}")))?;
            print_first_run_password(&outcome.root_username, &outcome.root_password);
            tracing::info!(
                fingerprint = %outcome.keystore.fingerprint,
                "keystore initialized"
            );
            (outcome.keystore, outcome.user_store)
        }
        Err(e) => {
            return Err(std::io::Error::other(format!("load keystore: {e}")));
        }
    };

    tracing::info!(
        fingerprint = %public_keystore.fingerprint,
        "deployment public-key fingerprint"
    );

    let mek = derive_mek(&public_keystore.public_key);

    let auth_state = web::Data::new(AuthState::new(
        public_keystore,
        user_store,
        cfg.auth.clone(),
        cfg.crypto.argon2.clone(),
    ));

    // Background sweeper for expired sessions + idle-keystore drop.
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
                auth_state.keystore.reconcile(&auth_state.sessions);
            }
        });
    }

    let index_path = cfg
        .storage
        .index_path
        .clone()
        .unwrap_or_else(|| format!("{}/_y2q_index.redb", cfg.storage.base_path));
    let storage: Arc<AnyStorage> = Arc::new(match cfg.storage.backend {
        config::StorageBackend::Filesystem => AnyStorage::Filesystem(
            FilesystemStorage::new(&cfg.storage.base_path, &index_path)
                .map_err(|e| std::io::Error::other(format!("storage init: {e}")))?
                .with_mek(mek),
        ),
        #[cfg(all(target_os = "linux", feature = "uring"))]
        config::StorageBackend::Uring => AnyStorage::Uring(
            UringStorage::new(&cfg.storage.base_path, &index_path, UringConfig { mek: Some(mek), ..UringConfig::default() })
                .map_err(|e| std::io::Error::other(format!("storage init: {e}")))?,
        ),
        #[cfg(not(all(target_os = "linux", feature = "uring")))]
        config::StorageBackend::Uring => {
            return Err(std::io::Error::other(
                "storage.backend = \"uring\" requires building with --features y2q-core/uring on Linux",
            ));
        }
    });
    let storage_data = web::Data::new(storage);
    let label_limits = web::Data::new(config::LabelLimits::from(&cfg.storage));
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
            .app_data(auth_state.clone())
            .app_data(web::PayloadConfig::new(max_body_bytes));
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
    server
        .backlog(actix_backlog)
        .max_connections(actix_max_connections)
        .keep_alive(actix_keep_alive)
        .client_request_timeout(actix_req_timeout)
        .client_disconnect_timeout(actix_disc_timeout)
        .shutdown_timeout(actix_shutdown)
        .bind((cfg.server.host.as_str(), cfg.server.port))?
        .run()
        .await
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
