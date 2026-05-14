//! `y2qd` — HTTP daemon for the y2q post-quantum secure object store.
//!
//! Exposes [`y2q_core::Storage`] operations over a REST API. Objects are
//! addressed by a `(bucket, key)` pair extracted from the URL path. Keys may
//! contain `/` characters; the route pattern `/{bucket}/{tail}*` captures the
//! entire remainder of the path as the key.
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
//! ```
//!
//! # Swagger UI
//!
//! Available at `/swagger-ui/` when the server is running.
//! The raw OpenAPI JSON is served at `/api-docs/openapi.json`.
//!
//! # Metrics
//!
//! An interactive dashboard is served at `/metrics/dashboard`.
//! Prometheus scrape endpoint: `/metrics/prometheus`.
//!
//! # Logging
//!
//! Set `RUST_LOG` to control verbosity, e.g. `RUST_LOG=y2qd=debug,actix_web=info`.

use std::sync::Arc;

use actix_web::{App, HttpServer, middleware::from_fn, web};
use clap::Parser;
use metrics_exporter_prometheus::Matcher;
use metrics_rs_dashboard_actix::{DashboardInput, create_metrics_actx_scope};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use y2q_core::{AnyStorage, FilesystemStorage};

#[cfg(all(target_os = "linux", feature = "uring"))]
use y2q_core::{UringStorage, storage::uring::UringConfig};

mod cli;
mod config;
mod error;
mod handlers;
pub(crate) mod observability;

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
    )),
    tags(
        (name = "objects", description = "Object storage — read, write, and delete objects addressed by bucket/key"),
        (name = "listing", description = "Enumerate buckets and the objects within them"),
        (name = "admin", description = "Administrative operations — secondary-index rebuild, stale-lock cleanup"),
    ),
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    let cli = cli::Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::load(&cli)
        .expect("failed to load config (config.toml, Y2QD_* env vars, or --set)");

    tracing::info!(host = %cfg.server.host, port = cfg.server.port, "starting y2qd");

    let index_path = cfg
        .storage
        .index_path
        .clone()
        .unwrap_or_else(|| format!("{}/_y2q_index.redb", cfg.storage.base_path));
    let storage: Arc<AnyStorage> = Arc::new(match cfg.storage.backend {
        config::StorageBackend::Filesystem => AnyStorage::Filesystem(
            FilesystemStorage::new(&cfg.storage.base_path, &index_path)
                .map_err(|e| std::io::Error::other(format!("storage init: {e}")))?,
        ),
        #[cfg(all(target_os = "linux", feature = "uring"))]
        config::StorageBackend::Uring => AnyStorage::Uring(
            UringStorage::new(&cfg.storage.base_path, &index_path, UringConfig::default())
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

    let max_body_bytes = cfg.server.max_body_bytes;
    HttpServer::new(move || {
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
            ],
        };
        let dashboard_scope = create_metrics_actx_scope(&dashboard_input)
            .expect("failed to create metrics dashboard scope");
        // describe_* is idempotent; call it here so HELP/TYPE lines appear
        // in the output as soon as the recorder is installed.
        observability::describe_metrics();

        App::new()
            .wrap(TracingLogger::default())
            .wrap(from_fn(observability::metrics_middleware))
            .app_data(storage_data.clone())
            .app_data(label_limits.clone())
            .app_data(web::PayloadConfig::new(max_body_bytes))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi.clone()),
            )
            // Dashboard scope must be registered before handlers::configure,
            // which contains the greedy /{bucket}/{tail}* pattern that would
            // otherwise capture /metrics/dashboard.
            .service(dashboard_scope)
            .configure(handlers::configure)
    })
    .bind((cfg.server.host.as_str(), cfg.server.port))?
    .run()
    .await
}
