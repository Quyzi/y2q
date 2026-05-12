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
//! # Logging
//!
//! Set `RUST_LOG` to control verbosity, e.g. `RUST_LOG=y2qd=debug,actix_web=info`.

use std::sync::Arc;

use actix_web::{App, HttpServer, web};
use tracing_actix_web::TracingLogger;
use tracing_subscriber::EnvFilter;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;
use y2q_core::FilesystemStorage;

mod config;
mod error;
mod handlers;

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
    ),
    components(schemas(error::ErrorBody)),
    tags(
        (name = "objects", description = "Object storage — read, write, and delete objects addressed by bucket/key"),
    ),
)]
struct ApiDoc;

#[tokio::main]
async fn main() -> std::io::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    let cfg = config::Config::load().expect("failed to load config (config.toml or Y2QD_* env vars)");

    tracing::info!(host = %cfg.server.host, port = cfg.server.port, "starting y2qd");

    let storage = Arc::new(FilesystemStorage::new(&cfg.storage.base_path));
    let storage_data = web::Data::new(storage);
    let openapi = ApiDoc::openapi();

    let max_body_bytes = cfg.server.max_body_bytes;
    HttpServer::new(move || {
        App::new()
            .wrap(TracingLogger::default())
            .app_data(storage_data.clone())
            .app_data(web::PayloadConfig::new(max_body_bytes))
            .service(
                SwaggerUi::new("/swagger-ui/{_:.*}")
                    .url("/api-docs/openapi.json", openapi.clone()),
            )
            .configure(handlers::configure)
    })
    .bind((cfg.server.host.as_str(), cfg.server.port))?
    .run()
    .await
}
