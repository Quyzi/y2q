//! Route registration for all object-store endpoints.
//!
//! Object routes share the pattern `/{bucket}/{tail}*`, where `bucket` is the
//! first path segment and `tail` captures everything after it, including any
//! embedded `/` characters. Listing routes (`/` and `/{bucket}/`) are
//! registered first so the greedy tail pattern does not shadow them.
//! Admin routes live under `/api/v1/` and are also registered before the
//! greedy tail pattern.

use actix_web::web;

pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod head;
pub(crate) mod labels;
pub(crate) mod list_buckets;
pub(crate) mod list_objects;
pub(crate) mod locks;
pub(crate) mod put;
pub(crate) mod rebuild;

// Re-exported so the ApiDoc derive in main.rs can reference these by a stable
// crate-relative path without exposing the submodule structure publicly.
/// Register all object-store routes on `cfg`.
///
/// Intended to be passed directly to [`actix_web::App::configure`].
pub fn configure(cfg: &mut web::ServiceConfig) {
    cfg.service(web::resource("/").route(web::get().to(list_buckets::handle)));
    cfg.service(web::resource("/{bucket}/").route(web::get().to(list_objects::handle)));
    cfg.service(
        web::resource("/api/v1/rebuild")
            .route(web::post().to(rebuild::start))
            .route(web::get().to(rebuild::status)),
    );
    cfg.service(
        web::resource("/api/v1/locks")
            .route(web::get().to(locks::list))
            .route(web::delete().to(locks::clear)),
    );

    cfg.service(
        web::resource("/{bucket}/{tail}*")
            .route(web::get().to(get::handle))
            .route(web::put().to(put::handle))
            .route(web::delete().to(delete::handle))
            .route(web::head().to(head::handle)),
    );
}
