//! Route registration for all object-store endpoints.
//!
//! Object routes share the pattern `/{bucket}/{tail}*`, where `bucket` is the
//! first path segment and `tail` captures everything after it, including any
//! embedded `/` characters. Listing routes (`/` and `/{bucket}/`) are
//! registered first so the greedy tail pattern does not shadow them.
//! Admin and auth routes live under `/api/v1/` and are also registered before
//! the greedy tail pattern.

use actix_governor::Governor;
use actix_web::web;

pub(crate) mod acl;
pub(crate) mod buckets;
pub(crate) mod delete;
pub(crate) mod get;
pub(crate) mod head;
pub(crate) mod keys;
pub(crate) mod labels;
pub(crate) mod list_buckets;
pub(crate) mod list_objects;
pub(crate) mod locks;
pub(crate) mod personas;
pub(crate) mod put;
pub(crate) mod rebuild;
pub(crate) mod search;
pub(crate) mod tags;

use crate::auth::handlers as auth_handlers;

/// Register all object-store + auth routes on `cfg`.
///
/// Intended to be passed directly to [`actix_web::App::configure`].
pub fn configure(cfg: &mut web::ServiceConfig) {
    // Auth and user-management endpoints. Registered before the greedy
    // /{bucket}/{tail}* pattern so they aren't shadowed.
    cfg.service(
        web::resource("/api/v1/auth/login")
            .wrap(Governor::new(&crate::rate_limit::LOGIN_GOVERNOR_CONFIG))
            .route(web::post().to(auth_handlers::login)),
    );
    cfg.service(
        web::resource("/api/v1/auth/refresh").route(web::post().to(auth_handlers::refresh)),
    );
    cfg.service(web::resource("/api/v1/auth/logout").route(web::post().to(auth_handlers::logout)));
    cfg.service(
        web::resource("/api/v1/auth/password")
            .route(web::post().to(auth_handlers::change_password)),
    );
    cfg.service(web::resource("/api/v1/users/add").route(web::put().to(auth_handlers::add_user)));
    cfg.service(web::resource("/api/v1/users").route(web::get().to(auth_handlers::list_users)));
    cfg.service(
        web::resource("/api/v1/users/{user}/role").route(web::put().to(auth_handlers::set_role)),
    );
    cfg.service(
        web::resource("/api/v1/users/{user}").route(web::delete().to(auth_handlers::delete_user)),
    );
    cfg.service(
        web::resource("/api/v1/users/{user}/reset-identity")
            .route(web::post().to(auth_handlers::reset_identity)),
    );
    cfg.service(
        web::resource("/api/v1/personas").route(web::post().to(auth_handlers::create_persona)),
    );
    // Registered before `/api/v1/personas/{slot}` so the literal `me` path
    // isn't swallowed by the `{slot}: u8` pattern (actix matches by path
    // shape first, then fails `u8` extraction on non-numeric segments).
    cfg.service(
        web::resource("/api/v1/personas/me").route(web::get().to(auth_handlers::whoami_persona)),
    );
    cfg.service(
        web::resource("/api/v1/personas/{slot}").route(web::delete().to(auth_handlers::delete_persona)),
    );
    cfg.service(
        web::resource("/api/v1/personas/{slot}/grant")
            .route(web::post().to(personas::grant_persona))
            .route(web::delete().to(personas::revoke_persona_grant)),
    );

    // Object store + admin endpoints.
    cfg.service(web::resource("/").route(web::get().to(list_buckets::handle)));
    cfg.service(
        web::resource("/{bucket}/")
            .route(web::get().to(list_objects::handle))
            .route(web::put().to(buckets::create))
            .route(web::delete().to(buckets::remove)),
    );
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
    cfg.service(web::resource("/api/v1/search").route(web::get().to(search::handle)));
    cfg.service(web::resource("/api/v1/trace").route(web::get().to(crate::trace::stream)));
    cfg.service(
        web::resource("/api/v1/buckets/{bucket}/config")
            .route(web::get().to(buckets::get_config))
            .route(web::put().to(buckets::set_config)),
    );
    cfg.service(
        web::resource("/api/v1/buckets/{bucket}/acl")
            .route(web::get().to(acl::get_acl))
            .route(web::put().to(acl::set_acl)),
    );
    cfg.service(
        web::resource("/api/v1/buckets/{bucket}/rotate-key").route(web::post().to(keys::rotate_key)),
    );
    cfg.service(
        web::resource("/api/v1/buckets/{bucket}/rekey")
            .route(web::post().to(keys::start_rekey))
            .route(web::get().to(keys::rekey_status)),
    );

    cfg.service(
        web::resource("/{bucket}/{tail}*")
            .route(web::get().to(get::handle))
            .route(web::put().to(put::handle))
            .route(web::patch().to(tags::handle))
            .route(web::delete().to(delete::handle))
            .route(web::head().to(head::handle)),
    );
}
