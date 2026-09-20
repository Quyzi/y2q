//! S3-compatible gateway.
//!
//! Adds an optional second HTTP listener (`[s3] enabled = true`) speaking
//! AWS S3 REST semantics on top of the same storage, crypto, and
//! authorization code paths the native REST API uses. Every S3 request
//! resolves to a live [`crate::auth::session::SessionInfo`] through the same
//! [`crate::auth::session::SessionStore`] the REST listener uses, so logout,
//! expiry, revocation, and duress persona switches all take effect here too,
//! mid-transfer included.

pub(crate) mod auth;
pub(crate) mod body;
pub(crate) mod bucket;
pub(crate) mod credentials;
pub(crate) mod error;
pub(crate) mod httpdate;
pub(crate) mod meta;
pub(crate) mod multipart;
pub(crate) mod object;
pub(crate) mod routes;
pub(crate) mod service;
pub(crate) mod sigv4;
pub(crate) mod state;
pub(crate) mod xml;
