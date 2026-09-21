//! Bundled `web::Data` for the S3 gateway's write paths.
//!
//! `PutObject`, `CopyObject`, `UploadPart`, and `CompleteMultipartUpload`
//! all need the same handful of app-registered dependencies. Threading them
//! as six individual `web::Data<T>` parameters is what drove every one of
//! those handlers past clippy's `too_many_arguments` threshold. [`WriteCtx`]
//! extracts them once, as a single parameter, resolved the same way an
//! ordinary `web::Data<T>` extractor is.

use std::sync::Arc;

use actix_web::{FromRequest, dev::Payload, web};
use y2q_core::{AnyStorage, SyncLevel};

use crate::auth::AuthState;
use crate::config::LabelLimits;
use crate::s3::error::S3Error;
use crate::s3::state::S3State;

/// Everything an S3 write path needs, resolved once per request.
pub(crate) struct WriteCtx {
    pub storage: web::Data<Arc<AnyStorage>>,
    pub auth_state: web::Data<AuthState>,
    pub limits: web::Data<LabelLimits>,
    pub default_sync: web::Data<SyncLevel>,
    pub encryption: web::Data<crate::config::EncryptionParams>,
    pub s3: web::Data<S3State>,
}

impl FromRequest for WriteCtx {
    type Error = S3Error;
    type Future = std::future::Ready<Result<Self, S3Error>>;

    fn from_request(req: &actix_web::HttpRequest, _payload: &mut Payload) -> Self::Future {
        std::future::ready((|| {
            Ok(WriteCtx {
                storage: req
                    .app_data::<web::Data<Arc<AnyStorage>>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
                auth_state: req
                    .app_data::<web::Data<AuthState>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
                limits: req
                    .app_data::<web::Data<LabelLimits>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
                default_sync: req
                    .app_data::<web::Data<SyncLevel>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
                encryption: req
                    .app_data::<web::Data<crate::config::EncryptionParams>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
                s3: req
                    .app_data::<web::Data<S3State>>()
                    .cloned()
                    .ok_or_else(S3Error::internal_error)?,
            })
        })())
    }
}
