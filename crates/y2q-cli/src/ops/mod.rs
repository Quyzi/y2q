//! Shared operations layer.
//!
//! Each function performs one server operation (or a small composite) against a
//! `&Y2qClient` and returns structured data — no `println!`, no `OutputMode`.
//! Both the CLI command handlers (`crate::cmd`) and the TUI (`crate::tui`) call
//! into this layer so transfer, listing, and admin logic lives in one place.

pub mod admin;
pub mod auth;
pub mod buckets;
pub mod health;
pub mod listing;
pub mod objects;
