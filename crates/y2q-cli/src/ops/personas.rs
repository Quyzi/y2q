//! Persona (multiple-password / duress) operations shared by the CLI and
//! the TUI. Every function acts on the caller's own record — there is no
//! admin-directed variant.

use y2q_client::{ClientError, PersonaCreateResponse, PersonaView, Y2qClient};

/// Write a new persona into a credential slot (`0..CREDENTIAL_SLOTS`).
/// `role` is `"admin"`, `"user"`, `"readonly"`, `"writeonly"`, `"auditor"`,
/// `"disabled"`, or `None` for the server default (`user`). Always
/// overwrites whatever was in `slot`, real or decoy - except the slot the
/// caller is currently authenticated through, which the server refuses.
pub async fn add(
    client: &Y2qClient,
    slot: u8,
    password: &str,
    role: Option<&str>,
    revoke_other_sessions: bool,
) -> Result<PersonaCreateResponse, ClientError> {
    client
        .create_persona(slot, password, role, revoke_other_sessions)
        .await
}

/// Overwrite `slot` (excluding the one the caller is currently
/// authenticated through) with a fresh decoy and revoke any live session
/// opened through it.
pub async fn remove(client: &Y2qClient, slot: u8) -> Result<(), ClientError> {
    client.delete_persona(slot).await
}

/// The calling session's own persona slot and role. The server never
/// reports the duress flag, even for the caller's own session.
pub async fn whoami(client: &Y2qClient) -> Result<PersonaView, ClientError> {
    client.whoami_persona().await
}

/// Share the named buckets (that the caller's *current* persona really
/// holds) with `slot`, one of the caller's own other personas.
pub async fn grant(client: &Y2qClient, slot: u8, buckets: &[String]) -> Result<(), ClientError> {
    client.grant_persona(slot, buckets).await
}

/// Revoke `slot`'s access to the named buckets. The caller's own persona
/// keeps its access.
pub async fn revoke(client: &Y2qClient, slot: u8, buckets: &[String]) -> Result<(), ClientError> {
    client.revoke_persona_grant(slot, buckets).await
}
