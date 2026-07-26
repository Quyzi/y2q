use crate::client::Y2qClient;
use crate::error::ClientError;
use crate::model::{PersonaCreateRequest, PersonaCreateResponse, PersonaGrantBody, PersonaView};

impl Y2qClient {
    /// Write a new persona (credential slot `1..=3`) into the caller's own
    /// record. `role` is `"admin"`/`"user"`/`"readonly"`/`"writeonly"`/
    /// `"auditor"`/`"disabled"`, or `None` to let the server default to
    /// `user`. Always overwrites whatever was in `slot`, real or decoy.
    pub async fn create_persona(
        &self,
        slot: u8,
        password: &str,
        role: Option<&str>,
        revoke_other_sessions: bool,
    ) -> Result<PersonaCreateResponse, ClientError> {
        let url = self.url("api/v1/personas");
        let body = PersonaCreateRequest {
            slot,
            password: password.to_owned(),
            role: role.map(str::to_owned),
            revoke_other_sessions,
        };
        let resp = self.authed(self.inner.post(url)).json(&body).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<PersonaCreateResponse>().await?)
    }

    /// Overwrite `slot` (`1..=3`) with a fresh decoy and revoke any live
    /// session opened through it.
    pub async fn delete_persona(&self, slot: u8) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/personas/{slot}"));
        let resp = self.authed(self.inner.delete(url)).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// The calling session's own persona slot, role, and duress flag.
    pub async fn whoami_persona(&self) -> Result<PersonaView, ClientError> {
        let url = self.url("api/v1/personas/me");
        let resp = self.authed(self.inner.get(url)).send().await?;
        let resp = Self::check_status(resp).await?;
        Ok(resp.json::<PersonaView>().await?)
    }

    /// Share every bucket in `buckets` that the caller's *current* persona
    /// really holds with `slot`, one of the caller's own other personas.
    pub async fn grant_persona(&self, slot: u8, buckets: &[String]) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/personas/{slot}/grant"));
        let body = PersonaGrantBody {
            buckets: buckets.to_vec(),
        };
        let resp = self.authed(self.inner.post(url)).json(&body).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }

    /// Re-seal every bucket in `buckets` so `slot` no longer holds real
    /// access. The caller's own persona keeps its access.
    pub async fn revoke_persona_grant(&self, slot: u8, buckets: &[String]) -> Result<(), ClientError> {
        let url = self.url(&format!("api/v1/personas/{slot}/grant"));
        let body = PersonaGrantBody {
            buckets: buckets.to_vec(),
        };
        let resp = self.authed(self.inner.delete(url)).json(&body).send().await?;
        Self::check_status(resp).await?;
        Ok(())
    }
}
