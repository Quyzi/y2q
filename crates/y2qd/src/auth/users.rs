//! Username validation, common to add-user and login.

use super::error::AuthError;

/// Maximum username length in bytes.
pub const MAX_USERNAME_BYTES: usize = 64;

/// Reject empty/oversized/illegal usernames before they touch the user store.
///
/// Allowed: ASCII alphanumeric, `_`, `-`, `.`. Anything else returns
/// [`AuthError::InvalidUsername`]. Names are case-sensitive.
pub fn validate(username: &str) -> Result<(), AuthError> {
    if username.is_empty() {
        return Err(AuthError::InvalidUsername { reason: "empty" });
    }
    if username.len() > MAX_USERNAME_BYTES {
        return Err(AuthError::InvalidUsername { reason: "too long" });
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
    {
        return Err(AuthError::InvalidUsername {
            reason: "only [A-Za-z0-9_.-] allowed",
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ok_names() {
        assert!(validate("root").is_ok());
        assert!(validate("alice").is_ok());
        assert!(validate("user-1.test").is_ok());
        assert!(validate("a_b-c.d").is_ok());
    }

    #[test]
    fn bad_names() {
        assert!(validate("").is_err());
        assert!(validate("space user").is_err());
        assert!(validate("emoji🦀").is_err());
        assert!(validate(&"x".repeat(65)).is_err());
    }
}
