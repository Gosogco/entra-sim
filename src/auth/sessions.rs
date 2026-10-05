//! Short-lived state for the interactive flow: issued authorization codes and refresh tokens.
//!
//! Kept apart from the directory because none of it is directory data. It is transient,
//! per-sign-in state that a client exchanges and discards.

use std::collections::HashMap;
use std::sync::Arc;

use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

/// Entra's authorization codes are valid for a few minutes. Short enough that a leaked code is
/// of little use, long enough for a human to finish a redirect.
pub const CODE_LIFETIME_MINUTES: i64 = 10;
/// Refresh tokens last far longer, which is the point of having them.
pub const REFRESH_LIFETIME_DAYS: i64 = 90;

/// An authorization code waiting to be exchanged.
#[derive(Debug, Clone)]
pub struct AuthorizationCode {
    pub client_id: String,
    /// The redirect URI the code was issued for. The exchange must present the same one, so a
    /// stolen code cannot be redeemed towards a different destination.
    pub redirect_uri: String,
    pub user_id: String,
    /// Scopes the user consented to, space separated.
    pub scope: String,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// A refresh token waiting to be redeemed.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Default)]
pub struct Sessions {
    codes: HashMap<String, AuthorizationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
}

impl Sessions {
    /// Record a code against its opaque value.
    pub fn store_code(&mut self, code: String, details: AuthorizationCode) {
        self.codes.insert(code, details);
    }

    /// Take a code, removing it.
    ///
    /// Removing on read is what makes a code single-use: a replayed code finds nothing. An
    /// expired code is also consumed, so a client cannot keep retrying one.
    pub fn take_code(&mut self, code: &str, now: OffsetDateTime) -> Option<AuthorizationCode> {
        let details = self.codes.remove(code)?;
        (details.expires_at > now).then_some(details)
    }

    pub fn store_refresh_token(&mut self, token: String, details: RefreshToken) {
        self.refresh_tokens.insert(token, details);
    }

    /// Take a refresh token, removing it.
    ///
    /// Entra rotates refresh tokens, issuing a new one on each use, so the presented token is
    /// consumed and the caller stores a replacement.
    pub fn take_refresh_token(&mut self, token: &str, now: OffsetDateTime) -> Option<RefreshToken> {
        let details = self.refresh_tokens.remove(token)?;
        (details.expires_at > now).then_some(details)
    }

    /// Drop everything that has expired.
    ///
    /// Called on each issuance rather than from a timer, which keeps the map from growing
    /// without adding a background task whose failure would be invisible.
    pub fn evict_expired(&mut self, now: OffsetDateTime) {
        self.codes.retain(|_, code| code.expires_at > now);
        self.refresh_tokens
            .retain(|_, token| token.expires_at > now);
    }
}

/// Shared handle to the session state.
pub type SessionStore = Arc<Mutex<Sessions>>;

pub fn new_store() -> SessionStore {
    Arc::new(Mutex::new(Sessions::default()))
}

pub fn code_expiry(now: OffsetDateTime) -> OffsetDateTime {
    now + Duration::minutes(CODE_LIFETIME_MINUTES)
}

pub fn refresh_expiry(now: OffsetDateTime) -> OffsetDateTime {
    now + Duration::days(REFRESH_LIFETIME_DAYS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn code(expires_at: OffsetDateTime) -> AuthorizationCode {
        AuthorizationCode {
            client_id: "client".into(),
            redirect_uri: "https://app.test/cb".into(),
            user_id: "user".into(),
            scope: "openid".into(),
            nonce: None,
            code_challenge: None,
            code_challenge_method: None,
            expires_at,
        }
    }

    #[test]
    fn a_code_can_only_be_redeemed_once() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        sessions.store_code("abc".into(), code(code_expiry(now)));

        assert!(sessions.take_code("abc", now).is_some());
        // A replayed code finds nothing, which is what makes interception less useful.
        assert!(sessions.take_code("abc", now).is_none());
    }

    #[test]
    fn an_expired_code_is_refused_and_consumed() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        sessions.store_code("abc".into(), code(now - Duration::seconds(1)));

        assert!(sessions.take_code("abc", now).is_none());
        // Consumed as well as refused, so a client cannot keep retrying it.
        assert!(sessions.take_code("abc", now).is_none());
    }

    #[test]
    fn eviction_drops_only_what_has_expired() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        sessions.store_code("live".into(), code(code_expiry(now)));
        sessions.store_code("dead".into(), code(now - Duration::seconds(1)));

        sessions.evict_expired(now);
        assert!(sessions.take_code("dead", now).is_none());
        assert!(sessions.take_code("live", now).is_some());
    }

    #[test]
    fn a_refresh_token_is_rotated_on_use() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        sessions.store_refresh_token(
            "rt".into(),
            RefreshToken {
                client_id: "client".into(),
                user_id: "user".into(),
                scope: "openid".into(),
                expires_at: refresh_expiry(now),
            },
        );

        // Entra consumes the presented token and issues a replacement.
        assert!(sessions.take_refresh_token("rt", now).is_some());
        assert!(sessions.take_refresh_token("rt", now).is_none());
    }
}
