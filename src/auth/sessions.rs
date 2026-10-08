//! Short-lived state for the interactive flow: issued authorization codes and refresh tokens,
//! and a log of the tokens the simulator has issued.
//!
//! Kept apart from the directory because none of it is directory data. It is transient,
//! per-sign-in state that a client exchanges and discards.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;

use serde::Serialize;
use time::serde::rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::sync::Mutex;

/// Entra's authorization codes are valid for a few minutes. Short enough that a leaked code is
/// of little use, long enough for a human to finish a redirect.
pub const CODE_LIFETIME_MINUTES: i64 = 10;
/// Refresh tokens last far longer, which is the point of having them.
pub const REFRESH_LIFETIME_DAYS: i64 = 90;
/// How many issued tokens the log remembers. Plenty for an interactive session, and a bound so a
/// test suite hammering the token endpoint cannot grow it without limit.
pub const ISSUED_LOG_CAPACITY: usize = 1000;

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

/// A token the simulator issued, kept so `/__sim__/tokens` can show what was handed out.
///
/// Metadata only. The signed token is not kept, so reading the log tells you what was issued
/// without handing you a credential to replay.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct IssuedToken {
    pub id: String,
    pub kind: TokenKind,
    pub grant: Grant,
    pub client_id: String,
    pub subject_id: String,
    pub subject_kind: SubjectKind,
    /// The user's principal name, or the application's display name.
    pub subject_name: String,
    pub audience: String,
    /// Delegated permissions, on a token issued for a user.
    pub scopes: Vec<String>,
    /// App roles, on an app-only token.
    pub roles: Vec<String>,
    #[serde(with = "rfc3339")]
    pub issued_at: OffsetDateTime,
    #[serde(with = "rfc3339")]
    pub expires_at: OffsetDateTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum TokenKind {
    Access,
    Id,
}

/// The grant a token was issued under, named as the `grant_type` that requested it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Grant {
    ClientCredentials,
    AuthorizationCode,
    RefreshToken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum SubjectKind {
    User,
    ServicePrincipal,
}

#[derive(Debug, Default)]
pub struct Sessions {
    codes: HashMap<String, AuthorizationCode>,
    refresh_tokens: HashMap<String, RefreshToken>,
    /// Newest first.
    issued: VecDeque<IssuedToken>,
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

    /// Add a token to the issued log, dropping the oldest entry once the log is full.
    pub fn record_issued(&mut self, token: IssuedToken) {
        if self.issued.len() >= ISSUED_LOG_CAPACITY {
            self.issued.pop_back();
        }
        self.issued.push_front(token);
    }

    /// Issued tokens, newest first.
    ///
    /// Expired entries stay, because "has this token expired yet" is one of the things someone
    /// reading the log wants to find out. Only the capacity bound removes them.
    pub fn issued(&self) -> impl Iterator<Item = &IssuedToken> {
        self.issued.iter()
    }

    /// Authorization codes waiting to be exchanged, with their values.
    pub fn codes(&self) -> impl Iterator<Item = (&str, &AuthorizationCode)> {
        self.codes
            .iter()
            .map(|(code, details)| (code.as_str(), details))
    }

    /// Refresh tokens waiting to be redeemed, with their values.
    pub fn refresh_tokens(&self) -> impl Iterator<Item = (&str, &RefreshToken)> {
        self.refresh_tokens
            .iter()
            .map(|(token, details)| (token.as_str(), details))
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

    fn issued(id: &str, now: OffsetDateTime) -> IssuedToken {
        IssuedToken {
            id: id.into(),
            kind: TokenKind::Access,
            grant: Grant::ClientCredentials,
            client_id: "client".into(),
            subject_id: "principal".into(),
            subject_kind: SubjectKind::ServicePrincipal,
            subject_name: "App".into(),
            audience: "https://sim.test".into(),
            scopes: Vec::new(),
            roles: Vec::new(),
            issued_at: now,
            expires_at: now + Duration::hours(1),
        }
    }

    #[test]
    fn the_issued_log_is_newest_first_and_drops_the_oldest_when_full() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        for index in 0..=ISSUED_LOG_CAPACITY {
            sessions.record_issued(issued(&index.to_string(), now));
        }

        let ids: Vec<&str> = sessions.issued().map(|token| token.id.as_str()).collect();
        assert_eq!(ids.len(), ISSUED_LOG_CAPACITY);
        assert_eq!(ids.first(), Some(&ISSUED_LOG_CAPACITY.to_string().as_str()));
        // The very first entry is the one that made room for the last.
        assert!(!ids.contains(&"0"));
        assert_eq!(ids.last(), Some(&"1"));
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
