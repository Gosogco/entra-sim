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
    /// The tenant the user signed in to, which issues the tokens.
    pub tenant_id: String,
    pub client_id: String,
    /// The redirect URI the code was issued for. The exchange must present the same one, so a
    /// stolen code cannot be redeemed towards a different destination.
    pub redirect_uri: String,
    pub user_id: String,
    /// The scope the sign-in asked for, space separated. The token's permissions are read from
    /// the consent recorded in the directory when the code is redeemed.
    pub scope: String,
    pub nonce: Option<String>,
    /// Whether the user completed multifactor authentication in this sign-in.
    pub mfa: bool,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub expires_at: OffsetDateTime,
}

/// A refresh token waiting to be redeemed.
#[derive(Debug, Clone)]
pub struct RefreshToken {
    pub tenant_id: String,
    pub client_id: String,
    pub user_id: String,
    pub scope: String,
    /// Whether the sign-in it continues completed multifactor authentication.
    pub mfa: bool,
    /// Whether that sign-in was in a browser, for conditional access.
    pub browser: bool,
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
    /// `urn:ietf:params:oauth:grant-type:jwt-bearer` with `requested_token_use=on_behalf_of`.
    OnBehalfOf,
    /// `urn:ietf:params:oauth:grant-type:device_code`.
    DeviceCode,
    /// The resource owner password credentials grant.
    Password,
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
    /// Browser sign-in sessions, by the value of the session cookie.
    browser_sessions: HashMap<String, BrowserSession>,
    /// Device code sign-ins in progress, by device code.
    device_authorizations: HashMap<String, DeviceAuthorization>,
    /// What each delta token stands for, oldest first so the oldest can be dropped.
    delta_states: VecDeque<(String, crate::graph::delta::DeltaState)>,
}

/// How many delta tokens are remembered. Microsoft keeps directory delta tokens for seven days;
/// a bound on the count keeps a long test run from growing the map without limit.
const DELTA_STATE_CAPACITY: usize = 1000;

/// A device code sign-in: what the device asked for, and how far the user has got.
#[derive(Debug, Clone)]
pub struct DeviceAuthorization {
    pub tenant_id: String,
    pub client_id: String,
    pub scope: String,
    /// The short code the user types on the verification page.
    pub user_code: String,
    pub expires_at: OffsetDateTime,
    pub status: DeviceStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceStatus {
    Pending,
    Approved { user_id: String, mfa: bool },
    Declined,
}

/// A user signed in to the simulator in a browser, which is what single sign-on reuses.
#[derive(Debug, Clone)]
pub struct BrowserSession {
    pub user_id: String,
    /// Whether the user completed multifactor authentication.
    pub mfa: bool,
    pub expires_at: OffsetDateTime,
}

impl Sessions {
    /// Record a code against its opaque value.
    pub fn store_code(&mut self, code: String, details: AuthorizationCode) {
        self.codes.insert(code, details);
    }

    /// The tenant a code, refresh token or device code belongs to, without consuming it.
    pub fn tenant_of(&self, grant_type: &str, value: &str) -> Option<String> {
        match grant_type {
            "authorization_code" => self.codes.get(value).map(|code| code.tenant_id.clone()),
            "refresh_token" => self
                .refresh_tokens
                .get(value)
                .map(|token| token.tenant_id.clone()),
            "urn:ietf:params:oauth:grant-type:device_code" => self
                .device_authorizations
                .get(value)
                .map(|details| details.tenant_id.clone()),
            _ => None,
        }
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

    /// Start a browser session for a user who just signed in, returning the cookie value.
    pub fn start_browser_session(
        &mut self,
        user_id: &str,
        mfa: bool,
        now: OffsetDateTime,
    ) -> String {
        let id = uuid::Uuid::new_v4().simple().to_string();
        self.browser_sessions.insert(
            id.clone(),
            BrowserSession {
                user_id: user_id.to_string(),
                mfa,
                expires_at: now + Duration::hours(BROWSER_SESSION_LIFETIME_HOURS),
            },
        );
        id
    }

    /// The session a cookie belongs to, if it is still live.
    pub fn browser_session(&self, id: &str, now: OffsetDateTime) -> Option<BrowserSession> {
        self.browser_sessions
            .get(id)
            .filter(|session| session.expires_at > now)
            .cloned()
    }

    pub fn end_browser_session(&mut self, id: &str) {
        self.browser_sessions.remove(id);
    }

    pub fn store_device_authorization(
        &mut self,
        device_code: String,
        details: DeviceAuthorization,
    ) {
        self.device_authorizations.insert(device_code, details);
    }

    /// A device authorization by its device code. Expired ones stay until evicted, so the
    /// device can be told its code expired rather than that it never existed.
    pub fn device_authorization(&self, device_code: &str) -> Option<&DeviceAuthorization> {
        self.device_authorizations.get(device_code)
    }

    /// The device code of a pending, unexpired sign-in, by the code the user typed.
    pub fn pending_device_code(&self, user_code: &str, now: OffsetDateTime) -> Option<String> {
        self.device_authorizations
            .iter()
            .find(|(_, details)| {
                details.user_code.eq_ignore_ascii_case(user_code)
                    && details.status == DeviceStatus::Pending
                    && details.expires_at > now
            })
            .map(|(code, _)| code.clone())
    }

    pub fn set_device_status(&mut self, device_code: &str, status: DeviceStatus) {
        if let Some(details) = self.device_authorizations.get_mut(device_code) {
            details.status = status;
        }
    }

    /// Remove a device authorization once its tokens are issued, so the code is single-use.
    pub fn take_device_authorization(&mut self, device_code: &str) -> Option<DeviceAuthorization> {
        self.device_authorizations.remove(device_code)
    }

    /// Remember what a delta round saw, returning its token.
    pub fn store_delta_state(&mut self, state: crate::graph::delta::DeltaState) -> String {
        if self.delta_states.len() >= DELTA_STATE_CAPACITY {
            self.delta_states.pop_front();
        }
        let token = uuid::Uuid::new_v4().simple().to_string();
        self.delta_states.push_back((token.clone(), state));
        token
    }

    pub fn delta_state(&self, token: &str) -> Option<crate::graph::delta::DeltaState> {
        self.delta_states
            .iter()
            .find(|(known, _)| known == token)
            .map(|(_, state)| state.clone())
    }

    /// Drop everything that has expired.
    ///
    /// Called on each issuance rather than from a timer, which keeps the map from growing
    /// without adding a background task whose failure would be invisible.
    pub fn evict_expired(&mut self, now: OffsetDateTime) {
        self.codes.retain(|_, code| code.expires_at > now);
        self.refresh_tokens
            .retain(|_, token| token.expires_at > now);
        self.browser_sessions
            .retain(|_, session| session.expires_at > now);
        // Kept an hour past expiry, so a device still polling hears expired_token.
        self.device_authorizations
            .retain(|_, details| details.expires_at + Duration::hours(1) > now);
    }
}

/// Shared handle to the session state.
pub type SessionStore = Arc<Mutex<Sessions>>;

pub fn new_store() -> SessionStore {
    Arc::new(Mutex::new(Sessions::default()))
}

/// How long a browser stays signed in. Entra's own session lasts longer; a day is enough for a test
/// run and short enough that a forgotten session does not linger.
const BROWSER_SESSION_LIFETIME_HOURS: i64 = 24;

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
            tenant_id: "tenant".into(),
            client_id: "client".into(),
            redirect_uri: "https://app.test/cb".into(),
            user_id: "user".into(),
            scope: "openid".into(),
            nonce: None,
            mfa: false,
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
                tenant_id: "tenant".into(),
                client_id: "client".into(),
                user_id: "user".into(),
                scope: "openid".into(),
                mfa: false,
                browser: true,
                expires_at: refresh_expiry(now),
            },
        );

        // Entra consumes the presented token and issues a replacement.
        assert!(sessions.take_refresh_token("rt", now).is_some());
        assert!(sessions.take_refresh_token("rt", now).is_none());
    }

    #[test]
    fn an_expired_device_code_is_no_longer_offered_to_the_user() {
        let now = OffsetDateTime::now_utc();
        let mut sessions = Sessions::default();
        sessions.store_device_authorization(
            "device".into(),
            DeviceAuthorization {
                tenant_id: "tenant".into(),
                client_id: "client".into(),
                scope: "openid".into(),
                user_code: "ABCDEFGHJ".into(),
                expires_at: now + Duration::minutes(15),
                status: DeviceStatus::Pending,
            },
        );
        assert_eq!(
            sessions.pending_device_code("abcdefghj", now).as_deref(),
            Some("device"),
            "the user code is matched case-insensitively"
        );
        assert!(
            sessions
                .pending_device_code("ABCDEFGHJ", now + Duration::minutes(16))
                .is_none()
        );
        // The device can still be told it expired.
        sessions.evict_expired(now + Duration::minutes(16));
        assert!(sessions.device_authorization("device").is_some());
    }
}
