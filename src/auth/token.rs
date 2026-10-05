//! Access token claims, signing and validation.
//!
//! Claim names and shapes follow an Entra v2.0 app-only access token, because clients read them:
//! `roles` drives authorisation, `appid` identifies the caller, and `go-azure-sdk` parses `iat`
//! to decide when to refresh.

use anyhow::{Context, Result};
use jsonwebtoken::{Algorithm, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::auth::keys::SigningKey;

/// How the client proved its identity. Entra reports `1` for a shared secret and `2` for a
/// certificate, and some policies key off the distinction.
pub const APPIDACR_CLIENT_SECRET: &str = "1";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessTokenClaims {
    /// The resource the token is for. Equal to the Graph resource identifier the simulator
    /// advertises, which is also what `{resource}/.default` resolves against.
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    /// Client ID of the calling application.
    pub appid: String,
    pub appidacr: String,
    /// `app` marks an app-only token, as opposed to one obtained on behalf of a user.
    pub idtyp: String,
    /// Object ID of the service principal the token represents.
    pub oid: String,
    pub sub: String,
    pub tid: String,
    pub ver: String,
    /// App roles granted to the calling service principal on the resource. Present on an
    /// app-only token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub roles: Vec<String>,
    /// Space-separated delegated permissions. Present on a token obtained on behalf of a user,
    /// and what distinguishes the two kinds of caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scp: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_displayname: Option<String>,
}

/// Everything needed to mint an app-only token.
pub struct AppTokenRequest<'a> {
    pub audience: &'a str,
    pub issuer: &'a str,
    pub tenant_id: &'a str,
    pub client_id: &'a str,
    pub principal_id: &'a str,
    pub display_name: Option<&'a str>,
    pub roles: Vec<String>,
    pub ttl_seconds: u64,
}

/// Mint and sign an app-only access token, returning the token and its lifetime in seconds.
pub fn issue_app_token(
    key: &SigningKey,
    request: AppTokenRequest<'_>,
    now: OffsetDateTime,
) -> Result<(String, u64)> {
    let issued_at = now.unix_timestamp();
    let claims = AccessTokenClaims {
        aud: request.audience.to_string(),
        iss: request.issuer.to_string(),
        iat: issued_at,
        nbf: issued_at,
        exp: issued_at + request.ttl_seconds as i64,
        appid: request.client_id.to_string(),
        appidacr: APPIDACR_CLIENT_SECRET.to_string(),
        idtyp: "app".to_string(),
        // For an app-only token Entra sets `sub` to the service principal's object ID, the same
        // value as `oid`; there is no user to subject the token to.
        oid: request.principal_id.to_string(),
        sub: request.principal_id.to_string(),
        tid: request.tenant_id.to_string(),
        ver: "2.0".to_string(),
        roles: request.roles,
        scp: None,
        app_displayname: request.display_name.map(str::to_string),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let token = encode(&header, &claims, &key.encoding).context("signing the access token")?;
    Ok((token, request.ttl_seconds))
}

/// Verify a token's signature, issuer, audience and expiry, and return its claims.
pub fn validate(
    key: &SigningKey,
    token: &str,
    audience: &str,
    issuer: &str,
) -> Result<AccessTokenClaims, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[audience]);
    validation.set_issuer(&[issuer]);
    validation.validate_nbf = true;
    decode::<AccessTokenClaims>(token, &key.decoding, &validation).map(|data| data.claims)
}
