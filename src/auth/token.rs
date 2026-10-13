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
use crate::store::TokenVersion;

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
    /// The signed-in user's principal name. Present only on a delegated token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upn: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
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
        upn: None,
        name: None,
        preferred_username: None,
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

/// Verify a token this simulator issued, by its signature, issuer and lifetime, and return its
/// claims. The audience is left to the caller, which knows what it should be.
pub fn decode_issued(
    key: &SigningKey,
    token: &str,
    issuers: &[String],
) -> Result<serde_json::Value, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(Algorithm::RS256);
    validation.validate_aud = false;
    validation.set_issuer(issuers);
    validation.validate_nbf = true;
    decode::<serde_json::Value>(token, &key.decoding, &validation).map(|data| data.claims)
}

/// Everything needed to mint a token on behalf of a user.
pub struct UserTokenRequest<'a> {
    pub audience: &'a str,
    pub issuer: &'a str,
    pub tenant_id: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub user_principal_name: &'a str,
    pub display_name: &'a str,
    /// Space-separated delegated permissions the user consented to.
    pub scope: &'a str,
    /// App roles assigned to the user on the resource.
    pub roles: Vec<String>,
    pub ttl_seconds: u64,
}

/// Mint and sign a delegated access token.
pub fn issue_user_token(
    key: &SigningKey,
    request: UserTokenRequest<'_>,
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
        // `user` marks a token obtained on behalf of a signed-in user.
        idtyp: "user".to_string(),
        // The subject is the user, not the application.
        oid: request.user_id.to_string(),
        sub: request.user_id.to_string(),
        tid: request.tenant_id.to_string(),
        ver: "2.0".to_string(),
        // The user's own roles on the resource. Graph judges a delegated token on `scp` alone
        // (`permissions::satisfied`), so a role here never satisfies an app-only requirement.
        roles: request.roles,
        scp: Some(request.scope.to_string()),
        app_displayname: None,
        upn: Some(request.user_principal_name.to_string()),
        name: Some(request.display_name.to_string()),
        preferred_username: Some(request.user_principal_name.to_string()),
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    let token = encode(&header, &claims, &key.encoding).context("signing the access token")?;
    Ok((token, request.ttl_seconds))
}

/// How the client proved its identity, reported as `azpacr` in a v2 token and `appidacr` in a v1
/// token: `0` for a public client, `1` for a client secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    Public,
    Secret,
}

impl ClientAuth {
    fn code(self) -> &'static str {
        match self {
            Self::Public => "0",
            Self::Secret => APPIDACR_CLIENT_SECRET,
        }
    }
}

/// Who a token for a registered API represents.
pub enum ApiTokenSubject<'a> {
    /// The client application itself, through the client credentials grant.
    App { principal_id: &'a str },
    /// A signed-in user, with the delegated permissions the client holds for them.
    User {
        user_id: &'a str,
        user_principal_name: &'a str,
        display_name: &'a str,
        given_name: Option<&'a str>,
        family_name: Option<&'a str>,
        /// Space-separated delegated permissions on the API.
        scope: &'a str,
    },
}

/// Everything needed to mint an access token for an API registered in the directory, as
/// opposed to Microsoft Graph.
pub struct ApiTokenRequest<'a> {
    pub version: TokenVersion,
    /// The API's `appId` for a v2.0 token. Microsoft: "In v2.0 tokens, this value is always the
    /// client ID of the API. In v1.0 tokens, it can be the client ID or the resource URI used in
    /// the request."
    pub audience: &'a str,
    pub tenant_id: &'a str,
    /// The simulator's base URL, which a v2.0 issuer is built on.
    pub base_url: &'a str,
    pub client_id: &'a str,
    pub client_auth: ClientAuth,
    pub subject: ApiTokenSubject<'a>,
    /// App roles the subject holds on the API.
    pub roles: Vec<String>,
    /// Claims the API's registration asks for, such as `groups`, added last.
    pub extra_claims: serde_json::Map<String, serde_json::Value>,
    pub ttl_seconds: u64,
}

/// The issuer of a v1.0 token. Microsoft's v1.0 discovery document names
/// `https://sts.windows.net/{tenantid}/`, and the simulator's names the same, because an API
/// compares the two strings and never contacts the host.
pub fn v1_issuer(tenant_id: &str) -> String {
    format!("https://sts.windows.net/{tenant_id}/")
}

/// Mint and sign an access token for a registered API, in the version the API asked for.
///
/// The claims follow Microsoft's access token claims reference. A v2.0 token names the client
/// with `azp` and `azpacr`; a v1.0 token with `appid` and `appidacr`, and adds the v1.0 basic
/// claims such as `upn`, `unique_name`, `given_name` and `family_name`. `idtyp` is `app` only
/// on an app-only token. A user token carries `scp` and, when the user holds roles on the API,
/// `roles`.
pub fn issue_api_token(
    key: &SigningKey,
    request: ApiTokenRequest<'_>,
    now: OffsetDateTime,
) -> Result<(String, u64)> {
    use serde_json::{Value, json};

    let v1 = request.version == TokenVersion::V1;
    let issued_at = now.unix_timestamp();
    let mut claims = serde_json::Map::new();
    let mut set = |name: &str, value: Value| {
        claims.insert(name.to_string(), value);
    };
    set("aud", json!(request.audience));
    if v1 {
        set("iss", json!(v1_issuer(request.tenant_id)));
    } else {
        set(
            "iss",
            json!(format!("{}/{}/v2.0", request.base_url, request.tenant_id)),
        );
    }
    set("iat", json!(issued_at));
    set("nbf", json!(issued_at));
    set("exp", json!(issued_at + request.ttl_seconds as i64));
    if v1 {
        set("appid", json!(request.client_id));
        set("appidacr", json!(request.client_auth.code()));
    } else {
        set("azp", json!(request.client_id));
        set("azpacr", json!(request.client_auth.code()));
    }
    set("tid", json!(request.tenant_id));
    set("ver", json!(if v1 { "1.0" } else { "2.0" }));

    match request.subject {
        ApiTokenSubject::App { principal_id } => {
            set("idtyp", json!("app"));
            set("oid", json!(principal_id));
            set("sub", json!(principal_id));
        }
        ApiTokenSubject::User {
            user_id,
            user_principal_name,
            display_name,
            given_name,
            family_name,
            scope,
        } => {
            set("oid", json!(user_id));
            set("sub", json!(user_id));
            set("name", json!(display_name));
            if v1 {
                // Microsoft lists these as v1.0 claims that v2.0 tokens leave out by default.
                set("upn", json!(user_principal_name));
                set("unique_name", json!(user_principal_name));
                set("amr", json!(["pwd"]));
                if let Some(given_name) = given_name {
                    set("given_name", json!(given_name));
                }
                if let Some(family_name) = family_name {
                    set("family_name", json!(family_name));
                }
            } else {
                set("preferred_username", json!(user_principal_name));
            }
            // Microsoft: `scp` is "Only included for user tokens", and "Claims are present only
            // if a value exists to fill it".
            if !scope.is_empty() {
                set("scp", json!(scope));
            }
        }
    }
    if !request.roles.is_empty() {
        set("roles", json!(request.roles));
    }
    for (name, value) in request.extra_claims {
        set(&name, value);
    }

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    if v1 {
        // Microsoft: `x5t` "Functions the same (in use and value) as `kid`" and is "emitted only
        // in v1.0 access tokens".
        header.x5t = Some(key.kid.clone());
    }
    let token = encode(&header, &claims, &key.encoding).context("signing the access token")?;
    Ok((token, request.ttl_seconds))
}

/// An OpenID Connect ID token, which describes the signed-in user to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IdTokenClaims {
    /// An ID token is addressed to the client, not to a resource.
    pub aud: String,
    pub iss: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
    pub oid: String,
    pub sub: String,
    pub tid: String,
    pub ver: String,
    pub name: String,
    pub preferred_username: String,
    /// Echoed from the authorization request, so the client can tie the token to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// Claims the client's registration asks for, such as `groups`.
    #[serde(flatten)]
    pub extra: serde_json::Map<String, serde_json::Value>,
}

/// Everything needed to mint an ID token.
pub struct IdTokenRequest<'a> {
    pub issuer: &'a str,
    pub tenant_id: &'a str,
    pub client_id: &'a str,
    pub user_id: &'a str,
    pub user_principal_name: &'a str,
    pub display_name: &'a str,
    pub nonce: Option<&'a str>,
    pub extra_claims: serde_json::Map<String, serde_json::Value>,
    pub ttl_seconds: u64,
}

/// Mint and sign an ID token.
pub fn issue_id_token(
    key: &SigningKey,
    request: IdTokenRequest<'_>,
    now: OffsetDateTime,
) -> Result<String> {
    let issued_at = now.unix_timestamp();
    let claims = IdTokenClaims {
        aud: request.client_id.to_string(),
        iss: request.issuer.to_string(),
        iat: issued_at,
        nbf: issued_at,
        exp: issued_at + request.ttl_seconds as i64,
        oid: request.user_id.to_string(),
        sub: request.user_id.to_string(),
        tid: request.tenant_id.to_string(),
        ver: "2.0".to_string(),
        name: request.display_name.to_string(),
        preferred_username: request.user_principal_name.to_string(),
        nonce: request.nonce.map(str::to_string),
        extra: request.extra_claims,
    };

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(key.kid.clone());
    encode(&header, &claims, &key.encoding).context("signing the ID token")
}
