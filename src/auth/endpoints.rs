//! The OAuth 2.0 token endpoint.

use axum::extract::{Form, Path, State};
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::{info, warn};

use crate::auth::claims::{self, TokenType};
use crate::auth::client_auth::{self, Presented};
use crate::auth::oauth_error::{self, OAuthFailure};
use crate::auth::scopes::{self, RequestedResource};
use crate::auth::sessions::{Grant, IssuedToken, SubjectKind, TokenKind};
use crate::auth::token::{
    ApiTokenRequest, ApiTokenSubject, AppTokenRequest, ClientAuth, issue_api_token,
    issue_app_token, issue_user_token,
};
use crate::state::AppState;
use crate::store::TokenVersion;
use crate::store::model::MICROSOFT_GRAPH_APP_ID;

/// A token request. Fields are shared across grant types, so all are optional here and the
/// handler for each grant enforces what it needs.
#[derive(Debug, Deserialize)]
pub struct TokenRequest {
    pub grant_type: Option<String>,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub scope: Option<String>,
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    pub code_verifier: Option<String>,
    pub refresh_token: Option<String>,
    /// The user's credentials, in the resource owner password credentials grant.
    pub username: Option<String>,
    pub password: Option<String>,
    pub client_assertion_type: Option<String>,
    /// A JWT signed by the client, in place of a secret.
    pub client_assertion: Option<String>,
    /// The code a device polls with, in the device authorization grant.
    pub device_code: Option<String>,
    /// The incoming token, in the on-behalf-of flow.
    pub assertion: Option<String>,
    pub requested_token_use: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct TokenResponse {
    pub token_type: &'static str,
    pub expires_in: u64,
    /// Seconds until the token should be refreshed. Entra returns this alongside `expires_in`.
    pub ext_expires_in: u64,
    pub access_token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    /// Issued when the client asked for `openid`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    /// Issued when the client asked for `offline_access`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new().route("/{tenant}/oauth2/v2.0/token", post(token))
}

async fn token(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Form(request): Form<TokenRequest>,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let named_tenant = tenant;
    let tenant = state.config.resolve_tenant(&named_tenant);
    if tenant != state.config.tenant_id {
        return Err(oauth_error::unknown_client(&tenant));
    }

    match request.grant_type.as_deref() {
        Some("client_credentials") => client_credentials(&state, &tenant, &headers, &request).await,
        Some("authorization_code") => authorization_code(&state, &tenant, &headers, &request).await,
        Some("refresh_token") => refresh_token(&state, &tenant, &headers, &request).await,
        Some(JWT_BEARER) => on_behalf_of(&state, &tenant, &headers, &request).await,
        Some(DEVICE_CODE) => device_code(&state, &tenant, &headers, &request).await,
        Some("password") => password(&state, &tenant, &named_tenant, &headers, &request).await,
        Some(other) => Err(oauth_error::unsupported_grant_type(other)),
        None => Err(oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'grant_type'.",
        )),
    }
}

async fn client_credentials(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let (client_id, presented) = required_credential(headers, request)?;

    // The app-only flow is always `{resource}/.default`: it asks for every app role already
    // granted, because there is no user present to consent to anything narrower.
    let scope = request.scope.as_deref().unwrap_or_default();
    let resource_name = resource_from_scope(scope)
        .ok_or_else(|| oauth_error::invalid_scope(scope))?
        .to_string();

    let advertised = state.config.public_base_url();
    let now = OffsetDateTime::now_utc();
    let client_auth = authenticate(state, tenant, &client_id, &presented, now).await?;
    let directory = state.store.read().await;

    let Some(application) = directory.application_by_app_id(&client_id) else {
        return Err(oauth_error::unknown_client(&client_id));
    };

    // The token represents the service principal, not the application registration.
    let Some(principal) = directory.service_principal_by_app_id(&client_id) else {
        return Err(oauth_error::no_grant(format!(
            "AADSTS65001: The application {client_id:?} has no service principal in the \
             directory. Create one before requesting a token."
        )));
    };

    let Some(resource) = directory.resource_for(&resource_name, &advertised) else {
        return Err(oauth_error::invalid_resource(&resource_name, tenant));
    };
    if !directory.app_may_access(&principal.id, &resource.id) {
        return Err(oauth_error::app_not_assigned(
            &client_id,
            &resource.app_id,
            &resource.display_name,
        ));
    }

    let issuer = format!("{advertised}/{tenant}/v2.0");
    let roles = directory.granted_role_values(std::slice::from_ref(&principal.id), &resource.id);
    let (audience, signed) = if resource.app_id == MICROSOFT_GRAPH_APP_ID {
        // Graph tokens keep the simulator's own URL as their audience, whichever name the client
        // used, because that is what the simulator's Graph surface validates against.
        let signed = issue_app_token(
            &state.signing_key,
            AppTokenRequest {
                audience: &advertised,
                issuer: &issuer,
                tenant_id: tenant,
                client_id: &client_id,
                principal_id: &principal.id,
                display_name: Some(&application.display_name),
                client_auth,
                roles: roles.clone(),
                ttl_seconds: state.config.token_ttl_seconds,
            },
            now,
        );
        (advertised.clone(), signed)
    } else {
        let version = directory.requested_access_token_version(&resource.app_id);
        let audience = api_audience(version, &resource.app_id, &resource_name);
        let signed = issue_api_token(
            &state.signing_key,
            ApiTokenRequest {
                version,
                audience: &audience,
                tenant_id: tenant,
                base_url: &advertised,
                client_id: &client_id,
                client_auth,
                subject: ApiTokenSubject::App {
                    principal_id: &principal.id,
                },
                roles: roles.clone(),
                extra_claims: Default::default(),
                ttl_seconds: state.config.token_ttl_seconds,
            },
            now,
        );
        (audience, signed)
    };
    let (access_token, expires_in) =
        signed.map_err(|error| oauth_error::server_error(error.to_string()))?;

    let issued = IssuedToken {
        id: uuid::Uuid::new_v4().to_string(),
        kind: TokenKind::Access,
        grant: Grant::ClientCredentials,
        client_id: client_id.clone(),
        subject_id: principal.id.clone(),
        subject_kind: SubjectKind::ServicePrincipal,
        subject_name: application.display_name.clone(),
        audience,
        scopes: Vec::new(),
        roles,
        issued_at: now,
        expires_at: now + Duration::seconds(expires_in as i64),
    };
    // Released before taking the session lock, so the two locks are never held together.
    drop(directory);
    info!(
        client_id = %client_id,
        subject_id = %issued.subject_id,
        audience = %issued.audience,
        "issued an app token"
    );
    state.sessions.lock().await.record_issued(issued);

    Ok(Json(TokenResponse {
        token_type: "Bearer",
        expires_in,
        ext_expires_in: expires_in,
        access_token,
        scope: request.scope.clone(),
        // An app-only token represents no user, so there is nothing for an ID token to
        // describe, and there is no sign-in to refresh.
        id_token: None,
        refresh_token: None,
    }))
}

/// Exchange an authorization code for tokens.
async fn authorization_code(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let code = request.code.as_deref().ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'code'.",
        )
    })?;

    let now = OffsetDateTime::now_utc();
    let issued = {
        let mut sessions = state.sessions.lock().await;
        sessions.take_code(code, now)
    };
    // A code that was already redeemed, never issued, or has expired is indistinguishable here,
    // and Entra does not distinguish them either.
    let issued = issued.ok_or_else(|| {
        oauth_error::invalid_grant(
            "AADSTS54005: OAuth2 Authorization code was already redeemed, please retry with a              new valid code or use an existing refresh token.",
        )
    })?;

    // The client presenting the code must be the one it was issued to.
    let presented_client = request
        .client_id
        .clone()
        .or_else(|| basic_auth(headers).map(|(id, _)| id));
    if presented_client.as_deref() != Some(issued.client_id.as_str()) {
        return Err(oauth_error::invalid_grant(
            "AADSTS70000: The provided authorization code was issued to a different client.",
        ));
    }

    // And must present the same redirect URI, so a stolen code cannot be redeemed towards
    // another destination.
    if request.redirect_uri.as_deref() != Some(issued.redirect_uri.as_str()) {
        return Err(oauth_error::invalid_grant(
            "AADSTS50011: The redirect URI in the token request does not match the one the              authorization code was issued for.",
        ));
    }

    crate::auth::pkce::verify(
        issued.code_challenge.as_deref(),
        issued.code_challenge_method.as_deref(),
        request.code_verifier.as_deref(),
    )
    .map_err(|reason| oauth_error::invalid_grant(format!("AADSTS501481: {reason}.")))?;

    // A confidential client must still authenticate; a public one has no secret to present and
    // relies on PKCE instead.
    let client_auth =
        authenticate_if_presented(state, tenant, &issued.client_id, headers, request, now).await?;

    let target = {
        let directory = state.store.read().await;
        user_token_target(
            &directory,
            state,
            tenant,
            &issued.client_id,
            &issued.user_id,
            &issued.scope,
            request.scope.as_deref(),
            Redemption::AuthorizationCode,
        )?
    };

    issue_user_tokens(
        state,
        tenant,
        SignIn {
            client_id: &issued.client_id,
            user_id: &issued.user_id,
            target,
            authorized_scope: &issued.scope,
            client_auth,
            nonce: issued.nonce.as_deref(),
            id_token: true,
            grant: Grant::AuthorizationCode,
        },
        now,
    )
    .await
}

/// Exchange a refresh token for a fresh set of tokens.
async fn refresh_token(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let presented = request.refresh_token.as_deref().ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: \
             'refresh_token'.",
        )
    })?;

    let now = OffsetDateTime::now_utc();
    let issued = {
        let mut sessions = state.sessions.lock().await;
        sessions.take_refresh_token(presented, now)
    };
    let issued = issued.ok_or_else(|| {
        oauth_error::invalid_grant(
            "AADSTS700082: The refresh token has expired or is no longer valid.",
        )
    })?;

    let presented_client = request
        .client_id
        .clone()
        .or_else(|| basic_auth(headers).map(|(id, _)| id));
    if presented_client.as_deref() != Some(issued.client_id.as_str()) {
        return Err(oauth_error::invalid_grant(
            "AADSTS70000: The provided refresh token was issued to a different client.",
        ));
    }

    let client_auth =
        authenticate_if_presented(state, tenant, &issued.client_id, headers, request, now).await?;

    // The consented scopes are read again here, not taken from the refresh token. Entra
    // invalidates a refresh token when consent is revoked, so a token minted from an old one
    // must not keep permissions the directory no longer grants.
    let target = {
        let directory = state.store.read().await;
        user_token_target(
            &directory,
            state,
            tenant,
            &issued.client_id,
            &issued.user_id,
            &issued.scope,
            request.scope.as_deref(),
            Redemption::RefreshToken,
        )?
    };

    issue_user_tokens(
        state,
        tenant,
        SignIn {
            client_id: &issued.client_id,
            user_id: &issued.user_id,
            target,
            authorized_scope: &issued.scope,
            client_auth,
            // A refreshed ID token carries no nonce; there was no fresh authorization request
            // to bind it to.
            nonce: None,
            id_token: true,
            grant: Grant::RefreshToken,
        },
        now,
    )
    .await
}

/// Sign a user in with their username and password: the resource owner password credentials
/// grant.
///
/// Per Microsoft's ROPC documentation: the tenant "can't be set to `common` or `consumers`, but may
/// be set to `organizations`"; "If your app is a public client, then the `client_secret` or
/// `client_assertion` can't be included. If the app is a confidential client, then it must be
/// included"; "Accounts that don't have passwords can't sign in with ROPC"; a wrong password gives
/// `invalid_grant`, and "If the scopes aren't granted, a `consent_required` error will be
/// returned."
async fn password(
    state: &AppState,
    tenant: &str,
    named_tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    if matches!(named_tenant, "common" | "consumers") {
        return Err(oauth_error::invalid_request(
            "AADSTS90023: The grant type isn't supported on the /common or /consumers \
             authentication contexts. Use /organizations or a tenant ID instead.",
        ));
    }
    let missing = |name: &str| {
        oauth_error::invalid_request(format!(
            "AADSTS900144: The request body must contain the following parameter: '{name}'."
        ))
    };
    let username = request
        .username
        .as_deref()
        .ok_or_else(|| missing("username"))?;
    let password = request
        .password
        .as_deref()
        .ok_or_else(|| missing("password"))?;
    let (client_id, presented) = presented_credential(headers, request)?;
    let client_id = client_id.ok_or_else(|| missing("client_id"))?;
    let now = OffsetDateTime::now_utc();

    // Microsoft's manifest reference: when Entra "can't determine the client application type.
    // For example, the ROPC flow ... Microsoft Entra ID interprets the application type based on
    // the value of" isFallbackPublicClient.
    let public = {
        let directory = state.store.read().await;
        let application = directory
            .application_by_app_id(&client_id)
            .ok_or_else(|| oauth_error::unknown_client(&client_id))?;
        application.extra.get("isFallbackPublicClient") == Some(&serde_json::Value::Bool(true))
    };
    let client_auth = match (public, presented) {
        (true, None) => ClientAuth::Public,
        (true, Some(_)) => return Err(oauth_error::public_client_with_credential()),
        (false, None) => return Err(oauth_error::invalid_client_credential_missing()),
        (false, Some(presented)) => {
            authenticate(state, tenant, &client_id, &presented, now).await?
        }
    };

    let user_id = {
        let directory = state.store.read().await;
        let user = directory
            .user_by_principal_name(username)
            .filter(|user| user.password.as_deref() == Some(password))
            .ok_or_else(oauth_error::invalid_username_or_password)?;
        if !user.account_enabled {
            return Err(oauth_error::user_disabled());
        }
        user.id.clone()
    };

    let scope = request.scope.as_deref().unwrap_or_default();
    let target = {
        let directory = state.store.read().await;
        user_token_target(
            &directory,
            state,
            tenant,
            &client_id,
            &user_id,
            scope,
            Some(scope),
            Redemption::AuthorizationCode,
        )?
    };
    issue_user_tokens(
        state,
        tenant,
        SignIn {
            client_id: &client_id,
            user_id: &user_id,
            target,
            authorized_scope: scope,
            client_auth,
            nonce: None,
            id_token: true,
            grant: Grant::Password,
        },
        now,
    )
    .await
}

/// The grant type a device polls with.
const DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Answer a device polling for the tokens of a device code sign-in.
async fn device_code(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    use crate::auth::sessions::DeviceStatus;

    let device_code = request.device_code.as_deref().ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: \
             'device_code'.",
        )
    })?;
    let now = OffsetDateTime::now_utc();
    let bad_code = || {
        oauth_error::device_flow(
            "bad_verification_code",
            70018,
            "The device_code was not recognized.",
        )
    };
    let details = state
        .sessions
        .lock()
        .await
        .device_authorization(device_code)
        .cloned()
        .ok_or_else(bad_code)?;
    // Microsoft: client_id "Must match the client_id used in the initial request."
    if request.client_id.as_deref() != Some(details.client_id.as_str()) {
        return Err(bad_code());
    }
    if details.expires_at <= now {
        return Err(oauth_error::device_flow(
            "expired_token",
            70019,
            "Verification code expired.",
        ));
    }
    let user_id = match details.status {
        DeviceStatus::Pending => {
            return Err(oauth_error::device_flow(
                "authorization_pending",
                70016,
                "OAuth 2.0 device flow error. Authorization is pending. Continue polling.",
            ));
        }
        DeviceStatus::Declined => {
            return Err(oauth_error::device_flow(
                "authorization_declined",
                65004,
                "User declined to consent to access the app.",
            ));
        }
        DeviceStatus::Approved { user_id } => user_id,
    };
    let client_auth =
        authenticate_if_presented(state, tenant, &details.client_id, headers, request, now).await?;
    // Single use, like an authorization code.
    state
        .sessions
        .lock()
        .await
        .take_device_authorization(device_code);
    let target = {
        let directory = state.store.read().await;
        user_token_target(
            &directory,
            state,
            tenant,
            &details.client_id,
            &user_id,
            &details.scope,
            None,
            Redemption::AuthorizationCode,
        )?
    };
    issue_user_tokens(
        state,
        tenant,
        SignIn {
            client_id: &details.client_id,
            user_id: &user_id,
            target,
            authorized_scope: &details.scope,
            client_auth,
            nonce: None,
            id_token: true,
            grant: Grant::DeviceCode,
        },
        now,
    )
    .await
}

/// The grant type of the on-behalf-of flow.
const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Exchange a user's token for one API into a token for another, for the API the first token
/// was issued to.
///
/// Microsoft's on-behalf-of documentation: the `assertion` "must have an audience (`aud`) claim
/// of the app making this OBO request", "the OBO flow only works for user principals", and the
/// middle tier "only uses delegated scopes and not application roles. Roles remain attached to
/// the principal (the user) and never to the application operating on the user's behalf."
async fn on_behalf_of(
    state: &AppState,
    tenant: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    if request.requested_token_use.as_deref() != Some("on_behalf_of") {
        return Err(oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: \
             'requested_token_use'.",
        ));
    }
    let assertion = request.assertion.as_deref().ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'assertion'.",
        )
    })?;
    // The middle tier is a confidential client and must authenticate.
    let (client_id, presented) = required_credential(headers, request)?;
    let now = OffsetDateTime::now_utc();
    let advertised = state.config.public_base_url();

    let client_auth = authenticate(state, tenant, &client_id, &presented, now).await?;
    let user_id = {
        let directory = state.store.read().await;

        let issuers = [
            format!("{advertised}/{tenant}/v2.0"),
            crate::auth::token::v1_issuer(tenant),
        ];
        let claims = crate::auth::token::decode_issued(&state.signing_key, assertion, &issuers)
            .map_err(|error| {
                oauth_error::invalid_assertion(&format!("It could not be validated: {error}."))
            })?;

        let audience = claims["aud"].as_str().unwrap_or_default();
        let addressed_to = directory
            .resource_for(audience, &advertised)
            .map(|principal| principal.app_id.clone());
        if addressed_to.as_deref() != Some(client_id.as_str()) {
            return Err(oauth_error::invalid_assertion(&format!(
                "Its audience {audience:?} is not the application {client_id:?} making the \
                 request."
            )));
        }
        let user_id = claims["oid"].as_str().unwrap_or_default().to_string();
        if claims["idtyp"] == "app" || !directory.users.contains_key(&user_id) {
            return Err(oauth_error::invalid_assertion(
                "It is an app-only token, and the on-behalf-of flow only works for users.",
            ));
        }
        user_id
    };

    let scope = request.scope.as_deref().unwrap_or_default();
    let target = {
        let directory = state.store.read().await;
        user_token_target(
            &directory,
            state,
            tenant,
            &client_id,
            &user_id,
            scope,
            Some(scope),
            Redemption::OnBehalfOf,
        )?
    };

    issue_user_tokens(
        state,
        tenant,
        SignIn {
            client_id: &client_id,
            user_id: &user_id,
            target,
            authorized_scope: scope,
            client_auth,
            nonce: None,
            // Microsoft's response lists no ID token for this flow.
            id_token: false,
            grant: Grant::OnBehalfOf,
        },
        now,
    )
    .await
}

/// Which grant is redeeming the sign-in. Microsoft documents different rules for each.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Redemption {
    /// "The scopes must all be from a single resource", and a named permission that was never
    /// consented gives `consent_required`, which Microsoft says is "Returned when a scope
    /// parameter was used on the code redemption flow that the client app doesn't have
    /// permission to request."
    AuthorizationCode,
    /// "If the scopes specified in this request span multiple resource server, then the
    /// Microsoft identity platform returns a token for the resource specified in the first
    /// scope." Permissions no longer consented are left out of the token.
    RefreshToken,
    /// One API per token, and the user must already have consented to the middle tier calling
    /// it: "the middle-tier service has no user interaction to get the user's consent".
    OnBehalfOf,
}

/// The API a user token is for, and the permissions the user consented to on it.
struct UserTokenTarget {
    resource: RequestedResource,
    /// Consented scope values on the API, unqualified.
    granted: Vec<String>,
    /// Whether the sign-in asked for `offline_access`, which is what earns a refresh token.
    offline_access: bool,
    /// The OpenID Connect scopes the sign-in asked for, which some claims depend on.
    oidc: Vec<String>,
}

/// Decide which API a user token is for.
///
/// The token request's own `scope` wins when it names an API: Microsoft calls this "a
/// Microsoft extension ... to allow apps to declare the resource they want the token for during
/// token redemption", and a refresh token "can be used to request a new access token for"
/// another API. Otherwise the first API the sign-in asked for, and Microsoft Graph when it
/// named none. The permissions come from the consent recorded in the directory.
#[allow(clippy::too_many_arguments)]
fn user_token_target(
    directory: &crate::store::Directory,
    state: &AppState,
    tenant: &str,
    client_id: &str,
    user_id: &str,
    authorized_scope: &str,
    requested_scope: Option<&str>,
    redemption: Redemption,
) -> Result<UserTokenTarget, OAuthFailure> {
    let base_url = state.config.public_base_url();
    let (authorized_oidc, authorized_named) = scopes::parse(authorized_scope);
    let (_, requested_named) = scopes::parse(requested_scope.unwrap_or_default());

    let named = if requested_named.is_empty() {
        authorized_named
    } else {
        requested_named.clone()
    };
    let mut resources = scopes::resolve(directory, &base_url, &named)
        .map_err(|unknown| oauth_error::invalid_resource(&unknown, tenant))?;
    // The sign-in may have named several APIs; only the redemption's own scope must name one.
    if resources.len() > 1 && redemption != Redemption::RefreshToken && !requested_named.is_empty()
    {
        return Err(oauth_error::multiple_resources(
            requested_scope.unwrap_or_default(),
        ));
    }
    let resource = if resources.is_empty() {
        let graph = directory
            .graph_service_principal()
            .ok_or_else(|| oauth_error::server_error("Microsoft Graph is not registered."))?;
        RequestedResource {
            principal_id: graph.id.clone(),
            app_id: graph.app_id.clone(),
            requested_as: None,
            values: Vec::new(),
        }
    } else {
        resources.remove(0)
    };

    if !directory.user_may_access(user_id, &resource.principal_id) {
        let name = directory
            .service_principals
            .get(&resource.principal_id)
            .map(|principal| principal.display_name.clone())
            .unwrap_or_default();
        return Err(oauth_error::user_not_assigned(&resource.app_id, &name));
    }

    let granted = directory.consented_scopes(client_id, user_id, &resource.principal_id);
    if redemption == Redemption::OnBehalfOf {
        let missing = resource
            .named_scopes()
            .find(|scope| !granted.contains(scope));
        if let Some(scope) = missing {
            return Err(oauth_error::on_behalf_of_consent_required(
                &resource.qualify(scope),
            ));
        }
        if granted.is_empty() {
            let named = resource
                .requested_as
                .as_deref()
                .unwrap_or("Microsoft Graph");
            return Err(oauth_error::on_behalf_of_consent_required(named));
        }
    }
    if redemption == Redemption::AuthorizationCode
        && !requested_named.is_empty()
        && let Some(missing) = resource
            .named_scopes()
            .find(|scope| !granted.contains(scope))
    {
        return Err(oauth_error::consent_required(&resource.qualify(missing)));
    }

    Ok(UserTokenTarget {
        resource,
        granted,
        offline_access: authorized_oidc
            .iter()
            .any(|scope| scope == "offline_access"),
        oidc: authorized_oidc,
    })
}

/// A signed-in user to mint tokens for: through which client, for which API, and by which
/// grant the request arrived.
struct SignIn<'a> {
    client_id: &'a str,
    user_id: &'a str,
    target: UserTokenTarget,
    /// The scope the sign-in asked for, kept on the refresh token.
    authorized_scope: &'a str,
    client_auth: ClientAuth,
    nonce: Option<&'a str>,
    /// Whether to issue an ID token alongside the access token.
    id_token: bool,
    grant: Grant,
}

/// Mint the access, ID and refresh tokens for a signed-in user.
async fn issue_user_tokens(
    state: &AppState,
    tenant: &str,
    sign_in: SignIn<'_>,
    now: OffsetDateTime,
) -> Result<Json<TokenResponse>, OAuthFailure> {
    let SignIn {
        client_id,
        user_id,
        target,
        authorized_scope,
        client_auth,
        nonce,
        id_token: wants_id_token,
        grant,
    } = sign_in;
    let advertised = state.config.public_base_url();
    let issuer = format!("{advertised}/{tenant}/v2.0");

    let resource = &target.resource;
    let (
        user_principal_name,
        display_name,
        given_name,
        family_name,
        roles,
        id_roles,
        version,
        aud_use_guid,
        access_groups,
        id_groups,
    ) = {
        let directory = state.store.read().await;
        let user = directory.users.get(user_id).ok_or_else(|| {
            oauth_error::no_grant("AADSTS50034: The user account does not exist in the directory.")
        })?;
        // Microsoft: "For user tokens, this set of values contains the assigned roles of the user
        // on the target application."
        let roles = user_roles_on(&directory, user_id, &resource.principal_id);
        // "for an app that signs in users, the roles claims are included in the ID token."
        let id_roles = directory
            .service_principal_by_app_id(client_id)
            .map(|client| user_roles_on(&directory, user_id, &client.id))
            .unwrap_or_default();
        // Each token carries the group claims of the application it is issued for: the API for
        // the access token, the client for the ID token.
        let group_claims = |app_id: &str, token_type| {
            claims::group_claims(&directory, tenant, user_id, app_id, token_type)
        };
        let mut access_groups = group_claims(&resource.app_id, TokenType::Access);
        let mut id_groups = group_claims(client_id, TokenType::Id);
        let version = directory.requested_access_token_version(&resource.app_id);
        let access_optional = claims::optional_claims(
            &directory,
            &resource.app_id,
            TokenType::Access,
            version,
            user,
            &target.oidc,
        );
        // ID tokens come from the v2.0 endpoint, the only one the simulator implements.
        let id_optional = claims::optional_claims(
            &directory,
            client_id,
            TokenType::Id,
            TokenVersion::V2,
            user,
            &target.oidc,
        );
        access_groups.claims.extend(access_optional.claims);
        id_groups.claims.extend(id_optional.claims);
        (
            user.user_principal_name.clone(),
            user.display_name.clone(),
            user.given_name.clone(),
            user.surname.clone(),
            access_groups.roles_instead.clone().unwrap_or(roles),
            id_roles,
            version,
            access_optional.aud_use_guid,
            access_groups.claims,
            id_groups,
        )
    };

    // `offline_access` is consented on Graph like the other OpenID Connect scopes, but it governs
    // whether a refresh token is issued rather than access to Graph, so it stays out of `scp`.
    let granted: Vec<String> = target
        .granted
        .iter()
        .filter(|scope| *scope != "offline_access")
        .cloned()
        .collect();
    let scope = granted.join(" ");
    let (audience, signed) = if resource.is_graph() {
        let signed = issue_user_token(
            &state.signing_key,
            crate::auth::token::UserTokenRequest {
                audience: &advertised,
                issuer: &issuer,
                tenant_id: tenant,
                client_id,
                user_id,
                user_principal_name: &user_principal_name,
                display_name: &display_name,
                scope: &scope,
                roles: roles.clone(),
                client_auth,
                ttl_seconds: state.config.token_ttl_seconds,
            },
            now,
        );
        (advertised.clone(), signed)
    } else {
        let requested_as = if aud_use_guid {
            &resource.app_id
        } else {
            resource.requested_as.as_deref().unwrap_or(&resource.app_id)
        };
        let audience = api_audience(version, &resource.app_id, requested_as);
        let signed = issue_api_token(
            &state.signing_key,
            ApiTokenRequest {
                version,
                audience: &audience,
                tenant_id: tenant,
                base_url: &advertised,
                client_id,
                client_auth,
                subject: ApiTokenSubject::User {
                    user_id,
                    user_principal_name: &user_principal_name,
                    display_name: &display_name,
                    given_name: given_name.as_deref(),
                    family_name: family_name.as_deref(),
                    scope: &scope,
                },
                roles: roles.clone(),
                extra_claims: access_groups,
                ttl_seconds: state.config.token_ttl_seconds,
            },
            now,
        );
        (audience, signed)
    };
    let (access_token, expires_in) =
        signed.map_err(|error| oauth_error::server_error(error.to_string()))?;

    let mut id_claims = id_groups.claims;
    let id_roles = id_groups.roles_instead.unwrap_or(id_roles);
    if !id_roles.is_empty() {
        id_claims.insert("roles".to_string(), serde_json::json!(id_roles));
    }
    let id_token = if wants_id_token {
        let signed = crate::auth::token::issue_id_token(
            &state.signing_key,
            crate::auth::token::IdTokenRequest {
                issuer: &issuer,
                tenant_id: tenant,
                client_id,
                user_id,
                user_principal_name: &user_principal_name,
                display_name: &display_name,
                nonce,
                extra_claims: id_claims,
                ttl_seconds: state.config.token_ttl_seconds,
            },
            now,
        )
        .map_err(|error| oauth_error::server_error(error.to_string()))?;
        Some(signed)
    } else {
        None
    };

    let mut sessions = state.sessions.lock().await;
    sessions.evict_expired(now);

    let expires_at = now + Duration::seconds(expires_in as i64);
    let issued = |kind, audience: &str, scopes: Vec<String>| IssuedToken {
        id: uuid::Uuid::new_v4().to_string(),
        kind,
        grant,
        client_id: client_id.to_string(),
        subject_id: user_id.to_string(),
        subject_kind: SubjectKind::User,
        subject_name: user_principal_name.clone(),
        audience: audience.to_string(),
        scopes,
        roles: match kind {
            TokenKind::Access => roles.clone(),
            _ => Vec::new(),
        },
        issued_at: now,
        expires_at,
    };
    // The ID token first, so the access token, the one a reader usually wants, ends up on top
    // of the newest-first log.
    if id_token.is_some() {
        sessions.record_issued(issued(TokenKind::Id, client_id, Vec::new()));
    }
    sessions.record_issued(issued(TokenKind::Access, &audience, granted.clone()));

    let refresh = if target.offline_access {
        let token = uuid::Uuid::new_v4().simple().to_string();
        sessions.store_refresh_token(
            token.clone(),
            crate::auth::sessions::RefreshToken {
                client_id: client_id.to_string(),
                user_id: user_id.to_string(),
                scope: authorized_scope.to_string(),
                expires_at: crate::auth::sessions::refresh_expiry(now),
            },
        );
        Some(token)
    } else {
        None
    };
    info!(
        grant = ?grant,
        client_id = %client_id,
        user_id = %user_id,
        upn = %user_principal_name,
        audience = %audience,
        scope = %scope,
        refresh_token = refresh.is_some(),
        "issued user tokens"
    );

    let qualified: Vec<String> = granted
        .iter()
        .map(|value| resource.qualify(value))
        .collect();
    Ok(Json(TokenResponse {
        token_type: "Bearer",
        expires_in,
        ext_expires_in: expires_in,
        access_token,
        scope: Some(qualified.join(" ")),
        id_token,
        refresh_token: refresh,
    }))
}

/// The app roles a user holds on the application whose service principal is `principal_id`.
///
/// Roles assigned to a group reach its direct members only: Microsoft supports group-based
/// assignment for security groups, and "Nested group memberships aren't supported".
fn user_roles_on(
    directory: &crate::store::Directory,
    user_id: &str,
    principal_id: &str,
) -> Vec<String> {
    let mut holders = vec![user_id.to_string()];
    holders.extend(
        directory
            .groups_containing(user_id)
            .into_iter()
            .filter(|group| group.security_enabled)
            .map(|group| group.id.clone()),
    );
    directory.granted_role_values(&holders, principal_id)
}

/// The `aud` of a token for a registered API.
///
/// Microsoft: "In v2.0 tokens, this value is always the client ID of the API. In v1.0 tokens,
/// it can be the client ID or the resource URI used in the request."
fn api_audience(version: TokenVersion, app_id: &str, requested_as: &str) -> String {
    match version {
        TokenVersion::V2 => app_id.to_string(),
        TokenVersion::V1 => requested_as.to_string(),
    }
}

/// Authenticate the client when it presented a credential, and report how it did.
///
/// A public client has no secret and proves itself with PKCE instead, so an absent credential is
/// not an error here. A wrong one is.
async fn authenticate_if_presented(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    headers: &HeaderMap,
    request: &TokenRequest,
    now: OffsetDateTime,
) -> Result<ClientAuth, OAuthFailure> {
    let (_, presented) = presented_credential(headers, request)?;
    let Some(presented) = presented else {
        return Ok(ClientAuth::Public);
    };
    authenticate(state, tenant, client_id, &presented, now).await
}

/// Check a presented credential against the client's registration.
///
/// An assertion whose issuer is the client itself is signed with one of its certificates; any
/// other issuer is matched against its federated identity credentials.
async fn authenticate(
    state: &AppState,
    tenant: &str,
    client_id: &str,
    presented: &Presented,
    now: OffsetDateTime,
) -> Result<ClientAuth, OAuthFailure> {
    let assertion = match presented {
        Presented::Secret(secret) => {
            let directory = state.store.read().await;
            if directory.application_by_app_id(client_id).is_none() {
                return Err(oauth_error::unknown_client(client_id));
            }
            if directory
                .matching_credential(client_id, secret, now)
                .is_none()
            {
                warn!(client_id, "rejected a token request with an invalid secret");
                return Err(oauth_error::invalid_client_secret());
            }
            return Ok(ClientAuth::Secret);
        }
        Presented::Assertion(assertion) => assertion,
    };

    let claims = client_auth::peek_claims(assertion)
        .ok_or_else(|| oauth_error::invalid_jwt("The assertion is not a well-formed JWT."))?;
    let issuer = claims["iss"].as_str().unwrap_or_default().to_string();
    if issuer == client_id {
        let directory = state.store.read().await;
        client_auth::verify_certificate_assertion(
            &directory,
            client_id,
            assertion,
            &token_endpoint_urls(state, tenant),
            now,
        )?;
        return Ok(ClientAuth::Certificate);
    }

    // The lock is released before any network call.
    let federated = {
        let directory = state.store.read().await;
        client_auth::matching_federated_credential(&directory, client_id, &claims)?
    };
    let base = state.config.public_base_url();
    let own_issuers = [
        format!("{base}/{tenant}/v2.0"),
        crate::auth::token::v1_issuer(tenant),
    ];
    if own_issuers.contains(&issuer) {
        // A token this simulator issued. Microsoft: "Only app-only tokens can be used as
        // Federated Identity Credentials for Microsoft Entra issuer."
        let verified =
            crate::auth::token::decode_issued(&state.signing_key, assertion, &own_issuers)
                .map_err(|error| {
                    oauth_error::invalid_jwt(&format!("The assertion is not valid: {error}."))
                })?;
        if verified["idtyp"] != "app" {
            return Err(oauth_error::forbidden_token_type());
        }
    } else {
        client_auth::verify_external_signature(
            client_auth::http_client(),
            assertion,
            &issuer,
            &federated.audiences,
        )
        .await?;
    }
    // Microsoft documents azpacr values for a public client, a secret and a certificate only. A
    // federated assertion is an asymmetrically signed client assertion like a certificate's, so
    // it is reported the same way.
    Ok(ClientAuth::Certificate)
}

/// The token endpoint URLs a client assertion's `aud` may name: this tenant's, under any of the
/// names the simulator answers to, for both protocol versions.
fn token_endpoint_urls(state: &AppState, tenant: &str) -> Vec<String> {
    let base = state.config.public_base_url();
    [
        tenant,
        &state.config.tenant_domain,
        "common",
        "organizations",
    ]
    .iter()
    .flat_map(|name| {
        [
            format!("{base}/{name}/oauth2/v2.0/token"),
            format!("{base}/{name}/oauth2/token"),
        ]
    })
    .collect()
}

/// Read the client ID and the credential the request presents: `client_secret_post`,
/// `client_secret_basic` or `private_key_jwt`.
///
/// Body parameters win when both are present, matching Entra, which is lenient here.
fn presented_credential(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<(Option<String>, Option<Presented>), OAuthFailure> {
    if let Some(assertion) = &request.client_assertion {
        if request.client_assertion_type.as_deref() != Some(client_auth::JWT_BEARER_ASSERTION) {
            return Err(oauth_error::invalid_request(format!(
                "AADSTS900144: The request body must contain the following parameter: \
                 'client_assertion_type' with the value {:?}.",
                client_auth::JWT_BEARER_ASSERTION
            )));
        }
        return Ok((
            request.client_id.clone(),
            Some(Presented::Assertion(assertion.clone())),
        ));
    }
    if let (Some(id), Some(secret)) = (&request.client_id, &request.client_secret) {
        return Ok((Some(id.clone()), Some(Presented::Secret(secret.clone()))));
    }
    if let Some((id, secret)) = basic_auth(headers) {
        return Ok((Some(id), Some(Presented::Secret(secret))));
    }
    Ok((request.client_id.clone(), None))
}

/// The client ID and credential a confidential client must present.
fn required_credential(
    headers: &HeaderMap,
    request: &TokenRequest,
) -> Result<(String, Presented), OAuthFailure> {
    match presented_credential(headers, request)? {
        (Some(id), Some(presented)) => Ok((id, presented)),
        (Some(_), None) => Err(oauth_error::invalid_client_credential_missing()),
        (None, _) => Err(oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'client_id'.",
        )),
    }
}

/// Decode an HTTP Basic credential pair, which OAuth requires be form-urlencoded before use.
fn basic_auth(headers: &HeaderMap) -> Option<(String, String)> {
    let header = headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?;
    let encoded = header
        .strip_prefix("Basic ")
        .or_else(|| header.strip_prefix("basic "))?;
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (id, secret) = decoded.split_once(':')?;
    Some((percent_decode(id), percent_decode(secret)))
}

/// RFC 6749 section 2.3.1 requires the two halves of a Basic credential be form-urlencoded.
fn percent_decode(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' if index + 2 < bytes.len() => {
                match u8::from_str_radix(&value[index + 1..index + 3], 16) {
                    Ok(byte) => {
                        out.push(byte);
                        index += 3;
                    }
                    Err(_) => {
                        out.push(b'%');
                        index += 1;
                    }
                }
            }
            b'+' => {
                out.push(b' ');
                index += 1;
            }
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).unwrap_or_else(|_| value.to_string())
}

/// Pull the resource out of a `{resource}/.default` scope.
///
/// `go-azure-sdk` builds exactly this from the `microsoftGraphResourceId` in the metadata
/// document, so for the Terraform provider the resource it names is the simulator's own base
/// URL. Any other client names an API by its identifier URI or its appId.
fn resource_from_scope(scope: &str) -> Option<&str> {
    scope
        .split_whitespace()
        .find_map(|entry| entry.strip_suffix("/.default"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::header::AUTHORIZATION;

    #[test]
    fn resource_is_read_from_a_default_scope() {
        assert_eq!(
            resource_from_scope("https://sim.test/.default"),
            Some("https://sim.test")
        );
        // Entra tolerates additional scopes alongside the resource scope.
        assert_eq!(
            resource_from_scope("openid https://sim.test/.default"),
            Some("https://sim.test")
        );
        assert_eq!(resource_from_scope("User.Read"), None);
        assert_eq!(resource_from_scope(""), None);
    }

    #[test]
    fn basic_credentials_are_decoded_and_unescaped() {
        let mut headers = HeaderMap::new();
        // A secret containing a colon and a space, form-urlencoded as the RFC requires.
        let raw = format!("{}:{}", "my-client", "se%3Acret+with%20space");
        let encoded = STANDARD.encode(raw);
        headers.insert(
            AUTHORIZATION,
            format!("Basic {encoded}").parse().expect("header value"),
        );

        let (id, secret) = basic_auth(&headers).expect("decoding the credentials");
        assert_eq!(id, "my-client");
        assert_eq!(secret, "se:cret with space");
    }

    #[test]
    fn a_non_basic_authorization_header_is_ignored() {
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, "Bearer something".parse().unwrap());
        assert!(basic_auth(&headers).is_none());
    }
}
