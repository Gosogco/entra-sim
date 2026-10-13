//! The authorization endpoint and its sign-in page.
//!
//! The page stands in for Entra's sign-in and consent experience: it lists the tenant's users
//! and the permissions the client is asking for, and submitting it both chooses a user and
//! records consent as a real `oauth2PermissionGrant`. Recording consent properly matters because
//! the delegated token's `scp` claim is then derived from the directory, the same way Entra
//! derives it, rather than from whatever the client happened to ask for.

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use time::OffsetDateTime;
use tracing::info;
use uuid::Uuid;

use crate::auth::scopes::{self, RequestedResource};
use crate::auth::sessions::{AuthorizationCode, code_expiry};
use crate::state::AppState;
use crate::store::Directory;
use crate::store::model::{MICROSOFT_GRAPH_APP_ID, OAuth2PermissionGrant};

#[derive(Debug, Deserialize)]
pub struct AuthorizeRequest {
    pub client_id: Option<String>,
    pub response_type: Option<String>,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    pub code_challenge: Option<String>,
    pub code_challenge_method: Option<String>,
    pub response_mode: Option<String>,
    /// `login`, `select_account` and `consent` show the page even when the user could be
    /// signed in without it; `none` forbids showing it.
    pub prompt: Option<String>,
    /// The user to offer first on the sign-in page.
    pub login_hint: Option<String>,
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route(
            "/{tenant}/oauth2/v2.0/authorize",
            get(show_sign_in).post(complete_sign_in),
        )
        .route("/{tenant}/oauth2/v2.0/logout", get(logout))
}

/// A failure that cannot be reported by redirecting.
///
/// When the client or redirect URI is itself invalid, redirecting would send the error to an
/// unverified destination, so OAuth requires it be shown to the user instead.
struct Unredirectable(String);

/// A refused authorization request, either shown to the user or redirected to the client.
///
/// Boxed because a response is wide and this only ever travels on the failure path.
struct Refusal(Box<Response>);

impl IntoResponse for Refusal {
    fn into_response(self) -> Response {
        *self.0
    }
}

impl From<Unredirectable> for Refusal {
    fn from(failure: Unredirectable) -> Self {
        Self(Box::new(failure.into_response()))
    }
}

fn unredirectable(description: String) -> Refusal {
    Unredirectable(description).into()
}

/// Report an error to the client by redirecting to its verified redirect URI.
fn redirect_error(
    redirect_uri: &str,
    mode: ResponseMode,
    state: Option<&str>,
    error: &str,
    description: &str,
) -> Refusal {
    let mut parameters = vec![("error", error), ("error_description", description)];
    if let Some(value) = state {
        parameters.push(("state", value));
    }
    Refusal(Box::new(respond(redirect_uri, mode, &parameters)))
}

impl IntoResponse for Unredirectable {
    fn into_response(self) -> Response {
        (
            StatusCode::BAD_REQUEST,
            Html(page(
                "Sign-in error",
                &format!("<p class=\"error\">{}</p>", escape(&self.0)),
            )),
        )
            .into_response()
    }
}

async fn show_sign_in(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    headers: HeaderMap,
    Query(request): Query<AuthorizeRequest>,
) -> Result<Response, Refusal> {
    let directory = state.store.read().await;
    let validated = validate(&state, &directory, &request)?;
    let now = OffsetDateTime::now_utc();

    // The user this browser is already signed in as, which single sign-on reuses.
    let signed_in = match session_cookie(&headers) {
        Some(id) => state.sessions.lock().await.browser_session_user(&id, now),
        None => None,
    }
    .filter(|user_id| directory.users.contains_key(user_id))
    .filter(|user_id| {
        // A hint naming someone else is a request for that user, not the signed-in one.
        request.login_hint.as_deref().is_none_or(|hint| {
            directory.users[user_id]
                .user_principal_name
                .eq_ignore_ascii_case(hint)
        })
    });

    let prompt = request.prompt.as_deref();
    if prompt == Some("none") {
        // Microsoft: "prompt=none ... ensures that the user isn't presented with any
        // interactive prompt", with `login_required` when "a single user couldn't be found" and
        // `interaction_required` when "Another authentication step or consent is required".
        let Some(user_id) = signed_in else {
            return Err(redirect_error(
                &validated.redirect_uri,
                validated.response_mode,
                request.state.as_deref(),
                "login_required",
                "AADSTS50058: A silent sign-in request was sent but no user is signed in.",
            ));
        };
        if !consent_satisfied(&directory, &validated, &user_id) {
            return Err(redirect_error(
                &validated.redirect_uri,
                validated.response_mode,
                request.state.as_deref(),
                "interaction_required",
                "AADSTS65001: The user or administrator has not consented to use the \
                 application. Send an interactive authorization request for this user and \
                 resource.",
            ));
        }
        drop(directory);
        return Ok(issue_code(&state, &tenant, &request, &validated, &user_id, false).await);
    }

    // `prompt=login` forces credentials and `select_account` the account picker; `consent` asks
    // for consent again. The simulator's page does all three.
    let forced = matches!(prompt, Some("login" | "select_account" | "consent"));
    if let Some(upn) = state.config.auto_sign_in_user.as_deref()
        && !forced
    {
        let user = directory
            .user_by_principal_name(upn)
            .ok_or_else(|| {
                unredirectable(format!(
                    "The configured automatic sign-in user {upn:?} is not in the directory."
                ))
            })?
            .id
            .clone();
        drop(directory);
        return Ok(issue_code(&state, &tenant, &request, &validated, &user, true).await);
    }

    // Entra's default "is to either sign in the sole current user, show the account picker if
    // there are multiple users, or show the login page if there are no users signed in". A
    // signed-in user who has already consented is signed in again without the page.
    if !forced
        && let Some(user_id) = signed_in
        && consent_satisfied(&directory, &validated, &user_id)
    {
        drop(directory);
        return Ok(issue_code(&state, &tenant, &request, &validated, &user_id, false).await);
    }

    let mut users: Vec<(String, String, String)> = directory
        .users
        .values()
        .map(|user| {
            (
                user.id.clone(),
                user.display_name.clone(),
                user.user_principal_name.clone(),
            )
        })
        .collect();
    // The hinted user goes first, as Entra pre-fills the hinted name.
    if let Some(hint) = request.login_hint.as_deref() {
        users.sort_by_key(|(_, _, upn)| !upn.eq_ignore_ascii_case(hint));
    }

    Ok(Html(sign_in_page(&request, &validated, &users)).into_response())
}

/// Whether the user has already consented to everything the request names, so that signing
/// them in again needs no page. Only permissions the API publishes count, since nothing else can
/// be consented to.
fn consent_satisfied(directory: &Directory, validated: &Validated, user_id: &str) -> bool {
    with_oidc_on_graph(directory, validated)
        .iter()
        .all(|requested| {
            let Some(resource) = directory.service_principals.get(&requested.principal_id) else {
                return true;
            };
            let consented =
                directory.consented_scopes(&validated.client_id, user_id, &requested.principal_id);
            requested
                .named_scopes()
                .filter(|scope| {
                    resource
                        .oauth2_permission_scopes
                        .iter()
                        .any(|published| published.value.as_deref() == Some(scope.as_str()))
                })
                .all(|scope| consented.contains(scope))
        })
}

/// The name of the cookie that carries the browser session.
const SESSION_COOKIE: &str = "entra_sim_session";

fn session_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(';'))
        .filter_map(|pair| pair.trim().split_once('='))
        .find(|(name, _)| *name == SESSION_COOKIE)
        .map(|(_, value)| value.to_string())
}

/// `SameSite=None` because the cookie has to travel with a request from the client's own site,
/// such as a hidden iframe doing `prompt=none`.
fn session_cookie_header(value: &str, max_age_seconds: i64) -> String {
    format!(
        "{SESSION_COOKIE}={value}; Path=/; Max-Age={max_age_seconds}; HttpOnly; Secure; \
         SameSite=None"
    )
}

#[derive(Debug, Deserialize)]
pub struct SignInForm {
    user_id: String,
    #[serde(flatten)]
    request: AuthorizeRequest,
}

async fn complete_sign_in(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    Form(form): Form<SignInForm>,
) -> Result<Response, Refusal> {
    let request = form.request;
    let directory = state.store.read().await;
    let validated = validate(&state, &directory, &request)?;

    if !directory.users.contains_key(&form.user_id) {
        return Err(unredirectable(
            "The selected user is no longer in the directory.".to_string(),
        ));
    }
    drop(directory);

    Ok(issue_code(&state, &tenant, &request, &validated, &form.user_id, true).await)
}

/// What validating an authorization request established.
/// Where the authorization response is placed in the redirect URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ResponseMode {
    /// In the query string. Entra's default for the code flow.
    Query,
    /// After a `#`. The only mode msal-browser uses.
    Fragment,
    /// In a form the browser posts to the redirect URI, for server-side web apps.
    FormPost,
}

pub(crate) struct Validated {
    pub(crate) client_id: String,
    /// Object ID of the client's service principal.
    pub(crate) client_principal_id: String,
    pub(crate) client_display_name: String,
    pub(crate) redirect_uri: String,
    /// The APIs the client asked for permissions on, in the order it named them. Graph when it
    /// named none.
    pub(crate) resources: Vec<RequestedResource>,
    /// The OpenID Connect scopes the client asked for.
    pub(crate) oidc: Vec<String>,
    pub(crate) response_mode: ResponseMode,
}

fn validate(
    state: &AppState,
    directory: &Directory,
    request: &AuthorizeRequest,
) -> Result<Validated, Refusal> {
    let client_id = request
        .client_id
        .as_deref()
        .ok_or_else(|| Unredirectable("The request is missing 'client_id'.".to_string()))?;

    let application = directory.application_by_app_id(client_id).ok_or_else(|| {
        Unredirectable(format!(
            "AADSTS700016: Application with identifier {client_id:?} was not found in the \
             directory."
        ))
    })?;
    let principal = directory
        .service_principal_by_app_id(client_id)
        .ok_or_else(|| {
            Unredirectable(format!(
                "AADSTS650052: The application {client_id:?} has no service principal in this \
                 directory."
            ))
        })?;

    let redirect_uri = request
        .redirect_uri
        .as_deref()
        .ok_or_else(|| Unredirectable("The request is missing 'redirect_uri'.".to_string()))?;

    // Entra requires an exact match against a registered URI. Anything looser would let a
    // client be used to redirect a code to a destination its owner never approved.
    let registered = registered_redirect_uris(application);
    if !registered.iter().any(|uri| uri == redirect_uri) {
        return Err(unredirectable(format!(
            "AADSTS50011: The redirect URI {redirect_uri:?} specified in the request does not \
             match the redirect URIs configured for the application. Registered: {registered:?}."
        )));
    }

    // Only the code flow is supported, and the implicit flows are deliberately absent rather
    // than half-implemented.
    match request.response_type.as_deref() {
        Some("code") => {}
        Some(other) => {
            return Err(unredirectable(format!(
                "AADSTS70005: The response_type {other:?} is not supported; this simulator \
                 implements the authorization code flow only."
            )));
        }
        None => {
            return Err(unredirectable(
                "The request is missing 'response_type'.".to_string(),
            ));
        }
    }

    // `fragment` is not optional to support: it is the only mode msal-browser will use, by
    // deliberate design, because a fragment is never sent to a server.
    let response_mode = match request.response_mode.as_deref() {
        // Entra's default for the code flow.
        None | Some("query") => ResponseMode::Query,
        Some("fragment") => ResponseMode::Fragment,
        Some("form_post") => ResponseMode::FormPost,
        Some(other) => {
            return Err(unredirectable(format!(
                "The response_mode {other:?} is not supported; use 'query', 'fragment' or \
                 'form_post'."
            )));
        }
    };

    if let Some(method) = request.code_challenge_method.as_deref()
        && !matches!(method, "S256" | "plain")
    {
        return Err(unredirectable(format!(
            "The code_challenge_method {method:?} is not supported; use 'S256' or 'plain'."
        )));
    }

    let scope = request.scope.as_deref().unwrap_or_default();
    let (resources, oidc) = resolve_scope(state, directory, scope).map_err(|unknown| {
        // The client and redirect URI are genuine by now, so the error goes back to the
        // client, as Entra's `invalid_resource` does.
        redirect_error(
            redirect_uri,
            response_mode,
            request.state.as_deref(),
            "invalid_resource",
            &format!(
                "AADSTS500011: The resource principal named {unknown} was not found in the \
                 tenant named {}.",
                state.config.tenant_id
            ),
        )
    })?;

    Ok(Validated {
        client_id: client_id.to_string(),
        client_principal_id: principal.id.clone(),
        client_display_name: application.display_name.clone(),
        redirect_uri: redirect_uri.to_string(),
        resources,
        oidc,
        response_mode,
    })
}

/// The APIs a scope parameter names, Graph when it names none, and its OpenID Connect scopes. An
/// API that is not in the directory is returned as the error.
pub(crate) fn resolve_scope(
    state: &AppState,
    directory: &Directory,
    scope: &str,
) -> Result<(Vec<RequestedResource>, Vec<String>), String> {
    let (oidc, named) = scopes::parse(scope);
    let mut resources = scopes::resolve(directory, &state.config.public_base_url(), &named)?;
    if resources.is_empty()
        && let Some(graph) = directory.graph_service_principal()
    {
        // A sign-in that names no API still yields an access token, for Microsoft Graph.
        resources.push(RequestedResource {
            principal_id: graph.id.clone(),
            app_id: graph.app_id.clone(),
            requested_as: None,
            values: Vec::new(),
        });
    }
    Ok((resources, oidc))
}

/// Every redirect URI registered on the application, across the three client kinds.
///
/// They live under `web`, `spa` and `publicClient`, which the simulator keeps verbatim rather
/// than modelling, so they are read back out of there.
fn registered_redirect_uris(application: &crate::store::model::Application) -> Vec<String> {
    ["web", "spa", "publicClient"]
        .iter()
        .filter_map(|kind| application.extra.get(*kind))
        .filter_map(|block| block.get("redirectUris"))
        .filter_map(|uris| uris.as_array())
        .flatten()
        .filter_map(|uri| uri.as_str())
        .map(str::to_string)
        .collect()
}

/// Record consent, mint a code, and redirect the user agent back to the client.
async fn issue_code(
    state: &AppState,
    tenant: &str,
    request: &AuthorizeRequest,
    validated: &Validated,
    user_id: &str,
    start_session: bool,
) -> Response {
    let now = OffsetDateTime::now_utc();
    if let Some(refused) = unassigned(state, validated, user_id).await {
        return refused;
    }
    consent(state, validated, user_id).await;

    let code = Uuid::new_v4().simple().to_string();
    {
        let mut sessions = state.sessions.lock().await;
        sessions.evict_expired(now);
        sessions.store_code(
            code.clone(),
            AuthorizationCode {
                client_id: validated.client_id.clone(),
                redirect_uri: validated.redirect_uri.clone(),
                user_id: user_id.to_string(),
                scope: request.scope.clone().unwrap_or_default(),
                nonce: request.nonce.clone(),
                code_challenge: request.code_challenge.clone(),
                code_challenge_method: request.code_challenge_method.clone(),
                expires_at: code_expiry(now),
            },
        );
    }
    info!(
        client_id = %validated.client_id,
        user_id = %user_id,
        redirect_uri = %validated.redirect_uri,
        scope = %request.scope.as_deref().unwrap_or_default(),
        "issued an authorization code"
    );

    let _ = tenant;
    let mut parameters = vec![("code", code.as_str())];
    // `state` is echoed verbatim; a client uses it to defend against request forgery.
    if let Some(value) = &request.state {
        parameters.push(("state", value.as_str()));
    }

    let mut response = respond(
        &validated.redirect_uri,
        validated.response_mode,
        &parameters,
    );
    if start_session {
        let id = state
            .sessions
            .lock()
            .await
            .start_browser_session(user_id, now);
        if let Ok(cookie) = header::HeaderValue::from_str(&session_cookie_header(&id, 86_400)) {
            response.headers_mut().append(header::SET_COOKIE, cookie);
        }
    }
    response
}

/// Return the authorization response to the client in the requested mode.
fn respond(redirect_uri: &str, mode: ResponseMode, parameters: &[(&str, &str)]) -> Response {
    if mode == ResponseMode::FormPost {
        return form_post(redirect_uri, parameters);
    }
    let encoded = parameters
        .iter()
        .map(|(name, value)| format!("{name}={}", urlencode(value)))
        .collect::<Vec<_>>()
        .join("&");
    found(&redirect_target(redirect_uri, mode, &encoded))
}

/// A page that posts the parameters to the redirect URI as soon as it loads.
///
/// Microsoft: `form_post` "Executes a POST containing the code to your redirect URI." Entra does
/// it with a self-submitting form, with a button for when scripts are off, and so does this.
fn form_post(redirect_uri: &str, parameters: &[(&str, &str)]) -> Response {
    let fields: String = parameters
        .iter()
        .map(|(name, value)| {
            format!(
                "<input type=\"hidden\" name=\"{}\" value=\"{}\" />",
                escape(name),
                escape(value)
            )
        })
        .collect();
    let body = format!(
        "<html><head><title>Working...</title></head><body>\
         <form method=\"POST\" name=\"hiddenform\" action=\"{}\">{fields}\
         <noscript><p>Script is disabled. Click Submit to continue.</p>\
         <input type=\"submit\" value=\"Submit\" /></noscript></form>\
         <script>document.forms[0].submit();</script></body></html>",
        escape(redirect_uri)
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
        body,
    )
        .into_response()
}

/// Place the response parameters on the redirect URI, in the requested mode.
///
/// A registered redirect URI may already carry a query string, so query mode appends with `&`
/// rather than assuming it can start one.
fn redirect_target(redirect_uri: &str, mode: ResponseMode, parameters: &str) -> String {
    match mode {
        ResponseMode::Fragment => format!("{redirect_uri}#{parameters}"),
        // A form post carries nothing in the URL; `respond` builds the form instead.
        ResponseMode::FormPost => redirect_uri.to_string(),
        ResponseMode::Query => {
            let separator = if redirect_uri.contains('?') { "&" } else { "?" };
            format!("{redirect_uri}{separator}{parameters}")
        }
    }
}

/// Redirect with 302 Found.
///
/// axum's `Redirect::to` answers 303 See Other. Entra answers 302 here, and a client that
/// inspects the status rather than just following it should see what it would see in
/// production.
fn found(location: &str) -> Response {
    (
        StatusCode::FOUND,
        [(header::LOCATION, location.to_string())],
    )
        .into_response()
}

/// Refuse a user who is not assigned to the client app, or to an API the client asked for, when
/// that application requires assignment. Entra shows this on its sign-in page rather than
/// redirecting to the client.
pub(crate) async fn unassigned(
    state: &AppState,
    validated: &Validated,
    user_id: &str,
) -> Option<Response> {
    let directory = state.store.read().await;
    let applications = std::iter::once(validated.client_principal_id.as_str()).chain(
        validated
            .resources
            .iter()
            .map(|resource| resource.principal_id.as_str()),
    );
    for principal_id in applications {
        if directory.user_may_access(user_id, principal_id) {
            continue;
        }
        let principal = directory.service_principals.get(principal_id)?;
        return Some(
            Unredirectable(crate::auth::oauth_error::user_not_assigned_description(
                &principal.app_id,
                &principal.display_name,
            ))
            .into_response(),
        );
    }
    None
}

/// Record the user's consent as a permission grant on each API the client asked for.
///
/// Entra stores consent in the directory and derives the token's scopes from it, so the
/// simulator does the same: a client cannot widen its own token by asking for more scopes than
/// were consented, and an administrator revoking the grant narrows the next token.
pub(crate) async fn consent(state: &AppState, validated: &Validated, user_id: &str) {
    let mut directory = state.store.write().await;
    for requested in with_oidc_on_graph(&directory, validated) {
        consent_to(&mut directory, validated, &requested, user_id);
    }
}

/// The APIs a request names, with its OpenID Connect scopes added to Graph's permissions.
///
/// Microsoft: "openid, email, profile, and offline_access" are "well-defined scopes that are
/// also hosted on Microsoft Graph", so consent to them is consent to Graph.
fn with_oidc_on_graph(directory: &Directory, validated: &Validated) -> Vec<RequestedResource> {
    let mut resources = validated.resources.clone();
    if validated.oidc.is_empty() {
        return resources;
    }
    match resources.iter_mut().find(|resource| resource.is_graph()) {
        Some(graph) => {
            for scope in &validated.oidc {
                if !graph.values.contains(scope) {
                    graph.values.push(scope.clone());
                }
            }
        }
        None => {
            if let Some(graph) = directory.graph_service_principal() {
                resources.push(RequestedResource {
                    principal_id: graph.id.clone(),
                    app_id: graph.app_id.clone(),
                    requested_as: None,
                    values: validated.oidc.clone(),
                });
            }
        }
    }
    resources
}

fn consent_to(
    directory: &mut Directory,
    validated: &Validated,
    requested: &RequestedResource,
    user_id: &str,
) {
    let Some(resource) = directory.service_principals.get(&requested.principal_id) else {
        return;
    };
    let resource_id = resource.id.clone();
    // Only permissions the resource actually publishes can be consented to.
    let published: Vec<String> = resource
        .oauth2_permission_scopes
        .iter()
        .filter_map(|scope| scope.value.clone())
        .collect();

    let existing = directory
        .oauth2_permission_grants
        .values()
        .find(|grant| {
            grant.client_id == validated.client_principal_id
                && grant.resource_id == resource_id
                && (grant.consent_type == "AllPrincipals"
                    || grant.principal_id.as_deref() == Some(user_id))
        })
        .cloned();

    // `/.default` asks for everything already consented and adds nothing new.
    if requested.wants_default() {
        return;
    }

    let newly_requested: Vec<String> = requested
        .named_scopes()
        .filter(|scope| published.iter().any(|known| known == *scope))
        .cloned()
        .collect();

    let mut scopes: Vec<String> = existing
        .as_ref()
        .map(|grant| grant.scope.split_whitespace().map(str::to_string).collect())
        .unwrap_or_default();
    for scope in newly_requested {
        if !scopes.contains(&scope) {
            scopes.push(scope);
        }
    }
    scopes.sort();

    match existing {
        Some(grant) => {
            if let Some(stored) = directory.oauth2_permission_grants.get_mut(&grant.id) {
                stored.scope = scopes.join(" ");
                info!(grant_id = %grant.id, scope = %stored.scope, "updated OAuth2 permission grant on consent");
            }
        }
        None => {
            let grant = OAuth2PermissionGrant {
                id: Uuid::new_v4().to_string(),
                client_id: validated.client_principal_id.clone(),
                // The user consented for themselves, not for the tenant.
                consent_type: "Principal".to_string(),
                principal_id: Some(user_id.to_string()),
                resource_id,
                scope: scopes.join(" "),
            };
            info!(
                grant_id = %grant.id,
                client_id = %grant.client_id,
                user_id = %user_id,
                scope = %grant.scope,
                "created OAuth2 permission grant on consent"
            );
            directory
                .oauth2_permission_grants
                .insert(grant.id.clone(), grant);
        }
    }
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    post_logout_redirect_uri: Option<String>,
}

/// Sign the browser out: end its session, so the next sign-in shows the page again.
async fn logout(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(request): Query<LogoutRequest>,
) -> Response {
    if let Some(id) = session_cookie(&headers) {
        state.sessions.lock().await.end_browser_session(&id);
    }
    info!("signed out");
    let mut response = match request.post_logout_redirect_uri {
        Some(uri) => found(&uri),
        None => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "text/html; charset=utf-8")],
            Html(page(
                "Signed out",
                "<p>You have been signed out of the simulated tenant.</p>",
            )),
        )
            .into_response(),
    };
    if let Ok(cookie) = header::HeaderValue::from_str(&session_cookie_header("", 0)) {
        response.headers_mut().append(header::SET_COOKIE, cookie);
    }
    response
}

/// The sign-in and consent page.
fn sign_in_page(
    request: &AuthorizeRequest,
    validated: &Validated,
    users: &[(String, String, String)],
) -> String {
    let mut body = format!(
        "<p><strong>{}</strong> is asking you to sign in to the simulated tenant.</p>",
        escape(&validated.client_display_name)
    );

    let permissions: Vec<String> = validated
        .resources
        .iter()
        .flat_map(|resource| resource.named_scopes().map(|scope| resource.qualify(scope)))
        .collect();
    if permissions.is_empty() {
        body.push_str("<p class=\"muted\">No additional permissions are requested.</p>");
    } else {
        body.push_str("<p>It is requesting these permissions:</p><ul class=\"scopes\">");
        for scope in &permissions {
            body.push_str(&format!("<li><code>{}</code></li>", escape(scope)));
        }
        body.push_str("</ul>");
    }

    if users.is_empty() {
        body.push_str(
            "<p class=\"error\">There are no users in this tenant to sign in as. Create one \
             through <code>POST /v1.0/users</code> first.</p>",
        );
        return page("Sign in", &body);
    }

    body.push_str("<form method=\"post\"><ul class=\"users\">");
    for (id, display_name, upn) in users {
        body.push_str(&format!(
            "<li><button type=\"submit\" name=\"user_id\" value=\"{}\">\
             <span class=\"name\">{}</span><span class=\"upn\">{}</span></button></li>",
            escape(id),
            escape(display_name),
            escape(upn)
        ));
    }
    body.push_str("</ul>");

    // The authorization request is carried through the form so the POST can revalidate it
    // rather than trust anything held server-side between the two requests.
    for (name, value) in [
        ("client_id", request.client_id.as_deref()),
        ("response_type", request.response_type.as_deref()),
        ("redirect_uri", request.redirect_uri.as_deref()),
        ("scope", request.scope.as_deref()),
        ("state", request.state.as_deref()),
        ("nonce", request.nonce.as_deref()),
        ("code_challenge", request.code_challenge.as_deref()),
        (
            "code_challenge_method",
            request.code_challenge_method.as_deref(),
        ),
        ("response_mode", request.response_mode.as_deref()),
    ] {
        if let Some(value) = value {
            body.push_str(&format!(
                "<input type=\"hidden\" name=\"{name}\" value=\"{}\">",
                escape(value)
            ));
        }
    }
    body.push_str("</form>");
    body.push_str(
        "<p class=\"muted\">Choosing a user records consent for the permissions above, the \
         same way an administrator's consent is recorded in a real tenant.</p>",
    );

    page("Sign in", &body)
}

/// Wrap body content in a self-contained page.
///
/// Everything is inline: the page has to render with no network access, since the simulator may
/// be the only thing reachable from wherever it is running.
pub(crate) fn page(title: &str, body: &str) -> String {
    format!(
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{title} · entra-sim</title><style>\
         :root{{color-scheme:light dark}}\
         body{{font:16px/1.5 system-ui,sans-serif;margin:0;padding:2rem;display:flex;\
         justify-content:center}}\
         main{{max-width:34rem;width:100%}}\
         h1{{font-size:1.25rem;margin:0 0 1rem}}\
         .users{{list-style:none;padding:0;margin:1rem 0;display:grid;gap:.5rem}}\
         .users button{{width:100%;text-align:left;padding:.75rem 1rem;font:inherit;\
         border:1px solid currentColor;border-radius:.5rem;background:transparent;\
         color:inherit;cursor:pointer;display:grid;gap:.125rem}}\
         .users button:hover{{border-width:2px;padding:calc(.75rem - 1px) calc(1rem - 1px)}}\
         .name{{font-weight:600}}\
         .upn,.muted{{opacity:.7;font-size:.875rem}}\
         .scopes{{margin:.5rem 0 1rem}}\
         .error{{color:#b3261e}}\
         @media(prefers-color-scheme:dark){{.error{{color:#f2b8b5}}}}\
         </style></head><body><main><h1>{title}</h1>{body}</main></body></html>"
    )
}

pub(crate) fn escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/// Percent-encode a query parameter value.
fn urlencode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// The Graph resource every delegated permission in this simulator belongs to.
pub fn graph_app_id() -> &'static str {
    MICROSOFT_GRAPH_APP_ID
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_in_a_client_supplied_value_is_escaped() {
        // Values here come straight from the query string, so the page must not reflect them.
        let escaped = escape("<script>alert('x')</script>");
        assert!(!escaped.contains('<'));
        assert!(!escaped.contains('>'));
        assert!(!escaped.contains('\''));
    }

    #[test]
    fn the_response_mode_decides_where_the_parameters_go() {
        // msal-browser reads the code from the fragment and nothing else.
        assert_eq!(
            redirect_target("https://app.test/cb", ResponseMode::Fragment, "code=abc"),
            "https://app.test/cb#code=abc"
        );
        assert_eq!(
            redirect_target("https://app.test/cb", ResponseMode::Query, "code=abc"),
            "https://app.test/cb?code=abc"
        );
        // A registered URI may already carry a query string.
        assert_eq!(
            redirect_target("https://app.test/cb?x=1", ResponseMode::Query, "code=abc"),
            "https://app.test/cb?x=1&code=abc"
        );
        // A fragment is appended whole, so an existing query string is left alone.
        assert_eq!(
            redirect_target(
                "https://app.test/cb?x=1",
                ResponseMode::Fragment,
                "code=abc"
            ),
            "https://app.test/cb?x=1#code=abc"
        );
    }

    #[test]
    fn query_values_are_percent_encoded() {
        assert_eq!(urlencode("a b&c=d"), "a%20b%26c%3Dd");
        assert_eq!(urlencode("safe-._~"), "safe-._~");
    }
}
