//! The authorization endpoint and its sign-in page.
//!
//! The page stands in for Entra's sign-in and consent experience: it lists the tenant's users
//! and the permissions the client is asking for, and submitting it both chooses a user and
//! records consent as a real `oauth2PermissionGrant`. Recording consent properly matters because
//! the delegated token's `scp` claim is then derived from the directory, the same way Entra
//! derives it, rather than from whatever the client happened to ask for.

use axum::Router;
use axum::extract::{Form, Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::auth::sessions::{AuthorizationCode, code_expiry};
use crate::state::AppState;
use crate::store::Directory;
use crate::store::model::{MICROSOFT_GRAPH_APP_ID, OAuth2PermissionGrant};

/// Scopes OpenID Connect defines, which are not permissions on a resource.
const OIDC_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

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
    /// `login` forces the picker even when a user is configured for automatic sign-in.
    pub prompt: Option<String>,
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
    Query(request): Query<AuthorizeRequest>,
) -> Result<Response, Unredirectable> {
    let directory = state.store.read().await;
    let validated = validate(&state, &directory, &request)?;

    // `prompt=login` is a client asking to see the picker regardless.
    let forced = request.prompt.as_deref() == Some("login");
    if let Some(upn) = state.config.auto_sign_in_user.as_deref()
        && !forced
    {
        let user = directory
            .user_by_principal_name(upn)
            .ok_or_else(|| {
                Unredirectable(format!(
                    "The configured automatic sign-in user {upn:?} is not in the directory."
                ))
            })?
            .id
            .clone();
        drop(directory);
        return Ok(issue_code(&state, &tenant, &request, &validated, &user)
            .await
            .into_response());
    }

    let users: Vec<(String, String, String)> = directory
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

    Ok(Html(sign_in_page(&request, &validated, &users)).into_response())
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
) -> Result<Response, Unredirectable> {
    let request = form.request;
    let directory = state.store.read().await;
    let validated = validate(&state, &directory, &request)?;

    if !directory.users.contains_key(&form.user_id) {
        return Err(Unredirectable(
            "The selected user is no longer in the directory.".to_string(),
        ));
    }
    drop(directory);

    Ok(
        issue_code(&state, &tenant, &request, &validated, &form.user_id)
            .await
            .into_response(),
    )
}

/// What validating an authorization request established.
/// Where the authorization response is placed in the redirect URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ResponseMode {
    /// In the query string. Entra's default for the code flow.
    Query,
    /// After a `#`. The only mode msal-browser uses.
    Fragment,
}

struct Validated {
    client_id: String,
    /// Object ID of the client's service principal.
    client_principal_id: String,
    client_display_name: String,
    redirect_uri: String,
    /// Resource scopes the client asked for, without the OpenID Connect ones.
    requested_resource_scopes: Vec<String>,
    /// Whether the client asked for every already-consented permission.
    wants_default: bool,
    /// Whether the client asked for a refresh token.
    offline_access: bool,
    response_mode: ResponseMode,
}

fn validate(
    state: &AppState,
    directory: &Directory,
    request: &AuthorizeRequest,
) -> Result<Validated, Unredirectable> {
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
        return Err(Unredirectable(format!(
            "AADSTS50011: The redirect URI {redirect_uri:?} specified in the request does not \
             match the redirect URIs configured for the application. Registered: {registered:?}."
        )));
    }

    // Only the code flow is supported, and the implicit flows are deliberately absent rather
    // than half-implemented.
    match request.response_type.as_deref() {
        Some("code") => {}
        Some(other) => {
            return Err(Unredirectable(format!(
                "AADSTS70005: The response_type {other:?} is not supported; this simulator \
                 implements the authorization code flow only."
            )));
        }
        None => {
            return Err(Unredirectable(
                "The request is missing 'response_type'.".to_string(),
            ));
        }
    }

    // `fragment` is not optional to support: it is the only mode msal-browser will use, by
    // deliberate design, because a fragment is never sent to a server. `form_post` is left out
    // rather than half-implemented.
    let response_mode = match request.response_mode.as_deref() {
        // Entra's default for the code flow.
        None | Some("query") => ResponseMode::Query,
        Some("fragment") => ResponseMode::Fragment,
        Some(other) => {
            return Err(Unredirectable(format!(
                "The response_mode {other:?} is not supported; use 'query' or 'fragment'."
            )));
        }
    };

    if let Some(method) = request.code_challenge_method.as_deref()
        && !matches!(method, "S256" | "plain")
    {
        return Err(Unredirectable(format!(
            "The code_challenge_method {method:?} is not supported; use 'S256' or 'plain'."
        )));
    }

    let requested: Vec<&str> = request
        .scope
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .collect();
    let resource_prefix = format!("{}/", state.config.public_base_url());
    let wants_default = requested
        .iter()
        .any(|scope| scope.ends_with("/.default") || *scope == ".default");

    let requested_resource_scopes = requested
        .iter()
        .filter(|scope| !OIDC_SCOPES.contains(*scope))
        .filter(|scope| !scope.ends_with("/.default") && **scope != ".default")
        // A scope may be written bare or qualified by the resource it belongs to.
        .map(|scope| {
            scope
                .strip_prefix(&resource_prefix)
                .unwrap_or(scope)
                .to_string()
        })
        .collect();

    Ok(Validated {
        client_id: client_id.to_string(),
        client_principal_id: principal.id.clone(),
        client_display_name: application.display_name.clone(),
        redirect_uri: redirect_uri.to_string(),
        requested_resource_scopes,
        wants_default,
        offline_access: requested.contains(&"offline_access"),
        response_mode,
    })
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
) -> Response {
    let now = OffsetDateTime::now_utc();
    let granted = consent(state, validated, user_id).await;

    let mut scope = granted;
    if validated.offline_access {
        // Recorded on the code so the exchange knows whether to issue a refresh token.
        scope.push("offline_access".to_string());
    }

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
                scope: scope.join(" "),
                nonce: request.nonce.clone(),
                code_challenge: request.code_challenge.clone(),
                code_challenge_method: request.code_challenge_method.clone(),
                expires_at: code_expiry(now),
            },
        );
    }

    let _ = tenant;
    let mut parameters = format!("code={}", urlencode(&code));
    // `state` is echoed verbatim; a client uses it to defend against request forgery.
    if let Some(value) = &request.state {
        parameters.push_str(&format!("&state={}", urlencode(value)));
    }

    found(&redirect_target(
        &validated.redirect_uri,
        validated.response_mode,
        &parameters,
    ))
}

/// Place the response parameters on the redirect URI, in the requested mode.
///
/// A registered redirect URI may already carry a query string, so query mode appends with `&`
/// rather than assuming it can start one.
fn redirect_target(redirect_uri: &str, mode: ResponseMode, parameters: &str) -> String {
    match mode {
        ResponseMode::Fragment => format!("{redirect_uri}#{parameters}"),
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

/// Record the user's consent as a permission grant, and return what is now consented.
///
/// Entra stores consent in the directory and derives the token's scopes from it, so the
/// simulator does the same: a client cannot widen its own token by asking for more scopes than
/// were consented, and an administrator revoking the grant narrows the next token.
async fn consent(state: &AppState, validated: &Validated, user_id: &str) -> Vec<String> {
    let mut directory = state.store.write().await;

    let Some(resource) = directory.graph_service_principal() else {
        return Vec::new();
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
    if validated.wants_default {
        return existing
            .map(|grant| grant.scope.split_whitespace().map(str::to_string).collect())
            .unwrap_or_default();
    }

    let newly_requested: Vec<String> = validated
        .requested_resource_scopes
        .iter()
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
            directory
                .oauth2_permission_grants
                .insert(grant.id.clone(), grant);
        }
    }

    scopes
}

#[derive(Debug, Deserialize)]
struct LogoutRequest {
    post_logout_redirect_uri: Option<String>,
}

/// The simulator keeps no browser session, so signing out is only the redirect.
async fn logout(Query(request): Query<LogoutRequest>) -> Response {
    match request.post_logout_redirect_uri {
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
    }
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

    if validated.requested_resource_scopes.is_empty() {
        body.push_str("<p class=\"muted\">No additional permissions are requested.</p>");
    } else {
        body.push_str("<p>It is requesting these permissions:</p><ul class=\"scopes\">");
        for scope in &validated.requested_resource_scopes {
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
fn page(title: &str, body: &str) -> String {
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

fn escape(value: &str) -> String {
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

/// Exposed so the token endpoint shares the same notion of an OpenID Connect scope.
pub fn is_oidc_scope(scope: &str) -> bool {
    OIDC_SCOPES.contains(&scope)
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
