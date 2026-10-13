//! The device authorization grant: a device that cannot show a browser gets a short code, and the
//! user signs in on another device by typing it in.
//!
//! The shape follows Microsoft's device authorization documentation: `POST
//! /{tenant}/oauth2/v2.0/devicecode` answers with `device_code`, `user_code`,
//! `verification_uri`, `expires_in`, `interval` and `message`, and the device then polls the token
//! endpoint. The verification page is the simulator's own, at `/devicelogin`.

use axum::extract::{Form, Path, State};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use rand::Rng;
use serde::{Deserialize, Serialize};
use time::{Duration, OffsetDateTime};
use tracing::info;

use crate::auth::authorize::{
    ResponseMode, Validated, consent, escape, page, resolve_scope, unassigned,
};
use crate::auth::conditional_access;
use crate::auth::oauth_error::{self, OAuthFailure};
use crate::auth::sessions::{DeviceAuthorization, DeviceStatus};
use crate::state::AppState;

/// Microsoft: "From the moment the request is sent, the user has 15 minutes to sign in. This is
/// the default value for `expires_in`."
const EXPIRES_IN_SECONDS: i64 = 900;
/// How long the device should wait between polls.
const INTERVAL_SECONDS: u64 = 5;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/{tenant}/oauth2/v2.0/devicecode", post(device_code))
        .route("/devicelogin", get(enter_code).post(verify))
}

#[derive(Debug, Deserialize)]
struct DeviceCodeRequest {
    client_id: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Serialize)]
struct DeviceCodeResponse {
    device_code: String,
    user_code: String,
    verification_uri: String,
    expires_in: i64,
    interval: u64,
    message: String,
}

async fn device_code(
    State(state): State<AppState>,
    Path(tenant): Path<String>,
    Form(request): Form<DeviceCodeRequest>,
) -> Result<Json<DeviceCodeResponse>, OAuthFailure> {
    let named_tenant = tenant;
    let tenant = state.config.resolve_tenant(&named_tenant);
    if tenant != state.config.tenant_id {
        return Err(oauth_error::invalid_tenant(&named_tenant));
    }
    let client_id = request.client_id.ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'client_id'.",
        )
    })?;
    let scope = request.scope.ok_or_else(|| {
        oauth_error::invalid_request(
            "AADSTS900144: The request body must contain the following parameter: 'scope'.",
        )
    })?;
    {
        let directory = state.store.read().await;
        if directory.application_by_app_id(&client_id).is_none() {
            return Err(oauth_error::unknown_client(&client_id));
        }
        resolve_scope(&state, &directory, &scope)
            .map_err(|unknown| oauth_error::invalid_resource(&unknown, &tenant))?;
    }

    let now = OffsetDateTime::now_utc();
    let device_code = format!(
        "{}{}",
        uuid::Uuid::new_v4().simple(),
        uuid::Uuid::new_v4().simple()
    );
    let user_code = new_user_code();
    let verification_uri = format!("{}/devicelogin", state.config.public_base_url());
    {
        let mut sessions = state.sessions.lock().await;
        sessions.evict_expired(now);
        sessions.store_device_authorization(
            device_code.clone(),
            DeviceAuthorization {
                tenant_id: tenant.clone(),
                client_id: client_id.clone(),
                scope,
                user_code: user_code.clone(),
                expires_at: now + Duration::seconds(EXPIRES_IN_SECONDS),
                status: DeviceStatus::Pending,
            },
        );
    }
    info!(client_id = %client_id, user_code = %user_code, "started a device code sign-in");

    Ok(Json(DeviceCodeResponse {
        message: format!(
            "To sign in, use a web browser to open the page {verification_uri} and enter the \
             code {user_code} to authenticate."
        ),
        device_code,
        user_code,
        verification_uri,
        expires_in: EXPIRES_IN_SECONDS,
        interval: INTERVAL_SECONDS,
    }))
}

/// Nine characters from a set without look-alikes, which is easy to read off one screen and type
/// into another.
fn new_user_code() -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
    let mut rng = rand::thread_rng();
    (0..9)
        .map(|_| ALPHABET[rng.gen_range(0..ALPHABET.len())] as char)
        .collect()
}

async fn enter_code() -> Html<String> {
    Html(page("Enter code", &code_form("")))
}

fn code_form(message: &str) -> String {
    format!(
        "{message}<p>Enter the code shown on your device.</p>\
         <form method=\"post\"><p><input name=\"user_code\" autocomplete=\"off\" \
         autofocus required></p><p><button type=\"submit\">Next</button></p></form>"
    )
}

#[derive(Debug, Deserialize)]
struct VerifyForm {
    user_code: String,
    user_id: Option<String>,
    decline: Option<String>,
    /// Present when the user completed the multifactor step.
    mfa: Option<String>,
}

/// The verification page: check the code, then let the user choose who to sign in as, or
/// decline.
async fn verify(State(state): State<AppState>, Form(form): Form<VerifyForm>) -> Response {
    let now = OffsetDateTime::now_utc();
    let device_code = state
        .sessions
        .lock()
        .await
        .pending_device_code(form.user_code.trim(), now);
    let Some(device_code) = device_code else {
        return Html(page(
            "Enter code",
            &code_form(
                "<p class=\"error\">AADSTS70018: That code wasn't recognised, or it has \
                 expired. Check the code on your device and try again.</p>",
            ),
        ))
        .into_response();
    };
    let details = state
        .sessions
        .lock()
        .await
        .device_authorization(&device_code)
        .cloned()
        .expect("found a moment ago");

    if form.decline.is_some() {
        state
            .sessions
            .lock()
            .await
            .set_device_status(&device_code, DeviceStatus::Declined);
        info!(client_id = %details.client_id, "declined a device code sign-in");
        return Html(page(
            "Declined",
            "<p>You declined the sign-in. You can close this window.</p>",
        ))
        .into_response();
    }

    let validated = {
        let directory = state.store.read().await;
        let Some(application) = directory.application_by_app_id(&details.client_id) else {
            return error_page("The application is no longer in the directory.");
        };
        let Some(principal) = directory.service_principal_by_app_id(&details.client_id) else {
            return error_page("The application has no service principal in this directory.");
        };
        let Ok((resources, oidc)) = resolve_scope(&state, &directory, &details.scope) else {
            return error_page("An API the device asked for is no longer in the directory.");
        };
        Validated {
            client_id: details.client_id.clone(),
            client_principal_id: principal.id.clone(),
            client_display_name: application.display_name.clone(),
            redirect_uri: String::new(),
            resources,
            oidc,
            response_mode: ResponseMode::Query,
        }
    };

    let Some(user_id) = form.user_id else {
        return Html(choose_user_page(&state, &validated, &form.user_code).await).into_response();
    };
    if !state.store.read().await.users.contains_key(&user_id) {
        return error_page("The selected user is no longer in the directory.");
    }
    if let Some(refused) = unassigned(&state, &validated, &user_id).await {
        return refused;
    }
    let mfa = form.mfa.is_some();
    let decision = {
        let directory = state.store.read().await;
        let user = directory.users.get(&user_id).expect("checked a moment ago");
        let resources: Vec<String> = validated
            .resources
            .iter()
            .map(|resource| resource.app_id.clone())
            .collect();
        conditional_access::evaluate(
            &directory,
            &conditional_access::Access {
                user,
                client_app_id: &validated.client_id,
                resource_app_ids: &resources,
                client_app_type: conditional_access::ClientAppType::MobileAppsAndDesktopClients,
                mfa,
            },
        )
    };
    match decision {
        conditional_access::Decision::Allow => {}
        conditional_access::Decision::Block { code, description } => {
            return error_page(&format!("AADSTS{code}: {description}"));
        }
        conditional_access::Decision::RequireMfa => {
            return Html(page(
                "Approve sign-in",
                &format!(
                    "<p>Your organization requires more verification to sign in to \
                     <strong>{}</strong>.</p><form method=\"post\">\
                     <input type=\"hidden\" name=\"user_code\" value=\"{}\">\
                     <input type=\"hidden\" name=\"user_id\" value=\"{}\">\
                     <input type=\"hidden\" name=\"mfa\" value=\"1\">\
                     <p><button type=\"submit\">Approve sign-in</button></p></form>",
                    escape(&validated.client_display_name),
                    escape(&form.user_code),
                    escape(&user_id)
                ),
            ))
            .into_response();
        }
    }
    consent(&state, &validated, &user_id, false).await;
    state
        .sessions
        .lock()
        .await
        .set_device_status(&device_code, DeviceStatus::Approved { user_id, mfa });
    info!(client_id = %details.client_id, "approved a device code sign-in");
    Html(page(
        "Signed in",
        &format!(
            "<p>You have signed in to <strong>{}</strong> on your device. You can close this \
             window.</p>",
            escape(&validated.client_display_name)
        ),
    ))
    .into_response()
}

async fn choose_user_page(state: &AppState, validated: &Validated, user_code: &str) -> String {
    let directory = state.store.read().await;
    let mut body = format!(
        "<p><strong>{}</strong> on another device is asking you to sign in to the simulated \
         tenant.</p>",
        escape(&validated.client_display_name)
    );
    let permissions: Vec<String> = validated
        .resources
        .iter()
        .flat_map(|resource| resource.named_scopes().map(|scope| resource.qualify(scope)))
        .collect();
    if !permissions.is_empty() {
        body.push_str("<p>It is requesting these permissions:</p><ul class=\"scopes\">");
        for scope in &permissions {
            body.push_str(&format!("<li><code>{}</code></li>", escape(scope)));
        }
        body.push_str("</ul>");
    }
    body.push_str("<form method=\"post\"><ul class=\"users\">");
    for user in directory.users.values() {
        body.push_str(&format!(
            "<li><button type=\"submit\" name=\"user_id\" value=\"{}\">\
             <span class=\"name\">{}</span><span class=\"upn\">{}</span></button></li>",
            escape(&user.id),
            escape(&user.display_name),
            escape(&user.user_principal_name)
        ));
    }
    body.push_str(&format!(
        "</ul><input type=\"hidden\" name=\"user_code\" value=\"{}\">\
         <p><button type=\"submit\" name=\"decline\" value=\"1\">Decline</button></p></form>",
        escape(user_code)
    ));
    page("Sign in", &body)
}

fn error_page(message: &str) -> Response {
    (
        axum::http::StatusCode::BAD_REQUEST,
        Html(page(
            "Sign-in error",
            &format!("<p class=\"error\">{}</p>", escape(message)),
        )),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_codes_avoid_look_alike_characters() {
        for _ in 0..100 {
            let code = new_user_code();
            assert_eq!(code.len(), 9);
            assert!(!code.contains(['0', 'O', '1', 'I']), "{code}");
        }
    }
}
