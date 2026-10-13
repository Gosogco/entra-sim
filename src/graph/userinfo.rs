//! The OpenID Connect UserInfo endpoint.
//!
//! Microsoft hosts it on Graph: "UserInfo is a standard OAuth bearer token API hosted by
//! Microsoft Graph", called "by using the access token your application received when it
//! requested access to Microsoft Graph", at `/oidc/userinfo` with GET or POST. It returns "the
//! name claims, subject claim, and email when available and consented to".

use axum::Json;
use axum::extract::State;
use serde_json::{Map, Value, json};

use crate::auth::middleware::Caller;
use crate::graph::error::GraphError;
use crate::state::AppState;

pub async fn userinfo(
    State(state): State<AppState>,
    caller: Caller,
) -> Result<Json<Value>, GraphError> {
    let scopes: Vec<&str> = caller
        .claims
        .scp
        .as_deref()
        .unwrap_or_default()
        .split(' ')
        .collect();
    // "The openid claim is required"; an app-only token has no scopes and no user at all.
    if !scopes.contains(&"openid") {
        return Err(GraphError::authorization_request_denied());
    }

    let directory = state.store.read().await;
    let user = directory
        .users
        .get(&caller.claims.oid)
        .ok_or_else(|| GraphError::resource_not_found(&caller.claims.oid))?;

    let mut body = Map::new();
    body.insert("sub".to_string(), json!(caller.claims.sub));
    // "all names require the profile scope", and email "requires the email scope".
    if scopes.contains(&"profile") {
        body.insert("name".to_string(), json!(user.display_name));
        if let Some(surname) = &user.surname {
            body.insert("family_name".to_string(), json!(surname));
        }
        if let Some(given_name) = &user.given_name {
            body.insert("given_name".to_string(), json!(given_name));
        }
        body.insert(
            "picture".to_string(),
            json!(format!(
                "{}/v1.0/me/photo/$value",
                state.config.public_base_url()
            )),
        );
    }
    if scopes.contains(&"email")
        && let Some(mail) = &user.mail
    {
        body.insert("email".to_string(), json!(mail));
    }
    Ok(Json(Value::Object(body)))
}
