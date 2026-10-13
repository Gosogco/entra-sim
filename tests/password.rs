//! Tests for the resource owner password credentials grant.

mod common;

use common::{Graph, Sim};
use serde_json::{Value, json};

const PASSWORD: &str = "Sup3rSecret!";

/// A public client with public client flows allowed, and bob, who consented to User.Read through
/// it already.
async fn fixture(sim: &Sim) -> (Graph, common::Client, String) {
    let graph = sim.graph().await;
    let client = graph
        .register_public_client("Script", json!({ "isFallbackPublicClient": true }))
        .await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    sim.sign_in_ok(&client.app_id, &bob, "openid User.Read")
        .await;
    (graph, client, bob)
}

async fn ropc(sim: &Sim, tenant: &str, form: &[(&str, &str)]) -> reqwest::Response {
    sim.client
        .post(sim.url(&format!("/{tenant}/oauth2/v2.0/token")))
        .form(form)
        .send()
        .await
        .unwrap()
}

async fn error_code(response: reqwest::Response) -> (u16, String, u64) {
    let status = response.status().as_u16();
    let body: Value = response.json().await.unwrap();
    (
        status,
        body["error"].as_str().unwrap().to_string(),
        body["error_codes"][0].as_u64().unwrap(),
    )
}

#[tokio::test]
async fn the_right_password_gets_tokens() {
    let sim = Sim::start().await;
    let (_, client, bob) = fixture(&sim).await;

    let response = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "openid offline_access User.Read"),
        ],
    )
    .await;
    assert_eq!(response.status(), 200);
    let tokens: Value = response.json().await.unwrap();
    assert!(tokens["id_token"].is_string());
    assert!(tokens["refresh_token"].is_string());
    let claims = common::decode_claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(claims["oid"], bob.as_str());
}

#[tokio::test]
async fn a_wrong_password_is_invalid_grant() {
    let sim = Sim::start().await;
    let (_, client, _) = fixture(&sim).await;

    for (username, password) in [("bob@sim.test", "wrong"), ("nobody@sim.test", PASSWORD)] {
        let response = ropc(
            &sim,
            &sim.tenant_id,
            &[
                ("grant_type", "password"),
                ("client_id", &client.app_id),
                ("username", username),
                ("password", password),
                ("scope", "User.Read"),
            ],
        )
        .await;
        assert_eq!(
            error_code(response).await,
            (400, "invalid_grant".to_string(), 50126)
        );
    }
}

#[tokio::test]
async fn a_user_without_a_password_cannot_sign_in() {
    let sim = Sim::start().await;
    let (graph, client, _) = fixture(&sim).await;
    graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "No Password",
                "userPrincipalName": "nopassword@sim.test",
                "mailNickname": "nopassword",
                "accountEnabled": true
            }),
        )
        .await;

    let response = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("username", "nopassword@sim.test"),
            ("password", ""),
            ("scope", "User.Read"),
        ],
    )
    .await;
    assert_eq!(error_code(response).await.2, 50126);
}

#[tokio::test]
async fn a_scope_without_consent_needs_consent() {
    let sim = Sim::start().await;
    let (_, client, _) = fixture(&sim).await;

    let response = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "Mail.Read"),
        ],
    )
    .await;
    // "If the scopes aren't granted, a consent_required error will be returned."
    assert_eq!(error_code(response).await.1, "consent_required");
}

#[tokio::test]
async fn common_and_consumers_are_refused_but_organizations_is_not() {
    let sim = Sim::start().await;
    let (_, client, _) = fixture(&sim).await;
    let form = [
        ("grant_type", "password"),
        ("client_id", client.app_id.as_str()),
        ("username", "bob@sim.test"),
        ("password", PASSWORD),
        ("scope", "User.Read"),
    ];

    for tenant in ["common", "consumers"] {
        let response = ropc(&sim, tenant, &form).await;
        assert_eq!(error_code(response).await.1, "invalid_request", "{tenant}");
    }
    assert_eq!(ropc(&sim, "organizations", &form).await.status(), 200);
}

#[tokio::test]
async fn a_public_client_must_not_send_a_secret() {
    let sim = Sim::start().await;
    let (_, client, _) = fixture(&sim).await;

    let response = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("client_secret", &client.secret),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "User.Read"),
        ],
    )
    .await;
    assert_eq!(
        error_code(response).await,
        (401, "invalid_client".to_string(), 700025)
    );
}

#[tokio::test]
async fn a_confidential_client_must_send_its_secret() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    // No isFallbackPublicClient, so Entra treats it as confidential.
    let client = graph.register_public_client("Web app", json!({})).await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    sim.sign_in_ok(&client.app_id, &bob, "openid User.Read")
        .await;

    let without = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "User.Read"),
        ],
    )
    .await;
    assert_eq!(error_code(without).await.2, 7000218);

    let with = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("client_secret", &client.secret),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "User.Read"),
        ],
    )
    .await;
    assert_eq!(with.status(), 200);
}

#[tokio::test]
async fn a_disabled_account_cannot_sign_in() {
    let sim = Sim::start().await;
    let (graph, client, bob) = fixture(&sim).await;
    let disabled = graph
        .patch(
            &format!("/v1.0/users/{bob}"),
            &json!({ "accountEnabled": false }),
        )
        .await;
    assert_eq!(disabled.status(), 204);

    let response = ropc(
        &sim,
        &sim.tenant_id,
        &[
            ("grant_type", "password"),
            ("client_id", &client.app_id),
            ("username", "bob@sim.test"),
            ("password", PASSWORD),
            ("scope", "User.Read"),
        ],
    )
    .await;
    assert_eq!(error_code(response).await.2, 50057);
}
