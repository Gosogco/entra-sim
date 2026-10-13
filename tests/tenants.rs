//! Tests for serving more than one tenant from one process.

mod common;

use common::Sim;
use serde_json::{Value, json};

const SECOND: &str = "22222222-2222-2222-2222-222222222222";
const SECOND_DOMAIN: &str = "second.test";

async fn two_tenants() -> Sim {
    Sim::start_with(|config| {
        config.additional_tenants = vec![format!("{SECOND}={SECOND_DOMAIN}")];
    })
    .await
}

/// A bootstrap token from `tenant`, which may be named by ID or domain.
async fn bootstrap_token(sim: &Sim, tenant: &str) -> reqwest::Response {
    sim.client
        .post(sim.url(&format!("/{tenant}/oauth2/v2.0/token")))
        .form(&[
            ("grant_type", "client_credentials"),
            ("client_id", sim.bootstrap_client_id.as_str()),
            ("client_secret", sim.bootstrap_client_secret.as_str()),
            ("scope", "https://graph.microsoft.com/.default"),
        ])
        .send()
        .await
        .unwrap()
}

async fn token_for(sim: &Sim, tenant: &str) -> String {
    let response = bootstrap_token(sim, tenant).await;
    assert_eq!(response.status(), 200, "token from {tenant}");
    let body: Value = response.json().await.unwrap();
    body["access_token"].as_str().unwrap().to_string()
}

async fn users(sim: &Sim, token: &str) -> Vec<String> {
    let body: Value = sim
        .client
        .get(sim.url("/v1.0/users"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["userPrincipalName"].as_str().unwrap().to_string())
        .collect()
}

#[tokio::test]
async fn each_tenant_issues_its_own_tokens() {
    let sim = two_tenants().await;
    let token = token_for(&sim, SECOND).await;
    let claims = common::decode_claims(&token);
    assert_eq!(claims["tid"], SECOND);
    assert_eq!(
        claims["iss"],
        format!("{}/{SECOND}/v2.0", sim.public_base_url).as_str()
    );
}

#[tokio::test]
async fn a_tenant_can_be_named_by_its_domain() {
    let sim = two_tenants().await;
    let token = token_for(&sim, SECOND_DOMAIN).await;
    assert_eq!(common::decode_claims(&token)["tid"], SECOND);
}

#[tokio::test]
async fn graph_serves_the_directory_of_the_tokens_tenant() {
    let sim = two_tenants().await;
    let first = token_for(&sim, &sim.tenant_id).await;
    let second = token_for(&sim, SECOND).await;

    let created = sim
        .client
        .post(sim.url("/v1.0/users"))
        .bearer_auth(&second)
        .json(&json!({
            "displayName": "Second Only",
            "userPrincipalName": format!("only@{SECOND_DOMAIN}"),
            "mailNickname": "only",
            "accountEnabled": true,
            "passwordProfile": { "password": "Sup3rSecret!" }
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 201);

    assert!(
        users(&sim, &second)
            .await
            .contains(&format!("only@{SECOND_DOMAIN}"))
    );
    assert!(
        !users(&sim, &first)
            .await
            .contains(&format!("only@{SECOND_DOMAIN}"))
    );
}

#[tokio::test]
async fn discovery_names_each_tenants_issuer() {
    let sim = two_tenants().await;
    let discovery = sim
        .get_json(&format!("/{SECOND}/v2.0/.well-known/openid-configuration"))
        .await;
    assert_eq!(
        discovery["issuer"],
        format!("{}/{SECOND}/v2.0", sim.public_base_url).as_str()
    );
    assert_eq!(
        discovery["token_endpoint"],
        format!("{}/{SECOND}/oauth2/v2.0/token", sim.public_base_url).as_str()
    );
}

#[tokio::test]
async fn an_unknown_tenant_is_invalid_tenant() {
    let sim = two_tenants().await;
    let unknown = "33333333-3333-3333-3333-333333333333";

    let response = bootstrap_token(&sim, unknown).await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    // Microsoft's reference: "AADSTS90002 InvalidTenantName".
    assert_eq!(body["error"], "invalid_tenant");
    assert_eq!(body["error_codes"][0], 90002);

    let discovery = sim
        .get(&format!("/{unknown}/v2.0/.well-known/openid-configuration"))
        .await;
    assert_eq!(discovery.status(), 400);
}

#[tokio::test]
async fn a_reset_resets_every_tenant() {
    let sim = two_tenants().await;
    let second = token_for(&sim, SECOND).await;
    sim.client
        .post(sim.url("/v1.0/users"))
        .bearer_auth(&second)
        .json(&json!({
            "displayName": "Temporary",
            "userPrincipalName": format!("temporary@{SECOND_DOMAIN}"),
            "mailNickname": "temporary",
            "accountEnabled": true
        }))
        .send()
        .await
        .unwrap();

    sim.post_json("/__sim__/reset", &json!({})).await;
    let second = token_for(&sim, SECOND).await;
    assert!(users(&sim, &second).await.is_empty());
}

#[tokio::test]
async fn a_malformed_additional_tenant_is_refused_at_startup() {
    let result = Sim::try_start_with(|config| {
        config.additional_tenants = vec!["no-domain".to_string()];
    })
    .await;
    assert!(result.is_err());
}
