//! Tests for the on-behalf-of flow: a middle-tier API exchanging a user's token for one to a
//! downstream API.

mod common;

use common::{Api, Graph, Sim, decode_claims};
use serde_json::{Value, json};

const JWT_BEARER: &str = "urn:ietf:params:oauth:grant-type:jwt-bearer";

/// Orders is the middle tier, with a secret; Inventory is the downstream API; a website signs
/// bob in to Orders.
struct Fixture {
    graph: Graph,
    orders: Api,
    orders_secret: String,
    inventory: Api,
    website: common::Client,
    bob: String,
}

async fn fixture(sim: &Sim) -> Fixture {
    let graph = sim.graph().await;
    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &[],
            &["Orders.Read"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    let orders_secret = graph
        .post_created_or_ok(
            &format!("/v1.0/applications/{}/addPassword", orders.object_id),
            &json!({}),
        )
        .await["secretText"]
        .as_str()
        .unwrap()
        .to_string();
    let inventory = graph
        .register_api(
            "Inventory",
            "api://inventory",
            &["Reader"],
            &["Inventory.Read"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    let website = graph
        .register_public_client("Orders website", json!({}))
        .await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    Fixture {
        graph,
        orders,
        orders_secret,
        inventory,
        website,
        bob,
    }
}

/// An administrator consents, for every user, to Orders calling Inventory.
async fn admin_consent(f: &Fixture) {
    let orders_principal = f.orders.principal_id.clone();
    f.graph
        .post_created(
            "/v1.0/oauth2PermissionGrants",
            &json!({
                "clientId": orders_principal,
                "consentType": "AllPrincipals",
                "resourceId": f.inventory.principal_id,
                "scope": "Inventory.Read"
            }),
        )
        .await;
}

/// Bob's token for Orders, as the website would send it.
async fn token_for_orders(sim: &Sim, f: &Fixture) -> String {
    sim.sign_in_ok(&f.website.app_id, &f.bob, "openid api://orders/Orders.Read")
        .await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn exchange(
    sim: &Sim,
    client_id: &str,
    secret: &str,
    assertion: &str,
    scope: &str,
) -> reqwest::Response {
    sim.token_request(&[
        ("grant_type", JWT_BEARER),
        ("client_id", client_id),
        ("client_secret", secret),
        ("assertion", assertion),
        ("scope", scope),
        ("requested_token_use", "on_behalf_of"),
    ])
    .await
}

#[tokio::test]
async fn the_middle_tier_gets_a_token_for_the_downstream_api_as_the_user() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    admin_consent(&f).await;
    f.graph.assign_role(&f.bob, &f.inventory, "Reader").await;
    let incoming = token_for_orders(&sim, &f).await;

    let response = exchange(
        &sim,
        &f.orders.app_id,
        &f.orders_secret,
        &incoming,
        "api://inventory/Inventory.Read offline_access",
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    let claims = decode_claims(body["access_token"].as_str().unwrap());

    assert_eq!(claims["aud"], f.inventory.app_id.as_str());
    assert_eq!(claims["oid"], f.bob.as_str());
    assert_eq!(claims["azp"], f.orders.app_id.as_str());
    assert_eq!(claims["scp"], "Inventory.Read");
    // "Roles remain attached to the principal (the user)".
    assert_eq!(claims["roles"], json!(["Reader"]));
    assert!(body.get("id_token").is_none(), "{body}");
    assert!(body["refresh_token"].is_string(), "{body}");
}

#[tokio::test]
async fn a_token_for_another_application_is_refused() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    admin_consent(&f).await;
    let incoming = token_for_orders(&sim, &f).await;

    // Another confidential app presents bob's token for Orders.
    let other = f.graph.register_client("Other", json!({})).await;
    let response = exchange(
        &sim,
        &other.app_id,
        &other.secret,
        &incoming,
        "api://inventory/Inventory.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["error_codes"][0], 50013);
}

#[tokio::test]
async fn an_app_only_token_is_refused() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    admin_consent(&f).await;
    // An app-only token addressed to Orders.
    let caller = f.graph.register_client("Caller", json!({})).await;
    let app_only: Value = sim
        .app_token(&caller, "api://orders/.default")
        .await
        .json()
        .await
        .unwrap();

    let response = exchange(
        &sim,
        &f.orders.app_id,
        &f.orders_secret,
        app_only["access_token"].as_str().unwrap(),
        "api://inventory/Inventory.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50013);
}

#[tokio::test]
async fn a_graph_token_is_refused() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    admin_consent(&f).await;
    let graph_token = sim
        .sign_in_ok(&f.website.app_id, &f.bob, "openid User.Read")
        .await["access_token"]
        .as_str()
        .unwrap()
        .to_string();

    // Microsoft: "if a client sends an API a token meant for Microsoft Graph, the API can't
    // redeem it using OBO."
    let response = exchange(
        &sim,
        &f.orders.app_id,
        &f.orders_secret,
        &graph_token,
        "api://inventory/Inventory.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn without_consent_the_user_must_interact() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let incoming = token_for_orders(&sim, &f).await;

    let response = exchange(
        &sim,
        &f.orders.app_id,
        &f.orders_secret,
        &incoming,
        "api://inventory/Inventory.Read",
    )
    .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "invalid_grant");
    assert_eq!(body["suberror"], "consent_required");
    assert_eq!(body["error_codes"][0], 65001);
}

#[tokio::test]
async fn the_middle_tier_must_authenticate() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    admin_consent(&f).await;
    let incoming = token_for_orders(&sim, &f).await;

    let response = exchange(
        &sim,
        &f.orders.app_id,
        "not-the-secret",
        &incoming,
        "api://inventory/Inventory.Read",
    )
    .await;
    assert_eq!(response.status(), 401);
}
