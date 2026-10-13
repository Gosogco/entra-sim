//! Tests for `appRoleAssignmentRequired`: who may get a token for an application that requires
//! assignment.

mod common;

use common::{Api, Graph, Sim};
use serde_json::{Value, json};

const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";
const DEFAULT_ACCESS: &str = "00000000-0000-0000-0000-000000000000";

/// Orders requires assignment; bob and a public client exist.
async fn fixture(sim: &Sim) -> (Graph, Api, common::Client, String) {
    let graph = sim.graph().await;
    let orders = graph
        .register_api(
            "Orders",
            "api://orders",
            &["Reader"],
            &["Orders.Read"],
            json!({ "api": { "requestedAccessTokenVersion": 2 } }),
        )
        .await;
    require_assignment(&graph, &orders.principal_id).await;
    let client = graph
        .register_public_client("Orders website", json!({}))
        .await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    (graph, orders, client, bob)
}

async fn require_assignment(graph: &Graph, principal_id: &str) {
    let response = graph
        .patch(
            &format!("/v1.0/servicePrincipals/{principal_id}"),
            &json!({ "appRoleAssignmentRequired": true }),
        )
        .await;
    assert_eq!(response.status(), 204);
}

/// Submit the sign-in page for `scope` and return the response without following it.
async fn choose_user(sim: &Sim, client_id: &str, user_id: &str, scope: &str) -> reqwest::Response {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&[
            ("client_id", client_id),
            ("response_type", "code"),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", scope),
            ("user_id", user_id),
        ])
        .send()
        .await
        .unwrap()
}

async fn assert_refused_at_sign_in(sim: &Sim, client_id: &str, user_id: &str, scope: &str) {
    let response = choose_user(sim, client_id, user_id, scope).await;
    assert_eq!(response.status(), 400);
    let page = response.text().await.unwrap();
    assert!(page.contains("AADSTS50105"), "{page}");
}

#[tokio::test]
async fn an_unassigned_user_cannot_sign_in_to_an_api_that_requires_assignment() {
    let sim = Sim::start().await;
    let (_, _, client, bob) = fixture(&sim).await;
    assert_refused_at_sign_in(
        &sim,
        &client.app_id,
        &bob,
        "openid api://orders/Orders.Read",
    )
    .await;
}

#[tokio::test]
async fn an_assigned_user_signs_in() {
    let sim = Sim::start().await;
    let (graph, orders, client, bob) = fixture(&sim).await;
    graph.assign_role(&bob, &orders, "Reader").await;
    sim.sign_in_ok(&client.app_id, &bob, "openid api://orders/Orders.Read")
        .await;
}

#[tokio::test]
async fn an_assignment_to_a_security_group_lets_its_members_in() {
    let sim = Sim::start().await;
    let (graph, orders, client, bob) = fixture(&sim).await;
    let group = graph.create_group("Order clerks", &[&bob]).await;
    graph.assign_role(&group, &orders, "Reader").await;
    sim.sign_in_ok(&client.app_id, &bob, "openid api://orders/Orders.Read")
        .await;
}

#[tokio::test]
async fn the_default_access_role_counts_as_an_assignment() {
    let sim = Sim::start().await;
    let (graph, orders, client, bob) = fixture(&sim).await;
    graph
        .post_created(
            &format!(
                "/v1.0/servicePrincipals/{}/appRoleAssignedTo",
                orders.principal_id
            ),
            &json!({
                "principalId": bob,
                "resourceId": orders.principal_id,
                "appRoleId": DEFAULT_ACCESS
            }),
        )
        .await;
    sim.sign_in_ok(&client.app_id, &bob, "openid api://orders/Orders.Read")
        .await;
}

#[tokio::test]
async fn a_global_administrator_signs_in_without_an_assignment() {
    let sim = Sim::start().await;
    let (graph, _, client, bob) = fixture(&sim).await;
    let role = graph
        .post_created(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": GLOBAL_ADMINISTRATOR }),
        )
        .await;
    let added = graph
        .post(
            &format!("/v1.0/directoryRoles/{}/members/$ref", role["id"].as_str().unwrap()),
            &json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{bob}") }),
        )
        .await;
    assert!(added.status().is_success());

    // "Users with a Global Administrator role can sign in to applications, regardless of the
    // assignment required settings."
    sim.sign_in_ok(&client.app_id, &bob, "openid api://orders/Orders.Read")
        .await;
}

#[tokio::test]
async fn a_client_app_that_requires_assignment_refuses_an_unassigned_user() {
    let sim = Sim::start().await;
    let (graph, _, client, bob) = fixture(&sim).await;
    require_assignment(&graph, &client.principal_id).await;
    // Even for a Graph token: the user signs in to the client app.
    assert_refused_at_sign_in(&sim, &client.app_id, &bob, "openid User.Read").await;
}

#[tokio::test]
async fn a_refresh_for_an_api_that_requires_assignment_is_refused() {
    let sim = Sim::start().await;
    let (_, _, client, bob) = fixture(&sim).await;

    // Sign in for Graph only, then try to switch to Orders with the refresh token.
    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid offline_access User.Read")
        .await;
    let response = sim
        .token_request(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client.app_id),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("scope", "api://orders/.default"),
        ])
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50105);
}

#[tokio::test]
async fn an_unassigned_app_gets_no_app_only_token() {
    let sim = Sim::start().await;
    let (graph, orders, _, _) = fixture(&sim).await;
    let billing = graph.register_client("Billing job", json!({})).await;

    let refused = sim.app_token(&billing, "api://orders/.default").await;
    assert_eq!(refused.status(), 400);
    let body: Value = refused.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 501051);

    graph
        .assign_role(&billing.principal_id, &orders, "Reader")
        .await;
    let allowed = sim.app_token(&billing, "api://orders/.default").await;
    assert_eq!(allowed.status(), 200);
}

#[tokio::test]
async fn a_disabled_user_cannot_sign_in_or_refresh() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let client = graph.register_public_client("Website", json!({})).await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let tokens = sim
        .sign_in_ok(&client.app_id, &bob, "openid offline_access User.Read")
        .await;

    let disabled = graph
        .patch(
            &format!("/v1.0/users/{bob}"),
            &json!({ "accountEnabled": false }),
        )
        .await;
    assert_eq!(disabled.status(), 204);

    let response = choose_user(&sim, &client.app_id, &bob, "openid User.Read").await;
    assert_eq!(response.status(), 400);
    assert!(response.text().await.unwrap().contains("AADSTS50057"));

    let refreshed = sim
        .token_request(&[
            ("grant_type", "refresh_token"),
            ("client_id", &client.app_id),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
        ])
        .await;
    assert_eq!(refreshed.status(), 400);
    let body: Value = refreshed.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50057);
}
