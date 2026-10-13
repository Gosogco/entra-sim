//! Tests for conditional access policies: the Graph API, and their enforcement at sign-in.

mod common;

use common::{Graph, Sim};
use serde_json::{Value, json};

const POLICIES: &str = "/v1.0/identity/conditionalAccess/policies";

fn policy(state: &str, users: Value, controls: &[&str]) -> Value {
    json!({
        "displayName": "Test policy",
        "state": state,
        "conditions": {
            "clientAppTypes": ["all"],
            "applications": { "includeApplications": ["All"] },
            "users": users
        },
        "grantControls": { "operator": "OR", "builtInControls": controls }
    })
}

async fn create(graph: &Graph, body: &Value) -> Value {
    graph.post_created(POLICIES, body).await
}

#[tokio::test]
async fn a_policy_can_be_created_read_updated_and_deleted() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = create(
        &graph,
        &policy("disabled", json!({ "includeUsers": ["All"] }), &["mfa"]),
    )
    .await;
    let id = created["id"].as_str().unwrap().to_string();
    assert!(created["createdDateTime"].is_string());
    assert!(created["modifiedDateTime"].is_null());
    assert_eq!(created["grantControls"]["builtInControls"], json!(["mfa"]));

    let listed = graph.get_ok(POLICIES).await;
    assert_eq!(listed["value"].as_array().unwrap().len(), 1);

    let updated = graph
        .patch(
            &format!("{POLICIES}/{id}"),
            &json!({ "state": "enabledForReportingButNotEnforced" }),
        )
        .await;
    assert_eq!(updated.status(), 204);
    let read = graph.get_ok(&format!("{POLICIES}/{id}")).await;
    assert_eq!(read["state"], "enabledForReportingButNotEnforced");
    assert!(read["modifiedDateTime"].is_string());

    assert_eq!(
        graph.delete(&format!("{POLICIES}/{id}")).await.status(),
        204
    );
    assert_eq!(graph.get(&format!("{POLICIES}/{id}")).await.status(), 404);
}

#[tokio::test]
async fn conditions_and_a_valid_state_are_required() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let missing = graph
        .post(
            POLICIES,
            &json!({ "displayName": "No conditions", "state": "enabled" }),
        )
        .await;
    assert_eq!(missing.status(), 400);

    let bad_state = graph
        .post(
            POLICIES,
            &policy("sometimes", json!({ "includeUsers": ["All"] }), &["block"]),
        )
        .await;
    assert_eq!(bad_state.status(), 400);
}

#[tokio::test]
async fn policies_are_part_of_the_snapshot_and_cleared_by_reset() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create(
        &graph,
        &policy("disabled", json!({ "includeUsers": ["All"] }), &["block"]),
    )
    .await;

    let snapshot = sim.get_json("/__sim__/snapshot").await;
    assert_eq!(
        snapshot["conditionalAccessPolicies"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    sim.post_json("/__sim__/reset", &json!({})).await;
    let graph = sim.graph().await;
    let listed: Value = graph.get_ok(POLICIES).await;
    assert_eq!(listed["value"], json!([]));
}

/// Orders (v1.0 tokens, so `amr` is a default claim), a public client, and bob.
struct Fixture {
    graph: Graph,
    orders: common::Api,
    client: common::Client,
    bob: String,
}

async fn fixture(sim: &Sim) -> Fixture {
    let graph = sim.graph().await;
    let orders = graph
        .register_api("Orders", "api://orders", &[], &["Orders.Read"], json!({}))
        .await;
    let client = graph
        .register_public_client("Website", json!({ "isFallbackPublicClient": true }))
        .await;
    let bob = graph.create_user("bob@sim.test", "Bob").await;
    Fixture {
        graph,
        orders,
        client,
        bob,
    }
}

/// A policy on Orders for `users`, with `controls`.
fn on_orders(f: &Fixture, state: &str, users: Value, controls: &[&str]) -> Value {
    json!({
        "displayName": "Orders policy",
        "state": state,
        "conditions": {
            "clientAppTypes": ["all"],
            "applications": { "includeApplications": [f.orders.app_id] },
            "users": users
        },
        "grantControls": { "operator": "OR", "builtInControls": controls }
    })
}

async fn submit(sim: &Sim, f: &Fixture, scope: &str, extra: &[(&str, &str)]) -> reqwest::Response {
    let mut form = vec![
        ("client_id", f.client.app_id.as_str()),
        ("response_type", "code"),
        ("redirect_uri", common::SIGN_IN_REDIRECT),
        ("scope", scope),
        ("user_id", f.bob.as_str()),
    ];
    form.extend_from_slice(extra);
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
        .post(sim.url(&format!("/{}/oauth2/v2.0/authorize", sim.tenant_id)))
        .form(&form)
        .send()
        .await
        .unwrap()
}

#[tokio::test]
async fn a_block_policy_refuses_the_sign_in() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    create(
        &f.graph,
        &on_orders(
            &f,
            "enabled",
            json!({ "includeUsers": ["All"] }),
            &["block"],
        ),
    )
    .await;

    let refused = submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    assert_eq!(refused.status(), 400);
    assert!(refused.text().await.unwrap().contains("AADSTS53003"));

    // The policy names Orders only, so a sign-in for Graph goes ahead.
    let allowed = submit(&sim, &f, "openid User.Read", &[]).await;
    assert_eq!(allowed.status(), 302);
}

#[tokio::test]
async fn an_mfa_policy_adds_a_step_and_the_token_reports_it() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let group = f.graph.create_group("Needs MFA", &[&f.bob]).await;
    create(
        &f.graph,
        &on_orders(&f, "enabled", json!({ "includeGroups": [group] }), &["mfa"]),
    )
    .await;

    let step = submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    assert_eq!(step.status(), 200);
    assert!(step.text().await.unwrap().contains("Approve sign-in"));

    let done = submit(&sim, &f, "openid api://orders/Orders.Read", &[("mfa", "1")]).await;
    assert_eq!(done.status(), 302);
    let location = done.headers()["location"].to_str().unwrap().to_string();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let tokens: Value = sim
        .token_request(&[
            ("grant_type", "authorization_code"),
            ("client_id", &f.client.app_id),
            ("code", code),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
        ])
        .await
        .json()
        .await
        .unwrap();
    let claims = common::decode_claims(tokens["access_token"].as_str().unwrap());
    assert_eq!(claims["amr"], json!(["pwd", "mfa"]));
}

#[tokio::test]
async fn excluded_users_report_only_and_disabled_policies_do_not_apply() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    create(
        &f.graph,
        &on_orders(
            &f,
            "enabled",
            json!({ "includeUsers": ["All"], "excludeUsers": [f.bob] }),
            &["block"],
        ),
    )
    .await;
    create(
        &f.graph,
        &on_orders(
            &f,
            "enabledForReportingButNotEnforced",
            json!({ "includeUsers": ["All"] }),
            &["block"],
        ),
    )
    .await;
    create(
        &f.graph,
        &on_orders(
            &f,
            "disabled",
            json!({ "includeUsers": ["All"] }),
            &["block"],
        ),
    )
    .await;

    let allowed = submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    assert_eq!(allowed.status(), 302);
}

#[tokio::test]
async fn a_grant_with_no_page_answers_interaction_required() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    // Consent first, then require MFA.
    submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    create(
        &f.graph,
        &on_orders(&f, "enabled", json!({ "includeUsers": ["All"] }), &["mfa"]),
    )
    .await;

    let response = sim
        .token_request(&[
            ("grant_type", "password"),
            ("client_id", &f.client.app_id),
            ("username", "bob@sim.test"),
            ("password", "Sup3rSecret!"),
            ("scope", "api://orders/Orders.Read"),
        ])
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"], "interaction_required");
    assert_eq!(body["error_codes"][0], 50076);
}

#[tokio::test]
async fn a_refresh_into_a_protected_api_needs_mfa() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let done = submit(
        &sim,
        &f,
        "openid offline_access User.Read api://orders/Orders.Read",
        &[],
    )
    .await;
    let location = done.headers()["location"].to_str().unwrap().to_string();
    let code = location
        .split("code=")
        .nth(1)
        .unwrap()
        .split('&')
        .next()
        .unwrap();
    let tokens: Value = sim
        .token_request(&[
            ("grant_type", "authorization_code"),
            ("client_id", &f.client.app_id),
            ("code", code),
            ("redirect_uri", common::SIGN_IN_REDIRECT),
            ("scope", "User.Read"),
        ])
        .await
        .json()
        .await
        .unwrap();
    create(
        &f.graph,
        &on_orders(&f, "enabled", json!({ "includeUsers": ["All"] }), &["mfa"]),
    )
    .await;

    let response = sim
        .token_request(&[
            ("grant_type", "refresh_token"),
            ("client_id", &f.client.app_id),
            ("refresh_token", tokens["refresh_token"].as_str().unwrap()),
            ("scope", "api://orders/Orders.Read"),
        ])
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error_codes"][0], 50076);
}

#[tokio::test]
async fn a_device_requirement_cannot_be_met() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    create(
        &f.graph,
        &on_orders(
            &f,
            "enabled",
            json!({ "includeUsers": ["All"] }),
            &["compliantDevice"],
        ),
    )
    .await;

    let refused = submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    assert_eq!(refused.status(), 400);
    // Microsoft's reference: "AADSTS53000 DeviceNotCompliant".
    assert!(refused.text().await.unwrap().contains("AADSTS53000"));
}

#[tokio::test]
async fn a_policy_limited_to_specific_locations_never_applies() {
    let sim = Sim::start().await;
    let f = fixture(&sim).await;
    let mut body = on_orders(
        &f,
        "enabled",
        json!({ "includeUsers": ["All"] }),
        &["block"],
    );
    body["conditions"]["locations"] =
        json!({ "includeLocations": ["00000000-0000-0000-0000-00000000aaaa"] });
    create(&f.graph, &body).await;

    let allowed = submit(&sim, &f, "openid api://orders/Orders.Read", &[]).await;
    assert_eq!(allowed.status(), 302);
}
