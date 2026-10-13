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
