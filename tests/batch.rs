//! Tests for Graph JSON batching.

mod common;

use common::Sim;
use serde_json::{Value, json};

async fn batch(sim: &Sim, token: &str, path: &str, body: &Value) -> reqwest::Response {
    sim.client
        .post(sim.url(path))
        .bearer_auth(token)
        .json(body)
        .send()
        .await
        .unwrap()
}

async fn admin_token(sim: &Sim) -> String {
    sim.client_credentials_token().await["access_token"]
        .as_str()
        .unwrap()
        .to_string()
}

fn by_id<'a>(responses: &'a Value, id: &str) -> &'a Value {
    responses["responses"]
        .as_array()
        .unwrap()
        .iter()
        .find(|response| response["id"] == id)
        .unwrap_or_else(|| panic!("no response {id} in {responses}"))
}

#[tokio::test]
async fn a_mixed_batch_answers_each_request() {
    let sim = Sim::start().await;
    let token = admin_token(&sim).await;

    let response = batch(
        &sim,
        &token,
        "/v1.0/$batch",
        &json!({ "requests": [
            { "id": "1", "method": "GET", "url": "/users?$top=1" },
            { "id": "2", "method": "POST", "url": "/groups",
              "headers": { "Content-Type": "application/json" },
              "body": { "displayName": "Batched", "mailEnabled": false,
                        "mailNickname": "batched", "securityEnabled": true } },
            { "id": "3", "method": "GET", "url": "users/00000000-0000-0000-0000-00000000dead" }
        ] }),
    )
    .await;
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(by_id(&body, "1")["status"], 200);
    assert!(by_id(&body, "1")["body"]["value"].is_array());
    assert_eq!(by_id(&body, "2")["status"], 201);
    assert_eq!(by_id(&body, "2")["body"]["displayName"], "Batched");
    // A relative URL without its leading slash works too.
    assert_eq!(by_id(&body, "3")["status"], 404);
}

#[tokio::test]
async fn a_failed_dependency_fails_its_dependents_with_424() {
    let sim = Sim::start().await;
    let token = admin_token(&sim).await;

    let body: Value = batch(
        &sim,
        &token,
        "/v1.0/$batch",
        &json!({ "requests": [
            { "id": "2", "method": "GET", "url": "/users", "dependsOn": ["1"] },
            { "id": "1", "method": "GET", "url": "/users/00000000-0000-0000-0000-00000000dead" },
            { "id": "3", "method": "GET", "url": "/groups", "dependsOn": ["2"] }
        ] }),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(by_id(&body, "1")["status"], 404);
    // "If an individual request fails, any request that depends on that request fails with
    // status code 424 (Failed Dependency)."
    assert_eq!(by_id(&body, "2")["status"], 424);
    assert_eq!(by_id(&body, "3")["status"], 424);
}

#[tokio::test]
async fn dependencies_run_first_whatever_the_order_in_the_batch() {
    let sim = Sim::start().await;
    let token = admin_token(&sim).await;

    let body: Value = batch(
        &sim,
        &token,
        "/beta/$batch",
        &json!({ "requests": [
            { "id": "list", "method": "GET", "url": "/groups?$filter=displayName eq 'First'",
              "dependsOn": ["create"] },
            { "id": "create", "method": "POST", "url": "/groups",
              "headers": { "Content-Type": "application/json" },
              "body": { "displayName": "First", "mailEnabled": false,
                        "mailNickname": "first", "securityEnabled": true } }
        ] }),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(by_id(&body, "create")["status"], 201);
    assert_eq!(
        by_id(&body, "list")["body"]["value"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

#[tokio::test]
async fn more_than_20_requests_or_a_repeated_id_is_refused() {
    let sim = Sim::start().await;
    let token = admin_token(&sim).await;

    let too_many: Vec<Value> = (0..21)
        .map(|index| json!({ "id": index.to_string(), "method": "GET", "url": "/users" }))
        .collect();
    let response = batch(
        &sim,
        &token,
        "/v1.0/$batch",
        &json!({ "requests": too_many }),
    )
    .await;
    assert_eq!(response.status(), 400);

    let repeated = json!({ "requests": [
        { "id": "a", "method": "GET", "url": "/users" },
        { "id": "A", "method": "GET", "url": "/groups" }
    ] });
    // Ids are "Not case-sensitive" and "Must be unique in the batch".
    let response = batch(&sim, &token, "/v1.0/$batch", &repeated).await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn each_request_is_checked_against_its_own_permission() {
    let sim = Sim::start().await;
    // A token that may read users but not write groups.
    let graph = sim.graph_with_roles(&["User.Read.All"]).await;
    let token = graph.token().to_string();

    let body: Value = batch(
        &sim,
        &token,
        "/v1.0/$batch",
        &json!({ "requests": [
            { "id": "read", "method": "GET", "url": "/users" },
            { "id": "write", "method": "POST", "url": "/groups",
              "headers": { "Content-Type": "application/json" },
              "body": { "displayName": "Nope", "mailEnabled": false,
                        "mailNickname": "nope", "securityEnabled": true } }
        ] }),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(by_id(&body, "read")["status"], 200);
    assert_eq!(by_id(&body, "write")["status"], 403);
}

#[tokio::test]
async fn a_body_without_a_content_type_is_refused() {
    let sim = Sim::start().await;
    let token = admin_token(&sim).await;

    let body: Value = batch(
        &sim,
        &token,
        "/v1.0/$batch",
        &json!({ "requests": [
            { "id": "1", "method": "POST", "url": "/groups",
              "body": { "displayName": "No type" } }
        ] }),
    )
    .await
    .json()
    .await
    .unwrap();
    assert_eq!(by_id(&body, "1")["status"], 400);
}

#[tokio::test]
async fn the_batch_itself_needs_a_token() {
    let sim = Sim::start().await;
    let response = sim
        .client
        .post(sim.url("/v1.0/$batch"))
        .json(&json!({ "requests": [] }))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 401);
}
