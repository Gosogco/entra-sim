//! Tests that the simulator refuses calls the real service would refuse.
//!
//! The requirements come from Microsoft's published permission tables, so a client that passes
//! here should pass against real Graph, and one that fails here would have failed there too.

mod common;

use common::Sim;
use serde_json::json;

#[tokio::test]
async fn a_caller_without_the_required_role_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph_with_roles(&["User.Read.All"]).await;

    let response = graph
        .post("/v1.0/applications", &json!({ "displayName": "Forbidden" }))
        .await;
    assert_eq!(response.status(), 403);

    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Authorization_RequestDenied");
    assert_eq!(
        body["error"]["message"],
        "Insufficient privileges to complete the operation."
    );
}

#[tokio::test]
async fn the_same_caller_is_served_once_it_holds_the_role() {
    let sim = Sim::start().await;

    let unprivileged = sim.graph_with_roles(&["User.Read.All"]).await;
    assert_eq!(
        unprivileged
            .post("/v1.0/applications", &json!({ "displayName": "App" }))
            .await
            .status(),
        403
    );

    let privileged = sim.graph_with_roles(&["Application.ReadWrite.All"]).await;
    assert_eq!(
        privileged
            .post("/v1.0/applications", &json!({ "displayName": "App" }))
            .await
            .status(),
        201
    );
}

#[tokio::test]
async fn a_read_role_does_not_permit_a_write() {
    let sim = Sim::start().await;
    let graph = sim.graph_with_roles(&["Application.Read.All"]).await;

    // Reading is allowed.
    assert_eq!(graph.get("/v1.0/applications").await.status(), 200);

    // Creating is not, and the implication does not run from read to write.
    assert_eq!(
        graph
            .post("/v1.0/applications", &json!({ "displayName": "App" }))
            .await
            .status(),
        403
    );
}

#[tokio::test]
async fn a_write_role_permits_the_matching_read() {
    let sim = Sim::start().await;
    // Graph documents getByIds as needing only Directory.Read.All, but the real service serves
    // a caller holding the write permission, so the simulator must too.
    let graph = sim.graph_with_roles(&["Directory.ReadWrite.All"]).await;

    let response = graph
        .post("/v1.0/directoryObjects/getByIds", &json!({ "ids": [] }))
        .await;
    assert!(
        response.status().is_success(),
        "Directory.ReadWrite.All should serve a Directory.Read.All endpoint, got {}",
        response.status()
    );
}

#[tokio::test]
async fn a_conjunction_is_enforced_in_full() {
    let sim = Sim::start().await;

    // Look the resource up with a fully privileged client, so the assertion below is about the
    // write call rather than about reading service principals.
    let admin = sim.graph().await;
    let found = admin
        .get_ok(
            "/v1.0/servicePrincipals?$filter=appId%20eq%20'00000003-0000-0000-c000-000000000000'",
        )
        .await;
    let resource_id = found["value"][0]["id"].as_str().unwrap().to_string();
    let path = format!("/v1.0/servicePrincipals/{resource_id}/appRoleAssignedTo");
    let body = json!({ "principalId": resource_id, "resourceId": resource_id });

    // Graph documents this endpoint as needing AppRoleAssignment.ReadWrite.All together with a
    // read permission, so half the conjunction is not enough.
    let half = sim
        .graph_with_roles(&["AppRoleAssignment.ReadWrite.All"])
        .await;
    assert_eq!(half.post(&path, &body).await.status(), 403);

    let whole = sim
        .graph_with_roles(&["AppRoleAssignment.ReadWrite.All", "Application.Read.All"])
        .await;
    assert_eq!(whole.post(&path, &body).await.status(), 201);
}

#[tokio::test]
async fn a_caller_with_no_roles_at_all_is_refused_everywhere() {
    let sim = Sim::start().await;
    let graph = sim.graph_with_roles(&[]).await;

    for path in [
        "/v1.0/users",
        "/v1.0/groups",
        "/v1.0/applications",
        "/v1.0/servicePrincipals",
        "/v1.0/domains",
        "/v1.0/organization",
        "/v1.0/directoryRoles",
    ] {
        assert_eq!(
            graph.get(path).await.status(),
            403,
            "GET {path} should be refused to a caller holding no roles"
        );
    }
}

#[tokio::test]
async fn enforcement_applies_to_the_beta_prefix_too() {
    let sim = Sim::start().await;
    let graph = sim.graph_with_roles(&["User.Read.All"]).await;

    // The same handlers serve both prefixes, so enforcement cannot be bypassed by choosing one.
    assert_eq!(
        graph
            .post("/beta/applications", &json!({ "displayName": "App" }))
            .await
            .status(),
        403
    );
    assert_eq!(graph.get("/beta/users").await.status(), 200);
}

#[tokio::test]
async fn the_relax_flag_turns_enforcement_off() {
    let sim = Sim::start_with(|config| config.enforce_permissions = false).await;
    let graph = sim.graph_with_roles(&[]).await;

    // Useful for writing tests before wiring up consent.
    assert_eq!(
        graph
            .post("/v1.0/applications", &json!({ "displayName": "Allowed" }))
            .await
            .status(),
        201
    );
}

#[tokio::test]
async fn an_unauthenticated_request_is_still_a_401_not_a_403() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // The distinction tells a client whether to obtain a token or ask for a permission.
    let response = graph.get_anonymous("/v1.0/applications").await;
    assert_eq!(response.status(), 401);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "InvalidAuthenticationToken");
}
