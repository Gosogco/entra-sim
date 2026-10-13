//! Tests for Privileged Identity Management of directory roles: an eligible user activates a
//! role for a while, and holds it until the activation ends.

mod common;

use common::{Graph, Sim, decode_claims};
use serde_json::{Value, json};

const USER_ADMINISTRATOR: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const ELIGIBILITY_REQUESTS: &str = "/v1.0/roleManagement/directory/roleEligibilityScheduleRequests";
const ASSIGNMENT_REQUESTS: &str = "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests";

async fn make_eligible(graph: &Graph, principal: &str) -> Value {
    graph
        .post_created(
            ELIGIBILITY_REQUESTS,
            &json!({
                "action": "adminAssign",
                "justification": "On call",
                "principalId": principal,
                "roleDefinitionId": USER_ADMINISTRATOR,
                "directoryScopeId": "/",
                "scheduleInfo": { "expiration": { "type": "noExpiration" } }
            }),
        )
        .await
}

/// Sign bob in for Graph through a client whose ID tokens carry `wids`.
async fn sign_in(sim: &Sim, client_id: &str, bob: &str) -> (Value, String) {
    let body = sim
        .sign_in_ok(
            client_id,
            bob,
            "openid RoleAssignmentSchedule.ReadWrite.Directory",
        )
        .await;
    (
        decode_claims(body["id_token"].as_str().unwrap()),
        body["access_token"].as_str().unwrap().to_string(),
    )
}

fn activation(bob: &str, duration: &str) -> Value {
    json!({
        "action": "selfActivate",
        "justification": "Resetting a password",
        "principalId": bob,
        "roleDefinitionId": USER_ADMINISTRATOR,
        "directoryScopeId": "/",
        "scheduleInfo": {
            "expiration": { "type": "afterDuration", "duration": duration }
        }
    })
}

#[tokio::test]
async fn an_eligibility_is_readable_as_a_request_and_as_a_schedule_with_the_same_id() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;

    let request = make_eligible(&graph, &bob).await;
    assert_eq!(request["status"], "Provisioned");
    assert_eq!(request["action"], "adminAssign");
    let id = request["id"].as_str().unwrap();

    let read = graph.get_ok(&format!("{ELIGIBILITY_REQUESTS}/{id}")).await;
    assert_eq!(read["principalId"], bob.as_str());
    let schedule = graph
        .get_ok(&format!(
            "/v1.0/roleManagement/directory/roleEligibilitySchedules/{id}"
        ))
        .await;
    assert_eq!(schedule["roleDefinitionId"], USER_ADMINISTRATOR);
    assert_eq!(
        schedule["scheduleInfo"]["expiration"]["type"],
        "noExpiration"
    );

    // The azuread provider removes an eligibility with an adminRemove request.
    let removal = graph
        .post_created(
            ELIGIBILITY_REQUESTS,
            &json!({
                "action": "adminRemove",
                "principalId": bob,
                "roleDefinitionId": USER_ADMINISTRATOR,
                "directoryScopeId": "/"
            }),
        )
        .await;
    assert_eq!(removal["status"], "Revoked");
    let gone = graph
        .get(&format!(
            "/v1.0/roleManagement/directory/roleEligibilitySchedules/{id}"
        ))
        .await;
    assert_eq!(gone.status(), 404);
}

#[tokio::test]
async fn an_activated_role_shows_in_wids_and_membership_until_it_expires() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let client = graph
        .register_public_client(
            "Admin portal",
            json!({ "groupMembershipClaims": "DirectoryRole" }),
        )
        .await;
    make_eligible(&graph, &bob).await;

    let (claims, token) = sign_in(&sim, &client.app_id, &bob).await;
    assert!(claims.get("wids").is_none(), "{claims}");

    let as_bob = sim.graph_as(&token);
    let activated = as_bob
        .post_created(ASSIGNMENT_REQUESTS, &activation(&bob, "PT3S"))
        .await;
    assert_eq!(activated["status"], "Provisioned");
    let schedule = graph
        .get_ok(&format!(
            "/v1.0/roleManagement/directory/roleAssignmentSchedules/{}",
            activated["id"].as_str().unwrap()
        ))
        .await;
    assert_eq!(schedule["assignmentType"], "Activated");

    let (claims, _) = sign_in(&sim, &client.app_id, &bob).await;
    assert_eq!(claims["wids"], json!([USER_ADMINISTRATOR]));
    // Activating made the role active in the tenant.
    let listed = graph.get_ok("/v1.0/directoryRoles").await;
    let role = listed["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|role| role["roleTemplateId"] == USER_ADMINISTRATOR)
        .unwrap();
    let members = format!(
        "/v1.0/directoryRoles/{}/members",
        role["id"].as_str().unwrap()
    );
    let roles = graph.get_ok(&members).await;
    assert_eq!(roles["value"][0]["id"], bob.as_str());

    tokio::time::sleep(std::time::Duration::from_secs(4)).await;
    let (claims, _) = sign_in(&sim, &client.app_id, &bob).await;
    assert!(claims.get("wids").is_none(), "{claims}");
    let roles = graph.get_ok(&members).await;
    assert_eq!(roles["value"], json!([]));
}

#[tokio::test]
async fn a_user_who_is_not_eligible_cannot_activate() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let client = graph
        .register_public_client("Admin portal", json!({}))
        .await;

    let (_, token) = sign_in(&sim, &client.app_id, &bob).await;
    let response = sim
        .graph_as(&token)
        .post(ASSIGNMENT_REQUESTS, &activation(&bob, "PT1H"))
        .await;
    assert_eq!(response.status(), 400);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "RoleAssignmentDoesNotExist");
}

#[tokio::test]
async fn a_user_cannot_activate_for_someone_else() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let client = graph
        .register_public_client("Admin portal", json!({}))
        .await;
    make_eligible(&graph, &alice).await;

    let (_, token) = sign_in(&sim, &client.app_id, &bob).await;
    let response = sim
        .graph_as(&token)
        .post(ASSIGNMENT_REQUESTS, &activation(&alice, "PT1H"))
        .await;
    assert_eq!(response.status(), 403);
}
