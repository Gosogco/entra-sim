//! Tests for administrative units and directory roles scoped to them.

mod common;

use common::{Graph, Sim};
use serde_json::{Value, json};

const USER_ADMINISTRATOR: &str = "fe930be7-5e62-47db-91af-98c3a49a38b1";
const GLOBAL_ADMINISTRATOR: &str = "62e90394-69f5-4237-9190-012177145e10";
const UNITS: &str = "/v1.0/directory/administrativeUnits";

fn reference(id: &str) -> Value {
    json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{id}") })
}

async fn activate(graph: &Graph, template: &str) -> String {
    graph
        .post_created(
            "/v1.0/directoryRoles",
            &json!({ "roleTemplateId": template }),
        )
        .await["id"]
        .as_str()
        .unwrap()
        .to_string()
}

async fn unit_with(graph: &Graph, members: &[&str]) -> String {
    let unit = graph
        .post_created(UNITS, &json!({ "displayName": "Oslo office" }))
        .await;
    let id = unit["id"].as_str().unwrap().to_string();
    for member in members {
        let added = graph
            .post(&format!("{UNITS}/{id}/members/$ref"), &reference(member))
            .await;
        assert_eq!(added.status(), 204);
    }
    id
}

async fn scope_role(graph: &Graph, unit: &str, role: &str, member: &str) -> reqwest::Response {
    graph
        .post(
            &format!("{UNITS}/{unit}/scopedRoleMembers"),
            &json!({ "roleId": role, "roleMemberInfo": { "id": member } }),
        )
        .await
}

/// A Graph client acting as `user`, signed in with `User.ReadWrite.All`.
async fn signed_in(sim: &Sim, graph: &Graph, user: &str) -> Graph {
    let client = graph
        .register_public_client("Admin portal", json!({}))
        .await;
    let body = sim
        .sign_in_ok(&client.app_id, user, "User.ReadWrite.All")
        .await;
    sim.graph_as(body["access_token"].as_str().unwrap())
}

async fn rename(graph: &Graph, user: &str) -> u16 {
    graph
        .patch(
            &format!("/v1.0/users/{user}"),
            &json!({ "displayName": "Renamed" }),
        )
        .await
        .status()
        .as_u16()
}

#[tokio::test]
async fn a_unit_has_members_and_scoped_role_members() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let unit = unit_with(&graph, &[&bob]).await;
    let role = activate(&graph, USER_ADMINISTRATOR).await;

    let created = scope_role(&graph, &unit, &role, &alice).await;
    assert_eq!(created.status(), 201);
    let membership: Value = created.json().await.unwrap();
    assert_eq!(membership["administrativeUnitId"], unit.as_str());
    assert_eq!(membership["roleMemberInfo"]["displayName"], "Alice Example");

    // The azuread provider looks a member up with this filter.
    let members = graph
        .get_ok(&format!("{UNITS}/{unit}/members?$filter=id eq '{bob}'"))
        .await;
    assert_eq!(members["value"][0]["id"], bob.as_str());
    let read = graph
        .get_ok(&format!(
            "{UNITS}/{unit}/scopedRoleMembers/{}",
            membership["id"].as_str().unwrap()
        ))
        .await;
    assert_eq!(read["roleId"], role.as_str());

    // The provider deletes a unit through beta's top-level path.
    let deleted = graph
        .delete(&format!("/beta/administrativeUnits/{unit}"))
        .await;
    assert_eq!(deleted.status(), 204);
    assert_eq!(graph.get(&format!("{UNITS}/{unit}")).await.status(), 404);
}

#[tokio::test]
async fn only_roles_microsoft_lists_can_be_scoped_to_a_unit() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let unit = unit_with(&graph, &[]).await;
    let role = activate(&graph, GLOBAL_ADMINISTRATOR).await;

    assert_eq!(scope_role(&graph, &unit, &role, &alice).await.status(), 400);
}

#[tokio::test]
async fn a_scoped_user_administrator_manages_only_the_units_users() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let carol = graph.create_user("carol@sim.test", "Carol Example").await;
    let dave = graph.create_user("dave@sim.test", "Dave Example").await;
    // Dave is in the unit only through a group, which does not bring him into scope.
    let team = graph.create_group("Oslo team", &[&dave]).await;
    let unit = unit_with(&graph, &[&bob, &team]).await;
    let role = activate(&graph, USER_ADMINISTRATOR).await;
    assert_eq!(scope_role(&graph, &unit, &role, &alice).await.status(), 201);

    let as_alice = signed_in(&sim, &graph, &alice).await;
    assert_eq!(rename(&as_alice, &bob).await, 204);
    assert_eq!(rename(&as_alice, &carol).await, 403);
    assert_eq!(rename(&as_alice, &dave).await, 403);
    let deleted = as_alice.delete(&format!("/v1.0/users/{carol}")).await;
    assert_eq!(deleted.status(), 403);
}

#[tokio::test]
async fn a_signed_in_user_without_a_role_cannot_change_another_user() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let carol = graph.create_user("carol@sim.test", "Carol Example").await;

    let as_bob = signed_in(&sim, &graph, &bob).await;
    assert_eq!(rename(&as_bob, &carol).await, 403);
    // A user may still change their own profile.
    assert_eq!(rename(&as_bob, &bob).await, 204);
}

#[tokio::test]
async fn a_tenant_wide_user_administrator_manages_every_user() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let carol = graph.create_user("carol@sim.test", "Carol Example").await;
    let role = activate(&graph, USER_ADMINISTRATOR).await;
    let added = graph
        .post(
            &format!("/v1.0/directoryRoles/{role}/members/$ref"),
            &reference(&alice),
        )
        .await;
    assert_eq!(added.status(), 204);

    let as_alice = signed_in(&sim, &graph, &alice).await;
    assert_eq!(rename(&as_alice, &carol).await, 204);
}

#[tokio::test]
async fn a_pim_activation_over_a_unit_is_scoped_and_not_tenant_wide() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice Example").await;
    let bob = graph.create_user("bob@sim.test", "Bob Example").await;
    let carol = graph.create_user("carol@sim.test", "Carol Example").await;
    let unit = unit_with(&graph, &[&bob]).await;
    graph
        .post_created(
            "/v1.0/roleManagement/directory/roleAssignmentScheduleRequests",
            &json!({
                "action": "adminAssign",
                "principalId": alice,
                "roleDefinitionId": USER_ADMINISTRATOR,
                "directoryScopeId": format!("/administrativeUnits/{unit}"),
                "scheduleInfo": { "expiration": { "type": "noExpiration" } }
            }),
        )
        .await;

    let as_alice = signed_in(&sim, &graph, &alice).await;
    assert_eq!(rename(&as_alice, &bob).await, 204);
    assert_eq!(rename(&as_alice, &carol).await, 403);
}
