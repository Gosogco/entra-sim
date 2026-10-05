//! Tests for /groups, membership, ownership and transitive membership.

mod common;

use common::{Graph, Sim};
use serde_json::json;

async fn create_group(graph: &Graph, display_name: &str) -> String {
    let created = graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": display_name,
                "mailEnabled": false,
                "securityEnabled": true,
                "mailNickname": display_name.to_lowercase().replace(' ', "-")
            }),
        )
        .await;
    created["id"].as_str().expect("a group ID").to_string()
}

async fn create_user(graph: &Graph, upn: &str) -> String {
    let created = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "accountEnabled": true,
                "displayName": upn,
                "userPrincipalName": upn,
                "mailNickname": upn.split('@').next().unwrap()
            }),
        )
        .await;
    created["id"].as_str().expect("a user ID").to_string()
}

/// Build the reference body a client sends to a `/$ref` endpoint, naming the real Graph host as
/// a real client would.
fn reference(id: &str) -> serde_json::Value {
    json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{id}") })
}

#[tokio::test]
async fn a_created_group_can_be_read_back() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": "Platform",
                "description": "Platform engineering",
                "mailEnabled": false,
                "securityEnabled": true,
                "mailNickname": "platform",
                "groupTypes": []
            }),
        )
        .await;
    let id = created["id"].as_str().unwrap();
    assert_eq!(created["displayName"], "Platform");
    assert_eq!(created["securityEnabled"], true);

    let fetched = graph.get_ok(&format!("/v1.0/groups/{id}")).await;
    assert_eq!(fetched["description"], "Platform engineering");
}

#[tokio::test]
async fn mail_enabled_and_security_enabled_are_required_on_create() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // Graph refuses rather than defaulting, because the combination decides the group's kind.
    let response = graph
        .post("/v1.0/groups", &json!({ "displayName": "Incomplete" }))
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("mailEnabled"),
        "got {body}"
    );
}

#[tokio::test]
async fn members_are_a_navigation_property_not_a_group_field() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "alice@sim.test").await;

    assert_eq!(
        graph
            .post(
                &format!("/v1.0/groups/{group}/members/$ref"),
                &reference(&user)
            )
            .await
            .status(),
        204
    );

    // The group body must not carry members; Graph exposes them only through /members.
    let fetched = graph.get_ok(&format!("/v1.0/groups/{group}")).await;
    assert!(fetched["members"].is_null(), "got {fetched}");

    let members = graph.get_ok(&format!("/v1.0/groups/{group}/members")).await;
    let values = members["value"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"], user);
    // A heterogeneous collection needs the type annotation.
    assert_eq!(values[0]["@odata.type"], "#microsoft.graph.user");
}

#[tokio::test]
async fn adding_the_same_member_twice_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "bob@sim.test").await;
    let path = format!("/v1.0/groups/{group}/members/$ref");

    assert_eq!(graph.post(&path, &reference(&user)).await.status(), 204);

    // Graph refuses a duplicate rather than treating the add as idempotent.
    let repeat = graph.post(&path, &reference(&user)).await;
    assert_eq!(repeat.status(), 400);
    let body: serde_json::Value = repeat.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already exist"),
        "got {body}"
    );
}

#[tokio::test]
async fn a_member_reference_to_a_missing_object_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;

    let response = graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &reference("99999999-9999-9999-9999-999999999999"),
        )
        .await;
    assert_eq!(response.status(), 404);
}

#[tokio::test]
async fn a_member_can_be_removed() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "carol@sim.test").await;

    graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &reference(&user),
        )
        .await;
    assert_eq!(
        graph
            .delete(&format!("/v1.0/groups/{group}/members/{user}/$ref"))
            .await
            .status(),
        204
    );

    let members = graph.get_ok(&format!("/v1.0/groups/{group}/members")).await;
    assert!(members["value"].as_array().unwrap().is_empty());
}

#[tokio::test]
async fn owners_are_tracked_separately_from_members() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let owner = create_user(&graph, "dave@sim.test").await;
    let member = create_user(&graph, "erin@sim.test").await;

    graph
        .post(
            &format!("/v1.0/groups/{group}/owners/$ref"),
            &reference(&owner),
        )
        .await;
    graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &reference(&member),
        )
        .await;

    let owners = graph.get_ok(&format!("/v1.0/groups/{group}/owners")).await;
    let members = graph.get_ok(&format!("/v1.0/groups/{group}/members")).await;
    assert_eq!(owners["value"][0]["id"], owner);
    assert_eq!(members["value"][0]["id"], member);
    assert_eq!(owners["value"].as_array().unwrap().len(), 1);
    assert_eq!(members["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn transitive_members_follow_nested_groups() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let outer = create_group(&graph, "Outer").await;
    let inner = create_group(&graph, "Inner").await;
    let direct = create_user(&graph, "frank@sim.test").await;
    let nested = create_user(&graph, "gail@sim.test").await;

    graph
        .post(
            &format!("/v1.0/groups/{outer}/members/$ref"),
            &reference(&direct),
        )
        .await;
    graph
        .post(
            &format!("/v1.0/groups/{outer}/members/$ref"),
            &reference(&inner),
        )
        .await;
    graph
        .post(
            &format!("/v1.0/groups/{inner}/members/$ref"),
            &reference(&nested),
        )
        .await;

    let direct_only = graph.get_ok(&format!("/v1.0/groups/{outer}/members")).await;
    assert_eq!(direct_only["value"].as_array().unwrap().len(), 2);

    let transitive = graph
        .get_ok(&format!("/v1.0/groups/{outer}/transitiveMembers"))
        .await;
    let ids: Vec<&str> = transitive["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|object| object["id"].as_str().unwrap())
        .collect();

    // Graph includes the nested group itself alongside its members.
    assert_eq!(ids.len(), 3, "got {ids:?}");
    for expected in [&direct, &inner, &nested] {
        assert!(
            ids.contains(&expected.as_str()),
            "{expected} missing from {ids:?}"
        );
    }
}

#[tokio::test]
async fn a_membership_cycle_does_not_hang() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let first = create_group(&graph, "First").await;
    let second = create_group(&graph, "Second").await;

    // Entra prevents this, but a simulated directory can be driven into it, and the traversal
    // must terminate regardless.
    graph
        .post(
            &format!("/v1.0/groups/{first}/members/$ref"),
            &reference(&second),
        )
        .await;
    graph
        .post(
            &format!("/v1.0/groups/{second}/members/$ref"),
            &reference(&first),
        )
        .await;

    let transitive = graph
        .get_ok(&format!("/v1.0/groups/{first}/transitiveMembers"))
        .await;
    assert_eq!(transitive["value"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn member_of_reports_the_groups_a_user_belongs_to() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let other = create_group(&graph, "Unrelated").await;
    let user = create_user(&graph, "hank@sim.test").await;

    graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &reference(&user),
        )
        .await;

    let member_of = graph.get_ok(&format!("/v1.0/users/{user}/memberOf")).await;
    let values = member_of["value"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"], group);
    assert_ne!(values[0]["id"], other);
    assert_eq!(values[0]["@odata.type"], "#microsoft.graph.group");
}

#[tokio::test]
async fn expand_members_inlines_them_on_the_group() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "ivy@sim.test").await;
    graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &reference(&user),
        )
        .await;

    let expanded = graph
        .get_ok(&format!("/v1.0/groups/{group}?$expand=members"))
        .await;
    assert_eq!(expanded["members"][0]["id"], user);
}

#[tokio::test]
async fn expanding_an_unknown_property_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;

    let response = graph
        .get(&format!("/v1.0/groups/{group}?$expand=nonsense"))
        .await;
    assert_eq!(response.status(), 400);
}

#[tokio::test]
async fn members_can_be_bound_when_the_group_is_created() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let user = create_user(&graph, "jane@sim.test").await;

    // The azuread provider sets the whole membership in one call this way.
    let created = graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": "Bound",
                "mailEnabled": false,
                "securityEnabled": true,
                "members@odata.bind": [
                    format!("https://graph.microsoft.com/v1.0/directoryObjects/{user}")
                ]
            }),
        )
        .await;
    let id = created["id"].as_str().unwrap();

    let members = graph.get_ok(&format!("/v1.0/groups/{id}/members")).await;
    assert_eq!(members["value"][0]["id"], user);
}

#[tokio::test]
async fn deleting_a_group_removes_it_from_other_memberships() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let outer = create_group(&graph, "Outer").await;
    let inner = create_group(&graph, "Inner").await;
    graph
        .post(
            &format!("/v1.0/groups/{outer}/members/$ref"),
            &reference(&inner),
        )
        .await;

    assert_eq!(
        graph
            .delete(&format!("/v1.0/groups/{inner}"))
            .await
            .status(),
        204
    );

    // A dangling reference would otherwise surface as a phantom member.
    let members = graph.get_ok(&format!("/v1.0/groups/{outer}/members")).await;
    assert!(
        members["value"].as_array().unwrap().is_empty(),
        "got {members}"
    );
}

#[tokio::test]
async fn get_by_ids_resolves_a_mixed_batch() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "karl@sim.test").await;

    let resolved = graph
        .post_created_or_ok(
            "/v1.0/directoryObjects/getByIds",
            &json!({ "ids": [group.clone(), user.clone(), "missing-id"] }),
        )
        .await;
    let ids: Vec<&str> = resolved["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|object| object["id"].as_str().unwrap())
        .collect();

    // A missing ID is skipped rather than failing the whole call.
    assert_eq!(ids.len(), 2, "got {ids:?}");
    assert!(ids.contains(&group.as_str()));
    assert!(ids.contains(&user.as_str()));
}

#[tokio::test]
async fn get_by_ids_can_be_restricted_by_type() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let group = create_group(&graph, "Platform").await;
    let user = create_user(&graph, "liam@sim.test").await;

    let resolved = graph
        .post_created_or_ok(
            "/v1.0/directoryObjects/getByIds",
            &json!({ "ids": [group, user.clone()], "types": ["user"] }),
        )
        .await;
    let values = resolved["value"].as_array().unwrap();
    assert_eq!(values.len(), 1);
    assert_eq!(values[0]["id"], user);
}

#[tokio::test]
async fn groups_can_be_filtered_by_display_name() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_group(&graph, "Platform").await;
    create_group(&graph, "Security").await;

    let matched = graph
        .get_ok("/v1.0/groups?$filter=displayName%20eq%20'Platform'")
        .await;
    assert_eq!(matched["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn unified_groups_can_be_found_with_an_any_filter() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_group(&graph, "Security").await;
    graph
        .post_created(
            "/v1.0/groups",
            &json!({
                "displayName": "Microsoft 365",
                "mailEnabled": true,
                "securityEnabled": false,
                "mailNickname": "m365",
                "groupTypes": ["Unified"]
            }),
        )
        .await;

    // This is the shape the azuread provider uses to tell group kinds apart.
    let matched = graph
        .get_ok("/v1.0/groups?$filter=groupTypes/any(c:c%20eq%20'Unified')")
        .await;
    let values = matched["value"].as_array().unwrap();
    assert_eq!(values.len(), 1, "got {matched}");
    assert_eq!(values[0]["displayName"], "Microsoft 365");
}
