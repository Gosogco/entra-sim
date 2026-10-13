//! Tests for delta queries.

mod common;

use common::{Graph, Sim};
use serde_json::{Value, json};

/// Follow a delta link, which names the simulator's public address, against the test server.
async fn follow(sim: &Sim, graph: &Graph, link: &str) -> Value {
    let path = link.strip_prefix(&sim.public_base_url).unwrap();
    graph.get_ok(path).await
}

fn find<'a>(page: &'a Value, id: &str) -> Option<&'a Value> {
    page["value"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["id"] == id)
}

#[tokio::test]
async fn a_round_reports_created_updated_and_deleted_users() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let kept = graph.create_user("kept@sim.test", "Kept").await;
    let renamed = graph.create_user("renamed@sim.test", "Before").await;
    let removed = graph.create_user("removed@sim.test", "Removed").await;

    let first = graph.get_ok("/v1.0/users/delta").await;
    for id in [&kept, &renamed, &removed] {
        assert!(
            find(&first, id).is_some(),
            "{id} missing from the first round"
        );
    }
    assert!(first.get("@odata.nextLink").is_none());
    let link = first["@odata.deltaLink"].as_str().unwrap().to_string();
    assert!(link.contains("$deltatoken="), "{link}");

    let added = graph.create_user("added@sim.test", "Added").await;
    graph
        .patch(
            &format!("/v1.0/users/{renamed}"),
            &json!({ "displayName": "After" }),
        )
        .await;
    graph.delete(&format!("/v1.0/users/{removed}")).await;

    let second = follow(&sim, &graph, &link).await;
    assert_eq!(find(&second, &added).unwrap()["displayName"], "Added");
    assert_eq!(find(&second, &renamed).unwrap()["displayName"], "After");
    assert_eq!(
        find(&second, &removed).unwrap()["@removed"],
        json!({ "reason": "deleted" })
    );
    assert!(
        find(&second, &kept).is_none(),
        "an unchanged user is not reported"
    );

    // A round with no changes reports nothing.
    let third = follow(&sim, &graph, second["@odata.deltaLink"].as_str().unwrap()).await;
    assert_eq!(third["value"], json!([]));
}

#[tokio::test]
async fn group_membership_changes_come_back_in_members_delta() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let alice = graph.create_user("alice@sim.test", "Alice").await;
    let bob = graph.create_user("bob@sim.test", "Bob").await;
    let group = graph.create_group("Team", &[&alice]).await;

    let first = graph.get_ok("/v1.0/groups/delta").await;
    // Microsoft's first example has members@delta without $select.
    assert_eq!(
        find(&first, &group).unwrap()["members@delta"],
        json!([{ "@odata.type": "#microsoft.graph.user", "id": alice }])
    );

    graph
        .post(
            &format!("/v1.0/groups/{group}/members/$ref"),
            &json!({ "@odata.id": format!("https://graph.microsoft.com/v1.0/directoryObjects/{bob}") }),
        )
        .await;
    graph
        .delete(&format!("/v1.0/groups/{group}/members/{alice}/$ref"))
        .await;

    let second = follow(&sim, &graph, first["@odata.deltaLink"].as_str().unwrap()).await;
    let changes = find(&second, &group).unwrap()["members@delta"]
        .as_array()
        .unwrap()
        .clone();
    assert!(changes.contains(&json!({ "@odata.type": "#microsoft.graph.user", "id": bob })));
    assert!(changes.contains(&json!({
        "@odata.type": "#microsoft.graph.user",
        "id": alice,
        "@removed": { "reason": "deleted" }
    })));
}

#[tokio::test]
async fn latest_starts_from_now_without_data() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    graph.create_user("before@sim.test", "Before").await;

    let latest = graph.get_ok("/v1.0/users/delta?$deltatoken=latest").await;
    assert_eq!(latest["value"], json!([]));

    let after = graph.create_user("after@sim.test", "After").await;
    let next = follow(&sim, &graph, latest["@odata.deltaLink"].as_str().unwrap()).await;
    let ids: Vec<&str> = next["value"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|entry| entry["id"].as_str())
        .collect();
    assert_eq!(ids, [after.as_str()]);
}

#[tokio::test]
async fn select_limits_what_is_tracked_and_returned() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let carol = graph.create_user("carol@sim.test", "Carol").await;

    let first = graph.get_ok("/v1.0/users/delta?$select=displayName").await;
    let entry = find(&first, &carol).unwrap();
    assert_eq!(entry, &json!({ "id": carol, "displayName": "Carol" }));

    // "If a change occurs to a property that isn't selected, the resource for which that
    // property changed doesn't appear in the delta response".
    graph
        .patch(
            &format!("/v1.0/users/{carol}"),
            &json!({ "jobTitle": "Engineer" }),
        )
        .await;
    let second = follow(&sim, &graph, first["@odata.deltaLink"].as_str().unwrap()).await;
    assert!(find(&second, &carol).is_none(), "{second}");

    graph
        .patch(
            &format!("/v1.0/users/{carol}"),
            &json!({ "displayName": "Carol Example" }),
        )
        .await;
    let third = follow(&sim, &graph, second["@odata.deltaLink"].as_str().unwrap()).await;
    assert_eq!(
        find(&third, &carol).unwrap()["displayName"],
        "Carol Example"
    );
}

#[tokio::test]
async fn a_filter_by_id_tracks_only_those_objects() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let watched = graph.create_user("watched@sim.test", "Watched").await;
    let other = graph.create_user("other@sim.test", "Other").await;

    let first = graph
        .get_ok(&format!("/v1.0/users/delta?$filter=id%20eq%20'{watched}'"))
        .await;
    assert!(find(&first, &watched).is_some());
    assert!(find(&first, &other).is_none());
}

#[tokio::test]
async fn top_expand_and_orderby_are_refused_for_users_and_groups() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    for query in ["$top=5", "$orderby=displayName", "$expand=members"] {
        let response = graph.get(&format!("/v1.0/groups/delta?{query}")).await;
        assert_eq!(response.status(), 400, "{query}");
    }
}

#[tokio::test]
async fn prefer_return_minimal_sends_only_changed_properties() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let dave = graph.create_user("dave@sim.test", "Dave").await;
    let first = graph.get_ok("/v1.0/users/delta").await;

    graph
        .patch(
            &format!("/v1.0/users/{dave}"),
            &json!({ "jobTitle": "Tester" }),
        )
        .await;
    let link = first["@odata.deltaLink"].as_str().unwrap();
    let response = sim
        .client
        .get(sim.url(link.strip_prefix(&sim.public_base_url).unwrap()))
        .bearer_auth(graph.token())
        .header("Prefer", "return=minimal")
        .send()
        .await
        .unwrap();
    let second: Value = response.json().await.unwrap();
    assert_eq!(
        find(&second, &dave).unwrap(),
        &json!({ "id": dave, "jobTitle": "Tester" })
    );
}

#[tokio::test]
async fn every_supported_collection_answers_on_every_spelling() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    for collection in [
        "users",
        "groups",
        "applications",
        "servicePrincipals",
        "directoryRoles",
        "oauth2PermissionGrants",
    ] {
        for function in ["delta", "delta()", "microsoft.graph.delta()"] {
            for version in ["v1.0", "beta"] {
                let page = graph
                    .get_ok(&format!("/{version}/{collection}/{function}"))
                    .await;
                assert!(
                    page["@odata.deltaLink"].is_string(),
                    "{collection}/{function}"
                );
            }
        }
    }
}

#[tokio::test]
async fn a_delta_query_needs_a_token() {
    let sim = Sim::start().await;
    let response = sim.get("/v1.0/users/delta").await;
    assert_eq!(response.status(), 401);
}
