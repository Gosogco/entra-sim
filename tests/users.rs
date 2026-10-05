//! Tests for the /users collection, OData query options and the dual version prefixes.

mod common;

use common::{Graph, Sim};
use serde_json::json;

async fn create_user(graph: &Graph, upn: &str, display_name: &str) -> serde_json::Value {
    graph
        .post_created(
            "/v1.0/users",
            &json!({
                "accountEnabled": true,
                "displayName": display_name,
                "userPrincipalName": upn,
                "mailNickname": upn.split('@').next().unwrap(),
                "passwordProfile": { "password": "Sup3rSecret!" }
            }),
        )
        .await
}

#[tokio::test]
async fn a_created_user_can_be_read_back() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = create_user(&graph, "alice@sim.test", "Alice Example").await;
    let id = created["id"].as_str().expect("a generated object ID");
    assert_eq!(created["userPrincipalName"], "alice@sim.test");
    assert_eq!(created["displayName"], "Alice Example");
    assert_eq!(created["accountEnabled"], true);
    // Graph defaults userType for a new member account.
    assert_eq!(created["userType"], "Member");

    let fetched = graph.get_ok(&format!("/v1.0/users/{id}")).await;
    assert_eq!(fetched["id"], created["id"]);
    assert!(
        fetched["@odata.context"]
            .as_str()
            .unwrap()
            .contains("users"),
        "a single object response should carry @odata.context"
    );
}

#[tokio::test]
async fn the_password_is_never_returned() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = create_user(&graph, "alice@sim.test", "Alice Example").await;
    let id = created["id"].as_str().unwrap();
    let fetched = graph.get_ok(&format!("/v1.0/users/{id}")).await;

    // Graph has no readable password property; a password written through passwordProfile must
    // not come back out.
    for body in [&created, &fetched] {
        let serialised = body.to_string();
        assert!(
            !serialised.contains("Sup3rSecret!"),
            "the password leaked into {serialised}"
        );
        assert!(body["passwordProfile"].is_null());
    }
}

#[tokio::test]
async fn unrecognised_properties_round_trip() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    // The azuread provider writes many properties the simulator has no opinion about. Dropping
    // one would show up as a permanent diff on every plan.
    let created = graph
        .post_created(
            "/v1.0/users",
            &json!({
                "displayName": "Carol Example",
                "userPrincipalName": "carol@sim.test",
                "department": "Platform",
                "officeLocation": "Remote",
                "businessPhones": ["+44 20 7946 0000"]
            }),
        )
        .await;

    assert_eq!(created["department"], "Platform");
    assert_eq!(created["officeLocation"], "Remote");

    let id = created["id"].as_str().unwrap();
    let fetched = graph.get_ok(&format!("/v1.0/users/{id}")).await;
    assert_eq!(fetched["department"], "Platform");
    assert_eq!(fetched["businessPhones"][0], "+44 20 7946 0000");
}

#[tokio::test]
async fn the_same_routes_answer_under_v1_and_beta() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let created = create_user(&graph, "dave@sim.test", "Dave Example").await;
    let id = created["id"].as_str().unwrap();

    // The azuread provider uses the beta clients for groups, applications, users and service
    // principals, so beta is not optional.
    let from_beta = graph.get_ok(&format!("/beta/users/{id}")).await;
    assert_eq!(from_beta["id"], created["id"]);

    let listed = graph.get_ok("/beta/users").await;
    assert_eq!(listed["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn graph_routes_require_a_bearer_token() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph.get_anonymous("/v1.0/users").await;
    assert_eq!(response.status(), 401);
    assert_eq!(
        response.headers().get("www-authenticate").unwrap(),
        "Bearer",
        "a 401 should tell the client which scheme to use"
    );
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "InvalidAuthenticationToken");
}

#[tokio::test]
async fn filtering_by_principal_name_is_case_insensitive() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "erin@sim.test", "Erin Example").await;
    create_user(&graph, "frank@sim.test", "Frank Example").await;

    let matched = graph
        .get_ok("/v1.0/users?$filter=userPrincipalName%20eq%20'ERIN@SIM.TEST'")
        .await;
    let found = matched["value"].as_array().unwrap();
    assert_eq!(found.len(), 1, "got {matched}");
    assert_eq!(found[0]["displayName"], "Erin Example");
}

#[tokio::test]
async fn startswith_filters_the_collection() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "gail@sim.test", "Gail Example").await;
    create_user(&graph, "hank@sim.test", "Hank Example").await;

    let matched = graph
        .get_ok("/v1.0/users?$filter=startswith(displayName,'Gail')")
        .await;
    assert_eq!(matched["value"].as_array().unwrap().len(), 1);
}

#[tokio::test]
async fn select_narrows_the_properties_returned() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "ivy@sim.test", "Ivy Example").await;

    let listed = graph.get_ok("/v1.0/users?$select=displayName").await;
    let first = &listed["value"][0];
    assert_eq!(first["displayName"], "Ivy Example");
    // id is always returned, because clients need it to address the object.
    assert!(first["id"].is_string());
    assert!(
        first["userPrincipalName"].is_null(),
        "unselected properties should be omitted, got {first}"
    );
}

#[tokio::test]
async fn count_is_returned_only_when_asked_for() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "jane@sim.test", "Jane Example").await;
    create_user(&graph, "karl@sim.test", "Karl Example").await;

    let without = graph.get_ok("/v1.0/users").await;
    assert!(without["@odata.count"].is_null());

    let with = graph.get_ok("/v1.0/users?$count=true").await;
    assert_eq!(with["@odata.count"].as_u64().unwrap(), 2);
}

#[tokio::test]
async fn paging_walks_the_whole_collection_without_repeats() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    for index in 0..5 {
        create_user(
            &graph,
            &format!("user{index}@sim.test"),
            &format!("User {index}"),
        )
        .await;
    }

    let mut seen = Vec::new();
    let mut path = "/v1.0/users?$top=2".to_string();
    loop {
        let page = graph.get_ok(&path).await;
        let values = page["value"].as_array().unwrap();
        assert!(values.len() <= 2, "a page exceeded $top");
        seen.extend(
            values
                .iter()
                .map(|user| user["id"].as_str().unwrap().to_string()),
        );

        match page["@odata.nextLink"].as_str() {
            // The next link is absolute, so follow only its path and query.
            Some(next) => {
                path = next
                    .split_once(&sim.public_base_url)
                    .expect("nextLink should sit under the advertised base URL")
                    .1
                    .to_string();
            }
            None => break,
        }
    }

    assert_eq!(seen.len(), 5, "paging should visit every user exactly once");
    let unique: std::collections::HashSet<_> = seen.iter().collect();
    assert_eq!(unique.len(), 5, "paging returned a duplicate: {seen:?}");
}

#[tokio::test]
async fn orderby_sorts_descending() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "a@sim.test", "Anna").await;
    create_user(&graph, "c@sim.test", "Clara").await;
    create_user(&graph, "b@sim.test", "Bella").await;

    let listed = graph
        .get_ok("/v1.0/users?$orderby=displayName%20desc")
        .await;
    let names: Vec<&str> = listed["value"]
        .as_array()
        .unwrap()
        .iter()
        .map(|user| user["displayName"].as_str().unwrap())
        .collect();
    assert_eq!(names, ["Clara", "Bella", "Anna"]);
}

#[tokio::test]
async fn a_malformed_filter_is_rejected_not_ignored() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "liam@sim.test", "Liam Example").await;

    // Silently returning every user would be far worse than an error.
    let response = graph
        .get(" /v1.0/users?$filter=displayName%20equals%20'Liam'".trim())
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Request_UnsupportedQuery");
}

#[tokio::test]
async fn top_outside_the_allowed_range_is_rejected() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    for value in ["0", "1000", "abc"] {
        let response = graph.get(&format!("/v1.0/users?$top={value}")).await;
        assert_eq!(response.status(), 400, "$top={value} should be rejected");
    }
}

#[tokio::test]
async fn a_user_can_be_patched_and_deleted() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    let created = create_user(&graph, "mia@sim.test", "Mia Example").await;
    let id = created["id"].as_str().unwrap();

    let patched = graph
        .patch(
            &format!("/v1.0/users/{id}"),
            &json!({ "jobTitle": "Engineer", "accountEnabled": false }),
        )
        .await;
    // Graph answers a successful PATCH with no body.
    assert_eq!(patched.status(), 204);

    let fetched = graph.get_ok(&format!("/v1.0/users/{id}")).await;
    assert_eq!(fetched["jobTitle"], "Engineer");
    assert_eq!(fetched["accountEnabled"], false);

    assert_eq!(
        graph.delete(&format!("/v1.0/users/{id}")).await.status(),
        204
    );
    assert_eq!(graph.get(&format!("/v1.0/users/{id}")).await.status(), 404);
}

#[tokio::test]
async fn a_user_can_be_addressed_by_principal_name() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "nina@sim.test", "Nina Example").await;

    // Graph accepts either the object ID or the userPrincipalName in the path.
    let fetched = graph.get_ok("/v1.0/users/nina@sim.test").await;
    assert_eq!(fetched["displayName"], "Nina Example");
}

#[tokio::test]
async fn a_duplicate_principal_name_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;
    create_user(&graph, "olive@sim.test", "Olive Example").await;

    let response = graph
        .post(
            "/v1.0/users",
            &json!({ "displayName": "Impostor", "userPrincipalName": "OLIVE@sim.test" }),
        )
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert!(
        body["error"]["message"]
            .as_str()
            .unwrap()
            .contains("already exists"),
        "got {body}"
    );
}

#[tokio::test]
async fn a_missing_required_property_is_refused() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph
        .post(
            "/v1.0/users",
            &json!({ "displayName": "No Principal Name" }),
        )
        .await;
    assert_eq!(response.status(), 400);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Request_BadRequest");
    assert!(
        body["error"]["innerError"]["request-id"].is_string(),
        "the error envelope should carry innerError identifiers"
    );
}

#[tokio::test]
async fn a_missing_user_is_a_graph_not_found() {
    let sim = Sim::start().await;
    let graph = sim.graph().await;

    let response = graph.get("/v1.0/users/does-not-exist").await;
    assert_eq!(response.status(), 404);
    let body: serde_json::Value = response.json().await.unwrap();
    assert_eq!(body["error"]["code"], "Request_ResourceNotFound");
}
