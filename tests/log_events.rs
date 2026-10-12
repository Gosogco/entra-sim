//! Tests that events land in the log under the request that raised them.

mod common;

use common::Sim;

#[tokio::test]
async fn an_event_is_logged_under_the_request_that_raised_it() {
    use tracing_subscriber::layer::SubscriberExt;

    let sim = Sim::start_with_log(|_| {}).await;
    // A test runs on a single thread, server included, so a thread-local subscriber sees the
    // events the server raises. It sits in a binary of its own because a thread-local subscriber
    // can miss a span whose callsite a test on another thread reached first.
    let _subscriber = tracing::subscriber::set_default(
        tracing_subscriber::registry()
            .with(entra_sim::log::events::EventLayer(sim.log.clone().unwrap())),
    );

    let graph = sim.graph().await;
    let user = graph
        .post_created(
            "/v1.0/users",
            &serde_json::json!({
                "displayName": "Alice Example",
                "userPrincipalName": "alice@sim.test",
                "accountEnabled": true
            }),
        )
        .await;

    let entries = sim.get_json("/__sim__/logs?limit=1000").await["entries"]
        .as_array()
        .unwrap()
        .clone();
    let request = entries
        .iter()
        .find(|entry| entry["kind"] == "request" && entry["uri"] == "/v1.0/users")
        .expect("the request should be logged");
    let event = entries
        .iter()
        .find(|entry| entry["kind"] == "event" && entry["message"] == "created user")
        .expect("the creation should be logged");
    assert_eq!(event["requestId"], request["requestId"]);
    assert_eq!(event["level"], "INFO");
    assert_eq!(event["target"], "entra_sim::graph::users");
    assert_eq!(event["fields"]["user_id"], user["id"]);
    assert_eq!(event["fields"]["upn"], "alice@sim.test");
}
