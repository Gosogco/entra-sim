//! Tests for the log of requests and events.

mod common;

use common::Sim;

#[tokio::test]
async fn the_log_is_off_without_a_directory() {
    let sim = Sim::start().await;
    let body = sim.get_json("/__sim__/logs").await;
    assert_eq!(body["enabled"], false);
    assert_eq!(body["total"], 0);
    assert_eq!(body["entries"], serde_json::json!([]));
}

#[tokio::test]
async fn the_log_pages_through_entries_from_an_earlier_run() {
    let sim = Sim::start_with_log(|config| {
        let dir = config.log_dir.as_ref().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        let lines: String = (0..5).map(|n| format!("{{\"n\":{n}}}\n")).collect();
        std::fs::write(dir.join(entra_sim::log::FILE_NAME), lines).unwrap();
    })
    .await;

    let seqs = |body: serde_json::Value| -> Vec<u64> {
        body["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|entry| entry["seq"].as_u64().unwrap())
            .collect()
    };

    let newest = sim.get_json("/__sim__/logs?limit=2").await;
    assert_eq!(newest["enabled"], true);
    assert_eq!(newest["total"], 5);
    assert_eq!(newest["entries"][0]["n"], 4);
    assert_eq!(seqs(newest), [4, 3]);
    assert_eq!(
        seqs(sim.get_json("/__sim__/logs?before=3&limit=2").await),
        [2, 1]
    );
    assert_eq!(
        seqs(sim.get_json("/__sim__/logs?after=1&limit=2").await),
        [3, 2]
    );
}

/// Every request entry in the log, newest first.
async fn requests(sim: &Sim) -> Vec<serde_json::Value> {
    sim.get_json("/__sim__/logs?limit=1000").await["entries"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|entry| entry["kind"] == "request")
        .cloned()
        .collect()
}

fn find<'a>(
    entries: &'a [serde_json::Value],
    method: &str,
    uri: &str,
) -> Option<&'a serde_json::Value> {
    entries
        .iter()
        .find(|entry| entry["method"] == method && entry["uri"] == uri)
}

#[tokio::test]
async fn a_token_request_is_logged_with_both_bodies() {
    let sim = Sim::start_with_log(|_| {}).await;
    let token = sim.client_credentials_token().await;

    let entries = requests(&sim).await;
    let uri = format!("/{}/oauth2/v2.0/token", sim.tenant_id);
    let entry = find(&entries, "POST", &uri).expect("the token request should be logged");
    assert_eq!(entry["status"], 200);
    assert!(entry["requestId"].is_string());
    assert!(entry["durationMs"].is_number());
    let request_body = entry["requestBody"].as_str().unwrap();
    assert!(
        request_body.contains("grant_type=client_credentials"),
        "{request_body}"
    );
    assert!(
        request_body.contains(&sim.bootstrap_client_secret),
        "{request_body}"
    );
    let response_body = entry["responseBody"].as_str().unwrap();
    assert!(
        response_body.contains(token["access_token"].as_str().unwrap()),
        "{response_body}"
    );
}

#[tokio::test]
async fn a_graph_request_is_logged_with_its_headers_and_json() {
    let sim = Sim::start_with_log(|_| {}).await;
    let graph = sim.graph().await;
    graph
        .post_created(
            "/v1.0/users",
            &serde_json::json!({
                "displayName": "Alice Example",
                "userPrincipalName": "alice@sim.test",
                "accountEnabled": true
            }),
        )
        .await;

    let entries = requests(&sim).await;
    let entry = find(&entries, "POST", "/v1.0/users").expect("the Graph request should be logged");
    assert_eq!(entry["status"], 201);
    assert!(
        entry["requestHeaders"]["authorization"]
            .as_str()
            .unwrap()
            .starts_with("Bearer "),
    );
    assert_eq!(entry["responseHeaders"]["content-type"], "application/json");
    let sent: serde_json::Value =
        serde_json::from_str(entry["requestBody"].as_str().unwrap()).unwrap();
    assert_eq!(sent["userPrincipalName"], "alice@sim.test");
    let created: serde_json::Value =
        serde_json::from_str(entry["responseBody"].as_str().unwrap()).unwrap();
    assert_eq!(created["displayName"], "Alice Example");
}

#[tokio::test]
async fn the_studios_reads_are_left_out_but_control_writes_are_logged() {
    let sim = Sim::start_with_log(|_| {}).await;
    sim.get_json("/__sim__/health").await;
    sim.get_json("/__sim__/snapshot").await;
    sim.get_json("/__sim__/tokens").await;
    sim.post_json("/__sim__/reset", &serde_json::json!({}))
        .await;

    let entries = requests(&sim).await;
    let uris: Vec<_> = entries.iter().map(|entry| &entry["uri"]).collect();
    assert_eq!(uris, ["/__sim__/reset"]);
}

#[tokio::test]
async fn an_unknown_path_is_logged_but_a_studio_file_is_not() {
    let dir = common::TempDir::new();
    std::fs::create_dir_all(&dir.0).unwrap();
    std::fs::write(dir.0.join("index.html"), "<title>studio</title>").unwrap();
    let studio = dir.0.clone();
    let sim = Sim::start_with_log(|config| config.studio_dir = Some(studio)).await;

    assert_eq!(sim.get("/").await.status(), 200);
    assert_eq!(sim.get("/index.html").await.status(), 200);
    assert_eq!(sim.get("/v1.0/nonexistent").await.status(), 404);

    let entries = requests(&sim).await;
    let uris: Vec<_> = entries.iter().map(|entry| &entry["uri"]).collect();
    assert_eq!(uris, ["/v1.0/nonexistent"]);
}
