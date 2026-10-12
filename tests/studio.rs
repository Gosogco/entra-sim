//! Tests for serving the studio's files at `/`.

mod common;

use std::path::PathBuf;

use common::Sim;

/// A directory holding a stand-in for the built studio. Named per test, because the tests in
/// one binary share a process ID and run concurrently.
fn studio_dir(test: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("entra-sim-studio-{test}-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("index.html"), "<title>entra-sim studio</title>").unwrap();
    dir
}

#[tokio::test]
async fn the_studio_is_served_at_the_root() {
    let dir = studio_dir("root");
    let sim = Sim::start_with(|config| config.studio_dir = Some(dir.clone())).await;

    let response = sim
        .client
        .get(format!("{}/", sim.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.text().await.unwrap(),
        "<title>entra-sim studio</title>"
    );

    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn an_unknown_path_is_still_not_found() {
    let dir = studio_dir("unknown");
    let sim = Sim::start_with(|config| config.studio_dir = Some(dir.clone())).await;

    let response = sim
        .client
        .get(format!("{}/v1.0/nonexistent", sim.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);

    std::fs::remove_dir_all(dir).unwrap();
}

#[tokio::test]
async fn nothing_is_served_at_the_root_without_a_studio() {
    let sim = Sim::start().await;

    let response = sim
        .client
        .get(format!("{}/", sim.base_url))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 404);
}
