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
