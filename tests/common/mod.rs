//! Shared harness: start the simulator in-process on an ephemeral port.
//!
//! Tests exercise the plain HTTP listener. TLS is a transport concern verified separately, and
//! binding it per test would mean minting a certificate for every case.

#![allow(dead_code)]

use std::net::{Ipv4Addr, SocketAddr};

use clap::Parser;
use entra_sim::config::Config;
use entra_sim::state::AppState;

pub struct Sim {
    pub base_url: String,
    pub public_base_url: String,
    pub tenant_id: String,
    pub client: reqwest::Client,
}

impl Sim {
    /// Start a simulator with default configuration.
    pub async fn start() -> Self {
        Self::start_with(|_| {}).await
    }

    /// Start a simulator, letting the caller adjust the configuration first.
    pub async fn start_with(adjust: impl FnOnce(&mut Config)) -> Self {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("binding an ephemeral port");
        let addr = listener.local_addr().expect("reading the bound address");

        // Parse with no arguments so the clap defaults stay the single source of truth.
        let mut config = Config::parse_from(["entra-sim"]);
        // Advertise the address we actually bound, so emitted URLs are reachable.
        config.public_host = addr.to_string();
        adjust(&mut config);

        let tenant_id = config.tenant_id.clone();
        let public_base_url = config.public_base_url();
        let app = entra_sim::router(AppState::new(config));

        tokio::spawn(async move {
            axum::serve(listener, app).await.expect("serving");
        });

        Self {
            base_url: format!("http://{addr}"),
            public_base_url,
            tenant_id,
            client: reqwest::Client::new(),
        }
    }

    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    pub async fn get(&self, path: &str) -> reqwest::Response {
        self.client
            .get(self.url(path))
            .send()
            .await
            .expect("sending request")
    }

    pub async fn get_json(&self, path: &str) -> serde_json::Value {
        let response = self.get(path).await;
        assert!(
            response.status().is_success(),
            "GET {path} returned {}",
            response.status()
        );
        response.json().await.expect("decoding JSON")
    }
}
