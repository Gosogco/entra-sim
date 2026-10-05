use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{Context, Result};
use axum_server::tls_rustls::RustlsConfig;
use clap::Parser;
use entra_sim::auth::keys::SigningKey;
use entra_sim::config::Config;
use entra_sim::state::AppState;
use entra_sim::{router, tls};
use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("ENTRA_SIM_LOG").unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    run(Config::parse()).await
}

async fn run(config: Config) -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|_| anyhow::anyhow!("installing the ring crypto provider"))?;

    let http_addr = SocketAddr::new(config.bind, config.http_port);
    let https_addr = SocketAddr::new(config.bind, config.https_port);

    let tls = if config.no_tls {
        None
    } else {
        Some(build_tls(&config).await?)
    };

    let signing_key = Arc::new(load_signing_key(&config).await?);
    info!(kid = %signing_key.kid, "token signing key ready");

    let app = router(AppState::new(config, signing_key));

    let http = {
        let app = app.clone();
        tokio::spawn(async move {
            let listener = tokio::net::TcpListener::bind(http_addr)
                .await
                .with_context(|| format!("binding {http_addr}"))?;
            info!(address = %http_addr, "serving HTTP");
            axum::serve(listener, app).await.context("serving HTTP")
        })
    };

    let https = tokio::spawn(async move {
        let Some(tls) = tls else {
            // Nothing to serve; park so that `try_join` still waits on the HTTP listener.
            return std::future::pending().await;
        };
        info!(address = %https_addr, "serving HTTPS");
        axum_server::bind_rustls(https_addr, tls)
            .serve(app.into_make_service())
            .await
            .context("serving HTTPS")
    });

    // Either listener failing takes the process down, so a misconfiguration is loud.
    tokio::try_join!(flatten(http), flatten(https))?;
    Ok(())
}

async fn load_signing_key(config: &Config) -> Result<SigningKey> {
    match &config.signing_key {
        Some(path) => {
            let pem = tokio::fs::read_to_string(path)
                .await
                .with_context(|| format!("reading signing key {}", path.display()))?;
            SigningKey::from_pkcs8_pem(&pem)
        }
        None => {
            // Generating an RSA 2048 key can take a noticeable moment, and this is the first
            // thing that happens at startup, so say so rather than appear hung.
            info!("generating a token signing key");
            SigningKey::generate()
        }
    }
}

async fn build_tls(config: &Config) -> Result<RustlsConfig> {
    let material = tls::load_or_generate(
        config.tls_cert.as_deref(),
        config.tls_key.as_deref(),
        &config.tls_sans,
    )
    .await?;

    if let (Some(ca_pem), Some(path)) = (&material.ca_pem, &config.ca_out) {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        tokio::fs::write(path, ca_pem)
            .await
            .with_context(|| format!("writing CA certificate to {}", path.display()))?;
        info!(path = %path.display(), "wrote CA certificate");
    }

    RustlsConfig::from_pem(
        material.chain_pem.into_bytes(),
        material.key_pem.into_bytes(),
    )
    .await
    .context("building the TLS server configuration")
}

async fn flatten(handle: tokio::task::JoinHandle<Result<()>>) -> Result<()> {
    handle.await.context("server task panicked")?
}
