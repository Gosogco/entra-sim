//! State shared by every handler.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::auth::keys::SigningKey;
use crate::auth::sessions::{SessionStore, new_store as new_session_store};
use crate::config::Config;
use crate::log::Log;
use crate::store::snapshot::Snapshot;
use crate::store::{Directory, Store, bootstrap, new_store};

/// Cheap to clone; every field sits behind an `Arc`.
///
/// A state is for one tenant: `config` and `store` are that tenant's. The rest is shared by every
/// tenant the simulator serves, and `tenants` reaches the others.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<SigningKey>,
    pub store: Store,
    /// Authorization codes and refresh tokens awaiting redemption.
    pub sessions: SessionStore,
    /// The record of requests and events, when the simulator was given somewhere to keep it.
    pub log: Option<Log>,
    /// Every tenant served, the primary one first.
    pub tenants: Arc<Vec<Tenant>>,
}

/// One tenant's configuration and directory.
#[derive(Clone)]
pub struct Tenant {
    pub config: Arc<Config>,
    pub store: Store,
}

impl AppState {
    /// Build state with directories containing only the bootstrap objects.
    ///
    /// Panics on a malformed additional tenant; `with_seed` reports one as an error instead.
    pub fn new(config: Config, signing_key: Arc<SigningKey>, log: Option<Log>) -> Self {
        let additional = config
            .additional_tenants()
            .expect("the additional tenants should have been checked by with_seed");
        let mut tenants = Vec::new();
        for tenant_config in std::iter::once(config.clone()).chain(
            additional
                .iter()
                .map(|(id, domain)| config.for_tenant(id, domain)),
        ) {
            let mut directory = Directory::default();
            bootstrap::install(&mut directory, &tenant_config);
            tenants.push(Tenant {
                config: Arc::new(tenant_config),
                store: new_store(directory),
            });
        }
        let primary = tenants[0].clone();
        Self {
            config: primary.config,
            signing_key,
            store: primary.store,
            sessions: new_session_store(),
            log,
            tenants: Arc::new(tenants),
        }
    }

    /// The state for the tenant `tenant_id`, if the simulator serves it.
    pub fn for_tenant(&self, tenant_id: &str) -> Option<AppState> {
        self.tenants
            .iter()
            .find(|tenant| tenant.config.tenant_id.eq_ignore_ascii_case(tenant_id))
            .map(|tenant| AppState {
                config: tenant.config.clone(),
                store: tenant.store.clone(),
                ..self.clone()
            })
    }

    /// The state of every tenant served, the primary one first.
    pub fn all_tenants(&self) -> Vec<AppState> {
        self.tenants
            .iter()
            .filter_map(|tenant| self.for_tenant(&tenant.config.tenant_id))
            .collect()
    }

    /// The tenant a path segment names, by ID or domain.
    pub fn tenant_named(&self, segment: &str) -> Option<AppState> {
        self.tenants
            .iter()
            .find(|tenant| {
                tenant.config.tenant_id.eq_ignore_ascii_case(segment)
                    || tenant.config.tenant_domain.eq_ignore_ascii_case(segment)
            })
            .and_then(|tenant| self.for_tenant(&tenant.config.tenant_id))
    }

    /// Build state with the configured seed applied, failing if the seed cannot be read.
    pub async fn with_seed(
        config: Config,
        signing_key: Arc<SigningKey>,
        log: Option<Log>,
    ) -> Result<Self> {
        config.additional_tenants()?;
        let state = Self::new(config, signing_key, log);
        let seeded = state.rebuild_initial_directory().await?;
        *state.store.write().await = seeded;
        Ok(state)
    }

    /// The directory as it should look at startup, and after a reset.
    ///
    /// Reading the seed each time rather than caching it means editing the file takes effect on
    /// the next reset, which is what makes it useful while iterating on a test fixture.
    pub async fn rebuild_initial_directory(&self) -> Result<Directory> {
        let mut directory = match &self.config.seed {
            None => Directory::default(),
            Some(path) => {
                let contents = tokio::fs::read_to_string(path)
                    .await
                    .with_context(|| format!("reading the seed file {}", path.display()))?;
                let snapshot: Snapshot = serde_json::from_str(&contents)
                    .with_context(|| format!("parsing the seed file {}", path.display()))?;
                snapshot.restore()
            }
        };

        // Installed after the seed so a seed can never leave the simulator without a usable
        // client, and so the bootstrap client's configuration always wins.
        bootstrap::install(&mut directory, &self.config);
        Ok(directory)
    }
}
