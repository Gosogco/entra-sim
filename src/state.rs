//! State shared by every handler.

use std::sync::Arc;

use anyhow::{Context, Result};

use crate::auth::keys::SigningKey;
use crate::auth::sessions::{SessionStore, new_store as new_session_store};
use crate::config::Config;
use crate::store::snapshot::Snapshot;
use crate::store::{Directory, Store, bootstrap, new_store};

/// Cheap to clone; every field sits behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<SigningKey>,
    pub store: Store,
    /// Authorization codes and refresh tokens awaiting redemption.
    pub sessions: SessionStore,
}

impl AppState {
    /// Build state with a directory containing only the bootstrap objects.
    pub fn new(config: Config, signing_key: Arc<SigningKey>) -> Self {
        let mut directory = Directory::default();
        bootstrap::install(&mut directory, &config);
        Self {
            config: Arc::new(config),
            signing_key,
            store: new_store(directory),
            sessions: new_session_store(),
        }
    }

    /// Build state with the configured seed applied, failing if the seed cannot be read.
    pub async fn with_seed(config: Config, signing_key: Arc<SigningKey>) -> Result<Self> {
        let state = Self::new(config, signing_key);
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
