//! State shared by every handler.

use std::sync::Arc;

use crate::auth::keys::SigningKey;
use crate::config::Config;
use crate::store::{Directory, Store, bootstrap, new_store};

/// Cheap to clone; every field sits behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<SigningKey>,
    pub store: Store,
}

impl AppState {
    /// Build state with a directory containing only the bootstrap client.
    pub fn new(config: Config, signing_key: Arc<SigningKey>) -> Self {
        let mut directory = Directory::default();
        bootstrap::install(&mut directory, &config);
        Self {
            config: Arc::new(config),
            signing_key,
            store: new_store(directory),
        }
    }
}
