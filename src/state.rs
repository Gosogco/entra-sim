//! State shared by every handler.

use std::sync::Arc;

use crate::auth::keys::SigningKey;
use crate::config::Config;

/// Cheap to clone; every field sits behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
    pub signing_key: Arc<SigningKey>,
}

impl AppState {
    pub fn new(config: Config, signing_key: Arc<SigningKey>) -> Self {
        Self {
            config: Arc::new(config),
            signing_key,
        }
    }
}
