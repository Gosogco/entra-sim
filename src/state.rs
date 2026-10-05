//! State shared by every handler.

use std::sync::Arc;

use crate::config::Config;

/// Cheap to clone; every field sits behind an `Arc`.
#[derive(Clone)]
pub struct AppState {
    pub config: Arc<Config>,
}

impl AppState {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }
}
