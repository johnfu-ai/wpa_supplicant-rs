//! Structured logging with runtime level control.
//!
//! Per REQ-NF-DEPLOY-001 (#68).
//! Uses tracing-subscriber with reload handle for runtime log level changes.

use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

type ReloadFn = Arc<dyn Fn(EnvFilter) -> Result<()> + Send + Sync>;

/// Logging configuration and runtime handle.
///
/// Per REQ-NF-DEPLOY-001 (#68).
/// Supports runtime log level changes without restart.
pub struct Logging {
    /// Handle to reload the filter at runtime (type-erased).
    handle: ReloadFn,
}

impl Logging {
    /// Initialize structured logging with the given level.
    ///
    /// Returns a `Logging` handle that can change the log level at runtime.
    pub fn init(level: &str) -> Result<Self> {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

        let (reload_layer, reload_handle): (
            reload::Layer<EnvFilter, tracing_subscriber::Registry>,
            _,
        ) = reload::Layer::new(filter);

        let subscriber = tracing_subscriber::registry().with(reload_layer);

        subscriber.try_init()?;

        let handle: ReloadFn = Arc::new(move |new_filter: EnvFilter| -> Result<()> {
            reload_handle.reload(new_filter)?;
            Ok(())
        });

        Ok(Self { handle })
    }

    /// Change the log level at runtime without restart.
    ///
    /// Per REQ-NF-DEPLOY-001 (#68) acceptance criteria.
    pub fn set_level(&self, level: &str) -> Result<()> {
        let new_filter = EnvFilter::new(level);
        (self.handle)(new_filter)
    }

    /// Create a Logging handle from a reload function (for testing).
    #[cfg(test)]
    fn from_fn(handle: ReloadFn) -> Self {
        Self { handle }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Log level can be changed at runtime via handle.
    #[test]
    fn test_logging_set_level() {
        let filter = EnvFilter::new("warn");
        let (reload_layer, reload_handle): (
            reload::Layer<EnvFilter, tracing_subscriber::Registry>,
            _,
        ) = reload::Layer::new(filter);

        let handle: ReloadFn = Arc::new(move |new_filter: EnvFilter| -> Result<()> {
            reload_handle.reload(new_filter)?;
            Ok(())
        });

        let logging = Logging::from_fn(handle);
        assert!(logging.set_level("trace").is_ok());
        assert!(logging.set_level("error").is_ok());
        assert!(logging.set_level("info").is_ok());

        // Suppress unused variable warning
        let _ = reload_layer;
    }

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Set level with crate-level directive works.
    #[test]
    fn test_logging_set_level_directive() {
        let filter = EnvFilter::new("info");
        let (_reload_layer, reload_handle): (
            reload::Layer<EnvFilter, tracing_subscriber::Registry>,
            _,
        ) = reload::Layer::new(filter);

        let handle: ReloadFn = Arc::new(move |new_filter: EnvFilter| -> Result<()> {
            reload_handle.reload(new_filter)?;
            Ok(())
        });

        let logging = Logging::from_fn(handle);
        assert!(logging.set_level("wpa_supplicant=debug").is_ok());
    }

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Multiple level changes in sequence work.
    #[test]
    fn test_logging_multiple_level_changes() {
        let filter = EnvFilter::new("error");
        let (_reload_layer, reload_handle): (
            reload::Layer<EnvFilter, tracing_subscriber::Registry>,
            _,
        ) = reload::Layer::new(filter);

        let handle: ReloadFn = Arc::new(move |new_filter: EnvFilter| -> Result<()> {
            reload_handle.reload(new_filter)?;
            Ok(())
        });

        let logging = Logging::from_fn(handle);
        for level in &["trace", "debug", "info", "warn", "error"] {
            assert!(logging.set_level(level).is_ok());
        }
    }
}
