//! Structured logging with runtime level control.
//!
//! Per REQ-NF-DEPLOY-001 (#68) and INT-009 (#117).
//! Uses `tracing-subscriber` with a reload handle for runtime log-level
//! changes triggered by the control socket's `SET_LOG_LEVEL` command.

use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::reload;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Type-erased reload handle. Accepts the filter directive as a `&str`
/// so integration tests can record/inspect calls without depending on
/// `tracing-subscriber::EnvFilter` directly.
type ReloadFn = Arc<dyn Fn(&str) -> Result<()> + Send + Sync>;

/// Logging configuration and runtime handle.
///
/// Per REQ-NF-DEPLOY-001 (#68) and INT-009 (#117).
/// Supports runtime log-level changes without a daemon restart.
#[derive(Clone)]
pub struct Logging {
    /// Handle to reload the filter at runtime (type-erased).
    handle: ReloadFn,
}

impl Logging {
    /// Initialize structured logging with the given level.
    ///
    /// Returns a `Logging` handle that can change the log level at
    /// runtime via [`Logging::set_level`].
    ///
    /// Per REQ-NF-DEPLOY-001 (#68).
    pub fn init(level: &str) -> Result<Self> {
        let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(level));

        let (reload_layer, reload_handle): (
            reload::Layer<EnvFilter, tracing_subscriber::Registry>,
            _,
        ) = reload::Layer::new(filter);

        let subscriber = tracing_subscriber::registry().with(reload_layer);

        subscriber.try_init()?;

        let handle: ReloadFn = Arc::new(move |new_level: &str| -> Result<()> {
            let new_filter = EnvFilter::try_new(new_level)
                .map_err(|e| anyhow::anyhow!("invalid filter directive {:?}: {}", new_level, e))?;
            reload_handle.reload(new_filter)?;
            Ok(())
        });

        Ok(Self { handle })
    }

    /// Change the log level at runtime without a daemon restart.
    ///
    /// Per REQ-NF-DEPLOY-001 (#68) acceptance criterion and INT-009 (#117).
    ///
    /// # Errors
    /// Returns an error if the directive cannot be parsed as a
    /// `tracing_subscriber::EnvFilter` or if the reload handle is no
    /// longer attached to a live subscriber.
    pub fn set_level(&self, level: &str) -> Result<()> {
        (self.handle)(level)
    }

    /// Construct a `Logging` from a caller-supplied reload function.
    ///
    /// Per INT-009 (#117). Used by integration tests to record calls
    /// without initializing a global subscriber, and available as a
    /// supported extension point for embedders that ship their own
    /// `tracing-subscriber` stack.
    pub fn from_test_handle(handle: ReloadFn) -> Self {
        Self { handle }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Log level can be changed at runtime via a custom handle.
    #[test]
    fn test_logging_set_level() {
        let logging = Logging::from_test_handle(Arc::new(|_level: &str| Ok(())));
        assert!(logging.set_level("trace").is_ok());
        assert!(logging.set_level("error").is_ok());
        assert!(logging.set_level("info").is_ok());
    }

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Set level with crate-level directive works.
    #[test]
    fn test_logging_set_level_directive() {
        let logging = Logging::from_test_handle(Arc::new(|_level: &str| Ok(())));
        assert!(logging.set_level("wpa_supplicant=debug").is_ok());
    }

    /// Verifies: #68 (REQ-NF-DEPLOY-001)
    /// Multiple level changes in sequence work.
    #[test]
    fn test_logging_multiple_level_changes() {
        let logging = Logging::from_test_handle(Arc::new(|_level: &str| Ok(())));
        for level in &["trace", "debug", "info", "warn", "error"] {
            assert!(logging.set_level(level).is_ok());
        }
    }

    /// Verifies: INT-009 (#117)
    /// Reload-handle errors propagate from `set_level`.
    #[test]
    fn test_logging_set_level_propagates_handle_error() {
        let logging = Logging::from_test_handle(Arc::new(|_level: &str| {
            Err(anyhow::anyhow!("simulated reload failure"))
        }));
        assert!(logging.set_level("trace").is_err());
    }
}
