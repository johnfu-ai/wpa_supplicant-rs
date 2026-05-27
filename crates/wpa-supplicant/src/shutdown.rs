//! Graceful shutdown handler.
//!
//! Per REQ-NF-DEPLOY-002 (#69).
//! Catches SIGTERM/SIGINT and sets shutdown flag within 5 seconds.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;

/// Graceful shutdown handler.
///
/// Per REQ-NF-DEPLOY-002 (#69).
/// Catches SIGTERM/SIGINT and sets a shutdown flag.
pub struct ShutdownHandler {
    /// Shutdown flag shared with signal handler.
    shutdown: Arc<AtomicBool>,
}

/// Maximum time to complete in-flight operations after signal.
pub const SHUTDOWN_TIMEOUT_SECS: u64 = 5;

impl ShutdownHandler {
    /// Create a new shutdown handler without installing signal handlers.
    ///
    /// For use in tests or when signal handling is managed externally.
    pub fn new() -> Self {
        Self {
            shutdown: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Install signal handlers for SIGTERM and SIGINT.
    ///
    /// Per REQ-NF-DEPLOY-002 (#69).
    /// Sets the shutdown flag when either signal is received.
    pub fn install() -> Result<Self> {
        let handler = Self::new();
        let shutdown = handler.shutdown.clone();

        // Register SIGTERM handler
        let sigterm = signal_hook::consts::SIGTERM;
        signal_hook::flag::register(sigterm, Arc::clone(&shutdown))?;

        // Register SIGINT handler
        let sigint = signal_hook::consts::SIGINT;
        signal_hook::flag::register(sigint, Arc::clone(&shutdown))?;

        Ok(handler)
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Request shutdown programmatically.
    pub fn request_shutdown(&self) {
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Wait for shutdown with a timeout.
    ///
    /// Returns `Ok(())` if shutdown was requested within the timeout,
    /// `Err` if the timeout expired.
    pub fn wait_with_timeout(&self, timeout: std::time::Duration) -> Result<()> {
        let start = std::time::Instant::now();
        while !self.is_shutdown() {
            if start.elapsed() >= timeout {
                anyhow::bail!("shutdown timeout exceeded");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        Ok(())
    }

    /// Get the shutdown timeout duration.
    pub fn timeout() -> std::time::Duration {
        std::time::Duration::from_secs(SHUTDOWN_TIMEOUT_SECS)
    }
}

impl Default for ShutdownHandler {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// ShutdownHandler starts with shutdown=false.
    #[test]
    fn test_shutdown_initial_state() {
        let handler = ShutdownHandler::new();
        assert!(!handler.is_shutdown());
    }

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// Programmatic shutdown request sets the flag.
    #[test]
    fn test_shutdown_request() {
        let handler = ShutdownHandler::new();
        assert!(!handler.is_shutdown());
        handler.request_shutdown();
        assert!(handler.is_shutdown());
    }

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// wait_with_timeout returns Ok when shutdown requested.
    #[test]
    fn test_shutdown_wait_immediate() {
        let handler = ShutdownHandler::new();
        handler.request_shutdown();
        let result = handler.wait_with_timeout(std::time::Duration::from_secs(1));
        assert!(result.is_ok());
    }

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// wait_with_timeout returns Err on timeout.
    #[test]
    fn test_shutdown_wait_timeout() {
        let handler = ShutdownHandler::new();
        let result = handler.wait_with_timeout(std::time::Duration::from_millis(100));
        assert!(result.is_err());
    }

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// Timeout constant is 5 seconds per spec.
    #[test]
    fn test_shutdown_timeout_value() {
        assert_eq!(
            ShutdownHandler::timeout(),
            std::time::Duration::from_secs(5)
        );
    }

    /// Verifies: #69 (REQ-NF-DEPLOY-002)
    /// Default trait implementation works.
    #[test]
    fn test_shutdown_default() {
        let handler = ShutdownHandler::default();
        assert!(!handler.is_shutdown());
    }
}
