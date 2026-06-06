//! IEEE 802.1X-2020 Supplicant — binary entry point.
//!
//! Implements: INT-001 (#109) — Wire config-load → Supplicant
//! construction → event loop in main.rs.
//! Per REQ-NF-DEPLOY-002 (#69) — graceful shutdown on SIGTERM / SIGINT.
//! Per REQ-NF-DEPLOY-003 (#70) — configuration file support.
//! Architecture: #85 (ARC-C-WPA-005), #79 (ADR-EVT-007).
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::path::PathBuf;
use std::thread;
use std::time::Duration;

use wpa_supplicant::{Config, Logging, NoopNetworkIo, ShutdownHandler, Supplicant};

/// Default path for the configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/wpa_supplicant-rs.toml";

/// Tick cadence: sleep at most this long between `tick()` calls to
/// keep MKA Hello-timer jitter within Cl.9 bounds per INT-003 (#111).
pub const TICK_SLEEP_MS: u64 = 100;

fn main() {
    // --- Logging ---
    let logging = Logging::init("info").expect("failed to initialize logging");

    tracing::info!("wpa_supplicant-rs starting");

    // --- Signal handling ---
    let shutdown_handler = ShutdownHandler::install().expect("failed to install signal handlers");

    // --- CLI args ---
    let config_path = parse_config_path();
    tracing::debug!(?config_path, "loading configuration");

    // --- Config load ---
    let config = match Config::load(&config_path) {
        Ok(c) => c,
        Err(e) => {
            tracing::error!(error = %e, path = %config_path.display(), "failed to load config");
            std::process::exit(1);
        }
    };
    tracing::info!(
        interface = %config.interface,
        "configuration loaded"
    );

    // --- Network I/O ---
    // INT-001 (#109) uses the `NoopNetworkIo` stub. A real L2 raw-socket
    // binding (`RawSocketNetworkIo`) is tracked as a Phase-06 follow-up.
    let network = NoopNetworkIo::new([0x02, 0x00, 0x00, 0x00, 0x00, 0x00], true);

    // --- Supplicant construction with logging handle ---
    let mut supp = match Supplicant::with_logging(config, network, logging) {
        Ok(s) => s,
        Err(e) => {
            tracing::error!(error = %e, "failed to construct Supplicant");
            std::process::exit(1);
        }
    };

    // --- Event loop ---
    // Per ADR-EVT-007 (#79): poll `ShutdownHandler` and
    // `Supplicant::is_shutdown()` on every iteration so either the OS
    // signal or a control-socket `SHUTDOWN` command stops the daemon
    // cleanly. Per INT-003 (#111): sleep at most TICK_SLEEP_MS between
    // ticks so MKA timers meet their Cl.9 jitter bounds.
    tracing::info!("event loop started");

    while !shutdown_handler.is_shutdown() && !supp.is_shutdown() {
        if let Err(e) = supp.tick() {
            // Per ADR-EVT-007 (#79): a single tick error must not abort
            // the daemon. Log at `error` and continue.
            tracing::error!(error = %e, "event-loop tick error");
        }
        // Drain PaeEvents pushed by tick().
        // Per INT-005 (#113): MKA-transmitted MKPDUs and SAK install
        // events are routed inside dispatch_event; no event accumulator
        // is surfaced from tick() today — the Vec<PaeEvent> return is
        // preserved for integration-test assertions only. A future INT
        // may wire a separate dispatch here if the per-event cost of
        // re-entering dispatch_event is too high.
        thread::sleep(Duration::from_millis(TICK_SLEEP_MS));
    }

    tracing::info!("shutdown complete");
}

/// Parse the `--config` argument from CLI args, or get the default path.
///
/// Accepts: `wpa-supplicant --config /path/to/config.toml`
/// Defaults to: [`DEFAULT_CONFIG_PATH`] when `--config` is omitted.
/// On an unrecognized flag (e.g. `--help` or `--unknown`), logs a
/// `warn` and falls back to the default — the daemon does not abort
/// on CLI grammar errors in this initial pass. A future Phase-07 task
/// will add proper `clap`-style argument validation.
fn parse_config_path() -> PathBuf {
    let mut args = std::env::args().skip(1).peekable();
    while let Some(arg) = args.next() {
        if arg == "--config" {
            if let Some(path) = args.next() {
                return PathBuf::from(path);
            } else {
                tracing::warn!("--config flag without value; falling back to default path");
                break;
            }
        } else if arg.starts_with("--config=") {
            // Also accept --config=<path> syntax
            if let Some(path) = arg.strip_prefix("--config=") {
                if !path.is_empty() {
                    return PathBuf::from(path);
                }
            }
            tracing::warn!("--config= flag with empty value; falling back to default path");
            break;
        } else {
            tracing::warn!(%arg, "unrecognized CLI flag; ignoring");
        }
    }
    PathBuf::from(DEFAULT_CONFIG_PATH)
}
