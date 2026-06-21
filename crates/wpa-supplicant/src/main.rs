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

// Per #144 / TEST-VV-006 (REQ-NF-SEC-002): forbid `.unwrap()` / `.expect()`
// in production code. The two `.expect()` calls below are the documented
// fatal-init residuals — startup cannot proceed without logging or signal
// handling, so panicking with a message is the desired behavior.
#![warn(clippy::unwrap_used, clippy::expect_used)]

use std::path::PathBuf;
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use wpa_supplicant::{Config, Logging, NetworkIo, ShutdownHandler, Supplicant};

#[cfg(not(feature = "raw-socket"))]
use wpa_supplicant::NoopNetworkIo;
#[cfg(feature = "raw-socket")]
use wpa_supplicant::RawSocketNetworkIo;

/// Default path for the configuration file.
pub const DEFAULT_CONFIG_PATH: &str = "/etc/wpa_supplicant-rs.toml";

/// Tick cadence: sleep at most this long between `tick()` calls to
/// keep MKA Hello-timer jitter within Cl.9 bounds per INT-003 (#111).
pub const TICK_SLEEP_MS: u64 = 100;

fn main() {
    // --- Logging ---
    // Fatal init: the daemon cannot operate without logging. Documented
    // residual allow-listed per #144 / REQ-NF-SEC-002.
    #[allow(clippy::expect_used)]
    let logging = Logging::init("info").expect("failed to initialize logging");

    tracing::info!("wpa_supplicant-rs starting");

    // --- Signal handling ---
    // Fatal init: graceful-shutdown (REQ-NF-DEPLOY-002 / #69) depends on
    // signal handlers. Documented residual allow-listed per #144.
    #[allow(clippy::expect_used)]
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
    // Per #128: the `raw-socket` feature picks the real `AF_PACKET / SOCK_RAW`
    // backend; without it, the daemon still assembles end-to-end against the
    // `NoopNetworkIo` stub (acceptance criterion for INT-001 / #109). Both
    // backends are erased to `Arc<dyn NetworkIo>` so `Supplicant` instantiates
    // the same monomorphization either way — the blanket
    // `impl<T: NetworkIo + ?Sized> NetworkIo for Arc<T>` (network_io.rs:33)
    // makes this transparent.
    let network: Arc<dyn NetworkIo> = build_network(&config);

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

/// Construct the `NetworkIo` backend chosen at compile time.
///
/// * With `--features raw-socket`: a real `AF_PACKET / SOCK_RAW` socket bound
///   to `config.interface`. A `CAP_NET_RAW` failure surfaces here as a clear
///   `tracing::error!` plus non-zero exit, per the #128 acceptance criteria.
/// * Without the feature: a [`NoopNetworkIo`] stub that discards every
///   outbound frame — preserved so the daemon still assembles end-to-end on
///   hosts without `CAP_NET_RAW` (the INT-001 / #109 acceptance shape).
#[cfg(feature = "raw-socket")]
fn build_network(config: &Config) -> Arc<dyn NetworkIo> {
    match RawSocketNetworkIo::bind(&config.interface) {
        Ok(io) => {
            tracing::info!(
                interface = %config.interface,
                backend = "raw-socket",
                "network I/O bound"
            );
            Arc::new(io)
        }
        Err(e) => {
            tracing::error!(
                error = %e,
                interface = %config.interface,
                "failed to bind AF_PACKET socket — likely missing CAP_NET_RAW. \
                 Run as root or grant the capability with `setcap cap_net_raw+ep`."
            );
            std::process::exit(1);
        }
    }
}

#[cfg(not(feature = "raw-socket"))]
fn build_network(config: &Config) -> Arc<dyn NetworkIo> {
    tracing::warn!(
        interface = %config.interface,
        backend = "noop",
        "no `raw-socket` feature compiled in — using `NoopNetworkIo` stub; \
         the daemon will not exchange frames with peers"
    );
    Arc::new(NoopNetworkIo::new(
        [0x02, 0x00, 0x00, 0x00, 0x00, 0x00],
        true,
    ))
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
