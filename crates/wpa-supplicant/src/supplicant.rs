//! Supplicant assembly and event loop.
//!
//! Wires together all protocol state machines (Supplicant PAE, EAP peer,
//! MKA, CP, Logon Process) into a single runnable application.
//!
//! Implements: ARC-C-WPA-005 (#85)
//! Architecture: ADR-EVT-007 (#79), ADR-SM-002 (#74)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use anyhow::Result;
use pae::PaeEvent;

use crate::config::Config;
use crate::control::ControlCommand;
use crate::network_io::NetworkIo;

/// Supplicant state exposed to the control interface.
#[derive(Debug, Clone, serde::Serialize)]
pub struct SupplicantState {
    /// Current PAE state.
    pub pae_state: String,
    /// Current CP state.
    pub cp_state: String,
    /// Current Logon state (if applicable).
    pub logon_state: Option<String>,
    /// Selected NID (if applicable).
    pub selected_nid: Option<String>,
    /// MKA session status.
    pub mka_established: bool,
    /// Number of live MKA peers.
    pub mka_live_peers: usize,
}

/// IEEE 802.1X-2020 Supplicant — top-level application.
///
/// Assembles all protocol state machines and runs the event loop.
/// Per ARC-C-WPA-005 (#85) and ADR-EVT-007 (#79).
pub struct Supplicant<N: NetworkIo> {
    /// Application configuration.
    config: Config,
    /// Network I/O.
    network: N,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl<N: NetworkIo> Supplicant<N> {
    /// Initialize the supplicant from configuration.
    ///
    /// Per ARC-C-WPA-005 (#85).
    pub fn new(config: Config, network: N) -> Result<Self> {
        Ok(Self {
            config,
            network,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Perform one iteration of the event loop.
    ///
    /// 1. Check for incoming EAPOL frames (non-blocking)
    /// 2. Check for control interface commands (non-blocking)
    /// 3. Advance timer wheel
    /// 4. Call step() on each active state machine
    /// 5. Dispatch resulting events
    ///
    /// Per ADR-EVT-007 (#79).
    pub fn tick(&mut self) -> Result<Vec<PaeEvent>> {
        let events = Vec::new();

        // Check for incoming EAPOL frames
        if let Some(frame) = self.network.recv_eapol()? {
            tracing::debug!(len = frame.len(), "received EAPOL frame");
            // TODO: Dispatch to SupplicantPae::handle_eapol() once wired
            let _ = frame;
        }

        // TODO: Call step() on active state machines once wired
        // TODO: Dispatch resulting PaeEvents

        Ok(events)
    }

    /// Run the main event loop.
    ///
    /// Blocks until shutdown is requested.
    /// Per ADR-EVT-007 (#79).
    pub fn run(&mut self) -> Result<()> {
        tracing::info!(interface = %self.config.interface, "supplicant event loop started");

        while !self.shutdown.load(Ordering::SeqCst) {
            let events = self.tick()?;
            for event in events {
                if let Err(e) = self.dispatch_event(event) {
                    tracing::warn!(error = %e, "event dispatch error");
                }
            }
        }

        tracing::info!("supplicant event loop stopped");
        Ok(())
    }

    /// Request graceful shutdown.
    pub fn shutdown(&mut self) {
        tracing::info!("shutdown requested");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Whether shutdown has been requested.
    pub fn is_shutdown(&self) -> bool {
        self.shutdown.load(Ordering::SeqCst)
    }

    /// Dispatch a single event to the appropriate handler.
    ///
    /// Per ADR-EVT-007 (#79).
    fn dispatch_event(&mut self, event: PaeEvent) -> Result<()> {
        match &event {
            PaeEvent::MkaTransmit { mkpdu } => {
                tracing::debug!(len = mkpdu.len(), "transmitting MKPDU");
                let dest = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]; // PAE multicast
                self.network.send_eapol(dest, mkpdu)?;
            }
            PaeEvent::MkaSakInstalled { .. } => {
                tracing::info!("SAK installed");
                // TODO: Forward to CP state machine
            }
            PaeEvent::MkaSessionEstablished => {
                tracing::info!("MKA session established");
            }
            PaeEvent::MkaSessionTerminated => {
                tracing::info!("MKA session terminated");
            }
        }
        Ok(())
    }

    /// Get current supplicant state for the control interface.
    pub fn state(&self) -> SupplicantState {
        SupplicantState {
            pae_state: "disconnected".to_string(), // TODO: read from SupplicantPae
            cp_state: "closed".to_string(),        // TODO: read from CpStateMachine
            logon_state: None,                     // TODO: read from LogonProcess
            selected_nid: None,
            mka_established: false, // TODO: read from MkaParticipant
            mka_live_peers: 0,
        }
    }

    /// Handle a control command from the control interface.
    pub fn handle_command(&mut self, cmd: ControlCommand) -> Result<()> {
        match cmd {
            ControlCommand::Reauthenticate => {
                tracing::info!("reauthentication requested");
                // TODO: trigger SupplicantPae reauthentication
            }
            ControlCommand::Logoff => {
                tracing::info!("logoff requested");
                // TODO: trigger SupplicantPae logoff
            }
            ControlCommand::GetState => {
                let state = self.state();
                tracing::info!(?state, "current state");
            }
            ControlCommand::SetLogLevel { level } => {
                tracing::info!(%level, "log level change requested");
                // TODO: implement via tracing-subscriber reload
            }
            ControlCommand::Shutdown => {
                self.shutdown();
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::*;

    fn make_config() -> Config {
        Config::from_toml(
            r#"
interface = "eth0"

[eap]
identity = "test@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#,
        )
        .unwrap()
    }

    /// Verifies: ARC-C-WPA-005 (#85)
    /// Supplicant can be created from config.
    #[test]
    fn test_supplicant_new() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let supp = Supplicant::new(config, network);
        assert!(supp.is_ok());
    }

    /// Verifies: ARC-C-WPA-005 (#85)
    /// Shutdown flag works.
    #[test]
    fn test_supplicant_shutdown() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();
        assert!(!supp.is_shutdown());
        supp.shutdown();
        assert!(supp.is_shutdown());
    }

    /// Verifies: ADR-EVT-007 (#79)
    /// tick() returns empty events when no frames.
    #[test]
    fn test_supplicant_tick_no_frames() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();
        let events = supp.tick().unwrap();
        assert!(events.is_empty());
    }

    /// Verifies: ARC-C-WPA-005 (#85)
    /// Control command shutdown works.
    #[test]
    fn test_supplicant_command_shutdown() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();
        assert!(!supp.is_shutdown());
        supp.handle_command(ControlCommand::Shutdown).unwrap();
        assert!(supp.is_shutdown());
    }

    /// Verifies: ARC-C-WPA-005 (#85)
    /// SupplicantState is serializable.
    #[test]
    fn test_supplicant_state_serializable() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let supp = Supplicant::new(config, network).unwrap();
        let state = supp.state();
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("disconnected"));
    }

    /// Verifies: ADR-EVT-007 (#79)
    /// Event loop exits on shutdown.
    #[test]
    fn test_supplicant_run_exits_on_shutdown() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();
        // Pre-set shutdown so run() exits immediately
        supp.shutdown();
        let result = supp.run();
        assert!(result.is_ok());
    }
}
