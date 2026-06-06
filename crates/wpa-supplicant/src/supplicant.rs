//! Supplicant assembly and event loop.
//!
//! Wires together all protocol state machines (Supplicant PAE, EAP peer,
//! MKA, CP, Logon Process) into a single runnable application.
//!
//! Implements: ARC-C-WPA-005 (#85), REQ-NF-REL-003 (#59)
//! Architecture: ADR-EVT-007 (#79), ADR-SM-002 (#74)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Result;
use eapol_supp::frame::EapolFrame;
use eapol_supp::{PaeState, SupplicantPae};
use pae::{CpEvent, CpState, CpStateMachine, PaeEvent};

use crate::config::Config;
use crate::control::ControlCommand;
use crate::network_io::NetworkIo;
use crate::pae_adapter::SupplicantPaeAdapter;

/// Maximum time allowed for reconnection after link restoration.
///
/// Per REQ-NF-REL-003 (#59): re-establishment must complete within 10 seconds.
pub const RECONNECTION_TIMEOUT_SECS: u64 = 10;

/// Supplicant state exposed to the control interface.
///
/// Exposes runtime status per ARC-C-WPA-005 (#85) and ADR-EVT-007 (#79).
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

/// Link flap reconnection tracking state.
///
/// Per REQ-NF-REL-003 (#59): tracks the reconnection progress after link
/// restoration, measuring time from link-up to Controlled Port SECURE.
#[derive(Debug)]
enum ReconnectionState {
    /// No reconnection in progress; link is stable.
    Idle,
    /// Link is down; waiting for restoration.
    LinkDown,
    /// Link restored; reconnection in progress.
    /// Records the instant when link came back up.
    Reconnecting {
        /// Time when link came back up.
        link_up_at: Instant,
    },
}

/// IEEE 802.1X-2020 Supplicant — top-level application.
///
/// Assembles all protocol state machines and runs the event loop.
/// Per ARC-C-WPA-005 (#85) and ADR-EVT-007 (#79).
///
/// Implements: #59 (REQ-NF-REL-003: Reconnection After Link Flap)
pub struct Supplicant<N: NetworkIo> {
    /// Application configuration.
    config: Config,
    /// Network I/O (shared with the Supplicant PAE adapter so both can
    /// drive `send_eapol` / `recv_eapol` against the same underlying
    /// L2 socket). Per INT-002 (#110) and ADR-SM-002 (#74).
    network: Arc<N>,
    /// Supplicant PAE state machine. Per IEEE 802.1X-2020, Clause 8.
    /// Per INT-002 (#110).
    pae: SupplicantPae<SupplicantPaeAdapter<N>>,
    /// CP state machine. Per IEEE 802.1X-2020, Clause 10.
    cp: CpStateMachine,
    /// Link flap reconnection state. Per REQ-NF-REL-003 (#59).
    reconnection: ReconnectionState,
    /// Previous link state (for detecting transitions).
    prev_link_up: bool,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl<N: NetworkIo> Supplicant<N> {
    /// Initialize the supplicant from configuration.
    ///
    /// Accepts the network handle by value and stores it internally in an
    /// `Arc` so it can be shared with the `SupplicantPae` adapter per
    /// INT-002 (#110). Callers that need to retain their own reference
    /// (e.g. integration tests inspecting `sent_frames()`) can pass an
    /// `Arc<N>` directly thanks to the blanket
    /// `impl<T: NetworkIo + ?Sized> NetworkIo for Arc<T>` in
    /// `crate::network_io`.
    ///
    /// Per ARC-C-WPA-005 (#85).
    pub fn new(config: Config, network: N) -> Result<Self> {
        let network = Arc::new(network);
        let link_up = network.link_up();
        let identity = config.eap.identity.as_bytes().to_vec();
        let adapter = SupplicantPaeAdapter::new(Arc::clone(&network), identity);
        let pae = SupplicantPae::new(adapter);
        Ok(Self {
            config,
            network,
            pae,
            cp: CpStateMachine::new(0),
            reconnection: if link_up {
                ReconnectionState::Idle
            } else {
                ReconnectionState::LinkDown
            },
            prev_link_up: link_up,
            shutdown: Arc::new(AtomicBool::new(false)),
        })
    }

    /// Perform one iteration of the event loop.
    ///
    /// 1. Check for link state changes (link flap detection per #59)
    /// 2. Check for incoming EAPOL frames (non-blocking)
    /// 3. Check for control interface commands (non-blocking)
    /// 4. Advance timer wheel
    /// 5. Call step() on each active state machine
    /// 6. Dispatch resulting events
    ///
    /// Per ADR-EVT-007 (#79).
    pub fn tick(&mut self) -> Result<Vec<PaeEvent>> {
        let mut events = Vec::new();

        // 1. Check for link state changes — per REQ-NF-REL-003 (#59)
        let link_up = self.network.link_up();
        if link_up != self.prev_link_up {
            let link_events = self.handle_link_change(link_up)?;
            events.extend(link_events);
        }
        self.prev_link_up = link_up;

        // 2. Check for reconnection timeout
        self.check_reconnection_timeout()?;

        // 3. Check for incoming EAPOL frames — per INT-002 (#110) and Cl.8.3
        if let Some(bytes) = self.network.recv_eapol()? {
            tracing::debug!(len = bytes.len(), "received EAPOL frame");
            match EapolFrame::decode(&bytes) {
                Ok(frame) => {
                    if let Err(e) = self.pae.handle_eapol(&frame) {
                        // Per ADR-EVT-007 (#79): a parse / state-machine error
                        // on one frame must not abort the event loop.
                        tracing::warn!(error = %e, "Supplicant PAE rejected EAPOL frame");
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dropping malformed EAPOL frame");
                }
            }
        }

        // TODO(INT-003 / #111): Call step() on active state machines and dispatch PaeEvents

        Ok(events)
    }

    /// Handle a link state change (link flap).
    ///
    /// Per REQ-NF-REL-003 (#59): when link goes down, reset state machines;
    /// when link comes back up, start reconnection with 10-second deadline.
    fn handle_link_change(&mut self, link_up: bool) -> Result<Vec<PaeEvent>> {
        let events: Vec<PaeEvent> = Vec::new();

        if link_up {
            tracing::info!("link restored — starting reconnection per REQ-NF-REL-003");
            self.reconnection = ReconnectionState::Reconnecting {
                link_up_at: Instant::now(),
            };
            // Start EAP authentication by enabling the CP (Unsecured state)
            // Per Cl.10: EnableUnsecured transitions CP from Disabled → Unsecured
            match self.cp.handle_event(CpEvent::EnableUnsecured) {
                Ok(transitions) => {
                    tracing::info!(?transitions, "CP transitioned on link-up");
                }
                Err(e) => {
                    tracing::warn!(error = %e, "CP EnableUnsecured failed on link-up");
                }
            }
        } else {
            tracing::warn!("link lost — resetting state machines per REQ-NF-REL-003");
            self.reconnection = ReconnectionState::LinkDown;
            // Reset CP to Disabled
            let _ = self.cp.handle_event(CpEvent::Disable);
            // TODO: Tear down MKA session, reset Supplicant PAE
        }

        Ok(events)
    }

    /// Check if reconnection has exceeded the 10-second deadline.
    ///
    /// Per REQ-NF-REL-003 (#59): re-establishment must complete within 10 seconds.
    fn check_reconnection_timeout(&mut self) -> Result<()> {
        if let ReconnectionState::Reconnecting { link_up_at } = self.reconnection {
            if self.cp.state() == CpState::Secured {
                let elapsed = link_up_at.elapsed();
                tracing::info!(
                    elapsed_secs = elapsed.as_secs_f64(),
                    "reconnection completed — CP SECURE reached"
                );
                self.reconnection = ReconnectionState::Idle;
            } else if link_up_at.elapsed().as_secs() > RECONNECTION_TIMEOUT_SECS {
                tracing::error!(
                    "reconnection timeout — CP not SECURE within {}s per REQ-NF-REL-003",
                    RECONNECTION_TIMEOUT_SECS
                );
                // Reset and allow retry
                self.reconnection = ReconnectionState::Idle;
            }
        }
        Ok(())
    }

    /// Whether reconnection is in progress (link was down, now up but not yet SECURE).
    ///
    /// Per REQ-NF-REL-003 (#59).
    pub fn is_reconnecting(&self) -> bool {
        matches!(self.reconnection, ReconnectionState::Reconnecting { .. })
    }

    /// Whether link is currently down.
    ///
    /// Per REQ-NF-REL-003 (#59).
    pub fn is_link_down(&self) -> bool {
        matches!(self.reconnection, ReconnectionState::LinkDown)
    }

    /// Current CP state.
    ///
    /// Per IEEE 802.1X-2020 Clause 10 and REQ-NF-REL-003 (#59).
    pub fn cp_state(&self) -> CpState {
        self.cp.state()
    }

    /// Current Supplicant PAE state.
    ///
    /// Per IEEE 802.1X-2020 Clause 8.3 and INT-002 (#110).
    pub fn pae_state(&self) -> PaeState {
        self.pae.state()
    }

    /// Set the Supplicant PAE `authenticate` flag.
    ///
    /// Per IEEE 802.1X-2020 Clause 8.4: the Logon Process sets this flag
    /// to authorize PACP to initiate an authentication attempt. Exposed
    /// here for INT-002 (#110) end-to-end testing until the Logon Process
    /// wiring lands (planned alongside INT-003 / #111).
    pub fn pae_set_authenticate(&mut self, value: bool) {
        self.pae.set_authenticate(value);
    }

    /// Diagnostic counters for the Supplicant PAE.
    ///
    /// Per IEEE 802.1X-2020 Clause 8.8 (`PaeCounters`) and INT-002 (#110).
    /// `eapol_frames_rx` increments every time `handle_eapol` consumes
    /// an inbound frame — used by integration tests to confirm the
    /// `tick()` dispatch path is wired.
    pub fn pae_counters(&self) -> &eapol_supp::PaeCounters {
        self.pae.counters()
    }

    /// Advance CP to SECURE state (simulates successful MKA SAK installation).
    ///
    /// In a fully wired supplicant, this would be called automatically when
    /// MKA produces a SAK. For REQ-NF-REL-003 testing, this simulates the
    /// protocol completing successfully.
    pub fn simulate_sak_install(&mut self) -> Result<()> {
        use pae::{CipherSuite, Sak, Sci};

        // CP must be in Unsecured state to install a SAK
        if self.cp.state() != CpState::Unsecured {
            return Ok(());
        }

        let sak = Sak::from_bytes(&[0x01; 16], 0)
            .map_err(|e| anyhow::anyhow!("SAK creation failed: {}", e))?;
        let sci = Sci::new(self.network.mac_address(), 1);

        match self.cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        }) {
            Ok(transitions) => {
                tracing::info!(?transitions, "SAK installed — CP now SECURE");
                Ok(())
            }
            Err(e) => {
                tracing::warn!(error = %e, "SAK install failed");
                Ok(())
            }
        }
    }

    /// Time elapsed since link restoration, if reconnecting.
    ///
    /// Per REQ-NF-REL-003 (#59): used to verify reconnection timing.
    pub fn reconnection_elapsed(&self) -> Option<std::time::Duration> {
        match &self.reconnection {
            ReconnectionState::Reconnecting { link_up_at } => Some(link_up_at.elapsed()),
            _ => None,
        }
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
    ///
    /// Per ADR-EVT-007 (#79).
    pub fn shutdown(&mut self) {
        tracing::info!("shutdown requested");
        self.shutdown.store(true, Ordering::SeqCst);
    }

    /// Whether shutdown has been requested.
    ///
    /// Per ADR-EVT-007 (#79).
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
    ///
    /// Per ARC-C-WPA-005 (#85). The `pae_state` field is sourced from the
    /// live `SupplicantPae` per INT-002 (#110); `logon_state` and the
    /// MKA fields will follow as their wiring lands (INT-006 / #114).
    pub fn state(&self) -> SupplicantState {
        SupplicantState {
            pae_state: format!("{:?}", self.pae.state()).to_lowercase(),
            cp_state: format!("{:?}", self.cp.state()).to_lowercase(),
            logon_state: None, // TODO(INT-006 / #114): read from LogonProcess
            selected_nid: None,
            mka_established: false, // TODO(INT-006 / #114): read from MkaParticipant
            mka_live_peers: 0,
        }
    }

    /// Handle a control command from the control interface.
    ///
    /// Per ADR-EVT-007 (#79).
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
        assert!(json.contains("disabled"));
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

    // --- REQ-NF-REL-003: Reconnection After Link Flap ---

    /// Verifies: #59 (REQ-NF-REL-003)
    /// Per IEEE 802.1X-2020 and REQ-NF-REL-003.
    /// Link down transitions CP to Disabled state.
    #[test]
    fn test_link_down_disables_cp() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();

        // Initially CP is Disabled
        assert_eq!(supp.cp_state(), CpState::Disabled);
        assert!(!supp.is_link_down());

        // Simulate link down
        supp.network.set_link(false);
        supp.tick().unwrap();

        assert!(supp.is_link_down());
        assert_eq!(supp.cp_state(), CpState::Disabled);
    }

    /// Verifies: #59 (REQ-NF-REL-003)
    /// Per IEEE 802.1X-2020 and REQ-NF-REL-003.
    /// Link up after link down starts reconnection and CP enters Unsecured.
    #[test]
    fn test_link_up_starts_reconnection() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();

        // Simulate link down
        supp.network.set_link(false);
        supp.tick().unwrap();
        assert!(supp.is_link_down());

        // Simulate link up — starts reconnection
        supp.network.set_link(true);
        supp.tick().unwrap();

        assert!(supp.is_reconnecting());
        assert_eq!(supp.cp_state(), CpState::Unsecured);
    }

    /// Verifies: #59 (REQ-NF-REL-003)
    /// Per IEEE 802.1X-2020 and REQ-NF-REL-003.
    /// Reconnection completes when CP reaches SECURE within 10 seconds.
    #[test]
    fn test_reconnection_completes_on_secure() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();

        // Simulate link down then up
        supp.network.set_link(false);
        supp.tick().unwrap();
        supp.network.set_link(true);
        supp.tick().unwrap();

        assert!(supp.is_reconnecting());
        assert_eq!(supp.cp_state(), CpState::Unsecured);

        // Simulate successful MKA SAK installation
        supp.simulate_sak_install().unwrap();
        assert_eq!(supp.cp_state(), CpState::Secured);

        // Next tick should detect completion
        supp.tick().unwrap();
        assert!(
            !supp.is_reconnecting(),
            "reconnection should be complete after CP SECURE"
        );
    }

    /// Verifies: #59 (REQ-NF-REL-003)
    /// Per IEEE 802.1X-2020 and REQ-NF-REL-003.
    /// Full link flap cycle: SECURE → link down → link up → SECURE
    /// within 10 seconds.
    #[test]
    fn test_full_link_flap_recovery_within_10s() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();

        // 1. Initial: CP Disabled, link up
        assert_eq!(supp.cp_state(), CpState::Disabled);

        // 2. Simulate initial authentication — trigger link flap cycle
        //    (link down then up to enable CP via handle_link_change)
        supp.network.set_link(false);
        supp.tick().unwrap();
        assert!(supp.is_link_down());

        supp.network.set_link(true);
        supp.tick().unwrap();
        assert_eq!(supp.cp_state(), CpState::Unsecured);

        // 3. Install SAK (simulate MKA session established)
        supp.simulate_sak_install().unwrap();
        assert_eq!(supp.cp_state(), CpState::Secured);

        // 4. Link goes down — CP should be Disabled
        supp.network.set_link(false);
        supp.tick().unwrap();
        assert!(supp.is_link_down());
        assert_eq!(supp.cp_state(), CpState::Disabled);

        // 5. Link comes back up — reconnection starts
        supp.network.set_link(true);
        supp.tick().unwrap();
        assert!(supp.is_reconnecting());
        assert_eq!(supp.cp_state(), CpState::Unsecured);

        // 6. Simulate successful reconnection (SAK install)
        let elapsed_before = supp.reconnection_elapsed().unwrap();
        supp.simulate_sak_install().unwrap();
        assert_eq!(supp.cp_state(), CpState::Secured);

        // 7. Verify reconnection completes
        supp.tick().unwrap();
        assert!(!supp.is_reconnecting());

        // 8. Verify timing: elapsed should be well under 10 seconds
        // (This is a unit test — the simulated reconnection is instantaneous)
        assert!(
            elapsed_before.as_secs() < RECONNECTION_TIMEOUT_SECS,
            "reconnection should complete within {} seconds",
            RECONNECTION_TIMEOUT_SECS
        );
    }

    /// Verifies: #59 (REQ-NF-REL-003)
    /// Per IEEE 802.1X-2020 and REQ-NF-REL-003.
    /// Multiple link flaps in sequence are handled correctly.
    #[test]
    fn test_multiple_link_flaps() {
        let config = make_config();
        let network = crate::network_io::MockNetworkIo::new();
        let mut supp = Supplicant::new(config, network).unwrap();

        for _ in 0..3 {
            // Link down
            supp.network.set_link(false);
            supp.tick().unwrap();
            assert!(supp.is_link_down());

            // Link up — reconnection starts
            supp.network.set_link(true);
            supp.tick().unwrap();
            assert!(supp.is_reconnecting());
            assert_eq!(supp.cp_state(), CpState::Unsecured);

            // Complete reconnection
            supp.simulate_sak_install().unwrap();
            supp.tick().unwrap();
            assert!(!supp.is_reconnecting());
            assert_eq!(supp.cp_state(), CpState::Secured);
        }
    }
}
