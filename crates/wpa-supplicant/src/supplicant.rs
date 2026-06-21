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
use eap_peer::key_derivation::derive_cak_from_msk;
use eap_peer::peer::EapMethod;
use eapol_supp::frame::{EapolFrame, EapolPacketType};
use eapol_supp::{PaeState, SupplicantPae};
use pae::{
    AesCmacKdf, CipherSuite, CpEvent, CpState, CpStateMachine, MkaParticipant, MkaState, Msk,
    PaeEvent, Sak, Sci,
};

use crate::config::Config;
use crate::control::ControlCommand;
use crate::eap_session::EapSession;
use crate::logging::Logging;
use crate::mka_adapter::MkaParticipantAdapter;
use crate::network_io::NetworkIo;
use crate::pae_adapter::SupplicantPaeAdapter;

/// Maximum time allowed for reconnection after link restoration.
///
/// Per REQ-NF-REL-003 (#59): re-establishment must complete within 10 seconds.
pub const RECONNECTION_TIMEOUT_SECS: u64 = 10;

/// Key Server priority offered by this Supplicant during MKA Key
/// Server election per IEEE 802.1X-2020 Cl.9.5.
///
/// Lower-priority values win election; `0xFF` (the maximum) makes
/// this Supplicant the *least*-preferred Key Server. In a typical
/// deployment the Authenticator wins and distributes the SAK; the
/// Supplicant only consumes (unwrap_sak). Surface this as a named
/// constant so reviewers and auditors don't have to interpret a
/// magic byte in `try_construct_mka`.
const SUPPLICANT_KEY_SERVER_PRIORITY: u8 = 0xFF;

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
pub struct Supplicant<N: NetworkIo + 'static> {
    /// Application configuration.
    config: Config,
    /// Network I/O (shared with the Supplicant PAE adapter so both can
    /// drive `send_eapol` / `recv_eapol` against the same underlying
    /// L2 socket). Per INT-002 (#110) and ADR-SM-002 (#74).
    network: Arc<N>,
    /// Supplicant PAE state machine. Per IEEE 802.1X-2020, Clause 8.
    /// Per INT-002 (#110).
    pae: SupplicantPae<SupplicantPaeAdapter<N>>,
    /// EAP peer ↔ PAE bridge. Per #130: drives the EAP conversation
    /// from inbound EAP packets on the wire and routes terminal
    /// `Success` / `Failure` into the PAE.
    eap: EapSession<N>,
    /// MKA participant. `Some` once the EAP exchange has produced an
    /// MSK (#130) and the CAK has been derived per Cl.6.2.2 (#129).
    /// Dropped on link-down so the SAK / KEK / ICK do not survive
    /// into the next session — `pae::mka` types are `ZeroizeOnDrop`
    /// per ADR-SEC-004 (#76).
    mka: Option<MkaParticipant<MkaParticipantAdapter<N>>>,
    /// CP state machine. Per IEEE 802.1X-2020, Clause 10.
    cp: CpStateMachine,
    /// Logging reload handle. `Some` when the binary entry point wired
    /// one in; `None` when constructed via the bare `Supplicant::new`
    /// (e.g. unit tests that do not touch `tracing-subscriber`).
    /// Per INT-009 (#117).
    logging: Option<Logging>,
    /// Link flap reconnection state. Per REQ-NF-REL-003 (#59).
    reconnection: ReconnectionState,
    /// Previous link state (for detecting transitions).
    prev_link_up: bool,
    /// Shutdown flag.
    shutdown: Arc<AtomicBool>,
}

impl<N: NetworkIo + 'static> Supplicant<N> {
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
    /// Per ARC-C-WPA-005 (#85). For control-socket log-level reload
    /// support (INT-009 / #117), use [`Supplicant::with_logging`] instead.
    ///
    /// The EAP session is constructed with **no methods**. The peer can
    /// still handle EAP-Identity / EAP-Notification natively and route
    /// EAP-Success / EAP-Failure into the PAE; method-bearing methods
    /// (EAP-TLS / PEAP / TEAP) wait on the future method-factory
    /// follow-up that turns `EapMethodConfig` into a `Vec<Box<dyn
    /// EapMethod>>`.
    pub fn new(config: Config, network: N) -> Result<Self> {
        Self::build(config, network, None, Vec::new())
    }

    /// Initialize the supplicant with a [`Logging`] handle so the
    /// control socket can reload the log level at runtime.
    ///
    /// Per INT-009 (#117) and REQ-NF-DEPLOY-001 (#68). The binary
    /// entry point calls this after `Logging::init`; tests inject a
    /// recording handle via [`Logging::from_test_handle`].
    pub fn with_logging(config: Config, network: N, logging: Logging) -> Result<Self> {
        Self::build(config, network, Some(logging), Vec::new())
    }

    /// Initialize the supplicant with an explicit set of EAP methods
    /// for the bridge to dispatch to. Used by integration tests
    /// (e.g. `tests/eap_bridge.rs`) to inject mock methods that
    /// exercise the success / failure paths without a real TLS engine.
    ///
    /// Per #130. Prod callers should use [`Supplicant::new`] /
    /// [`Supplicant::with_logging`] until the EAP method factory
    /// (which loads PEM-based TLS engines from
    /// `EapMethodConfig`) lands.
    pub fn with_eap_methods(
        config: Config,
        network: N,
        methods: Vec<Box<dyn EapMethod>>,
    ) -> Result<Self> {
        Self::build(config, network, None, methods)
    }

    fn build(
        config: Config,
        network: N,
        logging: Option<Logging>,
        eap_methods: Vec<Box<dyn EapMethod>>,
    ) -> Result<Self> {
        let network = Arc::new(network);
        let link_up = network.link_up();
        let identity = config.eap.identity.as_bytes().to_vec();
        let adapter = SupplicantPaeAdapter::new(Arc::clone(&network), identity.clone());
        let pae = SupplicantPae::new(adapter);
        let eap = EapSession::new(Arc::clone(&network), identity, eap_methods);
        Ok(Self {
            config,
            network,
            pae,
            eap,
            mka: None,
            cp: CpStateMachine::new(0),
            logging,
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
                    // Per #130: also drive the EAP-peer bridge so an
                    // inbound EAP packet reaches `EapPeer::handle_packet`
                    // and any terminal Success / Failure is routed into
                    // the PAE via `eap_success` / `eap_failure`.
                    if frame.packet_type == EapolPacketType::EapPacket {
                        if let Err(e) = self.drive_eap_bridge(&frame.body) {
                            tracing::warn!(error = %e, "EAP bridge rejected packet");
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "dropping malformed EAPOL frame");
                }
            }
        }

        // 4. Drive the Supplicant PAE state machine — per INT-003 (#111) and Cl.8.3.
        //
        // `step()` is timer-driven: it consumes the PAE's internal flags
        // (`authenticate`, `eap_start`, etc.) and the configured
        // `startWhen` / `authWhile` / `heldWhile` timers, advancing
        // state and transmitting EAPOL-Start as appropriate. Per
        // ADR-EVT-007 (#79): a step error must not abort the loop.
        //
        // Per INT-004 (#112): skip the step when the link is down — the
        // PAE has just been reset to Disconnected by `link_changed(false)`
        // and stepping with `authenticate=true` would immediately bounce
        // it back to Connecting, defeating the teardown.
        if link_up {
            if let Err(e) = self.pae.step() {
                tracing::warn!(error = %e, "Supplicant PAE step error");
            }
        }

        // 5. Construct the MKA participant once the EAP-peer bridge
        // has produced an MSK and the link is up. Per #129 and
        // Cl.6.2.2: derive `(cak, ckn)` from the MSK via
        // `eap_peer::key_derivation::derive_cak_from_msk` and build
        // the participant. The bridge (#130) parks the MSK on
        // `self.eap.pending_msk`; we consume it here destructively
        // (Msk is not Clone per ADR-SEC-004 #76).
        if link_up && self.mka.is_none() {
            if let Some(msk) = self.eap.take_msk() {
                if let Err(e) = self.try_construct_mka(msk) {
                    tracing::warn!(error = %e, "MKA participant construction failed");
                }
            }
        }

        // 6. Drive the MKA participant — per #129 and Cl.9.5 / Cl.9.7.
        // `step()` consumes Hello / Life timers and produces a vector
        // of `PaeEvent`s (notably `MkaTransmit { mkpdu }` and
        // `MkaSakInstalled { sak_key, sak_an }`). Forward each
        // through `dispatch_event` so the Cl.9 / Cl.10 path closes
        // (INT-005 #113 wired the downstream dispatch).
        if link_up {
            if let Some(mka) = self.mka.as_mut() {
                let mka_events = match mka.step() {
                    Ok(ev) => ev,
                    Err(e) => {
                        tracing::warn!(error = %e, "MKA step error");
                        Vec::new()
                    }
                };
                for ev in mka_events {
                    if let Err(e) = self.dispatch_event(ev) {
                        tracing::warn!(error = %e, "MKA event dispatch error");
                    }
                }
            }
        }

        Ok(events)
    }

    /// Handle a link state change (link flap).
    ///
    /// Per REQ-NF-REL-003 (#59) and INT-004 (#112): when link goes
    /// down, reset state machines (Supplicant PAE → Disconnected,
    /// CP → Disabled, MKA participant dropped); when link comes back
    /// up, start reconnection with a 10-second deadline and notify
    /// the Supplicant PAE so it can restart authentication.
    fn handle_link_change(&mut self, link_up: bool) -> Result<Vec<PaeEvent>> {
        let events: Vec<PaeEvent> = Vec::new();

        if link_up {
            tracing::info!("link restored — starting reconnection per REQ-NF-REL-003");
            self.reconnection = ReconnectionState::Reconnecting {
                link_up_at: Instant::now(),
            };
            // Per Cl.8.3 and INT-004 (#112): notify the Supplicant PAE
            // of the link transition. If `authenticate` was set before
            // the flap, this drives the PAE back to Connecting and
            // emits an EAPOL-Start.
            if let Err(e) = self.pae.link_changed(true) {
                tracing::warn!(error = %e, "Supplicant PAE link-up notification failed");
            }
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
            // Reset CP to Disabled.
            let _ = self.cp.handle_event(CpEvent::Disable);
            // Per Cl.8.3 and INT-004 (#112): reset Supplicant PAE to
            // Disconnected, cancel its timers, and zero its retry
            // count. `link_changed(false)` is total and infallible by
            // construction (it only mutates state); the `_` guards
            // against future signature changes.
            let _ = self.pae.link_changed(false);
            // Per #129 and ADR-SEC-004 (#76): drop the MKA
            // participant so its peer list, SAK, and Hello timers do
            // not survive into the next link-up session. The
            // `zeroize::Zeroize` impls on `Cak` / `Ick` / `Kek` /
            // `Sak` (in `pae::mka`) fire on drop, zeroing the secret
            // material per Cl.6.2.2's "stale SAK must not be reused"
            // posture.
            if self.mka.take().is_some() {
                tracing::debug!("MKA participant dropped on link-down (CAK/ICK/KEK zeroized)");
            }
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

    /// Take the MSK from the most recent successful EAP exchange.
    ///
    /// Per RFC 5247 and IEEE 802.1X-2020 Cl.6.2.2. Returns `Some(Msk)`
    /// when the EAP peer reached `Success` and exported keying
    /// material, `None` otherwise. The MSK is held on the
    /// [`crate::eap_session::EapSession`] until consumed; consumption
    /// is destructive (`Msk` is not `Clone`).
    ///
    /// Since #129 landed, [`Self::tick`] consumes the MSK internally
    /// to construct the [`pae::MkaParticipant`]; in practice this
    /// accessor returns `None` on any tick after a successful EAP
    /// exchange. It is preserved for tests and embedders that want to
    /// inspect the MSK before the MKA participant claims it.
    ///
    /// ## Migration note (#130)
    ///
    /// The previous `pae_eap_success` integration shim was removed in
    /// #130. Inbound EAP-Success packets now reach the PAE through
    /// the EAP-peer bridge in `tick()`; tests that previously drove
    /// the PAE by calling `pae_eap_success` directly should instead
    /// enqueue an EAP-Success EAPOL frame on the wire and let
    /// `tick()` route it.
    pub fn take_msk(&mut self) -> Option<Msk> {
        self.eap.take_msk()
    }

    /// Whether the MKA participant has been constructed.
    ///
    /// Per #129: returns `true` after a successful EAP exchange has
    /// produced an MSK and [`Self::tick`] has derived the CAK and
    /// initialized the participant per Cl.6.2.2. Returns `false`
    /// before the first successful EAP exchange, and again after a
    /// link-down event drops the participant (so SAK / KEK / ICK are
    /// zeroized per ADR-SEC-004 #76).
    pub fn mka_is_some(&self) -> bool {
        self.mka.is_some()
    }

    /// Try to construct the MKA participant from a freshly-taken MSK.
    /// Internal — `tick()` is the only caller.
    fn try_construct_mka(&mut self, msk: Msk) -> Result<()> {
        // Derive the CAK + CKN from the MSK per Cl.6.2.2 and
        // ADR-KDF-008 (#80). The `derive_cak_from_msk` helper lives
        // in `eap_peer::key_derivation` (REQ-F-EAP-006 / #43).
        let kdf = AesCmacKdf;
        let (cak, ckn) = derive_cak_from_msk(&kdf, &msk).map_err(anyhow::Error::from)?;

        // Build the adapter (`MkaContext` impl) and the participant.
        // Cipher suite defaults to `GcmAes128`; full mapping from
        // `config.macsec.cipher_suite` to `pae::CipherSuite` is a
        // small follow-up.
        let adapter = MkaParticipantAdapter::new(Arc::clone(&self.network));
        let sci = Sci::new(self.network.mac_address(), 1);
        let participant = MkaParticipant::new(
            adapter,
            cak,
            ckn,
            CipherSuite::GcmAes128,
            sci,
            SUPPLICANT_KEY_SERVER_PRIORITY,
        )
        .map_err(anyhow::Error::from)?;

        tracing::info!("MKA participant constructed from EAP MSK per Cl.6.2.2");
        self.mka = Some(participant);
        Ok(())
    }

    /// Drive the EAP-peer bridge with the body of an inbound EAPOL
    /// `EapPacket` frame. Internal — `tick()` is the only caller.
    fn drive_eap_bridge(&mut self, raw_eap: &[u8]) -> Result<()> {
        let outcome = self.eap.handle_eap_bytes(raw_eap)?;
        if outcome.success {
            // PAE may be in Authenticating; downgrade an
            // invalid-state error to `warn!` per ADR-EVT-007.
            if let Err(e) = self.pae.eap_success() {
                tracing::warn!(error = %e, "PAE rejected eap_success from bridge");
            }
        }
        if outcome.failure {
            if let Err(e) = self.pae.eap_failure() {
                tracing::warn!(error = %e, "PAE rejected eap_failure from bridge");
            }
        }
        Ok(())
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

    /// Dispatch a single `PaeEvent` to the appropriate handler.
    ///
    /// Per ADR-EVT-007 (#79) and INT-005 (#113). Public so integration
    /// tests and the eventual MKA-driven tick-loop wiring can route
    /// events without poking at private internals. All errors are
    /// captured and downgraded to `warn!` — dispatching one bad event
    /// must not abort the supplicant.
    pub fn dispatch_pae_event(&mut self, event: PaeEvent) -> Result<()> {
        self.dispatch_event(event)
    }

    /// Dispatch a single event to the appropriate handler.
    ///
    /// Per ADR-EVT-007 (#79).
    fn dispatch_event(&mut self, event: PaeEvent) -> Result<()> {
        match event {
            PaeEvent::MkaTransmit { mkpdu } => {
                tracing::debug!(len = mkpdu.len(), "transmitting MKPDU");
                let dest = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03]; // PAE multicast
                self.network.send_eapol(dest, &mkpdu)?;
            }
            PaeEvent::MkaSakInstalled {
                sak_key,
                sak_an,
                sci,
                cipher_suite,
            } => {
                // Per IEEE 802.1X-2020 Clauses 9.13 (SAK install) and
                // 10 (CP transitions) and INT-005 (#113): reconstruct
                // the SAK and forward to the CP as `CpEvent::SakAvailable`.
                tracing::info!(
                    an = sak_an,
                    ?cipher_suite,
                    "SAK installed by MKA — forwarding to CP"
                );
                match Sak::from_bytes(&sak_key, sak_an) {
                    Ok(sak) => {
                        match self.cp.handle_event(CpEvent::SakAvailable {
                            sak,
                            sci,
                            cipher_suite,
                        }) {
                            Ok(transitions) => {
                                tracing::info!(
                                    ?transitions,
                                    "CP transitioned on SakAvailable per Cl.10"
                                );
                            }
                            Err(e) => {
                                // Per ADR-EVT-007 (#79): a wrong-state
                                // CP must not crash the loop. The most
                                // common cause is `MkaSakInstalled`
                                // arriving while CP is still `Disabled`
                                // (e.g. before the Logon Process has
                                // run `EnableUnsecured`).
                                tracing::warn!(
                                    error = %e,
                                    cp_state = ?self.cp.state(),
                                    "CP rejected SakAvailable"
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // Per ADR-EVT-007 (#79): a malformed SAK
                        // payload (wrong length for the cipher suite)
                        // is logged at `warn` and dropped — never
                        // propagated up the event loop.
                        tracing::warn!(error = %e, "failed to reconstruct SAK from MKA event");
                    }
                }
            }
            PaeEvent::MkaSessionEstablished => {
                tracing::info!("MKA session established");
            }
            PaeEvent::MkaSessionTerminated => {
                // Per IEEE 802.1X-2020 Clause 10 and INT-005 (#113):
                // when the MKA session terminates the CP must release
                // the SA. The CP state machine handles this via the
                // `Disable` event today; a dedicated `SakRetireExpired`
                // path lives in `pae::cp::CpEvent` and will be wired
                // when MKA's SAK-Retire timer fires (Cl.9, INT-005
                // follow-up). For now we log the transition.
                tracing::info!("MKA session terminated");
            }
        }
        Ok(())
    }

    /// Get current supplicant state for the control interface.
    ///
    /// Per ARC-C-WPA-005 (#85) and INT-006 (#114). All field provenance:
    ///
    /// | Field             | Source                                                  | Wired by           |
    /// |-------------------|---------------------------------------------------------|--------------------|
    /// | `pae_state`       | `SupplicantPae::state()` — live                         | INT-002 (#110) ✅  |
    /// | `cp_state`        | `CpStateMachine::state()` — live                        | INT-002 (#110) ✅  |
    /// | `logon_state`     | `LogonProcess::state()` once constructed                | INT-001 (#109)     |
    /// | `selected_nid`    | `LogonProcess::selected_nid()` once constructed         | INT-001 (#109)     |
    /// | `mka_established` | `MkaParticipant::state() == Established` (#129)         | INT-005 (#113) ✅  |
    /// | `mka_live_peers`  | `MkaParticipant::peers().live_count()` (#129)           | INT-005 (#113) ✅  |
    ///
    /// The Logon fields default to `None` while LogonProcess is not
    /// yet plugged into `Supplicant`; when INT-001 lands, its PR
    /// updates this method to read from the new fields. The MKA
    /// fields default to `false` / `0` until an EAP exchange yields
    /// an MSK and the participant is constructed (#129 path). The
    /// schema is stable — control-socket consumers (and the eventual
    /// NETCONF / YANG surface tracked under `docs/TODO.md` P5.3) see
    /// every field on every call.
    pub fn state(&self) -> SupplicantState {
        SupplicantState {
            pae_state: format!("{:?}", self.pae.state()).to_lowercase(),
            cp_state: format!("{:?}", self.cp.state()).to_lowercase(),
            // Per INT-006 (#114): populated when LogonProcess is wired
            // into `Supplicant` under INT-001 (#109).
            logon_state: None,
            selected_nid: None,
            // Per #129: populated from the constructed MKA participant.
            mka_established: self
                .mka
                .as_ref()
                .map(|p| p.state() == MkaState::Established)
                .unwrap_or(false),
            mka_live_peers: self
                .mka
                .as_ref()
                .map(|p| p.peers().live_count())
                .unwrap_or(0),
        }
    }

    /// Handle a control command from the control interface.
    ///
    /// Per ADR-EVT-007 (#79). Control commands must never crash the
    /// daemon: a state-machine rejection (e.g. reauth requested while
    /// the PAE is Disconnected) is downgraded to a `warn!` log and the
    /// command returns `Ok(())`.
    pub fn handle_command(&mut self, cmd: ControlCommand) -> Result<()> {
        match cmd {
            ControlCommand::Reauthenticate => {
                // Per IEEE 802.1X-2020 Clause 8.3 and INT-007 (#115).
                let before = self.pae.state();
                tracing::info!(?before, "reauthentication requested");
                match self.pae.reauthenticate() {
                    Ok(()) => {
                        tracing::info!(
                            ?before,
                            after = ?self.pae.state(),
                            "PAE reauthenticated per Cl.8.3"
                        );
                    }
                    Err(e) => {
                        // Per ADR-EVT-007 (#79): never crash the daemon
                        // on a control-socket command. The audit trail
                        // (StR-006) captures the operator action via
                        // the warn-level log line.
                        tracing::warn!(
                            error = %e,
                            ?before,
                            "reauthenticate rejected by Supplicant PAE"
                        );
                    }
                }
            }
            ControlCommand::Logoff => {
                // Per IEEE 802.1X-2020 Clause 8.5 and INT-008 (#116).
                let before = self.pae.state();
                tracing::info!(?before, "logoff requested");
                match self.pae.logoff() {
                    Ok(()) => {
                        tracing::info!(
                            ?before,
                            after = ?self.pae.state(),
                            "PAE entered Logoff per Cl.8.5"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(
                            error = %e,
                            ?before,
                            "logoff rejected by Supplicant PAE"
                        );
                    }
                }
            }
            ControlCommand::GetState => {
                let state = self.state();
                tracing::info!(?state, "current state");
            }
            ControlCommand::SetLogLevel { level } => {
                // Per INT-009 (#117) and REQ-NF-DEPLOY-001 (#68).
                tracing::info!(%level, "log level change requested");
                match &self.logging {
                    Some(logging) => {
                        if let Err(e) = logging.set_level(&level) {
                            // Per ADR-EVT-007 (#79): never crash the
                            // daemon on a control-socket command.
                            tracing::warn!(error = %e, %level, "log level reload failed");
                        } else {
                            tracing::info!(%level, "log level reloaded");
                        }
                    }
                    None => {
                        tracing::warn!(
                            %level,
                            "log level change requested but no Logging handle wired (see INT-009 / #117)"
                        );
                    }
                }
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
