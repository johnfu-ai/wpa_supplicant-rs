//! Bridge between the `eap-peer` EAP conversation and the
//! `eapol-supp` Supplicant PAE state machine.
//!
//! Implements: #130 — Phase 07 prerequisite. Drives
//! [`eap_peer::EapPeer`] from inbound EAP packets on the wire,
//! emits outbound EAP-Responses through [`NetworkIo`], and routes
//! terminal EAP-Success / EAP-Failure into [`SupplicantPae`].
//!
//! Architecture: ADR-EVT-007 (#79), ARC-C-EAP-003 (#83),
//! ARC-C-WPA-005 (#85), ADR-SM-002 (#74).
//!
//! ## Design
//!
//! [`Supplicant`] holds an `Option<EapSession<N>>`. The session owns:
//! * the EAP conversation state ([`EapPeer`]),
//! * the configured EAP methods (`Vec<Box<dyn EapMethod>>`),
//! * an internal [`EapContextImpl`] that adapts [`NetworkIo`] +
//!   identity bytes + a [`TlsClientConfig`] to the
//!   [`eap_peer::EapContext`] trait the methods expect.
//!
//! On every `tick()`, after `SupplicantPae::handle_eapol` has consumed
//! an EAPOL frame for its own state-machine purposes, the bridge
//! decodes the embedded EAP packet (if the EAPOL packet type is
//! `EapPacket`) and feeds it to `EapPeer::handle_packet`. The peer
//! may emit:
//! * an EAP-Response → re-wrapped in an EAPOL frame and sent via
//!   `NetworkIo::send_eapol` to the configured EAPOL PAE multicast
//!   address.
//! * an internal success → `SupplicantPae::eap_success` is invoked,
//!   the MSK is taken and stashed on the [`Supplicant`] for later
//!   consumption by the MKA participant (#129).
//! * an internal failure → `SupplicantPae::eap_failure` is invoked.
//!
//! ## Method construction
//!
//! Real EAP methods are built from [`crate::config::EapMethodConfig`]
//! by the EAP method factory (`crate::method_factory`, #133): it loads
//! PEM certificates, instantiates a `rustls`-backed `TlsEngine`, wires
//! EAP-TLS / EAP-PEAP / EAP-TEAP (with PEAP inner-method chains), and
//! returns the method list plus the [`TlsClientConfig`] the methods
//! read through [`EapContext::tls_config`]. [`crate::Supplicant::new`]
//! / [`crate::Supplicant::with_logging`] invoke the factory when the
//! `eap-tls-rustls` feature is enabled; otherwise the session is built
//! with no methods (the peer still handles EAP-Identity /
//! EAP-Notification natively and routes EAP-Success / EAP-Failure).
//!
//! Integration tests inject mock methods via
//! [`crate::Supplicant::with_eap_methods`], bypassing the factory.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE
//! 802.1X-2020 and RFC 3748. No copyrighted content from those
//! documents is reproduced.

use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use eap_peer::peer::{EapContext, EapMethod, EapPacket, EapPeer, EapPeerState, TlsClientConfig};
use eap_peer::EapError;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use pae::Msk;

use crate::network_io::NetworkIo;

/// PAE group address per IEEE 802.1X-2020 §11.1.1 — destination MAC
/// for outbound EAPOL frames originated by the Supplicant.
const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// Outcome of one `EapSession::handle_eap_bytes` invocation. The
/// bridge uses this to decide whether to call
/// `SupplicantPae::eap_success` / `eap_failure` and whether an MSK
/// became available.
pub(crate) struct EapDispatchOutcome {
    /// Whether the peer reached `EapPeerState::Success` on this call.
    /// The bridge translates this into `SupplicantPae::eap_success()`.
    pub success: bool,
    /// Whether the peer reached `EapPeerState::Failure` on this call.
    /// The bridge translates this into `SupplicantPae::eap_failure()`.
    pub failure: bool,
}

/// The bridge between the EAP peer conversation and the Supplicant
/// PAE state machine. See module-level documentation.
pub(crate) struct EapSession<N: NetworkIo> {
    peer: EapPeer,
    methods: Vec<Box<dyn EapMethod>>,
    ctx: EapContextImpl<N>,
    /// Wall-clock anchor for per-method retransmit deadlines. Read by
    /// `elapsed()`; wired for the EAP-method factory (#133) retransmit
    /// deadlines.
    #[allow(dead_code)]
    started_at: Instant,
    /// MSK taken from the EAP peer on success. Held until the MKA
    /// participant construction (#129) calls [`take_msk`] to consume
    /// it.
    pending_msk: Option<Msk>,
}

impl<N: NetworkIo> EapSession<N> {
    /// Construct an EAP session with the given methods, identity,
    /// network handle, and TLS client configuration.
    ///
    /// The `tls_config` flows into the [`EapContext`] the methods read
    /// via `ctx.tls_config()`. The EAP method factory (#133) builds it
    /// from PEM material in `EapMethodConfig`; callers that inject
    /// their own methods (tests) pass [`empty_tls_config`].
    pub(crate) fn new(
        network: Arc<N>,
        identity: Vec<u8>,
        methods: Vec<Box<dyn EapMethod>>,
        tls_config: TlsClientConfig,
    ) -> Self {
        Self {
            peer: EapPeer::new(),
            methods,
            ctx: EapContextImpl {
                network,
                identity,
                tls_config,
            },
            started_at: Instant::now(),
            pending_msk: None,
        }
    }

    /// Take any MSK that became available on a previous EAP success.
    /// Returns `None` if no MSK is queued. This is the hand-off point
    /// to the eventual MKA participant construction (#129).
    pub(crate) fn take_msk(&mut self) -> Option<Msk> {
        self.pending_msk.take()
    }

    /// Reset the conversation back to Idle (used on link-down or
    /// reauth). The MSK queue is cleared as well — a stale MSK from
    /// a previous session must not be reused per IEEE 802.1X-2020
    /// Cl.6.2.2.
    #[allow(dead_code)] // wired by #129 link-down teardown
    pub(crate) fn reset(&mut self) {
        self.peer.reset();
        for method in &mut self.methods {
            method.reset();
        }
        self.pending_msk = None;
    }

    /// Feed raw EAP packet bytes (the body of an EAPOL `EapPacket`
    /// frame) to the EAP peer.
    ///
    /// Returns an [`EapDispatchOutcome`] indicating whether the peer
    /// reached a terminal state on this call. On `Success` the MSK is
    /// taken from the peer and stashed in [`pending_msk`].
    ///
    /// All errors are converted to `Err(_)` and propagated; the
    /// caller (`Supplicant::tick`) logs at `warn!` and continues.
    pub(crate) fn handle_eap_bytes(&mut self, raw: &[u8]) -> Result<EapDispatchOutcome> {
        let packet = EapPacket::decode(raw)?;
        let response = self
            .peer
            .handle_packet(&packet, &mut self.methods, &self.ctx)?;

        // The peer may have produced a Response packet to send back.
        if let Some(resp) = response {
            let encoded = resp.encode().map_err(anyhow::Error::from)?;
            // Wrap in EAPOL EapPacket frame and send.
            let frame = EapolFrame {
                version: EapolVersion::V3,
                packet_type: EapolPacketType::EapPacket,
                body: encoded,
            };
            let bytes = frame.encode().map_err(anyhow::Error::from)?;
            self.ctx.network.send_eapol(PAE_GROUP_ADDR, &bytes)?;
            tracing::debug!(len = bytes.len(), "bridge: sent EAP-Response");
        }

        let mut outcome = EapDispatchOutcome {
            success: false,
            failure: false,
        };

        match self.peer.state() {
            EapPeerState::Success => {
                outcome.success = true;
                // Per RFC 5247: the MSK is the EAP method's exported
                // keying material. Take it off the peer (it is not
                // `Clone`) and stash for the MKA participant.
                if let Some(msk) = self.peer.take_msk() {
                    self.pending_msk = Some(msk);
                    tracing::debug!("bridge: MSK queued for MKA participant");
                } else {
                    // EAP-Success with no MSK — possible for
                    // tunnelled methods that have not exported keying
                    // material yet. Not an error; #129 will surface
                    // it via the state-machine path.
                    tracing::warn!("bridge: EAP-Success arrived but no MSK was produced");
                }
            }
            EapPeerState::Failure => {
                outcome.failure = true;
            }
            _ => {}
        }
        Ok(outcome)
    }
}

/// Internal [`EapContext`] adapter — gives the EAP methods access to
/// `send_eapol`, identity, TLS config, and the current time.
///
/// `send_eap` is implemented for completeness but is not currently
/// reached: the bridge intercepts EAP responses at the
/// `EapPeer::handle_packet` return value and sends them directly,
/// rather than letting each method send. Methods that internally call
/// `ctx.send_eap` will still work; the wrap-and-send logic mirrors
/// the bridge's primary outbound path.
struct EapContextImpl<N: NetworkIo> {
    network: Arc<N>,
    identity: Vec<u8>,
    tls_config: TlsClientConfig,
}

impl<N: NetworkIo + Send + Sync> EapContext for EapContextImpl<N> {
    fn send_eap(&self, packet: &EapPacket) -> std::result::Result<(), EapError> {
        let encoded = packet.encode()?;
        let frame = EapolFrame {
            version: EapolVersion::V3,
            packet_type: EapolPacketType::EapPacket,
            body: encoded,
        };
        let bytes = frame
            .encode()
            .map_err(|e| EapError::InvalidPacket(format!("EAPOL encode: {e}")))?;
        self.network
            .send_eapol(PAE_GROUP_ADDR, &bytes)
            .map_err(|e| EapError::InvalidPacket(format!("send_eapol: {e}")))
    }

    fn now(&self) -> Duration {
        // EAP retransmit timers measure relative durations; an
        // arbitrary monotonic base is fine. Methods that want
        // wall-clock have to bring their own source per ADR-EVT-007.
        Duration::from_secs(0)
    }

    fn get_identity(&self) -> &[u8] {
        &self.identity
    }

    fn tls_config(&self) -> &TlsClientConfig {
        &self.tls_config
    }
}

/// Placeholder TLS config for callers that do not load PEM material —
/// e.g. the test-injection path ([`crate::Supplicant::with_eap_methods`])
/// and the no-factory build (when the `eap-tls-rustls` feature is off).
/// Real EAP-TLS / PEAP / TEAP methods built by the method factory (#133)
/// carry their own [`TlsClientConfig`] loaded from `EapMethodConfig`.
pub(crate) fn empty_tls_config() -> TlsClientConfig {
    TlsClientConfig {
        cert_chain: Vec::new(),
        private_key: zeroize::Zeroizing::new(Vec::new()),
        ca_certs: Vec::new(),
        verify_server: true,
    }
}
