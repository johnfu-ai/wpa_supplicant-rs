//! Supplicant PAE context adapter — bridges `eapol_supp::SupplicantPaeContext`
//! to the in-binary `NetworkIo` + `Config` surfaces.
//!
//! Implements: INT-002 (#110)
//! Per IEEE 802.1X-2020 Clause 8.3 (Supplicant PACP frame ingestion).
//! Architecture: ADR-SM-002 (#74) — trait-based DI for state machines.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eapol_supp::frame::EapolFrame;
use eapol_supp::{EapolError, SupplicantPaeContext, PAE_GROUP_MAC};
use pae::ControlledPortState;

use crate::network_io::NetworkIo;

/// Default Supplicant PAE timer values per IEEE 802.1X-2020 Clause 8.6.
///
/// `heldPeriod` default per Cl.8.6 (60 s).
const DEFAULT_HELD_WHILE: Duration = Duration::from_secs(60);
/// `startWhen` default per Cl.8.3 (30 s).
const DEFAULT_START_WHEN: Duration = Duration::from_secs(30);
/// `authWhile` default per Cl.8.3 (30 s).
const DEFAULT_AUTH_WHILE: Duration = Duration::from_secs(30);
/// `retryMax` default per Cl.8.7.
const DEFAULT_MAX_RETRIES: u32 = 3;

/// Adapter that fulfills `SupplicantPaeContext` for the in-binary supplicant.
///
/// Holds an `Arc<N>` so the PAE state machine can drive EAPOL transmissions
/// through the same `NetworkIo` instance the `Supplicant` event loop owns.
///
/// Per IEEE 802.1X-2020 Clause 8.3 (Supplicant PACP context) and
/// INT-002 (#110); architecture per ADR-SM-002 (#74).
pub struct SupplicantPaeAdapter<N: NetworkIo> {
    network: Arc<N>,
    identity: Vec<u8>,
    start_instant: Instant,
    /// Destination MAC for outbound EAPOL frames. The PAE group address
    /// 01-80-C2-00-00-03 per IEEE 802.1X-2020 Clause 11.1.1.
    dest_mac: [u8; 6],
}

impl<N: NetworkIo> SupplicantPaeAdapter<N> {
    /// Construct a new adapter sharing the supplicant's `NetworkIo` handle.
    ///
    /// Outbound EAPOL frames are sent to the PAE group address
    /// 01-80-C2-00-00-03 per IEEE 802.1X-2020 Clause 11.1.1.
    ///
    /// Per INT-002 (#110) and ADR-SM-002 (#74).
    pub fn new(network: Arc<N>, identity: Vec<u8>) -> Self {
        Self {
            network,
            identity,
            start_instant: Instant::now(),
            dest_mac: PAE_GROUP_MAC,
        }
    }
}

impl<N: NetworkIo> SupplicantPaeContext for SupplicantPaeAdapter<N> {
    fn send_eapol(&self, frame: &EapolFrame) -> Result<(), EapolError> {
        let bytes = frame.encode()?;
        self.network
            .send_eapol(self.dest_mac, &bytes)
            .map_err(|e| EapolError::SendFailed(e.to_string()))
    }

    fn get_port_state(&self) -> ControlledPortState {
        // INT-002 baseline: the Controlled Port is unauthorized until the
        // CP state machine reaches Secured. INT-005 (#113) wires the live
        // CP state through; until then, `Unauthorized` is the safe value
        // that allows the PAE to run its full state cycle per Cl.8.3.
        ControlledPortState::Unauthorized
    }

    fn now(&self) -> Duration {
        self.start_instant.elapsed()
    }

    fn get_identity(&self) -> &[u8] {
        &self.identity
    }

    fn get_max_retries(&self) -> u32 {
        DEFAULT_MAX_RETRIES
    }

    fn get_held_while(&self) -> Duration {
        DEFAULT_HELD_WHILE
    }

    fn get_start_when(&self) -> Duration {
        DEFAULT_START_WHEN
    }

    fn get_auth_while(&self) -> Duration {
        DEFAULT_AUTH_WHILE
    }

    fn is_macsec_secured(&self) -> bool {
        // INT-002 baseline: not MACsec-secured. INT-005 (#113) will surface
        // the CP `Secured` state through this accessor once the CP/MKA
        // event path is wired.
        false
    }
}
