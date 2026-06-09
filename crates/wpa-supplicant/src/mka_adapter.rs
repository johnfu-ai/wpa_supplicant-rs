//! `MkaContext` adapter — wires the in-binary `NetworkIo` + std crypto
//! into the `pae::MkaParticipant` per IEEE 802.1X-2020 Cl.9.
//!
//! Implements: #129 — Phase 07 prerequisite. Constructs the
//! [`pae::MkaParticipant`] on [`crate::Supplicant`] once the EAP-peer
//! bridge (#130) has produced an MSK and the CAK has been derived per
//! Cl.6.2.2.
//!
//! Architecture: ARC-C-PAE-001 (#81), ARC-C-WPA-005 (#85),
//! ADR-SM-002 (#74), ADR-SEC-004 (#76 — secret zeroization),
//! ADR-KDF-008 (#80 — KDF abstraction).
//!
//! ## Scope
//!
//! This adapter implements the [`pae::MkaContext`] trait for the
//! Supplicant role. The trait covers operations needed by either role
//! (Supplicant or Authenticator); we implement the Supplicant-side
//! subset:
//!
//! * `derive_keys`, `compute_icv`, `verify_icv` — delegate to
//!   `pae::AesCmacKdf` and `pae::{compute_icv, verify_icv}` per
//!   Cl.9.6 / Cl.9.7.
//! * `random_mi` — delegate to `pae::SystemRng` per Cl.9.4.
//! * `now` — wrap a monotonic `Instant` shared across the
//!   participant's lifetime.
//! * `send_mkpdu` — wrap the raw MKPDU in an EAPOL-MKA frame per
//!   Cl.11 and forward to `NetworkIo::send_eapol` on the PAE group
//!   address `01:80:C2:00:00:03` (§11.1.1).
//!
//! The Key-Server-side operations are stubbed:
//!
//! * `generate_sak`, `wrap_sak` — the Supplicant elects itself
//!   Actor-by-default with low priority; in practice the Authenticator
//!   wins Key Server election (Cl.9.5) and these are never reached.
//!   They return `PaeError::NotKeyServer` to make a wrong call loud
//!   rather than silently producing garbage keys. This is **by design**
//!   per the Supplicant-only scope of this implementation.
//! * `unwrap_sak` — uses real AES Key Wrap (RFC 3394) via
//!   `pae::aes_key_unwrap` to extract the distributed SAK from the
//!   Key Server's Distribute SAK parameter set per Cl.9.8.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE
//! 802.1X-2020. No copyrighted content from the standard is reproduced.

use std::sync::Arc;
use std::time::{Duration, Instant};

use eapol_supp::frame::EapolFrame;
use pae::{
    AesCmacKdf, Cak, CipherSuite, Ckn, Ick, Kdf, Kek, MkaContext, PaeError, Rng, Sak, SystemRng,
};

use crate::network_io::NetworkIo;

/// PAE group address per IEEE 802.1X-2020 §11.1.1 — destination MAC
/// for outbound EAPOL-MKA frames originated by the Supplicant.
const PAE_GROUP_ADDR: [u8; 6] = [0x01, 0x80, 0xC2, 0x00, 0x00, 0x03];

/// `pae::MkaContext` implementation backed by a `NetworkIo` + std
/// crypto. Constructed by the Supplicant once the EAP-peer bridge has
/// produced an MSK.
pub(crate) struct MkaParticipantAdapter<N: NetworkIo> {
    network: Arc<N>,
    /// Monotonic time origin. The MKA Hello / Life timers measure
    /// elapsed time from this anchor.
    started_at: Instant,
}

impl<N: NetworkIo> MkaParticipantAdapter<N> {
    pub(crate) fn new(network: Arc<N>) -> Self {
        Self {
            network,
            started_at: Instant::now(),
        }
    }
}

impl<N: NetworkIo + Send + Sync + 'static> MkaContext for MkaParticipantAdapter<N> {
    fn derive_keys(&self, cak: &Cak, ckn: &Ckn) -> Result<(Ick, Kek), PaeError> {
        // Per Cl.9.6 / ADR-KDF-008 (#80).
        let kdf = AesCmacKdf;
        let ick = kdf.derive_ick(cak, ckn)?;
        let kek = kdf.derive_kek(cak, ckn)?;
        Ok((ick, kek))
    }

    fn generate_sak(&self, _cipher_suite: CipherSuite) -> Result<Sak, PaeError> {
        // Per IEEE 802.1X-2020 Cl.9.5 / Cl.9.8: the Supplicant role
        // never generates SAKs — only the elected Key Server does.
        // This method returns `NotKeyServer` to make an incorrect call
        // site loud rather than silently producing invalid keys. This is
        // **by design** per the Supplicant-only scope of this
        // implementation.
        Err(PaeError::NotKeyServer)
    }

    fn wrap_sak(&self, _sak: &Sak, _kek: &Kek) -> Result<Vec<u8>, PaeError> {
        // Per IEEE 802.1X-2020 Cl.9.8: the Supplicant role never wraps
        // SAKs — only the Key Server distributes wrapped SAKs. This
        // method returns `NotKeyServer` by design per Cl.9.5.
        Err(PaeError::NotKeyServer)
    }

    fn unwrap_sak(&self, wrapped: &[u8], kek: &Kek, an: u8) -> Result<Sak, PaeError> {
        // Per IEEE 802.1X-2020 Cl.9.8: unwrap the SAK using AES Key
        // Wrap (RFC 3394) with the KEK derived from the CAK per Cl.9.6.
        let plaintext = pae::aes_key_unwrap(wrapped, kek.as_bytes())?;
        Sak::from_bytes(&plaintext, an)
            .map_err(|e| PaeError::CryptoError(format!("unwrapped SAK invalid: {}", e)))
    }

    fn compute_icv(&self, payload: &[u8], ick: &Ick) -> Result<[u8; 16], PaeError> {
        pae::compute_icv(payload, ick)
    }

    fn verify_icv(&self, payload: &[u8], icv: &[u8], ick: &Ick) -> Result<(), PaeError> {
        // `pae::verify_icv` expects a fixed-size 16-byte ICV; the
        // trait passes a slice from the wire, so we reject any length
        // mismatch up-front rather than have `verify_icv` panic on
        // the cast.
        let icv_arr: &[u8; 16] = icv.try_into().map_err(|_| PaeError::IcvFailed)?;
        pae::verify_icv(payload, icv_arr, ick)
    }

    fn random_mi(&self) -> [u8; 12] {
        // Per Cl.9.4 a fresh 12-byte MI is drawn from the system CSPRNG.
        // `SystemRng::random_mi` propagates `PaeError` on getrandom
        // failure; the trait signature here is infallible, so on
        // failure we fall back to an all-zero MI and log. An all-zero
        // MI is harmless because the MKPDU ICV-binding immediately
        // rejects any peer claiming it, but in practice `getrandom`
        // failing on a Linux host with `CAP_NET_RAW` is a deeper
        // system problem.
        match SystemRng.random_mi() {
            Ok(mi) => mi,
            Err(e) => {
                tracing::error!(error = %e, "mka-adapter: random_mi fallback to zeros");
                [0u8; 12]
            }
        }
    }

    fn now(&self) -> Duration {
        self.started_at.elapsed()
    }

    fn send_mkpdu(&self, mkpdu: &[u8]) -> Result<(), PaeError> {
        // Per Cl.11: wrap the MKPDU in an EAPOL-MKA frame
        // (`EapolPacketType::EapolMka = 0x05`) and send to the PAE
        // group address §11.1.1.
        let frame = EapolFrame::mka(mkpdu.to_vec());
        let bytes = frame
            .encode()
            .map_err(|e| PaeError::InvalidMkpdu(format!("EAPOL encode: {e}")))?;
        self.network
            .send_eapol(PAE_GROUP_ADDR, &bytes)
            .map_err(|e| PaeError::InvalidMkpdu(format!("send_eapol: {e}")))?;
        tracing::trace!(len = bytes.len(), "mka-adapter: sent EAPOL-MKA frame");
        Ok(())
    }
}
