//! Controlled Port state machine per IEEE 802.1X-2020, Clause 10.
//!
//! Implements: #29 (REQ-F-CP-001), #30 (REQ-F-CP-002), #31 (REQ-F-CP-003), #32 (REQ-F-CP-004)
//! Architecture: #74 (ADR-SM-002), #76 (ADR-SEC-004)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use crate::mka::{CipherSuite, Sak, Sci};

/// Controlled Port state.
///
/// Per IEEE 802.1X-2020, Clause 10.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CpState {
    /// Controlled Port is disabled (blocked).
    Disabled,
    /// Controlled Port is unsecured (open, no MACsec).
    Unsecured,
    /// Controlled Port is secured (MACsec active).
    Secured,
}

/// Events that drive CP state transitions.
///
/// Per IEEE 802.1X-2020, Clause 10.
#[derive(Debug)]
pub enum CpEvent {
    /// Logon Process requests port enable (unsecured).
    EnableUnsecured,
    /// Logon Process or MKA requests port disable.
    Disable,
    /// MKA has produced a new SAK for installation.
    SakAvailable {
        /// The SAK to install.
        sak: Sak,
        /// SCI for the secure channel.
        sci: Sci,
        /// Cipher suite for the secure channel.
        cipher_suite: CipherSuite,
    },
    /// SAK retire timer expired.
    SakRetireExpired,
}

/// Secure Channel — represents an active MACsec secure channel.
///
/// Per IEEE 802.1X-2020, Clause 9.10.
/// Tracks the number of active SAs (at most 4: AN 0-3).
///
/// Implements: #31 (REQ-F-CP-003: Secure Channel/SA Management)
#[derive(Debug, Clone)]
pub struct SecureChannel {
    /// SCI for this channel.
    sci: Sci,
    /// Cipher suite in use.
    cipher_suite: CipherSuite,
    /// Channel offset for XPN mode.
    offset: u64,
    /// Number of active SAs in this channel.
    active_sa_count: usize,
}

impl SecureChannel {
    /// Create a new secure channel.
    pub fn new(sci: Sci, cipher_suite: CipherSuite) -> Self {
        Self {
            sci,
            cipher_suite,
            offset: 0,
            active_sa_count: 1,
        }
    }

    /// SCI for this channel.
    pub fn sci(&self) -> &Sci {
        &self.sci
    }

    /// Cipher suite in use.
    pub fn cipher_suite(&self) -> CipherSuite {
        self.cipher_suite
    }

    /// Channel offset (XPN mode).
    pub fn offset(&self) -> u64 {
        self.offset
    }

    /// Number of active SAs in this channel.
    pub fn active_sa_count(&self) -> usize {
        self.active_sa_count
    }

    /// Key length in bytes for this channel's cipher suite. Per Cl.9.7.
    pub fn key_len(&self) -> usize {
        self.cipher_suite.key_len()
    }

    /// Whether this channel uses XPN (extended packet number). Per Cl.9.7.
    pub fn is_xpn(&self) -> bool {
        self.cipher_suite.is_xpn()
    }
}

/// Secure Association — represents a SAK within a Secure Channel.
///
/// Per IEEE 802.1X-2020, Clause 9.10.
/// Lifecycle: receive-only → receive+transmit → retired.
///
/// Implements: #31 (REQ-F-CP-003: Secure Channel/SA Management)
#[derive(Debug, Clone)]
pub struct SecureAssociation {
    /// Association Number (AN), 0-3.
    an: u8,
    /// Whether this SA is receiving.
    receiving: bool,
    /// Whether this SA is transmitting.
    transmitting: bool,
    /// Whether this SA has been retired.
    retired: bool,
}

impl SecureAssociation {
    /// Create a new secure association in receive-only mode.
    ///
    /// Per Cl.9.10: SAK install enables receive first.
    /// Transmit is enabled after Key Server distributes SAKuse parameters.
    pub fn new(an: u8) -> Self {
        Self {
            an,
            receiving: true,
            transmitting: false,
            retired: false,
        }
    }

    /// Association Number.
    pub fn an(&self) -> u8 {
        self.an
    }

    /// Whether this SA is receiving.
    pub fn is_receiving(&self) -> bool {
        self.receiving
    }

    /// Whether this SA is transmitting.
    pub fn is_transmitting(&self) -> bool {
        self.transmitting
    }

    /// Whether this SA has been retired.
    pub fn is_retired(&self) -> bool {
        self.retired
    }

    /// Enable transmit on this SA. Per Cl.9.10.
    ///
    /// Called after Key Server distributes SAKuse parameters.
    pub fn enable_transmit(&mut self) {
        self.transmitting = true;
    }

    /// Retire this SA. Per Cl.9.10.
    ///
    /// Called when SAK Retire timer expires. Clears both receive and transmit.
    pub fn retire(&mut self) {
        self.receiving = false;
        self.transmitting = false;
        self.retired = true;
    }
}

/// CP State Machine — manages Controlled Port transitions.
///
/// Per IEEE 802.1X-2020, Clause 10 and Clause 12.3.
/// Transitions driven by MKA SAK installation and Logon Process.
///
/// Implements: #29 (REQ-F-CP-001), #30 (REQ-F-CP-002)
///
/// State transitions (INV-PAE-006):
/// - `Disabled` → `Unsecured`: on `EnableUnsecured` or `authenticated=TRUE`
/// - `Unsecured` → `Secured`: on `SakAvailable` or `secure=TRUE`
/// - `Secured` → `Disabled`: on `Disable` or `failed=TRUE`
/// - `Unsecured` → `Disabled`: on `Disable` or `failed=TRUE`
/// - `Secured` → `Unsecured`: on `SakRetireExpired` (SAK retired, fall back)
pub struct CpStateMachine {
    /// Current CP state.
    state: CpState,
    /// Port identifier.
    port_id: u32,
    /// Current Secure Channel (if in Secured state).
    secure_channel: Option<SecureChannel>,
    /// Current Secure Association (if SAK installed).
    current_sa: Option<SecureAssociation>,
    /// Old Secure Association pending retirement (SAK rekey scenario).
    old_sa: Option<SecureAssociation>,
    /// Per Cl.12.3: principal actor signals MACsec is active.
    secure: bool,
    /// Per Cl.12.3: principal actor signals authentication succeeded.
    authenticated: bool,
    /// Per Cl.12.3: all actors have failed.
    failed: bool,
    /// Per Cl.12.3: state change notification flag.
    new_info: bool,
}

impl CpStateMachine {
    /// Create a new CP state machine in Disabled state. Per Cl.10.
    pub fn new(port_id: u32) -> Self {
        Self {
            state: CpState::Disabled,
            port_id,
            secure_channel: None,
            current_sa: None,
            old_sa: None,
            secure: false,
            authenticated: false,
            failed: false,
            new_info: false,
        }
    }

    /// Process a CP event. Per Cl.10.
    ///
    /// Returns events generated by the transition.
    ///
    /// # Errors
    /// Returns `PaeError::InvalidTransition` for invalid transitions.
    pub fn handle_event(&mut self, event: CpEvent) -> Result<Vec<CpTransition>, crate::PaeError> {
        match event {
            CpEvent::EnableUnsecured => self.enable_unsecured(),
            CpEvent::Disable => self.disable(),
            CpEvent::SakAvailable {
                sak,
                sci,
                cipher_suite,
            } => self.install_sak(sak, sci, cipher_suite),
            CpEvent::SakRetireExpired => self.retire_sak(),
        }
    }

    /// Current CP state.
    pub fn state(&self) -> CpState {
        self.state
    }

    /// Port identifier.
    pub fn port_id(&self) -> u32 {
        self.port_id
    }

    /// Current secure channel, if any.
    pub fn secure_channel(&self) -> Option<&SecureChannel> {
        self.secure_channel.as_ref()
    }

    /// Current secure association, if any.
    pub fn current_sa(&self) -> Option<&SecureAssociation> {
        self.current_sa.as_ref()
    }

    /// Whether the Controlled Port is MAC_Operational.
    ///
    /// Per Cl.10: the port is operational in Unsecured or Secured states.
    pub fn is_operational(&self) -> bool {
        matches!(self.state, CpState::Unsecured | CpState::Secured)
    }

    /// Whether MACsec protection is active.
    pub fn is_macsec_active(&self) -> bool {
        self.state == CpState::Secured
    }

    // --- Clause 12.3 Interface Variables (REQ-F-CP-002, #30) ---

    /// Per Cl.12.3: controlledPortEnabled.
    ///
    /// TRUE when the Controlled Port is operational (Unsecured or Secured)
    /// and not failed. FALSE in Disabled or when failed=TRUE.
    pub fn controlled_port_enabled(&self) -> bool {
        if self.failed {
            return false;
        }
        self.secure || self.authenticated
    }

    /// Per Cl.12.3: secure — principal actor signals MACsec is active.
    pub fn secure(&self) -> bool {
        self.secure
    }

    /// Per Cl.12.3: authenticated — principal actor signals authentication succeeded.
    pub fn authenticated(&self) -> bool {
        self.authenticated
    }

    /// Per Cl.12.3: failed — all actors have failed.
    pub fn failed(&self) -> bool {
        self.failed
    }

    /// Per Cl.12.3: newInfo — state change notification flag.
    pub fn new_info(&self) -> bool {
        self.new_info
    }

    /// Per Cl.12.3: set the secure signal from the principal actor.
    ///
    /// When secure changes, updates `new_info` and recomputes CP state.
    pub fn set_secure(&mut self, value: bool) {
        if self.secure != value {
            self.secure = value;
            self.new_info = true;
            self.recompute_state();
        }
    }

    /// Per Cl.12.3: set the authenticated signal from the principal actor.
    ///
    /// When authenticated changes, updates `new_info` and recomputes CP state.
    pub fn set_authenticated(&mut self, value: bool) {
        if self.authenticated != value {
            self.authenticated = value;
            self.new_info = true;
            self.recompute_state();
        }
    }

    /// Per Cl.12.3: set the failed signal from the principal actor.
    ///
    /// When failed changes, updates `new_info` and recomputes CP state.
    pub fn set_failed(&mut self, value: bool) {
        if self.failed != value {
            self.failed = value;
            self.new_info = true;
            self.recompute_state();
        }
    }

    /// Per Cl.12.3: clear the newInfo flag after the consumer has read it.
    pub fn clear_new_info(&mut self) {
        self.new_info = false;
    }

    // --- REQ-F-CP-003: Secure Channel/SA Management (Clause 9.10, #31) ---

    /// Old Secure Association pending retirement, if any.
    ///
    /// Per Cl.9.10: after SAK rekey, the old SA remains until SAK Retire timer expires.
    pub fn old_sa(&self) -> Option<&SecureAssociation> {
        self.old_sa.as_ref()
    }

    /// Number of old SAs pending retirement.
    pub fn old_sa_count(&self) -> usize {
        if self.old_sa.is_some() {
            1
        } else {
            0
        }
    }

    /// Enable transmit on the current SA for the specified AN.
    ///
    /// Per Cl.9.10: called after Key Server distributes SAKuse parameters.
    ///
    /// # Errors
    /// Returns `PaeError::InvalidTransition` if no SA is installed or AN doesn't match.
    pub fn enable_sa_transmit(&mut self, an: u8) -> Result<(), crate::PaeError> {
        if let Some(ref mut sa) = self.current_sa {
            if sa.an() == an {
                sa.enable_transmit();
                return Ok(());
            }
        }
        Err(crate::PaeError::InvalidTransition {
            from: format!("AN={}", an),
            to: "transmit enabled".into(),
        })
    }

    /// Recompute CP state from interface variables per Cl.12.3.
    ///
    /// Priority: failed > secure > authenticated.
    /// - failed=TRUE → Disabled
    /// - secure=TRUE → Secured
    /// - authenticated=TRUE → Unsecured
    /// - else → Disabled
    fn recompute_state(&mut self) {
        let new_state = if self.failed {
            CpState::Disabled
        } else if self.secure {
            CpState::Secured
        } else if self.authenticated {
            CpState::Unsecured
        } else {
            CpState::Disabled
        };

        if self.state != new_state {
            // Clear secure channel when leaving Secured
            if self.state == CpState::Secured && new_state != CpState::Secured {
                self.secure_channel = None;
                self.current_sa = None;
                self.old_sa = None;
            }
            self.state = new_state;
        }
    }

    fn enable_unsecured(&mut self) -> Result<Vec<CpTransition>, crate::PaeError> {
        match self.state {
            CpState::Disabled => {
                self.authenticated = true;
                self.new_info = true;
                self.state = CpState::Unsecured;
                Ok(vec![CpTransition::ToUnsecured {
                    port_id: self.port_id,
                }])
            }
            CpState::Unsecured => Ok(vec![]), // Already unsecured, no-op
            CpState::Secured => Err(crate::PaeError::InvalidTransition {
                from: "Secured".into(),
                to: "Unsecured".into(),
            }),
        }
    }

    fn disable(&mut self) -> Result<Vec<CpTransition>, crate::PaeError> {
        match self.state {
            CpState::Disabled => Ok(vec![]), // Already disabled, no-op
            CpState::Unsecured => {
                self.authenticated = false;
                self.new_info = true;
                self.state = CpState::Disabled;
                Ok(vec![CpTransition::ToDisabled {
                    port_id: self.port_id,
                }])
            }
            CpState::Secured => {
                self.secure = false;
                self.authenticated = false;
                self.new_info = true;
                self.secure_channel = None;
                self.current_sa = None;
                self.old_sa = None;
                self.state = CpState::Disabled;
                Ok(vec![CpTransition::ToDisabled {
                    port_id: self.port_id,
                }])
            }
        }
    }

    fn install_sak(
        &mut self,
        sak: Sak,
        sci: Sci,
        cipher_suite: CipherSuite,
    ) -> Result<Vec<CpTransition>, crate::PaeError> {
        // Validate SAK key length matches cipher suite per Cl.9.7
        if sak.as_bytes().len() != cipher_suite.key_len() {
            return Err(crate::PaeError::KeyError(format!(
                "SAK length {} does not match cipher suite key length {}",
                sak.as_bytes().len(),
                cipher_suite.key_len()
            )));
        }

        match self.state {
            CpState::Disabled => Err(crate::PaeError::InvalidTransition {
                from: "Disabled".into(),
                to: "Secured".into(),
            }),
            CpState::Unsecured => {
                let an = sak.an();
                self.secure = true;
                self.new_info = true;
                self.secure_channel = Some(SecureChannel::new(sci, cipher_suite));
                self.current_sa = Some(SecureAssociation::new(an));
                self.state = CpState::Secured;
                Ok(vec![CpTransition::ToSecured {
                    port_id: self.port_id,
                }])
            }
            CpState::Secured => {
                // SAK rekey: retire current SA, install new one
                let an = sak.an();
                self.new_info = true;
                // Move current SA to old_sa (pending retirement)
                if let Some(mut old) = self.current_sa.take() {
                    old.retire();
                    self.old_sa = Some(old);
                }
                self.secure_channel = Some(SecureChannel::new(sci, cipher_suite));
                self.current_sa = Some(SecureAssociation::new(an));
                Ok(vec![CpTransition::SakRekeyed {
                    port_id: self.port_id,
                }])
            }
        }
    }

    fn retire_sak(&mut self) -> Result<Vec<CpTransition>, crate::PaeError> {
        match self.state {
            CpState::Secured => {
                // If there's an old SA pending retirement, remove it
                if self.old_sa.is_some() {
                    self.old_sa = None;
                    // Stay in Secured — current SA is still active
                    return Ok(vec![]);
                }
                // No old SA: retire the current SA and fall back to Unsecured
                self.secure = false;
                self.new_info = true;
                self.current_sa = None;
                self.secure_channel = None;
                self.state = CpState::Unsecured;
                Ok(vec![CpTransition::ToUnsecured {
                    port_id: self.port_id,
                }])
            }
            CpState::Unsecured | CpState::Disabled => {
                // No SAK to retire; no-op
                Ok(vec![])
            }
        }
    }
}

/// CP state transition outcomes.
///
/// Returned by `CpStateMachine::handle_event()` to signal what happened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CpTransition {
    /// Port transitioned to Unsecured.
    ToUnsecured {
        /// Port identifier.
        port_id: u32,
    },
    /// Port transitioned to Secured.
    ToSecured {
        /// Port identifier.
        port_id: u32,
    },
    /// Port transitioned to Disabled.
    ToDisabled {
        /// Port identifier.
        port_id: u32,
    },
    /// SAK was rekeyed (stayed in Secured).
    SakRekeyed {
        /// Port identifier.
        port_id: u32,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per IEEE 802.1X-2020, Clause 10.
    /// CP state machine starts in Disabled state.
    #[test]
    fn test_cp_initial_state() {
        let cp = CpStateMachine::new(1);
        assert_eq!(cp.state(), CpState::Disabled);
        assert!(!cp.is_operational());
        assert!(!cp.is_macsec_active());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per Cl.10: Disabled → Unsecured on EnableUnsecured.
    #[test]
    fn test_cp_disabled_to_unsecured() {
        let mut cp = CpStateMachine::new(1);
        let transitions = cp
            .handle_event(CpEvent::EnableUnsecured)
            .expect("EnableUnsecured should succeed");
        assert_eq!(cp.state(), CpState::Unsecured);
        assert!(cp.is_operational());
        assert!(!cp.is_macsec_active());
        assert_eq!(transitions, vec![CpTransition::ToUnsecured { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per Cl.10: Unsecured → Secured on SakAvailable.
    #[test]
    fn test_cp_unsecured_to_secured() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        let transitions = cp
            .handle_event(CpEvent::SakAvailable {
                sak,
                sci,
                cipher_suite: CipherSuite::GcmAes128,
            })
            .expect("SakAvailable should succeed");
        assert_eq!(cp.state(), CpState::Secured);
        assert!(cp.is_operational());
        assert!(cp.is_macsec_active());
        assert!(cp.secure_channel().is_some());
        assert!(cp.current_sa().is_some());
        assert_eq!(transitions, vec![CpTransition::ToSecured { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per Cl.10: Full cycle Disabled → Unsecured → Secured → Disabled.
    #[test]
    fn test_cp_full_cycle() {
        let mut cp = CpStateMachine::new(1);

        // Disabled → Unsecured
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        assert_eq!(cp.state(), CpState::Unsecured);

        // Unsecured → Secured
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert_eq!(cp.state(), CpState::Secured);

        // Secured → Disabled
        let transitions = cp.handle_event(CpEvent::Disable).unwrap();
        assert_eq!(cp.state(), CpState::Disabled);
        assert!(cp.secure_channel().is_none());
        assert!(cp.current_sa().is_none());
        assert_eq!(transitions, vec![CpTransition::ToDisabled { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per Cl.10: Secured → Unsecured on SakRetireExpired.
    #[test]
    fn test_cp_sak_retire() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert_eq!(cp.state(), CpState::Secured);

        let transitions = cp
            .handle_event(CpEvent::SakRetireExpired)
            .expect("SakRetireExpired should succeed");
        assert_eq!(cp.state(), CpState::Unsecured);
        assert!(cp.is_operational());
        assert!(!cp.is_macsec_active());
        assert!(cp.secure_channel().is_none());
        assert_eq!(transitions, vec![CpTransition::ToUnsecured { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// SAK rekey in Secured state stays in Secured.
    #[test]
    fn test_cp_sak_rekey() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak1 = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci1 = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak1,
            sci: sci1,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();

        // Rekey with new SAK (AN=1)
        let sak2 = Sak::from_bytes(&[0x03; 16], 1).unwrap();
        let sci2 = Sci::new([0x04; 6], 1);
        let transitions = cp
            .handle_event(CpEvent::SakAvailable {
                sak: sak2,
                sci: sci2,
                cipher_suite: CipherSuite::GcmAes128,
            })
            .expect("SAK rekey should succeed");
        assert_eq!(cp.state(), CpState::Secured);
        assert_eq!(cp.current_sa().unwrap().an(), 1);
        assert_eq!(transitions, vec![CpTransition::SakRekeyed { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Disabled → Secured is invalid.
    #[test]
    fn test_cp_disabled_to_secured_invalid() {
        let mut cp = CpStateMachine::new(1);
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        let result = cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        });
        assert!(result.is_err());
        assert_eq!(cp.state(), CpState::Disabled);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Secured → Unsecured via EnableUnsecured is invalid.
    #[test]
    fn test_cp_secured_to_unsecured_invalid() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();

        let result = cp.handle_event(CpEvent::EnableUnsecured);
        assert!(result.is_err());
        assert_eq!(cp.state(), CpState::Secured);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Disable on already-Disabled is a no-op.
    #[test]
    fn test_cp_disable_noop() {
        let mut cp = CpStateMachine::new(1);
        let transitions = cp
            .handle_event(CpEvent::Disable)
            .expect("Disable on Disabled should be no-op");
        assert_eq!(cp.state(), CpState::Disabled);
        assert!(transitions.is_empty());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// EnableUnsecured on already-Unsecured is a no-op.
    #[test]
    fn test_cp_enable_unsecured_noop() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let transitions = cp
            .handle_event(CpEvent::EnableUnsecured)
            .expect("EnableUnsecured on Unsecured should be no-op");
        assert_eq!(cp.state(), CpState::Unsecured);
        assert!(transitions.is_empty());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// SakRetireExpired on Unsecured/Disabled is a no-op.
    #[test]
    fn test_cp_retire_noop() {
        let mut cp = CpStateMachine::new(1);
        let transitions = cp
            .handle_event(CpEvent::SakRetireExpired)
            .expect("SakRetire on Disabled should be no-op");
        assert!(transitions.is_empty());

        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let transitions = cp
            .handle_event(CpEvent::SakRetireExpired)
            .expect("SakRetire on Unsecured should be no-op");
        assert!(transitions.is_empty());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Unsecured → Disabled on Disable.
    #[test]
    fn test_cp_unsecured_to_disabled() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let transitions = cp
            .handle_event(CpEvent::Disable)
            .expect("Disable should succeed");
        assert_eq!(cp.state(), CpState::Disabled);
        assert!(!cp.is_operational());
        assert_eq!(transitions, vec![CpTransition::ToDisabled { port_id: 1 }]);
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Secure channel and association are set correctly on SAK install.
    #[test]
    fn test_cp_secure_channel_after_sak() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 32], 2).unwrap();
        let sci = Sci::new([0xAA; 6], 42);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes256,
        })
        .unwrap();

        let sc = cp.secure_channel().expect("secure channel should exist");
        assert_eq!(sc.sci().mac(), &[0xAA; 6]);
        assert_eq!(sc.sci().port(), 42);
        assert_eq!(sc.cipher_suite(), CipherSuite::GcmAes256);

        let sa = cp.current_sa().expect("secure association should exist");
        assert_eq!(sa.an(), 2);
        assert!(sa.is_receiving());
        assert!(!sa.is_transmitting());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per REQ-F-CP-001 acceptance: authentication succeeds and MKA establishes
    /// secured connectivity → controlledPortEnabled → MAC_Operational.
    #[test]
    fn test_cp_acceptance_secured() {
        let mut cp = CpStateMachine::new(1);
        // Authentication succeeds → EnableUnsecured
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        assert!(cp.is_operational());

        // MKA establishes secured connectivity → SakAvailable
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert!(cp.is_operational());
        assert!(cp.is_macsec_active());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per REQ-F-CP-001 acceptance: MKA fails → controlledPortEnabled cleared →
    /// Controlled Port MAC_Operational=FALSE.
    #[test]
    fn test_cp_acceptance_mka_fails() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();

        // MKA fails → Disable
        cp.handle_event(CpEvent::Disable).unwrap();
        assert!(!cp.is_operational());
        assert!(!cp.is_macsec_active());
    }

    /// Verifies: #29 (REQ-F-CP-001)
    /// Per REQ-F-CP-001 acceptance: authentication succeeds without MACsec →
    /// controlledPortEnabled without MACsec protection.
    #[test]
    fn test_cp_acceptance_unsecured() {
        let mut cp = CpStateMachine::new(1);
        // Authentication succeeds without MACsec → EnableUnsecured
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        assert!(cp.is_operational());
        assert!(!cp.is_macsec_active());
    }

    // --- REQ-F-CP-002: CP State Machine Interface (Clause 12.3) ---

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// controlledPortEnabled is FALSE in Disabled state.
    #[test]
    fn test_cp_controlled_port_disabled() {
        let cp = CpStateMachine::new(1);
        assert!(!cp.controlled_port_enabled());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// controlledPortEnabled is TRUE in Unsecured state (authenticated without MACsec).
    #[test]
    fn test_cp_controlled_port_unsecured() {
        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        assert!(cp.controlled_port_enabled());
        assert!(!cp.secure());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// When secure=TRUE, controlledPortEnabled is TRUE and MACsec is enabled.
    #[test]
    fn test_cp_controlled_port_secured() {
        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        cp.set_secure(true);
        assert!(cp.controlled_port_enabled());
        assert!(cp.secure());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// When failed=TRUE, controlledPortEnabled is cleared.
    #[test]
    fn test_cp_controlled_port_failed() {
        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        assert!(cp.controlled_port_enabled());

        cp.set_failed(true);
        assert!(!cp.controlled_port_enabled());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// newInfo is set when CP state changes and cleared after read.
    #[test]
    fn test_cp_new_info_on_transition() {
        let mut cp = CpStateMachine::new(1);
        assert!(!cp.new_info());

        cp.set_authenticated(true);
        assert!(cp.new_info());

        // Clear after read
        cp.clear_new_info();
        assert!(!cp.new_info());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// secure starts FALSE and becomes TRUE when principal actor is secured.
    #[test]
    fn test_cp_secure_interface_variable() {
        let cp = CpStateMachine::new(1);
        assert!(!cp.secure());

        let mut cp = CpStateMachine::new(1);
        cp.set_secure(true);
        assert!(cp.secure());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// authenticated starts FALSE and becomes TRUE when principal actor authenticates.
    #[test]
    fn test_cp_authenticated_interface_variable() {
        let cp = CpStateMachine::new(1);
        assert!(!cp.authenticated());

        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        assert!(cp.authenticated());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// failed starts FALSE and becomes TRUE when all actors have failed.
    #[test]
    fn test_cp_failed_interface_variable() {
        let cp = CpStateMachine::new(1);
        assert!(!cp.failed());

        let mut cp = CpStateMachine::new(1);
        cp.set_failed(true);
        assert!(cp.failed());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// secure=TRUE implies controlledPortEnabled=TRUE regardless of authenticated.
    #[test]
    fn test_cp_secure_implies_enabled() {
        let mut cp = CpStateMachine::new(1);
        cp.set_secure(true);
        assert!(cp.controlled_port_enabled());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// failed=TRUE clears controlledPortEnabled even if secure was TRUE.
    #[test]
    fn test_cp_failed_overrides_secure() {
        let mut cp = CpStateMachine::new(1);
        cp.set_secure(true);
        assert!(cp.controlled_port_enabled());

        cp.set_failed(true);
        assert!(!cp.controlled_port_enabled());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// Clearing failed allows controlledPortEnabled to reflect secure/authenticated again.
    #[test]
    fn test_cp_clear_failed_restores_state() {
        let mut cp = CpStateMachine::new(1);
        cp.set_secure(true);
        cp.set_failed(true);
        assert!(!cp.controlled_port_enabled());

        cp.set_failed(false);
        assert!(cp.controlled_port_enabled());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// newInfo is set when secure changes.
    #[test]
    fn test_cp_new_info_on_secure_change() {
        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        cp.clear_new_info();

        cp.set_secure(true);
        assert!(cp.new_info());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// newInfo is set when failed changes.
    #[test]
    fn test_cp_new_info_on_failed_change() {
        let mut cp = CpStateMachine::new(1);
        cp.set_authenticated(true);
        cp.clear_new_info();

        cp.set_failed(true);
        assert!(cp.new_info());
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// CpState reflects interface variables: secure→Secured, authenticated→Unsecured, failed→Disabled.
    #[test]
    fn test_cp_state_reflects_interface() {
        let mut cp = CpStateMachine::new(1);
        assert_eq!(cp.state(), CpState::Disabled);

        cp.set_authenticated(true);
        assert_eq!(cp.state(), CpState::Unsecured);

        cp.set_secure(true);
        assert_eq!(cp.state(), CpState::Secured);

        cp.set_failed(true);
        assert_eq!(cp.state(), CpState::Disabled);
    }

    /// Verifies: #30 (REQ-F-CP-002)
    /// Per IEEE 802.1X-2020, Clause 12.3.
    /// CpState is Unsecured when authenticated=TRUE and secure=FALSE.
    #[test]
    fn test_cp_state_unsecured_when_authenticated_not_secure() {
        let mut cp = CpStateMachine::new(1);
        cp.set_secure(true);
        cp.set_secure(false);
        // secure=FALSE, authenticated defaults to FALSE, so state is Disabled
        assert_eq!(cp.state(), CpState::Disabled);

        cp.set_authenticated(true);
        // authenticated=TRUE, secure=FALSE → Unsecured
        assert_eq!(cp.state(), CpState::Unsecured);
    }

    // --- REQ-F-CP-003: Secure Channel/SA Management (Clause 9.10) ---

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// New SA starts with receive=TRUE, transmit=FALSE (receive-only first).
    #[test]
    fn test_sa_new_receive_only() {
        let sa = SecureAssociation::new(0);
        assert!(sa.is_receiving());
        assert!(
            !sa.is_transmitting(),
            "new SA should be receive-only initially"
        );
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SA can be promoted to transmit after Key Server distributes SAKuse.
    #[test]
    fn test_sa_enable_transmit() {
        let mut sa = SecureAssociation::new(0);
        assert!(!sa.is_transmitting());
        sa.enable_transmit();
        assert!(sa.is_transmitting());
        assert!(sa.is_receiving(), "receiving should remain TRUE");
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SA can be retired (both receive and transmit cleared).
    #[test]
    fn test_sa_retire() {
        let mut sa = SecureAssociation::new(2);
        sa.enable_transmit();
        sa.retire();
        assert!(!sa.is_receiving());
        assert!(!sa.is_transmitting());
        assert!(sa.is_retired());
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// CP can track old SA pending retirement alongside new SA.
    #[test]
    fn test_cp_sak_rekey_retires_old_sa() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        // Install first SAK (AN=0)
        let sak0 = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak0,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert_eq!(cp.current_sa().unwrap().an(), 0);

        // Rekey with new SAK (AN=1) — old SA should be pending retirement
        let sak1 = Sak::from_bytes(&[0x03; 16], 1).unwrap();
        let sci2 = Sci::new([0x04; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak1,
            sci: sci2,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert_eq!(cp.current_sa().unwrap().an(), 1);
        // Old SA (AN=0) should be pending retirement
        assert_eq!(cp.old_sa().unwrap().an(), 0);
        assert!(cp.old_sa().unwrap().is_retired());
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SAK retire timer expires — old SA is removed from the SC.
    #[test]
    fn test_cp_sak_retire_removes_old_sa() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        let sak0 = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak0,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();

        let sak1 = Sak::from_bytes(&[0x03; 16], 1).unwrap();
        let sci2 = Sci::new([0x04; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak1,
            sci: sci2,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert!(cp.old_sa().is_some());

        // SAK retire timer fires — old SA removed
        cp.handle_event(CpEvent::SakRetireExpired).unwrap();
        assert!(
            cp.old_sa().is_none(),
            "old SA should be removed after retire"
        );
        // Current SA should still be active
        assert_eq!(cp.current_sa().unwrap().an(), 1);
        // State should remain Secured
        assert_eq!(cp.state(), CpState::Secured);
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SAK install enables receive then transmit for the specified AN.
    #[test]
    fn test_cp_sak_install_receive_then_transmit() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        let sak = Sak::from_bytes(&[0x01; 16], 2).unwrap();
        let sci = Sci::new([0xAA; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();

        // After install: receive=TRUE, transmit=FALSE (per Cl.9.10)
        let sa = cp.current_sa().unwrap();
        assert!(sa.is_receiving());
        assert!(
            !sa.is_transmitting(),
            "transmit should be FALSE until SAKuse distributed"
        );

        // Key Server distributes SAKuse → enable transmit
        cp.enable_sa_transmit(2);
        let sa = cp.current_sa().unwrap();
        assert!(sa.is_transmitting());
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SecureChannel tracks its active and pending-retirement SAs.
    #[test]
    fn test_cp_secure_channel_sa_count() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0x02; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        // 1 active SA, 0 old SAs
        assert_eq!(cp.secure_channel().unwrap().active_sa_count(), 1);
        assert_eq!(cp.old_sa_count(), 0);

        // Rekey
        let sak1 = Sak::from_bytes(&[0x03; 16], 1).unwrap();
        let sci2 = Sci::new([0x04; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak1,
            sci: sci2,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        // 1 active SA, 1 old SA pending retirement
        assert_eq!(cp.secure_channel().unwrap().active_sa_count(), 1);
        assert_eq!(cp.old_sa_count(), 1);
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// AN must be in range 0-3.
    #[test]
    fn test_sa_an_range() {
        assert!(SecureAssociation::new(0).an() == 0);
        assert!(SecureAssociation::new(3).an() == 3);
    }

    /// Verifies: #31 (REQ-F-CP-003)
    /// Per IEEE 802.1X-2020, Clause 9.10.
    /// SA has a retired state that indicates it is no longer in use.
    #[test]
    fn test_sa_state_lifecycle() {
        let mut sa = SecureAssociation::new(1);
        // Initial: receive-only
        assert!(sa.is_receiving());
        assert!(!sa.is_transmitting());
        assert!(!sa.is_retired());

        // After transmit enabled: full operation
        sa.enable_transmit();
        assert!(sa.is_receiving());
        assert!(sa.is_transmitting());
        assert!(!sa.is_retired());

        // After retire: no longer active
        sa.retire();
        assert!(!sa.is_receiving());
        assert!(!sa.is_transmitting());
        assert!(sa.is_retired());
    }

    // --- REQ-F-CP-004: MACsec Cipher Suite Support (Clause 9.7) ---

    /// Verifies: #32 (REQ-F-CP-004)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-128 SAK has 16-byte key and SecureChannel is configured.
    #[test]
    fn test_cp_cipher_suite_gcm_aes_128() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0xAA; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        let sc = cp.secure_channel().unwrap();
        assert_eq!(sc.cipher_suite(), CipherSuite::GcmAes128);
        assert_eq!(sc.key_len(), 16);
        assert!(!sc.is_xpn());
    }

    /// Verifies: #32 (REQ-F-CP-004)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-256 SAK has 32-byte key and SecureChannel is configured.
    #[test]
    fn test_cp_cipher_suite_gcm_aes_256() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 32], 0).unwrap();
        let sci = Sci::new([0xAA; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes256,
        })
        .unwrap();
        let sc = cp.secure_channel().unwrap();
        assert_eq!(sc.cipher_suite(), CipherSuite::GcmAes256);
        assert_eq!(sc.key_len(), 32);
        assert!(!sc.is_xpn());
    }

    /// Verifies: #32 (REQ-F-CP-004)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// GCM-AES-XPN-256 SAK has 32-byte key and XPN mode is enabled.
    #[test]
    fn test_cp_cipher_suite_gcm_aes_xpn_256() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        let sak = Sak::from_bytes(&[0x01; 32], 1).unwrap();
        let sci = Sci::new([0xBB; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAesXpn256,
        })
        .unwrap();
        let sc = cp.secure_channel().unwrap();
        assert_eq!(sc.cipher_suite(), CipherSuite::GcmAesXpn256);
        assert_eq!(sc.key_len(), 32);
        assert!(sc.is_xpn());
    }

    /// Verifies: #32 (REQ-F-CP-004)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// SecureChannel rejects SAK with wrong key length for the cipher suite.
    #[test]
    fn test_cp_cipher_suite_wrong_sak_length() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();
        // 16-byte SAK with AES-256 cipher suite → wrong
        let sak = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci = Sci::new([0xAA; 6], 1);
        let result = cp.handle_event(CpEvent::SakAvailable {
            sak,
            sci,
            cipher_suite: CipherSuite::GcmAes256,
        });
        assert!(
            result.is_err(),
            "SAK with wrong key length must be rejected"
        );
    }

    /// Verifies: #32 (REQ-F-CP-004)
    /// Per IEEE 802.1X-2020, Clause 9.7.
    /// Cipher suite rekey changes the SecureChannel configuration.
    #[test]
    fn test_cp_cipher_suite_rekey() {
        let mut cp = CpStateMachine::new(1);
        cp.handle_event(CpEvent::EnableUnsecured).unwrap();

        // First SAK: AES-128
        let sak0 = Sak::from_bytes(&[0x01; 16], 0).unwrap();
        let sci0 = Sci::new([0xAA; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak0,
            sci: sci0,
            cipher_suite: CipherSuite::GcmAes128,
        })
        .unwrap();
        assert_eq!(
            cp.secure_channel().unwrap().cipher_suite(),
            CipherSuite::GcmAes128
        );

        // Rekey with AES-256
        let sak1 = Sak::from_bytes(&[0x02; 32], 1).unwrap();
        let sci1 = Sci::new([0xBB; 6], 1);
        cp.handle_event(CpEvent::SakAvailable {
            sak: sak1,
            sci: sci1,
            cipher_suite: CipherSuite::GcmAes256,
        })
        .unwrap();
        assert_eq!(
            cp.secure_channel().unwrap().cipher_suite(),
            CipherSuite::GcmAes256
        );
        assert_eq!(cp.secure_channel().unwrap().key_len(), 32);
    }
}
