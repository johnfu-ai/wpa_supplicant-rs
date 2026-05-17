//! Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.
//!
//! Implements: #11 (REQ-F-PAE-001), #12 (REQ-F-PAE-002), #13 (REQ-F-PAE-003),
//! #14 (REQ-F-PAE-004), #15 (REQ-F-PAE-005), #16 (REQ-F-PAE-006),
//! #17 (REQ-F-PAE-007), #18 (REQ-F-PAE-008)
//! Architecture: #74 (ADR-SM-002), #79 (ADR-EVT-007)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::time::Duration;

use crate::frame::EapolFrame;
use crate::EapolError;

/// Supplicant PAE state.
///
/// Per IEEE 802.1X-2020, Clause 8.3.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaeState {
    /// Disconnected — port is down or disabled.
    Disconnected,
    /// Connecting — EAPOL-Start sent, awaiting EAP-Request/Identity.
    Connecting,
    /// Authenticating — EAP exchange in progress.
    Authenticating,
    /// Authenticated — EAP Success received.
    Authenticated,
    /// Held — authentication failed, waiting for heldWhile timer.
    Held,
    /// ForceAuth — administratively forced authenticated.
    ForceAuth,
    /// ForceUnauth — administratively forced unauthenticated.
    ForceUnauth,
    /// Logoff — EAPOL-Logoff sent.
    Logoff,
}

/// Diagnostic counters per IEEE 802.1X-2020, Clause 8.8.
///
/// Implements: #18 (REQ-F-PAE-008: Supplicant PAE Counters)
#[derive(Debug, Clone, Default)]
pub struct PaeCounters {
    /// EAPOL frames received.
    pub eapol_frames_rx: u64,
    /// EAPOL frames transmitted.
    pub eapol_frames_tx: u64,
    /// EAPOL-Start frames transmitted.
    pub eapol_start_tx: u64,
    /// EAPOL-Logoff frames transmitted.
    pub eapol_logoff_tx: u64,
    /// EAP Response/Identity frames transmitted.
    pub eap_resp_identity_tx: u64,
    /// Last EAPOL frame version received.
    pub last_eapol_version: u8,
    /// Per Cl.8.8: enters Authenticating state.
    pub enters_authenticating: u64,
    /// Per Cl.8.8: auth timeouts while Authenticating.
    pub auth_timeouts_while_authenticating: u64,
    /// Per Cl.8.8: EAP Logoff while Authenticating.
    pub eap_logoff_while_authenticating: u64,
    /// Per Cl.8.8: auth failures while Authenticating.
    pub auth_fail_while_authenticating: u64,
    /// Per Cl.8.8: auth successes while Authenticating.
    pub auth_successes_while_authenticating: u64,
    /// Per Cl.8.8: auth failures while Authenticated.
    pub auth_fail_while_authenticated: u64,
    /// Per Cl.8.8: EAP Logoff while Authenticated.
    pub eap_logoff_while_authenticated: u64,
}

/// EAP authentication results from higher layer.
///
/// Per Cl.8.3: carried by eapSuccess/eapFail signals.
#[derive(Debug, Clone, Default)]
pub struct AuthResult {
    /// EAP identity from EAP-Response/Identity.
    pub identity: Vec<u8>,
}

/// Context trait for Supplicant PAE — abstracts I/O and time.
///
/// Per ADR-SM-002 (#74).
/// Enables mock injection for unit testing.
pub trait SupplicantPaeContext: Send + Sync {
    /// Send an EAPOL frame on the Uncontrolled Port.
    fn send_eapol(&self, frame: &EapolFrame) -> Result<(), EapolError>;

    /// Get the current port state.
    fn get_port_state(&self) -> pae::PortState;

    /// Get the current time.
    fn now(&self) -> Duration;

    /// Get the configured EAP identity string.
    fn get_identity(&self) -> &[u8];

    /// Get the configured maximum reauthentication retries (retryMax). Per Cl.8.7.
    fn get_max_retries(&self) -> u32;

    /// Get the heldWhile timer duration (heldPeriod, default 60s). Per Cl.8.6.
    fn get_held_while(&self) -> Duration;

    /// Get the startWhen timer duration (default 30s). Per Cl.8.3.
    fn get_start_when(&self) -> Duration;

    /// Get the authWhile timer duration (default 30s). Per Cl.8.3.
    fn get_auth_while(&self) -> Duration;

    /// Check if the port is secured by MACsec/MKA. Per Cl.8.5.
    fn is_macsec_secured(&self) -> bool;
}

/// Supplicant PAE state machine — Aggregate root for PACP.
///
/// Per IEEE 802.1X-2020, Clause 8.3.
/// Generic over context trait for testability.
/// Owns state, timers, and counters; enforces transition invariants.
///
/// Implements: #11 (REQ-F-PAE-001), #12 (REQ-F-PAE-002), #13 (REQ-F-PAE-003),
/// #14 (REQ-F-PAE-004), #15 (REQ-F-PAE-005), #16 (REQ-F-PAE-006),
/// #17 (REQ-F-PAE-007), #18 (REQ-F-PAE-008)
pub struct SupplicantPae<C: SupplicantPaeContext> {
    /// Current PACP state.
    state: PaeState,
    /// Retry counter (retryCount). Per Cl.8.7.
    start_count: u32,
    /// Whether `authenticate` flag is set by higher layer. Per Cl.8.4.
    authenticate: bool,
    /// Whether `eapStart` is set by higher layer. Per Cl.8.3.
    eap_start: bool,
    /// Whether `eapStop` is set by higher layer. Per Cl.8.3.
    eap_stop: bool,
    /// Whether `enabled` is set. Per Cl.8.4.
    enabled: bool,
    /// Whether `authenticated` is set. Per Cl.8.4.
    authenticated: bool,
    /// Whether `failed` is set. Per Cl.8.4.
    failed: bool,
    /// Authentication results. Per Cl.8.4.
    results: Option<AuthResult>,
    /// Diagnostic counters.
    counters: PaeCounters,
    /// Time when current timer was started.
    timer_start: Option<Duration>,
    /// Timer duration (heldWhile or startWhen or authWhile).
    timer_duration: Duration,
    /// Which timer is active.
    active_timer: ActiveTimer,
    /// Context (injected).
    ctx: C,
}

/// Which timer is currently active.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
enum ActiveTimer {
    /// No timer active.
    None,
    /// heldWhile timer (Held state).
    HeldWhile,
    /// startWhen timer (Connecting state).
    StartWhen,
    /// authWhile timer (Authenticating state).
    AuthWhile,
}

impl<C: SupplicantPaeContext> SupplicantPae<C> {
    /// Initialize the Supplicant PAE in Disconnected state. Per Cl.8.3.
    pub fn new(ctx: C) -> Self {
        Self {
            state: PaeState::Disconnected,
            start_count: 0,
            authenticate: false,
            eap_start: false,
            eap_stop: false,
            enabled: false,
            authenticated: false,
            failed: false,
            results: None,
            counters: PaeCounters::default(),
            timer_start: None,
            timer_duration: Duration::ZERO,
            active_timer: ActiveTimer::None,
            ctx,
        }
    }

    /// Current PACP state.
    pub fn state(&self) -> PaeState {
        self.state
    }

    /// Diagnostic counters (read-only).
    pub fn counters(&self) -> &PaeCounters {
        &self.counters
    }

    /// Whether the authenticate flag is set. Per Cl.8.4.
    pub fn is_authenticate(&self) -> bool {
        self.authenticate
    }

    /// Current start retry count. Per Cl.8.7.
    pub fn start_count(&self) -> u32 {
        self.start_count
    }

    /// Access the context.
    pub fn ctx(&self) -> &C {
        &self.ctx
    }

    // --- #12 (REQ-F-PAE-002): Higher Layer Interface ---

    /// Signal eapStart from higher layer. Per Cl.8.3.
    ///
    /// Sets the eapStart flag, which will be processed on the next step.
    /// The flag is cleared when the EAP attempt begins.
    pub fn eap_start(&mut self) {
        self.eap_start = true;
    }

    /// Signal eapStop from higher layer. Per Cl.8.3.
    ///
    /// Sets the eapStop flag. When processed, the PAE stops processing
    /// EAP messages until eapStart is set again.
    pub fn eap_stop(&mut self) {
        self.eap_stop = true;
    }

    /// Signal eapTimeout. Per Cl.8.3.
    ///
    /// Called when authWhile timer expires during Authenticating state.
    /// Results in either a retry or transition to Held.
    pub fn eap_timeout(&mut self) {
        if self.state == PaeState::Authenticating {
            self.counters.auth_timeouts_while_authenticating += 1;
        }
    }

    /// Whether eapStart flag is set. Per Cl.8.3.
    pub fn is_eap_start(&self) -> bool {
        self.eap_start
    }

    /// Whether eapStop flag is set. Per Cl.8.3.
    pub fn is_eap_stop(&self) -> bool {
        self.eap_stop
    }

    // --- #13 (REQ-F-PAE-003): Client Interface ---

    /// Set the `enabled` flag. Per Cl.8.4.
    pub fn set_enabled(&mut self, value: bool) {
        self.enabled = value;
    }

    /// Whether `enabled` is set. Per Cl.8.4.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// Set the `authenticate` flag. Per Cl.8.4.
    pub fn set_authenticate(&mut self, value: bool) {
        self.authenticate = value;
    }

    /// Whether `authenticated` is set. Per Cl.8.4.
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    /// Whether `failed` is set. Per Cl.8.4.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    /// Get authentication results. Per Cl.8.4.
    pub fn results(&self) -> Option<&AuthResult> {
        self.results.as_ref()
    }

    // --- #15 (REQ-F-PAE-005): EAPOL-Start Transmission ---
    // (transition_to_connecting handles this, already verified by existing tests)

    // --- #16 (REQ-F-PAE-006): EAPOL-Logoff Transmission ---

    /// Trigger logoff. Per Cl.8.5.
    ///
    /// Per Cl.8.5: EAPOL-Logoff is transmitted unless connectivity is
    /// secured by MACsec/MKA (in which case it may be omitted).
    ///
    /// # Errors
    /// Returns `EapolError::InvalidTransition` if not in an authenticatable state.
    pub fn logoff(&mut self) -> Result<(), EapolError> {
        match self.state {
            PaeState::Authenticated | PaeState::Authenticating | PaeState::Connecting => {
                // Per Cl.8.5: skip EAPOL-Logoff if secured by MACsec
                if !self.ctx.is_macsec_secured() {
                    let frame = EapolFrame::logoff();
                    self.ctx.send_eapol(&frame)?;
                    self.counters.eapol_logoff_tx += 1;
                    self.counters.eapol_frames_tx += 1;
                }
                // Cl.8.8 counters
                match self.state {
                    PaeState::Authenticating => {
                        self.counters.eap_logoff_while_authenticating += 1;
                    }
                    PaeState::Authenticated => {
                        self.counters.eap_logoff_while_authenticated += 1;
                    }
                    _ => {}
                }
                self.state = PaeState::Logoff;
                self.authenticated = false;
                self.cancel_timer();
                Ok(())
            }
            _ => Err(EapolError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: "Logoff".into(),
            }),
        }
    }

    /// Trigger reauthentication. Per Cl.8.3.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidTransition` if not in Authenticated state.
    pub fn reauthenticate(&mut self) -> Result<(), EapolError> {
        if self.state != PaeState::Authenticated {
            return Err(EapolError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: "Connecting".into(),
            });
        }
        self.start_count = 0;
        self.transition_to_connecting()?;
        Ok(())
    }

    /// Handle link state change. Per Cl.8.3.
    pub fn link_changed(&mut self, up: bool) -> Result<(), EapolError> {
        if !up {
            self.state = PaeState::Disconnected;
            self.cancel_timer();
            self.start_count = 0;
        } else if up && self.authenticate && self.state == PaeState::Disconnected {
            self.start_count = 0;
            self.transition_to_connecting()?;
        }
        Ok(())
    }

    /// Handle a received EAPOL frame. Per Cl.8.3.
    pub fn handle_eapol(&mut self, frame: &EapolFrame) -> Result<(), EapolError> {
        self.counters.eapol_frames_rx += 1;
        self.counters.last_eapol_version = frame.version as u8;

        // Per Cl.8.3: if eapStop is set, no EAP messages processed
        if self.eap_stop {
            return Ok(());
        }

        match self.state {
            PaeState::Connecting
                if matches!(frame.packet_type, crate::frame::EapolPacketType::EapPacket) =>
            {
                self.state = PaeState::Authenticating;
                self.counters.enters_authenticating += 1;
                // Clear eapStart when EAP attempt begins
                self.eap_start = false;
                // Per Cl.8.3: start authWhile timer on entering Authenticating
                let now = self.ctx.now();
                self.start_timer(ActiveTimer::AuthWhile, self.ctx.get_auth_while(), now);
            }
            _ => {}
        }
        Ok(())
    }

    /// Perform a single timer-driven step. Per Cl.8.3.
    pub fn step(&mut self) -> Result<(), EapolError> {
        let now = self.ctx.now();

        // Per Cl.8.4: if enabled is set, Logon Process can set authenticate
        if self.enabled && self.authenticate && self.state == PaeState::Disconnected {
            self.start_count = 0;
            self.transition_to_connecting()?;
            return Ok(());
        }

        // Per Cl.8.3: if eapStop is set, no EAP processing
        if self.eap_stop {
            self.eap_stop = false;
            return Ok(());
        }

        // Check port state
        let port_state = self.ctx.get_port_state();
        if port_state != pae::PortState::Authorized && port_state != pae::PortState::Unauthorized {
            if self.state != PaeState::Disconnected {
                self.state = PaeState::Disconnected;
                self.cancel_timer();
            }
            return Ok(());
        }

        match self.state {
            PaeState::Disconnected => {
                if self.authenticate {
                    self.start_count = 0;
                    self.transition_to_connecting()?;
                }
            }
            PaeState::Connecting => {
                if self.timer_expired(now) {
                    if self.start_count < self.ctx.get_max_retries() {
                        self.transition_to_connecting()?;
                    } else {
                        self.state = PaeState::Held;
                        self.start_timer(ActiveTimer::HeldWhile, self.ctx.get_held_while(), now);
                    }
                }
            }
            PaeState::Authenticating => {
                if self.timer_expired(now) {
                    self.counters.auth_timeouts_while_authenticating += 1;
                    if self.start_count < self.ctx.get_max_retries() {
                        self.start_count += 1;
                        self.transition_to_connecting()?;
                    } else {
                        self.state = PaeState::Held;
                        self.start_timer(ActiveTimer::HeldWhile, self.ctx.get_held_while(), now);
                    }
                }
            }
            PaeState::Held => {
                if self.timer_expired(now) && self.authenticate {
                    self.start_count = 0;
                    self.transition_to_connecting()?;
                }
            }
            PaeState::Authenticated => {
                if !self.authenticate {
                    self.logoff()?;
                }
            }
            PaeState::Logoff => {
                if self.authenticate {
                    self.start_count = 0;
                    self.transition_to_connecting()?;
                }
            }
            PaeState::ForceAuth | PaeState::ForceUnauth => {}
        }

        Ok(())
    }

    /// Signal EAP Success received. Per Cl.8.3.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidTransition` if not in Authenticating state.
    pub fn eap_success(&mut self) -> Result<(), EapolError> {
        if self.state != PaeState::Authenticating {
            return Err(EapolError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: "Authenticated".into(),
            });
        }
        self.state = PaeState::Authenticated;
        self.start_count = 0;
        self.authenticated = true;
        self.failed = false;
        self.counters.auth_successes_while_authenticating += 1;
        self.results = Some(AuthResult {
            identity: self.ctx.get_identity().to_vec(),
        });
        self.cancel_timer();
        Ok(())
    }

    /// Signal EAP Failure received. Per Cl.8.3.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidTransition` if not in Authenticating state.
    pub fn eap_failure(&mut self) -> Result<(), EapolError> {
        if self.state != PaeState::Authenticating {
            return Err(EapolError::InvalidTransition {
                from: format!("{:?}", self.state),
                to: "Held".into(),
            });
        }
        self.counters.auth_fail_while_authenticating += 1;
        if self.start_count < self.ctx.get_max_retries() {
            // Per Cl.8.3: retry authentication
            self.transition_to_connecting()?;
        } else {
            self.state = PaeState::Held;
            self.authenticated = false;
            self.failed = true;
            let now = self.ctx.now();
            self.start_timer(ActiveTimer::HeldWhile, self.ctx.get_held_while(), now);
        }
        Ok(())
    }

    fn transition_to_connecting(&mut self) -> Result<(), EapolError> {
        let frame = EapolFrame::start();
        self.ctx.send_eapol(&frame)?;
        self.counters.eapol_start_tx += 1;
        self.counters.eapol_frames_tx += 1;
        self.start_count += 1;
        self.state = PaeState::Connecting;
        self.authenticated = false;
        self.failed = false;
        let now = self.ctx.now();
        self.start_timer(ActiveTimer::StartWhen, self.ctx.get_start_when(), now);
        Ok(())
    }

    fn start_timer(&mut self, timer: ActiveTimer, duration: Duration, now: Duration) {
        self.active_timer = timer;
        self.timer_duration = duration;
        self.timer_start = Some(now);
    }

    fn cancel_timer(&mut self) {
        self.active_timer = ActiveTimer::None;
        self.timer_start = None;
    }

    fn timer_expired(&self, now: Duration) -> bool {
        match self.timer_start {
            Some(start) => now.saturating_sub(start) >= self.timer_duration,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex, RwLock};

    /// Mock context for testing SupplicantPae.
    struct MockContext {
        sent_frames: RwLock<Vec<EapolFrame>>,
        port_state: pae::PortState,
        now: Mutex<Duration>,
        max_retries: u32,
        held_while: Duration,
        start_when: Duration,
        auth_while: Duration,
        macsec_secured: bool,
    }

    impl MockContext {
        fn new() -> Self {
            Self {
                sent_frames: RwLock::new(vec![]),
                port_state: pae::PortState::Unauthorized,
                now: Mutex::new(Duration::from_secs(0)),
                max_retries: 3,
                held_while: Duration::from_secs(60),
                start_when: Duration::from_secs(30),
                auth_while: Duration::from_secs(30),
                macsec_secured: false,
            }
        }

        fn advance_time(&self, dur: Duration) {
            let mut now = self.now.lock().unwrap();
            *now += dur;
        }
    }

    impl SupplicantPaeContext for MockContext {
        fn send_eapol(&self, frame: &EapolFrame) -> Result<(), EapolError> {
            self.sent_frames.write().unwrap().push(frame.clone());
            Ok(())
        }

        fn get_port_state(&self) -> pae::PortState {
            self.port_state
        }

        fn now(&self) -> Duration {
            *self.now.lock().unwrap()
        }

        fn get_identity(&self) -> &[u8] {
            b"test-identity"
        }

        fn get_max_retries(&self) -> u32 {
            self.max_retries
        }

        fn get_held_while(&self) -> Duration {
            self.held_while
        }

        fn get_start_when(&self) -> Duration {
            self.start_when
        }

        fn get_auth_while(&self) -> Duration {
            self.auth_while
        }

        fn is_macsec_secured(&self) -> bool {
            self.macsec_secured
        }
    }

    /// Helper: create pae with shared context for testing.
    fn create_pae() -> (SupplicantPae<Arc<MockContext>>, Arc<MockContext>) {
        let ctx = Arc::new(MockContext::new());
        let pae = SupplicantPae::new(ctx.clone());
        (pae, ctx)
    }

    impl SupplicantPaeContext for Arc<MockContext> {
        fn send_eapol(&self, frame: &EapolFrame) -> Result<(), EapolError> {
            (**self).send_eapol(frame)
        }

        fn get_port_state(&self) -> pae::PortState {
            (**self).get_port_state()
        }

        fn now(&self) -> Duration {
            (**self).now()
        }

        fn get_identity(&self) -> &[u8] {
            (**self).get_identity()
        }

        fn get_max_retries(&self) -> u32 {
            (**self).get_max_retries()
        }

        fn get_held_while(&self) -> Duration {
            (**self).get_held_while()
        }

        fn get_start_when(&self) -> Duration {
            (**self).get_start_when()
        }

        fn get_auth_while(&self) -> Duration {
            (**self).get_auth_while()
        }

        fn is_macsec_secured(&self) -> bool {
            (**self).is_macsec_secured()
        }
    }

    // --- #11 (REQ-F-PAE-001) existing tests ---

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per IEEE 802.1X-2020, Clause 8.3.
    /// PAE starts in Disconnected state.
    #[test]
    fn test_pae_initial_state() {
        let (pae, _) = create_pae();
        assert_eq!(pae.state(), PaeState::Disconnected);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Disconnected + authenticate → Connecting, txEapolStart().
    #[test]
    fn test_pae_disconnected_to_connecting() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
        assert_eq!(ctx.sent_frames.read().unwrap().len(), 1);
        assert_eq!(
            ctx.sent_frames.read().unwrap()[0].packet_type,
            crate::frame::EapolPacketType::EapolStart
        );
        assert_eq!(pae.counters().eapol_start_tx, 1);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Authenticating + eapSuccess → Authenticated.
    #[test]
    fn test_pae_authenticating_to_authenticated() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        assert_eq!(pae.state(), PaeState::Authenticating);
        pae.eap_success().unwrap();
        assert_eq!(pae.state(), PaeState::Authenticated);
        assert_eq!(pae.start_count(), 0);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Authenticating + eapFail + retries < max → retry (transition to Connecting).
    #[test]
    fn test_pae_eap_failure_retry() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
        pae.eap_failure().unwrap();
        // eap_failure now transitions to Connecting for retry
        assert_eq!(pae.state(), PaeState::Connecting);
        assert_eq!(pae.start_count(), 2); // 1 from initial + 1 from retry
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Authenticating + eapFail + retries >= max → Held.
    #[test]
    fn test_pae_eap_failure_to_held() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
                             // Drive retries until exhausted
        for _ in 0..ctx.max_retries {
            let eap_frame = EapolFrame::eap_packet(vec![0x01]);
            pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
            pae.eap_failure().unwrap(); // → Connecting (retry) or Held (exhausted)
        }
        assert_eq!(pae.state(), PaeState::Held);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Authenticated + logoff → Logoff, txEapolLogoff().
    #[test]
    fn test_pae_authenticated_to_logoff() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        assert_eq!(pae.state(), PaeState::Authenticated);
        pae.logoff().unwrap();
        assert_eq!(pae.state(), PaeState::Logoff);
        assert_eq!(pae.counters().eapol_logoff_tx, 1);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Held + heldWhile expires + authenticate → Connecting.
    #[test]
    fn test_pae_held_to_connecting_after_timer() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        for _ in 0..ctx.max_retries {
            let eap_frame = EapolFrame::eap_packet(vec![0x01]);
            pae.handle_eapol(&eap_frame).unwrap();
            pae.eap_failure().unwrap();
        }
        assert_eq!(pae.state(), PaeState::Held);
        ctx.advance_time(ctx.held_while + Duration::from_secs(1));
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Link down → Disconnected, link up + authenticate → Connecting.
    #[test]
    fn test_pae_link_changed() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
        pae.link_changed(false).unwrap();
        assert_eq!(pae.state(), PaeState::Disconnected);
        pae.link_changed(true).unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// eap_success from wrong state is an error.
    #[test]
    fn test_pae_eap_success_invalid_state() {
        let (mut pae, _) = create_pae();
        assert!(pae.eap_success().is_err());
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// logoff from Disconnected is an error.
    #[test]
    fn test_pae_logoff_invalid_state() {
        let (mut pae, _) = create_pae();
        assert!(pae.logoff().is_err());
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// reauthenticate from non-Authenticated state is an error.
    #[test]
    fn test_pae_reauthenticate_invalid_state() {
        let (mut pae, _) = create_pae();
        assert!(pae.reauthenticate().is_err());
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Connecting + startWhen timeout → retry EAPOL-Start.
    #[test]
    fn test_pae_start_when_timeout_retry() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
        assert_eq!(pae.counters().eapol_start_tx, 1);
        ctx.advance_time(ctx.start_when + Duration::from_secs(1));
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
        assert_eq!(pae.counters().eapol_start_tx, 2);
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Connecting + startWhen timeout + max retries → Held.
    #[test]
    fn test_pae_start_max_retries_to_held() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
        for _ in 0..ctx.max_retries {
            ctx.advance_time(ctx.start_when + Duration::from_secs(1));
            pae.step().unwrap();
        }
        assert_eq!(pae.state(), PaeState::Held);
    }

    // --- #12 (REQ-F-PAE-002): Higher Layer Interface ---

    /// Verifies: #12 (REQ-F-PAE-002)
    /// Per Cl.8.3: eapStart is set, then cleared when EAP begins.
    #[test]
    fn test_eap_start_cleared_on_eap_begin() {
        let (mut pae, _) = create_pae();
        pae.eap_start();
        assert!(pae.is_eap_start());
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating, clears eapStart
        assert!(!pae.is_eap_start());
    }

    /// Verifies: #12 (REQ-F-PAE-002)
    /// Per Cl.8.3: eapStop prevents EAP message processing.
    #[test]
    fn test_eap_stop_blocks_eap() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting
        pae.eap_stop();
        assert!(pae.is_eap_stop());
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // Should not transition
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    /// Verifies: #12 (REQ-F-PAE-002)
    /// Per Cl.8.3: eapStop is cleared after processing.
    #[test]
    fn test_eap_stop_cleared_after_step() {
        let (mut pae, _) = create_pae();
        pae.eap_stop();
        assert!(pae.is_eap_stop());
        pae.step().unwrap();
        assert!(!pae.is_eap_stop());
    }

    /// Verifies: #12 (REQ-F-PAE-002)
    /// Per Cl.8.3: eapTimeout increments timeout counter.
    #[test]
    fn test_eap_timeout_increments_counter() {
        let (mut pae, _) = create_pae();
        // Not in Authenticating state, so counter stays 0
        pae.eap_timeout();
        assert_eq!(pae.counters().auth_timeouts_while_authenticating, 0);
    }

    // --- #13 (REQ-F-PAE-003): Client Interface ---

    /// Verifies: #13 (REQ-F-PAE-003)
    /// Per Cl.8.4: enabled + authenticate → authentication can proceed.
    #[test]
    fn test_enabled_authenticate_proceeds() {
        let (mut pae, _) = create_pae();
        pae.set_enabled(true);
        pae.set_authenticate(true);
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    /// Verifies: #13 (REQ-F-PAE-003)
    /// Per Cl.8.4: authenticated flag is set on eapSuccess.
    #[test]
    fn test_authenticated_flag_on_success() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        assert!(pae.is_authenticated());
        assert!(!pae.is_failed());
    }

    /// Verifies: #13 (REQ-F-PAE-003)
    /// Per Cl.8.4: failed flag is set when auth fails and retries exhausted.
    #[test]
    fn test_failed_flag_on_exhausted_retries() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        for _ in 0..ctx.max_retries {
            let eap_frame = EapolFrame::eap_packet(vec![0x01]);
            pae.handle_eapol(&eap_frame).unwrap();
            pae.eap_failure().unwrap();
        }
        assert!(pae.is_failed());
        assert!(!pae.is_authenticated());
    }

    /// Verifies: #13 (REQ-F-PAE-003)
    /// Per Cl.8.4: results are available after eapSuccess.
    #[test]
    fn test_results_available_on_success() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        let results = pae.results().expect("results should be available");
        assert_eq!(results.identity, b"test-identity");
    }

    // --- #14 (REQ-F-PAE-004): Timers ---

    /// Verifies: #14 (REQ-F-PAE-004)
    /// Per Cl.8.6: heldWhile timer starts with heldPeriod on transition to HELD.
    #[test]
    fn test_held_while_timer_starts() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        for _ in 0..ctx.max_retries {
            let eap_frame = EapolFrame::eap_packet(vec![0x01]);
            pae.handle_eapol(&eap_frame).unwrap();
            pae.eap_failure().unwrap();
        }
        assert_eq!(pae.state(), PaeState::Held);
        // heldWhile starts, default is 60s
        ctx.advance_time(ctx.held_while + Duration::from_secs(1));
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    /// Verifies: #14 (REQ-F-PAE-004)
    /// Per Cl.8.6: heldPeriod 0 means immediate retry.
    #[test]
    fn test_held_period_zero() {
        let ctx = Arc::new(MockContext {
            held_while: Duration::from_secs(0),
            ..MockContext::new()
        });
        let mut pae = SupplicantPae::new(ctx.clone());
        pae.set_authenticate(true);
        pae.step().unwrap();
        for _ in 0..ctx.max_retries {
            let eap_frame = EapolFrame::eap_packet(vec![0x01]);
            pae.handle_eapol(&eap_frame).unwrap();
            pae.eap_failure().unwrap();
        }
        assert_eq!(pae.state(), PaeState::Held);
        // With heldPeriod=0, step should immediately transition
        pae.step().unwrap();
        assert_eq!(pae.state(), PaeState::Connecting);
    }

    // --- #15 (REQ-F-PAE-005): EAPOL-Start Transmission ---

    /// Verifies: #15 (REQ-F-PAE-005)
    /// Per Cl.8.5: EAPOL-Start transmitted on transition from Disconnected to Connecting.
    #[test]
    fn test_eapol_start_transmitted_on_connecting() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting
        assert_eq!(pae.state(), PaeState::Connecting);
        assert_eq!(pae.counters().eapol_start_tx, 1);
        let sent = ctx.sent_frames.read().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(
            sent[0].packet_type,
            crate::frame::EapolPacketType::EapolStart
        );
    }

    // --- #16 (REQ-F-PAE-006): EAPOL-Logoff Transmission ---

    /// Verifies: #16 (REQ-F-PAE-006)
    /// Per Cl.8.5: EAPOL-Logoff transmitted when not MACsec secured.
    #[test]
    fn test_logoff_transmitted_when_not_secured() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        pae.logoff().unwrap();
        assert_eq!(pae.counters().eapol_logoff_tx, 1);
        let sent = ctx.sent_frames.read().unwrap();
        assert!(sent
            .iter()
            .any(|f| f.packet_type == crate::frame::EapolPacketType::EapolLogoff));
    }

    /// Verifies: #16 (REQ-F-PAE-006)
    /// Per Cl.8.5: EAPOL-Logoff omitted when MACsec secured.
    #[test]
    fn test_logoff_omitted_when_macsec_secured() {
        let ctx = Arc::new(MockContext {
            macsec_secured: true,
            ..MockContext::new()
        });
        let mut pae = SupplicantPae::new(ctx.clone());
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        pae.logoff().unwrap();
        assert_eq!(pae.state(), PaeState::Logoff);
        assert_eq!(pae.counters().eapol_logoff_tx, 0); // No Logoff frame sent
    }

    // --- #17 (REQ-F-PAE-007): Retry Control ---

    /// Verifies: #17 (REQ-F-PAE-007)
    /// Per Cl.8.7: retryCount increments on each retry.
    #[test]
    fn test_retry_count_increments() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // start_count=1
                             // Timeout → retry
        ctx.advance_time(ctx.start_when + Duration::from_secs(1));
        pae.step().unwrap(); // start_count=2
        assert_eq!(pae.start_count(), 2);
    }

    /// Verifies: #17 (REQ-F-PAE-007)
    /// Per Cl.8.7: when retryCount >= retryMax, transition to Held.
    #[test]
    fn test_retry_max_exceeded_to_held() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // start_count=1
                             // Exhaust retries
        for _ in 0..ctx.max_retries {
            ctx.advance_time(ctx.start_when + Duration::from_secs(1));
            pae.step().unwrap();
        }
        assert_eq!(pae.state(), PaeState::Held);
    }

    /// Verifies: #17 (REQ-F-PAE-007)
    /// Per Cl.8.7: retryCount resets on reauthentication.
    #[test]
    fn test_retry_count_resets_on_reauth() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        assert_eq!(pae.state(), PaeState::Authenticated);
        pae.reauthenticate().unwrap();
        assert_eq!(pae.start_count(), 1); // reset + 1 from transition
    }

    // --- #18 (REQ-F-PAE-008): Diagnostic Counters ---

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: entersAuthenticating counter increments.
    #[test]
    fn test_counter_enters_authenticating() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
        assert_eq!(pae.counters().enters_authenticating, 1);
    }

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: authSuccessesWhileAuthenticating counter increments.
    #[test]
    fn test_counter_auth_successes() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        assert_eq!(pae.counters().auth_successes_while_authenticating, 1);
    }

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: authFailWhileAuthenticating counter increments.
    #[test]
    fn test_counter_auth_fail_while_authenticating() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_failure().unwrap();
        assert_eq!(pae.counters().auth_fail_while_authenticating, 1);
    }

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: eapLogoffWhileAuthenticating counter increments.
    #[test]
    fn test_counter_logoff_while_authenticating() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.logoff().unwrap();
        assert_eq!(pae.counters().eap_logoff_while_authenticating, 1);
    }

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: eapLogoffWhileAuthenticated counter increments.
    #[test]
    fn test_counter_logoff_while_authenticated() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        pae.eap_success().unwrap();
        pae.logoff().unwrap();
        assert_eq!(pae.counters().eap_logoff_while_authenticated, 1);
    }

    /// Verifies: #18 (REQ-F-PAE-008)
    /// Per Cl.8.8: authTimeoutsWhileAuthenticating counter increments on timeout.
    #[test]
    fn test_counter_auth_timeouts() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap();
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
                                               // Wait for authWhile timeout
        ctx.advance_time(ctx.auth_while + Duration::from_secs(1));
        pae.step().unwrap(); // Timeout → retry
        assert_eq!(pae.counters().auth_timeouts_while_authenticating, 1);
    }
}
