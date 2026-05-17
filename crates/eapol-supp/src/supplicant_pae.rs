//! Supplicant PAE state machine per IEEE 802.1X-2020, Clause 8.
//!
//! Implements: #11 (REQ-F-PAE-001: Supplicant PACP State Machine)
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

/// Diagnostic counters for the Supplicant PAE.
///
/// Per IEEE 802.1X-2020, Clause 8.3.
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

    /// Get the configured maximum reauthentication retries.
    fn get_max_retries(&self) -> u32;

    /// Get the heldWhile timer duration (default 60s). Per Cl.8.3.
    fn get_held_while(&self) -> Duration;

    /// Get the startWhen timer duration (default 30s). Per Cl.8.3.
    fn get_start_when(&self) -> Duration;

    /// Get the authWhile timer duration (default 30s). Per Cl.8.3.
    fn get_auth_while(&self) -> Duration;
}

/// Supplicant PAE state machine — Aggregate root for PACP.
///
/// Per IEEE 802.1X-2020, Clause 8.3.
/// Generic over context trait for testability.
/// Owns state, timers, and counters; enforces transition invariants.
///
/// Implements: #11 (REQ-F-PAE-001: Supplicant PACP State Machine)
pub struct SupplicantPae<C: SupplicantPaeContext> {
    /// Current PACP state.
    state: PaeState,
    /// Retry counter for EAPOL-Start retransmissions.
    start_count: u32,
    /// Whether `authenticate` flag is set by higher layer.
    authenticate: bool,
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

    /// Whether the authenticate flag is set.
    pub fn is_authenticate(&self) -> bool {
        self.authenticate
    }

    /// Current start retry count.
    pub fn start_count(&self) -> u32 {
        self.start_count
    }

    /// Access the context.
    pub fn ctx(&self) -> &C {
        &self.ctx
    }

    /// Set the `authenticate` flag. Per Cl.8.3.
    pub fn set_authenticate(&mut self, value: bool) {
        self.authenticate = value;
    }

    /// Trigger logoff. Transitions to Logoff state. Per Cl.8.3.
    ///
    /// # Errors
    /// Returns `EapolError::InvalidTransition` if not in an authenticatable state.
    pub fn logoff(&mut self) -> Result<(), EapolError> {
        match self.state {
            PaeState::Authenticated | PaeState::Authenticating | PaeState::Connecting => {
                let frame = EapolFrame::logoff();
                self.ctx.send_eapol(&frame)?;
                self.counters.eapol_logoff_tx += 1;
                self.counters.eapol_frames_tx += 1;
                self.state = PaeState::Logoff;
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

        match self.state {
            PaeState::Connecting
                if matches!(frame.packet_type, crate::frame::EapolPacketType::EapPacket) =>
            {
                self.state = PaeState::Authenticating;
            }
            _ => {}
        }
        Ok(())
    }

    /// Perform a single timer-driven step. Per Cl.8.3.
    pub fn step(&mut self) -> Result<(), EapolError> {
        let now = self.ctx.now();

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
        if self.start_count < self.ctx.get_max_retries() {
            self.start_count += 1;
        } else {
            self.state = PaeState::Held;
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
    }

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
    /// Per Cl.8.3: Authenticating + eapFail + retries < max → retry.
    #[test]
    fn test_pae_eap_failure_retry() {
        let (mut pae, _) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
        pae.eap_failure().unwrap();
        assert_eq!(pae.start_count(), 2); // 1 from connecting + 1 from failure
    }

    /// Verifies: #11 (REQ-F-PAE-001)
    /// Per Cl.8.3: Authenticating + eapFail + retries >= max → Held.
    #[test]
    fn test_pae_eap_failure_to_held() {
        let (mut pae, ctx) = create_pae();
        pae.set_authenticate(true);
        pae.step().unwrap(); // → Connecting, start_count=1
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap(); // → Authenticating
        for _ in 0..ctx.max_retries {
            pae.eap_failure().unwrap();
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
        let eap_frame = EapolFrame::eap_packet(vec![0x01]);
        pae.handle_eapol(&eap_frame).unwrap();
        for _ in 0..ctx.max_retries {
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
}
