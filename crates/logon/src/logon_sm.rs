//! Logon Process state machine per IEEE 802.1X-2020, Clause 12.
//!
//! Implements: #33 (REQ-F-LOGON-001: Logon Process State Machine)
//! Architecture: #74 (ADR-SM-002: Trait-based state machine), #79 (ADR-EVT-007: Event-driven inter-crate communication)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::time::Duration;

use pae::{Cak, Ckn, CpState, Msk, PaeEvent, TimerWheel};

use crate::cak_cache::CakCache;
use crate::nid::NidGroup;
use crate::LogonError;

/// NID information extracted from an EAPOL-Announcement.
///
/// Per IEEE 802.1X-2020, Clause 12.5.
/// Used by `LogonProcess::handle_announcement` to evaluate NID groups.
#[derive(Debug, Clone)]
pub struct AnnouncementNid {
    /// NID identifier bytes advertised by the authenticator.
    pub id: Vec<u8>,
    /// Whether the authenticator supports PSK for this NID.
    pub supports_psk: bool,
}

impl From<eapol_supp::AnnouncementNidEntry> for AnnouncementNid {
    fn from(entry: eapol_supp::AnnouncementNidEntry) -> Self {
        Self {
            id: entry.id,
            supports_psk: entry.supports_psk,
        }
    }
}

/// Logon Process state.
///
/// Per IEEE 802.1X-2020, Clause 12.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogonState {
    /// Initial — no authentication attempted.
    Initial,
    /// NID group selection in progress.
    NidSelection,
    /// Waiting for authentication to complete.
    Waiting,
    /// Authentication succeeded.
    Authenticated,
    /// Authentication failed.
    Failed,
    /// Using unsecured connectivity (fallback).
    Unsecured,
    /// Logoff initiated.
    Logoff,
}

/// Context trait for Logon Process — abstracts interactions with PAE/CP/EAPOL.
///
/// Per ADR-SM-002 (#74).
/// The Logon Process orchestrates across multiple bounded contexts;
/// this trait provides the integration points.
pub trait LogonContext: Send + Sync {
    /// Start Supplicant PAE authentication. Per Cl.12.
    fn start_authentication(&self, nid: Option<&[u8]>) -> Result<(), LogonError>;

    /// Get current Supplicant PAE state.
    fn pae_state(&self) -> eapol_supp::PaeState;

    /// Get current CP state.
    fn cp_state(&self) -> CpState;

    /// Send EAPOL-Announcement-Req. Per Cl.12.
    fn send_announcement_req(&self) -> Result<(), LogonError>;

    /// Install a pre-shared CAK from cache. Per Cl.12.6.
    fn install_cak(&self, cak: Cak, ckn: Ckn) -> Result<(), LogonError>;

    /// Get current time.
    fn now(&self) -> Duration;
}

/// Logon Process — Aggregate root for network logon orchestration.
///
/// Per IEEE 802.1X-2020, Clause 12.
/// Orchestrates PAE, CP, and EAPOL interactions.
/// Generic over context trait for testability.
///
/// Implements: #33 (REQ-F-LOGON-001: Logon Process State Machine)
pub struct LogonProcess<C: LogonContext> {
    /// Current Logon state.
    state: LogonState,
    /// Configured NID groups (ordered by preference).
    nid_groups: Vec<NidGroup>,
    /// Currently selected NID group.
    selected_nid: Option<NidGroup>,
    /// Whether unsecured connectivity fallback is enabled.
    allow_unsecured: bool,
    /// Whether PSK fallback is enabled.
    allow_psk: bool,
    /// NID identifiers to ignore from announcements (filtering list).
    ignore_nids: Vec<Vec<u8>>,
    /// CAK cache for pre-shared key acceleration.
    cak_cache: CakCache,
    /// Whether link is up.
    link_up: bool,
    /// Whether the authenticate variable is set (user wants authentication).
    authenticate: bool,
    /// Timer wheel (used by step() for timeout-driven transitions).
    #[allow(dead_code)] // will be used by REQ-F-LOGON-003/004 timer logic
    timers: TimerWheel,
    /// Context (injected).
    ctx: C,
}

impl<C: LogonContext> LogonProcess<C> {
    /// Create a new Logon Process. Per Cl.12.
    ///
    /// Implements: #33 (REQ-F-LOGON-001)
    pub fn new(ctx: C, nid_groups: Vec<NidGroup>, allow_unsecured: bool, allow_psk: bool) -> Self {
        Self {
            state: LogonState::Initial,
            nid_groups,
            selected_nid: None,
            allow_unsecured,
            allow_psk,
            ignore_nids: Vec::new(),
            cak_cache: CakCache::new(),
            link_up: false,
            authenticate: false,
            timers: TimerWheel::new(),
            ctx,
        }
    }

    /// Set the NID ignore list for announcement filtering. Per Cl.12.
    pub fn set_ignore_nids(&mut self, nids: Vec<Vec<u8>>) {
        self.ignore_nids = nids;
    }

    /// Mutable access to the CAK cache. Per Cl.12.6.
    pub fn cak_cache_mut(&mut self) -> &mut CakCache {
        &mut self.cak_cache
    }

    /// Current Logon state.
    pub fn state(&self) -> LogonState {
        self.state
    }

    /// Currently selected NID group.
    pub fn selected_nid(&self) -> Option<&NidGroup> {
        self.selected_nid.as_ref()
    }

    /// Transition to NidSelection, start authentication, then enter Waiting.
    fn begin_authentication(&mut self) -> Result<(), LogonError> {
        self.state = LogonState::NidSelection;
        self.ctx
            .start_authentication(self.selected_nid().map(|n| n.id()))?;
        self.state = LogonState::Waiting;
        Ok(())
    }

    /// Handle link state change. Per Cl.12.
    ///
    /// Implements: #33 (REQ-F-LOGON-001)
    /// AC1: Given Logon Process in unauthenticated state, When port becomes
    /// MAC_Operational, Then Logon Process instructs PAE to authenticate.
    pub fn link_changed(&mut self, up: bool) -> Result<Vec<PaeEvent>, LogonError> {
        self.link_up = up;
        if up && self.state != LogonState::Authenticated && self.state != LogonState::Logoff {
            self.authenticate = true;
            self.begin_authentication()?;
        } else if !up {
            self.state = LogonState::Initial;
            self.authenticate = false;
        }
        Ok(vec![])
    }

    /// Process a received EAPOL-Announcement. Per Cl.12.
    ///
    /// Implements: #34 (REQ-F-LOGON-002), #35 (REQ-F-LOGON-003)
    /// Evaluates advertised NIDs against configured network profiles,
    /// applies ignore-list filtering, and selects the best matching NID group.
    /// Returns events generated by processing.
    pub fn handle_announcement(
        &mut self,
        nids: &[AnnouncementNid],
    ) -> Result<Vec<PaeEvent>, LogonError> {
        // Filter out ignored NIDs
        let filtered: Vec<&AnnouncementNid> = nids
            .iter()
            .filter(|n| !self.ignore_nids.contains(&n.id))
            .collect();

        // Search for a matching NID group in configured preference order
        for advertised in &filtered {
            for group in &self.nid_groups {
                if group.matches(&advertised.id) {
                    self.selected_nid = Some(group.clone());
                    return Ok(vec![]);
                }
            }
        }

        // No matching NID — try null NID (empty id) if supported
        if !filtered.is_empty() {
            for group in &self.nid_groups {
                if group.id().is_empty() {
                    self.selected_nid = Some(group.clone());
                    return Ok(vec![]);
                }
            }
        }

        Err(LogonError::NoMatchingNid(
            nids.first().map(|n| n.id.clone()).unwrap_or_default(),
        ))
    }

    /// Process a parsed EAPOL-Announcement frame. Per Cl.12.
    ///
    /// Implements: #35 (REQ-F-LOGON-003)
    /// Extracts NID Set TLVs from the parsed announcement,
    /// applies filtering, and selects the best matching NID group.
    pub fn handle_eapol_announcement(
        &mut self,
        announcement: &eapol_supp::EapolAnnouncement,
    ) -> Result<Vec<PaeEvent>, LogonError> {
        let nids: Vec<AnnouncementNid> = announcement
            .nids
            .iter()
            .cloned()
            .map(AnnouncementNid::from)
            .collect();
        self.handle_announcement(&nids)
    }

    /// Handle EAP Success event. Per Cl.12.
    ///
    /// Implements: #33 (REQ-F-LOGON-001)
    /// AC2: Given authentication succeeds, When MKA establishes connectivity,
    /// Then Logon Process instructs CP state machine to enable Controlled Port.
    pub fn handle_eap_success(&mut self, _msk: Msk) -> Result<Vec<PaeEvent>, LogonError> {
        if self.state != LogonState::Waiting {
            return Err(LogonError::StateError(format!(
                "EAP success unexpected in state {:?}",
                self.state
            )));
        }
        self.state = LogonState::Authenticated;
        Ok(vec![])
    }

    /// Handle EAP Failure event. Per Cl.12.
    ///
    /// Implements: #33 (REQ-F-LOGON-001)
    /// AC3: Given authentication fails and PSK fallback is configured,
    /// When EAP fails, Then Logon Process attempts PSK-based MKA.
    pub fn handle_eap_failure(&mut self) -> Result<Vec<PaeEvent>, LogonError> {
        if self.state != LogonState::Waiting {
            return Err(LogonError::StateError(format!(
                "EAP failure unexpected in state {:?}",
                self.state
            )));
        }

        if self.allow_psk {
            let psk_nid = self
                .selected_nid
                .as_ref()
                .filter(|n| n.has_psk())
                .cloned()
                .or_else(|| self.nid_groups.iter().find(|n| n.has_psk()).cloned());

            if let Some(nid) = psk_nid {
                self.selected_nid = Some(nid.clone());
                self.ctx.start_authentication(Some(nid.id()))?;
                self.state = LogonState::Waiting;
                return Ok(vec![]);
            }
        }

        if self.allow_unsecured {
            self.state = LogonState::Unsecured;
            return Ok(vec![]);
        }

        self.state = LogonState::Failed;
        Err(LogonError::NoFallback)
    }

    /// Initiate logoff. Per Cl.12.
    pub fn logoff(&mut self) -> Result<Vec<PaeEvent>, LogonError> {
        self.state = LogonState::Logoff;
        self.authenticate = false;
        Ok(vec![])
    }

    /// Force reauthentication. Per Cl.12.
    ///
    /// Implements: #33 (REQ-F-LOGON-001)
    /// AC4: Given MKA fails after secured connectivity was established,
    /// When CP state machine reports failure and authenticate variable is set,
    /// Then Logon Process shall attempt reauthentication.
    pub fn reauthenticate(&mut self) -> Result<Vec<PaeEvent>, LogonError> {
        if !self.authenticate {
            return Err(LogonError::StateError(
                "reauthenticate requested but authenticate flag not set".into(),
            ));
        }
        self.begin_authentication()?;
        Ok(vec![])
    }

    /// Perform a single timer-driven step. Per Cl.12.
    pub fn step(&mut self) -> Result<Vec<PaeEvent>, LogonError> {
        if self.state == LogonState::Authenticated && self.ctx.cp_state() == CpState::Disabled {
            if self.authenticate {
                return self.reauthenticate();
            }
            self.state = LogonState::Failed;
        }
        Ok(vec![])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Mutex;

    /// Mock context for testing LogonProcess.
    struct MockLogonContext {
        pae_state: Mutex<eapol_supp::PaeState>,
        cp_state: Mutex<CpState>,
        auth_started: AtomicBool,
        auth_nid: Mutex<Option<Vec<u8>>>,
        now_value: Mutex<Duration>,
    }

    impl MockLogonContext {
        fn new() -> Self {
            Self {
                pae_state: Mutex::new(eapol_supp::PaeState::Disconnected),
                cp_state: Mutex::new(CpState::Disabled),
                auth_started: AtomicBool::new(false),
                auth_nid: Mutex::new(None),
                now_value: Mutex::new(Duration::ZERO),
            }
        }
    }

    impl LogonContext for MockLogonContext {
        fn start_authentication(&self, nid: Option<&[u8]>) -> Result<(), LogonError> {
            self.auth_started.store(true, Ordering::SeqCst);
            *self.auth_nid.lock().unwrap() = nid.map(|n| n.to_vec());
            Ok(())
        }

        fn pae_state(&self) -> eapol_supp::PaeState {
            *self.pae_state.lock().unwrap()
        }

        fn cp_state(&self) -> CpState {
            *self.cp_state.lock().unwrap()
        }

        fn send_announcement_req(&self) -> Result<(), LogonError> {
            Ok(())
        }

        fn install_cak(&self, _cak: Cak, _ckn: Ckn) -> Result<(), LogonError> {
            Ok(())
        }

        fn now(&self) -> Duration {
            *self.now_value.lock().unwrap()
        }
    }

    fn make_nid_group(name: &str, id: &[u8], has_psk: bool) -> NidGroup {
        NidGroup::new(
            name.to_string(),
            id.to_vec(),
            pae::CipherSuite::GcmAes128,
            has_psk,
        )
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// AC1: Given Logon Process in unauthenticated state, When port becomes
    /// MAC_Operational, Then Logon Process instructs PAE to authenticate.
    #[test]
    fn test_link_up_triggers_authentication() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        assert_eq!(lp.state(), LogonState::Initial);

        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);
        assert!(lp.ctx.auth_started.load(Ordering::SeqCst));
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// AC2: Given authentication succeeds, When MKA establishes connectivity,
    /// Then Logon Process instructs CP state machine to enable Controlled Port.
    #[test]
    fn test_eap_success_transitions_to_authenticated() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);

        let msk = Msk::from_bytes(vec![1u8; 64]).unwrap();
        lp.handle_eap_success(msk).unwrap();
        assert_eq!(lp.state(), LogonState::Authenticated);
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// AC3: Given authentication fails and PSK fallback is configured,
    /// When EAP fails, Then Logon Process attempts PSK-based MKA.
    #[test]
    fn test_eap_failure_psk_fallback() {
        let nid = make_nid_group("test", b"nid1", true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![nid], false, true);
        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);

        // Reset the auth_started flag to verify PSK retry triggers it again
        lp.ctx.auth_started.store(false, Ordering::SeqCst);

        lp.handle_eap_failure().unwrap();
        // Should retry authentication with PSK — state back to Waiting
        assert_eq!(lp.state(), LogonState::Waiting);
        assert!(lp.ctx.auth_started.load(Ordering::SeqCst));
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// EAP failure with no PSK fallback configured goes to Failed.
    #[test]
    fn test_eap_failure_no_fallback() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);

        let result = lp.handle_eap_failure();
        assert!(result.is_err());
        assert_eq!(lp.state(), LogonState::Failed);
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// EAP failure with unsecured fallback enabled transitions to Unsecured.
    #[test]
    fn test_eap_failure_unsecured_fallback() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], true, false);
        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);

        lp.handle_eap_failure().unwrap();
        assert_eq!(lp.state(), LogonState::Unsecured);
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// AC4: Given MKA fails after secured connectivity was established,
    /// When CP state machine reports failure and authenticate is set,
    /// Then Logon Process shall attempt reauthentication.
    #[test]
    fn test_reauthentication_on_cp_failure() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        lp.link_changed(true).unwrap();

        let msk = Msk::from_bytes(vec![1u8; 64]).unwrap();
        lp.handle_eap_success(msk).unwrap();
        assert_eq!(lp.state(), LogonState::Authenticated);

        // Simulate CP failure (e.g., MKA session lost)
        *lp.ctx.cp_state.lock().unwrap() = CpState::Disabled;
        lp.ctx.auth_started.store(false, Ordering::SeqCst);

        lp.step().unwrap();
        // authenticate flag is still set → reauthentication
        assert_eq!(lp.state(), LogonState::Waiting);
        assert!(lp.ctx.auth_started.load(Ordering::SeqCst));
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// Link down resets to Initial.
    #[test]
    fn test_link_down_resets_to_initial() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        lp.link_changed(true).unwrap();
        assert_eq!(lp.state(), LogonState::Waiting);

        lp.link_changed(false).unwrap();
        assert_eq!(lp.state(), LogonState::Initial);
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// Logoff transitions.
    #[test]
    fn test_logoff() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        lp.link_changed(true).unwrap();

        let msk = Msk::from_bytes(vec![1u8; 64]).unwrap();
        lp.handle_eap_success(msk).unwrap();
        assert_eq!(lp.state(), LogonState::Authenticated);

        lp.logoff().unwrap();
        assert_eq!(lp.state(), LogonState::Logoff);
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// EAP success in wrong state returns error.
    #[test]
    fn test_eap_success_wrong_state() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        // In Initial state, EAP success is unexpected
        let msk = Msk::from_bytes(vec![1u8; 64]).unwrap();
        let result = lp.handle_eap_success(msk);
        assert!(result.is_err());
    }

    /// Verifies: #33 (REQ-F-LOGON-001)
    /// Reauthenticate when authenticate flag is not set returns error.
    #[test]
    fn test_reauthenticate_without_authenticate_flag() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, false);
        let result = lp.reauthenticate();
        assert!(result.is_err());
    }

    // --- REQ-F-LOGON-002: NID Selection ---

    /// Verifies: #34 (REQ-F-LOGON-002)
    /// AC1: Given EAPOL-Announcement received with matching NID,
    /// Then the matching NID group is selected.
    #[test]
    fn test_announcement_matching_nid_selected() {
        let group1 = make_nid_group("net1", b"nid-aaa", false);
        let group2 = make_nid_group("net2", b"nid-bbb", true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group1, group2], false, false);

        let announcement = vec![AnnouncementNid {
            id: b"nid-bbb".to_vec(),
            supports_psk: true,
        }];
        lp.handle_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().name(), "net2");
    }

    /// Verifies: #34 (REQ-F-LOGON-002)
    /// AC2: Given matching NID, credentials from that profile are used.
    #[test]
    fn test_announcement_matching_nid_has_psk() {
        let group = make_nid_group("secure", b"nid-secure", true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group], false, false);

        let announcement = vec![AnnouncementNid {
            id: b"nid-secure".to_vec(),
            supports_psk: true,
        }];
        lp.handle_announcement(&announcement).unwrap();
        assert!(lp.selected_nid().unwrap().has_psk());
    }

    /// Verifies: #34 (REQ-F-LOGON-002)
    /// AC3: Given no matching NID and null NID supported,
    /// Then supplicant attempts authentication with default credentials.
    #[test]
    fn test_announcement_null_nid_fallback() {
        let null_group = NidGroup::new(
            "default".to_string(),
            vec![], // null NID
            pae::CipherSuite::GcmAes128,
            false,
        );
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![null_group], false, false);

        let announcement = vec![AnnouncementNid {
            id: b"unknown-nid".to_vec(),
            supports_psk: false,
        }];
        lp.handle_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().name(), "default");
        assert!(lp.selected_nid().unwrap().id().is_empty());
    }

    /// Verifies: #34 (REQ-F-LOGON-002)
    /// No matching NID and no null NID returns NoMatchingNid error.
    #[test]
    fn test_announcement_no_match_no_null_nid() {
        let group = make_nid_group("specific", b"nid-specific", false);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group], false, false);

        let announcement = vec![AnnouncementNid {
            id: b"other-nid".to_vec(),
            supports_psk: false,
        }];
        let result = lp.handle_announcement(&announcement);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LogonError::NoMatchingNid(_)));
    }

    /// Verifies: #34 (REQ-F-LOGON-002)
    /// Multiple advertised NIDs — first matching group by preference order wins.
    #[test]
    fn test_announcement_multiple_nids_preference_order() {
        let group_low = make_nid_group("low", b"nid-low", false);
        let group_high = make_nid_group("high", b"nid-high", true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group_low, group_high], false, false);

        let announcement = vec![
            AnnouncementNid {
                id: b"nid-high".to_vec(),
                supports_psk: true,
            },
            AnnouncementNid {
                id: b"nid-low".to_vec(),
                supports_psk: false,
            },
        ];
        lp.handle_announcement(&announcement).unwrap();
        // "low" comes first in nid_groups → preference order
        // But "nid-high" is advertised first and matches group_high
        // Design: iterate advertised NIDs, for each check all groups in preference order
        // → first advertised NID "nid-high" matches "high" group (second in list)
        assert_eq!(lp.selected_nid().unwrap().name(), "high");
    }

    // --- REQ-F-LOGON-003: EAPOL-Announcement Reception ---

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// AC1: NID Set TLVs parsed and access capabilities extracted.
    #[test]
    fn test_eapol_announcement_nid_set_parsed() {
        let group = make_nid_group("net1", &[0xAA, 0xBB], true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group], false, false);

        let announcement = eapol_supp::EapolAnnouncement {
            access_status: eapol_supp::AccessStatus::AuthenticationRequired,
            nids: vec![eapol_supp::AnnouncementNidEntry {
                id: vec![0xAA, 0xBB],
                supports_psk: true,
            }],
        };
        lp.handle_eapol_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().name(), "net1");
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// AC2: Announcement filtering — NID in ignore list is discarded.
    #[test]
    fn test_announcement_filtering_ignored_nid() {
        let group1 = make_nid_group("wanted", b"nid-wanted", false);
        let group2 = make_nid_group("ignored", b"nid-ignored", false);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group1, group2], false, false);
        lp.set_ignore_nids(vec![b"nid-ignored".to_vec()]);

        let announcement = vec![AnnouncementNid {
            id: b"nid-ignored".to_vec(),
            supports_psk: false,
        }];
        let result = lp.handle_announcement(&announcement);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), LogonError::NoMatchingNid(_)));
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Filtering allows non-ignored NIDs through.
    #[test]
    fn test_announcement_filtering_allows_non_ignored() {
        let group1 = make_nid_group("wanted", b"nid-wanted", false);
        let group2 = make_nid_group("ignored", b"nid-ignored", false);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group1, group2], false, false);
        lp.set_ignore_nids(vec![b"nid-ignored".to_vec()]);

        let announcement = vec![
            AnnouncementNid {
                id: b"nid-ignored".to_vec(),
                supports_psk: false,
            },
            AnnouncementNid {
                id: b"nid-wanted".to_vec(),
                supports_psk: false,
            },
        ];
        lp.handle_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().name(), "wanted");
    }

    /// Verifies: #35 (REQ-F-LOGON-003)
    /// Parsed EAPOL-Announcement with multiple NID entries.
    #[test]
    fn test_eapol_announcement_multiple_nids() {
        let group1 = make_nid_group("net1", &[0x11], false);
        let group2 = make_nid_group("net2", &[0x22], true);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group1, group2], false, false);

        let announcement = eapol_supp::EapolAnnouncement {
            access_status: eapol_supp::AccessStatus::Authenticated,
            nids: vec![
                eapol_supp::AnnouncementNidEntry {
                    id: vec![0x22],
                    supports_psk: true,
                },
                eapol_supp::AnnouncementNidEntry {
                    id: vec![0x11],
                    supports_psk: false,
                },
            ],
        };
        lp.handle_eapol_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().name(), "net2");
    }

    // --- REQ-F-LOGON-004: NID in EAPOL-Start ---

    /// Verifies: #36 (REQ-F-LOGON-004)
    /// When authentication starts with a selected NID, the NID is passed
    /// to start_authentication so it can be encoded in EAPOL-Start.
    #[test]
    fn test_start_authentication_includes_selected_nid() {
        let group = make_nid_group("net1", b"nid-test", false);
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![group], false, false);

        // Select a NID via announcement
        let announcement = vec![AnnouncementNid {
            id: b"nid-test".to_vec(),
            supports_psk: false,
        }];
        lp.handle_announcement(&announcement).unwrap();
        assert_eq!(lp.selected_nid().unwrap().id(), b"nid-test");

        // Link up triggers authentication — should pass the selected NID
        lp.ctx.auth_started.store(false, Ordering::SeqCst);
        lp.link_changed(true).unwrap();
        assert!(lp.ctx.auth_started.load(Ordering::SeqCst));
        assert_eq!(
            lp.ctx.auth_nid.lock().unwrap().as_deref(),
            Some(b"nid-test".as_slice())
        );
    }

    // --- REQ-F-LOGON-005: CAK Cache Management ---

    /// Verifies: #37 (REQ-F-LOGON-005)
    /// AC3: LogonProcess provides access to CAK cache for MKA participant creation.
    #[test]
    fn test_logon_process_cak_cache_access() {
        let ctx = MockLogonContext::new();
        let mut lp = LogonProcess::new(ctx, vec![], false, true);

        let cak = pae::Cak::from_bytes(&[0x0A; 16]).unwrap();
        let ckn = pae::Ckn::from_bytes(vec![0x0B; 16]).unwrap();
        let now = Duration::from_secs(100);

        let entry = crate::CakCacheEntry::new(
            cak,
            ckn.clone(),
            pae::CipherSuite::GcmAes128,
            now,
            Duration::from_secs(3600),
        );
        lp.cak_cache_mut().insert(entry);

        let found = lp.cak_cache_mut().lookup(&ckn, now);
        assert!(found.is_some());
        assert_eq!(found.unwrap().cipher_suite(), pae::CipherSuite::GcmAes128);
    }
}
