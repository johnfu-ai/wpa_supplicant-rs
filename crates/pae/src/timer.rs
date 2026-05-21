//! Protocol timer wheel for MKA and CP state machines.
//!
//! Per ADR-TMR-003 (#75): tick-driven (no async), virtual clock for testing.
//! BTreeMap-based for O(log n) expiry lookup with bounded execution.
//!
//! Implements: #25 (REQ-F-MKA-007: MKA Participant Timer Values)

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

/// Protocol timer identifiers.
///
/// Per IEEE 802.1X-2020 and ADR-TMR-003 (#75).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TimerId {
    /// MKA Hello Time (default 2000ms). Per Cl.9.5.
    MkaHello,
    /// MKA Bounded Hello Time (default 500ms). Per Cl.9.5.
    MkaBoundedHello,
    /// MKA Life Time (default 6000ms). Per Cl.9.5.
    MkaLife,
    /// SAK Retire timer. Per Cl.9.8.
    SakRetire,
}

/// Default MKA Hello Time: 2000ms per Cl.9.5.
pub const MKA_HELLO_TIME: Duration = Duration::from_millis(2000);

/// Default MKA Bounded Hello Time: 500ms per Cl.9.5.
pub const MKA_BOUNDED_HELLO_TIME: Duration = Duration::from_millis(500);

/// Default MKA Life Time: 6000ms per Cl.9.5.
pub const MKA_LIFE_TIME: Duration = Duration::from_millis(6000);

/// Default SAK Retire Time: 3000ms per Cl.9.8.
pub const SAK_RETIRE_TIME: Duration = Duration::from_millis(3000);

/// Deterministic timer wheel for protocol timers.
///
/// Per ADR-TMR-003 (#75).
/// Tick-driven (no async); virtual clock for testing.
/// BTreeMap-based for O(log n) expiry lookup.
///
/// Implements: #25 (REQ-F-MKA-007: MKA Participant Timer Values)
#[derive(Debug)]
pub struct TimerWheel {
    /// Current virtual time.
    now: Duration,
    /// Scheduled timers: expiry time → list of timer IDs.
    timers: BTreeMap<Duration, Vec<TimerId>>,
    /// Active timer IDs and their expiry times (for cancellation).
    active: HashMap<TimerId, Duration>,
}

impl TimerWheel {
    /// Create a timer wheel starting at time zero.
    pub fn new() -> Self {
        Self {
            now: Duration::ZERO,
            timers: BTreeMap::new(),
            active: HashMap::new(),
        }
    }

    /// Schedule a timer. Returns the expiry time.
    ///
    /// If the timer is already active, it is rescheduled.
    pub fn schedule(&mut self, id: TimerId, duration: Duration) -> Duration {
        // Cancel existing if any
        self.cancel(id);

        let expiry = self.now + duration;
        self.timers.entry(expiry).or_default().push(id);
        self.active.insert(id, expiry);
        expiry
    }

    /// Cancel a timer.
    pub fn cancel(&mut self, id: TimerId) {
        if let Some(expiry) = self.active.remove(&id) {
            if let Some(list) = self.timers.get_mut(&expiry) {
                list.retain(|t| *t != id);
                if list.is_empty() {
                    self.timers.remove(&expiry);
                }
            }
        }
    }

    /// Advance the clock and return all expired timer IDs.
    ///
    /// Bounded execution: O(k log n) where k is expired timers.
    pub fn advance_to(&mut self, now: Duration) -> Vec<TimerId> {
        if now <= self.now {
            return vec![];
        }
        self.now = now;

        let mut expired = Vec::new();
        let keys_to_remove: Vec<Duration> = self
            .timers
            .keys()
            .filter(|&&expiry| expiry <= now)
            .copied()
            .collect();

        for key in keys_to_remove {
            if let Some(ids) = self.timers.remove(&key) {
                for id in ids {
                    self.active.remove(&id);
                    expired.push(id);
                }
            }
        }
        expired
    }

    /// Current virtual time.
    pub fn now(&self) -> Duration {
        self.now
    }

    /// Whether a timer is currently active.
    pub fn is_active(&self, id: TimerId) -> bool {
        self.active.contains_key(&id)
    }

    /// Get the remaining time for a timer, if active.
    pub fn remaining(&self, id: TimerId) -> Option<Duration> {
        self.active
            .get(&id)
            .map(|&expiry| expiry.saturating_sub(self.now))
    }
}

impl Default for TimerWheel {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #25 (REQ-F-MKA-007)
    /// TimerWheel starts at time zero.
    #[test]
    fn test_timer_wheel_new() {
        let tw = TimerWheel::new();
        assert_eq!(tw.now(), Duration::ZERO);
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// Schedule a timer and check it is active.
    #[test]
    fn test_timer_wheel_schedule() {
        let mut tw = TimerWheel::new();
        let expiry = tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
        assert_eq!(expiry, MKA_HELLO_TIME);
        assert!(tw.is_active(TimerId::MkaHello));
        assert_eq!(tw.remaining(TimerId::MkaHello), Some(MKA_HELLO_TIME));
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// advance_to returns expired timers.
    #[test]
    fn test_timer_wheel_advance() {
        let mut tw = TimerWheel::new();
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
        tw.schedule(TimerId::MkaLife, MKA_LIFE_TIME);

        let expired = tw.advance_to(Duration::from_millis(2500));
        assert_eq!(expired, vec![TimerId::MkaHello]);
        assert!(!tw.is_active(TimerId::MkaHello));
        assert!(tw.is_active(TimerId::MkaLife));
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// advance_to returns multiple expired timers.
    #[test]
    fn test_timer_wheel_multiple_expired() {
        let mut tw = TimerWheel::new();
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
        tw.schedule(TimerId::MkaLife, MKA_LIFE_TIME);

        let expired = tw.advance_to(Duration::from_millis(7000));
        assert!(expired.contains(&TimerId::MkaHello));
        assert!(expired.contains(&TimerId::MkaLife));
        assert!(!tw.is_active(TimerId::MkaHello));
        assert!(!tw.is_active(TimerId::MkaLife));
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// Cancel a timer.
    #[test]
    fn test_timer_wheel_cancel() {
        let mut tw = TimerWheel::new();
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
        tw.cancel(TimerId::MkaHello);
        assert!(!tw.is_active(TimerId::MkaHello));

        let expired = tw.advance_to(Duration::from_millis(3000));
        assert!(expired.is_empty());
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// Reschedule a timer replaces the previous schedule.
    #[test]
    fn test_timer_wheel_reschedule() {
        let mut tw = TimerWheel::new();
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);
        tw.schedule(TimerId::MkaHello, Duration::from_secs(10));

        let expired = tw.advance_to(Duration::from_millis(3000));
        assert!(expired.is_empty(), "should not expire at original time");

        let expired = tw.advance_to(Duration::from_secs(11));
        assert!(expired.contains(&TimerId::MkaHello));
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// advance_to with past time returns no expired timers.
    #[test]
    fn test_timer_wheel_advance_past_time() {
        let mut tw = TimerWheel::new();
        tw.advance_to(Duration::from_secs(5));
        tw.schedule(TimerId::MkaHello, MKA_HELLO_TIME);

        let expired = tw.advance_to(Duration::from_secs(3));
        assert!(
            expired.is_empty(),
            "advancing to past time should not expire"
        );
    }

    /// Verifies: #25 (REQ-F-MKA-007)
    /// MKA timer constants are correct per IEEE 802.1X-2020.
    #[test]
    fn test_mka_timer_constants() {
        assert_eq!(MKA_HELLO_TIME, Duration::from_millis(2000));
        assert_eq!(MKA_BOUNDED_HELLO_TIME, Duration::from_millis(500));
        assert_eq!(MKA_LIFE_TIME, Duration::from_millis(6000));
        assert_eq!(SAK_RETIRE_TIME, Duration::from_millis(3000));
    }
}
