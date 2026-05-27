//! Control interface abstraction for the supplicant.
//!
//! Per REQ-NF-DEPLOY-005 (#72).
//! Enables testability without real D-Bus/socket.

use anyhow::Result;

/// Commands from the control interface.
#[derive(Debug, Clone)]
pub enum ControlCommand {
    /// Request reauthentication.
    Reauthenticate,
    /// Request logoff.
    Logoff,
    /// Get current state.
    GetState,
    /// Set log level.
    SetLogLevel { level: String },
    /// Request shutdown.
    Shutdown,
}

/// Control interface — abstracts D-Bus or Unix socket control.
///
/// Per REQ-NF-DEPLOY-005 (#72).
/// Enables testability without real D-Bus/socket.
pub trait ControlInterface: Send + Sync {
    /// Poll for control commands (non-blocking).
    ///
    /// Returns `Ok(None)` if no command is available.
    fn poll_command(&self) -> Result<Option<ControlCommand>>;

    /// Notify control interface of state change.
    fn notify_state(&self, state: &super::SupplicantState) -> Result<()>;
}

/// Mock control interface for testing.
#[cfg(test)]
pub struct MockControlInterface {
    commands: std::sync::Mutex<Vec<ControlCommand>>,
    last_state: std::sync::Mutex<Option<super::SupplicantState>>,
}

#[cfg(test)]
impl MockControlInterface {
    /// Create a mock control interface.
    pub fn new() -> Self {
        Self {
            commands: std::sync::Mutex::new(Vec::new()),
            last_state: std::sync::Mutex::new(None),
        }
    }

    /// Enqueue a command for polling.
    pub fn enqueue(&self, cmd: ControlCommand) {
        self.commands.lock().unwrap().push(cmd);
    }
}

#[cfg(test)]
impl ControlInterface for MockControlInterface {
    fn poll_command(&self) -> Result<Option<ControlCommand>> {
        Ok(self.commands.lock().unwrap().pop())
    }

    fn notify_state(&self, state: &super::SupplicantState) -> Result<()> {
        *self.last_state.lock().unwrap() = Some(state.clone());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// MockControlInterface enqueues and polls commands.
    #[test]
    fn test_mock_control_interface() {
        let ctrl = MockControlInterface::new();

        // No commands initially
        assert!(ctrl.poll_command().unwrap().is_none());

        // Enqueue and poll
        ctrl.enqueue(ControlCommand::Shutdown);
        let cmd = ctrl.poll_command().unwrap().unwrap();
        assert!(matches!(cmd, ControlCommand::Shutdown));

        // Notify state
        let state = super::super::SupplicantState {
            pae_state: "authenticated".to_string(),
            cp_state: "secured".to_string(),
            logon_state: None,
            selected_nid: None,
            mka_established: true,
            mka_live_peers: 1,
        };
        ctrl.notify_state(&state).unwrap();
    }
}
