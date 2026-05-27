//! Control interface abstraction for the supplicant.
//!
//! Per REQ-NF-DEPLOY-005 (#72).
//! Supports Unix domain socket control interface.

use std::io::BufRead;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;

use anyhow::Result;

/// Commands from the control interface.
#[derive(Debug, Clone, PartialEq)]
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

impl ControlCommand {
    /// Parse a command from a line of text.
    ///
    /// Protocol: simple text commands, one per line.
    /// - `REAUTHENTICATE` → Reauthenticate
    /// - `LOGOFF` → Logoff
    /// - `GET_STATE` → GetState
    /// - `SET_LOG_LEVEL <level>` → SetLogLevel
    /// - `SHUTDOWN` → Shutdown
    pub fn parse(line: &str) -> Option<Self> {
        let line = line.trim();
        match line {
            "REAUTHENTICATE" => Some(Self::Reauthenticate),
            "LOGOFF" => Some(Self::Logoff),
            "GET_STATE" => Some(Self::GetState),
            "SHUTDOWN" => Some(Self::Shutdown),
            s if s.starts_with("SET_LOG_LEVEL ") => {
                let level = s.strip_prefix("SET_LOG_LEVEL ")?.trim();
                if level.is_empty() {
                    None
                } else {
                    Some(Self::SetLogLevel {
                        level: level.to_string(),
                    })
                }
            }
            _ => None,
        }
    }
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

/// Unix domain socket control interface.
///
/// Per REQ-NF-DEPLOY-005 (#72).
/// Accepts connections on a Unix socket, reads line-based commands.
pub struct UnixControl {
    /// Path to the Unix socket.
    path: String,
    /// Listener for incoming connections.
    listener: Mutex<Option<UnixListener>>,
    /// Buffered pending commands from clients.
    pending: Mutex<Vec<ControlCommand>>,
}

impl UnixControl {
    /// Create a Unix control interface bound to the given path.
    ///
    /// Removes any existing socket file before binding.
    pub fn bind(path: &str) -> Result<Self> {
        // Remove stale socket file
        let _ = std::fs::remove_file(path);

        let listener = UnixListener::bind(path)?;

        // Set non-blocking
        listener.set_nonblocking(true)?;

        Ok(Self {
            path: path.to_string(),
            listener: Mutex::new(Some(listener)),
            pending: Mutex::new(Vec::new()),
        })
    }

    /// Get the socket path.
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Accept pending connections and read commands.
    ///
    /// Call this from the event loop tick.
    fn accept_commands(&self) -> Result<()> {
        let listener_guard = self.listener.lock().unwrap();
        if let Some(listener) = listener_guard.as_ref() {
            loop {
                match listener.accept() {
                    Ok((stream, _addr)) => {
                        if let Err(e) = self.handle_connection(&stream) {
                            tracing::debug!(error = %e, "control connection error");
                        }
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        break;
                    }
                    Err(e) => {
                        return Err(e.into());
                    }
                }
            }
        }
        Ok(())
    }

    /// Handle a single control connection.
    fn handle_connection(&self, stream: &UnixStream) -> Result<()> {
        let reader = std::io::BufReader::new(stream);
        let mut pending = self.pending.lock().unwrap();
        for line in reader.lines() {
            match line {
                Ok(line) => {
                    if let Some(cmd) = ControlCommand::parse(&line) {
                        pending.push(cmd);
                    }
                }
                Err(_) => break,
            }
        }
        Ok(())
    }
}

impl ControlInterface for UnixControl {
    fn poll_command(&self) -> Result<Option<ControlCommand>> {
        self.accept_commands()?;
        let mut pending = self.pending.lock().unwrap();
        Ok(pending.pop())
    }

    fn notify_state(&self, state: &super::SupplicantState) -> Result<()> {
        // For Unix socket, we write state as JSON to any connected clients
        // In a full implementation, we'd track connected clients.
        // For now, log the state change.
        tracing::debug!(?state, "control state notification");
        Ok(())
    }
}

impl Drop for UnixControl {
    fn drop(&mut self) {
        // Clean up socket file on drop
        let _ = std::fs::remove_file(&self.path);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// ControlCommand::parse handles all known commands.
    #[test]
    fn test_command_parse_reauthenticate() {
        assert_eq!(
            ControlCommand::parse("REAUTHENTICATE"),
            Some(ControlCommand::Reauthenticate)
        );
    }

    #[test]
    fn test_command_parse_logoff() {
        assert_eq!(
            ControlCommand::parse("LOGOFF"),
            Some(ControlCommand::Logoff)
        );
    }

    #[test]
    fn test_command_parse_get_state() {
        assert_eq!(
            ControlCommand::parse("GET_STATE"),
            Some(ControlCommand::GetState)
        );
    }

    #[test]
    fn test_command_parse_shutdown() {
        assert_eq!(
            ControlCommand::parse("SHUTDOWN"),
            Some(ControlCommand::Shutdown)
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// SET_LOG_LEVEL with argument parses correctly.
    #[test]
    fn test_command_parse_set_log_level() {
        assert_eq!(
            ControlCommand::parse("SET_LOG_LEVEL debug"),
            Some(ControlCommand::SetLogLevel {
                level: "debug".to_string()
            })
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// SET_LOG_LEVEL without argument returns None.
    #[test]
    fn test_command_parse_set_log_level_empty() {
        assert_eq!(ControlCommand::parse("SET_LOG_LEVEL "), None);
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// Unknown command returns None.
    #[test]
    fn test_command_parse_unknown() {
        assert_eq!(ControlCommand::parse("UNKNOWN"), None);
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// Whitespace-trimmed input parses correctly.
    #[test]
    fn test_command_parse_whitespace() {
        assert_eq!(
            ControlCommand::parse("  SHUTDOWN  "),
            Some(ControlCommand::Shutdown)
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// UnixControl can bind and accept commands via socket.
    #[test]
    fn test_unix_control_bind_and_command() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();
        assert_eq!(ctrl.path(), socket_str);

        // No commands initially
        assert!(ctrl.poll_command().unwrap().is_none());

        // Send a command via socket
        let mut stream = UnixStream::connect(socket_str).unwrap();
        writeln!(stream, "SHUTDOWN").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        // Give the listener a moment to accept
        std::thread::sleep(std::time::Duration::from_millis(50));

        // Poll should find the command
        let cmd = ctrl.poll_command().unwrap();
        assert!(matches!(cmd, Some(ControlCommand::Shutdown)));
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// UnixControl accepts multiple commands from a single connection.
    #[test]
    fn test_unix_control_multiple_commands() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test2.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();

        let mut stream = UnixStream::connect(socket_str).unwrap();
        writeln!(stream, "GET_STATE").unwrap();
        writeln!(stream, "LOGOFF").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let mut cmds = Vec::new();
        while let Some(cmd) = ctrl.poll_command().unwrap() {
            cmds.push(cmd);
        }
        assert!(cmds.len() >= 2);
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// notify_state does not error.
    #[test]
    fn test_unix_control_notify_state() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("test3.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();
        let state = super::super::SupplicantState {
            pae_state: "authenticated".to_string(),
            cp_state: "secured".to_string(),
            logon_state: None,
            selected_nid: None,
            mka_established: true,
            mka_live_peers: 1,
        };
        assert!(ctrl.notify_state(&state).is_ok());
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// Socket file is cleaned up on drop.
    #[test]
    fn test_unix_control_cleanup() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("cleanup.sock");
        let socket_str = socket_path.to_str().unwrap();

        {
            let _ctrl = UnixControl::bind(socket_str).unwrap();
            assert!(socket_path.exists());
        }
        // After drop, socket should be cleaned up
        assert!(!socket_path.exists());
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72)
    /// SET_LOG_LEVEL via socket parses correctly.
    #[test]
    fn test_unix_control_set_log_level() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("level.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();

        let mut stream = UnixStream::connect(socket_str).unwrap();
        writeln!(stream, "SET_LOG_LEVEL trace").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(50));

        let cmd = ctrl.poll_command().unwrap();
        assert!(matches!(cmd, Some(ControlCommand::SetLogLevel { .. })));
        if let Some(ControlCommand::SetLogLevel { level }) = cmd {
            assert_eq!(level, "trace");
        }
    }
}
