//! Control interface abstraction for the supplicant.
//!
//! Per REQ-NF-DEPLOY-005 (#72).
//! Supports Unix domain socket control interface.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use std::io::BufRead;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{Context, Result};

/// Maximum bytes accepted per command line on the control socket.
///
/// Per the security review of 2026-06-13 (F-02 / #150): without a per-line
/// upper bound, a misbehaving or malicious client can send a multi-GB line
/// and keep the listener-servicing loop reading forever, starving the
/// supplicant tick. Real commands top out at ~32 bytes (e.g.
/// `SET_LOG_LEVEL pae::mka=trace`); 256 is generous + memorable.
const MAX_COMMAND_LINE_BYTES: usize = 256;

/// Maximum number of command lines accepted per connection.
///
/// Defence-in-depth alongside `MAX_COMMAND_LINE_BYTES` so that a client
/// streaming valid-but-tiny lines forever cannot wedge the connection
/// servicer either.
const MAX_LINES_PER_CONNECTION: usize = 32;

/// Per-connection read deadline.
///
/// Per the security review of 2026-06-13 (F-02 / #150): the `accept`-ed
/// stream is set to this read timeout so a client that opens a connection
/// and never sends data cannot wedge `handle_connection`. Real clients
/// (`nc -U`, `socat`, the future `wpa-supplicant-ctl`) all write within
/// milliseconds; one second is comfortably above any reasonable RTT.
const CONNECTION_READ_TIMEOUT: Duration = Duration::from_secs(1);

/// File mode for the control socket inode.
///
/// Per the security review of 2026-06-13 (F-01 / #150): bind alone honours
/// the process umask, which on a typical default-umask root daemon yields
/// `0o755` — world-readable+executable, group-writable. Tighten to
/// `0o660` so only members of the daemon's UID/GID can issue commands.
/// The systemd `.socket` unit's `SocketMode=0660` covers the
/// socket-activation path; this constant covers the direct-bind path.
const CONTROL_SOCKET_MODE: u32 = 0o660;

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
    /// Removes any existing socket file before binding, then chmods the
    /// new socket to `0o660` so only the daemon's UID/GID can connect
    /// (per the security review of 2026-06-13 / F-01 / #150).
    pub fn bind(path: &str) -> Result<Self> {
        // Remove stale socket file
        let _ = std::fs::remove_file(path);

        let listener = UnixListener::bind(path)
            .with_context(|| format!("binding control socket at {path}"))?;

        // F-01 / #150: chmod the inode immediately after bind. The systemd
        // `.socket` unit's `SocketMode=0660` covers the socket-activation
        // path; this covers the direct-bind path. Done as soon as the
        // path exists so the world-readable window is as small as
        // possible.
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(CONTROL_SOCKET_MODE))
            .with_context(|| format!("chmod {CONTROL_SOCKET_MODE:o} on {path}"))?;

        // Non-blocking listener — `accept_commands` polls in a loop.
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
    /// Call this from the event loop tick. The listener mutex is held
    /// only for the `accept` itself; per-connection servicing happens
    /// after the lock is dropped, per the security review of 2026-06-13
    /// (F-02 / #150) — otherwise a slow client can wedge the entire
    /// listener.
    fn accept_commands(&self) -> Result<()> {
        loop {
            let stream = {
                // Held for the accept call only.
                let listener_guard = self.listener.lock().unwrap();
                let Some(listener) = listener_guard.as_ref() else {
                    return Ok(());
                };
                match listener.accept() {
                    Ok((stream, _addr)) => stream,
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                    Err(e) => return Err(e.into()),
                }
                // listener_guard dropped here.
            };
            if let Err(e) = self.handle_connection(stream) {
                tracing::debug!(error = %e, "control connection error");
            }
        }
        Ok(())
    }

    /// Handle a single control connection.
    ///
    /// Bounded by `MAX_COMMAND_LINE_BYTES` per line and
    /// `CONNECTION_READ_TIMEOUT` per read syscall (F-02 / #150).
    fn handle_connection(&self, stream: UnixStream) -> Result<()> {
        // Switch the accepted stream to blocking-with-timeout: the
        // listener was non-blocking but `accept` returns a stream that
        // inherits the *socket*'s blocking flag (i.e. blocking, despite
        // the listener being non-blocking). A read deadline lets a
        // misbehaving client get cleanly cut off.
        stream.set_nonblocking(false)?;
        stream.set_read_timeout(Some(CONNECTION_READ_TIMEOUT))?;

        // Cap the total bytes any single connection can deliver so a
        // misbehaving client (multi-GB line, or trickle-fed stream)
        // cannot wedge the daemon. Per-line limit × max lines per
        // connection bounds both surfaces.
        let total_cap = (MAX_COMMAND_LINE_BYTES * MAX_LINES_PER_CONNECTION) as u64;
        let reader = std::io::BufReader::new(std::io::Read::take(stream, total_cap));
        let mut pending = self.pending.lock().unwrap();
        let mut count = 0usize;
        for line in reader.lines() {
            count += 1;
            if count > MAX_LINES_PER_CONNECTION {
                break;
            }
            match line {
                Ok(line) => {
                    if line.len() > MAX_COMMAND_LINE_BYTES {
                        // Truncated by the global `take` or otherwise
                        // oversize — log and stop reading from this
                        // client.
                        tracing::warn!(
                            len = line.len(),
                            "control command line exceeded {} bytes; closing connection",
                            MAX_COMMAND_LINE_BYTES
                        );
                        break;
                    }
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

    /// Verifies: REQ-NF-DEPLOY-005 (#72), security-review F-01 (#150).
    ///
    /// After `bind`, the socket inode mode must be exactly `0o660` so
    /// that local users outside the daemon's UID/GID cannot connect.
    #[test]
    fn test_unix_control_socket_mode_is_0660() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("mode.sock");
        let socket_str = socket_path.to_str().unwrap();

        let _ctrl = UnixControl::bind(socket_str).unwrap();
        let meta = std::fs::metadata(&socket_path).unwrap();
        let mode = meta.permissions().mode() & 0o777;
        assert_eq!(
            mode, CONTROL_SOCKET_MODE,
            "socket {socket_str} mode should be {CONTROL_SOCKET_MODE:o}, got {mode:o}",
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72), security-review F-02 (#150).
    ///
    /// A client that connects but never writes anything (idle stream)
    /// must not block `poll_command` indefinitely. The accepted stream's
    /// read timeout (`CONNECTION_READ_TIMEOUT`) bounds the wait.
    #[test]
    fn test_unix_control_idle_client_does_not_wedge_poll() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("idle.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();

        // Connect and immediately stop writing — never close. The daemon
        // will block in `read_line` until `CONNECTION_READ_TIMEOUT` fires.
        let _stream = UnixStream::connect(socket_str).unwrap();

        let started = std::time::Instant::now();
        let _ = ctrl.poll_command().unwrap();
        let elapsed = started.elapsed();

        // Generous slack (2× timeout) to absorb scheduling jitter on
        // loaded CI hosts. The point is "does not hang forever," not
        // "exact timeout."
        assert!(
            elapsed < CONNECTION_READ_TIMEOUT * 2,
            "poll_command took {elapsed:?}, should give up after {CONNECTION_READ_TIMEOUT:?}",
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72), security-review F-02 (#150).
    ///
    /// A line longer than `MAX_COMMAND_LINE_BYTES` must not be parsed
    /// as a command, and must not exhaust the daemon's allocator. We
    /// cap at 256 bytes; a 100 KB line is two orders of magnitude over.
    #[test]
    fn test_unix_control_oversize_line_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("oversize.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();

        let mut stream = UnixStream::connect(socket_str).unwrap();
        // 100 KB of "A" with a trailing newline — well over the
        // MAX_COMMAND_LINE_BYTES cap.
        let huge = "A".repeat(100_000) + "\n";
        std::io::Write::write_all(&mut stream, huge.as_bytes()).unwrap();
        // Then a real command — which the daemon should ignore because
        // the connection is already truncated.
        std::io::Write::write_all(&mut stream, b"SHUTDOWN\n").unwrap();
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));

        // The first line was oversize — it must not parse as a command.
        // The truncated middle (which begins with "AAA…") is not a
        // recognized command either. So no commands should land in
        // pending. (If `take` truncated mid-line and the rest contained
        // "SHUTDOWN", we'd see a Shutdown — which is exactly the
        // behaviour we're protecting against.)
        let mut commands = Vec::new();
        while let Some(cmd) = ctrl.poll_command().unwrap() {
            commands.push(cmd);
        }
        assert!(
            !commands.contains(&ControlCommand::Shutdown),
            "oversize line must not let a downstream SHUTDOWN through; got {commands:?}",
        );
    }

    /// Verifies: REQ-NF-DEPLOY-005 (#72), security-review F-02 (#150).
    ///
    /// A client streaming many tiny valid lines is bounded by
    /// `MAX_LINES_PER_CONNECTION`. Beyond that, the daemon stops
    /// reading from the connection — preventing an infinite-stream
    /// client from monopolizing the listener servicer.
    #[test]
    fn test_unix_control_per_connection_line_cap() {
        let dir = tempfile::tempdir().unwrap();
        let socket_path = dir.path().join("flood.sock");
        let socket_str = socket_path.to_str().unwrap();

        let ctrl = UnixControl::bind(socket_str).unwrap();

        let mut stream = UnixStream::connect(socket_str).unwrap();
        // Send well over MAX_LINES_PER_CONNECTION valid commands.
        for _ in 0..(MAX_LINES_PER_CONNECTION * 4) {
            std::io::Write::write_all(&mut stream, b"GET_STATE\n").unwrap();
        }
        stream.shutdown(std::net::Shutdown::Write).unwrap();

        std::thread::sleep(std::time::Duration::from_millis(100));

        let mut count = 0usize;
        while ctrl.poll_command().unwrap().is_some() {
            count += 1;
            if count > MAX_LINES_PER_CONNECTION * 4 {
                panic!(
                    "saw {count} commands; per-connection cap of {MAX_LINES_PER_CONNECTION} not enforced",
                );
            }
        }
        assert!(
            count <= MAX_LINES_PER_CONNECTION,
            "per-connection cap not enforced: parsed {count} commands, cap is {MAX_LINES_PER_CONNECTION}",
        );
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
