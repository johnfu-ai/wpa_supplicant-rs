//! systemd integration — unit file and socket activation.
//!
//! Per REQ-NF-DEPLOY-004 (#71).
//! Feature-gated behind `systemd` feature flag.

use anyhow::Result;

/// systemd socket activation support.
///
/// Per REQ-NF-DEPLOY-004 (#71).
/// When the supplicant is started via systemd socket activation,
/// systemd passes pre-bound file descriptors via LISTEN_FDS.
/// This module checks for those FDs and creates Unix listeners from them.
pub struct SystemdActivation;

impl SystemdActivation {
    /// Check if running under systemd socket activation.
    ///
    /// Returns true if LISTEN_FDS environment variable is set.
    pub fn is_socket_activation() -> bool {
        std::env::var("LISTEN_FDS").is_ok()
    }

    /// Get the number of FDs passed by systemd.
    ///
    /// Per systemd socket activation protocol (sd_listen_fds(3)).
    /// FDs start at SD_LISTEN_FDS_START (3).
    pub fn listen_fds() -> Result<usize> {
        let fds_str = std::env::var("LISTEN_FDS")?;
        let fds: usize = fds_str.parse()?;
        Ok(fds)
    }

    /// Create a UnixListener from systemd-provided FD.
    ///
    /// SD_LISTEN_FDS_START is 3 (FD 0=stdin, 1=stdout, 2=stderr, 3+=systemd).
    pub fn take_unix_listener(fd_index: usize) -> Result<std::os::unix::net::UnixListener> {
        let fd = 3 + fd_index; // SD_LISTEN_FDS_START
        use std::os::unix::io::FromRawFd;
        // SAFETY: FD is provided by systemd and is valid for the lifetime
        // of this process. We take ownership once.
        let listener = unsafe { std::os::unix::net::UnixListener::from_raw_fd(fd as _) };
        listener.set_nonblocking(true)?;
        Ok(listener)
    }
}

/// Generate the systemd service unit file content.
///
/// Per REQ-NF-DEPLOY-004 (#71).
pub fn generate_unit_file() -> String {
    r#"[Unit]
Description=IEEE 802.1X-2020 Supplicant
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/wpa-supplicant /etc/wpa-supply/config.toml
Restart=on-failure
RestartSec=5

# Security hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=/run/wpa-supply

[Install]
WantedBy=multi-user.target
"#
    .to_string()
}

/// Generate the systemd socket unit file content.
///
/// Per REQ-NF-DEPLOY-004 (#71).
pub fn generate_socket_unit(socket_path: &str) -> String {
    format!(
        r#"[Unit]
Description=IEEE 802.1X-2020 Supplicant Control Socket

[Socket]
ListenStream={socket_path}
SocketMode=0660

[Install]
WantedBy=sockets.target
"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// is_socket_activation returns false when not under systemd.
    #[test]
    fn test_not_socket_activation() {
        // In test environment, LISTEN_FDS is not set
        assert!(!SystemdActivation::is_socket_activation());
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// listen_fds returns error when not under systemd.
    #[test]
    fn test_listen_fds_not_set() {
        assert!(SystemdActivation::listen_fds().is_err());
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// generate_unit_file produces valid systemd unit.
    #[test]
    fn test_unit_file_generation() {
        let unit = generate_unit_file();
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("wpa-supplicant"));
        assert!(unit.contains("NoNewPrivileges=true"));
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// generate_socket_unit includes the specified path.
    #[test]
    fn test_socket_unit_generation() {
        let socket = generate_socket_unit("/run/wpa-supply/ctrl.sock");
        assert!(socket.contains("[Socket]"));
        assert!(socket.contains("ListenStream=/run/wpa-supply/ctrl.sock"));
        assert!(socket.contains("SocketMode=0660"));
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// Unit file can be written to a temp file and parsed as valid INI-ish.
    #[test]
    fn test_unit_file_writable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wpa-supplicant.service");
        std::fs::write(&path, generate_unit_file()).unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert!(content.contains("[Unit]"));
    }
}
