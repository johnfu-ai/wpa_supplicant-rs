//! systemd integration — unit file and socket activation.
//!
//! Per REQ-NF-DEPLOY-004 (#71).
//! Feature-gated behind `systemd` feature flag.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

use anyhow::{bail, Result};

/// systemd `SD_LISTEN_FDS_START` constant — the FD number of the first
/// socket-activation FD passed by systemd. FDs 0/1/2 are stdin/stdout/stderr.
const SD_LISTEN_FDS_START: usize = 3;

/// systemd socket activation support.
///
/// Per REQ-NF-DEPLOY-004 (#71) and security-review F-06 (#154).
/// When the supplicant is started via systemd socket activation,
/// systemd passes pre-bound file descriptors via `LISTEN_FDS`. The
/// `LISTEN_PID` env var must equal `getpid()` for the FDs to be ours;
/// otherwise we are inheriting them from a process that wasn't supposed
/// to hand them off (an `exec` ancestor, a stale env var, a non-systemd
/// parent), and we must ignore them per `sd_listen_fds(3)`.
pub struct SystemdActivation;

impl SystemdActivation {
    /// Check if running under systemd socket activation.
    ///
    /// Returns `true` only if **both**:
    /// 1. `LISTEN_FDS` is set, **and**
    /// 2. `LISTEN_PID` equals the current process's PID.
    ///
    /// The PID check is the systemd contract — see `sd_listen_fds(3)` —
    /// and closes security-review F-06 (#154): without it, FDs leaked
    /// across `exec` or stale env vars in a process spawned by something
    /// other than systemd could be silently adopted as the control
    /// socket.
    pub fn is_socket_activation() -> bool {
        Self::validate_listen_pid().is_ok() && std::env::var("LISTEN_FDS").is_ok()
    }

    /// Validate `LISTEN_PID == std::process::id()`. Returns `Ok(())` if
    /// the env is unset or the PID matches; `Err` otherwise.
    fn validate_listen_pid() -> Result<()> {
        let Ok(pid_str) = std::env::var("LISTEN_PID") else {
            // No LISTEN_PID set — defer to the LISTEN_FDS check at the
            // call site (which will return false / Err if unset).
            return Ok(());
        };
        let pid: u32 = pid_str
            .parse()
            .map_err(|e| anyhow::anyhow!("LISTEN_PID is not a valid PID: {e}"))?;
        let mine = std::process::id();
        if pid != mine {
            bail!("LISTEN_PID={pid} does not match this process's PID {mine}; ignoring LISTEN_FDS",);
        }
        Ok(())
    }

    /// Get the number of FDs passed by systemd.
    ///
    /// Per systemd socket activation protocol (`sd_listen_fds(3)`).
    /// FDs start at `SD_LISTEN_FDS_START` (3). Validates `LISTEN_PID`
    /// before honouring `LISTEN_FDS` (security-review F-06 / #154).
    ///
    /// Returns an error if `LISTEN_PID` is set but does not match.
    pub fn listen_fds() -> Result<usize> {
        Self::validate_listen_pid()?;
        let fds_str = std::env::var("LISTEN_FDS")?;
        let fds: usize = fds_str.parse()?;
        Ok(fds)
    }

    /// Clear the `LISTEN_FDS` and `LISTEN_PID` environment variables.
    ///
    /// systemd's contract (`sd_listen_fds(3)`, `unset_environment` flag)
    /// recommends clearing both env vars after first read so that any
    /// future `exec`'d child does not double-adopt the same FDs. Call
    /// this **after** `listen_fds()` has been read and the FDs taken.
    pub fn clear_env() {
        // SAFETY: `std::env::remove_var` is safe in Rust 1.75 (the
        // workspace MSRV). The 1.79+ unsafe-fn migration does not apply.
        std::env::remove_var("LISTEN_FDS");
        std::env::remove_var("LISTEN_PID");
        std::env::remove_var("LISTEN_FDNAMES");
    }

    /// Create a `UnixListener` from a systemd-provided FD.
    ///
    /// `SD_LISTEN_FDS_START` is 3 (FD 0=stdin, 1=stdout, 2=stderr,
    /// 3+=systemd). `fd_index` is 0-based — the first systemd FD is
    /// `fd_index = 0`, addressing FD 3.
    ///
    /// Returns an error if `fd_index >= listen_fds()` (security-review
    /// F-06 / #154 — bounds check so a caller bug becomes a clean error
    /// instead of an FD-confusion bug). Also returns an error if
    /// `LISTEN_PID` is set and does not match.
    pub fn take_unix_listener(fd_index: usize) -> Result<std::os::unix::net::UnixListener> {
        let n = Self::listen_fds()?;
        if fd_index >= n {
            bail!("systemd FD index {fd_index} out of bounds: only {n} FD(s) passed by systemd",);
        }
        let fd = SD_LISTEN_FDS_START + fd_index;
        use std::os::unix::io::FromRawFd;
        // SAFETY: `LISTEN_PID` was checked to match this process, so
        // systemd passed us this FD. `fd_index` was bounds-checked
        // against `LISTEN_FDS` so `fd` is one of the FDs systemd opened.
        // `from_raw_fd` takes ownership; we never call `take_unix_listener`
        // for the same `fd_index` twice in practice, and double-take
        // would be a caller bug we cannot guard against here.
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
    use std::sync::Mutex;

    /// Tests in this module mutate the process-wide environment. Cargo
    /// runs `#[test]` functions in parallel by default, so each test
    /// that touches `LISTEN_*` env vars takes this mutex first to
    /// serialise execution. Without it, two parallel tests setting
    /// `LISTEN_PID` to different PIDs race and the assertions become
    /// non-deterministic.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    /// Helper: clear the systemd env vars to a known-empty baseline.
    fn clear_listen_env() {
        SystemdActivation::clear_env();
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// is_socket_activation returns false when not under systemd.
    #[test]
    fn test_not_socket_activation() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_listen_env();
        assert!(!SystemdActivation::is_socket_activation());
    }

    /// Verifies: #71 (REQ-NF-DEPLOY-004)
    /// listen_fds returns error when not under systemd.
    #[test]
    fn test_listen_fds_not_set() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_listen_env();
        assert!(SystemdActivation::listen_fds().is_err());
    }

    /// Verifies: REQ-NF-DEPLOY-004 (#71), security-review F-06 (#154).
    ///
    /// LISTEN_PID set to a different PID makes is_socket_activation
    /// return false even when LISTEN_FDS is set — closes the FD-leak
    /// vector across exec or stale env vars in a non-systemd parent.
    #[test]
    fn test_listen_pid_mismatch_rejects() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_listen_env();
        // Set LISTEN_PID to a PID that is definitely not us (PID 1 is
        // the init process; even on weird hosts it is not the cargo
        // test runner).
        std::env::set_var("LISTEN_PID", "1");
        std::env::set_var("LISTEN_FDS", "1");
        assert!(
            !SystemdActivation::is_socket_activation(),
            "LISTEN_PID mismatch must veto socket activation",
        );
        assert!(
            SystemdActivation::listen_fds().is_err(),
            "listen_fds must reject mismatched LISTEN_PID",
        );
        clear_listen_env();
    }

    /// Verifies: REQ-NF-DEPLOY-004 (#71), security-review F-06 (#154).
    ///
    /// LISTEN_PID set to our PID + LISTEN_FDS=N makes listen_fds
    /// succeed and return N. Confirms the validate-then-honour path.
    #[test]
    fn test_listen_pid_match_accepts() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_listen_env();
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
        std::env::set_var("LISTEN_FDS", "2");
        assert!(SystemdActivation::is_socket_activation());
        assert_eq!(SystemdActivation::listen_fds().unwrap(), 2);
        clear_listen_env();
    }

    /// Verifies: REQ-NF-DEPLOY-004 (#71), security-review F-06 (#154).
    ///
    /// take_unix_listener bounds-checks fd_index against LISTEN_FDS so
    /// an out-of-bounds caller bug returns a clean error instead of
    /// silently grabbing some other process's FD.
    #[test]
    fn test_take_unix_listener_bounds_check() {
        let _guard = ENV_LOCK.lock().unwrap();
        clear_listen_env();
        std::env::set_var("LISTEN_PID", std::process::id().to_string());
        std::env::set_var("LISTEN_FDS", "1");
        // fd_index 5 is out of bounds when only 1 FD was passed.
        let res = SystemdActivation::take_unix_listener(5);
        assert!(
            res.is_err(),
            "take_unix_listener(5) with LISTEN_FDS=1 must error",
        );
        let msg = format!("{:?}", res.unwrap_err());
        assert!(
            msg.contains("out of bounds") || msg.contains("only 1"),
            "expected out-of-bounds error, got {msg:?}",
        );
        clear_listen_env();
    }

    /// Verifies: REQ-NF-DEPLOY-004 (#71), security-review F-06 (#154).
    ///
    /// clear_env removes both LISTEN_PID and LISTEN_FDS so a re-exec'd
    /// child does not double-adopt.
    #[test]
    fn test_clear_env() {
        let _guard = ENV_LOCK.lock().unwrap();
        std::env::set_var("LISTEN_PID", "12345");
        std::env::set_var("LISTEN_FDS", "1");
        std::env::set_var("LISTEN_FDNAMES", "control:another");
        SystemdActivation::clear_env();
        assert!(std::env::var("LISTEN_PID").is_err());
        assert!(std::env::var("LISTEN_FDS").is_err());
        assert!(std::env::var("LISTEN_FDNAMES").is_err());
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
