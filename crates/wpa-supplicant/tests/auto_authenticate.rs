//! Integration tests for daemon auto-authentication (#187, found
//! during the F-INT-1 live FreeRADIUS interop run #170).
//!
//! The live FreeRADIUS interop run (F-INT-1) exposed that the daemon
//! binary never set the Supplicant PAE `authenticate` variable
//! (Cl.8.4 PAE client interface) — the PAE idled in Disconnected
//! forever, so no EAPOL-Start was ever transmitted and the live
//! handshake could not begin. Integration tests masked this by
//! calling the `pae_set_authenticate` test shim manually.
//!
//! A supplicant daemon's whole purpose is to authenticate the port
//! (StR-003 / StR-010), so `Supplicant::new` must auto-start
//! authentication: with the link up at construction the PAE enters
//! Connecting and EAPOL-Start (Cl.8.3) is on the wire with no
//! external control command.
//!
//! Verifies: #187 (relates to #170 / F-INT-1) — REQ-F-PAE-001 (#11),
//! REQ-F-PAE-005 (#15). Per IEEE 802.1X-2020 Cl.8.3 / Cl.8.4.

use std::sync::{Arc, Mutex};

use anyhow::Result;
use eapol_supp::frame::{EapolFrame, EapolPacketType, EapolVersion};
use eapol_supp::PaeState;
use wpa_supplicant::{Config, NetworkIo, Supplicant};

/// Local `NetworkIo` double — mirrors the production `MockNetworkIo`
/// but is reachable from integration tests (the workspace mock is
/// `#[cfg(test)]`-gated and not exported).
struct TestNet {
    mac: [u8; 6],
    link: Mutex<bool>,
    sent: Mutex<Vec<(Vec<u8>, Vec<u8>)>>,
    inbox: Mutex<Vec<Vec<u8>>>,
}

impl TestNet {
    fn new(link_up: bool) -> Self {
        Self {
            mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            link: Mutex::new(link_up),
            sent: Mutex::new(Vec::new()),
            inbox: Mutex::new(Vec::new()),
        }
    }

    fn sent_frames(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        self.sent.lock().unwrap().clone()
    }

    fn enqueue(&self, frame: Vec<u8>) {
        self.inbox.lock().unwrap().push(frame);
    }

    fn set_link(&self, up: bool) {
        *self.link.lock().unwrap() = up;
    }
}

impl NetworkIo for TestNet {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        self.sent
            .lock()
            .unwrap()
            .push((dest.to_vec(), frame.to_vec()));
        Ok(())
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        Ok(self.inbox.lock().unwrap().pop())
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    fn link_up(&self) -> bool {
        *self.link.lock().unwrap()
    }
}

fn make_config() -> Config {
    Config::from_toml(
        r#"
interface = "eth0"

[eap]
identity = "alice@example.com"

[eap.method]
type = "tls"
cert = "/etc/certs/client.pem"
key = "/etc/certs/client.key"
ca = "/etc/certs/ca.pem"
"#,
    )
    .unwrap()
}

/// Verifies: #187 (relates to #170 / F-INT-1) — REQ-F-PAE-001 / REQ-F-PAE-005
/// Per Cl.8.4: the PAE client (Logon Process role) sets `authenticate`;
/// the daemon plays that role, so construction must set it. With the
/// link up at boot the PAE is in Connecting straight after
/// construction — before any tick — so the auto-start is provable
/// without the tick loop's normal Disconnected→Connecting advance.
#[test]
fn supplicant_auto_starts_authentication_on_boot() {
    let net = TestNet::new(true);
    let mut supp = Supplicant::with_eap_methods(make_config(), net, Vec::new()).unwrap();

    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "construction must auto-enter Connecting when the link is up at boot"
    );

    // The state must hold through a quiet tick (no re-advance).
    supp.tick().unwrap();
    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "a quiet tick must hold the boot-time Connecting state"
    );
}

/// Verifies: #187 (relates to #170 / F-INT-1) — REQ-F-PAE-005
/// The boot-time auto-start must actually put an EAPOL-Start frame on
/// the wire. Drives the full Cl.8.3 path: EAPOL-Start (1) then an
/// EAP-Request/Identity reply advances Connecting → Authenticating,
/// proving the daemon-initiated conversation is a real exchange.
#[test]
fn supplicant_boot_transmits_eapol_start_and_advances_on_identity_request() {
    let net = Arc::new(TestNet::new(true));
    let mut supp = Supplicant::with_eap_methods(
        make_config(),
        NetHandle {
            inner: Arc::clone(&net),
        },
        Vec::new(),
    )
    .unwrap();

    supp.tick().unwrap();
    assert_eq!(supp.pae_state(), PaeState::Connecting);
    let frames = net.sent_frames();
    assert!(
        frames.iter().any(|(_, f)| {
            matches!(EapolFrame::decode(f), Ok(frame) if frame.packet_type == EapolPacketType::EapolStart)
        }),
        "an EAPOL-Start frame must be transmitted at boot, got {} frame(s)",
        frames.len()
    );

    // Feed an EAP-Request/Identity (code=1, id=0, type=1) — the PAE
    // must advance Connecting → Authenticating per Cl.8.3.
    net.enqueue(
        EapolFrame {
            version: EapolVersion::V3,
            packet_type: EapolPacketType::EapPacket,
            body: vec![0x01, 0x00, 0x00, 0x05, 0x01],
        }
        .encode()
        .unwrap(),
    );
    supp.tick().unwrap();
    assert_eq!(
        supp.pae_state(),
        PaeState::Authenticating,
        "EAP-Request/Identity must advance Connecting → Authenticating"
    );
}

/// Verifies: #187 (relates to #170 / F-INT-1) — REQ-NF-REL-003 interplay
/// Auto-start honors the link state: booting with the link DOWN must
/// keep the PAE in Disconnected, and a later link-up must start the
/// conversation (EAPOL-Start on link-up per INT-004 / #112).
#[test]
fn supplicant_auto_start_waits_for_link() {
    let net = Arc::new(TestNet::new(false));
    let mut supp = Supplicant::with_eap_methods(
        make_config(),
        NetHandle {
            inner: Arc::clone(&net),
        },
        Vec::new(),
    )
    .unwrap();

    supp.tick().unwrap();
    assert_eq!(
        supp.pae_state(),
        PaeState::Disconnected,
        "no EAPOL-Start while the link is down"
    );
    assert!(
        net.sent_frames().is_empty(),
        "nothing on the wire while the link is down"
    );

    net.set_link(true);
    supp.tick().unwrap();
    assert_eq!(
        supp.pae_state(),
        PaeState::Connecting,
        "link-up must start authentication without a control command"
    );
}

/// Thin wrapper so the `Supplicant` owns a `NetworkIo` while the test
/// keeps shared access to the recorded frames.
struct NetHandle {
    inner: Arc<TestNet>,
}

impl NetworkIo for NetHandle {
    fn send_eapol(&self, dest: [u8; 6], frame: &[u8]) -> Result<()> {
        self.inner.send_eapol(dest, frame)
    }

    fn recv_eapol(&self) -> Result<Option<Vec<u8>>> {
        self.inner.recv_eapol()
    }

    fn mac_address(&self) -> [u8; 6] {
        self.inner.mac_address()
    }

    fn link_up(&self) -> bool {
        self.inner.link_up()
    }
}
