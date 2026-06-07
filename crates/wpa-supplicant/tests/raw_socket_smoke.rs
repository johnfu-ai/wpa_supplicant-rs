//! Smoke test for `RawSocketNetworkIo` — Phase 07 prerequisite (#128).
//!
//! These tests bind a real `AF_PACKET / SOCK_RAW` socket to the loopback
//! interface and exercise the EAPOL send / recv paths against it. They
//! require:
//!
//! * `CAP_NET_RAW` (root or equivalent capability).
//! * A real loopback interface present (`lo`).
//!
//! Both prerequisites are unavailable in the default CI sandbox, so every
//! case is `#[ignore]`-gated. Run locally with:
//!
//! ```sh
//! sudo -E cargo test -p wpa-supplicant --features raw-socket \
//!     --test raw_socket_smoke -- --ignored
//! ```
//!
//! Verifies: #128
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020.
//! No copyrighted content from the standard is reproduced.

#![cfg(feature = "raw-socket")]

use wpa_supplicant::{NetworkIo, RawSocketNetworkIo};

/// Verifies: #128
/// `RawSocketNetworkIo::bind` succeeds on the loopback interface when
/// the process has `CAP_NET_RAW`. Probes the MAC and the link state.
#[test]
#[ignore = "requires CAP_NET_RAW; run with `sudo -E cargo test -- --ignored`"]
fn raw_socket_binds_to_loopback() {
    let io = RawSocketNetworkIo::bind("lo").expect("bind lo");
    // Loopback MAC is all-zeros on Linux; we only assert the call returns.
    let _mac = io.mac_address();
    // `lo` is always up on a running host.
    assert!(io.link_up(), "lo should be up");
}

/// Verifies: #128
/// A frame sent via `send_eapol` reaches the kernel without error. The
/// loopback interface drops EAPOL (EtherType 0x888E) silently because no
/// peer is listening, so we do not require a round-trip — only that the
/// `sendto(2)` syscall succeeds.
#[test]
#[ignore = "requires CAP_NET_RAW; run with `sudo -E cargo test -- --ignored`"]
fn raw_socket_sends_one_eapol_frame() {
    let io = RawSocketNetworkIo::bind("lo").expect("bind lo");
    // 14-byte L2 header is prepended by the implementation; the caller
    // passes just the EAPOL payload starting at the version octet.
    let eapol_payload: [u8; 4] = [
        0x03, // version 3 (IEEE 802.1X-2020 §11.3.1)
        0x01, // packet type: EAPOL-Start
        0x00, 0x00, // body length 0
    ];
    io.send_eapol([0xFF; 6], &eapol_payload)
        .expect("send_eapol on lo");
}

/// Verifies: #128
/// A freshly-bound socket has nothing queued — `recv_eapol` returns
/// `Ok(None)` rather than blocking or erroring on `EAGAIN`.
#[test]
#[ignore = "requires CAP_NET_RAW; run with `sudo -E cargo test -- --ignored`"]
fn raw_socket_recv_returns_none_when_empty() {
    let io = RawSocketNetworkIo::bind("lo").expect("bind lo");
    let frame = io.recv_eapol().expect("recv_eapol must not error on empty");
    assert!(
        frame.is_none(),
        "no frame should be queued on a fresh socket"
    );
}
