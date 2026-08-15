#![no_main]

//! Fuzz target: `EapPacket::decode` (REQ-NF-REL-001/002, #143 / TEST-VV-005).
//!
//! The EAP packet parser ingests adversary-controlled bytes relayed by
//! the Authenticator. The only assertion is "no panic": malformed input
//! must surface as `Err(EapError)`, never as a panic (per the RFC 3748
//! §4 message-format constraints).

use eap_peer::peer::EapPacket;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EapPacket::decode(data);
});
