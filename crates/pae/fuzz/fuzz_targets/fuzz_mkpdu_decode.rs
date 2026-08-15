#![no_main]

//! Fuzz target: `Mkpdu::decode` (REQ-NF-REL-001/002, #143 / TEST-VV-005).
//!
//! The MKPDU parser ingests adversary-controlled bytes (any peer on the
//! LAN can send MKPDUs). The only assertion is "no panic": malformed
//! input must surface as `Err(PaeError)`, never as a panic (per IEEE
//! 802.1X-2020 Clause 11.11 MKPDU validation/decoding robustness).

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = pae::Mkpdu::decode(data);
});
