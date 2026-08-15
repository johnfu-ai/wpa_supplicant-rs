#![no_main]

//! Fuzz target: `EapolFrame::decode` (REQ-NF-REL-001/002, #143 / TEST-VV-005).
//!
//! The EAPOL frame parser ingests adversary-controlled bytes received
//! on the Uncontrolled Port. The only assertion is "no panic":
//! malformed input must surface as `Err(EapolError)`, never as a panic
//! (per IEEE 802.1X-2020 Clause 8 frame-format robustness).

use eapol_supp::EapolFrame;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = EapolFrame::decode(data);
});
