//! FreeRADIUS-in-Docker interop harness driver, callable from `cargo test`.
//!
//! Implements: `docs/TODO.md` P3.1. Covers REQ-F-EAP-002 / REQ-F-EAP-003 /
//! REQ-F-EAP-004 once the EAP method factory (#133) and AES Key Wrap
//! (#135) follow-ups land. Today this test asserts the harness
//! infrastructure (docker-compose, certs, veth setup, binary boot)
//! works end-to-end; the *full* EAP-TLS / PEAP / TEAP handshake
//! assertion is deferred behind a `// TODO(#133)` marker.
//!
//! Verifies: `docs/TODO.md` P3.1 (harness today); REQ-F-EAP-002 /
//! REQ-F-EAP-003 / REQ-F-EAP-004 once #133 + #135 land.
//!
//! ## Why `#[ignore]`
//!
//! The harness needs:
//! * Docker daemon running (`docker compose up`).
//! * `sudo` for `CAP_NET_RAW` (AF_PACKET socket) and `iproute2` (veth
//!   pair + network namespace).
//! * `openssl` in `PATH` for throwaway cert generation.
//! * The supplicant binary built with `--features raw-socket --release`.
//!
//! None of these are available in the default `cargo test --workspace`
//! sandbox, so every case here is `#[ignore]`. Run explicitly with:
//!
//! ```sh
//! cargo build -p wpa-supplicant --features raw-socket --release
//! cd 07-verification-validation/interop && ./scripts/gen-certs.sh
//! sudo -E cargo test -p wpa-supplicant --features raw-socket \
//!     --test interop_freeradius -- --ignored --nocapture
//! ```
//!
//! Or via the dedicated CI workflow at `.github/workflows/interop.yml`.
//!
//! IMPORTANT: This implementation is based on understanding of IEEE
//! 802.1X-2020 and RFC 3748. No copyrighted content from those
//! documents is reproduced.

#![cfg(feature = "raw-socket")]

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

fn interop_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("07-verification-validation")
        .join("interop")
        .canonicalize()
        .expect("interop/ directory must exist next to crates/")
}

fn run_script(script: &str, args: &[&str]) -> std::process::ExitStatus {
    // Test harness only — panic on script-execution failure is acceptable
    // because this whole file is `#[ignore]`-gated.
    let path = interop_dir().join("scripts").join(script);
    eprintln!("[interop] running {}", path.display());
    Command::new(&path)
        .args(args)
        .status()
        .unwrap_or_else(|e| panic!("failed to execute {}: {e}", path.display()))
}

fn docker_compose(args: &[&str]) -> std::process::ExitStatus {
    // Test harness only — see `run_script` for the panic rationale.
    let dir = interop_dir();
    eprintln!(
        "[interop] docker compose {} (cwd={})",
        args.join(" "),
        dir.display()
    );
    Command::new("docker")
        .arg("compose")
        .args(args)
        .current_dir(&dir)
        .status()
        .unwrap_or_else(|e| panic!("docker compose failed: {e}"))
}

/// Verifies: `docs/TODO.md` P3.1
///
/// Smoke-tests the full P3.1 harness end-to-end:
/// 1. Generate the throwaway cert chain.
/// 2. Bring up the Docker stack (FreeRADIUS + hostapd).
/// 3. Run the supplicant binary inside a netns connected via veth
///    to hostapd's bridge.
/// 4. Confirm the binary entered the event loop and survived the
///    initial EAP-Request/Identity exchange.
/// 5. Tear down.
///
/// Once #133 lands (real EAP method factory from `EapMethodConfig`),
/// this test grows assertions on the full EAP-TLS handshake. Once
/// #135 lands (AES Key Wrap), it grows assertions on the SAK install
/// path. Until then it pins the *infrastructure* contract — the
/// stack composes, the certs validate, the veth wiring works, and
/// the binary reaches `event loop started`.
#[test]
#[ignore = "requires Docker + sudo + openssl; run via `sudo -E cargo test \
            -p wpa-supplicant --features raw-socket --test interop_freeradius \
            -- --ignored`"]
fn interop_freeradius_smoke() {
    // Pre-flight: bail early with a clear message if Docker is not
    // available rather than blowing up halfway through.
    let docker_ok = Command::new("docker")
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    assert!(
        docker_ok,
        "docker is not running or not reachable — start dockerd and re-run"
    );

    // Idempotent cert generation.
    assert!(
        run_script("gen-certs.sh", &[]).success(),
        "scripts/gen-certs.sh must succeed"
    );

    // Install the teardown guard **before** we touch docker so a
    // failed `up -d` still cleans the network namespace + veth pair
    // and any partially-started containers.
    let _guard = TeardownGuard;

    // Bring up FreeRADIUS + hostapd. `up -d` returns once the stack
    // is started; we then poll for healthy.
    assert!(
        docker_compose(&["up", "-d"]).success(),
        "docker compose up -d must succeed"
    );

    // Give FreeRADIUS up to 30 s to pass its healthcheck.
    let mut healthy = false;
    for _ in 0..30 {
        let out = Command::new("docker")
            .args([
                "inspect",
                "-f",
                "{{.State.Health.Status}}",
                "wpa-sup-freeradius",
            ])
            .output()
            .expect("docker inspect must run");
        if String::from_utf8_lossy(&out.stdout).trim() == "healthy" {
            healthy = true;
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }

    assert!(healthy, "FreeRADIUS must become healthy within 30 s");

    // Run the supplicant binary against the harness.
    let supp_status = run_script("run-supplicant.sh", &[]);
    assert!(
        supp_status.success(),
        "scripts/run-supplicant.sh exited with {:?} — see /tmp/wpa-sup-interop.log",
        supp_status.code()
    );

    // TODO(#133): once the EAP method factory lands, parse the
    // supplicant log for an EAP-Success event and assert PAE reached
    // Authenticated against the real RADIUS server.
    //
    // TODO(#135): once AES Key Wrap lands in `MkaParticipantAdapter::unwrap_sak`,
    // assert that hostapd's MKA install (if hostapd ever gains it for
    // wired mode) drives CP -> Secured.
}

/// RAII guard that always tears down the harness on test exit,
/// success or failure. Prevents container / veth leaks across runs.
struct TeardownGuard;

impl Drop for TeardownGuard {
    fn drop(&mut self) {
        let _ = run_script("teardown.sh", &[]);
    }
}
