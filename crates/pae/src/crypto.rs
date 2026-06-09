//! AES crypto primitives for MKA.
//!
//! Groups all AES-based crypto operations behind the `std` feature:
//! - AES-CMAC ICV computation and verification (IEEE 802.1X-2020 Cl.9.7)
//! - AES Key Wrap / Unwrap per RFC 3394 (IEEE 802.1X-2020 Cl.9.8)
//!
//! Implements: #20 (REQ-F-MKA-002: MKA Transport), #24 (REQ-F-MKA-006: SAK Reception)
//! Architecture: #74 (ADR-SM-002), #76 (ADR-SEC-004), #80 (ADR-KDF-008)
//!
//! IMPORTANT: This implementation is based on understanding of IEEE 802.1X-2020
//! and RFC 3394. No copyrighted content is reproduced.

use aes::cipher::{
    generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit as CipherKeyInit,
};
use cmac::{Cmac, Mac};
use digest::KeyInit;
use zeroize::Zeroize;

use crate::mka::Ick;

// ---------------------------------------------------------------------------
// AES-CMAC ICV — moved from mka.rs
// ---------------------------------------------------------------------------

/// Compute ICV for MKPDU content using AES-CMAC-128 with the ICK.
///
/// Per IEEE 802.1X-2020, Clause 9.7: the ICV is computed over all
/// parameter sets in the MKPDU except the ICV parameter set itself.
///
/// Implements: #20 (REQ-F-MKA-002: MKA Transport)
///
/// Only available with the `std` feature (requires AES-CMAC crypto crates).
///
/// # Errors
/// Returns `PaeError::CryptoError` if CMAC computation fails.
pub fn compute_icv(payload: &[u8], ick: &Ick) -> Result<[u8; 16], crate::PaeError> {
    match ick.len() {
        16 => {
            let mut cmac =
                <Cmac<aes::Aes128> as KeyInit>::new_from_slice(ick.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-128-CMAC key init failed: {}", e))
                })?;
            cmac.update(payload);
            let result = cmac.finalize().into_bytes();
            let mut icv = [0u8; 16];
            icv.copy_from_slice(&result);
            Ok(icv)
        }
        32 => {
            let mut cmac =
                <Cmac<aes::Aes256> as KeyInit>::new_from_slice(ick.as_bytes()).map_err(|e| {
                    crate::PaeError::CryptoError(format!("AES-256-CMAC key init failed: {}", e))
                })?;
            cmac.update(payload);
            let result = cmac.finalize().into_bytes();
            let mut icv = [0u8; 16];
            icv.copy_from_slice(&result);
            Ok(icv)
        }
        _ => Err(crate::PaeError::CryptoError(format!(
            "unsupported ICK length: {}",
            ick.len()
        ))),
    }
}

/// Verify ICV using constant-time comparison.
///
/// Per IEEE 802.1X-2020, Clause 9.7.
/// Implements: #20 (REQ-F-MKA-002: MKA Transport)
///
/// Only available with the `std` feature (requires AES-CMAC crypto crates).
///
/// # Errors
/// Returns `PaeError::IcvFailed` if the ICV does not match.
pub fn verify_icv(
    payload: &[u8],
    expected_icv: &[u8; 16],
    ick: &Ick,
) -> Result<(), crate::PaeError> {
    let computed = compute_icv(payload, ick)?;
    // Constant-time comparison to prevent timing attacks
    let mut diff = 0u8;
    for (a, b) in computed.iter().zip(expected_icv.iter()) {
        diff |= a ^ b;
    }
    if diff == 0 {
        Ok(())
    } else {
        Err(crate::PaeError::IcvFailed)
    }
}

// ---------------------------------------------------------------------------
// AES Key Wrap / Unwrap — RFC 3394
// ---------------------------------------------------------------------------

/// Default IV per RFC 3394 Section 2.2.1.
const KEY_WRAP_IV: [u8; 8] = [0xA6; 8];

/// Execute the 6-round wrap loop per RFC 3394 §2.2.1.
#[allow(clippy::needless_range_loop)]
fn wrap_rounds<C: BlockEncrypt>(a: &mut [u8; 8], r: &mut [[u8; 8]], n: usize, cipher: &C) {
    for j in 0..6u64 {
        for i in 0..n {
            let t = ((n as u64) * j) + ((i as u64) + 1);

            // Build 16-byte block: A || R[i]
            let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
            block[..8].copy_from_slice(a);
            block[8..].copy_from_slice(&r[i]);

            cipher.encrypt_block(&mut block);

            // A = MSB_64(B) XOR t
            let mut msb = [0u8; 8];
            msb.copy_from_slice(&block[..8]);
            xor_be64(&mut msb, t);
            a.copy_from_slice(&msb);

            // R[i] = LSB_64(B)
            r[i].copy_from_slice(&block[8..]);

            // Zeroize intermediate block per ADR-SEC-004 (#76).
            block.iter_mut().for_each(|b| *b = 0);
        }
    }
}

/// Execute the 6-round unwrap loop per RFC 3394 §2.2.2.
fn unwrap_rounds<C: BlockDecrypt>(a: &mut [u8; 8], r: &mut [[u8; 8]], n: usize, cipher: &C) {
    for j in (0..6u64).rev() {
        for i in (0..n).rev() {
            let t = ((n as u64) * j) + ((i as u64) + 1);

            // A = A XOR t
            xor_be64(a, t);

            // Build 16-byte block: A || R[i]
            let mut block = GenericArray::clone_from_slice(&[0u8; 16]);
            block[..8].copy_from_slice(a);
            block[8..].copy_from_slice(&r[i]);

            cipher.decrypt_block(&mut block);

            // A = MSB_64(B)
            a.copy_from_slice(&block[..8]);

            // R[i] = LSB_64(B)
            r[i].copy_from_slice(&block[8..]);

            // Zeroize intermediate block per ADR-SEC-004 (#76).
            block.iter_mut().for_each(|b| *b = 0);
        }
    }
}

/// XOR an 8-byte big-endian value with a u64 counter.
fn xor_be64(val: &mut [u8; 8], t: u64) {
    let t_bytes = t.to_be_bytes();
    for i in 0..8 {
        val[i] ^= t_bytes[i];
    }
}

/// AES Key Wrap per RFC 3394 Section 2.2.1.
///
/// Wraps `plaintext` (must be a multiple of 8 bytes, at least 16 bytes)
/// using the given `kek` (16 or 32 bytes). Returns the ciphertext with
/// the 8-byte IV prefix; total length = `plaintext.len()` + 8.
///
/// Per IEEE 802.1X-2020 Cl.9.8: used by the Key Server to wrap the SAK
/// for distribution in a Distribute SAK parameter set (Cl.11.11).
///
/// Implements: #24 (REQ-F-MKA-006: SAK Reception/Installation)
///
/// # Errors
/// Returns `PaeError::CryptoError` if:
/// - `plaintext` is fewer than 16 bytes or not a multiple of 8
/// - `kek` is not 16 or 32 bytes
/// - AES cipher initialization fails
pub fn aes_key_wrap(plaintext: &[u8], kek: &[u8]) -> Result<Vec<u8>, crate::PaeError> {
    // Input validation per RFC 3394 Section 2.2.1.
    if plaintext.len() < 16 {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Wrap: plaintext must be at least 16 bytes, got {}",
            plaintext.len()
        )));
    }
    if plaintext.len() % 8 != 0 {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Wrap: plaintext must be a multiple of 8 bytes, got {}",
            plaintext.len()
        )));
    }
    if !matches!(kek.len(), 16 | 32) {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Wrap: KEK must be 16 or 32 bytes, got {}",
            kek.len()
        )));
    }

    // n = number of 8-byte semi-blocks in the plaintext.
    let n = plaintext.len() / 8;

    // Working set: A (8-byte integrity check) + R[1..n] (semi-blocks).
    let mut a = KEY_WRAP_IV;
    let mut r: Vec<[u8; 8]> = plaintext
        .chunks_exact(8)
        .map(|chunk| {
            let mut semi = [0u8; 8];
            semi.copy_from_slice(chunk);
            semi
        })
        .collect();

    // RFC 3394 §2.2.1: 6 rounds, n iterations each.
    match kek.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(kek).map_err(|e| {
                crate::PaeError::CryptoError(format!("AES-128 Key Wrap init failed: {}", e))
            })?;
            wrap_rounds(&mut a, &mut r, n, &cipher);
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(kek).map_err(|e| {
                crate::PaeError::CryptoError(format!("AES-256 Key Wrap init failed: {}", e))
            })?;
            wrap_rounds(&mut a, &mut r, n, &cipher);
        }
        _ => unreachable!("validated above"),
    }

    // Output: C[0] = A, C[1..n] = R[1..n].
    let mut out = Vec::with_capacity(8 + n * 8);
    out.extend_from_slice(&a);
    for semi in &r {
        out.extend_from_slice(semi);
    }

    // Zeroize intermediate state per ADR-SEC-004 (#76).
    a.zeroize();
    for semi in &mut r {
        semi.zeroize();
    }

    Ok(out)
}

/// AES Key Unwrap per RFC 3394 Section 2.2.2.
///
/// Unwraps `ciphertext` (must be a multiple of 8 bytes, at least 24 bytes)
/// using the given `kek` (16 or 32 bytes). Verifies the IV matches the
/// default value `0xA6A6A6A6A6A6A6A6`. Returns the plaintext without
/// the 8-byte IV prefix.
///
/// Per IEEE 802.1X-2020 Cl.9.8: used by the Supplicant to unwrap the SAK
/// from a received Distribute SAK parameter set (Cl.11.11).
///
/// Implements: #24 (REQ-F-MKA-006: SAK Reception/Installation)
///
/// # Errors
/// Returns `PaeError::CryptoError` if:
/// - `ciphertext` is fewer than 24 bytes or not a multiple of 8
/// - `kek` is not 16 or 32 bytes
/// - AES cipher initialization fails
/// - The IV check fails (wrong KEK or corrupted data)
pub fn aes_key_unwrap(ciphertext: &[u8], kek: &[u8]) -> Result<Vec<u8>, crate::PaeError> {
    // Input validation per RFC 3394 Section 2.2.2.
    if ciphertext.len() < 24 {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Unwrap: ciphertext must be at least 24 bytes, got {}",
            ciphertext.len()
        )));
    }
    if ciphertext.len() % 8 != 0 {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Unwrap: ciphertext must be a multiple of 8 bytes, got {}",
            ciphertext.len()
        )));
    }
    if !matches!(kek.len(), 16 | 32) {
        return Err(crate::PaeError::CryptoError(format!(
            "AES Key Unwrap: KEK must be 16 or 32 bytes, got {}",
            kek.len()
        )));
    }

    // n = number of 8-byte semi-blocks in the plaintext (one fewer than ciphertext).
    let n = (ciphertext.len() / 8) - 1;

    // A = C[0] (first 8 bytes), R[1..n] = C[1..n].
    let mut a: [u8; 8] = [0u8; 8];
    a.copy_from_slice(&ciphertext[..8]);
    let mut r: Vec<[u8; 8]> = ciphertext[8..]
        .chunks_exact(8)
        .map(|chunk| {
            let mut semi = [0u8; 8];
            semi.copy_from_slice(chunk);
            semi
        })
        .collect();

    // RFC 3394 §2.2.2: 6 rounds, reverse iteration.
    match kek.len() {
        16 => {
            let cipher = aes::Aes128::new_from_slice(kek).map_err(|e| {
                crate::PaeError::CryptoError(format!("AES-128 Key Unwrap init failed: {}", e))
            })?;
            unwrap_rounds(&mut a, &mut r, n, &cipher);
        }
        32 => {
            let cipher = aes::Aes256::new_from_slice(kek).map_err(|e| {
                crate::PaeError::CryptoError(format!("AES-256 Key Unwrap init failed: {}", e))
            })?;
            unwrap_rounds(&mut a, &mut r, n, &cipher);
        }
        _ => unreachable!("validated above"),
    }

    // IV check: A must equal the default IV.
    if a != KEY_WRAP_IV {
        // Zeroize before returning error per ADR-SEC-004 (#76).
        a.zeroize();
        for semi in &mut r {
            semi.zeroize();
        }
        return Err(crate::PaeError::CryptoError(
            "AES Key Unwrap: IV check failed — wrong KEK or corrupted data".into(),
        ));
    }

    // Output: P[1..n] = R[1..n].
    let mut out = Vec::with_capacity(n * 8);
    for semi in &r {
        out.extend_from_slice(semi);
    }

    // Zeroize intermediate state per ADR-SEC-004 (#76).
    a.zeroize();
    for semi in &mut r {
        semi.zeroize();
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // RFC 3394 test vectors
    // -----------------------------------------------------------------------

    /// RFC 3394 §4.1 — 128-bit KEK wrapping 128-bit key data.
    #[test]
    fn test_rfc3394_wrap_128_kek_128_key() {
        let kek: Vec<u8> = (0x00..=0x0F).collect();
        let key_data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = vec![
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        assert_eq!(wrapped, expected, "wrapped output must match RFC 3394 §4.1");
    }

    /// RFC 3394 §4.1 — unwrap the 128-bit KEK / 128-bit key data vector.
    #[test]
    fn test_rfc3394_unwrap_128_kek_128_key() {
        let kek: Vec<u8> = (0x00..=0x0F).collect();
        let ciphertext = vec![
            0x1F, 0xA6, 0x8B, 0x0A, 0x81, 0x12, 0xB4, 0x47, 0xAE, 0xF3, 0x4B, 0xD8, 0xFB, 0x5A,
            0x7B, 0x82, 0x9D, 0x3E, 0x86, 0x23, 0x71, 0xD2, 0xCF, 0xE5,
        ];
        let expected = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];

        let unwrapped = aes_key_unwrap(&ciphertext, &kek).expect("unwrap should succeed");
        assert_eq!(
            unwrapped, expected,
            "unwrapped output must match RFC 3394 §4.1"
        );
    }

    /// RFC 3394 §4.3 — 256-bit KEK wrapping 128-bit key data.
    #[test]
    fn test_rfc3394_wrap_256_kek_128_key() {
        let kek: Vec<u8> = (0x00..=0x1F).collect();
        let key_data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF,
        ];
        let expected = vec![
            0x64, 0xE8, 0xC3, 0xF9, 0xCE, 0x0F, 0x5B, 0xA2, 0x63, 0xE9, 0x77, 0x79, 0x05, 0x81,
            0x8A, 0x2A, 0x93, 0xC8, 0x19, 0x1E, 0x7D, 0x6E, 0x8A, 0xE7,
        ];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        assert_eq!(wrapped, expected, "wrapped output must match RFC 3394 §4.3");
    }

    /// RFC 3394 §4.6 — 256-bit KEK wrapping 256-bit key data.
    #[test]
    fn test_rfc3394_wrap_256_kek_256_key() {
        let kek: Vec<u8> = (0x00..=0x1F).collect();
        let key_data = vec![
            0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD,
            0xEE, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
            0x0C, 0x0D, 0x0E, 0x0F,
        ];
        let expected = vec![
            0x28, 0xC9, 0xF4, 0x04, 0xC4, 0xB8, 0x10, 0xF4, 0xCB, 0xCC, 0xB3, 0x5C, 0xFB, 0x87,
            0xF8, 0x26, 0x3F, 0x57, 0x86, 0xE2, 0xD8, 0x0E, 0xD3, 0x26, 0xCB, 0xC7, 0xF0, 0xE7,
            0x1A, 0x99, 0xF4, 0x3B, 0xFB, 0x98, 0x8B, 0x9B, 0x7A, 0x02, 0xDD, 0x21,
        ];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        assert_eq!(wrapped, expected, "wrapped output must match RFC 3394 §4.6");
    }

    // -----------------------------------------------------------------------
    // Round-trip tests
    // -----------------------------------------------------------------------

    /// Round-trip: AES-128 KEK wrapping/unwrapping a 16-byte key (SAK-128).
    #[test]
    fn test_roundtrip_128_kek_16_byte_sak() {
        let kek = [0xAB_u8; 16];
        let key_data = [0xCD_u8; 16];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        assert_eq!(wrapped.len(), 24, "wrapped output = 16 + 8 bytes");

        let unwrapped = aes_key_unwrap(&wrapped, &kek).expect("unwrap should succeed");
        assert_eq!(unwrapped, key_data, "round-trip must recover original key");
    }

    /// Round-trip: AES-256 KEK wrapping/unwrapping a 32-byte key (SAK-256).
    #[test]
    fn test_roundtrip_256_kek_32_byte_sak() {
        let kek = [0xAB_u8; 32];
        let key_data = [0xCD_u8; 32];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        assert_eq!(wrapped.len(), 40, "wrapped output = 32 + 8 bytes");

        let unwrapped = aes_key_unwrap(&wrapped, &kek).expect("unwrap should succeed");
        assert_eq!(unwrapped, key_data, "round-trip must recover original key");
    }

    /// Round-trip: AES-256 KEK wrapping/unwrapping a 16-byte key.
    #[test]
    fn test_roundtrip_256_kek_16_byte_sak() {
        let kek = [0x37_u8; 32];
        let key_data = [0x55_u8; 16];

        let wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        let unwrapped = aes_key_unwrap(&wrapped, &kek).expect("unwrap should succeed");
        assert_eq!(unwrapped, key_data, "round-trip must recover original key");
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    /// Unwrap with wrong KEK fails IV check.
    #[test]
    fn test_unwrap_wrong_kek_fails() {
        let kek1 = [0x00_u8; 16];
        let kek2 = [0xFF_u8; 16];
        let key_data = [0xAB_u8; 16];

        let wrapped = aes_key_wrap(&key_data, &kek1).expect("wrap should succeed");
        let result = aes_key_unwrap(&wrapped, &kek2);
        assert!(result.is_err(), "unwrap with wrong KEK must fail");
        let err = result.unwrap_err();
        match err {
            crate::PaeError::CryptoError(msg) => {
                assert!(
                    msg.contains("IV check failed"),
                    "expected IV check failure, got: {msg}"
                );
            }
            other => panic!("expected CryptoError, got: {other}"),
        }
    }

    /// Unwrap corrupted ciphertext fails IV check.
    #[test]
    fn test_unwrap_corrupted_ciphertext_fails() {
        let kek = [0x00_u8; 16];
        let key_data = [0xAB_u8; 16];

        let mut wrapped = aes_key_wrap(&key_data, &kek).expect("wrap should succeed");
        // Flip a bit in the ciphertext body
        wrapped[12] ^= 0x01;
        let result = aes_key_unwrap(&wrapped, &kek);
        assert!(
            result.is_err(),
            "unwrap with corrupted ciphertext must fail"
        );
    }

    /// Wrap: plaintext too short (< 16 bytes).
    #[test]
    fn test_wrap_plaintext_too_short() {
        let kek = [0x00_u8; 16];
        let plaintext = [0xAB_u8; 8];
        let result = aes_key_wrap(&plaintext, &kek);
        assert!(result.is_err(), "wrap with < 16-byte plaintext must fail");
    }

    /// Wrap: plaintext not a multiple of 8.
    #[test]
    fn test_wrap_plaintext_not_multiple_of_8() {
        let kek = [0x00_u8; 16];
        let plaintext = [0xAB_u8; 17];
        let result = aes_key_wrap(&plaintext, &kek);
        assert!(
            result.is_err(),
            "wrap with non-multiple-of-8 plaintext must fail"
        );
    }

    /// Unwrap: ciphertext too short (< 24 bytes).
    #[test]
    fn test_unwrap_ciphertext_too_short() {
        let kek = [0x00_u8; 16];
        let ciphertext = [0xAB_u8; 16];
        let result = aes_key_unwrap(&ciphertext, &kek);
        assert!(
            result.is_err(),
            "unwrap with < 24-byte ciphertext must fail"
        );
    }

    /// Unwrap: ciphertext not a multiple of 8.
    #[test]
    fn test_unwrap_ciphertext_not_multiple_of_8() {
        let kek = [0x00_u8; 16];
        let ciphertext = [0xAB_u8; 25];
        let result = aes_key_unwrap(&ciphertext, &kek);
        assert!(
            result.is_err(),
            "unwrap with non-multiple-of-8 ciphertext must fail"
        );
    }

    /// KEK wrong length (24 bytes — not 16 or 32).
    #[test]
    fn test_kek_wrong_length() {
        let kek = [0x00_u8; 24];
        let key_data = [0xAB_u8; 16];
        let result = aes_key_wrap(&key_data, &kek);
        assert!(result.is_err(), "wrap with 24-byte KEK must fail");

        let ciphertext = [0xAB_u8; 24];
        let result2 = aes_key_unwrap(&ciphertext, &kek);
        assert!(result2.is_err(), "unwrap with 24-byte KEK must fail");
    }
}
