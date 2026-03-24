//! ZIP32 key derivation via the Ledger Secure SDK `sys_hdkey_derive` syscall.
//!
//! Only ZIP32 Orchard mode (Pallas curve) is exposed here.
//!
//! # Errors
//! The raw syscall returns a `bolos_err_t` (u32).  Common error codes:
//! * `0x0000` – success
//! * `0x550B` – PIN not validated
//! * `0x4215` – forbidden derivation (app manifest lacks `HDKEY_DERIVE_AUTH_ZIP32`)
//! * `0x3308` – cryptographic computation failure

use crate::ec::CxErr;

// ---------------------------------------------------------------------------
// Constants – derivation mode and curve
// ---------------------------------------------------------------------------

/// ZIP32 Orchard hardened derivation mode.
const HDKEY_DERIVE_MODE_ZIP32_ORCHARD: u32 = 0x20;

/// Pallas curve identifier (reused from `crate::ec`).
const CX_CURVE_PALLAS: u32 = crate::ec::CX_CURVE_PALLAS;

/// Byte length of an Orchard spending key (sk) and chain code.
pub const ZIP32_SK_SIZE: usize = 32;
pub const ZIP32_CHAIN_CODE_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// Raw FFI declaration
// ---------------------------------------------------------------------------

unsafe extern "C" {
    /// Derives a private key and an optional chain code using the specified
    /// derivation mode and curve.
    ///
    /// Matches `sys_hdkey_derive` in `os_hdkey.h`.
    fn sys_hdkey_derive(
        derivation_mode: u32,
        curve: u32,
        path: *const u32,
        path_len: usize,
        private_key: *mut u8,
        private_key_len: usize,
        chain_code: *mut u8,
        chain_code_len: usize,
        seed: *mut u8,
        seed_len: usize,
    ) -> u32;
}

// ---------------------------------------------------------------------------
// Public wrapper
// ---------------------------------------------------------------------------

/// Derive an Orchard spending key (and chain code) at the given BIP32-style
/// path using ZIP32 Orchard mode on the Pallas curve.
///
/// # Parameters
/// * `path` – derivation path as a slice of 32-bit child indices.
/// * `sk`   – output buffer for the 32-byte Orchard spending key.
/// * `chain_code` – optional output buffer for the 32-byte chain code.
///
/// # Returns
/// `Ok(())` on success, `Err(bolos_err)` on failure.
pub fn zip32_orchard_derive(
    path: &[u32],
    sk: &mut [u8; ZIP32_SK_SIZE],
    chain_code: Option<&mut [u8; ZIP32_CHAIN_CODE_SIZE]>,
) -> Result<(), CxErr> {
    let (cc_ptr, cc_len) = match chain_code {
        Some(buf) => (buf.as_mut_ptr(), ZIP32_CHAIN_CODE_SIZE),
        None => (core::ptr::null_mut(), 0),
    };

    let err = unsafe {
        sys_hdkey_derive(
            HDKEY_DERIVE_MODE_ZIP32_ORCHARD,
            CX_CURVE_PALLAS,
            path.as_ptr(),
            path.len(),
            sk.as_mut_ptr(),
            ZIP32_SK_SIZE,
            cc_ptr,
            cc_len,
            core::ptr::null_mut(), // seed: not used
            0,
        )
    };

    if err == 0 { Ok(()) } else { Err(err) }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

pub mod tests {
    use super::*;

    /// Standard Zcash Orchard path: m/32'/133'/0'
    /// Hardened indices have bit 31 set.
    const ORCHARD_PATH: [u32; 3] = [
        32  | 0x8000_0000,
        133 | 0x8000_0000,
        0   | 0x8000_0000,
    ];

    /// Derivation succeeds and produces a non-zero spending key.
    pub fn test_zip32_orchard_derive_smoke() {
        let mut sk = [0u8; ZIP32_SK_SIZE];
        zip32_orchard_derive(&ORCHARD_PATH, &mut sk, None).unwrap();
        assert_ne!(sk, [0u8; ZIP32_SK_SIZE]);
    }

    /// Derivation is deterministic: same path yields the same sk.
    pub fn test_zip32_orchard_derive_deterministic() {
        let mut sk1 = [0u8; ZIP32_SK_SIZE];
        let mut sk2 = [0u8; ZIP32_SK_SIZE];
        zip32_orchard_derive(&ORCHARD_PATH, &mut sk1, None).unwrap();
        zip32_orchard_derive(&ORCHARD_PATH, &mut sk2, None).unwrap();
        assert_eq!(sk1, sk2);
    }

    /// Chain code output is non-zero and consistent across calls.
    pub fn test_zip32_orchard_derive_chain_code() {
        let mut sk1 = [0u8; ZIP32_SK_SIZE];
        let mut sk2 = [0u8; ZIP32_SK_SIZE];
        let mut cc1 = [0u8; ZIP32_CHAIN_CODE_SIZE];
        let mut cc2 = [0u8; ZIP32_CHAIN_CODE_SIZE];
        zip32_orchard_derive(&ORCHARD_PATH, &mut sk1, Some(&mut cc1)).unwrap();
        zip32_orchard_derive(&ORCHARD_PATH, &mut sk2, Some(&mut cc2)).unwrap();
        assert_ne!(cc1, [0u8; ZIP32_CHAIN_CODE_SIZE]);
        assert_eq!(sk1, sk2);
        assert_eq!(cc1, cc2);
    }

    /// Different account indices yield different spending keys.
    pub fn test_zip32_orchard_derive_different_accounts() {
        let path_acc0: [u32; 3] = [44 | 0x8000_0000, 133 | 0x8000_0000, 0 | 0x8000_0000];
        let path_acc1: [u32; 3] = [44 | 0x8000_0000, 133 | 0x8000_0000, 1 | 0x8000_0000];
        let mut sk0 = [0u8; ZIP32_SK_SIZE];
        let mut sk1 = [0u8; ZIP32_SK_SIZE];
        zip32_orchard_derive(&path_acc0, &mut sk0, None).unwrap();
        zip32_orchard_derive(&path_acc1, &mut sk1, None).unwrap();
        assert_ne!(sk0, sk1);
    }

    pub fn run_zip32_tests() {
        test_zip32_orchard_derive_smoke();
        test_zip32_orchard_derive_deterministic();
        test_zip32_orchard_derive_chain_code();
        test_zip32_orchard_derive_different_accounts();
    }
}
