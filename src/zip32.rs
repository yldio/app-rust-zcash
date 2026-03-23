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
