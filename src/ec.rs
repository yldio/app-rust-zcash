//! FFI bindings and Rust wrappers for Ledger Secure SDK elliptic-curve syscalls.
//!
//! Supported curves
//! ----------------
//! | Curve  | Type            | Curve ID (`cx_curve_e`) |
//! |--------|-----------------|------------------------|
//! | Jubjub | Twisted Edwards | `CX_CURVE_JUBJUB` 0x74 |
//! | Pallas | Weierstrass     | `CX_CURVE_PALLAS` 0x53 |
//! | Vesta  | Weierstrass     | `CX_CURVE_VESTA`  0x54 |
//!
//! All three curves have 32-byte (256-bit) field elements.
//!
//! # BN lock requirement
//! Every syscall in this module requires the Ledger BN processor to be locked
//! (via `cx_bn_lock`).  Use [`BnLock::acquire`] to obtain an RAII guard before
//! calling any operation, and keep it alive for the duration of the computation.
//!
//! # Byte order
//! The Ledger SDK uses **big-endian** byte order for all coordinates.
//! For Sapling / Orchard wire format (little-endian) callers must reverse the
//! returned byte arrays themselves.
#![allow(dead_code)]
use crate::log::debug;

// ---------------------------------------------------------------------------
// Curve identifiers
// ---------------------------------------------------------------------------

pub const CX_CURVE_JUBJUB: u32 = 0x74;
pub const CX_CURVE_PALLAS: u32 = 0x53;
pub const CX_CURVE_VESTA: u32 = 0x54;

/// BN word size used when locking – must be a power-of-two multiple of 16.
/// 32 bytes covers the 256-bit fields of all three curves.
const BN_WORD_BYTES: usize = 32;

/// Byte length of a field element / scalar for all supported curves.
pub const COORD_SIZE: usize = 32;

// ---------------------------------------------------------------------------
// C types
// ---------------------------------------------------------------------------

/// `cx_err_t` – error code returned by Ledger SDK syscalls.
pub type CxErr = u32;

pub const CX_OK: CxErr = 0x0000_0000;

/// Mirror of `cx_ec_point_s` / `cx_ecpoint_t`.
///
/// The `x`, `y`, `z` fields are **BN slot indices** into the SDK's internal
/// memory pool, not raw coordinate bytes.
#[repr(C)]
pub struct CxEcPoint {
    pub curve: u32,
    pub x: u32,
    pub y: u32,
    pub z: u32,
}

// ---------------------------------------------------------------------------
// Raw FFI declarations  (ox_ec.h + ox_bn.h)
// ---------------------------------------------------------------------------

unsafe extern "C" {
    // --- BN processor lock/unlock ---
    fn cx_bn_lock(word_nbytes: usize, flags: u32) -> CxErr;
    fn cx_bn_unlock() -> u32;

    // --- EC point lifecycle ---
    fn cx_ecpoint_alloc(p: *mut CxEcPoint, cv: u32) -> CxErr;
    fn cx_ecpoint_destroy(p: *mut CxEcPoint) -> CxErr;

    // --- EC point initialisation ---
    /// Initialise a point from affine (x, y) coordinate bytes.
    fn cx_ecpoint_init(
        p: *mut CxEcPoint,
        x: *const u8,
        x_len: usize,
        y: *const u8,
        y_len: usize,
    ) -> CxErr;

    // --- Domain / generator ---
    /// Load the curve generator into an already-allocated point.
    fn cx_ecdomain_generator_bn(cv: u32, p: *mut CxEcPoint) -> CxErr;

    // --- Scalar multiplication ---

    /// Secure scalar multiplication `[k]P`.
    /// Use this when `k` is a **secret** value.
    fn cx_ecpoint_rnd_scalarmul(p: *mut CxEcPoint, k: *const u8, k_len: usize) -> CxErr;

    /// Non-secure scalar multiplication `[k]P`.
    /// Use only when `k` is **public** (non-secret) data.
    fn cx_ecpoint_scalarmul(p: *mut CxEcPoint, k: *const u8, k_len: usize) -> CxErr;

    // --- Point arithmetic ---
    fn cx_ecpoint_add(r: *mut CxEcPoint, p: *const CxEcPoint, q: *const CxEcPoint) -> CxErr;
    fn cx_ecpoint_neg(p: *mut CxEcPoint) -> CxErr;

    // --- Point export ---
    /// Export affine coordinates as raw bytes.
    fn cx_ecpoint_export(
        p: *const CxEcPoint,
        x: *mut u8,
        x_len: usize,
        y: *mut u8,
        y_len: usize,
    ) -> CxErr;

    /// Export the compressed coordinate and its companion sign bit.
    ///
    /// * Weierstrass (Pallas/Vesta): `xy_compressed` ← x-coord; `*sign` ← LSB of y.
    /// * Twisted Edwards (Jubjub):   `xy_compressed` ← y-coord; `*sign` ← LSB of x.
    fn cx_ecpoint_compress(
        p: *const CxEcPoint,
        xy_compressed: *mut u8,
        xy_compressed_len: usize,
        sign: *mut u32,
    ) -> CxErr;
}

// ---------------------------------------------------------------------------
// BN lock RAII guard
// ---------------------------------------------------------------------------

/// Holds the BN processor lock for the duration of its lifetime.
///
/// All EC / BN syscalls must be made while this guard is live.
pub struct BnLock;

impl BnLock {
    /// Acquire the BN processor lock (word size = 32 bytes, no flags).
    ///
    /// Returns `Err(cx_err)` if locking fails, e.g. because it is already
    /// locked (`CX_LOCKED`).
    pub fn acquire() -> Result<Self, CxErr> {
        let err = unsafe { cx_bn_lock(BN_WORD_BYTES, 0) };
        if err == CX_OK { Ok(BnLock) } else { Err(err) }
    }
}

impl Drop for BnLock {
    fn drop(&mut self) {
        unsafe { cx_bn_unlock() };
    }
}

// ---------------------------------------------------------------------------
// EC point RAII wrapper
// ---------------------------------------------------------------------------

/// An allocated EC point backed by the SDK's internal BN memory pool.
///
/// Automatically destroys (frees) its BN slots on drop.
struct EcPoint {
    inner: CxEcPoint,
}

impl EcPoint {
    /// Allocate an uninitialised point on `curve`.
    fn alloc(curve: u32) -> Result<Self, CxErr> {
        // SAFETY: cx_ecpoint_alloc fills every field of the struct.
        let mut inner = core::mem::MaybeUninit::<CxEcPoint>::uninit();
        let err = unsafe { cx_ecpoint_alloc(inner.as_mut_ptr(), curve) };
        if err != CX_OK {
            return Err(err);
        }
        Ok(EcPoint {
            inner: unsafe { inner.assume_init() },
        })
    }

    /// Initialise from affine coordinates (big-endian, 32 bytes each).
    fn init(&mut self, x: &[u8; COORD_SIZE], y: &[u8; COORD_SIZE]) -> Result<(), CxErr> {
        let err = unsafe {
            cx_ecpoint_init(
                &mut self.inner,
                x.as_ptr(),
                COORD_SIZE,
                y.as_ptr(),
                COORD_SIZE,
            )
        };
        cx_ok(err)
    }

    /// Allocate and load the curve generator.
    fn generator(curve: u32) -> Result<Self, CxErr> {
        let mut pt = Self::alloc(curve)?;
        let err = unsafe { cx_ecdomain_generator_bn(curve, &mut pt.inner) };
        cx_ok(err)?;
        Ok(pt)
    }

    /// In-place secure scalar multiplication `[k]P` (secret `k`).
    fn scalarmul_secret(&mut self, k: &[u8; COORD_SIZE]) -> Result<(), CxErr> {
        let err = unsafe { cx_ecpoint_rnd_scalarmul(&mut self.inner, k.as_ptr(), COORD_SIZE) };
        cx_ok(err)
    }

    /// In-place non-secure scalar multiplication `[k]P` (public `k`).
    fn scalarmul_public(&mut self, k: &[u8; COORD_SIZE]) -> Result<(), CxErr> {
        let err = unsafe { cx_ecpoint_scalarmul(&mut self.inner, k.as_ptr(), COORD_SIZE) };
        cx_ok(err)
    }

    /// Negate this point in-place: `P ← -P`.
    fn negate(&mut self) -> Result<(), CxErr> {
        cx_ok(unsafe { cx_ecpoint_neg(&mut self.inner) })
    }

    /// Export affine coordinates as big-endian byte arrays.
    fn export(&self) -> Result<([u8; COORD_SIZE], [u8; COORD_SIZE]), CxErr> {
        let mut x = [0u8; COORD_SIZE];
        let mut y = [0u8; COORD_SIZE];
        let err = unsafe {
            cx_ecpoint_export(
                &self.inner,
                x.as_mut_ptr(),
                COORD_SIZE,
                y.as_mut_ptr(),
                COORD_SIZE,
            )
        };
        cx_ok(err)?;
        Ok((x, y))
    }

    /// Compress the point.  Returns `(compressed_coord, sign_bit)`.
    ///
    /// * Weierstrass: `compressed_coord` = x-coordinate (BE); `sign` = LSB of y.
    /// * Twisted Edwards: `compressed_coord` = y-coordinate (BE); `sign` = LSB of x.
    fn compress(&self) -> Result<([u8; COORD_SIZE], u32), CxErr> {
        let mut coord = [0u8; COORD_SIZE];
        let mut sign: u32 = 0;
        let err =
            unsafe { cx_ecpoint_compress(&self.inner, coord.as_mut_ptr(), COORD_SIZE, &mut sign) };
        cx_ok(err)?;
        Ok((coord, sign))
    }
}

impl Drop for EcPoint {
    fn drop(&mut self) {
        // Ignore the return value – we cannot propagate errors from Drop.
        unsafe { cx_ecpoint_destroy(&mut self.inner) };
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline(always)]
fn cx_ok(err: CxErr) -> Result<(), CxErr> {
    if err == CX_OK { Ok(()) } else { Err(err) }
}

// --- Scalar-mul variants ---

fn do_scalarmul_basepoint(
    curve: u32,
    scalar: &[u8; COORD_SIZE],
    secret: bool,
) -> Result<EcPoint, CxErr> {
    let mut pt = EcPoint::generator(curve)?;
    if secret {
        pt.scalarmul_secret(scalar)?;
    } else {
        pt.scalarmul_public(scalar)?;
    }
    Ok(pt)
}

fn do_scalarmul_point(
    curve: u32,
    px: &[u8; COORD_SIZE],
    py: &[u8; COORD_SIZE],
    scalar: &[u8; COORD_SIZE],
    secret: bool,
) -> Result<EcPoint, CxErr> {
    let mut pt = EcPoint::alloc(curve)?;
    pt.init(px, py)?;
    if secret {
        pt.scalarmul_secret(scalar)?;
    } else {
        pt.scalarmul_public(scalar)?;
    }
    Ok(pt)
}

fn do_point_add(
    curve: u32,
    px: &[u8; COORD_SIZE],
    py: &[u8; COORD_SIZE],
    qx: &[u8; COORD_SIZE],
    qy: &[u8; COORD_SIZE],
) -> Result<EcPoint, CxErr> {
    let mut p = EcPoint::alloc(curve)?;
    p.init(px, py)?;
    let mut q = EcPoint::alloc(curve)?;
    q.init(qx, qy)?;
    let mut r = EcPoint::alloc(curve)?;
    cx_ok(unsafe { cx_ecpoint_add(&mut r.inner, &p.inner, &q.inner) })?;
    Ok(r)
}

fn do_point_neg(curve: u32, x: &[u8; COORD_SIZE], y: &[u8; COORD_SIZE]) -> Result<EcPoint, CxErr> {
    let mut pt = EcPoint::alloc(curve)?;
    pt.init(x, y)?;
    pt.negate()?;
    Ok(pt)
}

// --- Encoding helpers ---

/// Compressed Weierstrass point: 0x02/0x03 prefix || x-coordinate (BE, 32 B).
pub type CompressedWeierstrass = [u8; 33];

/// Compressed twisted-Edwards point: y-coordinate (BE, 32 B) with the MSB
/// (bit 7 of byte 0 in big-endian) set to the sign of x.
///
/// **Note:** Sapling wire format uses little-endian y with bit 255 = sign of x.
/// To convert: reverse the 32 bytes, then bit 7 of byte 31 carries the sign.
pub type CompressedEdwards = [u8; COORD_SIZE];

fn encode_weierstrass(pt: &EcPoint) -> Result<CompressedWeierstrass, CxErr> {
    let (x, sign) = pt.compress()?;
    let mut out = [0u8; 33];
    out[0] = if sign & 1 == 0 { 0x02 } else { 0x03 };
    out[1..].copy_from_slice(&x);
    Ok(out)
}

fn encode_edwards(pt: &EcPoint) -> Result<CompressedEdwards, CxErr> {
    let (mut y, sign) = pt.compress()?;
    // High bit of first byte (big-endian MSB) encodes sign of x.
    if sign & 1 != 0 {
        y[0] |= 0x80;
    }
    Ok(y)
}

// ===========================================================================
// Public API – per-curve modules
// ===========================================================================

// ---------------------------------------------------------------------------
// Jubjub  (twisted Edwards, CX_CURVE_JUBJUB = 0x74)
// ---------------------------------------------------------------------------

/// EC operations on the **Jubjub** twisted-Edwards curve.
///
/// All coordinate and scalar inputs are 32-byte **big-endian** arrays.
/// The returned [`CompressedEdwards`] value is also big-endian.
pub mod jubjub {
    use super::*;

    const CURVE: u32 = CX_CURVE_JUBJUB;

    /// `[scalar] × G`  — secure (scalar is a secret key).
    pub fn scalar_mul_basepoint(scalar: &[u8; COORD_SIZE]) -> Result<CompressedEdwards, CxErr> {
        encode_edwards(&do_scalarmul_basepoint(CURVE, scalar, true)?)
    }

    /// `[scalar] × pk`  — secure (scalar is secret; pk is a public key).
    pub fn scalar_mul_pubkey(
        scalar: &[u8; COORD_SIZE],
        pk_x: &[u8; COORD_SIZE],
        pk_y: &[u8; COORD_SIZE],
    ) -> Result<CompressedEdwards, CxErr> {
        encode_edwards(&do_scalarmul_point(CURVE, pk_x, pk_y, scalar, true)?)
    }

    /// `[scalar] × P`  — non-secure (scalar and point are both public).
    pub fn scalar_mul_point(
        scalar: &[u8; COORD_SIZE],
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
    ) -> Result<CompressedEdwards, CxErr> {
        encode_edwards(&do_scalarmul_point(CURVE, px, py, scalar, false)?)
    }

    /// `P + Q`
    pub fn point_add(
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
        qx: &[u8; COORD_SIZE],
        qy: &[u8; COORD_SIZE],
    ) -> Result<CompressedEdwards, CxErr> {
        encode_edwards(&do_point_add(CURVE, px, py, qx, qy)?)
    }

    /// `-P`
    pub fn point_neg(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedEdwards, CxErr> {
        encode_edwards(&do_point_neg(CURVE, x, y)?)
    }

    /// Encode an affine point `(x, y)` into compressed form.
    pub fn encode_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedEdwards, CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        encode_edwards(&pt)
    }

    /// Export an affine point `(x, y)` as raw big-endian coordinate pairs.
    pub fn export_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<([u8; COORD_SIZE], [u8; COORD_SIZE]), CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        pt.export()
    }
}

// ---------------------------------------------------------------------------
// Pallas  (Weierstrass, CX_CURVE_PALLAS = 0x53)
// ---------------------------------------------------------------------------

/// EC operations on the **Pallas** short-Weierstrass curve.
///
/// All coordinate and scalar inputs are 32-byte **big-endian** arrays.
/// The returned [`CompressedWeierstrass`] value is 33 bytes: a 0x02/0x03
/// prefix followed by the x-coordinate in big-endian order.
pub mod pallas {
    use super::*;

    const CURVE: u32 = CX_CURVE_PALLAS;

    /// `[scalar] × G`  — secure (scalar is a secret key).
    pub fn scalar_mul_basepoint(scalar: &[u8; COORD_SIZE]) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_basepoint(CURVE, scalar, true)?)
    }

    /// `[scalar] × pk`  — secure (scalar is secret; pk is a public key).
    pub fn scalar_mul_pubkey(
        scalar: &[u8; COORD_SIZE],
        pk_x: &[u8; COORD_SIZE],
        pk_y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_point(CURVE, pk_x, pk_y, scalar, true)?)
    }

    /// `[scalar] × P`  — non-secure (scalar and point are both public).
    pub fn scalar_mul_point(
        scalar: &[u8; COORD_SIZE],
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_point(CURVE, px, py, scalar, false)?)
    }

    /// `P + Q`
    pub fn point_add(
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
        qx: &[u8; COORD_SIZE],
        qy: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_point_add(CURVE, px, py, qx, qy)?)
    }

    /// `-P`
    pub fn point_neg(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_point_neg(CURVE, x, y)?)
    }

    /// Encode an affine point `(x, y)` into compressed form.
    pub fn encode_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        encode_weierstrass(&pt)
    }

    /// Export an affine point `(x, y)` as raw big-endian coordinate pairs.
    pub fn export_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<([u8; COORD_SIZE], [u8; COORD_SIZE]), CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        pt.export()
    }
}

// ---------------------------------------------------------------------------
// Vesta   (Weierstrass, CX_CURVE_VESTA = 0x54)
// ---------------------------------------------------------------------------

/// EC operations on the **Vesta** short-Weierstrass curve.
///
/// All coordinate and scalar inputs are 32-byte **big-endian** arrays.
/// The returned [`CompressedWeierstrass`] value is 33 bytes: a 0x02/0x03
/// prefix followed by the x-coordinate in big-endian order.
pub mod vesta {
    use super::*;

    const CURVE: u32 = CX_CURVE_VESTA;

    /// `[scalar] × G`  — secure (scalar is a secret key).
    pub fn scalar_mul_basepoint(scalar: &[u8; COORD_SIZE]) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_basepoint(CURVE, scalar, true)?)
    }

    /// `[scalar] × pk`  — secure (scalar is secret; pk is a public key).
    pub fn scalar_mul_pubkey(
        scalar: &[u8; COORD_SIZE],
        pk_x: &[u8; COORD_SIZE],
        pk_y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_point(CURVE, pk_x, pk_y, scalar, true)?)
    }

    /// `[scalar] × P`  — non-secure (scalar and point are both public).
    pub fn scalar_mul_point(
        scalar: &[u8; COORD_SIZE],
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_scalarmul_point(CURVE, px, py, scalar, false)?)
    }

    /// `P + Q`
    pub fn point_add(
        px: &[u8; COORD_SIZE],
        py: &[u8; COORD_SIZE],
        qx: &[u8; COORD_SIZE],
        qy: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_point_add(CURVE, px, py, qx, qy)?)
    }

    /// `-P`
    pub fn point_neg(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        encode_weierstrass(&do_point_neg(CURVE, x, y)?)
    }

    /// Encode an affine point `(x, y)` into compressed form.
    pub fn encode_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<CompressedWeierstrass, CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        encode_weierstrass(&pt)
    }

    /// Export an affine point `(x, y)` as raw big-endian coordinate pairs.
    pub fn export_point(
        x: &[u8; COORD_SIZE],
        y: &[u8; COORD_SIZE],
    ) -> Result<([u8; COORD_SIZE], [u8; COORD_SIZE]), CxErr> {
        let mut pt = EcPoint::alloc(CURVE)?;
        pt.init(x, y)?;
        pt.export()
    }
}

pub mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pallas – point addition
    // -----------------------------------------------------------------------
    pub fn test_point_add_pallas() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x16, 0xd2, 0xcd, 0xa8, 0xef, 0x80, 0xb4, 0xc4, 0x9b, 0x3a, 0xda, 0xcc, 0x38, 0x4f,
            0xea, 0xf1, 0xfb, 0x38, 0xa3, 0x5b, 0xe1, 0xbc, 0x02, 0xad, 0x6a, 0xa4, 0xc4, 0x99,
            0xb6, 0xc6, 0xfe, 0xe6,
        ];
        let py: [u8; 32] = [
            0x03, 0x88, 0xe7, 0x11, 0xd1, 0x20, 0xf9, 0x03, 0xf0, 0x1c, 0x36, 0xe2, 0x14, 0x39,
            0x21, 0xeb, 0x6b, 0xc2, 0x7f, 0xdd, 0xd5, 0xd3, 0xb6, 0x53, 0x44, 0xc1, 0xa7, 0x67,
            0x3d, 0x7d, 0x0d, 0x78,
        ];
        let qx: [u8; 32] = [
            0x36, 0x18, 0x3a, 0x16, 0x36, 0xd7, 0x3b, 0xf0, 0x6f, 0x65, 0xd6, 0x98, 0xb4, 0x36,
            0x20, 0xb3, 0xd6, 0xb8, 0xaf, 0x06, 0xf4, 0x4b, 0xd2, 0x0b, 0xc8, 0x02, 0xeb, 0xea,
            0xa9, 0x41, 0x97, 0x4f,
        ];
        let qy: [u8; 32] = [
            0x00, 0x80, 0x81, 0xc8, 0x75, 0x85, 0xe4, 0x7b, 0x7b, 0xec, 0x78, 0xfa, 0xd5, 0x74,
            0x3d, 0xf7, 0x06, 0x37, 0x40, 0xfa, 0xa1, 0xc5, 0xef, 0x40, 0x90, 0x23, 0x58, 0x50,
            0xc7, 0xa8, 0x19, 0x54,
        ];
        let expected_rx: [u8; 32] = [
            0x1f, 0xc1, 0x2c, 0xa8, 0xc1, 0x33, 0x24, 0x0e, 0x3e, 0x81, 0x6d, 0x4f, 0x5d, 0xbd,
            0xac, 0xbb, 0x3f, 0x5a, 0x81, 0xbe, 0x4d, 0x0f, 0x1f, 0x53, 0x62, 0x37, 0x31, 0xfa,
            0x26, 0xb5, 0xbd, 0x07,
        ];
        let expected_ry: [u8; 32] = [
            0x19, 0x23, 0x65, 0xe8, 0x53, 0x5e, 0x65, 0x15, 0xa0, 0x66, 0xcd, 0x14, 0x47, 0xf2,
            0xa6, 0x20, 0x90, 0xbb, 0x1a, 0x18, 0xe5, 0x71, 0x13, 0xe8, 0x46, 0x90, 0x88, 0x38,
            0x7f, 0x7a, 0xea, 0xc0,
        ];

        let r = do_point_add(CX_CURVE_PALLAS, &px, &py, &qx, &qy).unwrap();
        let (rx, ry) = r.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Pallas – scalar multiplication (public scalar)
    // -----------------------------------------------------------------------
    pub fn test_scalarmul_point_pallas() {
        let _lock = BnLock::acquire().unwrap();

        // Uncompressed input point: 0x04 || x[32] || y[32]
        let px: [u8; 32] = [
            0x28, 0x48, 0x25, 0x74, 0x0b, 0x7d, 0xba, 0x08, 0x3b, 0x10, 0xcf, 0x18, 0x4f, 0x4e,
            0x64, 0xe0, 0x34, 0x80, 0x39, 0x6c, 0x84, 0x96, 0xda, 0x70, 0x71, 0x4f, 0xe1, 0x7e,
            0x2f, 0x06, 0xef, 0x07,
        ];
        let py: [u8; 32] = [
            0x36, 0x3f, 0x4b, 0x44, 0xaf, 0xc6, 0x0d, 0xed, 0xd4, 0xa6, 0x16, 0x4a, 0x91, 0xa4,
            0xbf, 0xee, 0xa5, 0xbc, 0x6c, 0x32, 0x69, 0x89, 0xb5, 0xf8, 0x5d, 0x00, 0x2e, 0x7b,
            0x0a, 0xf4, 0x20, 0x7a,
        ];
        let scalar: [u8; 32] = [
            0x1c, 0x1e, 0xc9, 0xdf, 0xd4, 0x26, 0x30, 0xea, 0x88, 0x8d, 0x5f, 0xc5, 0x11, 0x4a,
            0xf8, 0xe8, 0x17, 0x83, 0x8a, 0x41, 0x83, 0x90, 0x32, 0x02, 0x51, 0x0c, 0x85, 0xdc,
            0x88, 0x57, 0x7a, 0x76,
        ];
        let expected_rx: [u8; 32] = [
            0x35, 0x62, 0x36, 0x34, 0x3f, 0xf6, 0x78, 0xc3, 0xf9, 0xf4, 0x19, 0xc5, 0xcf, 0xc6,
            0x48, 0xab, 0xc0, 0x34, 0xd8, 0x56, 0xd9, 0x76, 0x4e, 0x7c, 0x36, 0x83, 0x06, 0x89,
            0x5d, 0x26, 0x63, 0xb3,
        ];
        let expected_ry: [u8; 32] = [
            0x34, 0x80, 0x4f, 0xab, 0x52, 0x38, 0xb0, 0xca, 0x70, 0xc2, 0xfb, 0xe9, 0x4d, 0xac,
            0x04, 0x20, 0xbb, 0x3f, 0x11, 0xc1, 0x6b, 0xd6, 0x3c, 0xb5, 0xe8, 0x83, 0xaf, 0x78,
            0xbb, 0x84, 0x55, 0xcd,
        ];

        let pt = do_scalarmul_point(CX_CURVE_PALLAS, &px, &py, &scalar, false).unwrap();
        let (rx, ry) = pt.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Pallas – point negation  (double-negation round-trip)
    // -----------------------------------------------------------------------

    pub fn test_point_neg_pallas() {
        let _lock = BnLock::acquire().unwrap();

        // Reuse P from the add test.
        let px: [u8; 32] = [
            0x16, 0xd2, 0xcd, 0xa8, 0xef, 0x80, 0xb4, 0xc4, 0x9b, 0x3a, 0xda, 0xcc, 0x38, 0x4f,
            0xea, 0xf1, 0xfb, 0x38, 0xa3, 0x5b, 0xe1, 0xbc, 0x02, 0xad, 0x6a, 0xa4, 0xc4, 0x99,
            0xb6, 0xc6, 0xfe, 0xe6,
        ];
        let py: [u8; 32] = [
            0x03, 0x88, 0xe7, 0x11, 0xd1, 0x20, 0xf9, 0x03, 0xf0, 0x1c, 0x36, 0xe2, 0x14, 0x39,
            0x21, 0xeb, 0x6b, 0xc2, 0x7f, 0xdd, 0xd5, 0xd3, 0xb6, 0x53, 0x44, 0xc1, 0xa7, 0x67,
            0x3d, 0x7d, 0x0d, 0x78,
        ];

        let neg = do_point_neg(CX_CURVE_PALLAS, &px, &py).unwrap();
        let (neg_x, neg_y) = neg.export().unwrap();
        // For Weierstrass negation flips y but keeps x.
        assert_eq!(neg_x, px);

        let double_neg = do_point_neg(CX_CURVE_PALLAS, &neg_x, &neg_y).unwrap();
        let (back_x, back_y) = double_neg.export().unwrap();
        assert_eq!(back_x, px);
        assert_eq!(back_y, py);
    }

    // -----------------------------------------------------------------------
    // Vesta – point addition
    // -----------------------------------------------------------------------

    pub fn test_point_add_vesta() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x1c, 0xfc, 0xea, 0x6b, 0x9d, 0xcd, 0xab, 0x97, 0x62, 0x79, 0x56, 0x42, 0x3e, 0x80,
            0x59, 0x63, 0x07, 0x02, 0x04, 0x04, 0x75, 0x86, 0x86, 0xf7, 0x4a, 0x6a, 0xd1, 0x80,
            0x61, 0xb2, 0xb3, 0xd4,
        ];
        let py: [u8; 32] = [
            0x3a, 0x90, 0x98, 0xa9, 0xb5, 0x5f, 0xad, 0x54, 0x93, 0x7a, 0x7f, 0x40, 0x9b, 0x59,
            0xc1, 0xfd, 0xd5, 0x6e, 0x3d, 0x52, 0x22, 0xeb, 0x5c, 0x6a, 0x01, 0x01, 0x52, 0x05,
            0xd0, 0x70, 0x1f, 0x6e,
        ];
        let qx: [u8; 32] = [
            0x02, 0x53, 0xdb, 0xbc, 0xc6, 0x15, 0xa1, 0x87, 0x9e, 0x12, 0xa6, 0x9d, 0x60, 0x1c,
            0xab, 0x8a, 0xe1, 0x5f, 0x2f, 0xfa, 0x1a, 0x1e, 0xce, 0xd5, 0xd4, 0x70, 0x06, 0x7a,
            0xb6, 0xcb, 0xa0, 0x06,
        ];
        let qy: [u8; 32] = [
            0x29, 0x1e, 0x04, 0xbc, 0x91, 0xcc, 0x28, 0xae, 0x71, 0x8a, 0x39, 0xa0, 0x07, 0xe3,
            0xc0, 0x1a, 0x2e, 0x03, 0x98, 0xc5, 0xd7, 0x2a, 0xb8, 0x34, 0x80, 0x06, 0xb0, 0x13,
            0xee, 0x32, 0x87, 0x90,
        ];
        let expected_rx: [u8; 32] = [
            0x2c, 0x63, 0x3f, 0xdf, 0x1e, 0x49, 0x07, 0xa7, 0xd4, 0x4d, 0x94, 0x00, 0x88, 0xd3,
            0xf7, 0x67, 0xda, 0x28, 0x74, 0xeb, 0x16, 0x56, 0x5d, 0xb6, 0x69, 0x94, 0xfd, 0x9d,
            0x63, 0x0d, 0x6e, 0x41,
        ];
        let expected_ry: [u8; 32] = [
            0x2b, 0x92, 0x30, 0xb8, 0x12, 0xd0, 0x42, 0x89, 0x99, 0x1e, 0xfc, 0xc7, 0x5e, 0x23,
            0xd4, 0xce, 0x7e, 0xcb, 0xed, 0x68, 0x86, 0x57, 0xe7, 0xbc, 0x0c, 0xdb, 0xa8, 0x97,
            0xe4, 0x88, 0xc1, 0x83,
        ];

        let r = do_point_add(CX_CURVE_VESTA, &px, &py, &qx, &qy).unwrap();
        let (rx, ry) = r.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Vesta – scalar multiplication (public scalar)
    // -----------------------------------------------------------------------

    pub fn test_scalarmul_point_vesta() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x3b, 0x4a, 0xcb, 0xba, 0x89, 0x60, 0xa2, 0x57, 0xf3, 0xe7, 0x92, 0xbe, 0x6a, 0x79,
            0x4e, 0xd3, 0x6c, 0x34, 0x0a, 0xde, 0x31, 0x97, 0xe8, 0x12, 0x69, 0x36, 0x89, 0xba,
            0xeb, 0x16, 0xd5, 0x33,
        ];
        let py: [u8; 32] = [
            0x1b, 0xb8, 0xa3, 0x2f, 0x3b, 0xe3, 0x47, 0xe4, 0xe6, 0x6d, 0x80, 0xe4, 0x1a, 0x45,
            0xeb, 0xf5, 0xf1, 0xb7, 0xb4, 0x93, 0x32, 0xe5, 0x73, 0x3e, 0xfb, 0x47, 0x1b, 0xa6,
            0x83, 0xac, 0xff, 0x54,
        ];
        let scalar: [u8; 32] = [
            0x20, 0x7b, 0x58, 0x59, 0xdb, 0x7c, 0x04, 0x42, 0x54, 0x8d, 0xf5, 0xec, 0xfe, 0xb9,
            0x69, 0xec, 0x55, 0xae, 0xda, 0x6f, 0x6e, 0x92, 0xc8, 0x81, 0x80, 0x6d, 0xf9, 0xe3,
            0x2b, 0xd6, 0x87, 0x2a,
        ];
        let expected_rx: [u8; 32] = [
            0x0e, 0xc8, 0x51, 0x1e, 0xd1, 0x8a, 0x09, 0x32, 0x79, 0xb6, 0xab, 0xfa, 0x01, 0x1d,
            0xd9, 0x4c, 0xd8, 0x6d, 0x3f, 0x50, 0x0d, 0x0e, 0xe5, 0x8c, 0x84, 0xc8, 0x4f, 0x5b,
            0xdb, 0xf3, 0x0a, 0x88,
        ];
        let expected_ry: [u8; 32] = [
            0x1d, 0x7a, 0xcc, 0xb6, 0x63, 0x1e, 0xe8, 0xdb, 0x82, 0xe2, 0xdf, 0x36, 0x07, 0xef,
            0x46, 0x11, 0x99, 0x16, 0x19, 0x04, 0x40, 0x6d, 0xd9, 0x72, 0x82, 0x5b, 0xa9, 0xfa,
            0x34, 0xe6, 0x32, 0x8d,
        ];

        let pt = do_scalarmul_point(CX_CURVE_VESTA, &px, &py, &scalar, false).unwrap();
        let (rx, ry) = pt.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Vesta – point negation  (double-negation round-trip)
    // -----------------------------------------------------------------------

    pub fn test_point_neg_vesta() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x1c, 0xfc, 0xea, 0x6b, 0x9d, 0xcd, 0xab, 0x97, 0x62, 0x79, 0x56, 0x42, 0x3e, 0x80,
            0x59, 0x63, 0x07, 0x02, 0x04, 0x04, 0x75, 0x86, 0x86, 0xf7, 0x4a, 0x6a, 0xd1, 0x80,
            0x61, 0xb2, 0xb3, 0xd4,
        ];
        let py: [u8; 32] = [
            0x3a, 0x90, 0x98, 0xa9, 0xb5, 0x5f, 0xad, 0x54, 0x93, 0x7a, 0x7f, 0x40, 0x9b, 0x59,
            0xc1, 0xfd, 0xd5, 0x6e, 0x3d, 0x52, 0x22, 0xeb, 0x5c, 0x6a, 0x01, 0x01, 0x52, 0x05,
            0xd0, 0x70, 0x1f, 0x6e,
        ];

        let neg = do_point_neg(CX_CURVE_VESTA, &px, &py).unwrap();
        let (neg_x, neg_y) = neg.export().unwrap();
        assert_eq!(neg_x, px);

        let double_neg = do_point_neg(CX_CURVE_VESTA, &neg_x, &neg_y).unwrap();
        let (back_x, back_y) = double_neg.export().unwrap();
        assert_eq!(back_x, px);
        assert_eq!(back_y, py);
    }

    // -----------------------------------------------------------------------
    // Jubjub – point addition
    // -----------------------------------------------------------------------

    pub fn test_point_add_jubjub() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x16, 0x0a, 0x53, 0x08, 0xa9, 0x46, 0x6d, 0x47, 0x22, 0x57, 0x3d, 0x33, 0xb8, 0xae,
            0x4d, 0x60, 0x88, 0xdd, 0xff, 0x16, 0x4d, 0xad, 0x57, 0x09, 0x6e, 0x05, 0x66, 0xbe,
            0xed, 0x00, 0xf0, 0x88,
        ];
        let py: [u8; 32] = [
            0x3c, 0x32, 0xa1, 0x53, 0x08, 0x08, 0xc3, 0x64, 0x82, 0xcd, 0x15, 0x88, 0x0e, 0xab,
            0xef, 0x41, 0x43, 0x9f, 0xd0, 0x16, 0x7a, 0xc2, 0x3e, 0x40, 0x77, 0x72, 0x0f, 0x0c,
            0x24, 0x92, 0x56, 0x8b,
        ];
        let qx: [u8; 32] = [
            0x0d, 0x85, 0xef, 0xb1, 0xed, 0x6f, 0xd5, 0xee, 0xe8, 0x44, 0xaf, 0x4d, 0xd0, 0x78,
            0x22, 0xe6, 0xee, 0x06, 0x42, 0xa5, 0x38, 0x38, 0x93, 0xf4, 0xd9, 0x8a, 0x82, 0xc8,
            0xfb, 0x3b, 0x67, 0x4e,
        ];
        let qy: [u8; 32] = [
            0x45, 0xfb, 0x4a, 0xec, 0x80, 0x00, 0x33, 0xe7, 0x51, 0x30, 0xe1, 0xf5, 0xb5, 0x6b,
            0xc3, 0x1e, 0x75, 0xe6, 0xc8, 0xb6, 0x3f, 0x50, 0xcb, 0x00, 0x47, 0xa5, 0x80, 0xf8,
            0xb0, 0x60, 0x8f, 0xab,
        ];
        let expected_rx: [u8; 32] = [
            0x2a, 0x30, 0xa2, 0x55, 0xcf, 0x67, 0xb3, 0xbf, 0xfb, 0x64, 0x7f, 0xbe, 0x60, 0x36,
            0x78, 0x8d, 0xdb, 0x41, 0xa8, 0xc7, 0x6e, 0xd8, 0x96, 0x08, 0x4e, 0x30, 0x51, 0x59,
            0x0f, 0xed, 0x84, 0xa6,
        ];
        let expected_ry: [u8; 32] = [
            0x0e, 0x08, 0x7a, 0x73, 0x48, 0xda, 0x7e, 0x61, 0x02, 0xe0, 0xc7, 0x1a, 0xd1, 0x4f,
            0x1d, 0xfa, 0x99, 0x26, 0x2b, 0x5a, 0x86, 0xaa, 0xef, 0x65, 0x77, 0x82, 0x07, 0x87,
            0x3f, 0xa7, 0x78, 0xc1,
        ];

        let r = do_point_add(CX_CURVE_JUBJUB, &px, &py, &qx, &qy).unwrap();
        let (rx, ry) = r.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Jubjub – scalar multiplication (public scalar)
    // -----------------------------------------------------------------------

    pub fn test_scalarmul_point_jubjub() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x35, 0x08, 0x9a, 0xeb, 0x84, 0x0b, 0xd9, 0x22, 0xcb, 0x72, 0x81, 0x17, 0x50, 0x8f,
            0xf3, 0x8b, 0x03, 0x3b, 0x3f, 0x11, 0x0c, 0x09, 0x15, 0x9a, 0x88, 0x23, 0xf7, 0xe9,
            0x02, 0x58, 0x59, 0x28,
        ];
        let py: [u8; 32] = [
            0x55, 0x16, 0xcf, 0x42, 0xa9, 0x1c, 0xac, 0x6f, 0x53, 0x5b, 0x86, 0xbd, 0xbe, 0x4b,
            0x0d, 0x98, 0xf7, 0x41, 0x78, 0xc3, 0x0b, 0x04, 0x66, 0x7b, 0xcb, 0x00, 0x84, 0x5f,
            0x41, 0xbc, 0xe7, 0xb8,
        ];
        let scalar: [u8; 32] = [
            0xe0, 0x5e, 0xb7, 0xa2, 0xdb, 0x60, 0xd2, 0x50, 0xf6, 0xd7, 0x8d, 0x87, 0x80, 0x61,
            0xc4, 0x0b, 0xb0, 0x48, 0x21, 0xf0, 0xc5, 0x72, 0xff, 0x59, 0x92, 0xeb, 0x5d, 0x03,
            0x93, 0x47, 0xf5, 0x8d,
        ];
        let expected_rx: [u8; 32] = [
            0x33, 0xf7, 0x75, 0x5b, 0x10, 0xd9, 0x13, 0x8b, 0x55, 0x9f, 0x3c, 0xae, 0x00, 0xc1,
            0x7f, 0x2a, 0x1a, 0x53, 0x52, 0x49, 0x15, 0xa9, 0x50, 0x15, 0x74, 0xb5, 0x91, 0x25,
            0x2d, 0xc6, 0x5c, 0xfd,
        ];
        let expected_ry: [u8; 32] = [
            0x09, 0x35, 0x66, 0xb9, 0xdb, 0x44, 0x51, 0x63, 0xd6, 0x7a, 0x95, 0x34, 0x59, 0x1d,
            0xb3, 0x93, 0xc7, 0x66, 0x23, 0x9b, 0x48, 0x78, 0x7f, 0xdf, 0x78, 0x38, 0xab, 0x1e,
            0x3a, 0xea, 0x41, 0xcf,
        ];

        let pt = do_scalarmul_point(CX_CURVE_JUBJUB, &px, &py, &scalar, false).unwrap();
        let (rx, ry) = pt.export().unwrap();
        assert_eq!(rx, expected_rx);
        assert_eq!(ry, expected_ry);
    }

    // -----------------------------------------------------------------------
    // Jubjub – point negation  (double-negation round-trip)
    // Twisted-Edwards negation flips x but keeps y.
    // -----------------------------------------------------------------------

    pub fn test_point_neg_jubjub() {
        let _lock = BnLock::acquire().unwrap();

        let px: [u8; 32] = [
            0x16, 0x0a, 0x53, 0x08, 0xa9, 0x46, 0x6d, 0x47, 0x22, 0x57, 0x3d, 0x33, 0xb8, 0xae,
            0x4d, 0x60, 0x88, 0xdd, 0xff, 0x16, 0x4d, 0xad, 0x57, 0x09, 0x6e, 0x05, 0x66, 0xbe,
            0xed, 0x00, 0xf0, 0x88,
        ];
        let py: [u8; 32] = [
            0x3c, 0x32, 0xa1, 0x53, 0x08, 0x08, 0xc3, 0x64, 0x82, 0xcd, 0x15, 0x88, 0x0e, 0xab,
            0xef, 0x41, 0x43, 0x9f, 0xd0, 0x16, 0x7a, 0xc2, 0x3e, 0x40, 0x77, 0x72, 0x0f, 0x0c,
            0x24, 0x92, 0x56, 0x8b,
        ];

        let neg = do_point_neg(CX_CURVE_JUBJUB, &px, &py).unwrap();
        let (neg_x, neg_y) = neg.export().unwrap();
        // For twisted-Edwards negation flips x but keeps y.
        assert_eq!(neg_y, py);

        let double_neg = do_point_neg(CX_CURVE_JUBJUB, &neg_x, &neg_y).unwrap();
        let (back_x, back_y) = double_neg.export().unwrap();
        assert_eq!(back_x, px);
        assert_eq!(back_y, py);
    }
}

pub fn run_ec_tests() {
    crate::ec::tests::test_point_add_pallas();
    crate::ec::tests::test_scalarmul_point_pallas();
    crate::ec::tests::test_point_neg_pallas();

    crate::ec::tests::test_point_add_vesta();
    crate::ec::tests::test_scalarmul_point_vesta();
    crate::ec::tests::test_point_neg_vesta();

    crate::ec::tests::test_point_add_jubjub();
    crate::ec::tests::test_scalarmul_point_jubjub();
    crate::ec::tests::test_point_neg_jubjub();
    debug!("EC TESTS PASSED..");
}
