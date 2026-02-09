use ledger_device_sdk::libcall::swap::CheckAddressParams;

use crate::{swap::SwapAppErrorCode, AppSW};

pub const MAX_ZCASH_BIP32_PATH: usize = 10;

/// BIP32 derivation path stored as a vector of u32 components.
///
/// Each component represents one level in the path (e.g., m/44'/1'/0'/0/0 has 5 components).
/// Hardened derivation is indicated by setting the high bit (>= 0x80000000).
#[derive(Default, Debug)]
pub struct Bip32Path {
    path: [u32; MAX_ZCASH_BIP32_PATH],
    path_len: u8,
}

impl Bip32Path {
    pub fn as_slice(&self) -> &[u32] {
        &self.path[..self.path_len as usize]
    }
}
impl<
        const COIN_CONFIG_BUF_SIZE: usize,
        const ADDRESS_BUF_SIZE: usize,
        const IDADDRESS_EXTRA_ID_BUF_SIZE: usize,
    >
    TryFrom<
        &CheckAddressParams<COIN_CONFIG_BUF_SIZE, ADDRESS_BUF_SIZE, IDADDRESS_EXTRA_ID_BUF_SIZE>,
    > for Bip32Path
{
    type Error = SwapAppErrorCode;
    fn try_from(
        value: &CheckAddressParams<
            COIN_CONFIG_BUF_SIZE,
            ADDRESS_BUF_SIZE,
            IDADDRESS_EXTRA_ID_BUF_SIZE,
        >,
    ) -> Result<Self, Self::Error> {
        let path_len = value.dpath_len as u8;

        if value.dpath_len > MAX_ZCASH_BIP32_PATH {
            return Err(SwapAppErrorCode::PathTooLong);
        }

        let mut path = [0u32; MAX_ZCASH_BIP32_PATH];

        for (dst, chunk) in path.iter_mut().zip(value.dpath.chunks_exact(4)) {
            *dst = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
        }

        Ok(Bip32Path { path, path_len })
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Constructs a [`Bip32Path`] from APDU-encoded bytes.
    ///
    /// # Format
    ///
    /// - First byte: Number of path components (e.g., 5 for m/44'/1'/0'/0/0)
    /// - Remaining bytes: Big-endian u32 components (4 bytes each)
    ///
    /// # Example
    ///
    /// For path m/44'/1'/0'/0/0:
    /// ```text
    /// [0x05, 0x8000002C, 0x80000001, 0x80000000, 0x00000000, 0x00000000]
    /// ```
    ///
    /// # Note
    ///
    /// This uses `Vec` for dynamic allocation, which is fine for normal APDU handlers
    /// but CANNOT be used in swap's `check_address` or `get_printable_amount` due to
    /// BSS memory sharing with the Exchange app.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // Check data length
        if data.is_empty() // At least the length byte is required
            || (data[0] as usize * 4 != data.len() - 1)
        {
            return Err(AppSW::WrongApduLength);
        }
        let path_len = data[0];

        let mut path = [0; MAX_ZCASH_BIP32_PATH];
        for (i, chunk) in data[1..].chunks(4).enumerate() {
            path[i] = u32::from_be_bytes(chunk.try_into().unwrap());
        }

        Ok(Bip32Path { path, path_len })
    }
}
