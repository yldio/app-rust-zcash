use alloc::vec::Vec;
use arrayvec::ArrayString;
use bs58::encode::EncodeTarget;

use crate::{
    log::{debug, error},
    AppSW,
};

pub mod blake2b_256_pers;

// Buffer for bs58 encoding output
struct OutBuf<'b, const N: usize> {
    out: &'b mut [u8; N],
}

impl<const N: usize> EncodeTarget for OutBuf<'_, N> {
    fn encode_with(
        &mut self,
        max_len: usize,
        f: impl for<'a> FnOnce(&'a mut [u8]) -> bs58::encode::Result<usize>,
    ) -> bs58::encode::Result<usize> {
        let len = f(&mut self.out[..max_len])?;
        Ok(len)
    }
}

/// BIP32 path stored as an array of [`u32`].
#[derive(Default)]
pub struct Bip32Path(Vec<u32>);

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
    }
}

impl TryFrom<&[u8]> for Bip32Path {
    type Error = AppSW;

    /// Constructs a [`Bip32Path`] from a given byte array.
    ///
    /// This method will return an error in the following cases:
    /// - the input array is empty,
    /// - the number of bytes in the input array is not a multiple of 4,
    ///
    /// # Arguments
    ///
    /// * `data` - Encoded BIP32 path. First byte is the length of the path, as encoded by ragger.
    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        // Check data length
        if data.is_empty() // At least the length byte is required
            || (data[0] as usize * 4 != data.len() - 1)
        {
            return Err(AppSW::WrongApduLength);
        }

        Ok(Bip32Path(
            data[1..]
                .chunks(4)
                .map(|chunk| u32::from_be_bytes(chunk.try_into().unwrap()))
                .collect(),
        ))
    }
}

pub struct PubKeyWithCC {
    pub public_key: [u8; 65],
    pub public_key_len: usize,
    pub chain_code: [u8; 32],
}

pub fn derive_public_key(path: &Bip32Path) -> Result<PubKeyWithCC, AppSW> {
    use ledger_device_sdk::ecc::{Secp256k1, SeedDerive};

    let (k, cc) = Secp256k1::derive_from(path.as_ref());
    let pk = k.public_key().map_err(|_| AppSW::IncorrectData)?;

    let code = cc.ok_or(AppSW::IncorrectData)?;
    Ok(PubKeyWithCC {
        public_key: pk.pubkey,
        public_key_len: pk.keylength,
        chain_code: code.value,
    })
}

pub fn public_key_hash160(public_key: &[u8]) -> Result<[u8; 20], AppSW> {
    use ledger_device_sdk::hash::{ripemd::Ripemd160, sha2::Sha2_256, HashInit};

    let mut sha256 = Sha2_256::new();
    let mut sha256_output: [u8; 32] = [0u8; 32];
    sha256
        .hash(public_key, &mut sha256_output)
        .map_err(|_| AppSW::IncorrectData)?;

    let mut ripemd160 = Ripemd160::new();
    let mut ripemd160_output: [u8; 20] = [0u8; 20];
    ripemd160
        .hash(&sha256_output, &mut ripemd160_output)
        .map_err(|_| AppSW::IncorrectData)?;

    debug!("PubKey SHA256: {:02X?}", &sha256_output);
    debug!("PubKey HASH160: {:02X?}", &ripemd160_output);

    Ok(ripemd160_output)
}

fn compute_cheksum(input: &[u8]) -> [u8; 4] {
    use ledger_device_sdk::hash::{sha2::Sha2_256, HashInit};

    let mut sha256 = Sha2_256::new();
    let mut sha256_output: [u8; 32] = [0u8; 32];
    sha256.hash(input, &mut sha256_output).unwrap();

    let mut sha256_2 = Sha2_256::new();
    let mut sha256_2_output: [u8; 32] = [0u8; 32];
    sha256_2.hash(&sha256_output, &mut sha256_2_output).unwrap();

    debug!("Checksum: {:02X?}", &sha256_2_output[0..4]);

    [
        sha256_2_output[0],
        sha256_2_output[1],
        sha256_2_output[2],
        sha256_2_output[3],
    ]
}

pub fn compress_public_key(public_key: &[u8]) -> Result<[u8; 33], AppSW> {
    if public_key.len() != 65 {
        return Err(AppSW::IncorrectData);
    }
    let mut compressed_pk = [0u8; 33];
    compressed_pk[0] = if public_key[64] & 1 == 1 { 0x03 } else { 0x02 };
    compressed_pk[1..33].copy_from_slice(&public_key[1..33]);
    Ok(compressed_pk)
}

pub fn public_key_to_address_base58<const MAX_OUT_SIZE: usize>(
    public_key: &[u8],
) -> Result<ArrayString<MAX_OUT_SIZE>, AppSW> {
    // T-address P2PKH prefix (mainnet)
    const P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];
    // T-address P2PKH prefix (testnet)
    const _P2PKH_PREFIX: [u8; 2] = [0x1D, 0x25];

    let mut buf = [0u8; 26];

    // For Zcash, the address is the HASH160 of the public key
    debug!("To hash: {:02X?}", &public_key);
    let pubkey_hash160 = public_key_hash160(public_key)?;
    buf[0] = P2PKH_PREFIX[0];
    buf[1] = P2PKH_PREFIX[1];
    buf[2..22].copy_from_slice(&pubkey_hash160);

    let checksum = compute_cheksum(&buf[0..22]);
    buf[22..26].copy_from_slice(&checksum);

    let mut out_buf = [0u8; MAX_OUT_SIZE];
    let out_len = bs58::encode(&buf[..26])
        .onto(OutBuf { out: &mut out_buf })
        .map_err(|_| {
            error!("Base58 encoding failed");
            AppSW::IncorrectData
        })?;

    let mut address_base58 =
        ArrayString::from_byte_string(&out_buf).expect("bs58 produces valid ASCII");
    address_base58.truncate(out_len);

    debug!("Address Base58: {}", address_base58);

    Ok(address_base58)
}

pub enum Endianness {
    Big,
    _Little,
}

pub fn read_u32(buffer: &[u8], endianness: Endianness, skip_sign: bool) -> Result<u32, AppSW> {
    if buffer.len() < 4 {
        return Err(AppSW::IncorrectData);
    }

    let buffer4 = buffer[..4].try_into().expect("cannot fail");

    let mut word = match endianness {
        Endianness::Big => u32::from_be_bytes(buffer4),
        Endianness::_Little => u32::from_le_bytes(buffer4),
    };

    if skip_sign {
        word &= 0x7FFF_FFFF;
    }

    Ok(word)
}

pub struct HexSlice<'a>(pub &'a [u8]);

impl core::fmt::Display for HexSlice<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for byte in self.0 {
            write!(f, "{:02X}", byte)?;
        }
        Ok(())
    }
}
