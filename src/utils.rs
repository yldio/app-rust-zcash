use alloc::{string::String, vec::Vec};

use crate::log::{debug, error};

pub mod blake2b_256_pers;
use crate::AppSW;

/// BIP32 derivation path stored as a vector of u32 components.
///
/// Each component represents one level in the path (e.g., m/44'/1'/0'/0/0 has 5 components).
/// Hardened derivation is indicated by setting the high bit (>= 0x80000000).
#[derive(Default, Debug)]
pub struct Bip32Path(Vec<u32>);

impl AsRef<[u32]> for Bip32Path {
    fn as_ref(&self) -> &[u32] {
        &self.0
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

fn compute_checksum(input: &[u8]) -> [u8; 4] {
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

// T-address P2PKH prefix (mainnet)
const P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];
// T-address P2PKH prefix (testnet)
const _P2PKH_PREFIX: [u8; 2] = [0x1D, 0x25];

pub fn public_key_to_address_base58(public_key: &[u8], is_hashed: bool) -> Result<String, AppSW> {
    let mut buf = [0u8; 26];

    // For Zcash, the address is the HASH160 of the public key
    if is_hashed {
        buf[0..22].copy_from_slice(&public_key[0..22]);
    } else {
        debug!("To hash: {:02X?}", &public_key);
        let pubkey_hash160 = public_key_hash160(public_key)?;
        buf[0] = P2PKH_PREFIX[0];
        buf[1] = P2PKH_PREFIX[1];
        buf[2..22].copy_from_slice(&pubkey_hash160);
    }

    let checksum = compute_checksum(&buf[0..22]);
    buf[22..26].copy_from_slice(&checksum);

    let mut address_base58 = String::new();
    let _ = bs58::encode(&buf[..26])
        .onto(&mut address_base58)
        .map_err(|_| {
            error!("Base58 encoding failed");
            AppSW::IncorrectData
        })?;

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

/// Constant-time memory comparison to prevent timing attacks.
#[inline(never)]
pub fn secure_memcmp(buf1: &[u8], buf2: &[u8]) -> bool {
    if buf1.len() != buf2.len() {
        return false;
    }

    let mut error: u8 = 0;
    for i in 0..buf1.len() {
        error |= buf1[i] ^ buf2[i];
    }

    error == 0
}

pub fn output_script_is_op_return(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() < 2 {
        return false;
    }

    script_pubkey[1] == 0x6A
}

pub fn output_script_is_regular(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() != 0x19 {
        return false;
    }

    // OP_DUP, OP_HASH160, address length
    const REGULAR_PREFIX: [u8; 3] = [0x76, 0xA9, 0x14];
    // OP_EQUALVERIFY, OP_CHECKSIG
    const REGULAR_POSTFIX: [u8; 2] = [0x88, 0xAC];

    if script_pubkey[0] != REGULAR_PREFIX[0]
        || script_pubkey[1] != REGULAR_PREFIX[1]
        || script_pubkey[2] != REGULAR_PREFIX[2]
    {
        return false;
    }

    if script_pubkey[script_pubkey.len() - 2] != REGULAR_POSTFIX[0]
        || script_pubkey[script_pubkey.len() - 1] != REGULAR_POSTFIX[1]
    {
        return false;
    }

    true
}

pub fn output_script_is_p2sh(script_pubkey: &[u8]) -> bool {
    if script_pubkey.is_empty() {
        return false;
    }

    // P2SH script prefix
    const P2SH_PREFIX: [u8; 3] = [0xA9, 0x14, 0x00];
    const P2SH_POSTFIX: [u8; 2] = [0x87, 0x00];

    if script_pubkey.len() < 23 {
        return false;
    }

    if script_pubkey[0] != P2SH_PREFIX[0]
        || script_pubkey[1] != P2SH_PREFIX[1]
        || script_pubkey[2] != P2SH_PREFIX[2]
    {
        return false;
    }

    if script_pubkey[script_pubkey.len() - 1] != P2SH_POSTFIX[1] {
        return false;
    }

    true
}

#[derive(PartialEq, Debug)]
pub enum CheckDispOutput {
    None,
    Displayable,
    Change,
}

pub fn check_output_displayable(
    script_pubkey: &[u8],
    amount: u64,
    change_address: &[u8; 20],
) -> CheckDispOutput {
    const ADDRESS_OFFSET: usize = 3;

    debug!("Check output displayable");
    debug!("ScriptPubKey: {:02X?}", script_pubkey);

    if script_pubkey.is_empty() {
        return CheckDispOutput::None;
    }

    if amount == 0 {
        return CheckDispOutput::None;
    }

    if output_script_is_op_return(script_pubkey) || output_script_is_p2sh(script_pubkey) {
        return CheckDispOutput::None;
    }

    let script_len = script_pubkey.len();
    if script_len < ADDRESS_OFFSET + 20 {
        return CheckDispOutput::None;
    }

    if &script_pubkey[ADDRESS_OFFSET..][..20] == change_address {
        debug!("Change output detected");
        return CheckDispOutput::Change;
    }

    debug!("Displayable output detected");
    CheckDispOutput::Displayable
}

pub fn get_address_from_output_script(script: &[u8]) -> Result<String, AppSW> {
    const COIN_P2PKH_VERSION: u16 = 7352;
    const ADDRESS_OFFSET: usize = 3;
    const VERSION_SIZE: usize = 2;
    const ADDRESS_SIZE: usize = 22;

    if output_script_is_op_return(script) {
        error!("Unsupported OP_RETURN script");
        return Err(AppSW::IncorrectData);
    }

    if !output_script_is_regular(script) {
        error!("Unsupported script type");
        return Err(AppSW::IncorrectData);
    }

    let mut address = [0u8; ADDRESS_SIZE];
    let version = COIN_P2PKH_VERSION.to_be_bytes();

    address[..VERSION_SIZE].copy_from_slice(&version);
    address[VERSION_SIZE..].copy_from_slice(&script[ADDRESS_OFFSET..ADDRESS_OFFSET + 20]);

    let address_base58 = public_key_to_address_base58(&address, true)?;

    Ok(address_base58)
}

pub fn check_bip44_compliance(path: &Bip32Path, is_change_path: bool) -> bool {
    const BIP44_PATH_LEN: usize = 5;
    const BIP44_PURPOSE_OFFSET: usize = 0;
    const BIP44_COIN_TYPE_OFFSET: usize = 1;
    const BIP44_ACCOUNT_OFFSET: usize = 2;
    const BIP44_CHANGE_OFFSET: usize = 3;
    const BIP44_ADDRESS_INDEX_OFFSET: usize = 4;
    const BIP44_COIN_TYPE: u32 = 133;
    const MAX_BIP44_ACCOUNT_RECOMMENDED: u32 = 100;
    const MAX_BIP44_ADDRESS_INDEX_RECOMMENDED: u32 = 50000;

    let path = path.as_ref();

    if path.len() != BIP44_PATH_LEN {
        error!("Bad Bip44 path len");
        return false;
    }

    let purpose = path[BIP44_PURPOSE_OFFSET] & 0x7FFF_FFFF;
    if purpose != 44 && purpose != 49 && purpose != 84 {
        error!("Bad Bip44 purpose");
        return false;
    }

    let coin_type = path[BIP44_COIN_TYPE_OFFSET] & 0x7FFF_FFFF;
    if coin_type != BIP44_COIN_TYPE {
        error!("Bad Bip44 coin type");
        return false;
    }

    let account = path[BIP44_ACCOUNT_OFFSET] & 0x7FFF_FFFF;
    if account > MAX_BIP44_ACCOUNT_RECOMMENDED {
        error!("Bad Bip44 account");
        return false;
    }

    let change = path[BIP44_CHANGE_OFFSET];
    if change != if is_change_path { 1 } else { 0 } {
        error!("Bad Bip44 change");
        return false;
    }

    let address_index = path[BIP44_ADDRESS_INDEX_OFFSET] & 0x7FFF_FFFF;
    if address_index > MAX_BIP44_ADDRESS_INDEX_RECOMMENDED {
        error!("Bad Bip44 address index");
        return false;
    }

    true
}
