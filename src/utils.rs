use alloc::vec::Vec;
use arrayvec::ArrayString;
use bs58::encode::EncodeTarget;

use crate::{
    log::{debug, error, info},
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

/*
unsigned char btchip_output_script_is_op_return(unsigned char *buffer) {
    return (buffer[1] == 0x6A);
}
 */

pub fn output_script_is_op_return(script_pubkey: &[u8]) -> bool {
    if script_pubkey.len() < 2 {
        return false;
    }

    script_pubkey[1] == 0x6A
}

/*
unsigned char btchip_output_script_is_p2sh(unsigned char *buffer) {
    if ((memcmp(buffer, TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE,
                    sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE)) == 0) &&
            (memcmp(buffer + sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_PRE) + 20,
                       TRANSACTION_OUTPUT_SCRIPT_P2SH_POST,
                       sizeof(TRANSACTION_OUTPUT_SCRIPT_P2SH_POST)) == 0)) {
        return 1;
    }
    return 0;
}
*/

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

// Seems not supported
pub fn output_script_is_native_witness(_script_pubkey: &[u8]) -> bool {
    false
}

/*
struct btchip_tmp_output_s {
    /** Change address if initialized */
    unsigned char changeAddress[20];
    /** Flag set if the change address was initialized */
    unsigned char changeInitialized;
    /** Flag set if the change address was checked */
    unsigned char changeChecked;
    /** Flag set if the change address can be submitted */
    unsigned char changeAccepted;
    /** Flag set if the outputs have been fragmented */
    unsigned char multipleOutput;
};
 */

#[derive(Default)]
pub struct ChangeOutputChecker {
    pub change_address: [u8; 20],
    pub change_initialized: bool,
    pub change_checked: bool,
    pub change_accepted: bool,
    pub multiple_output: bool,
}

/*
static bool check_output_displayable() {
    bool displayable = true;
    unsigned char amount[8], isOpReturn, isP2sh, isNativeSegwit, j,
        nullAmount = 1;

    for (j = 0; j < 8; j++) {
        if (btchip_context_D.currentOutput[j] != 0) {
            nullAmount = 0;
            break;
        }
    }
    if (!nullAmount) {
        btchip_swap_bytes(amount, btchip_context_D.currentOutput, 8);
        transaction_amount_add_be(btchip_context_D.totalOutputAmount,
                                  btchip_context_D.totalOutputAmount, amount);
    }
    isOpReturn =
        btchip_output_script_is_op_return(btchip_context_D.currentOutput + 8);
    isP2sh = btchip_output_script_is_p2sh(btchip_context_D.currentOutput + 8);
    isNativeSegwit = btchip_output_script_is_native_witness(
        btchip_context_D.currentOutput + 8);
    if (btchip_context_D.tmpCtx.output.changeInitialized && !isOpReturn) {
        bool changeFound = false;
        unsigned char addressOffset =
            (isNativeSegwit ? OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET
                            : isP2sh ? OUTPUT_SCRIPT_P2SH_PRE_LENGTH
                                     : OUTPUT_SCRIPT_REGULAR_PRE_LENGTH);
        if (!isP2sh &&
            memcmp(btchip_context_D.currentOutput + 8 + addressOffset,
                      btchip_context_D.tmpCtx.output.changeAddress,
                      20) == 0) {
            changeFound = true;
        } else if (isP2sh && btchip_context_D.usingSegwit) {
            unsigned char changeSegwit[22];
            changeSegwit[0] = 0x00;
            changeSegwit[1] = 0x14;
            memmove(changeSegwit + 2,
                       btchip_context_D.tmpCtx.output.changeAddress, 20);
            btchip_public_key_hash160(changeSegwit, 22, changeSegwit);
            if (memcmp(btchip_context_D.currentOutput + 8 + addressOffset,
                          changeSegwit, 20) == 0) {
                // Attempt to avoid fatal failures on Bitcoin Cash
                PRINTF("Error : Non spendable Segwit change");
                THROW(EXCEPTION);
            }
        }
        if (changeFound) {
            if (btchip_context_D.changeOutputFound) {
                PRINTF("Error : Multiple change output found");
                THROW(EXCEPTION);
            }
            btchip_context_D.changeOutputFound = true;
            displayable = false;
        }
    }

    return displayable;
}
 */

pub fn check_output_displayable(
    change_checker: &ChangeOutputChecker,
    script_pubkey: &[u8],
    amount: u64,
) -> bool {
    info!("Check output displayable");

    if script_pubkey.is_empty() {
        return false;
    }

    if amount == 0 {
        return false;
    }

    let is_op_return = output_script_is_op_return(script_pubkey);
    let is_p2sh = output_script_is_p2sh(script_pubkey);
    let is_native_segwit = output_script_is_native_witness(script_pubkey);

    if change_checker.change_initialized && !is_op_return {
        let address_offset = if is_native_segwit {
            2 // OUTPUT_SCRIPT_NATIVE_WITNESS_PROGRAM_OFFSET
        } else if is_p2sh {
            3 // OUTPUT_SCRIPT_P2SH_PRE_LENGTH
        } else {
            5 // OUTPUT_SCRIPT_REGULAR_PRE_LENGTH
        };

        let script_len = script_pubkey.len();
        if script_len < address_offset + 20 {
            return false;
        }

        let address_start = address_offset;
        let address_end = address_offset + 20;

        if !is_p2sh {
            if script_pubkey[address_start..address_end] == change_checker.change_address[..] {
                return false;
            }
        } else if is_p2sh {
            let mut change_segwit = [0u8; 22];
            change_segwit[0] = 0x00;
            change_segwit[1] = 0x14;
            change_segwit[2..22].copy_from_slice(&change_checker.change_address[..]);

            let pubkey_hash160 = public_key_hash160(&change_segwit).expect("hash160 cannot fail");

            if script_pubkey[address_start..address_end] == pubkey_hash160[..] {
                // Attempt to avoid fatal failures on Bitcoin Cash
                error!("Error : Non spendable Segwit change");
                return false;
            }
        }
    }

    true
}
