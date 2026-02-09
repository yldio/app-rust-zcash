use crate::{
    log::debug,
    utils::{hashers::Hash160, output_script_is_op_return, output_script_is_regular},
    AppSW,
};

pub const TRANSPARENT_ADDRESS_B58_LEN: usize = 35;

type P2pkhPayload = [u8; 22];

pub struct Base58Address {
    pub bytes: [u8; TRANSPARENT_ADDRESS_B58_LEN],
    pub len: usize,
}

impl Base58Address {
    // T-address P2PKH prefix (mainnet)
    const P2PKH_PREFIX: [u8; 2] = [0x1C, 0xB8];
    // T-address P2PKH prefix (testnet)
    const _P2PKH_PREFIX: [u8; 2] = [0x1D, 0x25];

    pub fn as_str(&self) -> Result<&str, AppSW> {
        core::str::from_utf8(&self.bytes[..self.len]).map_err(|_| AppSW::ExecutionError)
    }

    pub fn from_output_script(script: &[u8]) -> Result<Base58Address, AppSW> {
        let payload = Self::output_script_to_p2pkh_payload(script)?;
        Self::from_p2pkh_payload(&payload)
    }

    pub fn from_public_key_hash(public_key_hash160: &Hash160) -> Result<Base58Address, AppSW> {
        // PREFIX(2) + HASH160(20)
        let mut buf = [0u8; 22];

        buf[0] = Self::P2PKH_PREFIX[0];
        buf[1] = Self::P2PKH_PREFIX[1];
        buf[2..22].copy_from_slice(public_key_hash160);

        Self::from_p2pkh_payload(&buf)
    }

    fn from_p2pkh_payload(payload: &P2pkhPayload) -> Result<Self, AppSW> {
        let mut buf = [0u8; 26];

        // payload
        buf[..22].copy_from_slice(payload);

        // checksum
        let checksum = Self::compute_checksum(&buf[..22]);
        buf[22..26].copy_from_slice(&checksum);

        // base58
        let mut out = [0u8; TRANSPARENT_ADDRESS_B58_LEN];
        let written = bs58::encode(&buf)
            .onto(&mut out[..])
            .map_err(|_| AppSW::IncorrectData)?;

        Ok(Base58Address {
            bytes: out,
            len: written,
        })
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

    fn output_script_to_p2pkh_payload(script: &[u8]) -> Result<P2pkhPayload, AppSW> {
        const ADDRESS_OFFSET: usize = 3;

        if output_script_is_op_return(script) {
            return Err(AppSW::IncorrectData);
        }

        if !output_script_is_regular(script) {
            return Err(AppSW::IncorrectData);
        }

        let mut payload = [0u8; 22];
        payload[0] = Self::P2PKH_PREFIX[0];
        payload[1] = Self::P2PKH_PREFIX[1];
        payload[2..].copy_from_slice(&script[ADDRESS_OFFSET..ADDRESS_OFFSET + 20]);

        Ok(payload)
    }
}
