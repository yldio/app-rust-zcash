use crate::zip32::{zip32_orchard_derive, ZIP32_CHAIN_CODE_SIZE, ZIP32_SK_SIZE};
use crate::AppSW;
use ledger_device_sdk::io::Comm;

/// Maximum BIP32 path depth accepted by this handler.
const MAX_PATH_DEPTH: usize = 10;

/// Maps a raw bolos error code from `sys_hdkey_derive` to an [`AppSW`].
fn map_bolos_err(e: u32) -> AppSW {
    match e {
        0x550B => AppSW::SecurityStatusNotSatisfied, // PIN not validated
        0x4215 => AppSW::Deny,                       // Forbidden derivation
        0x420E | 0x4210 | 0x4213 => AppSW::IncorrectData, // Bad path / param
        _ => AppSW::TechnicalProblem,
    }
}

/// Handler for `INS_ZIP32_ORCHARD_DERIVE` (0xB8).
///
/// # Request data
/// ```text
/// [n: u8]  [index_0: u32 BE] ... [index_{n-1}: u32 BE]
/// ```
/// (Same layout as BIP32 path produced by `ragger.bip.pack_derivation_path`.)
///
/// # Response (SW=0x9000)
/// ```text
/// [sk: 32 bytes] [chain_code: 32 bytes]
/// ```
///
/// # Errors
/// Returns an appropriate [`AppSW`] status word on failure; the response body
/// is empty.
pub fn handler_zip32_orchard_derive(comm: &mut Comm) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    // Parse path: first byte = number of 4-byte components
    if data.is_empty() {
        return Err(AppSW::WrongApduLength);
    }
    let path_len = data[0] as usize;
    if path_len > MAX_PATH_DEPTH {
        return Err(AppSW::IncorrectData);
    }
    let required = 1 + path_len * 4;
    if data.len() < required {
        return Err(AppSW::WrongApduLength);
    }

    let mut path = [0u32; MAX_PATH_DEPTH];
    for i in 0..path_len {
        let off = 1 + i * 4;
        path[i] = u32::from_be_bytes(data[off..off + 4].try_into().unwrap());
    }

    let mut sk = [0u8; ZIP32_SK_SIZE];
    let mut cc = [0u8; ZIP32_CHAIN_CODE_SIZE];

    if let Err(e) = zip32_orchard_derive(&path[..path_len], &mut sk, Some(&mut cc)) {
        comm.append(&e.to_le_bytes());
        return Err(map_bolos_err(e));
    }

    comm.append(&sk);
    comm.append(&cc);
    Ok(())
}
