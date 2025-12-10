/*****************************************************************************
 *   Ledger App Boilerplate Rust.
 *   (c) 2023 Ledger SAS.
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *****************************************************************************/

use crate::app_ui::address::ui_display_pk;
use crate::log::debug;
use crate::utils::{
    compress_public_key, derive_public_key, public_key_to_address_base58, Bip32Path, PubKeyWithCC,
};
use crate::AppSW;
use ledger_device_sdk::io::Comm;

pub fn handler_get_public_key(comm: &mut Comm, display: bool) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    let path: Bip32Path = data.try_into()?;

    let PubKeyWithCC {
        public_key,
        public_key_len,
        chain_code,
    } = derive_public_key(&path)?;
    let public_key = &public_key[..public_key_len];

    let comp_public_key = compress_public_key(public_key)?;
    let address_str = public_key_to_address_base58::<150>(&comp_public_key)?;

    // Display address on device if requested
    if display && !ui_display_pk(&address_str)? {
        return Err(AppSW::Deny);
    }

    comm.append(&[public_key_len as u8]);
    comm.append(public_key);

    debug!("Public Key: {:02X?}", public_key);

    let addr_len = address_str.len() as u8;
    comm.append(&[addr_len]);
    comm.append(address_str.as_bytes());

    debug!("Address: {}", address_str);

    // Don't encode chain code length, it's always 32 bytes
    comm.append(&chain_code);

    debug!("Chain Code: {:02X?}", chain_code);

    Ok(())
}
