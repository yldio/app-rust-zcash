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
use crate::log::{debug, error, info};
use crate::parser::{OutputParser, Parser, ParserCtx, ParserMode, ParserSourceError};
use crate::utils::blake2b_256_pers::Blake2b256Personalization;
use crate::utils::{
    check_bip44_compliance, compress_public_key, derive_public_key, public_key_hash160, Bip32Path,
    HexSlice, PubKeyWithCC,
};
use crate::AppSW;
use alloc::string::String;
use alloc::vec::Vec;
use ledger_device_sdk::ecc::{Secp256k1, SeedDerive as _};
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::HashInit;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

use zcash_primitives::transaction::txid::ZCASH_OUTPUTS_HASH_PERSONALIZATION;
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;

#[derive(Default)]
pub struct Hashers {
    // Transparent transaction hashers
    pub prevouts_hasher: Blake2b_256,
    pub sequence_hasher: Blake2b_256,
    pub outputs_hasher: Blake2b_256,
    pub amounts_hasher: Blake2b_256,
    pub scripts_hasher: Blake2b_256,

    pub orchard_hasher: Blake2b_256,
    pub sapling_hasher: Blake2b_256,

    pub tx_full_hasher: Blake2b_256,
}

#[derive(Default)]
pub struct TxOutput {
    pub amount: u64,
    pub address: String,
    pub is_change: bool,
}

#[derive(Default)]
pub struct TxInfo {
    pub tx_version: Option<TxVersion>,
    pub branch_id: Option<BranchId>,
    pub locktime: u32,
    pub sighash_type: u8,
    pub expiry_height: u32,
    pub total_amount: u64,

    pub outputs: Vec<TxOutput>,
    pub is_change_found: bool,
    pub change_pk_hash: [u8; 20],

    pub prevouts_hash: [u8; 32],
    pub sequence_hash: [u8; 32],
    pub outputs_hash: [u8; 32],
    pub amounts_hash: [u8; 32],
    pub scripts_hash: [u8; 32],

    pub header_digest: [u8; 32],
}

#[derive(Default)]
pub struct TrustedInputInfo {
    // Transaction input to catch for a Trusted Input lookup
    pub input_idx: Option<u32>,
    pub is_input_processed: bool,
    pub amount: u64,
    pub tx_id: [u8; 32],
}

#[derive(Default)]
pub struct TxSigningState {
    pub segwit_parsed_once: bool,
}

pub struct TxContext {
    review_finished: bool,

    pub is_all_outputs_validated: bool,
    pub is_ready_to_sign: bool,
    pub tx_signing_state: TxSigningState,

    pub tx_info: TxInfo,
    pub trusted_input_info: TrustedInputInfo,
    pub hashers: Hashers,

    pub home: NbglHomeAndSettings,
    pub parser: Parser,
    pub output_parser: OutputParser,
}

impl TxContext {
    pub fn new(parser_mode: ParserMode) -> TxContext {
        TxContext {
            review_finished: false,

            tx_info: Default::default(),
            trusted_input_info: Default::default(),
            hashers: Default::default(),

            is_all_outputs_validated: false,
            is_ready_to_sign: false,
            tx_signing_state: Default::default(),

            home: Default::default(),
            parser: Parser::new(parser_mode),
            output_parser: OutputParser::new(),
        }
    }

    pub fn set_transaction_trusted_input_idx(&mut self, idx: u32) {
        self.trusted_input_info.input_idx = idx.into();
    }

    pub fn review_finished(&self) -> bool {
        self.review_finished
    }
}

pub fn handler_hash_input_start(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    continue_hashing: bool,
) -> Result<(), AppSW> {
    if continue_hashing {
        info!("Reset parser");
        ctx.parser = Parser::new(ParserMode::Signature);
    } else if first {
        info!("Init TX context");
        *ctx = TxContext::new(ParserMode::Signature);
    }

    // Try to get data from comm
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    ctx.parser
        .parse_chunk(
            &mut ParserCtx {
                tx_state: &mut ctx.tx_signing_state,
                tx_info: &mut ctx.tx_info,
                trusted_input_info: &mut ctx.trusted_input_info,
                hashers: &mut ctx.hashers,
            },
            data,
        )
        .map_err(|e| {
            error!("Error parsing/hashing TX: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                _ => AppSW::IncorrectData,
            }
        })?;

    Ok(())
}

pub fn handler_hash_input_finalize_full(
    comm: &mut Comm,
    ctx: &mut TxContext,
    is_change: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        return Err(AppSW::WrongApduLength);
    }

    let mut hash_offset = 0;

    // TODO: FIXME: move to output parser
    // Skip number of outputs on parsing start
    if !ctx.output_parser.is_started() {
        let frist_byte = data[0];

        if frist_byte < 0xfd {
            hash_offset = 1;
        } else if frist_byte == 0xfd {
            hash_offset = 3;
        } else if frist_byte == 0xfe {
            hash_offset = 5;
        }
    }

    // Check parser state
    if !ctx.parser.is_presign_ready() {
        error!("Parser not ready for finalize full");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    if is_change {
        if ctx.is_all_outputs_validated {
            // Already validated, should be prevented on the client side
            error!("All outputs already validated");
            return Err(AppSW::ConditionsOfUseNotSatisfied);
        }

        let path: Bip32Path = data.try_into()?;

        let PubKeyWithCC {
            public_key,
            public_key_len,
            ..
        } = derive_public_key(&path)?;
        let public_key = &public_key[..public_key_len];
        let comp_public_key = compress_public_key(public_key)?;

        ctx.tx_info.change_pk_hash = public_key_hash160(&comp_public_key)?;

        info!("Change pk hash: {}", HexSlice(&ctx.tx_info.change_pk_hash));

        if !check_bip44_compliance(&path, true) {
            error!("Change address path not Bip44 compliant");
            return Err(AppSW::ConditionsOfUseNotSatisfied);
        }

        return Ok(());
    }

    if !ctx.tx_signing_state.segwit_parsed_once {
        if data.len() < hash_offset {
            error!("Not enough data for hash offset");
            return Err(AppSW::WrongApduLength);
        }

        // FIMXE: move to output parser
        if !ctx.output_parser.is_started() {
            ctx.hashers
                .outputs_hasher
                .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        }

        ctx.hashers
            .outputs_hasher
            .update(&data[hash_offset..])
            .map_err(|_| AppSW::TechnicalProblem)?;
    }

    if !ctx.is_all_outputs_validated {
        ctx.output_parser
            .parse(
                &mut crate::parser::OutputParserCtx {
                    tx_info: &mut ctx.tx_info,
                    _hashers: &mut ctx.hashers,
                },
                data,
            )
            .map_err(|e| {
                error!("Error parsing TX output: {:#?}", e);
                match e.source {
                    ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                    ParserSourceError::AppSW(sw) => sw,
                    ParserSourceError::UserDenied => AppSW::Deny,
                    _ => AppSW::IncorrectData,
                }
            })?;

        if ctx.output_parser.is_finished() {
            ctx.review_finished = true;
            info!("All outputs parsed");
            ctx.is_all_outputs_validated = true;
        }
    }

    if !ctx.tx_signing_state.segwit_parsed_once && ctx.output_parser.is_finished() {
        ctx.hashers
            .outputs_hasher
            .finalize(&mut ctx.tx_info.outputs_hash)
            .map_err(|_| AppSW::TechnicalProblem)?;
        info!("Outputs hash: {}", HexSlice(&ctx.tx_info.outputs_hash));
    }

    #[allow(clippy::collapsible_if)]
    if ctx.is_all_outputs_validated {
        if !ctx.tx_signing_state.segwit_parsed_once {
            info!("Mark segwit parsed once");
            ctx.tx_signing_state.segwit_parsed_once = true;
        }
    }

    Ok(())
}

pub fn handler_hash_sign(comm: &mut Comm, ctx: &mut TxContext) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if ctx.tx_signing_state.segwit_parsed_once && !ctx.is_ready_to_sign {
        // not used 2 + locktime 4 + sighhash ty 1 +  expiry height 4
        const EXTRA_HEADER_DATA_LEN: usize = 11;

        if data.len() != EXTRA_HEADER_DATA_LEN {
            error!("Not enough data for extra header data");
            return Err(AppSW::WrongApduLength);
        }

        // Skip unused bytes
        let data = &data[2..];

        // Extract extra TX data
        // TODO: FIXME: double check endianness of locktime and expiry height
        let locktime: u32 = u32::from_be_bytes(data[..4].try_into().unwrap());
        let sighash_type: u8 = data[4];
        let expiry_height: u32 = u32::from_be_bytes(data[5..9].try_into().unwrap());

        info!("Extra TX data received:");
        info!("locktime: {}", locktime);
        info!("sighash_type: {}", sighash_type);
        info!("expiry_height: {}", expiry_height);

        ctx.tx_info.locktime = locktime;
        ctx.tx_info.sighash_type = sighash_type;
        ctx.tx_info.expiry_height = expiry_height;

        ctx.is_ready_to_sign = true;

        return Ok(());
    }

    // TODO: add more state checks before signing

    if data.is_empty() {
        error!("Not enough data for derivation path length");
        return Err(AppSW::WrongApduLength);
    }

    let path_len = data[0] as usize * 4 + 1; // Path segment 4 bytes + 1 byte length
    let path_data = &data[..path_len];
    let path: Bip32Path = path_data.try_into()?;

    if !check_bip44_compliance(&path, false) {
        error!("Output address path not Bip44 compliant");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    // TODO: skip parsing of not used data?
    let data = &data[path_len..];

    // Skip not used auth length
    let _nu = data[0];
    let data = &data[1..];

    // Read locktime && sighash type
    let _locktime: u32 = u32::from_be_bytes(data[..4].try_into().unwrap());
    let _sighash_type: u8 = data[4];

    // Finalize hash
    compute_signature_and_append(
        comm,
        &mut ctx.hashers.tx_full_hasher,
        &path,
        ctx.tx_info.sighash_type,
        true,
    )?;

    Ok(())
}

fn compute_signature_and_append(
    comm: &mut Comm,
    tx_full_hasher: &mut Blake2b_256,
    path: &Bip32Path,
    sighash_type: u8,
    deterministic_sign: bool,
) -> Result<(), AppSW> {
    let mut hash = [0u8; 32];
    tx_full_hasher
        .finalize(&mut hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    debug!("Final TX hash: {}", HexSlice(&hash));

    let (p, _chain_code) = Secp256k1::derive_from(path.as_ref());

    let (mut sig, sig_len, info) = if deterministic_sign {
        p.deterministic_sign(&hash)
    } else {
        p.sign(&hash)
    }
    .map_err(|_| AppSW::TechnicalProblem)?;

    // Store information about the parity of the 'y' coordinate
    if info != 0 {
        sig[0] |= 0x01;
    }

    debug!("Signature: {}", HexSlice(&sig[..sig_len as usize]));

    comm.append(&sig[..sig_len as usize]);
    comm.append(&[sighash_type]);

    Ok(())
}
