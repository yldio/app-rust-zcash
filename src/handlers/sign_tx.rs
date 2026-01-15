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
use crate::app_ui::sign::ui_display_tx_output;
use crate::log::{debug, error, info};
use crate::parser::{OutputParser, Parser, ParserCtx, ParserMode, ParserSourceError};
use crate::utils::blake2b_256_pers::Blake2b256Personalization;
use crate::utils::{Bip32Path, HexSlice};
use crate::AppSW;
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
pub struct TxInfo {
    pub tx_version: Option<TxVersion>,
    pub branch_id: Option<BranchId>,
    pub locktime: u32,
    pub sighash_type: u8,
    pub expiry_height: u32,
    pub total_amount: u64,

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
    path: Bip32Path,
    review_finished: bool,
    summary: TransactionSummary,

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
            path: Default::default(),
            review_finished: false,
            summary: Default::default(),

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

    pub fn reset(&mut self, _mode: ParserMode) {
        todo!()
    }
}

pub fn handler_hash_input_start(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    reset_parser: bool,
) -> Result<(), AppSW> {
    if first {
        info!("Init TX context");
        *ctx = TxContext::new(ParserMode::Signature);
    } else if reset_parser {
        info!("Reset parser");
        ctx.parser = Parser::new(ParserMode::Signature);
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

#[derive(Default)]
struct TransactionSummary {
    active: u8,
    pay_to_address_version: u8,
    pay_to_script_hash_version: u8,
    authorization_hash: [u8; 32],
    //key_path: [u8; 41], // MAX_BIP32_PATH_LENGTH
    transaction_nonce: [u8; 8],
    message_length: u16,
    sighash_type: u8,
}

pub fn handler_hash_input_finalize_full(
    comm: &mut Comm,
    ctx: &mut TxContext,
    is_change_flag: bool,
) -> Result<(), AppSW> {
    handler_hash_input_finalize_full_internal(comm, ctx, is_change_flag)
}

fn handler_hash_input_finalize_full_internal(
    comm: &mut Comm,
    ctx: &mut TxContext,
    is_change_flag: bool,
) -> Result<(), AppSW> {
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        return Err(AppSW::WrongApduLength);
    }

    let frist_byte = data[0];
    let mut hash_offset = 0;

    if frist_byte < 0xfd {
        hash_offset = 1;
    } else if frist_byte == 0xfd {
        hash_offset = 3;
    } else if frist_byte == 0xfe {
        hash_offset = 5;
    }

    // Check parser state
    if !ctx.parser.is_presign_ready() {
        error!("Parser not ready for finalize full");
        return Err(AppSW::ConditionsOfUseNotSatisfied);
    }

    // NOTE: probably should be stored in ctx
    // OR EVEN BETTER MOVE TO PARSER !!!
    let mut hasher_full = Blake2b_256::default();

    if !ctx.tx_signing_state.segwit_parsed_once {
        if data.len() < hash_offset {
            error!("Not enough data for hash offset");
            return Err(AppSW::WrongApduLength);
        }

        hasher_full.init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        hasher_full
            .update(&data[hash_offset..])
            .map_err(|_| AppSW::TechnicalProblem)?;
    }

    if !ctx.is_all_outputs_validated {
        ctx.output_parser.parse(data).unwrap();
        // TODO: proper display
        if ctx.output_parser.current_is_displayable {
            //if !ui_display_tx_output(
            //    ctx.output_parser.output_parsed_count,
            //    ctx.output_parser.current_output_value,
            //    "XXXXXXXXXXXXXXXX",
            //    424242, // TODO fees
            //    is_change_flag,
            //)? {
            //    return Err(AppSW::Deny);
            //}
        }

        if ctx.output_parser.is_finished() {
            info!("All outputs parsed");
            ctx.is_all_outputs_validated = true;
        }
    }

    if !ctx.tx_signing_state.segwit_parsed_once {
        hasher_full
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

        // Extract additional TX data
        let locktime: u32 = u32::from_be_bytes(data[..4].try_into().unwrap());
        let sighash_type: u8 = data[4];
        let expiry_height: u32 = u32::from_be_bytes(data[5..9].try_into().unwrap());

        info!("locktime: {}", locktime);
        info!("sighash_type: {}", sighash_type);
        info!("expiry_height: {}", expiry_height);

        ctx.tx_info.locktime = locktime;
        ctx.tx_info.sighash_type = sighash_type;
        ctx.tx_info.expiry_height = expiry_height;

        ctx.is_ready_to_sign = true;

        return Ok(());
    }

    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if data.is_empty() {
        error!("Not enough data for sign hash");
        return Err(AppSW::WrongApduLength);
    }

    let path_len = data[0] as usize * 4 + 1; // Path segment 4 bytes + 1 byte length
    let path_data = &data[..path_len];
    let path: Bip32Path = path_data.try_into()?;

    let data = &data[path_len..];

    // Skip not used auth length
    let _nu = data[0];
    let data = &data[1..];

    // Read locktime && sighash type
    let _locktime: u32 = u32::from_be_bytes(data[..4].try_into().unwrap());
    let _sighash_type: u8 = data[4];

    // Finalize hash
    sign_tx(&mut ctx.hashers.tx_full_hasher)?;

    Ok(())
}

fn sign_tx(tx_full_hasher: &mut Blake2b_256) -> Result<(), AppSW> {
    let mut hash = [0u8; 32];
    tx_full_hasher
        .finalize(&mut hash)
        .map_err(|_| AppSW::TechnicalProblem)?;

    debug!("Final TX hash: {}", HexSlice(&hash));

    // Sign tx hash
    // TODO:

    Ok(())
}
