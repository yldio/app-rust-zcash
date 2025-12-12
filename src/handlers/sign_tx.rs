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
use crate::app_ui::sign::ui_display_tx;
use crate::parser::Parser;
use crate::utils::Bip32Path;
use crate::{AppSW, SignHashFlag};
use alloc::vec::Vec;
use ledger_device_sdk::io::Comm;
use ledger_device_sdk::nbgl::NbglHomeAndSettings;

use serde::Deserialize;
use serde_json_core::from_slice;

const MAX_TRANSACTION_LEN: usize = 510;

#[derive(Deserialize)]
pub struct Tx<'a> {
    #[allow(dead_code)]
    nonce: u64,
    pub coin: &'a str,
    pub value: u64,
    #[serde(with = "hex::serde")] // Allows JSON deserialization from hex string
    pub to: [u8; 20],
    pub memo: &'a str,
}

pub struct TxContext {
    raw_tx: Vec<u8>,
    path: Bip32Path,
    review_finished: bool,
    pub home: NbglHomeAndSettings,
    // Transaction input to catch for a Trusted Input lookup
    transaction_trusted_input_idx: Option<u32>,
    pub parser: Parser,
}

// Implement constructor for TxInfo with default values
impl TxContext {
    // Constructor
    pub fn new() -> TxContext {
        TxContext {
            raw_tx: Vec::new(),
            path: Default::default(),
            review_finished: false,
            home: Default::default(),
            transaction_trusted_input_idx: None,
            parser: Parser::new(),
        }
    }

    pub fn set_transaction_trusted_input_idx(&mut self, idx: u32) {
        self.transaction_trusted_input_idx = idx.into();
        self.parser.set_transaction_trusted_input_idx(idx);
    }

    pub fn transaction_trusted_input_idx(&self) -> Option<u32> {
        self.transaction_trusted_input_idx
    }

    // Get review status
    #[allow(dead_code)]
    pub fn finished(&self) -> bool {
        self.review_finished
    }
    // Implement reset for TxInfo
    pub fn reset(&mut self) {
        self.raw_tx.clear();
        self.path = Default::default();
        self.review_finished = false;
        self.transaction_trusted_input_idx = None;
        self.parser = Parser::new();
    }
}

pub fn handler_sign_tx(
    comm: &mut Comm,
    ctx: &mut TxContext,
    flag: SignHashFlag,
    _first: bool,
    _next: bool,
) -> Result<(), AppSW> {
    // Try to get data from comm
    let data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;
    // First chunk, try to parse the path
    if flag == SignHashFlag::Start {
        // Reset transaction context
        ctx.reset();
        // This will propagate the error if the path is invalid
        ctx.path = data.try_into()?;
        Ok(())
    // Next chunks, append data to raw_tx and return or parse
    // the transaction if it is the last chunk.
    } else {
        if ctx.raw_tx.len() + data.len() > MAX_TRANSACTION_LEN {
            return Err(AppSW::WrongApduLength);
        }

        // Append data to raw_tx
        ctx.raw_tx.extend(data);

        // If we expect more chunks, return
        if flag == SignHashFlag::Finalize {
            ctx.review_finished = false;
            Ok(())
        // Otherwise, try to parse the transaction
        } else {
            // Try to deserialize the transaction
            let (tx, _): (Tx, usize) = from_slice(&ctx.raw_tx).map_err(|_| AppSW::TxParsingFail)?;
            // Display transaction. If user approves
            // the transaction, sign it. Otherwise,
            // return a "deny" status word.
            if ui_display_tx(&tx)? {
                ctx.review_finished = true;
                compute_signature_and_append(comm, ctx)
            } else {
                ctx.review_finished = true;
                Err(AppSW::Deny)
            }
        }
    }
}

fn compute_signature_and_append(_comm: &mut Comm, _ctx: &mut TxContext) -> Result<(), AppSW> {
    Ok(())
}
