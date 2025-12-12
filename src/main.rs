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

#![no_std]
#![no_main]

mod app_ui {
    pub mod address;
    pub mod menu;
    pub mod sign;
}
mod handlers {
    pub mod get_public_key;
    pub mod get_trusted_input;
    pub mod get_version;
    pub mod sign_msg;
    pub mod sign_tx;
}

mod consts;
mod log;
mod parser;
mod settings;
mod utils;

use app_ui::menu::ui_menu_main;
use handlers::{
    get_public_key::handler_get_public_key,
    get_version::handler_get_version,
    sign_tx::{handler_sign_tx, TxContext},
};
use ledger_device_sdk::{
    io::{ApduHeader, Comm, Reply},
    nbgl::init_comm,
    random::rand_bytes,
};

ledger_device_sdk::set_panic!(panic_handler);

// Required for using String, Vec, format!...
extern crate alloc;

use ledger_device_sdk::nbgl::{NbglReviewStatus, StatusType};

use crate::{
    consts::{
        INS_GET_FIRMWARE_VERSION, INS_GET_TRUSTED_INPUT, INS_GET_WALLET_PUBLIC_KEY,
        INS_HASH_INPUT_FINALIZE, INS_HASH_INPUT_FINALIZE_FULL, INS_HASH_INPUT_START, INS_HASH_SIGN,
        INS_SIGN_MESSAGE, ZCASH_CLA,
    },
    handlers::{get_trusted_input::handler_get_trusted_input, sign_msg::handler_sign_msg},
    log::{debug, error},
    settings::Settings,
};

pub const P1_FIRST: u8 = 0x00;
pub const P1_NEXT: u8 = 0x80;

// Application status words.
#[repr(u16)]
#[derive(Clone, Copy, PartialEq)]
pub enum AppSW {
    PinRemainingAttempts = 0x63C0,
    WrongApduLength = 0x6700,
    CommandIncompatibleFileStructure = 0x6981,
    SecurityStatusNotSatisfied = 0x6982,
    IncorrectData = 0x6A80,
    NotEnoughMemorySpace = 0x6A84,
    ReferencedDataNotFound = 0x6A88,
    FileAlreadyExists = 0x6A89,
    SwapWithoutTrustedInputs = 0x6A8A,
    WrongP1P2 = 0x6B00,
    InsNotSupported = 0x6D00,
    ClaNotSupported = 0x6E00,
    MemoryProblem = 0x9240,
    NoEfSelected = 0x9400,
    InvalidOffset = 0x9402,
    FileNotFound = 0x9404,
    InconsistentFile = 0x9408,
    AlgorithmNotSupported = 0x9484,
    InvalidKcv = 0x9485,
    CodeNotInitialized = 0x9802,
    AccessConditionNotFulfilled = 0x9804,
    ContradictionSecretCodeStatus = 0x9808,
    ContradictionInvalidation = 0x9810,
    CodeBlocked = 0x9840,
    MaxValueReached = 0x9850,
    GpAuthFailed = 0x6300,
    Licensing = 0x6F42,
    Halted = 0x6FAA,
    Deny = 0x6985,
    //TxWrongLength = 0x6F00,
    TechnicalProblem = 0x6F00,
    VersionParsingFail = 0x6F01,
    TxParsingFail = 0x6F02,
    Ok = 0x9000,
}

impl From<AppSW> for Reply {
    fn from(sw: AppSW) -> Reply {
        Reply(sw as u16)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SignHashFlag {
    Start = INS_HASH_INPUT_START,
    Finalize = INS_HASH_INPUT_FINALIZE,
    Sign = INS_HASH_SIGN,
    FinalizeFull = INS_HASH_INPUT_FINALIZE_FULL,
}

/// Possible input commands received through APDUs.
pub enum Instruction {
    GetVersion,
    GetPubkey {
        display: bool,
    },
    GetTrustedInput {
        first: bool,
        next: bool,
    },
    SignTx {
        flag: SignHashFlag,
        first: bool,
        next: bool,
    },
    SignMessage {
        first: bool,
        next: bool,
    },
}

impl TryFrom<ApduHeader> for Instruction {
    type Error = AppSW;

    /// APDU parsing logic.
    ///
    /// Parses INS, P1 and P2 bytes to build an [`Instruction`]. P1 and P2 are translated to
    /// strongly typed variables depending on the APDU instruction code. Invalid INS, P1 or P2
    /// values result in errors with a status word, which are automatically sent to the host by the
    /// SDK.
    ///
    /// This design allows a clear separation of the APDU parsing logic and commands handling.
    ///
    /// Note that CLA is not checked here. Instead the method [`Comm::set_expected_cla`] is used in
    /// [`sample_main`] to have this verification automatically performed by the SDK.
    fn try_from(value: ApduHeader) -> Result<Self, Self::Error> {
        match (value.ins, value.p1, value.p2) {
            (INS_GET_FIRMWARE_VERSION, 0, 0) => Ok(Instruction::GetVersion),
            (INS_GET_WALLET_PUBLIC_KEY, 0 | 1, 0) => Ok(Instruction::GetPubkey {
                display: value.p1 != 0,
            }),
            (INS_GET_TRUSTED_INPUT, p1, _) => Ok(Instruction::GetTrustedInput {
                first: p1 == P1_FIRST,
                next: p1 == P1_NEXT,
            }),
            (
                INS_HASH_INPUT_START
                | INS_HASH_INPUT_FINALIZE
                | INS_HASH_SIGN
                | INS_HASH_INPUT_FINALIZE_FULL,
                p1,
                0,
            ) => {
                let state = match value.ins {
                    INS_HASH_INPUT_START => SignHashFlag::Start,
                    INS_HASH_INPUT_FINALIZE => SignHashFlag::Finalize,
                    INS_HASH_SIGN => SignHashFlag::Sign,
                    INS_HASH_INPUT_FINALIZE_FULL => SignHashFlag::FinalizeFull,
                    _ => unreachable!(),
                };
                Ok(Instruction::SignTx {
                    flag: state,
                    first: p1 == P1_FIRST,
                    next: p1 == P1_NEXT,
                })
            }
            (INS_SIGN_MESSAGE, p1, 0) => Ok(Instruction::SignMessage {
                first: p1 == P1_FIRST,
                next: p1 == P1_NEXT,
            }),
            (_, _, _) => {
                if value.p1 != 0 || value.p2 != 0 {
                    return Err(AppSW::WrongP1P2);
                }
                Err(AppSW::InsNotSupported)
            }
        }
    }
}

fn show_status_and_home_if_needed(ins: &Instruction, tx_ctx: &mut TxContext, status: &AppSW) {
    let (show_status, status_type) = match (ins, status) {
        (Instruction::GetPubkey { display: true }, AppSW::Deny | AppSW::Ok) => {
            (true, StatusType::Address)
        }
        (Instruction::SignTx { .. }, AppSW::Deny | AppSW::Ok) if tx_ctx.finished() => {
            (true, StatusType::Transaction)
        }
        (_, _) => (false, StatusType::Transaction),
    };

    if show_status {
        let success = *status == AppSW::Ok;
        NbglReviewStatus::new()
            .status_type(status_type)
            .show(success);

        // call home.show_and_return() to show home and setting screen
        tx_ctx.home.show_and_return();
    }
}

fn try_init_trusted_input_key_storage() {
    if Settings.trusted_input_key().is_none() {
        let mut rng = [0u8; 32];
        rand_bytes(&mut rng);

        Settings.set_trusted_input_key(rng);
        debug!("Initialized trusted input key storage");
    }
}

#[no_mangle]
extern "C" fn sample_main() {
    // Create the communication manager, and configure it to accept only APDU from the 0xe0 class.
    // If any APDU with a wrong class value is received, comm will respond automatically with
    // BadCla status word.
    let mut comm = Comm::new().set_expected_cla(ZCASH_CLA);
    init_comm(&mut comm);

    try_init_trusted_input_key_storage();

    debug!("App started");

    let mut tx_ctx = TxContext::new();

    tx_ctx.home = ui_menu_main(&mut comm);
    tx_ctx.home.show_and_return();

    loop {
        let ins: Instruction = comm.next_command();

        let _status = match handle_apdu(&mut comm, &ins, &mut tx_ctx) {
            Ok(()) => {
                comm.reply_ok();
                AppSW::Ok
            }
            Err(sw) => {
                comm.reply(sw);
                sw
            }
        };
        show_status_and_home_if_needed(&ins, &mut tx_ctx, &_status);
    }
}

fn handle_apdu(comm: &mut Comm, ins: &Instruction, ctx: &mut TxContext) -> Result<(), AppSW> {
    match ins {
        Instruction::GetVersion => handler_get_version(comm),
        Instruction::GetPubkey { display } => handler_get_public_key(comm, *display),
        Instruction::GetTrustedInput { first, next } => {
            handler_get_trusted_input(comm, ctx, *first, *next)
        }
        Instruction::SignTx { flag, first, next } => {
            handler_sign_tx(comm, ctx, *flag, *first, *next)
        }
        Instruction::SignMessage { first, next } => handler_sign_msg(comm, ctx, *first, *next),
    }
}

/// In case of runtime problems, return an internal error and exit the app
#[inline]
pub fn panic_handler(info: &PanicInfo) -> ! {
    error!("Panicking: {:?}\n", info);
    ledger_device_sdk::exiting_panic(info)
}
