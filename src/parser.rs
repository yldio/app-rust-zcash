use alloc::vec::Vec;
use core::{cmp, iter, mem};
use ledger_device_sdk::hmac::HMACError;
use zcash_primitives::transaction::sighash_v5::{
    ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};

use core2::io::{Error as IoError, Read};
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::{HashError, HashInit};
use ledger_device_sdk::hmac::{sha2::Sha2_256 as HmacSha256, HMACInit};
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::txid::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_PREVOUTS_HASH_PERSONALIZATION, ZCASH_SEQUENCE_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_HASH_PERSONALIZATION, ZCASH_TX_PERSONALIZATION_PREFIX,
};
use zcash_primitives::transaction::TxVersion;
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::{BalanceError, Zatoshis};
use zcash_transparent::address::Script;
use zcash_transparent::bundle::OutPoint;

use crate::consts::{MAX_SCRIPT_SIZE, TRUSTED_INPUT_TOTAL_SIZE};
use crate::handlers::sign_tx::{Hashers, TrustedInputInfo, TxInfo, TxSigningState};
use crate::log::{debug, error, info};
use crate::settings::Settings;
use crate::utils::blake2b_256_pers::{AsWriter, Blake2b256Personalization};
use crate::utils::{check_output_displayable, secure_memcmp, HexSlice};

// TODO: use personalization consts from protocol libraries
const ZCASH_SAPLING_HASH_PERSONALIZATION: &[u8] = b"ZTxIdSaplingHash";
const ZCASH_ORCHARD_HASH_PERSONALIZATION: &[u8] = b"ZTxIdOrchardHash";

#[allow(unused)]
#[derive(Debug)]
pub enum ParserSourceError {
    Io(IoError),
    Hash(HashError),
    Hmac(HMACError),
    Balance(BalanceError),
    Custom(&'static str),
}

impl From<IoError> for ParserSourceError {
    fn from(e: IoError) -> Self {
        ParserSourceError::Io(e)
    }
}

impl From<HashError> for ParserSourceError {
    fn from(e: HashError) -> Self {
        ParserSourceError::Hash(e)
    }
}

impl From<HMACError> for ParserSourceError {
    fn from(e: HMACError) -> Self {
        ParserSourceError::Hmac(e)
    }
}

impl From<BalanceError> for ParserSourceError {
    fn from(e: BalanceError) -> Self {
        ParserSourceError::Balance(e)
    }
}

impl From<&'static str> for ParserSourceError {
    fn from(e: &'static str) -> Self {
        ParserSourceError::Custom(e)
    }
}

#[derive(Debug)]
pub struct ParserError {
    pub source: ParserSourceError,
    #[allow(unused)]
    pub file: &'static str,
    #[allow(unused)]
    pub line: u32,
}

impl ParserError {
    #[track_caller]
    pub fn from_str(reason: &'static str) -> ParserError {
        ParserError {
            source: reason.into(),
            file: file!(),
            line: line!(),
        }
    }
}

macro_rules! ok {
    ($expr:expr) => {{
        match $expr {
            Ok(v) => Ok(v),
            Err(e) => Err(ParserError {
                source: e.into(),
                file: file!(),
                line: line!(),
            }),
        }?
    }};
    ($expr:expr, $reason:literal) => {{
        match $expr {
            Ok(v) => Ok(v),
            Err(()) => Err(ParserError {
                source: $reason.into(),
                file: file!(),
                line: line!(),
            }),
        }?
    }};
}

#[derive(Debug, Default, PartialEq)]
pub enum ParserMode {
    #[default]
    TrustedInput,
    Signature,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ParserState {
    #[default]
    None,
    WaitInput,
    ProcessInputScript {
        size: usize,
        remaining_size: usize,
    },
    InputHashingDone,
    WaitOutput,
    ProcessOutputScript {
        size: usize,
        remaining_size: usize,
    },
    OutputHashingDone,
    ProcessExtra,
    TransactionParsed,
    TransactionPresignReady,
    TransactionReadyToSign,
}

struct ByteReader<'b> {
    buf: &'b [u8],
    pos: usize,
}

impl<'b> ByteReader<'b> {
    pub fn new(buf: &'b [u8]) -> Self {
        ByteReader { buf, pos: 0 }
    }

    pub fn remaining_bytes(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn _remaining_debug(&self) {
        debug!(
            "Remaining bytes (len {}) {:X?}",
            self.remaining_bytes(),
            &self.buf[self.pos..]
        );
    }

    fn remaining_slice(&self) -> &[u8] {
        &self.buf[self.pos..]
    }
}

impl Read for ByteReader<'_> {
    fn read(&mut self, buf: &'_ mut [u8]) -> core2::io::Result<usize> {
        let remaining = self.buf.len() - self.pos;
        let to_read = cmp::min(remaining, buf.len());
        buf[..to_read].copy_from_slice(&self.buf[self.pos..self.pos + to_read]);
        self.pos += to_read;

        Ok(to_read)
    }
}

pub struct ParserCtx<'ctx> {
    pub tx_state: &'ctx mut TxSigningState,
    pub tx_info: &'ctx mut TxInfo,
    pub trusted_input_info: &'ctx mut TrustedInputInfo,
    pub hashers: &'ctx mut Hashers,
}

pub struct Parser {
    mode: ParserMode,

    state: ParserState,

    input_count: usize,
    input_parsed_count: usize,
    output_count: usize,
    output_parsed_count: usize,

    sapling_spend_remaining: usize,
    sapling_output_count: usize,
    orchard_action_count: usize,

    script_bytes: Vec<u8>,
}

impl Parser {
    pub fn new(mode: ParserMode) -> Self {
        Parser {
            mode,
            state: ParserState::None,

            input_count: 0,
            input_parsed_count: 0,
            output_count: 0,
            output_parsed_count: 0,
            sapling_spend_remaining: 0,
            sapling_output_count: 0,
            orchard_action_count: 0,

            script_bytes: Vec::new(),
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == ParserState::TransactionParsed
    }

    pub fn is_presign_ready(&self) -> bool {
        self.state == ParserState::TransactionPresignReady
    }

    pub fn parse_chunk(&mut self, ctx: &mut ParserCtx<'_>, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_bytes() > 0 {
            let prev_state = self.state;

            match self.state {
                ParserState::None => self.parse_header(ctx, &mut reader)?,
                ParserState::WaitInput if self.mode == ParserMode::Signature => {
                    self.parse_input_signature_mode(ctx, &mut reader)?
                }
                ParserState::WaitInput => self.parse_input(ctx, &mut reader)?,
                ParserState::ProcessInputScript {
                    size,
                    remaining_size,
                } => self.parse_input_script(ctx, &mut reader, size, remaining_size)?,
                ParserState::InputHashingDone => {
                    self.parse_input_hashing_done(ctx, &mut reader)?;
                }
                ParserState::WaitOutput => self.parse_output(ctx, &mut reader)?,
                ParserState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => self.parse_output_script(ctx, &mut reader, size, remaining_size)?,
                ParserState::OutputHashingDone => {
                    self.parse_output_hashing_done(ctx, &mut reader)?;
                }
                ParserState::ProcessExtra => self.parse_process_extra(ctx, &mut reader)?,
                ParserState::TransactionParsed
                | ParserState::TransactionPresignReady
                | ParserState::TransactionReadyToSign => {
                    break;
                }
            }

            if self.state != prev_state {
                info!("Parser state changed: {:?} -> {:?}", prev_state, self.state);
            }
        }

        Ok(())
    }

    fn parse_header(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let version = ok!(TxVersion::read(&mut *reader));

        let value = ok!(reader.read_u32_le());
        let consensus_branch_id = ok!(BranchId::try_from(value));

        info!(
            "Transaction version: {:?}, consensus branch id: {:?}",
            version, consensus_branch_id
        );
        ctx.tx_info.tx_version = Some(version);
        ctx.tx_info.branch_id = Some(consensus_branch_id);

        let input_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Input count: {}", input_count);

        // In case of Signature mode, continue computiing Tx hash from previous state
        if self.mode == ParserMode::Signature && ctx.tx_state.segwit_parsed_once {
            info!("Resume segwit hashing for signing");
            info!("SEGWIT Version {:X?}", version);
            info!(
                "SEGWIT prevout hash {}",
                HexSlice(&ctx.tx_info.prevouts_hash)
            );
            info!(
                "SEGWIT sequence hash {}",
                HexSlice(&ctx.tx_info.sequence_hash)
            );

            info!("Compute headers hash");

            let full_hasher = &mut ctx.hashers.tx_full_hasher;
            full_hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION);

            ok!(version.write(&mut full_hasher.as_writer()));
            ok!(full_hasher.update(&u32::from(consensus_branch_id).to_le_bytes()));
            ok!(full_hasher.update(&ctx.tx_info.locktime.to_le_bytes()));
            ok!(full_hasher.update(&ctx.tx_info.expiry_height.to_le_bytes()));

            // Save header_digest
            ok!(full_hasher.finalize(&mut ctx.tx_info.header_digest));

            info!("NU5 header digest {}", HexSlice(&ctx.tx_info.header_digest));

            ctx.hashers
                .prevouts_hasher
                .init_with_perso(ZCASH_TRANSPARENT_INPUT_HASH_PERSONALIZATION);
        } else {
            // Normal flow, reinit hashers
            // Init TX hashers for V5 version
            debug!("Init Tx hashers");
            ctx.hashers
                .prevouts_hasher
                .init_with_perso(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
            ctx.hashers
                .sequence_hasher
                .init_with_perso(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
            ctx.hashers
                .outputs_hasher
                .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
            ctx.hashers
                .amounts_hasher
                .init_with_perso(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION);
            ctx.hashers
                .scripts_hasher
                .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
            ctx.hashers
                .sapling_hasher
                .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION);
            ctx.hashers
                .orchard_hasher
                .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION);
        }

        self.input_count = input_count;
        self.state = ParserState::WaitInput;

        Ok(())
    }

    fn parse_input(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let prevout = ok!(OutPoint::read(&mut *reader));

        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));

        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad input script size"));
        }

        info!("Previous outpoint: {:?}", prevout);
        info!("Script size: {}", script_size);

        self.state = ParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_input_signature_mode(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        debug!("Parsing input for signature mode...");

        let segwit_mode = ok!(reader.read_u8());
        if segwit_mode != 0x01 {
            error!(
                "Unsupported trusted input not in segwit mode: {}",
                segwit_mode
            );
            return Err(ParserError::from_str(
                "Unsupported trusted input not in segwit mode",
            ));
        } else {
            info!("Trusted input used in segwit mode");
        }

        let trusted_input_len = ok!(reader.read_u8()) as usize;
        if trusted_input_len != TRUSTED_INPUT_TOTAL_SIZE {
            return Err(ParserError::from_str("Invalid trusted input size"));
        }

        if reader.remaining_bytes() < trusted_input_len {
            return Err(ParserError::from_str("Not enough data for trusted input"));
        }

        let mut trusted_input = &reader.remaining_slice()[..trusted_input_len];
        let trusted_input_hmac = &trusted_input[trusted_input_len - 8..][..8];
        let mut computed_hmac = [0x00u8; 8];

        // Compute HMAC-SHA256 signature over the trusted input
        let mut hmac_sha256_signer = HmacSha256::new(
            &Settings
                .trusted_input_key()
                .ok_or_else(|| ParserError::from_str("Trusted input key not set"))?,
        );

        ok!(hmac_sha256_signer.update(&trusted_input[0..trusted_input_len - 8]));
        ok!(hmac_sha256_signer.finalize(&mut computed_hmac));

        info!(
            "=====> Computed trusted input HMAC: {}",
            HexSlice(&computed_hmac)
        );
        info!(
            "=====> Provided trusted input HMAC: {}",
            HexSlice(trusted_input_hmac)
        );
        if !secure_memcmp(&computed_hmac, trusted_input_hmac) {
            error!("Trusted input HMAC mismatch");
            return Err(ParserError::from_str("Trusted input HMAC mismatch"));
        }
        info!("HMACs matched");

        // Advance reader position
        ok!({
            let mut _magic = [0u8; 2];
            reader.read_exact(&mut _magic)
        });

        ok!({
            let mut _rand_bytes = [0u8; 2];
            reader.read_exact(&mut _rand_bytes)
        });

        let prevout = ok!(OutPoint::read(&mut *reader));
        info!("Previous outpoint: {:?}", prevout);
        ok!(prevout.write(ctx.hashers.prevouts_hasher.as_writer()));

        let amount = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            // Hash amount
            ok!(ctx.hashers.amounts_hasher.update(&tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });
        ctx.tx_info.total_amount = ctx.tx_info.total_amount.saturating_add(amount.into_u64());
        info!("Input amount: {:?}", amount);
        info!("New amount: {}", ctx.tx_info.total_amount);

        ok!({
            let mut _hmac = [0u8; 8];
            reader.read_exact(&mut _hmac)
        });

        // TODO: Extract common code?
        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Script size: {}", script_size);

        if ctx.tx_state.segwit_parsed_once {
            ok!(ctx
                .hashers
                .prevouts_hasher
                .update(&amount.to_i64_le_bytes()));
        }

        self.state = ParserState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_input_script(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParserState::ProcessInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad input script len"));
        }

        let mut script_sig = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_sig.0 .0 = mem::take(&mut self.script_bytes);
        ok!(script_sig.write(ctx.hashers.scripts_hasher.as_writer()));

        info!("Script sig: {:?}", script_sig);

        let sequence = {
            let mut sequence = [0; 4];
            ok!(reader.read_exact(&mut sequence));
            u32::from_le_bytes(sequence)
        };
        info!("Sequence: {:X?}", sequence);

        ok!(ctx.hashers.sequence_hasher.update(&sequence.to_le_bytes()));

        if ctx.tx_state.segwit_parsed_once {
            ok!(script_sig.write(ctx.hashers.prevouts_hasher.as_writer()));
            ok!(ctx.hashers.prevouts_hasher.update(&sequence.to_le_bytes()));
        }

        self.input_parsed_count = self.input_parsed_count.saturating_add(1);

        if self.input_count == self.input_parsed_count {
            info!("All inputs parsed");

            if self.mode == ParserMode::Signature && ctx.tx_state.segwit_parsed_once {
                let mut txin_sig_digest = [0u8; 32];
                ok!(ctx.hashers.prevouts_hasher.finalize(&mut txin_sig_digest));
                info!("txin sig digest {}", HexSlice(&txin_sig_digest));

                // Compute transparent_sig_digest
                let transparent_digest = {
                    let mut hash = [0u8; 32];

                    let mut hasher = Blake2b_256::default();
                    hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

                    ok!(hasher.update(&[ctx.tx_info.sighash_type]));
                    ok!(hasher.update(&ctx.tx_info.prevouts_hash));
                    ok!(hasher.update(&ctx.tx_info.amounts_hash));
                    ok!(hasher.update(&ctx.tx_info.scripts_hash));
                    ok!(hasher.update(&ctx.tx_info.sequence_hash));
                    ok!(hasher.update(&ctx.tx_info.outputs_hash));
                    ok!(hasher.update(&txin_sig_digest));

                    ok!(hasher.finalize(&mut hash));
                    hash
                };
                debug!("Transparent hash: {}", HexSlice(&transparent_digest));

                // Compute sapling_digest. Assume no Sapling spends or outputs are present
                let sapling_digest = {
                    let mut sapling_digest = [0u8; 32];
                    ctx.hashers
                        .sapling_hasher
                        .init_with_perso(ZCASH_SAPLING_HASH_PERSONALIZATION);
                    ok!(ctx.hashers.sapling_hasher.finalize(&mut sapling_digest));
                    sapling_digest
                };

                // Compute orchard_digest. Assume there are no Orchard actions
                let orchard_digest = {
                    let mut orchard_digest = [0u8; 32];
                    ctx.hashers
                        .orchard_hasher
                        .init_with_perso(ZCASH_ORCHARD_HASH_PERSONALIZATION);
                    ok!(ctx.hashers.orchard_hasher.finalize(&mut orchard_digest));
                    orchard_digest
                };

                let branch_id = ctx.tx_info.branch_id.expect("should be set at this point");

                // Start to compute signature_digest
                let mut personalization = [0u8; 16];
                personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
                personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

                let hasher = &mut ctx.hashers.tx_full_hasher;
                hasher.init_with_perso(&personalization);

                ok!(hasher.update(&ctx.tx_info.header_digest));
                ok!(hasher.update(&transparent_digest));
                ok!(hasher.update(&sapling_digest));
                ok!(hasher.update(&orchard_digest));

                self.state = ParserState::TransactionReadyToSign;

                return Ok(());
            }

            self.state = ParserState::InputHashingDone;
        } else {
            self.state = ParserState::WaitInput;
        }

        Ok(())
    }

    fn parse_input_hashing_done(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Input hashing done");

        if self.mode == ParserMode::Signature && !ctx.tx_state.segwit_parsed_once {
            ok!(ctx
                .hashers
                .prevouts_hasher
                .finalize(&mut ctx.tx_info.prevouts_hash));
            info!("prevout hash {}", HexSlice(&ctx.tx_info.prevouts_hash));

            ok!(ctx
                .hashers
                .sequence_hasher
                .finalize(&mut ctx.tx_info.sequence_hash));
            info!("sequence hash {}", HexSlice(&ctx.tx_info.sequence_hash));

            ok!(ctx
                .hashers
                .amounts_hasher
                .finalize(&mut ctx.tx_info.amounts_hash));
            info!("amounts hash {}", HexSlice(&ctx.tx_info.amounts_hash));

            ok!(ctx
                .hashers
                .scripts_hasher
                .finalize(&mut ctx.tx_info.scripts_hash));
            info!("scripts hash {}", HexSlice(&ctx.tx_info.scripts_hash));

            self.state = ParserState::TransactionPresignReady;

            // FIXME: HMMM??? 4 zero bytes remaining
            reader._remaining_debug();

            return Ok(());
        }

        let output_count: usize = ok!(CompactSize::read_t(&mut *reader));
        info!("Output count: {}", output_count);

        self.output_count = output_count;
        self.state = ParserState::WaitOutput;

        Ok(())
    }

    fn parse_output(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        let value = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        });

        if ctx
            .trusted_input_info
            .input_idx
            .expect("should be set at this point")
            == self.output_parsed_count as u32
        {
            ctx.trusted_input_info.amount = value.into_u64();
            info!(
                "Found amount for trusted input: {}",
                ctx.trusted_input_info.amount
            );
        }

        ok!(ctx.hashers.outputs_hasher.update(&value.to_i64_le_bytes()));
        let script_size: usize = ok!(CompactSize::read_t(&mut *reader));

        if script_size > MAX_SCRIPT_SIZE {
            return Err(ParserError::from_str("Bad output script size"));
        }

        info!("Output value: {:?}", value);
        info!("Output script size: {}", script_size);

        self.state = ParserState::ProcessOutputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        self.script_bytes.extend(iter::repeat_n(0, script_size));

        Ok(())
    }

    fn parse_output_script(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = ok!(reader.read(&mut self.script_bytes[offset..][..remaining_size]));

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParserState::ProcessOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            info!(
                "Need more output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        if size != self.script_bytes.len() {
            return Err(ParserError::from_str("Bad output script len"));
        }

        let mut script_pubkey = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_pubkey.0 .0 = mem::take(&mut self.script_bytes);
        ok!(script_pubkey.write(&mut ctx.hashers.outputs_hasher.as_writer()));

        info!("Output script pubkey: {:?}", script_pubkey);

        self.output_parsed_count = self.output_parsed_count.saturating_add(1);

        if self.output_count == self.output_parsed_count {
            info!("All outputs parsed");
            self.state = ParserState::OutputHashingDone;
        } else {
            self.state = ParserState::WaitOutput;
        }

        Ok(())
    }

    fn parse_output_hashing_done(
        &mut self,
        _ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Output hashing done");

        self.sapling_spend_remaining = ok!(CompactSize::read_t(&mut *reader));
        self.sapling_output_count = ok!(CompactSize::read_t(&mut *reader));
        self.orchard_action_count = ok!(CompactSize::read_t(&mut *reader));

        info!("Sapling spend remaining: {}", self.sapling_spend_remaining);
        info!("Sapling output count: {}", self.sapling_output_count);
        info!("Orchard action count: {}", self.orchard_action_count);

        self.state = ParserState::ProcessExtra;

        Ok(())
    }

    fn parse_process_extra(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Processing extra data...");

        ctx.tx_info.locktime = ok!(reader.read_u32_le());

        info!("Locktime: {:X?}", ctx.tx_info.locktime);

        let extra_data_len = ok!(reader.read_u8());
        if let Some(TxVersion::V5) = ctx.tx_info.tx_version {
            if extra_data_len != 4 {
                error!(
                    "Expected extra data length to be 4 for expiry height, got {}",
                    extra_data_len
                );
                return Err(ParserError::from_str(
                    "Invalid extra data length for expiry height",
                ));
            }
        }

        ctx.tx_info.expiry_height = ok!(reader.read_u32_le());
        info!("Expiry height: {:X?}", ctx.tx_info.expiry_height);

        ctx.trusted_input_info.is_input_processed = true;
        self.state = ParserState::TransactionParsed;

        self.compute_tx_id(ctx)?;

        Ok(())
    }

    fn compute_tx_id(&mut self, ctx: &mut ParserCtx<'_>) -> Result<(), ParserError> {
        let tx_version = ctx
            .tx_info
            .tx_version
            .expect("tx_version should be set at this point");
        let branch_id = ctx
            .tx_info
            .branch_id
            .expect("branch_id should be set at this point");

        if ctx.tx_info.tx_version == Some(TxVersion::V5) {
            let prevouts_hash = {
                let mut hash = [0u8; 32];
                ok!(ctx.hashers.prevouts_hasher.finalize(&mut hash));
                hash
            };
            debug!("Prevouts hash: {}", HexSlice(&prevouts_hash));

            let sequence_hash = {
                let mut hash = [0u8; 32];
                ok!(ctx.hashers.sequence_hasher.finalize(&mut hash));
                hash
            };
            debug!("Sequence hash: {}", HexSlice(&sequence_hash));

            let outputs_hash = {
                let mut hash = [0u8; 32];
                ok!(ctx.hashers.outputs_hasher.finalize(&mut hash));
                hash
            };
            debug!("Outputs hash: {}", HexSlice(&outputs_hash));

            let header_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION);

                ok!(tx_version.write(&mut hasher.as_writer()));

                ok!(hasher.update(&u32::from(branch_id).to_le_bytes()));

                ok!(hasher.update(&ctx.tx_info.locktime.to_le_bytes()));
                ok!(hasher.update(&ctx.tx_info.expiry_height.to_le_bytes()));

                ok!(hasher.finalize(&mut hash));
                hash
            };
            debug!("Header hash: {}", HexSlice(&header_hash));

            let transparent_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

                ok!(hasher.update(&prevouts_hash));
                ok!(hasher.update(&sequence_hash));
                ok!(hasher.update(&outputs_hash));

                ok!(hasher.finalize(&mut hash));
                hash
            };
            debug!("Transparent hash: {}", HexSlice(&transparent_hash));

            let sapling_hash = {
                let mut hash = [0u8; 32];
                ok!(ctx.hashers.sapling_hasher.finalize(&mut hash));
                hash
            };
            debug!("Sapling hash: {}", HexSlice(&sapling_hash));

            let orchard_hash = {
                let mut hash = [0u8; 32];
                ok!(ctx.hashers.orchard_hasher.finalize(&mut hash));
                hash
            };
            debug!("Orchard hash: {}", HexSlice(&orchard_hash));

            let mut personalization = [0u8; 16];
            personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
            personalization[12..].copy_from_slice(&u32::from(branch_id).to_le_bytes());

            let mut hasher = Blake2b_256::default();
            hasher.init_with_perso(&personalization);

            ok!(hasher.update(&header_hash));
            ok!(hasher.update(&transparent_hash));
            ok!(hasher.update(&sapling_hash));
            ok!(hasher.update(&orchard_hash));

            ok!(hasher.finalize(&mut ctx.trusted_input_info.tx_id));

            debug!(
                "Transaction ID hash: {}",
                HexSlice(&ctx.trusted_input_info.tx_id)
            );
        } else {
            error!("TX ID computation for versions other than V5 is not implemented");
            return Err(ParserError::from_str(
                "TX ID computation for versions other than V5 is not implemented",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputParseState {
    ParsingNumberOfOutputs,
    ParsingOutput,
    ProcessOutputScript { size: usize, remaining_size: usize },
    OutputProcessingDone,
}

pub struct OutputParser {
    output_count: usize,
    totoal_output_amount: u64,
    state: OutputParseState,
    pub output_parsed_count: usize,
    pub current_output_script: Vec<u8>,
    pub current_output_value: u64,
    pub current_is_displayable: bool,
}

impl OutputParser {
    pub fn new() -> Self {
        OutputParser {
            output_count: 0,
            output_parsed_count: 0,
            totoal_output_amount: 0,
            state: OutputParseState::ParsingNumberOfOutputs,
            current_output_script: Vec::new(),
            current_output_value: 0,
            current_is_displayable: false,
        }
    }

    pub fn is_finished(&self) -> bool {
        self.state == OutputParseState::OutputProcessingDone
    }

    pub fn parse(&mut self, data: &[u8]) -> Result<(), ParserError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_bytes() > 0 {
            let prev_state = self.state;

            match &self.state {
                OutputParseState::ParsingNumberOfOutputs => {
                    let output_count: usize = ok!(CompactSize::read_t(&mut reader));
                    info!("Output count: {}", output_count);
                    self.output_count = output_count;
                    self.state = OutputParseState::ParsingOutput;
                }
                OutputParseState::ParsingOutput => {
                    // Reset flags for the new output
                    self.current_is_displayable = false;

                    let value = ok!({
                        let mut tmp = [0u8; 8];
                        ok!(reader.read_exact(&mut tmp));
                        Zatoshis::from_nonnegative_i64_le_bytes(tmp)
                    });

                    info!("Output value: {:?}", value);
                    self.current_output_value = value.into_u64();
                    self.totoal_output_amount = self
                        .totoal_output_amount
                        .saturating_add(self.current_output_value);

                    let script_size: usize = ok!(CompactSize::read_t(&mut reader));

                    if script_size > MAX_SCRIPT_SIZE {
                        return Err(ParserError::from_str("Bad output script size"));
                    }

                    info!("Output script size: {}", script_size);

                    self.current_output_script.clear();
                    self.current_output_script
                        .extend(iter::repeat_n(0, script_size));

                    self.state = OutputParseState::ProcessOutputScript {
                        size: script_size,
                        remaining_size: script_size,
                    };
                }

                OutputParseState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => {
                    let new_remaining_size = {
                        let offset = size - remaining_size;
                        let len = ok!(reader
                            .read(&mut self.current_output_script[offset..][..*remaining_size]));

                        remaining_size.saturating_sub(len)
                    };

                    if new_remaining_size != 0 {
                        self.state = OutputParseState::ProcessOutputScript {
                            size: *size,
                            remaining_size: new_remaining_size,
                        };
                        info!(
                            "Need more output script bytes, remaining size: {}",
                            new_remaining_size
                        );
                        continue;
                    }

                    self.current_is_displayable = check_output_displayable(
                        &Default::default(),
                        &self.current_output_script,
                        self.current_output_value,
                    );
                    self.output_parsed_count = self.output_parsed_count.saturating_add(1);

                    if self.output_count == self.output_parsed_count {
                        info!("All outputs parsed");
                        self.state = OutputParseState::OutputProcessingDone;
                    } else {
                        self.state = OutputParseState::ParsingOutput;
                    }
                }

                OutputParseState::OutputProcessingDone => {
                    break;
                }
            }

            if self.state != prev_state {
                info!(
                    "Output parser state changed: {:?} -> {:?}",
                    prev_state, self.state
                );
            }
        }

        Ok(())
    }
}
