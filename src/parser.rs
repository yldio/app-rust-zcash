use alloc::vec::Vec;
use core::{cmp, hash, iter, mem};
use zcash_primitives::transaction::components::{orchard, sapling};
use zcash_primitives::transaction::sighash_v5::{
    ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION, ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION,
};

use core2::io::{self, Read};
use ledger_device_sdk::hash::blake2::Blake2b_256;
use ledger_device_sdk::hash::HashInit;
use zcash_encoding::CompactSize;
use zcash_primitives::encoding::ReadBytesExt;
use zcash_primitives::transaction::txid::{
    ZCASH_HEADERS_HASH_PERSONALIZATION, ZCASH_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_PREVOUTS_HASH_PERSONALIZATION, ZCASH_SEQUENCE_HASH_PERSONALIZATION,
    ZCASH_TRANSPARENT_HASH_PERSONALIZATION, ZCASH_TX_PERSONALIZATION_PREFIX,
};
use zcash_primitives::transaction::{Transaction, TxVersion};
use zcash_protocol::consensus::BranchId;
use zcash_protocol::value::Zatoshis;
use zcash_transparent::address::Script;
use zcash_transparent::bundle::{Authorization, Authorized, OutPoint, TxIn};

use crate::log::{debug, error, info};
use crate::utils::blake2b_256_pers::{AsWriter, Blake2b256Personalization};
use crate::utils::HexSlice;

#[derive(Debug)]
pub enum ParseError {
    InvalidFormat,
    //IoError(IoError),
}

pub enum ParseMode {
    TrustedInput,
    Signature,
}

#[derive(Debug, Default, Clone, Copy, PartialEq)]
pub enum ParseState {
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

    pub fn remaining_debug(&self) {
        debug!(
            "Remaining bytes (len {}) {:X?}",
            self.remaining_bytes(),
            &self.buf[self.pos..]
        );
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

pub struct Parser {
    mode: Option<ParseMode>,
    script_bytes: Vec<u8>,

    state: ParseState,
    tx_version: Option<TxVersion>,
    branch_id: Option<BranchId>,
    locktime: u32,
    expiry_height: u32,

    input_count: usize,
    input_parsed_count: usize,
    output_count: usize,
    output_parsed_count: usize,

    sapling_spend_remaining: usize,
    sapling_output_count: usize,
    orchard_action_count: usize,

    // Transparent transaction hashers
    prevouts_hasher: Blake2b_256,
    sequence_hasher: Blake2b_256,
    outputs_hasher: Blake2b_256,
    amounts_hasher: Blake2b_256,
    scripts_hasher: Blake2b_256,

    orchard_hasher: Blake2b_256,
    sapling_hasher: Blake2b_256,

    transaction_trusted_input_idx: Option<u32>,
    is_transaction_trusted_input_processed: bool,
    amount: u64,
    tx_id: [u8; 32],
}

impl Parser {
    pub fn new() -> Self {
        Parser {
            mode: None,
            script_bytes: Vec::new(),
            state: ParseState::None,
            tx_version: None,
            branch_id: None,
            locktime: 0,
            expiry_height: 0,

            input_count: 0,
            input_parsed_count: 0,
            output_count: 0,
            output_parsed_count: 0,
            sapling_spend_remaining: 0,
            sapling_output_count: 0,
            orchard_action_count: 0,

            prevouts_hasher: Blake2b_256::default(),
            sequence_hasher: Blake2b_256::default(),
            outputs_hasher: Blake2b_256::default(),
            amounts_hasher: Blake2b_256::default(),
            scripts_hasher: Blake2b_256::default(),
            orchard_hasher: Blake2b_256::default(),
            sapling_hasher: Blake2b_256::default(),

            transaction_trusted_input_idx: None,
            is_transaction_trusted_input_processed: false,
            amount: 0,
            tx_id: [0u8; 32],
        }
    }

    pub fn is_finished(&self) -> bool {
        matches!(self.state, ParseState::TransactionParsed)
    }

    pub fn set_transaction_trusted_input_idx(&mut self, idx: u32) {
        self.transaction_trusted_input_idx = Some(idx);
    }

    pub fn is_transaction_trusted_input_processed(&self) -> bool {
        self.is_transaction_trusted_input_processed
    }

    pub fn tx_id(&mut self) -> [u8; 32] {
        self.tx_id
    }

    pub fn amount(&self) -> u64 {
        self.amount
    }

    pub fn parse_chunk(&mut self, data: &[u8], mode: ParseMode) -> Result<(), ParseError> {
        let mut reader = ByteReader::new(data);

        while reader.remaining_bytes() > 0 {
            let mut prev_state = self.state.clone();

            match self.state {
                ParseState::None => self.parse_header(&mut reader)?,
                ParseState::WaitInput => self.parse_input(&mut reader)?,
                ParseState::ProcessInputScript {
                    size,
                    remaining_size,
                } => self.parse_input_script(&mut reader, size, remaining_size)?,
                ParseState::InputHashingDone => {
                    self.parse_input_hashing_done(&mut reader)?;
                }
                ParseState::WaitOutput => self.parse_output(&mut reader)?,
                ParseState::ProcessOutputScript {
                    size,
                    remaining_size,
                } => self.parse_output_script(&mut reader, size, remaining_size)?,
                ParseState::OutputHashingDone => {
                    self.parse_output_hashing_done(&mut reader)?;
                }
                ParseState::ProcessExtra => self.parse_process_extra(&mut reader)?,
                ParseState::TransactionParsed => {
                    break;
                }
                _ => return Err(ParseError::InvalidFormat),
            }

            if self.state != prev_state {
                info!("Parser state changed: {:?} -> {:?}", prev_state, self.state);
            }
        }

        Ok(())
    }

    fn parse_header(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        let version = TxVersion::read(&mut *reader)
            .inspect_err(|v| error!("Error reading TxVersion: {:#?}", v))
            .unwrap();

        let consensus_branch_id = reader
            .read_u32_le()
            .and_then(|value| {
                BranchId::try_from(value).map_err(|_e| {
                    io::Error::new(io::ErrorKind::InvalidData, "invalid consensus branch id")
                })
            })
            .unwrap();

        info!(
            "Transaction version: {:?}, consensus branch id: {:?}",
            version, consensus_branch_id
        );
        self.tx_version = Some(version);
        self.branch_id = Some(consensus_branch_id);

        let input_count: usize = CompactSize::read_t(&mut *reader).unwrap();
        info!("Input count: {}", input_count);

        // Init TX hashers for V5 version
        self.prevouts_hasher
            .init_with_perso(ZCASH_PREVOUTS_HASH_PERSONALIZATION);
        self.sequence_hasher
            .init_with_perso(ZCASH_SEQUENCE_HASH_PERSONALIZATION);
        self.outputs_hasher
            .init_with_perso(ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        self.amounts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_AMOUNTS_HASH_PERSONALIZATION);
        self.scripts_hasher
            .init_with_perso(ZCASH_TRANSPARENT_SCRIPTS_HASH_PERSONALIZATION);
        self.sapling_hasher.init_with_perso(b"ZTxIdSaplingHash");
        self.orchard_hasher.init_with_perso(b"ZTxIdOrchardHash");

        self.input_count = input_count;
        self.state = ParseState::WaitInput;

        Ok(())
    }

    fn parse_input(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        let prevout = OutPoint::read(&mut *reader)
            .inspect_err(|v| error!("Error reading OutPoint: {:#?}", v))
            .unwrap();

        prevout.write(self.prevouts_hasher.as_writer()).unwrap();

        let script_size: usize = CompactSize::read_t(&mut *reader).unwrap();

        info!("Previous outpoint: {:?}", prevout);
        info!("Script size: {}", script_size);

        self.state = ParseState::ProcessInputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        // Allocate script bytes buffer
        self.script_bytes.extend(iter::repeat(0).take(script_size));

        Ok(())
    }

    fn parse_input_script(
        &mut self,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParseError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = reader
                .read(&mut self.script_bytes[offset..][..remaining_size])
                .inspect_err(|v| error!("Error reading script bytes: {:#?}", v))
                .unwrap();

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParseState::ProcessInputScript {
                size,
                remaining_size: new_remaining_size,
            };
            debug!(
                "Need more script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        assert_eq!(size, self.script_bytes.len());

        let mut script_sig = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_sig.0 .0 = mem::take(&mut self.script_bytes);
        script_sig.write(self.scripts_hasher.as_writer()).unwrap();

        info!("Script sig: {:?}", script_sig);

        let sequence = {
            let mut sequence = [0; 4];
            reader.read_exact(&mut sequence).unwrap();
            u32::from_le_bytes(sequence)
        };
        info!("Sequence: {:X?}", sequence);

        self.sequence_hasher
            .update(&sequence.to_le_bytes())
            .unwrap();

        self.input_parsed_count = self.input_parsed_count.saturating_add(1);

        if self.input_count == self.input_parsed_count {
            info!("All inputs parsed");
            self.state = ParseState::InputHashingDone;
        } else {
            self.state = ParseState::WaitInput;
        }

        Ok(())
    }

    fn parse_input_hashing_done(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        info!("Input hashing done");

        let output_count: usize = CompactSize::read_t(&mut *reader).unwrap();
        info!("Output count: {}", output_count);

        self.output_count = output_count;
        self.state = ParseState::WaitOutput;

        Ok(())
    }

    fn parse_output(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        let value = {
            let mut tmp = [0u8; 8];
            reader.read_exact(&mut tmp).unwrap();
            Zatoshis::from_nonnegative_i64_le_bytes(tmp)
        }
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "value out of range"))
        .unwrap();

        if self
            .transaction_trusted_input_idx
            .expect("should be set at this point")
            == self.output_parsed_count as u32
        {
            self.amount = value.into_u64();
            info!("Found amount for trusted input: {}", self.amount);
        }

        self.outputs_hasher
            .update(&value.to_i64_le_bytes())
            .unwrap();

        let script_size: usize = CompactSize::read_t(&mut *reader).unwrap();

        info!("Output value: {:?}", value);
        info!("Output script size: {}", script_size);

        self.state = ParseState::ProcessOutputScript {
            size: script_size,
            remaining_size: script_size,
        };
        self.script_bytes.clear();
        self.script_bytes.extend(iter::repeat(0).take(script_size));

        Ok(())
    }

    fn parse_output_script(
        &mut self,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParseError> {
        let new_remaining_size = {
            let offset = size - remaining_size;
            let len = reader
                .read(&mut self.script_bytes[offset..][..remaining_size])
                .inspect_err(|v| error!("Error reading script bytes: {:#?}", v))
                .unwrap();

            remaining_size.saturating_sub(len)
        };

        if new_remaining_size != 0 {
            self.state = ParseState::ProcessOutputScript {
                size,
                remaining_size: new_remaining_size,
            };
            info!(
                "Need more output script bytes, remaining size: {}",
                new_remaining_size
            );
            return Ok(());
        }

        assert_eq!(size, self.script_bytes.len());

        let mut script_pubkey = Script::default();
        // NOTE: take/deallocate self.script_bytes here
        script_pubkey.0 .0 = mem::take(&mut self.script_bytes);
        script_pubkey
            .write(&mut self.outputs_hasher.as_writer())
            .unwrap();

        info!("Output script pubkey: {:?}", script_pubkey);

        self.output_parsed_count = self.output_parsed_count.saturating_add(1);

        if self.output_count == self.output_parsed_count {
            info!("All outputs parsed");
            self.state = ParseState::OutputHashingDone;
        } else {
            self.state = ParseState::WaitOutput;
        }

        Ok(())
    }

    fn parse_output_hashing_done(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        info!("Output hashing done");

        self.sapling_spend_remaining = CompactSize::read_t(&mut *reader).unwrap();
        self.sapling_output_count = CompactSize::read_t(&mut *reader).unwrap();
        self.orchard_action_count = CompactSize::read_t(&mut *reader).unwrap();

        info!("Sapling spend remaining: {}", self.sapling_spend_remaining);
        info!("Sapling output count: {}", self.sapling_output_count);
        info!("Orchard action count: {}", self.orchard_action_count);

        self.state = ParseState::ProcessExtra;

        Ok(())
    }

    fn parse_process_extra(&mut self, reader: &mut ByteReader<'_>) -> Result<(), ParseError> {
        info!("Processing extra data...");

        self.locktime = reader.read_u32_le().unwrap();

        info!("Locktime: {:X?}", self.locktime);

        let extra_data_len = reader.read_u8().unwrap();
        if let Some(TxVersion::V5) = self.tx_version {
            if extra_data_len != 4 {
                error!(
                    "Expected extra data length to be 4 for expiry height, got {}",
                    extra_data_len
                );
                return Err(ParseError::InvalidFormat);
            }
        }

        self.expiry_height = reader.read_u32_le().unwrap();
        info!("Expiry height: {:X?}", self.expiry_height);

        self.is_transaction_trusted_input_processed = true;
        self.state = ParseState::TransactionParsed;

        self.compute_tx_id()?;

        Ok(())
    }

    fn compute_tx_id(&mut self) -> Result<(), ParseError> {
        if self.tx_version == Some(TxVersion::V5) {
            let prevouts_hash = {
                let mut hash = [0u8; 32];
                self.prevouts_hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Prevouts hash: {}", HexSlice(&prevouts_hash));

            let sequence_hash = {
                let mut hash = [0u8; 32];
                self.sequence_hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Sequence hash: {}", HexSlice(&sequence_hash));

            let outputs_hash = {
                let mut hash = [0u8; 32];
                self.outputs_hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Outputs hash: {}", HexSlice(&outputs_hash));

            let header_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                hasher.init_with_perso(ZCASH_HEADERS_HASH_PERSONALIZATION);

                self.tx_version
                    .unwrap()
                    .write(&mut hasher.as_writer())
                    .unwrap();
                hasher
                    .update(&u32::from(self.branch_id.unwrap()).to_le_bytes())
                    .unwrap();
                hasher.update(&self.locktime.to_le_bytes()).unwrap();
                hasher.update(&self.expiry_height.to_le_bytes()).unwrap();

                hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Header hash: {}", HexSlice(&header_hash));

            let transparent_hash = {
                let mut hash = [0u8; 32];

                let mut hasher = Blake2b_256::default();
                hasher.init_with_perso(ZCASH_TRANSPARENT_HASH_PERSONALIZATION);

                hasher.update(&prevouts_hash).unwrap();
                hasher.update(&sequence_hash).unwrap();
                hasher.update(&outputs_hash).unwrap();

                hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Transparent hash: {}", HexSlice(&transparent_hash));

            let sapling_hash = {
                let mut hash = [0u8; 32];
                self.sapling_hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Sapling hash: {}", HexSlice(&sapling_hash));

            let orchard_hash = {
                let mut hash = [0u8; 32];
                self.orchard_hasher.finalize(&mut hash).unwrap();
                hash
            };
            debug!("Orchard hash: {}", HexSlice(&orchard_hash));

            let mut personalization = [0u8; 16];
            personalization[..12].copy_from_slice(ZCASH_TX_PERSONALIZATION_PREFIX);
            personalization[12..]
                .copy_from_slice(&u32::from(self.branch_id.unwrap()).to_le_bytes());

            let mut hasher = Blake2b_256::default();
            hasher.init_with_perso(&personalization);

            hasher.update(&header_hash).unwrap();
            hasher.update(&transparent_hash).unwrap();
            hasher.update(&sapling_hash).unwrap();
            hasher.update(&orchard_hash).unwrap();

            hasher.finalize(&mut self.tx_id).unwrap();

            debug!("Transaction ID hash: {}", HexSlice(&self.tx_id));
        } else {
            error!("TX ID computation for versions other than V5 is not implemented");
            return Err(ParseError::InvalidFormat);
        }

        Ok(())
    }
}
