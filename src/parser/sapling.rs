use zcash_primitives::transaction::txid::ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION;
use zcash_primitives::transaction::txid::ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION;
use zcash_primitives::transaction::txid::{
    ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION, ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION,
    ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION,
};
use zcash_primitives::transaction::txid::{
    ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION, ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION,
};
use zcash_protocol::value::ZatBalance;

use super::*;

impl Parser {
    pub fn parse_sapling(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Process sapling");

        let sapling_balance: ZatBalance = ok!({
            let mut tmp = [0u8; 8];
            ok!(reader.read_exact(&mut tmp));
            ZatBalance::from_i64_le_bytes(tmp)
        });

        info!("Sapling balance: {:?}", sapling_balance);
        self.sapling_balance = sapling_balance.into();

        if self.sapling_spend_count > 0 {
            let mut anchor = [0u8; 32];
            ok!(reader.read_exact(&mut anchor));

            // Init hashers
            ctx.hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_SPENDS_COMPACT_HASH_PERSONALIZATION);
            ctx.hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_SAPLING_SPENDS_NONCOMPACT_HASH_PERSONALIZATION);

            self.state = ParserState::ProcessSaplingSpends { anchor };
        } else if self.sapling_output_count > 0 {
            // No spends
            // Get empty sapling spends digest
            let sapling_spend = {
                let mut sapling_spend = [0u8; 32];
                let mut tmp_spend_hasher = Blake2b_256::new();
                tmp_spend_hasher.init_with_perso(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
                ok!(tmp_spend_hasher.finalize(&mut sapling_spend));

                sapling_spend
            };

            // Update sapling hasher with empty spends digest
            ok!(ctx.hashers.sapling_hasher.update(&sapling_spend));

            // Init outputs hasher
            ctx.hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);

            self.state = ParserState::ProcessSaplingOutputsCompact;
        } else {
            self.state = ParserState::ProcessExtra;
        }

        Ok(())
    }

    pub fn parse_sapling_spends(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        anchor: [u8; 32],
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling spends, remaining: {}",
            self.sapling_spend_count - self.sapling_spend_parsed_count
        );

        // update non compact hash with cv
        ok!(ctx.hashers.tx_non_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        // update non compact hash with anchor
        ok!(ctx.hashers.tx_non_compact_hasher.update(&anchor));

        // update compact hash with nullifier
        ok!(ctx.hashers.tx_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        // update non compact hash with rk
        ok!(ctx.hashers.tx_non_compact_hasher.update(&{
            let mut tmp = [0u8; 32];
            ok!(reader.read_exact(&mut tmp));
            tmp
        }));

        self.sapling_spend_parsed_count += 1;

        if self.sapling_spend_count == self.sapling_spend_parsed_count {
            info!("All sapling spends parsed");
            self.state = ParserState::ProcessSaplingSpendsHashing;
        }

        Ok(())
    }

    pub fn parse_sapling_spends_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Process sapling spends hashing");

        // Finalize compact and noncompact sapling spend hashes
        let mut sapling_spend_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .finalize(&mut sapling_spend_compact_digest));
        debug!(
            "Sapling spend compact digest: {}",
            HexSlice(&sapling_spend_compact_digest)
        );

        let mut sapling_spend_non_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .finalize(&mut sapling_spend_non_compact_digest));
        debug!(
            "Sapling spend non compact digest: {}",
            HexSlice(&sapling_spend_non_compact_digest)
        );

        // Initialize the sapling spend digest context
        let mut tmp_spend_hasher = Blake2b_256::new();
        tmp_spend_hasher.init_with_perso(ZCASH_SAPLING_SPENDS_HASH_PERSONALIZATION);
        ok!(tmp_spend_hasher.update(&sapling_spend_compact_digest,));
        ok!(tmp_spend_hasher.update(&sapling_spend_non_compact_digest,));

        let mut sapling_spend = [0u8; 32];
        ok!(tmp_spend_hasher.finalize(&mut sapling_spend));

        debug!("Sapling spend digest: {}", HexSlice(&sapling_spend));

        // Update sapling full hasher with sapling spend digest
        ok!(ctx.hashers.sapling_hasher.update(&sapling_spend));

        if self.sapling_output_count > 0 {
            // Init outputs hasher
            ctx.hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_COMPACT_HASH_PERSONALIZATION);

            self.state = ParserState::ProcessSaplingOutputsCompact;
        } else {
            self.state = ParserState::ProcessExtra;
        }

        Ok(())
    }

    pub fn parse_sapling_outputs_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs compact, remaining: {}",
            self.sapling_output_count - self.sapling_output_parsed_count
        );

        let compact_size = 32 + 32 + 52; // cmu + ephemeral_key + enc_ciphertext[..52]

        if reader.remaining_len() < compact_size {
            return Err(ParserError::from_str(
                "Not enough data for sapling compact output",
            ));
        }

        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&reader.remaining_slice()[..compact_size]));
        ok!(reader.advance(compact_size));

        self.sapling_output_parsed_count += 1;

        if self.sapling_output_count == self.sapling_output_parsed_count {
            info!("All sapling compact outputs parsed");
            // Init memo hasher
            ctx.hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_MEMOS_HASH_PERSONALIZATION);

            // memo_size = 512 each APDU will contain quarter of the memo
            self.state = ParserState::ProcessSaplingOutputsMemo {
                size: self.sapling_output_count * 512,
                remaining_size: self.sapling_output_count * 512,
            };
        }

        Ok(())
    }

    pub fn parse_sapling_outputs_memo(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs memo, remaining size: {}",
            remaining_size
        );

        let to_read = core::cmp::min(remaining_size, reader.remaining_len());
        let memo_data = &reader.remaining_slice()[..to_read];
        ok!(ctx.hashers.tx_memo_hasher.update(memo_data));
        ok!(reader.advance(to_read));
        let new_remaining_size = remaining_size - to_read;

        if new_remaining_size == 0 {
            info!("All sapling memo data parsed");

            // Init outputs non compact hasher
            ctx.hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_SAPLING_OUTPUTS_NONCOMPACT_HASH_PERSONALIZATION);

            self.sapling_output_parsed_count = 0;
            self.state = ParserState::ProcessSaplingOutputsNonCompact;
        } else {
            self.state = ParserState::ProcessSaplingOutputsMemo {
                size,
                remaining_size: new_remaining_size,
            };
        }

        Ok(())
    }

    pub fn parse_sapling_outputs_non_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Process sapling outputs non compact, remaining: {}",
            self.sapling_output_count - self.sapling_output_parsed_count
        );

        let non_compact_size = 32 + 16 + 80;

        if reader.remaining_len() < non_compact_size {
            return Err(ParserError::from_str(
                "Not enough data for sapling non compact output",
            ));
        }
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&reader.remaining_slice()[..non_compact_size]));
        ok!(reader.advance(non_compact_size));

        self.sapling_output_parsed_count += 1;

        if self.sapling_output_count == self.sapling_output_parsed_count {
            info!("All sapling non compact outputs parsed");
            self.state = ParserState::ProcessSaplingOutputHashing;
        }

        Ok(())
    }

    pub fn parse_sapling_output_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        _reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Finalize sapling outputs hashing");

        // Finalize compact, memo and noncompact sapling output hashes
        let mut sapling_output_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .finalize(&mut sapling_output_compact_digest));
        debug!(
            "Sapling output compact digest: {}",
            HexSlice(&sapling_output_compact_digest)
        );

        let mut sapling_output_memo_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_memo_hasher
            .finalize(&mut sapling_output_memo_digest));
        debug!(
            "Sapling output memo digest: {}",
            HexSlice(&sapling_output_memo_digest)
        );

        let mut sapling_output_non_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .finalize(&mut sapling_output_non_compact_digest));
        debug!(
            "Sapling output non compact digest: {}",
            HexSlice(&sapling_output_non_compact_digest)
        );

        // Initialize the sapling output digest context
        let mut sapling_output_hasher = Blake2b_256::new();
        sapling_output_hasher.init_with_perso(ZCASH_SAPLING_OUTPUTS_HASH_PERSONALIZATION);

        ok!(sapling_output_hasher.update(&sapling_output_compact_digest));
        ok!(sapling_output_hasher.update(&sapling_output_memo_digest));
        ok!(sapling_output_hasher.update(&sapling_output_non_compact_digest));

        let mut sapling_output = [0u8; 32];
        ok!(sapling_output_hasher.finalize(&mut sapling_output));
        debug!("Sapling output digest: {}", HexSlice(&sapling_output));

        // Update sapling full hasher with sapling output digest
        ok!(ctx.hashers.sapling_hasher.update(&sapling_output));
        // Update sapling full hasher with sapling balance
        ok!(ctx
            .hashers
            .sapling_hasher
            .update(&self.sapling_balance.to_le_bytes()));

        if self.orchard_action_count > 0 {
            ctx.hashers
                .tx_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_COMPACT_HASH_PERSONALIZATION);
            self.state = ParserState::ProcessOrchardCompact;
        } else {
            self.state = ParserState::ProcessExtra;
        }

        Ok(())
    }
}
