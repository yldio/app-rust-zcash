use ::orchard::bundle::commitments::{
    ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION,
    ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION,
};

use super::*;

impl Parser {
    pub fn parse_orchard_compact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Parsing orchard compact action {}/{}",
            self.orchard_action_parsed_count + 1,
            self.orchard_action_count
        );

        // nullifier + cmx + ephemeralKey + encCiphertext[..52]
        let compact_size = 32 + 32 + 32 + 52;

        if reader.remaining_len() < compact_size {
            return Err(ParserError::from_str(
                "Not enough data for orchard compact output",
            ));
        }

        ok!(ctx
            .hashers
            .tx_compact_hasher
            .update(&reader.remaining_slice()[..compact_size]));
        ok!(reader.advance(compact_size));

        self.orchard_action_parsed_count += 1;

        if self.orchard_action_parsed_count == self.orchard_action_count {
            info!("All orchard compact actions parsed");

            ctx.hashers
                .tx_memo_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_MEMOS_HASH_PERSONALIZATION);

            // memo_size = 512 each APDU will contain quarter of the memo
            self.state = ParserState::ProcessOrchardMemo {
                size: self.orchard_action_count * 512,
                remaining_size: self.orchard_action_count * 512,
            };
        }

        Ok(())
    }

    pub fn parse_orchard_memo(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
        size: usize,
        remaining_size: usize,
    ) -> Result<(), ParserError> {
        info!("Parsing orchard memo, remaining size: {}", remaining_size);

        let to_read = core::cmp::min(remaining_size, reader.remaining_len());
        ok!(ctx
            .hashers
            .tx_memo_hasher
            .update(&reader.remaining_slice()[..to_read]));
        ok!(reader.advance(to_read));

        let new_remaining_size = remaining_size - to_read;
        if new_remaining_size == 0 {
            info!("All orchard memos parsed");

            ctx.hashers
                .tx_non_compact_hasher
                .init_with_perso(ZCASH_ORCHARD_ACTIONS_NONCOMPACT_HASH_PERSONALIZATION);

            self.orchard_action_parsed_count = 0;
            self.state = ParserState::ProcessOrchardNonCompact;
        } else {
            self.state = ParserState::ProcessOrchardMemo {
                size,
                remaining_size: new_remaining_size,
            };
        }

        Ok(())
    }

    pub fn parse_orchard_noncompact(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!(
            "Parsing orchard non-compact action {}/{}",
            self.orchard_action_parsed_count + 1,
            self.orchard_action_count
        );

        // nullifier + cmx + outCiphertext + zkproof
        let non_compact_size = 32 + 32 + 16 + 80;
        if reader.remaining_len() < non_compact_size {
            return Err(ParserError::from_str(
                "Not enough data for orchard non-compact output",
            ));
        }

        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .update(&reader.remaining_slice()[..non_compact_size]));

        ok!(reader.advance(non_compact_size));

        self.orchard_action_parsed_count += 1;

        if self.orchard_action_parsed_count == self.orchard_action_count {
            info!("All orchard non-compact actions parsed");
            self.state = ParserState::ProcessOrchardHashing;
        }

        Ok(())
    }

    pub fn parse_orchard_hashing(
        &mut self,
        ctx: &mut ParserCtx<'_>,
        reader: &mut ByteReader<'_>,
    ) -> Result<(), ParserError> {
        info!("Finalizing orchard hashing");

        let mut orchard_output_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_compact_hasher
            .finalize(&mut orchard_output_compact_digest));

        let mut orchard_output_memo_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_memo_hasher
            .finalize(&mut orchard_output_memo_digest));

        let mut orchard_output_non_compact_digest = [0u8; 32];
        ok!(ctx
            .hashers
            .tx_non_compact_hasher
            .finalize(&mut orchard_output_non_compact_digest));

        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_compact_digest));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_memo_digest));
        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&orchard_output_non_compact_digest));

        // Read orchard digest data: 1 + 8 + 32
        let orch_dig_data_size = 1 + 8 + 32;
        if reader.remaining_len() < orch_dig_data_size {
            return Err(ParserError::from_str(
                "Not enough data for orchard digest data",
            ));
        }

        ok!(ctx
            .hashers
            .orchard_hasher
            .update(&reader.remaining_slice()[..orch_dig_data_size]));
        ok!(reader.advance(orch_dig_data_size));

        self.state = ParserState::ProcessExtra;

        Ok(())
    }
}
