use crate::{
    handlers::sign_tx::TxContext,
    log::{debug, error, info},
    parser::{ParserMode, ParserSourceError},
    settings::Settings,
    utils::{read_u32, Endianness},
    AppSW,
};
use ledger_device_sdk::{
    hmac::{sha2::Sha2_256 as HmacSha256, HMACInit},
    io::Comm,
    random::rand_bytes,
};

const MAGIC_TRUSTED_INPUT: u8 = 0x32;
const TRUSTED_INPUT_SIZE: usize = 2 + 2 + 32 + 4 + 8; // magic + rand + txid + idx + amount

pub fn handler_get_trusted_input(
    comm: &mut Comm,
    ctx: &mut TxContext,
    first: bool,
    _next: bool,
) -> Result<(), AppSW> {
    // Try to get data from comm
    let mut data = comm.get_data().map_err(|_| AppSW::WrongApduLength)?;

    if first {
        info!("Init parser");
        *ctx = TxContext::new();

        let transaction_trusted_input_idx = read_u32(data, Endianness::Big, false)?;
        data = &data[4..];

        ctx.set_transaction_trusted_input_idx(transaction_trusted_input_idx);
        info!("Trusted input idx: {}", transaction_trusted_input_idx);
    }

    ctx.parser
        .parse_chunk(data, ParserMode::TrustedInput)
        .map_err(|e| {
            error!("Error parsing trusted input: {:#?}", e);
            match e.source {
                ParserSourceError::Hash(_) => AppSW::TechnicalProblem,
                _ => AppSW::IncorrectData,
            }
        })?;

    if ctx.parser.is_finished() {
        if !ctx.parser.is_transaction_trusted_input_processed() {
            error!("Trusted input index was not processed");
            return Err(AppSW::IncorrectData);
        }

        let mut rng = [0u8; 4];
        rand_bytes(&mut rng);

        comm.append(&[MAGIC_TRUSTED_INPUT, 0x00]);
        comm.append(&rng[2..]);
        comm.append(&ctx.parser.tx_id());
        comm.append(
            ctx.transaction_trusted_input_idx()
                .expect("should be set at init parser state (see above)")
                .to_le_bytes()
                .as_ref(),
        );
        comm.append(ctx.parser.amount().to_le_bytes().as_ref());

        // Compute HMAC-SHA256 signature over the trusted input
        let mut signature = [0u8; 8];
        let mut hmac_sha256_signer = HmacSha256::new(
            &Settings
                .trusted_input_key()
                .ok_or(AppSW::TechnicalProblem)?,
        );
        debug!("HMAC input: {:02X?}", comm.get(0, TRUSTED_INPUT_SIZE));

        hmac_sha256_signer
            .update(comm.get(0, TRUSTED_INPUT_SIZE))
            .map_err(|err| {
                error!("HMAC update error {:?}", err);
                AppSW::TechnicalProblem
            })?;
        hmac_sha256_signer.finalize(&mut signature).map_err(|err| {
            error!("HMAC finalize error {:?}", err);
            AppSW::TechnicalProblem
        })?;

        comm.append(&signature);
    }

    Ok(())
}
