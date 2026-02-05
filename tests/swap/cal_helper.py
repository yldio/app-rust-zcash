from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration
from ragger.bip import pack_derivation_path
from ragger.utils import create_currency_config
from application_client.zcash_currency_utils import ZCASH_PATH

# ZCASH native currency definition
ZCASH_CONF = create_currency_config("ZEC", "Zcash", sub_coin_config=None)
# Serialized derivation path for the Boilerplate app
ZCASH_PACKED_DERIVATION_PATH = pack_derivation_path(ZCASH_PATH)
# Coin configuration mock as stored in CAL for the SWAP feature
ZCASH_CURRENCY_CONFIGURATION = CurrencyConfiguration(ticker="ZEC", conf=ZCASH_CONF, packed_derivation_path=ZCASH_PACKED_DERIVATION_PATH)

