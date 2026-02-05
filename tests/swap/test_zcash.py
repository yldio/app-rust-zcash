import pytest
from ledger_app_clients.exchange.test_runner import ExchangeTestRunner, ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES
from ledger_app_clients.exchange.cal_helper import CurrencyConfiguration
from ragger.error import ExceptionRAPDU
from ragger.utils import create_currency_config

from application_client.zcash_currency_utils import ZCASH_PATH
from application_client.zcash_command_sender import ZcashCommandSender, Errors as ZcashErrors

from . import cal_helper as cal


class ZcashTests(ExchangeTestRunner):
    # The coin configuration of our currency. Replace by your own
    currency_configuration = cal.ZCASH_CURRENCY_CONFIGURATION
    # A valid template address of a supposed trade partner.
    valid_destination_1 = "t1KVhvpor9RJrenB6UpmeeoN3NzrnYRCwBD" # FIXME: incorrect
    # A memo to use associated with the destination address if applicable.
    valid_destination_memo_1 = ""
    # A second valid template address of a supposed trade partner.
    valid_destination_2 = "t1KVhvpor9RJrenB6UpmeeoN3NzrnYRCwBD" # FIXME: incorrect
    # A second memo to use associated with the destination address if applicable.
    valid_destination_memo_2 = ""
    # The address of the Speculos seed on the ZCASH_PATH.
    valid_refund = "fd2095a37e72be2cd575d18fe8f16e78c51eafa3" # FIXME: incorrect
    valid_refund_memo = ""

    # Values we ask the ExchangeTestRunner to use in the test setup
    valid_send_amount_1 = 1000000
    valid_send_amount_2 = 666000
    valid_fees_1 = 0
    valid_fees_2 = 0

    # Fake addresses to test the address rejection code.
    fake_refund = "abcdabcd"
    fake_refund_memo = "bla"
    fake_payout = "abcdabcd"
    fake_payout_memo = "bla"

    # The error code we expect our application to respond when encountering errors.
    signature_refusal_error_code = ZcashErrors.SW_DENY
    wrong_amount_error_code = ZcashErrors.SW_SWAP_FAIL
    wrong_destination_error_code = ZcashErrors.SW_SWAP_FAIL

    # The final transaction to craft and send as part of the SWAP finalization.
    # This function will be called by the ExchangeTestRunner in a callback like way
    def perform_final_tx(self, destination, send_amount, fees, memo):
        # Create the transaction that will be sent to the device for signing
        # TODO:
        # Send the TX
        # TODO:
        # TODO : assert signature validity. Not required but recommended
        pass


# We use a class to reuse the same Speculos instance (faster performances)
class TestsZcash:
    # Run all the tests applicable to our setup: here we don't test fees mismatch, memo mismatch, and Thorswap / LiFi
    @pytest.mark.parametrize('test_to_run', ALL_TESTS_EXCEPT_MEMO_THORSWAP_AND_FEES)
    def test_zcash(self, backend, exchange_navigation_helper, test_to_run):
        # Call run_test method of ExchangeTestRunner
        ZcashTests(backend, exchange_navigation_helper).run_test(test_to_run)

