import pytest

from application_client.zcash_command_sender import ZcashCommandSender, Errors
from application_client.zcash_response_unpacker import unpack_get_public_key_response
from ragger.bip import calculate_public_key_and_chaincode, CurveChoice
from ragger.error import ExceptionRAPDU
from application_client.zcash_utils import t_address_from_pubkey


# In this test we check that the GET_PUBLIC_KEY works in non-confirmation mode
def test_get_public_key_no_confirm(backend):
    for path in ["m/44'/133'/0'/0/0", "m/44'/133'/0/0/0", "m/44'/133'/911'/0/0", "m/44'/133'/255/255/255", "m/44'/133'/2147483647/0/0/0/0/0/0/0"]:
        client = ZcashCommandSender(backend)
        response = client.get_public_key(path=path).data
        public_key, address, chain_code = unpack_get_public_key_response(response)

        ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
        ref_t_address = t_address_from_pubkey(bytes.fromhex(ref_public_key))

        assert public_key.hex() == ref_public_key
        assert address == ref_t_address
        assert chain_code.hex() == ref_chain_code


# In this test we check that the GET_PUBLIC_KEY works in confirmation mode
def test_get_public_key_confirm_accepted(backend, scenario_navigator):
    client = ZcashCommandSender(backend)
    path = "m/44'/133'/0'/0/0"

    with client.get_public_key_with_confirmation(path=path):
        scenario_navigator.address_review_approve()

    response = client.get_async_response().data
    public_key, address, chain_code = unpack_get_public_key_response(response)

    ref_public_key, ref_chain_code = calculate_public_key_and_chaincode(CurveChoice.Secp256k1, path=path)
    ref_t_address = t_address_from_pubkey(bytes.fromhex(ref_public_key))

    assert public_key.hex() == ref_public_key
    assert address == ref_t_address
    assert chain_code.hex() == ref_chain_code


# In this test we check that the GET_PUBLIC_KEY in confirmation mode replies an error if the user refuses
def test_get_public_key_confirm_refused(backend, scenario_navigator):
    client = ZcashCommandSender(backend)
    path = "m/44'/133'/0'/0/0"

    with pytest.raises(ExceptionRAPDU) as e:
        with client.get_public_key_with_confirmation(path=path):
            scenario_navigator.address_review_reject()

    # Assert that we have received a refusal
    assert e.value.status == Errors.SW_DENY
    assert len(e.value.data) == 0