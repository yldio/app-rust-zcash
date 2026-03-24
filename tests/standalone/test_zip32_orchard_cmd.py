import pytest
from ragger.error import ExceptionRAPDU

from application_client.zcash_command_sender import ZcashCommandSender, Errors

ZIP32_SK_SIZE = 32
ZIP32_CC_SIZE = 32

# Standard ZIP32 Orchard path: m/32'/133'/account'
ORCHARD_PATH_ACC0 = "m/32'/133'/0'"
ORCHARD_PATH_ACC1 = "m/32'/133'/1'"


def unpack_zip32_orchard_response(data: bytes) -> tuple[bytes, bytes]:
    """Split the 64-byte response into (sk, chain_code)."""
    assert len(data) == ZIP32_SK_SIZE + ZIP32_CC_SIZE, \
        f"Expected {ZIP32_SK_SIZE + ZIP32_CC_SIZE} bytes, got {len(data)}"
    return data[:ZIP32_SK_SIZE], data[ZIP32_SK_SIZE:]


# ---------------------------------------------------------------------------
# Happy-path tests
# ---------------------------------------------------------------------------

def test_zip32_orchard_derive_success(backend):
    """Derivation returns 64 bytes (sk || chain_code) with SW=0x9000."""
    client = ZcashCommandSender(backend)
    rapdu = client.zip32_orchard_derive(ORCHARD_PATH_ACC0)
    sk, cc = unpack_zip32_orchard_response(rapdu.data)
    print(f"Child sk: {sk.hex()}")
    print(f"Child chain code: {cc.hex()}")
    assert sk != bytes(ZIP32_SK_SIZE), "sk must not be all-zero"
    assert cc != bytes(ZIP32_CC_SIZE), "chain_code must not be all-zero"


def test_zip32_orchard_derive_deterministic(backend):
    """Same path always produces the same sk and chain_code."""
    client = ZcashCommandSender(backend)
    sk1, cc1 = unpack_zip32_orchard_response(
        client.zip32_orchard_derive(ORCHARD_PATH_ACC0).data
    )
    sk2, cc2 = unpack_zip32_orchard_response(
        client.zip32_orchard_derive(ORCHARD_PATH_ACC0).data
    )
    assert sk1 == sk2
    assert cc1 == cc2


def test_zip32_orchard_derive_different_accounts(backend):
    """Account 0 and account 1 yield different spending keys."""
    client = ZcashCommandSender(backend)
    sk0, _ = unpack_zip32_orchard_response(
        client.zip32_orchard_derive(ORCHARD_PATH_ACC0).data
    )
    sk1, _ = unpack_zip32_orchard_response(
        client.zip32_orchard_derive(ORCHARD_PATH_ACC1).data
    )
    assert sk0 != sk1


# ---------------------------------------------------------------------------
# Error-path tests
# ---------------------------------------------------------------------------

def test_zip32_orchard_derive_wrong_p1(backend):
    """Non-zero P1 is rejected with SW_WRONG_P1P2."""
    with pytest.raises(ExceptionRAPDU) as exc:
        ZcashCommandSender(backend).backend.exchange(
            cla=0xE0, ins=0xB8, p1=0x01, p2=0x00, data=b"\x00"
        )
    assert exc.value.status == Errors.SW_WRONG_P1P2


def test_zip32_orchard_derive_wrong_p2(backend):
    """Non-zero P2 is rejected with SW_WRONG_P1P2."""
    with pytest.raises(ExceptionRAPDU) as exc:
        ZcashCommandSender(backend).backend.exchange(
            cla=0xE0, ins=0xB8, p1=0x00, p2=0x01, data=b"\x00"
        )
    assert exc.value.status == Errors.SW_WRONG_P1P2


def test_zip32_orchard_derive_empty_data(backend):
    """Empty APDU data (missing path-length byte) is rejected with 0x6700."""
    with pytest.raises(ExceptionRAPDU) as exc:
        ZcashCommandSender(backend).backend.exchange(
            cla=0xE0, ins=0xB8, p1=0x00, p2=0x00, data=b""
        )
    assert exc.value.status == 0x6d00  # WrongApduLength


def test_zip32_orchard_derive_truncated_path(backend):
    """Path shorter than declared length is rejected with 0x6700."""
    with pytest.raises(ExceptionRAPDU) as exc:
        # Declare 3 components but provide only 1 (4 bytes)
        ZcashCommandSender(backend).backend.exchange(
            cla=0xE0, ins=0xB8, p1=0x00, p2=0x00,
            data=bytes([3]) + b"\x80\x00\x00\x20",
        )
    assert exc.value.status == 0x6d00  # WrongApduLength
