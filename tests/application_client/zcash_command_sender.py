from enum import IntEnum
from typing import Generator, List, Optional, Tuple
from contextlib import contextmanager
from struct import pack

from ragger.backend.interface import BackendInterface, RAPDU
from ragger.bip import pack_derivation_path

from application_client.zcash_transaction import (
    split_tx_to_chunks_v5,
    split_tx_v5_for_hash_input,
)

MAGIC_TRUSTED_INPUT: int = 0x32

MAX_APDU_LEN: int = 255

CLA: int = 0xE0


class P1(IntEnum):
    # Parameter 1 for first APDU number.
    P1_START = 0x00
    # Parameter 1 for screen confirmation for GET_PUBLIC_KEY.
    P1_CONFIRM = 0x01
    # Parameter 2 for more APDU to receive.
    P1_MORE = 0x80
    # Parameter 1 for change information
    P1_CHANGE_INFO = 0xFF


class P2(IntEnum):
    # Parameter 2 default value
    P2_NONE = 0x00
    P2_TRUSTED_INPUT_SAPLING = 0x05
    P2_CONTINUE_HASHING = 0x80


class InsType(IntEnum):
    GET_VERSION = 0xC4
    GET_APP_NAME = 0x04
    GET_WALLET_PUBLIC_KEY = 0x40
    GET_TRUSTED_INPUT = 0x42
    HASH_INPUT_START = 0x44
    HASH_INPUT_FINALIZE_FULL = 0x4A
    HASH_SIGN = 0x48


class Errors(IntEnum):
    SW_DENY = 0x6985
    SW_WRONG_P1P2 = 0x6B00
    SW_INS_NOT_SUPPORTED = 0x6D00
    SW_CLA_NOT_SUPPORTED = 0x6E00
    SW_WRONG_APDU_LENGTH = 0x6E03
    SW_WRONG_RESPONSE_LENGTH = 0xB000
    SW_DISPLAY_BIP32_PATH_FAIL = 0xB001
    SW_DISPLAY_ADDRESS_FAIL = 0xB002
    SW_DISPLAY_AMOUNT_FAIL = 0xB003
    SW_WRONG_TX_LENGTH = 0xB004
    SW_TX_PARSING_FAIL = 0xB005
    SW_TX_HASH_FAIL = 0xB006
    SW_BAD_STATE = 0xB007
    SW_SIGNATURE_FAIL = 0xB008


def split_message(message: bytes, max_size: int) -> List[bytes]:
    return [message[x : x + max_size] for x in range(0, len(message), max_size)]


class ZcashCommandSender:
    def __init__(self, backend: BackendInterface) -> None:
        self.backend = backend
        self.tx_chunks: dict = {}
        self.trusted_inputs: list[bytes] = []

    def exchange_raw(self, data: str) -> Tuple[int, bytes]:
        data_bytes = bytes.fromhex(data)
        res = self.backend.exchange_raw(data_bytes)
        return res.status, res.data

    @contextmanager
    def exchange_async_raw(self, data: str) -> Generator[None, None, None]:
        data_bytes = bytes.fromhex(data)
        with self.backend.exchange_async_raw(data_bytes):
            yield

    def get_app_and_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=0xB0,  # specific CLA for BOLOS
            ins=0x01,  # specific INS for get_app_and_version
            p1=P1.P1_START,
            p2=P2.P2_NONE,
            data=b"",
        )

    def get_version(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_VERSION, p1=P1.P1_START, p2=P2.P2_NONE, data=b""
        )

    def get_app_name(self) -> RAPDU:
        return self.backend.exchange(
            cla=CLA, ins=InsType.GET_APP_NAME, p1=P1.P1_START, p2=P2.P2_NONE, data=b""
        )

    def get_public_key(self, path: str) -> RAPDU:
        return self.backend.exchange(
            cla=CLA,
            ins=InsType.GET_WALLET_PUBLIC_KEY,
            p1=P1.P1_START,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path),
        )

    @contextmanager
    def get_public_key_with_confirmation(
        self, path: str
    ) -> Generator[None, None, None]:
        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_WALLET_PUBLIC_KEY,
            p1=P1.P1_CONFIRM,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path),
        ) as response:
            yield response

    @contextmanager
    def get_trusted_input(
        self, transaction: bytes, trusted_input_idx: int
    ) -> Generator[None, None, None]:
        chunks = split_tx_to_chunks_v5(transaction)
        # convert trusted-input index to 4 bytes big endian
        trusted_idx = pack(">I", trusted_input_idx)
        # prepend the trusted input index to the first chunk
        chunks[0] = bytes(trusted_idx + chunks[0])

        p1 = P1.P1_START

        for c in chunks[:-1]:
            self.backend.exchange(
                cla=CLA, ins=InsType.GET_TRUSTED_INPUT, p1=p1, p2=P2.P2_NONE, data=c
            )
            p1 = P1.P1_MORE

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.GET_TRUSTED_INPUT,
            p1=P1.P1_MORE,
            p2=P2.P2_NONE,
            data=chunks[-1],
        ) as response:
            yield response

    def _send_trusted_inputs_and_header(self, continue_hashing: bool):
        header = self.tx_chunks["header"]
        inputs = self.tx_chunks["inputs"]
        inputs_num = len(inputs)

        # Send header chunk
        self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_INPUT_START,
            p1=P1.P1_START,
            p2=(
                P2.P2_CONTINUE_HASHING
                if continue_hashing
                else P2.P2_TRUSTED_INPUT_SAPLING
            ),
            data=header + inputs_num.to_bytes(1, byteorder="big"),
        )

        # Send trusted inputs chunks
        for idx, inp in enumerate(inputs):
            flag = 0x01
            trusted_input_data = self.trusted_inputs[idx]
            trusted_input_len = len(trusted_input_data)
            script = inp["script"]
            script_len = len(script)
            sequence = inp["sequence"]

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_START,
                p1=P1.P1_MORE,
                p2=P2.P2_TRUSTED_INPUT_SAPLING,
                data=flag.to_bytes(1, byteorder="big")
                + trusted_input_len.to_bytes(1, byteorder="big")
                + trusted_input_data
                + script_len.to_bytes(1, byteorder="big"),
            )

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_START,
                p1=P1.P1_MORE,
                p2=P2.P2_TRUSTED_INPUT_SAPLING,
                data=script + sequence,
            )

    @contextmanager
    def hash_input(
        self,
        transaction: bytes,
        trusted_inputs: list[bytes],
        change_path: str | None = None,
    ) -> Generator[None, None, None]:
        self.tx_chunks = split_tx_v5_for_hash_input(transaction)
        self.trusted_inputs = trusted_inputs

        self._send_trusted_inputs_and_header(continue_hashing=False)

        # Send outputs chunks
        outputs: dict = self.tx_chunks["outputs"] # type: ignore
        outputs_num = len(outputs)
        outputs_num_bytes = outputs_num.to_bytes(1, byteorder="big")

        if change_path:
            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_CHANGE_INFO,
                p2=P2.P2_NONE,
                data=pack_derivation_path(change_path),
            )

        for out in outputs[:-1]:
            value = out["value"]
            script = out["script"]
            script_len = len(script)

            self.backend.exchange(
                cla=CLA,
                ins=InsType.HASH_INPUT_FINALIZE_FULL,
                p1=P1.P1_MORE,
                p2=P2.P2_NONE,
                data=outputs_num_bytes + value + script_len.to_bytes(1, byteorder="big") + script,
            )

            outputs_num_bytes = b""

        value = outputs[-1]["value"]
        script = outputs[-1]["script"]
        script_len = len(script)

        with self.backend.exchange_async(
            cla=CLA,
            ins=InsType.HASH_INPUT_FINALIZE_FULL,
            p1=P1.P1_MORE,
            p2=P2.P2_NONE,
            data=outputs_num_bytes + value + script_len.to_bytes(1, byteorder="big") + script,
        ) as response:
            yield response

    def hash_sign(
        self, path: str, locktime: int, expiry: int, sighash_type: int = 0x01
    ) -> RAPDU:
        # Send extra header data
        self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_SIGN,
            p1=P1.P1_START,
            p2=P2.P2_NONE,
            data=0x00.to_bytes(2, byteorder="big")
            + locktime.to_bytes(4, byteorder="big")
            + sighash_type.to_bytes(1, byteorder="big")
            + expiry.to_bytes(4, byteorder="big"),
        )

        self._send_trusted_inputs_and_header(continue_hashing=True)

        return self.backend.exchange(
            cla=CLA,
            ins=InsType.HASH_SIGN,
            p1=P1.P1_START,
            p2=P2.P2_NONE,
            data=pack_derivation_path(path)
            + 0x00.to_bytes(1, byteorder="big")
            + locktime.to_bytes(4, byteorder="big")
            + sighash_type.to_bytes(1, byteorder="big")
            + expiry.to_bytes(4, byteorder="big"),
        )

    def get_async_response(self) -> Optional[RAPDU]:
        return self.backend.last_async_response
