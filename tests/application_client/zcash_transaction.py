import json
from dataclasses import dataclass
from struct import pack
from .zcash_utils import UINT64_MAX, read_compactsize

class TransactionError(Exception):
    pass

@dataclass
class Transaction:
    nonce: int
    coin: str
    value: str
    to: str
    memo: str

    def serialize(self) -> bytes:
        if not 0 <= self.nonce <= UINT64_MAX:
            raise TransactionError(f"Bad nonce: '{self.nonce}'!")

        if len(self.to) != 40:
            raise TransactionError(f"Bad address: '{self.to}'!")

        # Serialize the transaction data to a JSON-formatted string
        return json.dumps({
            "nonce": self.nonce,
            "coin": self.coin,
            "value": self.value,
            "to": self.to,
            "memo": self.memo
        }).encode('utf-8')

#  V5 TX format:
#  [ nVersion | flags ]           4 bytes
#  [ nGroupId ]                   4 bytes
#  [ nConsensusBranchId ]         4 bytes
#  [ nLockTime ]                  4 bytes (LE)
#  [ nExpiryHeight ]              4 bytes (LE)
#
#  [ vin_count ]                  CompactSize
#    for each vin:
#      [ prev_txid ]              32 bytes (LE)
#      [ prev_vout ]               4 bytes (LE)
#      [ scriptSig_len ]           CompactSize
#      [ scriptSig ]               N bytes
#      [ sequence ]                4 bytes (LE)
#
#  [ vout_count ]                 CompactSize
#    for each vout:
#      [ value ]                   8 bytes (LE, zatoshis)
#      [ scriptPubKey_len ]        CompactSize
#      [ scriptPubKey ]            N bytes
#
#  [ nSaplingSpends ]             CompactSize
#  [ nSaplingOutputs ]            CompactSize
#  [ nOrchardActions ]            CompactSize
#
#  -- witness data (excluded from txid) --
#
# NOTE: lockTime and expiryHeight are, for some reason, serialized at the end of the transaction data
# (as if it were a v4 transaction format).
def split_tx_to_chunks_v5(buf: bytes) -> list[bytes]:
    i = 0
    chunks = []

    header_size = 4 * 5
    header_quirk_size = 4 * 3

    locktime = buf[header_quirk_size:header_quirk_size+4]
    expiry   = buf[header_quirk_size+4:header_quirk_size+4*2]

    i += header_size

    vin_n, i = read_compactsize(buf, i)
    header_bytes = bytes(buf[0:header_quirk_size]) + bytes(buf[i - 1:i])
    chunks.append(header_bytes)

    for _ in range(vin_n):
        prevout_start = i
        i += 32 + 4
        slen, i   = read_compactsize(buf, i)
        chunks.append(buf[prevout_start:i])

        script_start = i
        i = i + slen + 4

        chunks.append(buf[script_start:i])

    vout_n, i = read_compactsize(buf, i)
    chunks.append(buf[i-1:i])

    for _ in range(vout_n):
        value_start = i
        i += 8
        plen, i  = read_compactsize(buf, i)
        chunks.append(buf[value_start:i])

        script_pk_start = i
        i = i + plen
        chunks.append(buf[script_pk_start:i])

    # Sapling and Orchard fields
    sapling_start = i
    sap_sp, i = read_compactsize(buf, i)
    assert sap_sp == 0, "Sapling spends not supported in this chunking function!"
    sap_out,i = read_compactsize(buf, i)
    assert sap_out == 0, "Sapling outputs not supported in this chunking function!"
    orch, i   = read_compactsize(buf, i)
    assert orch == 0, "Orchard actions not supported in this chunking function!"
    chunks.append(buf[sapling_start:i])

    assert i == len(buf), "Transaction splitting did not consume all bytes!"

    # Extra data
    chunks.append(locktime + pack("b", 0x04) + expiry)

    return chunks
