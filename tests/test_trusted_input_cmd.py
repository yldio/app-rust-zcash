from application_client.zcash_command_sender import ZcashCommandSender
from application_client.zcash_response_unpacker import unpack_trusted_input_response

TRUSTED_INPUT_RESPONSE_HEX_LEN = 112

def test_trusted_input_transparent_v5_two_inputs(backend):
    TX_BYTES = bytes.fromhex("050000800a27a726b4d0d6c200000000a8841e00021111111111111111111111111111111111111111111111111111111111111111000000006b483045022100e35dd2be5e5aeccce0ff7ff892db278047685bc11d34692fd72a9c1914d05f8e0220426dd0a98b39eb6051df9706e4ff9fba4a8be5cd6ef5c3fdd6f2200c709b2bad01210228d06186c26df6afa96076b0ac64cf0d8caf212937f328a52894183cc36e5dd8ffffffff2222222222222222222222222222222222222222222222222222222222222222010000006b483045022100abb1831a7c59bd893420bfe51df0627f239ac2c1524de86958fe84f122c5344d022046ef451e009e500c12516f082a03ffafd3743f522790b866af88ef202fc83a1d0121037e0c5efb047f692c0c89ea9a817f577dc086303aed2f662df4879c89448287c7ffffffff01a0860100000000001976a914b1630abe4ac3749ca5b0ea4c30a7eae5abab19be88ac000000")

    trusted_input_idx = 0

    client = ZcashCommandSender(backend)

    with client.get_trusted_input(TX_BYTES, trusted_input_idx):
        pass

    resp = client.get_async_response().data
    txid, idx, amount, _, _ = unpack_trusted_input_response(resp)

    assert txid.hex() == "754d1a6d0c8e7bfaff9bb1d2f356db3475e60e27d27376f64ba0f21c23adbd80"
    assert idx == trusted_input_idx
    assert amount == 100_000

def test_trusted_input_transparent_v5_two_outputs(backend):
    TX_BYTES = bytes.fromhex("050000800a27a726b4d0d6c200000000a8841e00011111111111111111111111111111111111111111111111111111111111111111000000006a47304402207822747dfbbb31fda5ec92ec908bed2fd9b347d14c5756cf7f81f6548c0eb9170220576933ee4c037cf2c4116a5e4bd374b3b5b518ace808ce740637e1c460ac7cc10121031b84c5567b126440995d3ed5aaba0565d71e1834604819ff9c17f5e9d5dd078fffffffff0250973100000000001976a914417d4be90d35363267b8f2afafc9531111c41ae488ac50973100000000001976a914417d4be90d35363267b8f2afafc9531111c41ae488ac000000");

    trusted_input_idx = 1

    client = ZcashCommandSender(backend)

    with client.get_trusted_input(TX_BYTES, trusted_input_idx):
        pass

    resp = client.get_async_response().data
    txid, idx, amount, _, _ = unpack_trusted_input_response(resp)

    assert txid.hex() == "f5f79290d3dfe4e768aec837affe8eb9e46fbc82ef9dfdf2c62af1ad0b3878a3"
    assert idx == trusted_input_idx
    assert amount == 3_250_000

def test_trusted_input_transparent_v5_old_1(backend):
    EXPECTED_TRUSTED_INPUT = "a9a27d42321c7ace2884a65a343abb9755f3eba881e53834bdb4a3fed4432a1301000000"

    transport = ZcashCommandSender(backend)

    # with transparent apdus
    sw, _ = transport.exchange_raw("e04200001100000001050000800a27a7265510e7c801")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800025e1360c957489515ddfb5c564962e2c8cb2dc3c651c4a219e25e0b5e569f49d33000000006b")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000324830450221008844cfb8d9983226f74cdd20cb63ee282360374def5de88d093df7f340775d65022072673cea8cd2092484c1")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000321c6e8c35ab765a9501024a96265bdd3b80d0c46f9190012102495e50ff5127b9b74083bad438208c7a39ddd83301cd04e40b")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000bff5556d3351ab300000000")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000102")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800022a0860100000000001976a914a96e684ec46cd8a2f98d6ef4b847c0ee88395e9388ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800022cedb0e00000000001976a9142495eecd3d7ea979d2066da533f45956a3a6b5c888ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000
    sw, resp = transport.exchange_raw("e042800009000000000400000000")
    assert sw == 0x9000

    resp = resp.hex()
    assert len(resp) == TRUSTED_INPUT_RESPONSE_HEX_LEN
    assert resp[8:8+32*2+8] == EXPECTED_TRUSTED_INPUT

def test_trusted_input_transparent_v5_old_2(backend):
    EXPECTED_TRUSTED_INPUT = "58854aa4e2e3b82aa2040c0bc3a6dc9b8ac6acb5e15bf0cfeacd09e77249c18a00000000"

    transport = ZcashCommandSender(backend)

    sw, _ = transport.exchange_raw("e04200001100000000050000800a27a726b4d0d6c201")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280002598cd6cd9559cd98109ad0622f899bc38805f11648e4f985ebe344b8238f87b13010000006b")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280003248304502210095104ae9d53a95105be4ba5a31caddff2ae83ced24b21ab4aec6d735d568fad102206e054b158047529bb736")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800032c810902ea7fc8d92f3f604c1b2a8bb0b92f0e6c016a8012102010a560c7325827df0212bca20f5cf6556b1345991b6b64b46")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000b9c616e758230a5ffffffff")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e04280000102")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e0428000221595dd04000000001976a914ca3ba17907dde979bf4e88f5c1be0ddf0847b25d88ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800022a245117c140000001976a914c8b56e00740e62449a053c15bdd4809f720b5cb588ac")
    assert sw == 0x9000
    sw, _ = transport.exchange_raw("e042800003000000")
    assert sw == 0x9000

    sw, resp = transport.exchange_raw("e0428000090000000004f9081a00")
    assert sw == 0x9000

    resp = resp.hex()
    assert len(resp) == TRUSTED_INPUT_RESPONSE_HEX_LEN
    assert resp[8:8+32*2+8] == EXPECTED_TRUSTED_INPUT
