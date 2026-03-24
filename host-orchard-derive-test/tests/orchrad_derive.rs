use bip0039::{English, Mnemonic};
use zip32::ChildIndex;
use zip32::hardened_only::{Context, HardenedOnlyKey};
use zcash_spec::{PrfExpand, VariableLengthSlice};

struct OrchardContext;

impl Context for OrchardContext {
    const MKG_DOMAIN: [u8; 16] = *b"ZcashIP32Orchard";
    const CKD_DOMAIN: PrfExpand<([u8; 32], [u8; 4], [u8; 1], VariableLengthSlice)> =
        PrfExpand::ORCHARD_ZIP32_CHILD;
}

// -----------------------  Default speculos seed ---------------------------------
// * glory promote mansion idle axis finger extra february uncover one trip
// * resource lawn turtle enact monster seven myth punch hobby comfort wild raise
// * skin
// --------------------------------------------------------------------------------

// Exported keys from ledger device using the above seed and the path m/32'/133'/0':
// Child sk: b9880c68c59436419fe615ef7e05d26ffb6de0ef36f151c764bd80c259254a1e
// Child chain code: 5cc85343f688608f94d5548f4dfc4086d708b13eb34c47be06c966f5e739427e
const DEVICE_DERIVED_CHILD_SK_ACC_0: [u8; 32] = [
    0xb9, 0x88, 0x0c, 0x68, 0xc5, 0x94, 0x36, 0x41,
    0x9f, 0xe6, 0x15, 0xef, 0x7e, 0x05, 0xd2, 0x6f,
    0xfb, 0x6d, 0xe0, 0xef, 0x36, 0xf1, 0x51, 0xc7,
    0x64, 0xbd, 0x80, 0xc2, 0x59, 0x25, 0x4a, 0x1e,
];
const DEVICE_DERIVED_CHILD_CC_ACC_0: [u8; 32] = [
    0x5c, 0xc8, 0x53, 0x43, 0xf6, 0x88, 0x60, 0x8f,
    0x94, 0xd5, 0x54, 0x8f, 0x4d, 0xfc, 0x40, 0x86,
    0xd7, 0x08, 0xb1, 0x3e, 0xb3, 0x4c, 0x47, 0xbe,
    0x06, 0xc9, 0x66, 0xf5, 0xe7, 0x39, 0x42, 0x7e,
];

// Exported keys from ledger device using the above seed and the path m/32'/133'/1':
// Child sk: 2e34ba81595227a2394e352ebdcad030db3872c820ada7ef2d6157351244a5ac
// Child chain code: f7c8f3956e2f8bcb71da50639b1b0431e6627334bd00797f3e0ca2b739f273b3

const DEVICE_DERIVED_CHILD_SK_ACC_1: [u8; 32] = [
    0x2e, 0x34, 0xba, 0x81, 0x59, 0x52, 0x27, 0xa2,
    0x39, 0x4e, 0x35, 0x2e, 0xbd, 0xca, 0xd0, 0x30,
    0xdb, 0x38, 0x72, 0xc8, 0x20, 0xad, 0xa7, 0xef,
    0x2d, 0x61, 0x57, 0x35, 0x12, 0x44, 0xa5, 0xac,
];

const DEVICE_DERIVED_CHILD_CC_ACC_1: [u8; 32] = [
    0xf7, 0xc8, 0xf3, 0x95, 0x6e, 0x2f, 0x8b, 0xcb,
    0x71, 0xda, 0x50, 0x63, 0x9b, 0x1b, 0x04, 0x31,
    0xe6, 0x62, 0x73, 0x34, 0xbd, 0x00, 0x79, 0x7f,
    0x3e, 0x0c, 0xa2, 0xb7, 0x39, 0xf2, 0x73, 0xb3,
];


fn test_zip32_orchard_derive_impl(account: u32, (expected_sk, expected_cc): (&[u8; 32], &[u8; 32])) {
    const PURPOSE: u32 = 32;
    const COIN_TYPE: u32 = 133;

    let mnemonic = Mnemonic::<English>::from_phrase("\
        glory promote mansion idle axis finger extra february uncover one trip \
        resource lawn turtle enact monster seven myth punch hobby comfort wild raise \
        skin"
    ).expect("Failed to parse mnemonic phrase.");

    println!("Mnemonic phrase: {}", mnemonic.phrase());

    let seed = mnemonic.to_seed("");

    // Derive chain code via zip32 hardened-only derivation (orchard ExtendedSpendingKey is pub(crate))
    let orchard_esk = HardenedOnlyKey::<OrchardContext>::master(&[&seed])
        .derive_child(ChildIndex::hardened(PURPOSE))
        .derive_child(ChildIndex::hardened(COIN_TYPE))
        .derive_child(ChildIndex::hardened(account));

    let (esk_sk, esk_cc) = orchard_esk.parts();

    println!("Orchard spending key:    {}", hex_str(esk_sk));
    println!("Orchard chain code:      {}", hex_str(esk_cc.as_bytes()));

    assert_eq!(esk_sk, expected_sk, "sk mismatch via zip32 derivation");
    assert_eq!(esk_cc.as_bytes(), expected_cc, "chain code mismatch");
}

fn hex_str(bytes: &[u8]) -> String {
    let mut s = String::new();
    for byte in bytes {
        s.push_str(&format!("{:02x}", byte));
    }
    s
}

#[test]
fn test_zip32_orchard_derive() {
    test_zip32_orchard_derive_impl(0, (&DEVICE_DERIVED_CHILD_SK_ACC_0, &DEVICE_DERIVED_CHILD_CC_ACC_0));
    test_zip32_orchard_derive_impl(1, (&DEVICE_DERIVED_CHILD_SK_ACC_1, &DEVICE_DERIVED_CHILD_CC_ACC_1));
}