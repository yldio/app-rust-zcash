# PCZT Comparison Table

Based on `librustzcash/pczt` crate.

# Key points

* The legacy transparent Input format differs substantially from the PCZT format, and we would have to drop Trusted Input support (used in the legacy format, see the `GET_TRUSTED_INPUT` command).
* The legacy transparent Output format has some minor fields differences (some fields added)
* The legacy Orchard Action format differs substantially from the PCZT format:
    1. The action value and recipient are passed unencrypted.
    2. PCZT adds additional decoded Spend fields that need to be supported.


## Top-level PCZT

| PCZT path | Rust type / encoding | Status | Current behavior / gap |
|---|---|---|---|
| PCZT encoding prefix | `MAGIC_BYTES = b"PCZT"`, `PCZT_VERSION_1 = 1` | `Not supported` | The prefix is checked only by `Pczt::parse`; the app signing flow does not accept this container. |
| `Pczt.global` | `common::Global` | `Partial` | Some header equivalents are present in the raw/app stream, but `Global` is not modeled as a structure. |
| `Pczt.transparent` | `transparent::Bundle` | `Partial` | Transparent inputs/outputs are present in the current flow, but inputs require a trusted-input envelope. |
| `Pczt.sapling` | `sapling::Bundle` | `Skipped` | Sapling fields are skipped; Sapling will not be supported. |
| `Pczt.orchard` | `orchard::Bundle` | `Partial` | Orchard action bytes and digest data are parsed/hashed, but not as a PCZT structure. |

## `common::Global`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `global.tx_version` | `u32` | `Supported` | Parsed as part of the transaction header; the signer effectively works with supported versions, mainly V5. |
| `global.version_group_id` | `u32` | `Partial` | Read inside the transaction version format, but not stored as a separate PCZT field. |
| `global.consensus_branch_id` | `u32` | `Supported` | Parsed and used in personalization/signature digest construction. |
| `global.fallback_lock_time` | `Option<u32>` | `Partial` | The current flow receives a concrete `locktime` as raw/header or extra signing metadata; PCZT fallback/default logic is not implemented. |
| `global.expiry_height` | `u32` | `Supported` | Parsed/passed as expiry height and included in the header digest. |
| `global.coin_type` | `u32` | `Not supported` | Network/coin type is checked through the BIP32 path and local logic, not from PCZT `coin_type`. |
| `global.tx_modifiable` | `u8` | `Not supported` | The PCZT lifecycle bitfield is not accepted or enforced. |
| `global.tx_modifiable` bit 0 | transparent inputs modifiable | `Not supported` | There is no check for whether transparent inputs may be added or removed. |
| `global.tx_modifiable` bit 1 | transparent outputs modifiable | `Not supported` | There is no check for whether transparent outputs may be added or removed. |
| `global.tx_modifiable` bit 2 | has `SIGHASH_SINGLE` | `Not supported` | `sighash_type` is passed separately in the signing APDU; the PCZT flag is not used. |
| `global.tx_modifiable` bit 7 | shielded modifiable | `Not supported` | There is no check for whether shielded spends/outputs may be changed. |
| `global.proprietary` | `BTreeMap<String, Vec<u8>>` | `Not supported` | Proprietary maps are not supported. |

## Common nested type: `Zip32Derivation`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `Zip32Derivation.seed_fingerprint` | `[u8; 32]` | `Not supported` | Used inside PCZT derivation fields; the current signer does not read the fingerprint from PCZT. |
| `Zip32Derivation.derivation_path` | `Vec<u32>` | `Partial` | The signing BIP32/ZIP32 path is passed as a separate APDU parameter, not as PCZT metadata. |

## `transparent::Bundle`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `transparent.inputs` | `Vec<Input>` | `Partial` | Input count and data are present in the raw/app stream, but signing mode accepts only trusted inputs. |
| `transparent.outputs` | `Vec<Output>` | `Partial` | Outputs are parsed from the raw/app stream; the PCZT bundle/container is Not supported. |

## `transparent::Input`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `transparent.inputs[*].prevout_txid` | `[u8; 32]` | `Supported` | Taken from the trusted input and hashed into the prevouts hash. |
| `transparent.inputs[*].prevout_index` | `u32` | `Supported` | Taken from the trusted input and hashed into the prevouts hash. |
| `transparent.inputs[*].sequence` | `Option<u32>` | `Partial` | Sequence is parsed as mandatory 4 bytes; PCZT `None => 0xffffffff` is not implemented separately. |
| `transparent.inputs[*].required_time_lock_time` | `Option<u32>` | `Not supported` | The PCZT time-based locktime requirement is not read. |
| `transparent.inputs[*].required_height_lock_time` | `Option<u32>` | `Not supported` | The PCZT height-based locktime requirement is not read. |
| `transparent.inputs[*].script_sig` | `Option<Vec<u8>>` | `Not supported` | Final `script_sig` as a PCZT witness is not read or assembled. |
| `transparent.inputs[*].value` | `u64` | `Supported` | Amount is taken from the trusted input, included in the amounts hash, and used in fee calculation. |
| `transparent.inputs[*].script_pubkey` | `Vec<u8>` | `Partial` | An equivalent script is sent in the input script slot and hashed; it is not tied to PCZT and is not HMAC-bound to the prevout. |
| `transparent.inputs[*].redeem_script` | `Option<Vec<u8>>` | `Not supported` | A P2SH redeem script as a separate PCZT field is not supported. |
| `transparent.inputs[*].partial_signatures` | `BTreeMap<[u8; 33], Vec<u8>>` | `Generated only` | The device returns a transparent signature, but does not read the map or insert the signature into PCZT. |
| `transparent.inputs[*].sighash_type` | `u8` | `Partial` | The sighash byte is passed separately in the signing APDU; the per-input PCZT field is not read. |
| `transparent.inputs[*].bip32_derivation` | `BTreeMap<[u8; 33], Zip32Derivation>` | `Partial` | The signing path is passed as a separate APDU parameter; the PCZT map is not read. |
| `transparent.inputs[*].ripemd160_preimages` | `BTreeMap<[u8; 20], Vec<u8>>` | `Not supported` | Hash preimage maps are not supported. |
| `transparent.inputs[*].sha256_preimages` | `BTreeMap<[u8; 32], Vec<u8>>` | `Not supported` | Hash preimage maps are not supported. |
| `transparent.inputs[*].hash160_preimages` | `BTreeMap<[u8; 20], Vec<u8>>` | `Not supported` | Hash preimage maps are not supported. |
| `transparent.inputs[*].hash256_preimages` | `BTreeMap<[u8; 32], Vec<u8>>` | `Not supported` | Hash preimage maps are not supported. |
| `transparent.inputs[*].proprietary` | `BTreeMap<String, Vec<u8>>` | `Not supported` | Proprietary maps are not supported. |

## `transparent::Output`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `transparent.outputs[*].value` | `u64` | `Supported` | Parsed, hashed into the outputs hash, and included in fee/review logic. |
| `transparent.outputs[*].script_pubkey` | `Vec<u8>` | `Partial` | Parsed and hashed; display is available only for supported script types. |
| `transparent.outputs[*].redeem_script` | `Option<Vec<u8>>` | `Supported` | This separate PCZT field is not supported. |
| `transparent.outputs[*].bip32_derivation` | `BTreeMap<[u8; 33], Zip32Derivation>` | `Not supported` | Output derivation metadata is not read. |
| `transparent.outputs[*].user_address` | `Option<String>` | `Not supported` | The address is derived from `script_pubkey`; a host-provided `user_address` is not checked. |
| `transparent.outputs[*].proprietary` | `BTreeMap<String, Vec<u8>>` | `Not supported` | Proprietary maps are not supported. |

## Sapling

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `sapling::*` | `sapling::Bundle`, `Spend`, `Output` | `Skipped` | The Sapling part from `depz/librustzcash/pczt/src/sapling.rs` is intentionally not expanded: Sapling will not be supported. |

## `orchard::Bundle`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `orchard.actions` | `Vec<Action>` | `Partial` | Action count and action bytes are parsed/hashed in compact/memo/non-compact layout, but not as PCZT `Action`. |
| `orchard.flags` | `u8` | `Partial` | Present in Orchard digest data (`flags + valueBalance + anchor`), but not stored or validated as PCZT flags. |
| `orchard.value_sum` | `(u64, bool)` | `Partial` | The current stream uses signed Orchard value balance bytes; explicit conversion from PCZT `(magnitude, sign)` is required. |
| `orchard.anchor` | `[u8; 32]` | `Partial` | Present in Orchard digest data and hashed, but not stored as a separate field. |
| `orchard.zkproof` | `Option<Vec<u8>>` | `Partial` | Equivalent proof bytes participate in the Orchard non-compact hash; the PCZT optional field is not read and the proof is not verified. |
| `orchard.bsk` | `Option<[u8; 32]>` | `Partial` | The binding signing key can be passed through a separate `BindingSig` APDU; PCZT `bsk` is not read or cleared. |

## `orchard::Action`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `orchard.actions[*].cv_net` | `[u8; 32]` | `Supported` | Parsed/hashed in Orchard non-compact action data. |
| `orchard.actions[*].spend` | `Spend` | `Partial` | Some spend-effecting data is present in action bytes; metadata/prover fields are not read. |
| `orchard.actions[*].output` | `Output` | `Partial` | Output-effecting data is present in action bytes; plaintext metadata is read only through decrypt/recover when possible. |
| `orchard.actions[*].rcv` | `Option<[u8; 32]>` | `Not supported` | Value commitment randomness is not read. |

## `orchard::Spend`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `orchard.actions[*].spend.nullifier` | `[u8; 32]` | `Supported` | Parsed/hashed in compact action data. |
| `orchard.actions[*].spend.rk` | `[u8; 32]` | `Supported` | Parsed/hashed in non-compact action data. |
| `orchard.actions[*].spend.spend_auth_sig` | `Option<[u8; 64]>` | `Generated only` | `SpendAuthSig` mode returns a signature, but does not insert it into PCZT. |
| `orchard.actions[*].spend.recipient` | `Option<[u8; 43]>` | `Not supported` | The recipient address of the spent note is not present in the current signing stream. |
| `orchard.actions[*].spend.value` | `Option<u64>` | `Not supported` | Per-spend plaintext value is not read. |
| `orchard.actions[*].spend.rho` | `Option<[u8; 32]>` | `Not supported` | Prover metadata is not read. |
| `orchard.actions[*].spend.rseed` | `Option<[u8; 32]>` | `Not supported` | Prover metadata is not read. |
| `orchard.actions[*].spend.fvk` | `Option<[u8; 96]>` | `Not supported` | PCZT FVK metadata is not read; the device derives local keys from the path when needed. |
| `orchard.actions[*].spend.witness` | `Option<(u32, [[u8; 32]; 32])>` | `Not supported` | Merkle witness is not read. |
| `orchard.actions[*].spend.alpha` | `Option<[u8; 32]>` | `Generated only` | The device generates `alpha` for spend auth and returns it to the host; PCZT `alpha` is not read. |
| `orchard.actions[*].spend.zip32_derivation` | `Option<Zip32Derivation>` | `Partial` | The signing path is passed as a separate APDU parameter; PCZT derivation metadata is not read. |
| `orchard.actions[*].spend.dummy_sk` | `Option<[u8; 32]>` | `Not supported` | Dummy spending keys are not read; there is no separate reject policy for PCZT dummy fields. |
| `orchard.actions[*].spend.proprietary` | `BTreeMap<String, Vec<u8>>` | `Not supported` | Proprietary maps are not supported. |

## `orchard::Output`

| PCZT path | Rust type | Status | Current behavior / gap |
|---|---|---|---|
| `orchard.actions[*].output.cmx` | `[u8; 32]` | `Supported` | Parsed/hashed in compact action data. |
| `orchard.actions[*].output.ephemeral_key` | `[u8; 32]` | `Supported` | Parsed/hashed in compact action data and used for decrypt/recover. |
| `orchard.actions[*].output.enc_ciphertext` | `Vec<u8>` | `Partial` | The equivalent is assembled from compact prefix + memo + non-compact tail; the PCZT vector is not read directly. |
| `orchard.actions[*].output.out_ciphertext` | `Vec<u8>` | `Supported` | Parsed from non-compact action data and used for OVK recovery. |
| `orchard.actions[*].output.recipient` | `Option<[u8; 43]>` | `Partial` | The explicit PCZT field is not read; the recipient may be recovered only after successful decrypt/recover. |
| `orchard.actions[*].output.value` | `Option<u64>` | `Partial` | The explicit PCZT field is not read; the value may be recovered from ciphertext, and value balance is used for fees. |
| `orchard.actions[*].output.rseed` | `Option<[u8; 32]>` | `Not supported` | Prover metadata is not read. |
| `orchard.actions[*].output.ock` | `Option<[u8; 32]>` | `Not supported` | Outgoing cipher key metadata is not read. |
| `orchard.actions[*].output.zip32_derivation` | `Option<Zip32Derivation>` | `Not supported` | Output derivation metadata is not read. |
| `orchard.actions[*].output.user_address` | `Option<String>` | `Not supported` | The device builds the address from the decrypted output; a host-provided `user_address` is not checked. |
| `orchard.actions[*].output.proprietary` | `BTreeMap<String, Vec<u8>>` | `Not supported` | Proprietary maps are not supported. |

