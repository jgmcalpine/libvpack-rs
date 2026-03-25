//! Property-based tests for [`vpack::validate_timelocks`].

use bitcoin::hashes::Hash;
use proptest::prelude::*;
use vpack::consensus::second_tech::{compile_bark_expiry_script, encode_bark_cltv};
use vpack::error::{TimelockViolationReason, VPackError};
use vpack::payload::tree::{GenesisItem, VPackTree, VtxoLeaf};
use vpack::types::{OutPoint, Txid};
use vpack::validate_timelocks;

const OP_CSV: u8 = 0xb2;

/// BIP-113 height vs time boundary (matches `timelocks` module).
const LOCKTIME_THRESHOLD: u32 = 500_000_000;

/// BIP-68 disable flag on `nSequence`.
const SEQUENCE_DISABLE_BIT: u32 = 1 << 31;

/// BIP-68 type flag: seconds (512 s units) when set.
const SEQUENCE_TYPE_SECONDS: u32 = 1 << 22;

fn asp_script_csv_minimal_push(value: u32) -> Vec<u8> {
    let bytes = encode_bark_cltv(value);
    let mut script = Vec::with_capacity(1 + bytes.len() + 1);
    script.push(bytes.len() as u8);
    script.extend_from_slice(&bytes);
    script.push(OP_CSV);
    script
}

fn sample_p2tr_spk() -> Vec<u8> {
    let mut spk = vec![0x51u8, 0x20];
    spk.extend_from_slice(&[0xEEu8; 32]);
    spk
}

fn base_tree() -> VPackTree {
    let txid = Txid::from_byte_array([0x22u8; 32]);
    VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0xFFFF_FFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: sample_p2tr_spk(),
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor: OutPoint { txid, vout: 0 },
        asset_id: None,
        fee_anchor_script: Vec::new(),
        internal_key: [0x44u8; 32],
        asp_expiry_script: Vec::new(),
    }
}

/// Block-type CSV script (operand `< 500_000_000`, type bit clear) and matching sequences.
fn tree_with_csv_block(script_mag: u32, seq_path: u32, seq_leaf: u32) -> VPackTree {
    let mut tree = base_tree();
    tree.asp_expiry_script = asp_script_csv_minimal_push(script_mag);
    tree.path = vec![GenesisItem {
        sequence: seq_path,
        ..Default::default()
    }];
    tree.leaf.sequence = seq_leaf;
    tree
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(1000))]

    #[test]
    fn csv_random_boundary(script_mag in 0u32..65536u32, seq_lo in 0u32..65536u32) {
        let tree = tree_with_csv_block(script_mag, seq_lo, seq_lo);
        let res = validate_timelocks(&tree);
        if seq_lo >= script_mag {
            prop_assert!(res.is_ok());
        } else if script_mag > 0 {
            prop_assert_eq!(
                res,
                Err(VPackError::TimelockViolation {
                    expected: script_mag,
                    actual: seq_lo,
                    is_relative: true,
                    reason: TimelockViolationReason::ValueTooLow,
                })
            );
        } else {
            prop_assert!(res.is_ok());
        }
    }

    #[test]
    fn cltv_random_boundary(script_val in any::<u32>(), tx_val in any::<u32>()) {
        let server_key = [0x77u8; 32];
        let mut tree = base_tree();
        tree.asp_expiry_script = compile_bark_expiry_script(script_val, &server_key);
        tree.leaf.expiry = tx_val;
        let res = validate_timelocks(&tree);
        if script_val < LOCKTIME_THRESHOLD {
            if tx_val >= LOCKTIME_THRESHOLD {
                prop_assert_eq!(
                    res,
                    Err(VPackError::TimelockViolation {
                        expected: script_val,
                        actual: tx_val,
                        is_relative: false,
                        reason: TimelockViolationReason::TypeMismatch,
                    })
                );
            } else if tx_val >= script_val {
                prop_assert!(res.is_ok());
            } else {
                prop_assert_eq!(
                    res,
                    Err(VPackError::TimelockViolation {
                        expected: script_val,
                        actual: tx_val,
                        is_relative: false,
                        reason: TimelockViolationReason::ValueTooLow,
                    })
                );
            }
        } else if tx_val < LOCKTIME_THRESHOLD {
            prop_assert_eq!(
                res,
                Err(VPackError::TimelockViolation {
                    expected: script_val,
                    actual: tx_val,
                    is_relative: false,
                    reason: TimelockViolationReason::TypeMismatch,
                })
            );
        } else if tx_val >= script_val {
            prop_assert!(res.is_ok());
        } else {
            prop_assert_eq!(
                res,
                Err(VPackError::TimelockViolation {
                    expected: script_val,
                    actual: tx_val,
                    is_relative: false,
                    reason: TimelockViolationReason::ValueTooLow,
                })
            );
        }
    }

    #[test]
    fn csv_disable_bit_always_fails(script_mag in 1u32..65536u32) {
        let disabled_seq = SEQUENCE_DISABLE_BIT | (script_mag & 0xFFFF);
        let tree = tree_with_csv_block(script_mag, disabled_seq, disabled_seq);
        let res = validate_timelocks(&tree);
        prop_assert_eq!(
            res,
            Err(VPackError::TimelockViolation {
                expected: 0,
                actual: disabled_seq,
                is_relative: true,
                reason: TimelockViolationReason::LocktimeDisabled,
            })
        );
    }
}

#[test]
fn csv_type_mismatch_fails() {
    let script_operand = SEQUENCE_TYPE_SECONDS | 5u32;
    let mut tree = base_tree();
    tree.asp_expiry_script = asp_script_csv_minimal_push(script_operand);
    tree.path = vec![GenesisItem {
        sequence: 0xFFFF,
        ..Default::default()
    }];
    tree.leaf.sequence = 0xFFFF;
    assert_eq!(
        validate_timelocks(&tree),
        Err(VPackError::TimelockViolation {
            expected: 5,
            actual: 0xFFFF,
            is_relative: true,
            reason: TimelockViolationReason::TypeMismatch,
        })
    );
}

#[test]
fn csv_edge_zero_zero_ok() {
    assert!(validate_timelocks(&tree_with_csv_block(0, 0, 0)).is_ok());
}

#[test]
fn csv_edge_one_vs_zero_fails() {
    assert_eq!(
        validate_timelocks(&tree_with_csv_block(1, 0, 0)),
        Err(VPackError::TimelockViolation {
            expected: 1,
            actual: 0,
            is_relative: true,
            reason: TimelockViolationReason::ValueTooLow,
        })
    );
}

#[test]
fn csv_edge_max_sequence_disable_bit_rejected() {
    let tree = tree_with_csv_block(1, 0xFFFF_FFFF, 0xFFFF_FFFF);
    assert_eq!(
        validate_timelocks(&tree),
        Err(VPackError::TimelockViolation {
            expected: 0,
            actual: 0xFFFF_FFFF,
            is_relative: true,
            reason: TimelockViolationReason::LocktimeDisabled,
        })
    );
}

#[test]
fn csv_edge_small_requirement_satisfied_without_disable_bit() {
    let tree = tree_with_csv_block(1, 0x0000_0001, 0x0000_0001);
    assert!(validate_timelocks(&tree).is_ok());
}

#[test]
fn csv_edge_exact_equality_ok() {
    let v = 144u32;
    assert!(validate_timelocks(&tree_with_csv_block(v, v, v)).is_ok());
}

/// `OP_5` (0x55) as the CSV argument: small-int push ops must parse.
#[test]
fn csv_op_5_push_before_csv() {
    let mut tree = base_tree();
    tree.asp_expiry_script = vec![0x55, OP_CSV];
    tree.path = vec![GenesisItem {
        sequence: 5,
        ..Default::default()
    }];
    tree.leaf.sequence = 5;
    assert!(validate_timelocks(&tree).is_ok());
}

#[test]
fn cltv_edge_zero_zero_ok() {
    let mut tree = base_tree();
    tree.asp_expiry_script = compile_bark_expiry_script(0, &[0x88u8; 32]);
    tree.leaf.expiry = 0;
    assert!(validate_timelocks(&tree).is_ok());
}

#[test]
fn cltv_edge_exact_equality_ok() {
    let v = 500u32;
    let mut tree = base_tree();
    tree.asp_expiry_script = compile_bark_expiry_script(v, &[0x99u8; 32]);
    tree.leaf.expiry = v;
    assert!(validate_timelocks(&tree).is_ok());
}

#[test]
fn no_timelock_opcodes_is_ok() {
    let mut tree = base_tree();
    tree.asp_expiry_script = vec![0x63];
    tree.path = vec![GenesisItem {
        sequence: 0,
        ..Default::default()
    }];
    tree.leaf.sequence = 0;
    assert!(validate_timelocks(&tree).is_ok());
}
