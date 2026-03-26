//! Tree-wide SIGHASH policy audit tests.
//!
//! Exercises `audit_sighash_policy` with a manually constructed 2-level tree:
//! valid signatures, rejected sighash flags, amount-binding, and forgery detection.

#![cfg(feature = "schnorr-verify")]

use vpack::consensus::taproot_sighash::{
    audit_sighash_policy, extract_verify_key, sign_sighash_for_test, taproot_sighash,
    verify_schnorr_bip340,
};
use vpack::consensus::{TxInPreimage, TxOutPreimage};
use vpack::error::VPackError;
use vpack::header::TxVariant;
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};

/// Builds a P2TR scriptPubKey: OP_1 OP_PUSHBYTES_32 <32-byte-key>.
fn p2tr_script(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(0x51); // OP_1
    s.push(0x20); // OP_PUSHBYTES_32
    s.extend_from_slice(pubkey);
    s
}

/// Derive the test pubkey from the fixed signing key used by `sign_sighash_for_test`.
fn test_pubkey() -> [u8; 32] {
    let dummy_hash = [0u8; 32];
    let (_sig, pk) = sign_sighash_for_test(&dummy_hash);
    pk
}

/// A fee anchor script placeholder: OP_1 OP_PUSHBYTES_2 "4e73" (P2A-style).
fn fee_anchor_script() -> Vec<u8> {
    vec![0x51, 0x02, 0x4e, 0x73]
}

/// Dummy anchor outpoint (all zeros).
fn dummy_anchor() -> vpack::types::OutPoint {
    use vpack::types::hashes::Hash;
    vpack::types::OutPoint {
        txid: vpack::types::Txid::from_byte_array([0u8; 32]),
        vout: 0,
    }
}

/// Constructs a 2-level tree with valid signatures at each depth.
///
/// Returns `(tree, anchor_value, anchor_script)` ready for `audit_sighash_policy`.
///
/// - `depth1_sighash_flag`: hash_type for the first GenesisItem.
/// - `depth2_sighash_flag`: hash_type for the second GenesisItem.
fn build_signed_tree(
    depth1_sighash_flag: u8,
    depth2_sighash_flag: u8,
) -> (VPackTree, u64, Vec<u8>) {
    use vpack::consensus::tx_factory::tx_preimage;
    use vpack::types::hashes::{sha256d, Hash};

    let pk = test_pubkey();
    let script = p2tr_script(&pk);
    let anchor_script = script.clone();
    let anchor_value: u64 = 10_000;
    let fee_script = fee_anchor_script();

    let child_amount_1: u64 = 9_000;
    let sibling_value_1: u64 = 1_000;

    let child_amount_2: u64 = 8_000;
    let sibling_value_2: u64 = 1_000;

    // --- Depth 1: spends the anchor ---
    let depth1_outputs = vec![
        TxOutPreimage {
            value: child_amount_1,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_value_1,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let depth1_input = TxInPreimage {
        prev_out_txid: [0u8; 32],
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let depth1_sighash = taproot_sighash(
        3,
        0,
        &depth1_input,
        anchor_value,
        &anchor_script,
        &depth1_outputs,
        depth1_sighash_flag,
    );
    let (depth1_sig, _) = sign_sighash_for_test(&depth1_sighash);

    let depth1_preimage = tx_preimage(3, &[depth1_input], &depth1_outputs, 0);
    let depth1_txid = sha256d::Hash::hash(&depth1_preimage).to_byte_array();

    // --- Depth 2: spends depth-1's output 0 ---
    let depth2_outputs = vec![
        TxOutPreimage {
            value: child_amount_2,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_value_2,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let depth2_input = TxInPreimage {
        prev_out_txid: depth1_txid,
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let depth2_sighash = taproot_sighash(
        3,
        0,
        &depth2_input,
        child_amount_1,
        &script,
        &depth2_outputs,
        depth2_sighash_flag,
    );
    let (depth2_sig, _) = sign_sighash_for_test(&depth2_sighash);

    let sibling1 = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_value_1,
        script: fee_script.clone(),
    };
    let sibling2 = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_value_2,
        script: fee_script.clone(),
    };

    let genesis_item_1 = GenesisItem {
        siblings: vec![sibling1],
        child_amount: child_amount_1,
        child_script_pubkey: script.clone(),
        signature: Some(depth1_sig),
        sighash_flag: depth1_sighash_flag,
        ..Default::default()
    };
    let genesis_item_2 = GenesisItem {
        siblings: vec![sibling2],
        child_amount: child_amount_2,
        child_script_pubkey: script.clone(),
        signature: Some(depth2_sig),
        sighash_flag: depth2_sighash_flag,
        ..Default::default()
    };

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: child_amount_2,
            vout: 0,
            sequence: 0xFFFF_FFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: script.clone(),
        },
        leaf_siblings: vec![],
        path: vec![genesis_item_1, genesis_item_2],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: fee_script,
        internal_key: [0u8; 32],
        asp_expiry_script: vec![],
    };

    (tree, anchor_value, anchor_script)
}

// ---------------------------------------------------------------------------
// Test 1: Safe Fee-Bumping (SIGHASH_ALL | ANYONECANPAY)
// ---------------------------------------------------------------------------

#[test]
fn audit_accepts_sighash_all_anyonecanpay() {
    let (tree, anchor_value, anchor_script) = build_signed_tree(0x00, 0x81);
    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert!(
        result.is_ok(),
        "Tree with SIGHASH_DEFAULT + SIGHASH_ALL|ACP should pass audit: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Test 2: Dangerous Malleability — SIGHASH_NONE rejected
// ---------------------------------------------------------------------------

#[test]
fn audit_rejects_sighash_none() {
    let (mut tree, anchor_value, anchor_script) = build_signed_tree(0x00, 0x00);
    tree.path[1].sighash_flag = 0x02;

    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSighashFlag(0x02)),
        "SIGHASH_NONE (0x02) must be rejected by policy filter"
    );
}

// ---------------------------------------------------------------------------
// Test 3: Amount Binding — wrong anchor value breaks sig verification
// ---------------------------------------------------------------------------

#[test]
fn audit_detects_wrong_anchor_amount() {
    let (tree, anchor_value, anchor_script) = build_signed_tree(0x00, 0x00);
    let wrong_value = anchor_value + 1;

    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, wrong_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSignature),
        "Changing anchor value by 1 satoshi must invalidate the BIP-341 sighash"
    );
}

// ---------------------------------------------------------------------------
// Test 4: Signature Forgery — corrupted signature byte
// ---------------------------------------------------------------------------

#[test]
fn audit_detects_signature_forgery() {
    let (mut tree, anchor_value, anchor_script) = build_signed_tree(0x00, 0x00);

    if let Some(ref mut sig) = tree.path[0].signature {
        sig[0] ^= 0xFF;
    }

    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSignature),
        "Flipping a signature byte must be detected as forgery"
    );
}

// ---------------------------------------------------------------------------
// 3-step signed tree builder and deep-path integrity tests
// ---------------------------------------------------------------------------

fn build_signed_tree_3_steps() -> (VPackTree, u64, Vec<u8>) {
    use vpack::consensus::tx_factory::tx_preimage;
    use vpack::types::hashes::{sha256d, Hash};

    let pk = test_pubkey();
    let script = p2tr_script(&pk);
    let anchor_script = script.clone();
    let anchor_value: u64 = 12_000;
    let fee_script = fee_anchor_script();

    let child_amount_1: u64 = 11_000;
    let sibling_value_1: u64 = 1_000;

    let child_amount_2: u64 = 10_000;
    let sibling_value_2: u64 = 1_000;

    let child_amount_3: u64 = 9_000;
    let sibling_value_3: u64 = 1_000;

    // --- Depth 1: spends the anchor ---
    let depth1_outputs = vec![
        TxOutPreimage {
            value: child_amount_1,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_value_1,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let depth1_input = TxInPreimage {
        prev_out_txid: [0u8; 32],
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let depth1_sighash = taproot_sighash(
        3,
        0,
        &depth1_input,
        anchor_value,
        &anchor_script,
        &depth1_outputs,
        0x00,
    );
    let (depth1_sig, _) = sign_sighash_for_test(&depth1_sighash);

    let depth1_preimage = tx_preimage(3, &[depth1_input], &depth1_outputs, 0);
    let depth1_txid = sha256d::Hash::hash(&depth1_preimage).to_byte_array();

    // --- Depth 2: spends depth-1's output 0 ---
    let depth2_outputs = vec![
        TxOutPreimage {
            value: child_amount_2,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_value_2,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let depth2_input = TxInPreimage {
        prev_out_txid: depth1_txid,
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let depth2_sighash = taproot_sighash(
        3,
        0,
        &depth2_input,
        child_amount_1,
        &script,
        &depth2_outputs,
        0x00,
    );
    let (depth2_sig, _) = sign_sighash_for_test(&depth2_sighash);

    let depth2_preimage = tx_preimage(3, &[depth2_input], &depth2_outputs, 0);
    let depth2_txid = sha256d::Hash::hash(&depth2_preimage).to_byte_array();

    // --- Depth 3: spends depth-2's output 0 ---
    let depth3_outputs = vec![
        TxOutPreimage {
            value: child_amount_3,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_value_3,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let depth3_input = TxInPreimage {
        prev_out_txid: depth2_txid,
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let depth3_sighash = taproot_sighash(
        3,
        0,
        &depth3_input,
        child_amount_2,
        &script,
        &depth3_outputs,
        0x00,
    );
    let (depth3_sig, _) = sign_sighash_for_test(&depth3_sighash);

    let sibling1 = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_value_1,
        script: fee_script.clone(),
    };
    let sibling2 = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_value_2,
        script: fee_script.clone(),
    };
    let sibling3 = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_value_3,
        script: fee_script.clone(),
    };

    let genesis_item_1 = GenesisItem {
        siblings: vec![sibling1],
        child_amount: child_amount_1,
        child_script_pubkey: script.clone(),
        signature: Some(depth1_sig),
        sighash_flag: 0x00,
        ..Default::default()
    };
    let genesis_item_2 = GenesisItem {
        siblings: vec![sibling2],
        child_amount: child_amount_2,
        child_script_pubkey: script.clone(),
        signature: Some(depth2_sig),
        sighash_flag: 0x00,
        ..Default::default()
    };
    let genesis_item_3 = GenesisItem {
        siblings: vec![sibling3],
        child_amount: child_amount_3,
        child_script_pubkey: script.clone(),
        signature: Some(depth3_sig),
        sighash_flag: 0x00,
        ..Default::default()
    };

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: child_amount_3,
            vout: 0,
            sequence: 0xFFFF_FFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: script.clone(),
        },
        leaf_siblings: vec![],
        path: vec![genesis_item_1, genesis_item_2, genesis_item_3],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: fee_script,
        internal_key: [0u8; 32],
        asp_expiry_script: vec![],
    };

    (tree, anchor_value, anchor_script)
}

// ---------------------------------------------------------------------------
// Test 5: 3-step tree with all valid signatures passes audit
// ---------------------------------------------------------------------------

#[test]
fn audit_3step_passes_when_valid() {
    let (tree, anchor_value, anchor_script) = build_signed_tree_3_steps();
    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert!(
        result.is_ok(),
        "3-step tree with all valid signatures must pass audit: {:?}",
        result.err()
    );
}

// ---------------------------------------------------------------------------
// Test 6: Forgery at step 3 only — proves the loop does not short-circuit
// ---------------------------------------------------------------------------

#[test]
fn test_sighash_auditor_path_integrity_step3_forgery() {
    let (mut tree, anchor_value, anchor_script) = build_signed_tree_3_steps();

    if let Some(ref mut sig) = tree.path[2].signature {
        sig[31] ^= 0x01;
    }

    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSignature),
        "Mutating a single byte in step 3's signature must be detected as forgery"
    );
}

// ---------------------------------------------------------------------------
// Test 7: Forgery at step 2 with valid steps 1 and 3
// ---------------------------------------------------------------------------

#[test]
fn test_sighash_auditor_step2_forgery_with_valid_step1_and_step3() {
    let (mut tree, anchor_value, anchor_script) = build_signed_tree_3_steps();

    if let Some(ref mut sig) = tree.path[1].signature {
        sig[0] ^= 0xFF;
    }

    let result = audit_sighash_policy(&tree, TxVariant::V3Anchored, anchor_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSignature),
        "Forgery at step 2 must be caught even when steps 1 and 3 are valid"
    );
}

// ---------------------------------------------------------------------------
// Root G: extract_verify_key edge cases
// ---------------------------------------------------------------------------

#[test]
fn test_extract_verify_key_rejects_34_byte_non_p2tr() {
    let mut script = [0u8; 34];
    script[0] = 0x00;
    script[1] = 0x20;
    script[2..].copy_from_slice(&[0xAA; 32]);

    assert_eq!(
        extract_verify_key(&script),
        None,
        "34-byte script not starting with P2TR prefix must return None"
    );
}

#[test]
fn test_extract_verify_key_32_byte_raw_key_roundtrip() {
    let pk = test_pubkey();

    let extracted = extract_verify_key(&pk);
    assert!(extracted.is_some(), "32-byte raw key must be accepted");
    assert_eq!(extracted.unwrap(), pk, "Extracted key must match input");

    let dummy_msg = [0x99u8; 32];
    let (sig, _) = sign_sighash_for_test(&dummy_msg);
    let result = verify_schnorr_bip340(&extracted.unwrap(), &dummy_msg, &sig);
    assert!(
        result.is_ok(),
        "Signature verification with extracted 32-byte key must pass: {:?}",
        result.err()
    );
}

#[test]
fn test_extract_verify_key_accepts_valid_p2tr() {
    let pk = test_pubkey();
    let script = p2tr_script(&pk);

    let extracted = extract_verify_key(&script);
    assert!(extracted.is_some(), "Valid P2TR script must yield Some");
    assert_eq!(
        extracted.unwrap(),
        pk,
        "Extracted key must match embedded key"
    );
}

// ---------------------------------------------------------------------------
// Root H: V3Plain audit branch — build_signed_tree_v3plain
// ---------------------------------------------------------------------------

fn build_signed_tree_v3plain() -> (VPackTree, u64, Vec<u8>) {
    use vpack::consensus::tx_factory::tx_preimage;
    use vpack::types::hashes::{sha256d, Hash};

    let pk = test_pubkey();
    let script = p2tr_script(&pk);
    let anchor_script = script.clone();
    let anchor_value: u64 = 20_000;
    let fee_script = fee_anchor_script();

    let child_amount_0: u64 = 12_000;
    let sibling_a_value: u64 = 8_000;

    let child_amount_1: u64 = 5_000;
    let sibling_c_value: u64 = 3_000;

    // --- Step 0: parent_index = 0, 2 siblings ---
    // Outputs: [child, sibling_a(P2TR), sibling_b(fee)]
    let step0_outputs = vec![
        TxOutPreimage {
            value: child_amount_0,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: sibling_a_value,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: 0,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let step0_input = TxInPreimage {
        prev_out_txid: [0u8; 32],
        prev_out_vout: 0,
        sequence: 0xFFFF_FFFF,
    };
    let step0_sighash = taproot_sighash(
        3,
        0,
        &step0_input,
        anchor_value,
        &anchor_script,
        &step0_outputs,
        0x00,
    );
    let (sig_0, _) = sign_sighash_for_test(&step0_sighash);

    let step0_txid =
        sha256d::Hash::hash(&tx_preimage(3, &[step0_input], &step0_outputs, 0)).to_byte_array();

    // Hand-off: vout = path[1].parent_index = 1
    // Next prevout: sibling_a (8000, P2TR)

    // --- Step 1: parent_index = 1, 2 siblings ---
    // Outputs: [sibling_c(P2TR), child, sibling_d(fee)]
    let step1_outputs = vec![
        TxOutPreimage {
            value: sibling_c_value,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: child_amount_1,
            script_pubkey: script.as_slice(),
        },
        TxOutPreimage {
            value: 0,
            script_pubkey: fee_script.as_slice(),
        },
    ];
    let step1_input = TxInPreimage {
        prev_out_txid: step0_txid,
        prev_out_vout: 1,
        sequence: 0xFFFF_FFFF,
    };
    let step1_sighash = taproot_sighash(
        3,
        0,
        &step1_input,
        sibling_a_value,
        &script,
        &step1_outputs,
        0x00,
    );
    let (sig_1, _) = sign_sighash_for_test(&step1_sighash);

    let sibling_a = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_a_value,
        script: script.clone(),
    };
    let sibling_b = SiblingNode::Compact {
        hash: [0u8; 32],
        value: 0,
        script: fee_script.clone(),
    };
    let sibling_c = SiblingNode::Compact {
        hash: [0u8; 32],
        value: sibling_c_value,
        script: script.clone(),
    };
    let sibling_d = SiblingNode::Compact {
        hash: [0u8; 32],
        value: 0,
        script: fee_script.clone(),
    };

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: child_amount_1,
            vout: 0,
            sequence: 0xFFFF_FFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: script.clone(),
        },
        leaf_siblings: vec![],
        path: vec![
            GenesisItem {
                siblings: vec![sibling_a, sibling_b],
                parent_index: 0,
                sequence: 0xFFFF_FFFF,
                child_amount: child_amount_0,
                child_script_pubkey: script.clone(),
                signature: Some(sig_0),
                sighash_flag: 0x00,
            },
            GenesisItem {
                siblings: vec![sibling_c, sibling_d],
                parent_index: 1,
                sequence: 0xFFFF_FFFF,
                child_amount: child_amount_1,
                child_script_pubkey: script.clone(),
                signature: Some(sig_1),
                sighash_flag: 0x00,
            },
        ],
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: fee_script,
        internal_key: [0u8; 32],
        asp_expiry_script: vec![],
    };

    (tree, anchor_value, anchor_script)
}

#[test]
fn test_audit_v3plain_valid() {
    let (tree, anchor_value, anchor_script) = build_signed_tree_v3plain();
    let result = audit_sighash_policy(&tree, TxVariant::V3Plain, anchor_value, &anchor_script);
    assert!(
        result.is_ok(),
        "V3Plain 2-step tree with valid signatures must pass audit: {:?}",
        result.err()
    );
}

#[test]
fn test_audit_v3plain_corrupted_sig_step1() {
    let (mut tree, anchor_value, anchor_script) = build_signed_tree_v3plain();

    if let Some(ref mut sig) = tree.path[1].signature {
        sig[31] ^= 0x01;
    }

    let result = audit_sighash_policy(&tree, TxVariant::V3Plain, anchor_value, &anchor_script);
    assert_eq!(
        result,
        Err(VPackError::InvalidSignature),
        "V3Plain: corrupted sig at step 1 must be detected as forgery"
    );
}
