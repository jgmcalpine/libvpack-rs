//! TDD tests for BIP-341 Taproot tree reconstruction primitives.
//! Validates `tap_leaf_hash`, `tap_branch_hash`, balanced Merkle root
//! construction, full tree reconstruction, and path exclusivity sabotage
//! against reference vectors extracted from arkd (Ark Labs) and bark (Second Tech).

mod vectors;

use bitcoin::hashes::Hash;
use vpack::error::VPackError;
use vpack::header::TxVariant;
use vpack::payload::tree::{VPackTree, VtxoLeaf};
use vpack::taproot::tap_leaf_hash;
use vpack::verify_path_exclusivity;

use vectors::arkd::{ARKD_2_LEAF_TREE, ARKD_6_LEAF_TREE};
use vectors::bark::{BARK_COSIGN_TAPROOT, BARK_LEAF_COSIGN_SORTING};

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex string")
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let bytes = hex_to_vec(s);
    assert_eq!(bytes.len(), 32, "expected 32-byte hex, got {}", bytes.len());
    bytes.try_into().unwrap()
}

#[test]
fn test_tapleaf_hash_against_arkd() {
    let script = hex_to_vec(ARKD_2_LEAF_TREE.leaf_scripts[0]);
    let expected = hex_to_32(ARKD_2_LEAF_TREE.tapleaf_hashes[0]);

    let result = vpack::taproot::tap_leaf_hash(&script);
    assert_eq!(
        result, expected,
        "TapLeaf hash mismatch for ARKD_2_LEAF_TREE leaf 0"
    );
}

#[test]
fn test_tapbranch_sorting_against_bark() {
    let left = hex_to_32(BARK_LEAF_COSIGN_SORTING.left_sorted);
    let right = hex_to_32(BARK_LEAF_COSIGN_SORTING.right_sorted);
    let expected = hex_to_32(BARK_LEAF_COSIGN_SORTING.tap_branch_hash);

    let forward = vpack::taproot::tap_branch_hash(left, right);
    assert_eq!(
        forward, expected,
        "TapBranch hash mismatch (left, right) order"
    );

    let reversed = vpack::taproot::tap_branch_hash(right, left);
    assert_eq!(
        reversed, expected,
        "TapBranch hash must be identical regardless of input order (sorting proof)"
    );
}

#[test]
fn test_taptweak_against_arkd() {
    let internal_key = hex_to_32(ARKD_2_LEAF_TREE.internal_key);
    let merkle_root = hex_to_32(ARKD_2_LEAF_TREE.merkle_root);
    let expected = hex_to_32(ARKD_2_LEAF_TREE.tweaked_pubkey);

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid ARKD_2_LEAF_TREE must produce a tweaked key");
    assert_eq!(result, expected, "TapTweak mismatch for ARKD_2_LEAF_TREE");
}

#[test]
fn test_taptweak_against_arkd_6_leaf() {
    let internal_key = hex_to_32(ARKD_6_LEAF_TREE.internal_key);
    let merkle_root = hex_to_32(ARKD_6_LEAF_TREE.merkle_root);
    let expected = hex_to_32(ARKD_6_LEAF_TREE.tweaked_pubkey);

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid ARKD_6_LEAF_TREE must produce a tweaked key");
    assert_eq!(result, expected, "TapTweak mismatch for ARKD_6_LEAF_TREE");
}

#[test]
fn test_taptweak_against_bark() {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let merkle_root = hex_to_32(BARK_COSIGN_TAPROOT.merkle_root);
    let expected = hex_to_32(BARK_COSIGN_TAPROOT.tweaked_pubkey);

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid BARK_COSIGN_TAPROOT must produce a tweaked key");
    assert_eq!(
        result, expected,
        "TapTweak mismatch for BARK_COSIGN_TAPROOT"
    );
}

#[test]
fn test_balanced_merkle_root_6_leaf() {
    let leaf_hashes: Vec<[u8; 32]> = ARKD_6_LEAF_TREE
        .tapleaf_hashes
        .iter()
        .map(|h| hex_to_32(h))
        .collect();
    let expected = hex_to_32(ARKD_6_LEAF_TREE.merkle_root);

    let result = vpack::taproot::compute_balanced_merkle_root(&leaf_hashes)
        .expect("6 leaves must produce a root");
    assert_eq!(
        result, expected,
        "Balanced Merkle root mismatch for ARKD_6_LEAF_TREE (recursive halving topology)"
    );
}

#[test]
fn test_ark_labs_full_tree_reconstruction() {
    let internal_key = hex_to_32(ARKD_2_LEAF_TREE.internal_key);
    let asp_expiry_script = hex_to_vec(ARKD_2_LEAF_TREE.leaf_scripts[1]);
    let expected_merkle_root = hex_to_32(ARKD_2_LEAF_TREE.merkle_root);
    let expected_tweaked = hex_to_32(ARKD_2_LEAF_TREE.tweaked_pubkey);

    let mut p2tr_script_pubkey = vec![0x51, 0x20];
    p2tr_script_pubkey.extend_from_slice(&expected_tweaked);

    let dummy_anchor = {
        let txid = vpack::types::Txid::from_byte_array([0u8; 32]);
        vpack::types::OutPoint { txid, vout: 0 }
    };

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0xFFFFFFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: p2tr_script_pubkey.clone(),
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor: dummy_anchor,
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    };

    let merkle_root = vpack::compute_ark_labs_merkle_root(&tree)
        .expect("compute_ark_labs_merkle_root must succeed for a valid 2-leaf tree");

    assert_eq!(
        merkle_root,
        expected_merkle_root,
        "Merkle root mismatch: got {}, expected {}",
        hex::encode(merkle_root),
        ARKD_2_LEAF_TREE.merkle_root,
    );

    let tweaked_key = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid point must produce a tweaked key");

    assert_eq!(
        tweaked_key,
        expected_tweaked,
        "Tweaked key mismatch: got {}, expected {}",
        hex::encode(tweaked_key),
        ARKD_2_LEAF_TREE.tweaked_pubkey,
    );

    assert_eq!(
        &tweaked_key,
        &p2tr_script_pubkey[2..34],
        "Tweaked key must match the x-only pubkey embedded in the P2TR scriptPubKey"
    );
}

#[test]
fn test_bark_full_tree_reconstruction() {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let asp_expiry_script = hex_to_vec(BARK_COSIGN_TAPROOT.leaf_scripts[0]);
    let expected_merkle_root = hex_to_32(BARK_COSIGN_TAPROOT.merkle_root);
    let expected_tweaked = hex_to_32(BARK_COSIGN_TAPROOT.tweaked_pubkey);

    let mut p2tr_script_pubkey = vec![0x51, 0x20];
    p2tr_script_pubkey.extend_from_slice(&expected_tweaked);

    let dummy_anchor = {
        let txid = vpack::types::Txid::from_byte_array([0u8; 32]);
        vpack::types::OutPoint { txid, vout: 0 }
    };

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0x00000000,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: p2tr_script_pubkey.clone(),
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor: dummy_anchor,
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    };

    let merkle_root = vpack::compute_bark_merkle_root(&tree)
        .expect("compute_bark_merkle_root must succeed for a valid Bark expiry script");

    assert_eq!(
        merkle_root,
        expected_merkle_root,
        "Merkle root mismatch: got {}, expected {}",
        hex::encode(merkle_root),
        BARK_COSIGN_TAPROOT.merkle_root,
    );

    let expiry_tapleaf = tap_leaf_hash(&hex_to_vec(BARK_COSIGN_TAPROOT.leaf_scripts[0]));
    let expected_right_sorted = hex_to_32(BARK_LEAF_COSIGN_SORTING.right_sorted);
    assert_eq!(
        expiry_tapleaf, expected_right_sorted,
        "Expiry TapLeaf hash must match BARK_LEAF_COSIGN_SORTING.right_sorted, \
         confirming parse->u32->re-encode->compile roundtrip is identical to Bark reference"
    );

    let tweaked_key = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid point must produce a tweaked key");

    assert_eq!(
        tweaked_key,
        expected_tweaked,
        "Tweaked key mismatch: got {}, expected {}",
        hex::encode(tweaked_key),
        BARK_COSIGN_TAPROOT.tweaked_pubkey,
    );

    assert_eq!(
        &tweaked_key,
        &p2tr_script_pubkey[2..34],
        "Tweaked key must match the x-only pubkey embedded in the P2TR scriptPubKey"
    );
}

// ---------------------------------------------------------------------------
// Helper: build a valid Ark Labs tree for path exclusivity testing
// ---------------------------------------------------------------------------

fn build_valid_ark_labs_tree() -> VPackTree {
    let internal_key = hex_to_32(ARKD_2_LEAF_TREE.internal_key);
    let asp_expiry_script = hex_to_vec(ARKD_2_LEAF_TREE.leaf_scripts[1]);
    let expected_tweaked = hex_to_32(ARKD_2_LEAF_TREE.tweaked_pubkey);

    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&expected_tweaked);

    let dummy_anchor = {
        let txid = vpack::types::Txid::from_byte_array([0u8; 32]);
        vpack::types::OutPoint { txid, vout: 0 }
    };

    VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0xFFFFFFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: p2tr,
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor: dummy_anchor,
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    }
}

fn build_valid_bark_tree() -> VPackTree {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let asp_expiry_script = hex_to_vec(BARK_COSIGN_TAPROOT.leaf_scripts[0]);
    let expected_tweaked = hex_to_32(BARK_COSIGN_TAPROOT.tweaked_pubkey);

    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&expected_tweaked);

    let dummy_anchor = {
        let txid = vpack::types::Txid::from_byte_array([0u8; 32]);
        vpack::types::OutPoint { txid, vout: 0 }
    };

    VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0x00000000,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: p2tr,
        },
        leaf_siblings: Vec::new(),
        path: Vec::new(),
        anchor: dummy_anchor,
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    }
}

// ---------------------------------------------------------------------------
// Path Exclusivity: valid trees must pass
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_valid_ark_labs() {
    let tree = build_valid_ark_labs_tree();
    verify_path_exclusivity(&tree, TxVariant::V3Anchored)
        .expect("valid Ark Labs tree must pass path exclusivity");
}

#[test]
fn test_path_exclusivity_valid_bark() {
    let tree = build_valid_bark_tree();
    verify_path_exclusivity(&tree, TxVariant::V3Plain)
        .expect("valid Bark tree must pass path exclusivity");
}

// ---------------------------------------------------------------------------
// Path Exclusivity: missing data must be rejected
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_missing_data() {
    let mut tree = build_valid_ark_labs_tree();
    tree.asp_expiry_script = vec![];
    let result = verify_path_exclusivity(&tree, TxVariant::V3Anchored);
    assert_eq!(
        result,
        Err(VPackError::MissingExclusivityData),
        "empty asp_expiry_script must yield MissingExclusivityData"
    );
}

// ---------------------------------------------------------------------------
// Sabotage 1: Mutated Internal Key
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_sabotage_mutated_internal_key_ark_labs() {
    let mut tree = build_valid_ark_labs_tree();
    tree.internal_key[0] ^= 0x01;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Anchored);
    assert_eq!(
        result,
        Err(VPackError::PathExclusivityViolation),
        "flipping one bit in internal_key must cascade into a different tweaked key"
    );
}

#[test]
fn test_path_exclusivity_sabotage_mutated_internal_key_bark() {
    let mut tree = build_valid_bark_tree();
    tree.internal_key[0] ^= 0x01;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Plain);
    assert_eq!(
        result,
        Err(VPackError::PathExclusivityViolation),
        "flipping one bit in internal_key must cascade into a different tweaked key"
    );
}

// ---------------------------------------------------------------------------
// Sabotage 2: Backdoored Expiry Script
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_sabotage_backdoored_expiry_ark_labs() {
    let mut tree = build_valid_ark_labs_tree();
    let mid = tree.asp_expiry_script.len() / 2;
    tree.asp_expiry_script[mid] ^= 0x01;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Anchored);
    assert!(
        matches!(
            result,
            Err(VPackError::PathExclusivityViolation) | Err(VPackError::InvalidArkLabsScript)
        ),
        "mutating a byte inside asp_expiry_script must fail: got {:?}",
        result
    );
}

#[test]
fn test_path_exclusivity_sabotage_backdoored_expiry_bark() {
    let mut tree = build_valid_bark_tree();
    let mid = tree.asp_expiry_script.len() / 2;
    tree.asp_expiry_script[mid] ^= 0x01;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Plain);
    assert!(
        matches!(
            result,
            Err(VPackError::PathExclusivityViolation) | Err(VPackError::InvalidBarkScript)
        ),
        "mutating a byte inside asp_expiry_script must fail: got {:?}",
        result
    );
}

// ---------------------------------------------------------------------------
// Sabotage 3: Fake Anchor Script (P2TR with wrong key)
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_sabotage_fake_anchor_ark_labs() {
    let mut tree = build_valid_ark_labs_tree();
    let mut fake_key = [0xABu8; 32];
    fake_key[0] = 0x02;
    let mut fake_p2tr = vec![0x51, 0x20];
    fake_p2tr.extend_from_slice(&fake_key);
    tree.leaf.script_pubkey = fake_p2tr;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Anchored);
    assert_eq!(
        result,
        Err(VPackError::PathExclusivityViolation),
        "replacing the P2TR key with a fake must be detected"
    );
}

#[test]
fn test_path_exclusivity_sabotage_fake_anchor_bark() {
    let mut tree = build_valid_bark_tree();
    let mut fake_key = [0xCDu8; 32];
    fake_key[0] = 0x02;
    let mut fake_p2tr = vec![0x51, 0x20];
    fake_p2tr.extend_from_slice(&fake_key);
    tree.leaf.script_pubkey = fake_p2tr;
    let result = verify_path_exclusivity(&tree, TxVariant::V3Plain);
    assert_eq!(
        result,
        Err(VPackError::PathExclusivityViolation),
        "replacing the P2TR key with a fake must be detected"
    );
}

// ---------------------------------------------------------------------------
// Sabotage 4: Non-P2TR script_pubkey
// ---------------------------------------------------------------------------

#[test]
fn test_path_exclusivity_sabotage_non_p2tr_script() {
    let mut tree = build_valid_ark_labs_tree();
    tree.leaf.script_pubkey = vec![
        0x00, 0x14, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
        0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,
    ];
    let result = verify_path_exclusivity(&tree, TxVariant::V3Anchored);
    assert_eq!(
        result,
        Err(VPackError::PathExclusivityViolation),
        "non-P2TR script_pubkey must be rejected"
    );
}
