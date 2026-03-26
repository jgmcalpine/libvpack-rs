//! TDD tests for BIP-341 Taproot tree reconstruction primitives.
//! Validates `tap_leaf_hash`, `tap_branch_hash`, balanced Merkle root
//! construction, full tree reconstruction, and path exclusivity sabotage
//! against reference vectors extracted from arkd (Ark Labs) and bark (Second Tech).

mod vectors;

use bitcoin::hashes::Hash;
use vpack::consensus::second_tech::compile_bark_unlock_script;
use vpack::error::VPackError;
use vpack::header::TxVariant;
use vpack::payload::tree::{SiblingNode, VPackTree, VtxoLeaf};
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

/// Builds a Bark tree with 4 unlock `leaf_siblings` (+ 1 expiry = 5 Taproot leaves).
/// The tweaked key is recomputed so `script_pubkey` matches — the tree passes
/// `verify_path_exclusivity` as-is, giving sabotage tests a valid baseline.
fn build_valid_bark_tree_with_unlock_siblings() -> VPackTree {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let asp_expiry_script = hex_to_vec(BARK_COSIGN_TAPROOT.leaf_scripts[0]);

    let musig_key = [0x11u8; 32];
    let leaf_siblings: Vec<SiblingNode> = (0u8..4)
        .map(|i| {
            let mut hash160 = [0u8; 20];
            hash160[0] = i;
            let unlock = compile_bark_unlock_script(&hash160, &musig_key);
            SiblingNode::Compact {
                hash: [0u8; 32],
                value: 1000,
                script: unlock,
            }
        })
        .collect();

    let dummy_anchor = {
        let txid = vpack::types::Txid::from_byte_array([0u8; 32]);
        vpack::types::OutPoint { txid, vout: 0 }
    };

    let mut tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0x00000000,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: vec![],
        },
        leaf_siblings,
        path: Vec::new(),
        anchor: dummy_anchor,
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    };

    let merkle_root =
        vpack::compute_bark_merkle_root(&tree).expect("valid 5-leaf bark tree must produce a root");
    let tweaked = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("valid internal key must produce a tweaked key");
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&tweaked);
    tree.leaf.script_pubkey = p2tr;
    tree
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

// ---------------------------------------------------------------------------
// Dual-Sabotage: exercises both arms of the P2TR guard and key comparison
// independently, killing `|| -> &&` and `!= -> ==` mutants.
// ---------------------------------------------------------------------------

#[test]
fn test_dual_sabotage_script_validation_gate() {
    // (A) Correct length (34 bytes), wrong prefix — kills `|| -> &&` on the prefix arm.
    let mut tree_a = build_valid_ark_labs_tree();
    let mut wrong_prefix = tree_a.leaf.script_pubkey.clone();
    wrong_prefix[0] = 0x00;
    tree_a.leaf.script_pubkey = wrong_prefix;
    assert_eq!(
        verify_path_exclusivity(&tree_a, TxVariant::V3Anchored),
        Err(VPackError::PathExclusivityViolation),
        "(A) correct length but wrong prefix must be rejected at the guard"
    );

    // (B) Correct prefix [0x51, 0x20], wrong length (33 bytes) — kills `|| -> &&` on the length arm.
    let mut tree_b = build_valid_ark_labs_tree();
    let mut short_script = vec![0x51, 0x20];
    short_script.extend_from_slice(&[0xAA; 31]);
    tree_b.leaf.script_pubkey = short_script;
    assert_eq!(
        verify_path_exclusivity(&tree_b, TxVariant::V3Anchored),
        Err(VPackError::PathExclusivityViolation),
        "(B) correct prefix but wrong length (33) must be rejected at the guard"
    );

    // (C) Correct format (34 bytes, valid P2TR prefix), wrong key — kills `!= -> ==`.
    let mut tree_c = build_valid_ark_labs_tree();
    let mut wrong_key_script = vec![0x51, 0x20];
    wrong_key_script.extend_from_slice(&[0xFF; 32]);
    tree_c.leaf.script_pubkey = wrong_key_script;
    assert_eq!(
        verify_path_exclusivity(&tree_c, TxVariant::V3Anchored),
        Err(VPackError::PathExclusivityViolation),
        "(C) correct P2TR format but wrong embedded key must be rejected at comparison"
    );
}

// ===========================================================================
// Sovereignty Guarantee: Merkle Inclusion Audit (adversarial tests)
// ===========================================================================

/// Sanity: the 5-leaf bark tree with unlock siblings passes path exclusivity.
#[test]
fn test_path_exclusivity_valid_bark_with_siblings() {
    let tree = build_valid_bark_tree_with_unlock_siblings();
    verify_path_exclusivity(&tree, TxVariant::V3Plain)
        .expect("valid 5-leaf Bark tree must pass path exclusivity");
}

/// Mutating one byte in a sibling's musig_key changes the TapLeaf hash, which
/// cascades through the Merkle root to the tweaked key, causing a mismatch.
/// The mutation preserves script structure so `parse_bark_unlock_script` still
/// succeeds — the failure occurs at the cryptographic key comparison, not parsing.
#[test]
fn test_merkle_sibling_substitution_fails() {
    let mut tree = build_valid_bark_tree_with_unlock_siblings();
    if let SiblingNode::Compact { ref mut script, .. } = tree.leaf_siblings[0] {
        let last_key_byte = script.len() - 2; // last byte of musig_key (before OP_CHECKSIG)
        script[last_key_byte] ^= 0x01;
    } else {
        panic!("expected Compact sibling");
    }
    assert_eq!(
        verify_path_exclusivity(&tree, TxVariant::V3Plain),
        Err(VPackError::PathExclusivityViolation),
        "substituting one musig_key byte in a sibling must invalidate the Merkle root"
    );
}

/// Truncation removes a Taproot leaf (5 → 4, odd-promoted → even-paired).
/// Extension adds a duplicate leaf (5 → 6, odd-promoted → even-paired).
/// Both change the Merkle root and must be rejected.
#[test]
fn test_path_truncation_and_extension_fails() {
    // --- Truncation: remove the last unlock sibling (5 leaves → 4) ---
    let mut truncated = build_valid_bark_tree_with_unlock_siblings();
    truncated.leaf_siblings.pop();
    assert_eq!(
        verify_path_exclusivity(&truncated, TxVariant::V3Plain),
        Err(VPackError::PathExclusivityViolation),
        "truncating a Taproot leaf must change the Merkle root and fail exclusivity"
    );

    // --- Extension: duplicate the first unlock sibling (5 leaves → 6) ---
    let mut extended = build_valid_bark_tree_with_unlock_siblings();
    let dup = extended.leaf_siblings[0].clone();
    extended.leaf_siblings.push(dup);
    assert_eq!(
        verify_path_exclusivity(&extended, TxVariant::V3Plain),
        Err(VPackError::PathExclusivityViolation),
        "extending the Taproot tree with a duplicate leaf must fail exclusivity"
    );
}

/// Flipping a single bit in the internal key (middle byte, high bit) while
/// keeping the Merkle path perfect must cascade into a different tweaked key.
#[test]
fn test_internal_key_mutation_fails() {
    let mut tree = build_valid_bark_tree_with_unlock_siblings();
    tree.internal_key[15] ^= 0x80;
    assert_eq!(
        verify_path_exclusivity(&tree, TxVariant::V3Plain),
        Err(VPackError::PathExclusivityViolation),
        "flipping bit 7 of internal_key[15] must cascade into a different tweaked key"
    );
}

/// BIP-341 requires lexicographic sorting inside `tap_branch_hash`.
/// Given two hashes where A > B, the result must be identical regardless of
/// argument order. This proves the sorting rule is enforced, not assumed.
#[test]
fn test_taproot_lexicographical_sorting_integrity() {
    let mut hash_a = [0u8; 32];
    hash_a[0] = 0xFF;

    let mut hash_b = [0u8; 32];
    hash_b[31] = 0x01;

    assert!(
        hash_a > hash_b,
        "precondition: hash_a must be lexicographically greater than hash_b"
    );

    let forward = vpack::taproot::tap_branch_hash(hash_a, hash_b);
    let reversed = vpack::taproot::tap_branch_hash(hash_b, hash_a);

    assert_eq!(
        forward, reversed,
        "tap_branch_hash must produce identical results regardless of input order"
    );

    // Verify that the canonical (sorted) order is (hash_b, hash_a) since hash_b < hash_a.
    // Compute manually: tagged_hash("TapBranch", hash_b || hash_a).
    let expected = vpack::taproot::tagged_hash(b"TapBranch", &{
        let mut payload = [0u8; 64];
        payload[..32].copy_from_slice(&hash_b);
        payload[32..].copy_from_slice(&hash_a);
        payload
    });
    assert_eq!(
        forward, expected,
        "tap_branch_hash must use sorted order: smaller hash first"
    );
}
