//! TDD tests for BIP-341 Taproot tree reconstruction primitives.
//! Validates `tap_leaf_hash` and `tap_branch_hash` against reference vectors
//! extracted from arkd (Ark Labs) and bark (Second Tech).

mod vectors;

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

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root);
    assert_eq!(result, expected, "TapTweak mismatch for ARKD_2_LEAF_TREE");
}

#[test]
fn test_taptweak_against_arkd_6_leaf() {
    let internal_key = hex_to_32(ARKD_6_LEAF_TREE.internal_key);
    let merkle_root = hex_to_32(ARKD_6_LEAF_TREE.merkle_root);
    let expected = hex_to_32(ARKD_6_LEAF_TREE.tweaked_pubkey);

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root);
    assert_eq!(result, expected, "TapTweak mismatch for ARKD_6_LEAF_TREE");
}

#[test]
fn test_taptweak_against_bark() {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let merkle_root = hex_to_32(BARK_COSIGN_TAPROOT.merkle_root);
    let expected = hex_to_32(BARK_COSIGN_TAPROOT.tweaked_pubkey);

    let result = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root);
    assert_eq!(
        result, expected,
        "TapTweak mismatch for BARK_COSIGN_TAPROOT"
    );
}
