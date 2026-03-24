//! Integration tests for `validate_tree_completeness` / `validate_exit_ready_completeness`.

use bitcoin::hashes::Hash;
use vpack::error::VPackError;
use vpack::payload::tree::{GenesisItem, SiblingNode, VPackTree, VtxoLeaf};
use vpack::types::{OutPoint, Txid};
use vpack::{validate_exit_ready_completeness, validate_tree_completeness};

fn non_zero_signature() -> Option<[u8; 64]> {
    let mut s = [0u8; 64];
    s[0] = 0x01;
    s[1] = 0x02;
    Some(s)
}

fn sample_sibling() -> SiblingNode {
    SiblingNode::Compact {
        hash: [0xABu8; 32],
        value: 500,
        script: vec![0x51, 0x01, 0x00],
    }
}

fn sample_genesis_item() -> GenesisItem {
    GenesisItem {
        siblings: vec![sample_sibling()],
        parent_index: 0,
        sequence: 0xFFFFFFFF,
        child_amount: 1000,
        child_script_pubkey: vec![0x76],
        signature: non_zero_signature(),
    }
}

fn leaf_script_nonempty() -> Vec<u8> {
    let mut s = vec![0x51u8, 0x20];
    s.extend_from_slice(&[0xCDu8; 32]);
    s
}

fn valid_tree() -> VPackTree {
    let txid = Txid::from_byte_array([0x11u8; 32]);
    VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0xFFFFFFFF,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: leaf_script_nonempty(),
        },
        leaf_siblings: vec![sample_sibling()],
        path: vec![sample_genesis_item()],
        anchor: OutPoint { txid, vout: 0 },
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x01, 0x00],
        internal_key: [0x22u8; 32],
        asp_expiry_script: vec![0x63],
    }
}

#[test]
fn valid_tree_passes_completeness() {
    let tree = valid_tree();
    assert!(validate_tree_completeness(&tree).is_ok());
}

#[test]
fn validate_exit_ready_alias_matches_validate_tree() {
    let tree = valid_tree();
    assert_eq!(
        validate_exit_ready_completeness(&tree),
        validate_tree_completeness(&tree)
    );
}

#[test]
fn missing_signature_reported_at_path_step_one() {
    let mut tree = valid_tree();
    tree.path[0].signature = None;

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 1,
            field: "signature",
        })
    );
}

#[test]
fn zeroed_signature_reported_at_path_step_one() {
    let mut tree = valid_tree();
    tree.path[0].signature = Some([0u8; 64]);

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 1,
            field: "signature",
        })
    );
}

#[test]
fn empty_path_siblings_reported_at_path_step_one() {
    let mut tree = valid_tree();
    tree.path[0].siblings.clear();

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 1,
            field: "siblings",
        })
    );
}

#[test]
fn empty_leaf_script_pubkey_stays_leaf_tier_depth_zero() {
    let mut tree = valid_tree();
    tree.leaf.script_pubkey.clear();

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 0,
            field: "leaf.script_pubkey",
        })
    );
}

#[test]
fn withheld_leaf_sibling_reported_at_leaf_tier_depth_zero() {
    let mut tree = valid_tree();
    if let SiblingNode::Compact { script, .. } = &mut tree.leaf_siblings[0] {
        script.clear();
    }

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 0,
            field: "leaf_sibling",
        })
    );
}

#[test]
fn second_path_step_uses_depth_two() {
    let mut tree = valid_tree();
    tree.path.push(GenesisItem {
        siblings: vec![sample_sibling()],
        parent_index: 0,
        sequence: 0xFFFFFFFF,
        child_amount: 1000,
        child_script_pubkey: vec![0x76],
        signature: non_zero_signature(),
    });
    tree.path[1].signature = None;

    assert_eq!(
        validate_tree_completeness(&tree),
        Err(VPackError::TreeIncomplete {
            depth: 2,
            field: "signature",
        })
    );
}
