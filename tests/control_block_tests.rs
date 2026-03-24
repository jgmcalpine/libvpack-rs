//! BIP-341 control block reconstruction and `verify_control_block` integration tests.

#[allow(dead_code)]
mod vectors;

use bitcoin::hashes::Hash;
use vpack::consensus::second_tech::{
    compile_bark_expiry_script, compile_bark_unlock_script, parse_bark_expiry_script,
};
use vpack::header::TxVariant;
use vpack::payload::tree::{SiblingNode, VPackTree, VtxoLeaf};
use vpack::reconstruct_control_block;
use vpack::types::{OutPoint, Txid};
use vpack::verify_control_block;

use vectors::arkd::ARKD_2_LEAF_TREE;
use vectors::bark::BARK_COSIGN_TAPROOT;

fn hex_to_vec(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

fn hex_to_32(s: &str) -> [u8; 32] {
    let b = hex_to_vec(s);
    assert_eq!(b.len(), 32);
    b.try_into().unwrap()
}

fn dummy_anchor() -> OutPoint {
    OutPoint {
        txid: Txid::from_byte_array([0u8; 32]),
        vout: 0,
    }
}

fn build_arkd_2_tree() -> VPackTree {
    let internal_key = hex_to_32(ARKD_2_LEAF_TREE.internal_key);
    let asp_expiry_script = hex_to_vec(ARKD_2_LEAF_TREE.leaf_scripts[1]);
    let expected_tweaked = hex_to_32(ARKD_2_LEAF_TREE.tweaked_pubkey);
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&expected_tweaked);
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
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    }
}

fn build_bark_cosign_tree() -> VPackTree {
    let internal_key = hex_to_32(BARK_COSIGN_TAPROOT.internal_key);
    let asp_expiry_script = hex_to_vec(BARK_COSIGN_TAPROOT.leaf_scripts[0]);
    let expected_tweaked = hex_to_32(BARK_COSIGN_TAPROOT.tweaked_pubkey);
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&expected_tweaked);
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
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    }
}

fn bark_expiry_leaf_script(tree: &VPackTree) -> Vec<u8> {
    let (cltv, sk) = parse_bark_expiry_script(&tree.asp_expiry_script).expect("parse bark expiry");
    compile_bark_expiry_script(cltv, &sk)
}

#[test]
fn control_block_wrong_variant_ark_tree_with_plain_fails() {
    let tree = build_arkd_2_tree();
    let err = reconstruct_control_block(&tree, TxVariant::V3Plain).unwrap_err();
    assert!(
        matches!(err, vpack::error::VPackError::InvalidBarkScript),
        "expected InvalidBarkScript when Bark rules are applied to an Ark tapscript, got {:?}",
        err
    );
}

#[test]
fn control_block_wrong_variant_bark_tree_with_anchored_fails() {
    let tree = build_bark_cosign_tree();
    let err = reconstruct_control_block(&tree, TxVariant::V3Anchored).unwrap_err();
    assert_eq!(
        err,
        vpack::error::VPackError::ControlBlockReconstructionFailed,
        "Ark leaf parser must not accept a Bark expiry script"
    );
}

#[test]
fn control_block_valid_arkd_reconstruct_and_verify() {
    let tree = build_arkd_2_tree();
    let cb =
        reconstruct_control_block(&tree, TxVariant::V3Anchored).expect("reconstruct ARKD tree");
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(verify_control_block(
        &cb,
        tree.asp_expiry_script.as_slice(),
        &out_key
    ));
}

#[test]
fn control_block_valid_bark_reconstruct_and_verify() {
    let tree = build_bark_cosign_tree();
    let cb = reconstruct_control_block(&tree, TxVariant::V3Plain).expect("reconstruct Bark tree");
    let leaf = bark_expiry_leaf_script(&tree);
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(verify_control_block(&cb, leaf.as_slice(), &out_key));
}

#[test]
fn control_block_sabotage_merkle_path_byte() {
    let tree = build_arkd_2_tree();
    let mut cb = reconstruct_control_block(&tree, TxVariant::V3Anchored).expect("reconstruct");
    assert!(
        cb.len() > 35,
        "2-leaf path expects at least one sibling hash"
    );
    cb[35] ^= 0x01;
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(!verify_control_block(
        &cb,
        tree.asp_expiry_script.as_slice(),
        &out_key
    ));
}

#[test]
fn control_block_sabotage_control_byte() {
    let tree = build_arkd_2_tree();
    let mut cb = reconstruct_control_block(&tree, TxVariant::V3Anchored).expect("reconstruct");
    cb[0] ^= 0x01;
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(!verify_control_block(
        &cb,
        tree.asp_expiry_script.as_slice(),
        &out_key
    ));
}

#[test]
fn control_block_sabotage_wrong_leaf_script() {
    let tree = build_arkd_2_tree();
    let cb = reconstruct_control_block(&tree, TxVariant::V3Anchored).expect("reconstruct");
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(!verify_control_block(&cb, &[0x51], &out_key));
}

#[test]
fn control_block_sabotage_internal_key_byte() {
    let tree = build_arkd_2_tree();
    let mut cb = reconstruct_control_block(&tree, TxVariant::V3Anchored).expect("reconstruct");
    cb[10] ^= 0x80;
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(!verify_control_block(
        &cb,
        tree.asp_expiry_script.as_slice(),
        &out_key
    ));
}

#[test]
fn control_block_deep_tree_length_33_plus_32_times_depth() {
    let internal_key = hex_to_32(ARKD_2_LEAF_TREE.internal_key);
    let server_key = [0x42u8; 32];
    let asp_expiry_script = compile_bark_expiry_script(144u32, &server_key);

    let musig_key = [0x11u8; 32];
    let mut leaf_siblings = Vec::new();
    for i in 0u32..31 {
        let mut hash160 = [0u8; 20];
        hash160[0..4].copy_from_slice(&i.to_le_bytes());
        let unlock = compile_bark_unlock_script(&hash160, &musig_key);
        leaf_siblings.push(SiblingNode::Compact {
            hash: [0u8; 32],
            value: 1000,
            script: unlock,
        });
    }

    let merkle_root = vpack::compute_bark_merkle_root(&VPackTree {
        leaf: VtxoLeaf {
            amount: 1,
            vout: 0,
            sequence: 0,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: vec![],
        },
        leaf_siblings: leaf_siblings.clone(),
        path: Vec::new(),
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script: asp_expiry_script.clone(),
    })
    .expect("32-leaf bark merkle root");

    let tweaked = vpack::taproot::compute_taproot_tweak(internal_key, merkle_root)
        .expect("tweak valid internal key");
    let mut p2tr = vec![0x51, 0x20];
    p2tr.extend_from_slice(&tweaked);

    let tree = VPackTree {
        leaf: VtxoLeaf {
            amount: 1000,
            vout: 0,
            sequence: 0x00000000,
            expiry: 0,
            exit_delta: 0,
            script_pubkey: p2tr,
        },
        leaf_siblings,
        path: Vec::new(),
        anchor: dummy_anchor(),
        asset_id: None,
        fee_anchor_script: vec![0x51, 0x02, 0x4e, 0x73],
        internal_key,
        asp_expiry_script,
    };

    let cb = reconstruct_control_block(&tree, TxVariant::V3Plain).expect("deep reconstruct");
    const DEPTH: usize = 5;
    assert_eq!(
        cb.len(),
        33 + 32 * DEPTH,
        "control block length {} (expected {})",
        cb.len(),
        33 + 32 * DEPTH
    );

    let leaf = bark_expiry_leaf_script(&tree);
    let out_key: [u8; 32] = tree.leaf.script_pubkey[2..34].try_into().unwrap();
    assert!(verify_control_block(&cb, leaf.as_slice(), &out_key));
}
